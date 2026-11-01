// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    io::{self, Seek, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::AsyncWrite;
use rust_rcs_core::{
    ffi::log::platform_log,
    http::{request::GET, response::Response},
    internet::{header, Header},
    io::ProgressReportingReader,
};
use tokio::io::copy;
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use url::Url;

use super::content_server::{reason_phrase, Auth, ContentServer};
use super::upload::SEALED_FILE_SUFFIX;

const LOG_TAG: &str = "fthttp";

pub enum FileDownloadError {
    Http(u16, String),
    IO,
    MalformedHost,
    NetworkIO,
    /// A file received encrypted that did not open with its key (RCC.16
    /// section 9.1.2.2)
    NotOpened,
}

impl FileDownloadError {
    pub fn error_code(&self) -> u16 {
        match &self {
            FileDownloadError::Http(status_code, _) => *status_code,
            FileDownloadError::IO => 0,
            FileDownloadError::MalformedHost => 0,
            FileDownloadError::NetworkIO => 0,
            FileDownloadError::NotOpened => 0,
        }
    }

    pub fn error_string(&self) -> String {
        match &self {
            FileDownloadError::Http(_, reason_phrase) => String::from(reason_phrase),
            FileDownloadError::IO => String::from("IO"),
            FileDownloadError::MalformedHost => String::from("MalformedHost"),
            FileDownloadError::NetworkIO => String::from("NetworkIO"),
            FileDownloadError::NotOpened => String::from("NotOpened"),
        }
    }
}

impl Display for FileDownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            FileDownloadError::Http(status_code, reason_phrase) => {
                f.write_fmt(format_args!("Http {} {}", status_code, reason_phrase))
            }
            FileDownloadError::IO => f.write_str("IO"),
            FileDownloadError::MalformedHost => f.write_str("MalformedHost"),
            FileDownloadError::NetworkIO => f.write_str("NetworkIO"),
            FileDownloadError::NotOpened => f.write_str("NotOpened"),
        }
    }
}

struct FileOutput {
    f: File,
}

impl AsyncWrite for FileOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let p = self.get_mut();
        match p.f.write(buf) {
            Ok(i) => Poll::Ready(Ok(i)),
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(e)),
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let p = self.get_mut();
        match p.f.flush() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(e)),
            },
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let p = self.get_mut();
        match p.f.sync_all() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,
                _ => Poll::Ready(Err(e)),
            },
        }
    }
}

/// Where the download starts: from `start` with a Range request, or from the
/// beginning
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resumed {
    From(usize),
    No,
}

/// The first byte of the range a 206 carries, by its Content-Range (RFC 9110
/// section 14.4)
fn content_range_start(resp: &Response) -> Option<usize> {
    let content_range = header::search(&resp.headers, b"Content-Range", false)?;
    let value = std::str::from_utf8(content_range.get_value()).ok()?.trim();
    let range = value.strip_prefix("bytes")?.trim_start();
    range.split('-').next()?.trim().parse().ok()
}

/// Downloads `file_uri` to `download_path`, from `start` on if the file holds
/// that much of it already, the whole file being `total` bytes if known
pub async fn download_file<F>(
    file_uri: &str,
    download_path: &str,
    start: usize,
    total: Option<usize>,
    server: &ContentServer<'_>,
    progress_callback: F,
) -> Result<(), FileDownloadError>
where
    F: Fn(u32, i32) + Send + Sync + 'static,
{
    let url = Url::parse(file_uri).map_err(|_| FileDownloadError::MalformedHost)?;
    if url.host_str().is_none() {
        return Err(FileDownloadError::MalformedHost);
    }

    // what is there already is of no use if it is all of it, or more
    let start = match total {
        Some(total) if start >= total => 0,
        _ => start,
    };

    let (resp, body) = server
        .send(
            GET,
            &url,
            |req| {
                if start > 0 {
                    req.headers
                        .push(Header::new(b"Range", format!("bytes={}-", start)));
                }
            },
            Arc::new(|_| {}),
            Auth::Stored,
            true,
        )
        .await
        .ok_or(FileDownloadError::NetworkIO)?;

    // a server that does not do ranges sends the whole file
    let resumed = match resp.status_code {
        200 => Resumed::No,
        206 if start > 0 && content_range_start(&resp) == Some(start) => Resumed::From(start),
        206 => {
            platform_log(LOG_TAG, "a range other than the one asked for");
            return Err(FileDownloadError::IO);
        }
        status_code => {
            return Err(FileDownloadError::Http(status_code, reason_phrase(&resp)));
        }
    };

    let body = body.ok_or(FileDownloadError::NetworkIO)?;

    let mut options = OpenOptions::new();
    options.write(true).create(true);
    match resumed {
        Resumed::From(_) => options.append(true),
        Resumed::No => options.truncate(true),
    };
    let mut f = options.open(download_path).map_err(|e| {
        platform_log(LOG_TAG, format!("file open error: {}", e));
        FileDownloadError::IO
    })?;

    let offset = match resumed {
        Resumed::From(start) => start,
        Resumed::No => 0,
    };

    // appended to what is there, which is to be what was asked for
    if let Resumed::From(start) = resumed {
        match f.seek(io::SeekFrom::End(0)) {
            Ok(size) if usize::try_from(size) == Ok(start) => {}
            _ => {
                platform_log(
                    LOG_TAG,
                    "underlying file size is inconsistent with provided value",
                );
                return Err(FileDownloadError::IO);
            }
        }
    }

    let progress_total = get_progress_total(total);

    let reader = ProgressReportingReader::new(body, move |read| {
        if let Ok(current) = u32::try_from(offset + read) {
            progress_callback(current, progress_total);
        }
    });

    let mut rh = reader.compat();
    let mut wh = FileOutput { f }.compat_write();

    match copy(&mut rh, &mut wh).await {
        Ok(copied) => {
            platform_log(LOG_TAG, format!("bytes copied {}", copied));
            let downloaded = usize::try_from(copied).ok().map(|copied| offset + copied);
            match total {
                Some(total) if downloaded != Some(total) => {
                    platform_log(
                        LOG_TAG,
                        "inconsistent result of bytes copied and expected total",
                    );
                    Err(FileDownloadError::IO)
                }
                _ => Ok(()),
            }
        }
        Err(e) => {
            platform_log(
                LOG_TAG,
                format!("http stream copy failed with error: {}", e),
            );
            Err(FileDownloadError::IO)
        }
    }
}

fn get_progress_total(total: Option<usize>) -> i32 {
    if let Some(total) = total {
        if let Ok(total) = i32::try_from(total) {
            total
        } else {
            -1
        }
    } else {
        -1
    }
}

/// Downloads the file at `file_uri`, received encrypted, as download_file()
/// does, into a file at `download_path` with SEALED_FILE_SUFFIX appended,
/// going on from what is there of it, then has `open` decrypt it into
/// `download_path` and deletes it (RCC.16 section 9.1.2.2)
///
/// One that does not open is deleted all the same, for it to be downloaded
/// afresh.
pub async fn download_sealed_file<F>(
    file_uri: &str,
    download_path: &str,
    total: Option<usize>,
    server: &ContentServer<'_>,
    progress_callback: F,
    open: &(dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync),
) -> Result<(), FileDownloadError>
where
    F: Fn(u32, i32) + Send + Sync + 'static,
{
    let sealed_path = format!("{}{}", download_path, SEALED_FILE_SUFFIX);
    let start = std::fs::metadata(&sealed_path)
        .ok()
        .and_then(|metadata| usize::try_from(metadata.len()).ok())
        .unwrap_or(0);
    download_file(
        file_uri,
        &sealed_path,
        start,
        total,
        server,
        progress_callback,
    )
    .await?;

    let ciphertext = std::fs::read(&sealed_path).map_err(|_| FileDownloadError::IO)?;
    let opened = open(&ciphertext);
    let _ = std::fs::remove_file(&sealed_path);
    let opened = opened.ok_or(FileDownloadError::NotOpened)?;
    std::fs::write(download_path, opened).map_err(|_| FileDownloadError::IO)
}
