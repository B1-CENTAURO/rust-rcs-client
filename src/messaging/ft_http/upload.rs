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

use std::{fmt::Display, fs, sync::Arc};

use rust_rcs_core::{
    ffi::log::platform_log,
    http::request::{GET, POST, PUT},
    internet::{
        body::{
            message_body::MessageBody,
            multipart_body::MultipartBody,
            streamed_body::{StreamSource, StreamedBody},
        },
        header, Body, Header,
    },
    io::Serializable,
    util::rand::create_raw_alpha_numeric_string,
};
use url::Url;
use uuid::Uuid;

use crate::messaging::cpm::encryption::SealedFile;

use super::{
    content_server::{read_text, reason_phrase, Auth, ContentServer},
    resume_info_xml::parse_xml,
    FileTransferOverHTTPService,
};

/// The name and the type a sealed file is uploaded under (RCC.16 section
/// 9.1.2.1)
pub const SEALED_FILE_NAME: &str = "encrypted_file";
pub const SEALED_FILE_TYPE: &str = "message/mls-ft";

/// What is appended to the path of a file for that of the file sealed of it
pub const SEALED_FILE_SUFFIX: &str = ".mls-ft";

const LOG_TAG: &str = "fthttp";

pub enum FileUploadError {
    Http(u16, String),
    IO,
    MalformedHost,
    NetworkIO,
}

impl FileUploadError {
    pub fn error_code(&self) -> u16 {
        match &self {
            FileUploadError::Http(status_code, _) => *status_code,
            FileUploadError::IO => 0,
            FileUploadError::MalformedHost => 0,
            FileUploadError::NetworkIO => 0,
        }
    }

    pub fn error_string(&self) -> String {
        match &self {
            FileUploadError::Http(_, reason_phrase) => String::from(reason_phrase),
            FileUploadError::IO => String::from("IO"),
            FileUploadError::MalformedHost => String::from("MalformedHost"),
            FileUploadError::NetworkIO => String::from("NetworkIO"),
        }
    }
}

impl Display for FileUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            FileUploadError::Http(status_code, reason_phrase) => {
                f.write_fmt(format_args!("Http {} {}", status_code, reason_phrase))
            }
            FileUploadError::IO => f.write_str("IO"),
            FileUploadError::MalformedHost => f.write_str("MalformedHost"),
            FileUploadError::NetworkIO => f.write_str("NetworkIO"),
        }
    }
}

pub struct FileInfo<'a> {
    pub path: &'a str,
    pub name: &'a str,
    pub mime: &'a str,
    pub hash: Option<&'a str>,
}

/// The size of the file at `path`, which is not to be empty
fn file_size(path: &str) -> Result<usize, FileUploadError> {
    match fs::metadata(path).map(|meta| usize::try_from(meta.len())) {
        Ok(Ok(size)) if size > 0 => Ok(size),
        _ => Err(FileUploadError::IO),
    }
}

/// The content server's URI asking `request` of the upload `tid`, as
/// get_upload_info
fn info_url(ft_http_cs_uri: &str, tid: Uuid, request: &str) -> Result<Url, FileUploadError> {
    let mut url = Url::parse(ft_http_cs_uri).map_err(|_| FileUploadError::MalformedHost)?;
    if url.host_str().is_none() {
        return Err(FileUploadError::MalformedHost);
    }
    let query = format!(
        "tid={}&{}",
        tid.as_hyphenated().encode_lower(&mut Uuid::encode_buffer()),
        request
    );
    let query = match url.query() {
        Some(existing) => format!("{}&{}", existing, query),
        None => query,
    };
    url.set_query(Some(&query));
    Ok(url)
}

fn http_error(status_code: u16, reason_phrase: String) -> FileUploadError {
    FileUploadError::Http(status_code, reason_phrase)
}

/// The form a file is uploaded with: the tid, the thumbnail if any, the file
fn upload_body(
    tid: Uuid,
    file: &FileInfo<'_>,
    file_size: usize,
    thumbnail: Option<(&FileInfo<'_>, usize)>,
) -> (Body, String) {
    let boundary = create_raw_alpha_numeric_string(16);
    let boundary_ = String::from_utf8_lossy(&boundary).into_owned();

    let tid_string = String::from(tid.as_hyphenated().encode_lower(&mut Uuid::encode_buffer()));

    let tid_payload = Body::Message(MessageBody {
        headers: vec![
            Header::new("Content-Disposition", "form-data; name=\"tid\""),
            Header::new("Content-Type", "text/plain; charset=utf-8"),
            Header::new("Content-Length", format!("{}", tid_string.len())),
        ],
        body: Arc::new(Body::Raw(tid_string.into_bytes())),
    });

    let file_part = |name: &str, file: &FileInfo<'_>, size: usize| {
        Body::Message(MessageBody {
            headers: vec![
                Header::new(
                    "Content-Disposition",
                    format!("form-data; name=\"{}\"; filename=\"{}\"", name, file.name),
                ),
                Header::new("Content-Type", String::from(file.mime)),
                Header::new("Content-Transfer-Encoding", "binary"),
                Header::new("Content-Range", format!("0-{}/{}", size - 1, size)),
                Header::new("Content-Length", format!("{}", size)),
            ],
            body: Arc::new(Body::Streamed(StreamedBody {
                stream_size: size,
                stream_source: StreamSource::File((String::from(file.path), 0)),
            })),
        })
    };

    let mut parts = vec![Arc::new(tid_payload)];
    if let Some((thumbnail, size)) = thumbnail {
        parts.push(Arc::new(file_part("Thumbnail", thumbnail, size)));
    }
    parts.push(Arc::new(file_part("File", file, file_size)));

    (
        Body::Multipart(MultipartBody { boundary, parts }),
        boundary_,
    )
}

/// Uploads `file`, with `thumbnail`, as `tid`: an empty POST first, which
/// the server may challenge, then the POST of the files, authorized as the
/// challenge asks. The XML the server tells where the files are with.
async fn upload(
    ft_http_cs_uri: &str,
    tid: Uuid,
    file: &FileInfo<'_>,
    thumbnail: Option<&FileInfo<'_>>,
    server: &ContentServer<'_>,
    progress_callback: &Arc<Box<dyn Fn(u32, i32) + Send + Sync>>,
) -> Result<String, FileUploadError> {
    platform_log(LOG_TAG, "calling upload()");

    let url = Url::parse(ft_http_cs_uri).map_err(|_| FileUploadError::MalformedHost)?;
    if url.host_str().is_none() {
        return Err(FileUploadError::MalformedHost);
    }

    let thumbnail = match thumbnail {
        Some(thumbnail) => Some((thumbnail, file_size(thumbnail.path)?)),
        None => None,
    };
    let file_size = file_size(file.path)?;

    let (empty_resp, _) = server
        .send(POST, &url, |_| {}, Arc::new(|_| {}), Auth::Stored, false)
        .await
        .ok_or(FileUploadError::NetworkIO)?;

    let auth = match empty_resp.status_code {
        200 | 204 => Auth::Stored,
        401 => match header::search(&empty_resp.headers, b"WWW-Authenticate", false) {
            Some(www_authenticate) => Auth::ChallengeOf(www_authenticate),
            None => return Err(http_error(401, reason_phrase(&empty_resp))),
        },
        status_code => return Err(http_error(status_code, reason_phrase(&empty_resp))),
    };
    let challenged = matches!(auth, Auth::ChallengeOf(_));

    let progress_total = {
        let (body, _) = upload_body(tid, file, file_size, thumbnail);
        body.estimated_size()
    };
    let progress_callback = Arc::clone(progress_callback);

    let sent = server
        .send(
            POST,
            &url,
            |req| {
                let (body, boundary) = upload_body(tid, file, file_size, thumbnail);
                req.headers.push(Header::new(
                    "Content-Type",
                    format!("multipart/form-data; boundary={}", boundary),
                ));
                req.headers.push(Header::new(
                    "Content-Length",
                    format!("{}", body.estimated_size()),
                ));
                req.body = Some(body);
            },
            Arc::new(move |written| {
                if let Ok(current) = u32::try_from(written) {
                    progress_callback(current, i32::try_from(progress_total).unwrap_or(-1));
                }
            }),
            auth,
            true,
        )
        .await;

    let (resp, body) = match sent {
        Some(sent) => sent,
        // the challenge could not be answered
        None if challenged => return Err(http_error(401, reason_phrase(&empty_resp))),
        None => return Err(FileUploadError::NetworkIO),
    };

    if resp.status_code == 200 {
        return read_text(body).await.ok_or(FileUploadError::NetworkIO);
    }

    Err(http_error(resp.status_code, reason_phrase(&resp)))
}

/// The XML the server tells where the files of `tid` are with
async fn get_download_info(
    ft_http_cs_uri: &str,
    tid: Uuid,
    server: &ContentServer<'_>,
) -> Result<String, FileUploadError> {
    let url = info_url(ft_http_cs_uri, tid, "get_download_info")?;

    let (resp, body) = server
        .send(GET, &url, |_| {}, Arc::new(|_| {}), Auth::Stored, true)
        .await
        .ok_or(FileUploadError::NetworkIO)?;

    if resp.status_code == 200 {
        return read_text(body).await.ok_or(FileUploadError::NetworkIO);
    }

    Err(http_error(resp.status_code, reason_phrase(&resp)))
}

/// Uploads what the server does not have yet of `file`, as `tid`, or all of
/// it, with `thumbnail`, if it knows nothing of `tid`
async fn resume_upload(
    ft_http_cs_uri: &str,
    tid: Uuid,
    file: &FileInfo<'_>,
    thumbnail: Option<&FileInfo<'_>>,
    server: &ContentServer<'_>,
    progress_callback: &Arc<Box<dyn Fn(u32, i32) + Send + Sync>>,
) -> Result<String, FileUploadError> {
    let url = info_url(ft_http_cs_uri, tid, "get_upload_info")?;

    let (resp, body) = server
        .send(GET, &url, |_| {}, Arc::new(|_| {}), Auth::Stored, true)
        .await
        .ok_or(FileUploadError::NetworkIO)?;

    let resume_info = match resp.status_code {
        200 => match read_text(body).await {
            Some(text) => parse_xml(text.as_bytes()),
            None => return Err(FileUploadError::NetworkIO),
        },
        404 => None,
        status_code => return Err(http_error(status_code, reason_phrase(&resp))),
    };

    let resume_info = match resume_info {
        Some(resume_info) => resume_info,
        None => {
            platform_log(LOG_TAG, "nothing to resume, uploading all");
            return upload(
                ft_http_cs_uri,
                tid,
                file,
                thumbnail,
                server,
                progress_callback,
            )
            .await;
        }
    };

    let file_size = file_size(file.path)?;

    // the server has up to the end of the range, which is the last byte it
    // has, as in an HTTP range
    let next = resume_info.range_end + 1;

    if next > file_size {
        platform_log(LOG_TAG, "the server has more than the file");
        return Err(FileUploadError::IO);
    }

    if next < file_size {
        let data_url =
            Url::parse(&resume_info.data_url).map_err(|_| FileUploadError::MalformedHost)?;
        if data_url.host_str().is_none() {
            return Err(FileUploadError::MalformedHost);
        }

        let progress_callback = Arc::clone(progress_callback);
        let path = String::from(file.path);

        let (resp, _) = server
            .send(
                PUT,
                &data_url,
                |req| {
                    req.headers
                        .push(Header::new("Content-Type", "application/octet-stream"));
                    req.headers.push(Header::new(
                        "Content-Range",
                        format!("bytes {}-{}/{}", next, file_size - 1, file_size),
                    ));
                    req.headers.push(Header::new(
                        "Content-Length",
                        format!("{}", file_size - next),
                    ));
                    req.body = Some(Body::Streamed(StreamedBody {
                        stream_size: file_size - next,
                        stream_source: StreamSource::File((path.clone(), next)),
                    }));
                },
                Arc::new(move |written| {
                    if let Ok(current) = u32::try_from(next + written) {
                        progress_callback(current, i32::try_from(file_size).unwrap_or(-1));
                    }
                }),
                Auth::Stored,
                true,
            )
            .await
            .ok_or(FileUploadError::NetworkIO)?;

        if !(200..300).contains(&resp.status_code) {
            return Err(http_error(resp.status_code, reason_phrase(&resp)));
        }
    }

    get_download_info(ft_http_cs_uri, tid, server).await
}

/// Uploads `file`, with `thumbnail`, as `tid` to the content server at
/// `ft_http_cs_uri`, resuming the upload if `tid` was uploaded before. The
/// XML the server tells where the files are with.
pub async fn upload_file(
    ft_http_service: &Arc<FileTransferOverHTTPService>,
    ft_http_cs_uri: &str,
    tid: Uuid,
    file: FileInfo<'_>,
    thumbnail: Option<FileInfo<'_>>,
    server: &ContentServer<'_>,
    progress_callback: &Arc<Box<dyn Fn(u32, i32) + Send + Sync>>,
) -> Result<String, FileUploadError> {
    let is_known_task = {
        let mut guard = ft_http_service.recorded_tids.lock().unwrap();
        if guard.contains(&tid) {
            true
        } else {
            guard.push(tid);
            false
        }
    };

    if is_known_task {
        resume_upload(
            ft_http_cs_uri,
            tid,
            &file,
            thumbnail.as_ref(),
            server,
            progress_callback,
        )
        .await
    } else {
        upload(
            ft_http_cs_uri,
            tid,
            &file,
            thumbnail.as_ref(),
            server,
            progress_callback,
        )
        .await
    }
}

/// The file and the thumbnail of an upload sealed, at the path of each, with
/// what was given of each besides its ciphertext
#[derive(Clone)]
pub(super) struct SealedUpload {
    file: (String, Vec<u8>),
    thumbnail: Option<(String, Vec<u8>)>,
}

/// The file `file` sealed with `seal`, the ciphertext written at its path
/// with SEALED_FILE_SUFFIX appended: that path, and what `seal` gave of it
/// besides
fn sealed(
    file: &FileInfo<'_>,
    seal: &(dyn Fn(&[u8], &str, &str) -> Option<SealedFile> + Send + Sync),
) -> Result<(String, Vec<u8>), FileUploadError> {
    let content = fs::read(file.path).map_err(|_| FileUploadError::IO)?;
    let sealed = seal(&content, file.name, file.mime).ok_or(FileUploadError::IO)?;
    let path = format!("{}{}", file.path, SEALED_FILE_SUFFIX);
    fs::write(&path, &sealed.ciphertext).map_err(|_| FileUploadError::IO)?;
    Ok((path, sealed.metadata))
}

/// Uploads `file`, with `thumbnail`, as upload_file() does, each sealed
/// with `seal` first, its name and type taken in, into a file at its path
/// with SEALED_FILE_SUFFIX appended, under the name SEALED_FILE_NAME and the
/// type SEALED_FILE_TYPE (RCC.16 section 9.1.2.1): the XML the server tells
/// where they are with, and what `seal` gave of the file and the thumbnail
/// besides the ciphertext
///
/// The files sealed are deleted once they are uploaded. Until then, an
/// upload of the same `tid` resumed uploads them, sealed as they were.
pub async fn upload_sealed_file(
    ft_http_service: &Arc<FileTransferOverHTTPService>,
    ft_http_cs_uri: &str,
    tid: Uuid,
    file: FileInfo<'_>,
    thumbnail: Option<FileInfo<'_>>,
    server: &ContentServer<'_>,
    progress_callback: &Arc<Box<dyn Fn(u32, i32) + Send + Sync>>,
    seal: &(dyn Fn(&[u8], &str, &str) -> Option<SealedFile> + Send + Sync),
) -> Result<(String, Vec<u8>, Option<Vec<u8>>), FileUploadError> {
    let kept = ft_http_service
        .sealed
        .lock()
        .unwrap()
        .get(&tid)
        .cloned()
        .filter(|kept| {
            fs::metadata(&kept.file.0).is_ok()
                && kept
                    .thumbnail
                    .as_ref()
                    .map_or(true, |thumbnail| fs::metadata(&thumbnail.0).is_ok())
        });
    let upload = match kept {
        Some(kept) => kept,
        None => {
            let upload = SealedUpload {
                file: sealed(&file, seal)?,
                thumbnail: match &thumbnail {
                    Some(thumbnail) => Some(sealed(thumbnail, seal)?),
                    None => None,
                },
            };
            ft_http_service
                .sealed
                .lock()
                .unwrap()
                .insert(tid, upload.clone());
            upload
        }
    };

    let sealed_file = FileInfo {
        path: &upload.file.0,
        name: SEALED_FILE_NAME,
        mime: SEALED_FILE_TYPE,
        hash: None,
    };
    let sealed_thumbnail = upload.thumbnail.as_ref().map(|(path, _)| FileInfo {
        path,
        name: SEALED_FILE_NAME,
        mime: SEALED_FILE_TYPE,
        hash: None,
    });
    let xml = upload_file(
        ft_http_service,
        ft_http_cs_uri,
        tid,
        sealed_file,
        sealed_thumbnail,
        server,
        progress_callback,
    )
    .await?;

    ft_http_service.sealed.lock().unwrap().remove(&tid);
    let _ = fs::remove_file(&upload.file.0);
    if let Some((path, _)) = &upload.thumbnail {
        let _ = fs::remove_file(path);
    }
    Ok((
        xml,
        upload.file.1,
        upload.thumbnail.map(|(_, metadata)| metadata),
    ))
}
