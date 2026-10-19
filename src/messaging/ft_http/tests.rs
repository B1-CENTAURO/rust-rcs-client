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

//! Uploads and downloads against a content server the test scripts, over
//! HTTP on localhost

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_rcs_core::dns::DnsClient;
use rust_rcs_core::http::HttpClient;
use rust_rcs_core::security::gba::GbaContext;
use rust_rcs_core::security::SecurityContext;
use rustls::{ClientConfig, RootCertStore};
use tokio::runtime::Runtime;
use uuid::Uuid;

use super::content_server::{ContentServer, Credentials};
use super::download::{download_file, FileDownloadError};
use super::upload::{upload_file, FileInfo, FileUploadError};
use super::FileTransferOverHTTPService;

/// A request the content server took
pub struct Taken {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Taken {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn read_request(reader: &mut BufReader<std::net::TcpStream>) -> Option<Taken> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = String::from(parts.next()?);
    let target = String::from(parts.next()?);

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((String::from(name.trim()), String::from(value.trim())));
    }

    let mut taken = Taken {
        method,
        target,
        headers,
        body: Vec::new(),
    };
    let length: usize = taken
        .header("Content-Length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    taken.body = vec![0; length];
    reader.read_exact(&mut taken.body).ok()?;
    Some(taken)
}

/// A response of `status`, with `headers` and `body`
pub fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut data = format!("HTTP/1.1 {}\r\n", status);
    for header in headers {
        data += header;
        data += "\r\n";
    }
    data += &format!("Content-Length: {}\r\n\r\n", body.len());
    let mut data = data.into_bytes();
    data.extend_from_slice(body);
    data
}

/// A content server on localhost answering each request, on whatever
/// connection, as `answer` says: its base URL and the requests it takes
pub fn content_server<A>(answer: A) -> (String, Receiver<Taken>)
where
    A: FnMut(&Taken) -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let answer = Arc::new(Mutex::new(answer));
    let (taken_tx, taken) = mpsc::channel();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => return,
            };
            let answer = Arc::clone(&answer);
            let taken_tx = taken_tx.clone();
            std::thread::spawn(move || {
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                while let Some(request) = read_request(&mut reader) {
                    let data = (answer.lock().unwrap())(&request);
                    if taken_tx.send(request).is_err() {
                        return;
                    }
                    if writer.write_all(&data).is_err() {
                        return;
                    }
                }
            });
        }
    });

    (base, taken)
}

/// What requests to the content server are made with
pub struct Client {
    pub rt: Arc<Runtime>,
    /// The host the credentials are for
    pub credentials_host: &'static str,
    http_client: Arc<HttpClient>,
    gba_context: Arc<GbaContext>,
    security_context: Arc<SecurityContext>,
}

impl Client {
    pub fn new() -> Client {
        let rt = Arc::new(Runtime::new().unwrap());
        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let dns_client = Arc::new(DnsClient::new(Arc::clone(&rt)));
        Client {
            http_client: Arc::new(HttpClient::new(
                Arc::new(config),
                dns_client,
                Arc::clone(&rt),
            )),
            gba_context: Arc::new(GbaContext::new(
                String::from("impi@example.com"),
                String::from("http://bsf.example.com"),
                String::from("bsf.example.com"),
                0,
            )),
            security_context: Arc::new(SecurityContext::new()),
            credentials_host: "127.0.0.1",
            rt,
        }
    }

    pub fn server(&self) -> ContentServer<'_> {
        ContentServer {
            http_client: &self.http_client,
            gba_context: &self.gba_context,
            security_context: &self.security_context,
            credentials: Some(Credentials {
                host: self.credentials_host,
                user: "ftuser",
                password: "ftpassword",
            }),
            msisdn: None,
        }
    }

    /// Downloads `uri` to `path` as download_file() does, with the progress
    /// it reported last
    pub fn download(
        &self,
        uri: &str,
        path: &str,
        start: usize,
        total: Option<usize>,
    ) -> (Result<(), FileDownloadError>, Option<(u32, i32)>) {
        let progress = Arc::new(Mutex::new(None));
        let progress_ = Arc::clone(&progress);
        let result = self.rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                download_file(uri, path, start, total, &self.server(), move |c, t| {
                    progress_.lock().unwrap().replace((c, t));
                }),
            )
            .await
            .expect("the download to end")
        });
        let progress = *progress.lock().unwrap();
        (result, progress)
    }

    pub fn upload(
        &self,
        service: &Arc<FileTransferOverHTTPService>,
        cs_uri: &str,
        tid: Uuid,
        path: &str,
    ) -> Result<String, FileUploadError> {
        let progress: Arc<Box<dyn Fn(u32, i32) + Send + Sync>> = Arc::new(Box::new(|_, _| {}));
        self.rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                upload_file(
                    service,
                    cs_uri,
                    tid,
                    FileInfo {
                        path,
                        name: "a.txt",
                        mime: "text/plain",
                        hash: None,
                    },
                    None,
                    &self.server(),
                    &progress,
                ),
            )
            .await
            .expect("the upload to end")
        })
    }
}

/// A file of `content` in the temporary directory, removed when dropped
pub struct TempFile(pub String);

impl TempFile {
    pub fn new(content: &[u8]) -> TempFile {
        let path = std::env::temp_dir().join(format!("ft-http-test-{}", Uuid::new_v4()));
        std::fs::write(&path, content).unwrap();
        TempFile(path.to_string_lossy().into_owned())
    }

    pub fn content(&self) -> Vec<u8> {
        std::fs::read(&self.0).unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The next request the content server took, within 5 s
fn next(taken: &Receiver<Taken>) -> Taken {
    taken
        .recv_timeout(Duration::from_secs(5))
        .expect("a request to the content server")
}

/// The value of the parameter `name` in the Digest Authorization `value`
fn digest_param<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    let value = value.strip_prefix("Digest ")?;
    value.split(',').find_map(|param| {
        let (n, v) = param.trim().split_once('=')?;
        if n == name {
            Some(v.trim_matches('"'))
        } else {
            None
        }
    })
}

const CHALLENGE: &str =
    "WWW-Authenticate: Digest realm=\"ftcs.example.com\", nonce=\"n0nce\", qop=\"auth\", algorithm=MD5";

fn error_code_of<T>(result: Result<T, FileDownloadError>) -> Option<u16> {
    result.err().map(|e| e.error_code())
}

#[test]
fn a_download_resumed_asks_for_the_rest_and_adds_it_to_what_is_there() {
    let client = Client::new();
    let (base, taken) = content_server(|_| {
        response(
            "206 Partial Content",
            &["Content-Range: bytes 6-10/11"],
            b"world",
        )
    });
    let file = TempFile::new(b"hello ");

    let (result, progress) = client.download(&format!("{}/f/1", base), &file.0, 6, Some(11));
    assert!(result.is_ok());
    assert_eq!(file.content(), b"hello world");
    assert_eq!(
        progress,
        Some((11, 11)),
        "the progress counts what was there"
    );

    let request = next(&taken);
    assert_eq!(request.header("Range"), Some("bytes=6-"));
    assert_eq!(
        request.header("Host"),
        Some(base.trim_start_matches("http://")),
        "the Host has the port"
    );
}

#[test]
fn a_download_the_server_sends_whole_replaces_what_is_there() {
    let client = Client::new();
    let (base, _taken) = content_server(|_| response("200 OK", &[], b"hello world"));

    // asked from where it was left, and from the start
    for start in [6, 0] {
        let file = TempFile::new(b"stale content, longer than the file");
        let (result, progress) =
            client.download(&format!("{}/f/1", base), &file.0, start, Some(11));
        assert!(result.is_ok());
        assert_eq!(file.content(), b"hello world");
        assert_eq!(progress, Some((11, 11)));
    }
}

#[test]
fn a_download_shorter_than_the_file_fails() {
    let client = Client::new();
    let (base, _taken) = content_server(|_| response("200 OK", &[], b"hello"));
    let file = TempFile::new(b"");

    let (result, _) = client.download(&format!("{}/f/1", base), &file.0, 0, Some(11));
    assert_eq!(error_code_of(result), Some(0));
}

#[test]
fn a_download_given_another_range_than_asked_for_fails() {
    let client = Client::new();
    let (base, _taken) = content_server(|_| {
        response(
            "206 Partial Content",
            &["Content-Range: bytes 0-4/11"],
            b"hello",
        )
    });
    let file = TempFile::new(b"hello ");

    let (result, _) = client.download(&format!("{}/f/1", base), &file.0, 6, Some(11));
    assert_eq!(error_code_of(result), Some(0));
    assert_eq!(file.content(), b"hello ", "the file is left as it was");
}

#[test]
fn a_download_challenged_is_answered_for_its_own_uri_with_the_credentials() {
    let client = Client::new();
    let (base, taken) = content_server(|request| {
        if request.header("Authorization").is_none() {
            response("401 Unauthorized", &[CHALLENGE], b"")
        } else {
            response("200 OK", &[], b"the file")
        }
    });
    let file = TempFile::new(b"");

    let (result, _) = client.download(&format!("{}/f/1?id=7", base), &file.0, 0, None);
    assert!(result.is_ok());
    assert_eq!(file.content(), b"the file");

    next(&taken);
    let answered = next(&taken);
    let authorization = answered.header("Authorization").unwrap();
    assert_eq!(digest_param(authorization, "uri"), Some("/f/1?id=7"));
    assert_eq!(digest_param(authorization, "username"), Some("ftuser"));
    assert_eq!(
        digest_param(authorization, "realm"),
        Some("ftcs.example.com")
    );
    assert_eq!(digest_param(authorization, "nonce"), Some("n0nce"));
    assert!(digest_param(authorization, "response").map_or(false, |r| r.len() == 32));
}

#[test]
fn another_host_is_not_answered_with_the_credentials() {
    let mut client = Client::new();
    client.credentials_host = "ftcs.example.com";
    let (base, taken) = content_server(|_| response("401 Unauthorized", &[CHALLENGE], b""));
    let file = TempFile::new(b"");

    let (result, _) = client.download(&format!("{}/f/1", base), &file.0, 0, None);
    assert_eq!(error_code_of(result), Some(401));
    next(&taken);
    assert!(taken.recv_timeout(Duration::from_millis(300)).is_err());
}

#[test]
fn a_download_refused_once_answered_reports_the_refusal() {
    let client = Client::new();
    let (base, taken) = content_server(|_| response("401 Unauthorized", &[CHALLENGE], b""));
    let file = TempFile::new(b"");

    let (result, _) = client.download(&format!("{}/f/1", base), &file.0, 0, None);
    assert_eq!(error_code_of(result), Some(401));
    // asked, and answered once
    next(&taken);
    next(&taken);
    assert!(taken.recv_timeout(Duration::from_millis(300)).is_err());
}

const RESULT_XML: &[u8] = b"<?xml version=\"1.0\"?><file><file-info type=\"file\"/></file>";

#[test]
fn an_upload_challenged_on_its_empty_post_sends_the_file_answered() {
    let client = Client::new();
    let (base, taken) = content_server(|request| {
        if request.header("Authorization").is_none() {
            response("401 Unauthorized", &[CHALLENGE], b"")
        } else {
            response("200 OK", &["Content-Type: application/xml"], RESULT_XML)
        }
    });
    let file = TempFile::new(b"the file content");
    let service = Arc::new(FileTransferOverHTTPService::new());

    let result = client.upload(
        &service,
        &format!("{}/upload", base),
        Uuid::new_v4(),
        &file.0,
    );
    assert_eq!(result.ok().as_deref().map(str::as_bytes), Some(RESULT_XML));

    let empty = next(&taken);
    assert_eq!((empty.method.as_str(), empty.body.len()), ("POST", 0));
    let posted = next(&taken);
    assert_eq!(posted.method, "POST");
    assert!(posted
        .header("Content-Type")
        .unwrap()
        .starts_with("multipart/form-data; boundary="));
    let body = String::from_utf8_lossy(&posted.body);
    assert!(body.contains("the file content"), "{}", body);
    assert_eq!(
        digest_param(posted.header("Authorization").unwrap(), "uri"),
        Some("/upload")
    );
    assert!(
        taken.recv_timeout(Duration::from_millis(300)).is_err(),
        "the empty POST is not made again"
    );
}

/// Answers the requests of a resumed upload of `tid`, the server having
/// bytes 0 to `end` of the file
fn resuming_server(base: &Arc<Mutex<String>>, end: usize) -> impl FnMut(&Taken) -> Vec<u8> {
    let base = Arc::clone(base);
    move |request| {
        if request.target.ends_with("&get_upload_info") {
            let xml = format!(
                "<?xml version=\"1.0\"?><file-resume-info>\
<file-range start=\"0\" end=\"{}\"/><data url=\"{}/data/1\"/></file-resume-info>",
                end,
                base.lock().unwrap()
            );
            response("200 OK", &[], xml.as_bytes())
        } else if request.method == "PUT" {
            response("200 OK", &[], b"")
        } else if request.target.ends_with("&get_download_info") {
            response("200 OK", &[], RESULT_XML)
        } else {
            response("500 Unexpected", &[], b"")
        }
    }
}

#[test]
fn an_upload_resumed_puts_the_rest_from_the_byte_after_the_range() {
    let client = Client::new();
    let base = Arc::new(Mutex::new(String::new()));
    let (url, taken) = content_server(resuming_server(&base, 3));
    *base.lock().unwrap() = url.clone();
    let file = TempFile::new(b"0123456789");
    let service = Arc::new(FileTransferOverHTTPService::new());
    let tid = Uuid::new_v4();
    service.recorded_tids.lock().unwrap().push(tid);

    let result = client.upload(&service, &format!("{}/upload", url), tid, &file.0);
    assert_eq!(result.ok().as_deref().map(str::as_bytes), Some(RESULT_XML));

    let asked = next(&taken);
    assert_eq!(
        (asked.method.as_str(), asked.target.as_str()),
        ("GET", &format!("/upload?tid={}&get_upload_info", tid)[..])
    );
    let put = next(&taken);
    assert_eq!(put.method, "PUT");
    assert_eq!(put.target, "/data/1");
    assert_eq!(put.header("Content-Range"), Some("bytes 4-9/10"));
    assert_eq!(put.body, b"456789");
    let info = next(&taken);
    assert_eq!(
        info.target,
        format!("/upload?tid={}&get_download_info", tid)
    );
}

#[test]
fn an_upload_resumed_the_server_has_all_of_only_asks_where_it_is() {
    let client = Client::new();
    let base = Arc::new(Mutex::new(String::new()));
    let (url, taken) = content_server(resuming_server(&base, 9));
    *base.lock().unwrap() = url.clone();
    let file = TempFile::new(b"0123456789");
    let service = Arc::new(FileTransferOverHTTPService::new());
    let tid = Uuid::new_v4();
    service.recorded_tids.lock().unwrap().push(tid);

    let result = client.upload(&service, &format!("{}/upload", url), tid, &file.0);
    assert_eq!(result.ok().as_deref().map(str::as_bytes), Some(RESULT_XML));

    assert!(next(&taken).target.ends_with("&get_upload_info"));
    assert!(next(&taken).target.ends_with("&get_download_info"));
}

#[test]
fn an_upload_resumed_the_server_knows_nothing_of_is_made_afresh() {
    let client = Client::new();
    let (url, taken) = content_server(|request| {
        if request.target.ends_with("&get_upload_info") {
            response("404 Not Found", &[], b"")
        } else if request.body.is_empty() {
            response("204 No Content", &[], b"")
        } else {
            response("200 OK", &[], RESULT_XML)
        }
    });
    let file = TempFile::new(b"0123456789");
    let service = Arc::new(FileTransferOverHTTPService::new());
    let tid = Uuid::new_v4();
    service.recorded_tids.lock().unwrap().push(tid);

    let result = client.upload(&service, &format!("{}/upload", url), tid, &file.0);
    assert_eq!(result.ok().as_deref().map(str::as_bytes), Some(RESULT_XML));

    assert!(next(&taken).target.ends_with("&get_upload_info"));
    assert_eq!(next(&taken).body.len(), 0);
    assert!(String::from_utf8_lossy(&next(&taken).body).contains("0123456789"));
}
