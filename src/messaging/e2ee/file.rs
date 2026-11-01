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

//! Files sent in the encrypted group chats of the device: encrypted, each
//! with a key of its own, before they are uploaded, their keys sent in the
//! message telling where they are (RCC.16 sections 7.8, 9.1.2.1, Annex C.2)

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose, Engine as _};
use quick_xml::events::Event;
use quick_xml::Reader;
use rust_rcs_core::mls::rcs::file::encrypt_file;
use rust_rcs_core::mls::rcs::proto::{self, FileInfo, FileMetadata};

use crate::messaging::cpm::encryption::SealedFile;

use super::device::E2eeDevice;

/// Content-Type of the messages telling where files are (RCC.07 section
/// 3.2.5.4)
pub const CONTENT_TYPE_FT_HTTP: &[u8] = b"application/vnd.gsma.rcs-ft-http+xml";

/// How long the keys of files uploaded are kept for the message sending them,
/// and of how many uploads at most, the oldest let go of first
const UPLOAD_KEPT_FOR: Duration = Duration::from_secs(24 * 60 * 60);
const UPLOADS_MOST: usize = 64;

/// The keys of files uploaded for a group chat, by the URL of the file
#[derive(Clone, Debug, PartialEq)]
struct Upload {
    conversation_id: String,
    url: String,
    file_info: FileInfo,
    uploaded: SystemTime,
}

/// The files uploaded for the encrypted group chats of the device, for as
/// long as it runs
#[derive(Default)]
pub(super) struct Uploads(Mutex<Vec<Upload>>);

impl Uploads {
    /// Keeps `file_info` for the message sending the file at `url` in the
    /// group chat `conversation_id`, uploaded `now`
    fn keep(&self, conversation_id: &str, url: &str, file_info: FileInfo, now: SystemTime) {
        let mut uploads = self.0.lock().unwrap();
        uploads.retain(|upload| upload.url != url && kept(upload, now));
        if uploads.len() >= UPLOADS_MOST {
            uploads.remove(0);
        }
        uploads.push(Upload {
            conversation_id: String::from(conversation_id),
            url: String::from(url),
            file_info,
            uploaded: now,
        });
    }

    /// What the FileInfo of the file at `url`, uploaded for the group chat
    /// `conversation_id`, tells, if it was within UPLOAD_KEPT_FOR of `now`
    fn file_info(&self, conversation_id: &str, url: &str, now: SystemTime) -> Option<FileInfo> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|upload| {
                upload.conversation_id == conversation_id && upload.url == url && kept(upload, now)
            })
            .map(|upload| upload.file_info.clone())
    }
}

fn kept(upload: &Upload, now: SystemTime) -> bool {
    now.duration_since(upload.uploaded)
        .map_or(true, |age| age < UPLOAD_KEPT_FOR)
}

/// The file `content`, named `name` and of `content_type`, encrypted with a
/// key of its own, its name taken in (RCC.16 section 9.1.2.1, Annex C.2)
pub fn seal_file(content: &[u8], name: &str, content_type: &str) -> Option<SealedFile> {
    let encrypted = encrypt_file(content, name).ok()?;
    let metadata = FileMetadata {
        file_name: String::from(name),
        content_type: String::from(content_type),
        encryption_info: Some(encrypted.encryption_info),
    };
    Some(SealedFile {
        ciphertext: encrypted.ciphertext,
        metadata: proto::encode(&metadata),
    })
}

/// The URLs of the file and of its thumbnail the FT HTTP XML `xml` tells,
/// each in the data element of its file-info (RCC.07 section 4.1.15.2.1)
pub(super) fn file_urls(xml: &[u8]) -> (Option<String>, Option<String>) {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let (mut file, mut thumbnail) = (None, None);
    // the type of the file-info read in, if any
    let mut info_type: Option<Vec<u8>> = None;
    loop {
        let event = match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) | Err(_) => break,
            Ok(event) => event,
        };
        match event {
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"file-info" => {
                info_type = e
                    .try_get_attribute("type")
                    .ok()
                    .flatten()
                    .map(|a| a.value.into_owned());
            }
            Event::End(e) if e.local_name().as_ref() == b"file-info" => info_type = None,
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"data" => {
                let url = e
                    .try_get_attribute("url")
                    .ok()
                    .flatten()
                    .and_then(|a| a.unescape_value().ok().map(|url| url.into_owned()));
                match info_type.as_deref() {
                    Some(b"file") if file.is_none() => file = url,
                    Some(b"thumbnail") if thumbnail.is_none() => thumbnail = url,
                    _ => {}
                }
            }
            _ => {}
        }
        buf.clear();
    }
    (file, thumbnail)
}

/// The FT HTTP XML `xml` with the mls-file element carrying `mls_message`,
/// base64 encoded, last in its root element (RCC.16 section 7.8.2); None if
/// it is no XML of a file element
pub(super) fn with_mls_file(xml: &[u8], mls_message: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    // where the end tag of the root element starts
    let root_end = loop {
        let position = reader.buffer_position();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if depth == 0 && e.local_name().as_ref() != b"file" {
                    return None;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    break position;
                }
            }
            Ok(Event::Empty(_)) if depth == 0 => return None,
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
        buf.clear();
    };
    let mut with = xml[..root_end].to_vec();
    with.extend_from_slice(b"<mls-file>");
    with.extend_from_slice(general_purpose::STANDARD.encode(mls_message).as_bytes());
    with.extend_from_slice(b"</mls-file>");
    with.extend_from_slice(&xml[root_end..]);
    Some(with)
}

impl E2eeDevice {
    /// Whether the files sent in the group chat `conversation_id` are to be
    /// encrypted before they are uploaded: while it is encrypted (RCC.16
    /// section 9.1.2.1)
    pub fn encrypts_files(&self, conversation_id: &str) -> bool {
        self.store().has_conversation(conversation_id.as_bytes())
            && !self.encryption_ended(conversation_id)
    }

    /// Keeps what the FileInfo of the file and the thumbnail uploaded for the
    /// group chat `conversation_id` tells, `file` and `thumbnail` the
    /// FileMetadata seal_file() gave of them, by the URL of the file the XML
    /// `xml` of the content server tells, for the message sending them
    /// (RCC.16 sections 7.8, 9.1.2.1); false if it tells none, or if `file`
    /// or `thumbnail` is no FileMetadata
    ///
    /// They are kept for a day at most, in memory.
    pub fn uploaded(
        &self,
        conversation_id: &str,
        xml: &[u8],
        file: &[u8],
        thumbnail: Option<&[u8]>,
    ) -> bool {
        let (Some(url), _) = file_urls(xml) else {
            return false;
        };
        let Ok(file) = proto::decode::<FileMetadata>(file) else {
            return false;
        };
        let thumbnail = match thumbnail.map(proto::decode::<FileMetadata>) {
            Some(Ok(thumbnail)) => Some(thumbnail),
            Some(Err(_)) => return false,
            None => None,
        };
        let file_info = FileInfo {
            file: Some(file),
            thumbnail,
            ..FileInfo::default()
        };
        self.uploads()
            .keep(conversation_id, &url, file_info, self.store().now());
        true
    }

    /// What the FileInfo of the file at `url`, uploaded for the group chat
    /// `conversation_id`, tells, if it was within a day
    pub(super) fn uploaded_file_info(&self, conversation_id: &str, url: &str) -> Option<FileInfo> {
        self.uploads()
            .file_info(conversation_id, url, self.store().now())
    }
}

#[cfg(test)]
/// What a content server answers an upload with, the file of the URL
/// `file_url`, after its thumbnail (RCC.07 section 4.1.15.2.1)
pub(super) fn upload_xml(file_url: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<file xmlns=\"urn:gsma:params:xml:ns:rcs:rcs:fthttp\" xmlns:x=\"urn:gsma:params:xml:ns:rcs:rcs:up:fthttpext\">\n\
<file-info type=\"thumbnail\">\n<file-size>128</file-size>\n<content-type>message/mls-ft</content-type>\n\
<data url=\"https://ftcs.example.com/t/1?a=1&amp;b=2\" until=\"2026-11-08T12:00:00Z\"/>\n</file-info>\n\
<file-info type=\"file\" file-disposition=\"attachment\">\n<file-size>4096</file-size>\n\
<file-name>encrypted_file</file-name>\n<content-type>message/mls-ft</content-type>\n\
<data url=\"{}\" until=\"2026-11-08T12:00:00Z\"/>\n</file-info>\n</file>\n",
        file_url
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use base64::{engine::general_purpose, Engine as _};
    use rust_rcs_core::mls::rcs::file::decrypt_file;
    use rust_rcs_core::mls::rcs::proto::{self, FileInfo, FileMetadata};

    use super::{
        file_urls, seal_file, upload_xml, with_mls_file, Uploads, UPLOADS_MOST, UPLOAD_KEPT_FOR,
    };

    #[test]
    fn the_urls_of_the_file_and_its_thumbnail_are_read() {
        let xml = upload_xml("https://ftcs.example.com/f/1");
        assert_eq!(
            file_urls(xml.as_bytes()),
            (
                Some(String::from("https://ftcs.example.com/f/1")),
                Some(String::from("https://ftcs.example.com/t/1?a=1&b=2"))
            )
        );
        // the data of another element than a file-info, and none without
        assert_eq!(
            file_urls(
                b"<file><data url=\"https://a.example.com/\"/><file-info type=\"file\"/></file>"
            ),
            (None, None)
        );
        assert_eq!(
            file_urls(b"<file><file-info type=\"file\"><data url=\"u\"/></file-info></file>"),
            (Some(String::from("u")), None)
        );
        // nor one after its file-info
        assert_eq!(
            file_urls(b"<file><file-info type=\"file\"></file-info><data url=\"u\"/></file>"),
            (None, None)
        );
        assert_eq!(file_urls(b"not XML"), (None, None));
    }

    #[test]
    fn the_mls_file_goes_last_in_the_file_element() {
        let xml = upload_xml("https://ftcs.example.com/f/1");
        let with =
            String::from_utf8(with_mls_file(xml.as_bytes(), b"\x01\x02mls").unwrap()).unwrap();
        let encoded = general_purpose::STANDARD.encode(b"\x01\x02mls");
        assert!(
            with.ends_with(&format!(
                "</file-info>\n<mls-file>{}</mls-file></file>\n",
                encoded
            )),
            "{}",
            with
        );
        assert!(with.starts_with(&xml[..xml.len() - "</file>\n".len()]));
        // the URLs as they were
        assert_eq!(file_urls(with.as_bytes()), file_urls(xml.as_bytes()));
        // not of another document, nor of one not closed
        for other in [
            &b"<files><file-info type=\"file\"/></files>"[..],
            b"<file/>",
            b"<file><file-info type=\"file\"/>",
            b"",
        ] {
            assert_eq!(with_mls_file(other, b"mls"), None);
        }
    }

    #[test]
    fn a_file_sealed_is_opened_with_the_key_its_metadata_tells() {
        let sealed = seal_file(b"the picture", "picture.jpg", "image/jpeg").unwrap();
        let metadata: FileMetadata = proto::decode(&sealed.metadata).unwrap();
        assert_eq!(metadata.file_name, "picture.jpg");
        assert_eq!(metadata.content_type, "image/jpeg");
        let info = metadata.encryption_info.unwrap();
        assert_ne!(sealed.ciphertext, b"the picture");
        assert_eq!(
            decrypt_file(&sealed.ciphertext, "picture.jpg", &info).unwrap(),
            b"the picture"
        );
        // its name taken in (Annex C.2)
        assert!(decrypt_file(&sealed.ciphertext, "other.jpg", &info).is_err());
        // each with a key of its own
        let again = seal_file(b"the picture", "picture.jpg", "image/jpeg").unwrap();
        assert_ne!(again.ciphertext, sealed.ciphertext);
    }

    fn info(name: &str) -> FileInfo {
        FileInfo {
            file: Some(FileMetadata {
                file_name: String::from(name),
                ..FileMetadata::default()
            }),
            ..FileInfo::default()
        }
    }

    #[test]
    fn uploads_are_kept_a_day_by_group_and_url() {
        let uploads = Uploads::default();
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        uploads.keep("group-1", "u1", info("a"), then);
        assert_eq!(uploads.file_info("group-1", "u1", then), Some(info("a")));
        assert_eq!(uploads.file_info("group-2", "u1", then), None);
        assert_eq!(uploads.file_info("group-1", "u2", then), None);
        // the same URL again replaces it
        uploads.keep("group-1", "u1", info("b"), then);
        assert_eq!(uploads.file_info("group-1", "u1", then), Some(info("b")));

        let later = then + UPLOAD_KEPT_FOR - Duration::from_secs(1);
        assert_eq!(uploads.file_info("group-1", "u1", later), Some(info("b")));
        assert_eq!(
            uploads.file_info("group-1", "u1", then + UPLOAD_KEPT_FOR),
            None
        );

        // so many at most, the oldest let go of first
        for n in 0..UPLOADS_MOST {
            uploads.keep("group-1", &format!("v{}", n), info("c"), later);
        }
        assert_eq!(uploads.file_info("group-1", "u1", later), None);
        assert_eq!(uploads.file_info("group-1", "v0", later), Some(info("c")));
        uploads.keep("group-1", "w", info("d"), later);
        assert_eq!(uploads.file_info("group-1", "v0", later), None);
        assert_eq!(uploads.file_info("group-1", "v1", later), Some(info("c")));
    }
}
