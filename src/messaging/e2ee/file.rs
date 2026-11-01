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
//! message telling where they are (RCC.16 sections 7.8, 9.1.2.1, Annex C.2);
//! and those received, their keys kept until they are downloaded and opened
//! (section 9.1.2.2, Annex C.3)

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose, Engine as _};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use rust_rcs_core::cpim::{CPIMInfo, CPIMMessage};
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::internet::Body;
use rust_rcs_core::mls::rcs::file::{decrypt_file, encrypt_file};
use rust_rcs_core::mls::rcs::proto::{self, FileInfo, FileMetadata};
use rust_rcs_core::mls::rcs::CONTENT_TYPE_MLS_RCS_FILE_INFO;

use crate::messaging::cpm::encryption::SealedFile;

use super::device::E2eeDevice;
use super::message::MessageError;
use super::notes::{put, put_time, NotesData, Reader as NotesReader};

const LOG_TAG: &str = "e2ee";

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

/// How long the keys of files received are kept for them to be downloaded,
/// and of how many files at most, the oldest let go of first
const RECEIVED_KEPT_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const RECEIVED_MOST: usize = 512;

/// The key of a file received encrypted, by its URL, for it to be opened
/// once downloaded (RCC.16 section 9.1.2.2)
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Received {
    pub(super) url: String,
    /// Its FileMetadata: its name, its type and its key
    pub(super) metadata: Vec<u8>,
    pub(super) received: SystemTime,
}

fn received_kept(received: &Received, now: SystemTime) -> bool {
    now.duration_since(received.received)
        .map_or(true, |age| age < RECEIVED_KEPT_FOR)
}

/// `data` keeping the FileMetadata `files` by URL, received `now`
fn keep_received(data: &mut NotesData, files: Vec<(String, Vec<u8>)>, now: SystemTime) {
    data.received.retain(|received| {
        received_kept(received, now) && files.iter().all(|(url, _)| *url != received.url)
    });
    for (url, metadata) in files {
        if data.received.len() >= RECEIVED_MOST {
            data.received.remove(0);
        }
        data.received.push(Received {
            url,
            metadata,
            received: now,
        });
    }
}

/// The FileMetadata `data` keeps of the file at `url`, if received within
/// RECEIVED_KEPT_FOR of `now`
fn received_file(data: &NotesData, url: &str, now: SystemTime) -> Option<FileMetadata> {
    data.received
        .iter()
        .find(|received| received.url == url && received_kept(received, now))
        .and_then(|received| proto::decode(&received.metadata).ok())
}

/// The keys of the files received `received`, as the notes of the device
/// hold them
pub(super) fn encode(received: &[Received]) -> Vec<u8> {
    let mut data = Vec::new();
    for received in received {
        put(&mut data, received.url.as_bytes());
        put(&mut data, &received.metadata);
        put_time(&mut data, received.received);
    }
    data
}

/// The keys of the files received `reader` reads, as encode() puts them
pub(super) fn decode(reader: &mut NotesReader) -> Option<Vec<Received>> {
    let mut received = Vec::new();
    while !reader.is_empty() {
        received.push(Received {
            url: reader.string()?,
            metadata: reader.vec()?,
            received: reader.time()?,
        });
    }
    Some(received)
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

/// The MlsMessage the mls-file element of the FT HTTP XML `xml` carries,
/// base64 encoded (RCC.16 section 7.8.2)
pub(super) fn mls_file_of(xml: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut inside = false;
    let mut text = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if e.local_name().as_ref() == b"mls-file" => inside = true,
            Ok(Event::Text(t)) if inside => text.extend_from_slice(&t),
            Ok(Event::End(e)) if inside && e.local_name().as_ref() == b"mls-file" => break,
            Ok(Event::Eof) | Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }
    text.retain(|b| !b.is_ascii_whitespace());
    general_purpose::STANDARD.decode(text).ok()
}

/// The FT HTTP XML `xml` as the app is given it once its mls-file is
/// decrypted to `file_info` (RCC.16 section 9.1.2.2): without the mls-file,
/// the name and the type of the file and of the thumbnail those
/// `file_info` tells, in place of those they were uploaded under; None if
/// it cannot be read
pub(super) fn opened_xml(xml: &[u8], file_info: &FileInfo) -> Option<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    // the metadata of the file-info read in, whether it is that of the file,
    // and whether its file-name and content-type were met
    let mut info: Option<(&FileMetadata, bool, bool, bool)> = None;
    // how deep in the mls-file, or in an element whose text is replaced
    let (mut skipped, mut replaced) = (0usize, 0usize);
    loop {
        let event = match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(event) => event,
            Err(_) => return None,
        };
        if skipped > 0 {
            match event {
                Event::Start(_) => skipped += 1,
                Event::End(_) => skipped -= 1,
                _ => {}
            }
            buf.clear();
            continue;
        }
        if replaced > 0 {
            match event {
                Event::Start(_) => replaced += 1,
                Event::End(_) => {
                    replaced -= 1;
                    if replaced == 0 {
                        writer.write_event(event).ok()?;
                    }
                }
                _ => {}
            }
            buf.clear();
            continue;
        }
        match &event {
            Event::Start(e) if e.local_name().as_ref() == b"mls-file" => {
                skipped = 1;
                buf.clear();
                continue;
            }
            Event::Empty(e) if e.local_name().as_ref() == b"mls-file" => {
                buf.clear();
                continue;
            }
            Event::Start(e) if e.local_name().as_ref() == b"file-info" => {
                let (metadata, is_file) = match e.try_get_attribute("type").ok().flatten() {
                    Some(t) if t.value.as_ref() == b"file" => (file_info.file.as_ref(), true),
                    Some(t) if t.value.as_ref() == b"thumbnail" => {
                        (file_info.thumbnail.as_ref(), false)
                    }
                    _ => (None, false),
                };
                info = metadata.map(|metadata| (metadata, is_file, false, false));
            }
            Event::Start(e) if info.is_some() => {
                let (metadata, _, name, content_type) = info.as_mut().unwrap();
                let value = match e.local_name().as_ref() {
                    b"file-name" => {
                        *name = true;
                        Some(&metadata.file_name)
                    }
                    b"content-type" => {
                        *content_type = true;
                        Some(&metadata.content_type)
                    }
                    _ => None,
                };
                if let Some(value) = value {
                    writer.write_event(event.clone()).ok()?;
                    writer
                        .write_event(Event::Text(BytesText::new(value)))
                        .ok()?;
                    replaced = 1;
                    buf.clear();
                    continue;
                }
            }
            Event::End(e) if e.local_name().as_ref() == b"file-info" => {
                // those it did not tell, told
                if let Some((metadata, is_file, name, content_type)) = info.take() {
                    let mut told = |element: &str, value: &str| -> Option<()> {
                        writer
                            .write_event(Event::Start(BytesStart::new(element)))
                            .ok()?;
                        writer
                            .write_event(Event::Text(BytesText::new(value)))
                            .ok()?;
                        writer.write_event(Event::End(BytesEnd::new(element))).ok()
                    };
                    if is_file && !name {
                        told("file-name", &metadata.file_name)?;
                    }
                    if !content_type {
                        told("content-type", &metadata.content_type)?;
                    }
                }
            }
            _ => {}
        }
        writer.write_event(event).ok()?;
        buf.clear();
    }
    Some(writer.into_inner())
}

/// The FileInfo the CPIM message `cpim` carries, as
/// `message/mls-rcs-file-info` (RCC.16 section 7.8.1)
fn file_info_of(cpim: &[u8]) -> Option<FileInfo> {
    let body = Body::construct_message(cpim).ok()?;
    let message = CPIMMessage::try_from(&body).ok()?;
    match message.get_message_body()? {
        (Some(content_type), content, false)
            if content_type
                .split(|b| *b == b';')
                .next()?
                .trim_ascii()
                .eq_ignore_ascii_case(CONTENT_TYPE_MLS_RCS_FILE_INFO) =>
        {
            proto::decode(content).ok()
        }
        _ => None,
    }
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

    /// The CPIM message the file transfer message of the group chat
    /// `conversation_id`, delivered in the CPIM message `cpim_info` tells of
    /// with the XML `xml`, carries: its headers as decrypt_message() gives
    /// them, and the XML with the names and types of the files as they were,
    /// its mls-file decrypted to the FileInfo of the files (RCC.16 sections
    /// 7.8, 9.1.2.2)
    ///
    /// The keys of the file and of the thumbnail are kept with the MLS state,
    /// by their URLs, for a download of either to be opened, before the
    /// message is given out: for 30 days, and of 512 files at most.
    pub fn decrypt_file_transfer(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        xml: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        let mls_message = mls_file_of(xml).ok_or(MessageError::NotFileTransfer)?;
        let decrypted = self.decrypt_message(conversation_id, cpim_info, &mls_message)?;
        let file_info = file_info_of(&decrypted).ok_or(MessageError::NotFileTransfer)?;
        let opened = opened_xml(xml, &file_info).ok_or(MessageError::NotFileTransfer)?;
        let (Some(file_url), thumbnail_url) = file_urls(xml) else {
            return Err(MessageError::NotFileTransfer);
        };
        let Some(file) = &file_info.file else {
            return Err(MessageError::NotFileTransfer);
        };
        let mut files = vec![(file_url, proto::encode(file))];
        if let (Some(url), Some(thumbnail)) = (thumbnail_url, &file_info.thumbnail) {
            files.push((url, proto::encode(thumbnail)));
        }
        let now = self.store().now();
        self.notes()
            .change(self.store(), |data| keep_received(data, files, now))
            .map_err(MessageError::Store)?;

        // the headers decrypted, then the XML in place of the FileInfo
        let headers_end = decrypted
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or(MessageError::NotFileTransfer)?
            + 4;
        let mut data = decrypted[..headers_end].to_vec();
        data.extend_from_slice(b"Content-Type: ");
        data.extend_from_slice(CONTENT_TYPE_FT_HTTP);
        data.extend_from_slice(format!("\r\nContent-Length: {}\r\n\r\n", opened.len()).as_bytes());
        data.extend_from_slice(&opened);
        Ok(data)
    }

    /// Whether the file at `url` was received encrypted, its key kept for it
    /// to be opened once downloaded (RCC.16 section 9.1.2.2), or is the
    /// encrypted icon of a group chat (section 9.7.1.4)
    pub fn opens_file(&self, url: &str) -> bool {
        let now = self.store().now();
        self.notes()
            .read(|data| received_file(data, url, now))
            .is_some()
            || self.icon_at(url).is_some()
    }

    /// `ciphertext`, downloaded from `url`, decrypted with the key kept for
    /// it, its tag checked first, and the key forgotten then (RCC.16 section
    /// 9.1.2.2, Annex C.3); None if no key is kept for it, or if it does not
    /// open with it, which keeps the key
    ///
    /// The encrypted icon of a group chat is decrypted with the key of the
    /// icon kept for the group, which is kept on (section 9.7.1.4).
    pub fn open_file(&self, url: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let now = self.store().now();
        let Some(metadata) = self.notes().read(|data| received_file(data, url, now)) else {
            let conversation_id = self.icon_at(url)?;
            return self.open_icon(&conversation_id, ciphertext);
        };
        let opened = decrypt_file(
            ciphertext,
            &metadata.file_name,
            metadata.encryption_info.as_ref()?,
        )
        .ok()?;
        let forgotten = self
            .notes()
            .change(self.store(), |data| data.received.retain(|r| r.url != url));
        if let Err(e) = forgotten {
            platform_log(
                LOG_TAG,
                format!("key of the file opened not forgotten: {:?}", e),
            );
        }
        Some(opened)
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

    use super::super::notes::{NotesData, Reader as NotesReader};
    use super::{
        decode, encode, file_urls, keep_received, mls_file_of, opened_xml, received_file,
        seal_file, upload_xml, with_mls_file, Received, Uploads, RECEIVED_KEPT_FOR, RECEIVED_MOST,
        UPLOADS_MOST, UPLOAD_KEPT_FOR,
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

    #[test]
    fn the_mls_file_is_read_as_it_was_put() {
        let xml = upload_xml("https://ftcs.example.com/f/1");
        let with = with_mls_file(xml.as_bytes(), b"\x00\x01mls message").unwrap();
        assert_eq!(
            mls_file_of(&with).as_deref(),
            Some(&b"\x00\x01mls message"[..])
        );
        // its base64 across lines
        let spread = b"<file><mls-file>\n  AAEC\n  AwQ=\n</mls-file></file>";
        assert_eq!(mls_file_of(spread).as_deref(), Some(&[0u8, 1, 2, 3, 4][..]));
        // none, or not base64
        assert_eq!(mls_file_of(xml.as_bytes()), None);
        assert_eq!(
            mls_file_of(b"<file><mls-file>not base64!</mls-file></file>"),
            None
        );
        assert_eq!(mls_file_of(b"<file><mls-file>AAEC"), None);
    }

    fn metadata(name: &str, content_type: &str) -> FileMetadata {
        FileMetadata {
            file_name: String::from(name),
            content_type: String::from(content_type),
            ..FileMetadata::default()
        }
    }

    #[test]
    fn the_xml_opened_tells_the_names_and_types_the_files_had() {
        let file_info = FileInfo {
            file: Some(metadata("a & b.pdf", "application/pdf")),
            thumbnail: Some(metadata("t.png", "image/png")),
            ..FileInfo::default()
        };
        let xml = with_mls_file(
            upload_xml("https://ftcs.example.com/f/1").as_bytes(),
            b"mls",
        )
        .unwrap();
        let opened = String::from_utf8(opened_xml(&xml, &file_info).unwrap()).unwrap();
        // in place of those they were uploaded under, all else as it was
        let expected = upload_xml("https://ftcs.example.com/f/1")
            .replace(
                "<content-type>message/mls-ft</content-type>\n<data url=\"https://ftcs.example.com/t",
                "<content-type>image/png</content-type>\n<data url=\"https://ftcs.example.com/t",
            )
            .replace("<file-name>encrypted_file</file-name>", "<file-name>a &amp; b.pdf</file-name>")
            .replace(
                "<content-type>message/mls-ft</content-type>",
                "<content-type>application/pdf</content-type>",
            );
        assert_eq!(opened, expected);

        // those it does not tell, told; another file-info as it is
        let xml = b"<file><file-info type=\"file\"><data url=\"u\"/></file-info>\
<file-info type=\"thumbnail\"><file-name>x</file-name></file-info>\
<file-info type=\"other\"><content-type>message/mls-ft</content-type></file-info>\
<mls-file>bWxz</mls-file></file>";
        let opened = String::from_utf8(opened_xml(xml, &file_info).unwrap()).unwrap();
        assert_eq!(
            opened,
            "<file><file-info type=\"file\"><data url=\"u\"/><file-name>a &amp; b.pdf</file-name>\
<content-type>application/pdf</content-type></file-info>\
<file-info type=\"thumbnail\"><file-name>t.png</file-name><content-type>image/png</content-type></file-info>\
<file-info type=\"other\"><content-type>message/mls-ft</content-type></file-info>\
</file>"
        );
        // a thumbnail it tells of none of, as it is
        let file_only = FileInfo {
            file: file_info.file.clone(),
            ..FileInfo::default()
        };
        let opened = String::from_utf8(opened_xml(xml, &file_only).unwrap()).unwrap();
        assert!(
            opened.contains("<file-info type=\"thumbnail\"><file-name>x</file-name></file-info>")
        );
        // nor what is not XML
        assert_eq!(opened_xml(b"<file><a></b></file>", &file_info), None);
    }

    #[test]
    fn the_keys_of_files_received_are_kept_30_days_by_url() {
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let mut data = NotesData::default();
        let (a, b) = (metadata("a", "x/a"), metadata("b", "x/b"));
        keep_received(
            &mut data,
            vec![
                (String::from("u1"), proto::encode(&a)),
                (String::from("u2"), proto::encode(&b)),
            ],
            then,
        );
        assert_eq!(received_file(&data, "u1", then), Some(a.clone()));
        assert_eq!(received_file(&data, "u2", then), Some(b.clone()));
        assert_eq!(received_file(&data, "u3", then), None);
        // the same URL again replaces it
        keep_received(
            &mut data,
            vec![(String::from("u1"), proto::encode(&b))],
            then,
        );
        assert_eq!(received_file(&data, "u1", then), Some(b.clone()));
        assert_eq!(data.received.len(), 2);

        let later = then + RECEIVED_KEPT_FOR - Duration::from_secs(1);
        assert_eq!(received_file(&data, "u2", later), Some(b.clone()));
        assert_eq!(received_file(&data, "u2", then + RECEIVED_KEPT_FOR), None);
        // those over 30 days let go of with the next kept
        keep_received(&mut data, vec![], then + RECEIVED_KEPT_FOR);
        assert!(data.received.is_empty());

        // so many at most, the oldest let go of first
        let files: Vec<_> = (0..RECEIVED_MOST + 1)
            .map(|n| (format!("v{}", n), proto::encode(&a)))
            .collect();
        keep_received(&mut data, files, then);
        assert_eq!(data.received.len(), RECEIVED_MOST);
        assert_eq!(received_file(&data, "v0", then), None);
        assert_eq!(received_file(&data, "v1", then), Some(a.clone()));
        // nor what is no FileMetadata
        keep_received(&mut data, vec![(String::from("w"), b"\xff".to_vec())], then);
        assert_eq!(received_file(&data, "w", then), None);
    }

    #[test]
    fn the_keys_of_files_received_are_read_as_they_were_kept() {
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let kept = vec![
            Received {
                url: String::from("https://ftcs.example.com/f/1"),
                metadata: proto::encode(&metadata("a", "x/a")),
                received: then,
            },
            Received {
                url: String::from("u2"),
                metadata: Vec::new(),
                received: then + Duration::from_secs(1),
            },
        ];
        let encoded = encode(&kept);
        assert_eq!(decode(&mut NotesReader(&encoded)), Some(kept));
        assert_eq!(
            decode(&mut NotesReader(&encoded[..encoded.len() - 1])),
            None
        );
        assert_eq!(decode(&mut NotesReader(&[])), Some(Vec::new()));
    }
}
