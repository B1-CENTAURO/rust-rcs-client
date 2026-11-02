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

//! What the device keeps besides MLS, with the MLS state: the messages it
//! could not decrypt, and those it sent encrypted, with the members of their
//! groups then (RCC.16 sections 10.2 to 10.4)
//!
//! A change to them is kept before anything it brings is given out, as the
//! MLS state is: a message lost or sent survives the device restarting.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::{self, MlsClient, MlsConversation};

use super::chat::{self, Chat};
use super::description::{self, Icon};
use super::file::{self, Received};
use super::lost::{self, Lost};
use super::sent::{self, Membership, Sent};
use super::store::{MlsStore, StoreError};

const LOG_TAG: &str = "e2ee";

/// Starts notes holding only messages not decrypted, as they were first kept
const NOTES_VERSION_LOST: u8 = 1;

/// Starts notes of sections, each a tag, its length on four bytes, then
/// what it holds
const NOTES_VERSION: u8 = 2;

const SECTION_LOST: u8 = 1;
const SECTION_SENT: u8 = 2;
const SECTION_MEMBERSHIPS: u8 = 3;
const SECTION_RECEIVED: u8 = 4;
const SECTION_ICONS: u8 = 5;
const SECTION_CHATS: u8 = 6;

/// What the device keeps besides MLS
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct NotesData {
    /// The messages not decrypted
    pub(super) lost: Vec<Lost>,
    /// The messages sent encrypted, the oldest first
    pub(super) sent: Vec<Sent>,
    /// The members of the groups when those were sent
    pub(super) memberships: Vec<Membership>,
    /// The keys of the files received encrypted, the oldest first
    pub(super) received: Vec<Received>,
    /// The encrypted icons of the groups
    pub(super) icons: Vec<Icon>,
    /// The encrypted 1-to-1 chats
    pub(super) chats: Vec<Chat>,
}

/// What the device keeps besides MLS, as the store keeps it
pub(super) struct Notes(Mutex<NotesData>);

impl Notes {
    /// Those `store` kept; none if it kept notes that cannot be read, as
    /// losing those is better than losing the MLS state they came with
    pub(super) fn kept_by(store: &MlsStore) -> Notes {
        let data = decode(&store.notes()).unwrap_or_else(|| {
            platform_log(LOG_TAG, "notes of the device not read, forgotten");
            NotesData::default()
        });
        Notes(Mutex::new(data))
    }

    /// What `read` reads of the notes
    pub(super) fn read<R>(&self, read: impl FnOnce(&NotesData) -> R) -> R {
        read(&self.0.lock().unwrap())
    }

    /// Changes the notes as `change` does, kept by `store` first; none
    /// changed if they cannot be
    pub(super) fn change<R>(
        &self,
        store: &MlsStore,
        change: impl FnOnce(&mut NotesData) -> R,
    ) -> Result<R, StoreError> {
        let mut data = self.0.lock().unwrap();
        let mut changed = data.clone();
        let result = change(&mut changed);
        if changed != *data {
            store.keep_notes(encode(&changed))?;
            *data = changed;
        }
        Ok(result)
    }

    /// Calls `mls` with the group `group_id` of `store` and the client, then
    /// changes the notes as `change` does with its result, both kept at once,
    /// or neither (see `MlsStore::with_conversation_and_notes()`)
    pub(super) fn change_with_conversation<T, R>(
        &self,
        store: &MlsStore,
        group_id: &[u8],
        mls: impl FnOnce(&mut MlsConversation, &MlsClient) -> mls::Result<T>,
        change: impl FnOnce(&mut NotesData, &T) -> R,
    ) -> Result<(T, R), StoreError> {
        let mut data = self.0.lock().unwrap();
        let mut changed = data.clone();
        let mut result = None;
        let made = store.with_conversation_and_notes(group_id, mls, |made| {
            result = Some(change(&mut changed, made));
            (changed != *data).then(|| encode(&changed))
        })?;
        *data = changed;
        // with the MLS call made, the change is
        Ok((made, result.expect("notes changed")))
    }
}

/// `bytes`, their length first on four bytes
pub(super) fn put(data: &mut Vec<u8>, bytes: &[u8]) {
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(bytes);
}

/// `time`, in seconds since the Unix epoch on eight bytes
pub(super) fn put_time(data: &mut Vec<u8>, time: SystemTime) {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|secs| secs.as_secs())
        .unwrap_or_default();
    data.extend_from_slice(&secs.to_be_bytes());
}

/// What is left to read of notes
pub(super) struct Reader<'a>(pub(super) &'a [u8]);

impl<'a> Reader<'a> {
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        (self.0.len() >= length).then(|| {
            let (bytes, rest) = self.0.split_at(length);
            self.0 = rest;
            bytes
        })
    }

    pub(super) fn byte(&mut self) -> Option<u8> {
        self.bytes(1).map(|bytes| bytes[0])
    }

    pub(super) fn flag(&mut self) -> Option<bool> {
        match self.byte()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.bytes(4)?.try_into().ok()?))
    }

    /// Bytes put with put()
    pub(super) fn vec(&mut self) -> Option<Vec<u8>> {
        let length = self.u32()? as usize;
        self.bytes(length).map(<[u8]>::to_vec)
    }

    pub(super) fn string(&mut self) -> Option<String> {
        String::from_utf8(self.vec()?).ok()
    }

    pub(super) fn time(&mut self) -> Option<SystemTime> {
        let secs = u64::from_be_bytes(self.bytes(8)?.try_into().ok()?);
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
    }
}

/// The notes holding `data`: none for none, else NOTES_VERSION, then a
/// section of each kind of record there is
fn encode(data: &NotesData) -> Vec<u8> {
    if *data == NotesData::default() {
        return Vec::new();
    }
    let mut notes = vec![NOTES_VERSION];
    let mut section = |tag: u8, body: Vec<u8>| {
        if !body.is_empty() {
            notes.push(tag);
            put(&mut notes, &body);
        }
    };
    section(SECTION_LOST, lost::encode(&data.lost));
    section(SECTION_SENT, sent::encode(&data.sent));
    section(
        SECTION_MEMBERSHIPS,
        sent::encode_memberships(&data.memberships),
    );
    section(SECTION_RECEIVED, file::encode(&data.received));
    section(SECTION_ICONS, description::encode(&data.icons));
    section(SECTION_CHATS, chat::encode(&data.chats));
    notes
}

/// What the notes `notes` hold; None if they cannot be read. Sections of a
/// kind not known are passed over.
fn decode(notes: &[u8]) -> Option<NotesData> {
    let Some((version, rest)) = notes.split_first() else {
        return Some(NotesData::default());
    };
    let mut data = NotesData::default();
    match *version {
        NOTES_VERSION_LOST => data.lost = lost::decode(&mut Reader(rest))?,
        NOTES_VERSION => {
            let mut reader = Reader(rest);
            while !reader.is_empty() {
                let tag = reader.byte()?;
                let body = reader.vec()?;
                let mut body = Reader(&body);
                match tag {
                    SECTION_LOST => data.lost = lost::decode(&mut body)?,
                    SECTION_SENT => data.sent = sent::decode(&mut body)?,
                    SECTION_MEMBERSHIPS => data.memberships = sent::decode_memberships(&mut body)?,
                    SECTION_RECEIVED => data.received = file::decode(&mut body)?,
                    SECTION_ICONS => data.icons = description::decode(&mut body)?,
                    SECTION_CHATS => data.chats = chat::decode(&mut body)?,
                    _ => {}
                }
            }
        }
        _ => return None,
    }
    Some(data)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use crate::messaging::cpm::encryption::FailedToDecrypt;

    use super::super::chat::Chat;
    use super::super::description::Icon;
    use super::super::file::Received;
    use super::super::lost::Lost;
    use super::super::sent::{Membership, Sent};
    use super::{decode, encode, NotesData, NOTES_VERSION_LOST};

    const BOB: &str = "tel:+491707654321";

    fn data() -> NotesData {
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        NotesData {
            lost: vec![Lost {
                conversation_id: String::from("group-1"),
                message_id: String::from("m1"),
                sender_uri: String::from(BOB),
                taken: then,
                to_tell: Some(FailedToDecrypt {
                    imdn: String::from("<imdn/>"),
                    sender_uri: String::from(BOB),
                    original_message_id: Some(String::from("m0")),
                }),
                told: false,
            }],
            sent: vec![Sent {
                conversation_id: String::from("group-1"),
                message_id: String::from("m2"),
                payload: b"payload".to_vec(),
                headers: vec![(b"From".to_vec(), b"<sip:alice>".to_vec())],
                disposition: b"negative-delivery".to_vec(),
                sent: then,
                membership: 7,
                resent: vec![(String::from("m3"), b"bob".to_vec())],
            }],
            memberships: vec![Membership {
                conversation_id: String::from("group-1"),
                id: 7,
                members: vec![(String::from(BOB), b"key".to_vec())],
            }],
            received: vec![Received {
                url: String::from("https://ftcs.example.com/f/1"),
                metadata: b"metadata".to_vec(),
                received: then,
            }],
            icons: vec![
                Icon {
                    conversation_id: String::from("group-1"),
                    url: String::from("https://ftcs.example.com/i/1"),
                    participant: Some(String::from(BOB)),
                },
                Icon {
                    conversation_id: String::from("group-2"),
                    url: String::from("https://ftcs.example.com/i/2"),
                    participant: None,
                },
            ],
            chats: vec![
                Chat {
                    contact: String::from(BOB),
                    group_id: String::from("chat-1"),
                    mls_opaque_token: Some(String::from("token-1")),
                },
                Chat {
                    contact: String::from("tel:+491701111111"),
                    group_id: String::from("chat-2"),
                    mls_opaque_token: None,
                },
            ],
        }
    }

    #[test]
    fn notes_are_read_as_they_were_kept() {
        let data = data();
        assert_eq!(decode(&encode(&data)), Some(data.clone()));
        assert_eq!(encode(&NotesData::default()), Vec::<u8>::new());
        assert_eq!(decode(&[]), Some(NotesData::default()));

        // those first kept, of messages not decrypted only
        let mut first = vec![NOTES_VERSION_LOST];
        first.extend_from_slice(&super::super::lost::encode(&data.lost));
        assert_eq!(
            decode(&first),
            Some(NotesData {
                lost: data.lost.clone(),
                ..NotesData::default()
            })
        );

        // a section of a kind not known passed over
        let mut later = encode(&data);
        later.push(9);
        later.extend_from_slice(&3u32.to_be_bytes());
        later.extend_from_slice(b"new");
        assert_eq!(decode(&later), Some(data.clone()));
    }

    #[test]
    fn notes_cut_or_of_another_version_are_not_read() {
        let notes = encode(&data());
        let mut another_version = notes.clone();
        another_version[0] = 3;
        let mut section_too_long = notes.clone();
        section_too_long[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        for notes in [
            notes[..notes.len() - 1].to_vec(),
            another_version,
            section_too_long,
        ] {
            assert_eq!(decode(&notes), None);
        }
    }
}
