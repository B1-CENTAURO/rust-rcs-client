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
//!
//! So too, as far as they can be kept, the control message of each group
//! the device waits for the Conversation Focus to take, where self-healing
//! and making new Eras of groups stand, where moving groups back to
//! encrypted stands, the KeyPackage Updates put off, where recovering the
//! Group Metadata keys of groups stands, the contacts found lately not to
//! take an encrypted 1-to-1 chat, the subjects and icons of groups that did
//! not open yet, and the keys of the files uploaded for the messages sending
//! them (RCC.16 sections 6.2.5, 8.1, 9.1.2.1, 9.5.4, 9.7.1, 10.1, 10.5, 11.1,
//! 11.2).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::{self, MlsClient, MlsConversation};

use super::chat::{self, Chat};
use super::description::{self, Icon, Unopened};
use super::device;
use super::file::{self, Received, Upload};
use super::heal::{self, Heal};
use super::lost::{self, Lost};
use super::metadata::{self, Recovery};
use super::sent::{self, Membership, Sent};
use super::store::{MlsStore, StoreError};
use super::upgrade::{self, GroupUse, UpgradeState};

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
const SECTION_CHAT_ACTIVITY: u8 = 7;
const SECTION_CONTROL_MESSAGES: u8 = 8;
const SECTION_HEALS: u8 = 9;
const SECTION_UPGRADES: u8 = 10;
const SECTION_GROUPS: u8 = 11;
const SECTION_REPLACEMENTS: u8 = 12;
const SECTION_RECOVERIES: u8 = 13;
const SECTION_UNENCRYPTED_CHATS: u8 = 14;
const SECTION_UNOPENED: u8 = 15;
const SECTION_UPLOADS: u8 = 16;

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
    /// By group, the Message-ID of the control message carrying the Commit
    /// of the device last sent, until the Conversation Focus takes it
    pub(super) control_messages: BTreeMap<String, String>,
    /// By group, where self-healing it and making its next Era stands
    pub(super) heals: BTreeMap<String, Heal>,
    /// By group, where moving it back to encrypted stands
    pub(super) upgrades: BTreeMap<String, UpgradeState>,
    /// By group, when it was last used and who takes part in it
    pub(super) groups: BTreeMap<String, GroupUse>,
    /// By group, until when its KeyPackage Update is put off
    pub(super) replacements: BTreeMap<String, SystemTime>,
    /// By group, where recovering its Group Metadata keys stands
    pub(super) recoveries: BTreeMap<String, Recovery>,
    /// By the tel URI of a contact, when it was found not to take an
    /// encrypted 1-to-1 chat
    pub(super) unencrypted_chats: BTreeMap<String, SystemTime>,
    /// By group, what did not open of its subject and icon
    pub(super) unopened: BTreeMap<String, Unopened>,
    /// The keys of the files uploaded, for the messages sending them, the
    /// oldest first
    pub(super) uploads: Vec<Upload>,
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

    /// Changes the notes as `change` does, kept by `store` if they can be:
    /// what the device does without after a restart, if it must, changed
    /// all the same
    pub(super) fn hold<R>(&self, store: &MlsStore, change: impl FnOnce(&mut NotesData) -> R) -> R {
        let mut data = self.0.lock().unwrap();
        let mut changed = data.clone();
        let result = change(&mut changed);
        if changed != *data {
            if let Err(e) = store.keep_notes(encode(&changed)) {
                platform_log(LOG_TAG, format!("notes of the device not kept: {:?}", e));
            }
            *data = changed;
        }
        result
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

/// `times`, their count first on four bytes, as Reader::times() reads them
pub(super) fn put_times(data: &mut Vec<u8>, times: &[SystemTime]) {
    data.extend_from_slice(&(times.len() as u32).to_be_bytes());
    for time in times {
        put_time(data, *time);
    }
}

/// `times`, each after its key, as decode_times_by() reads them
fn encode_times_by(times: &BTreeMap<String, SystemTime>) -> Vec<u8> {
    let mut data = Vec::new();
    for (key, time) in times {
        put(&mut data, key.as_bytes());
        put_time(&mut data, *time);
    }
    data
}

/// The times `reader` reads to its end, as encode_times_by() puts them; None
/// if they cannot be read
fn decode_times_by(reader: &mut Reader) -> Option<BTreeMap<String, SystemTime>> {
    let mut times = BTreeMap::new();
    while !reader.is_empty() {
        let key = reader.string()?;
        times.insert(key, reader.time()?);
    }
    Some(times)
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

    /// Times put with put_times()
    pub(super) fn times(&mut self) -> Option<Vec<SystemTime>> {
        let count = self.u32()?;
        (0..count).map(|_| self.time()).collect()
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
    section(SECTION_CHAT_ACTIVITY, chat::encode_activity(&data.chats));
    section(
        SECTION_CONTROL_MESSAGES,
        device::encode_control_messages(&data.control_messages),
    );
    section(SECTION_HEALS, heal::encode(&data.heals));
    section(SECTION_UPGRADES, upgrade::encode(&data.upgrades));
    section(SECTION_GROUPS, upgrade::encode_groups(&data.groups));
    section(SECTION_REPLACEMENTS, encode_times_by(&data.replacements));
    section(SECTION_RECOVERIES, metadata::encode(&data.recoveries));
    section(
        SECTION_UNENCRYPTED_CHATS,
        encode_times_by(&data.unencrypted_chats),
    );
    section(
        SECTION_UNOPENED,
        description::encode_unopened(&data.unopened),
    );
    section(SECTION_UPLOADS, file::encode_uploads(&data.uploads));
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
            let mut activity = Vec::new();
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
                    SECTION_CHAT_ACTIVITY => activity = chat::decode_activity(&mut body)?,
                    SECTION_CONTROL_MESSAGES => {
                        data.control_messages = device::decode_control_messages(&mut body)?
                    }
                    SECTION_HEALS => data.heals = heal::decode(&mut body)?,
                    SECTION_UPGRADES => data.upgrades = upgrade::decode(&mut body)?,
                    SECTION_GROUPS => data.groups = upgrade::decode_groups(&mut body)?,
                    SECTION_REPLACEMENTS => data.replacements = decode_times_by(&mut body)?,
                    SECTION_RECOVERIES => data.recoveries = metadata::decode(&mut body)?,
                    SECTION_UNENCRYPTED_CHATS => {
                        data.unencrypted_chats = decode_times_by(&mut body)?
                    }
                    SECTION_UNOPENED => data.unopened = description::decode_unopened(&mut body)?,
                    SECTION_UPLOADS => data.uploads = file::decode_uploads(&mut body)?,
                    _ => {}
                }
            }
            for chat in data.chats.iter_mut() {
                chat.active = activity
                    .iter()
                    .find(|(group_id, _)| *group_id == chat.group_id)
                    .map(|(_, active)| *active);
            }
        }
        _ => return None,
    }
    Some(data)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime};

    use rust_rcs_core::mls::rcs::proto::{self, EndMlsReason};

    use crate::messaging::cpm::encryption::FailedToDecrypt;

    use super::super::chat::Chat;
    use super::super::description::{Icon, Unopened};
    use super::super::file::{Received, Upload};
    use super::super::heal::{Heal, NextEra, Ongoing};
    use super::super::lost::Lost;
    use super::super::metadata::Recovery;
    use super::super::sent::{Membership, Sent};
    use super::super::upgrade::{GroupUse, UpgradeState};
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
                    active: Some(then),
                },
                Chat {
                    contact: String::from("tel:+491701111111"),
                    group_id: String::from("chat-2"),
                    mls_opaque_token: None,
                    active: None,
                },
            ],
            control_messages: BTreeMap::from([
                (String::from("group-1"), String::from("c1")),
                (String::from("group-2"), String::from("c2")),
            ]),
            heals: BTreeMap::from([
                (
                    String::from("group-1"),
                    Heal {
                        wanted: true,
                        ongoing: None,
                        attempts: vec![then, then + Duration::from_secs(60)],
                        failed: true,
                        singleton: Some(EndMlsReason::OutgoingCommitFailed),
                        eras: vec![then],
                    },
                ),
                (
                    String::from("group-2"),
                    Heal {
                        failed: true,
                        eras: vec![then],
                        ..Heal::default()
                    },
                ),
            ]),
            upgrades: BTreeMap::from([
                (
                    String::from("group-1"),
                    UpgradeState {
                        ended: Some(then),
                        attempted: None,
                        incapable: Some(then + Duration::from_secs(60)),
                        without_group: true,
                        restarting: true,
                    },
                ),
                (
                    String::from("group-2"),
                    UpgradeState {
                        attempted: Some(then),
                        restarting: true,
                        ..UpgradeState::default()
                    },
                ),
            ]),
            groups: BTreeMap::from([
                (
                    String::from("group-1"),
                    GroupUse {
                        used: Some(then),
                        participants: vec![
                            String::from("sip:alice@example.com"),
                            String::from(BOB),
                        ],
                        refresh_at: None,
                    },
                ),
                (
                    String::from("group-2"),
                    GroupUse {
                        used: None,
                        participants: Vec::new(),
                        refresh_at: Some(then),
                    },
                ),
            ]),
            replacements: BTreeMap::from([
                (String::from("group-1"), then),
                (String::from("group-2"), then + Duration::from_secs(3600)),
            ]),
            recoveries: BTreeMap::from([
                (
                    String::from("group-1"),
                    Recovery {
                        check: true,
                        token_mismatch: false,
                        commits: vec![then, then + Duration::from_secs(60)],
                    },
                ),
                (
                    String::from("group-2"),
                    Recovery {
                        check: false,
                        token_mismatch: true,
                        commits: Vec::new(),
                    },
                ),
            ]),
            unencrypted_chats: BTreeMap::from([
                (String::from(BOB), then),
                (String::from("tel:+491701111111"), then),
            ]),
            unopened: BTreeMap::from([
                (
                    String::from("group-1"),
                    Unopened {
                        subject: Some((b"ciphertext".to_vec(), Some(String::from(BOB)))),
                        icon: Some(b"tag".to_vec()),
                    },
                ),
                (
                    String::from("group-2"),
                    Unopened {
                        subject: Some((b"another".to_vec(), None)),
                        icon: None,
                    },
                ),
                (
                    String::from("group-3"),
                    Unopened {
                        subject: None,
                        icon: Some(Vec::new()),
                    },
                ),
            ]),
            uploads: vec![
                Upload {
                    conversation_id: String::from("group-1"),
                    url: String::from("https://ftcs.example.com/f/1"),
                    file_info: proto::FileInfo {
                        file: Some(proto::FileMetadata {
                            file_name: String::from("picture.jpg"),
                            content_type: String::from("image/jpeg"),
                            encryption_info: None,
                        }),
                        ..proto::FileInfo::default()
                    },
                    uploaded: then,
                },
                Upload {
                    conversation_id: String::from(BOB),
                    url: String::from("https://ftcs.example.com/f/2"),
                    file_info: proto::FileInfo::default(),
                    uploaded: then,
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

        // those kept before the activity of chats was, their chats of none
        let mut before = vec![super::NOTES_VERSION];
        before.push(super::SECTION_CHATS);
        super::put(&mut before, &super::super::chat::encode(&data.chats));
        let mut chats = data.chats.clone();
        chats[0].active = None;
        assert_eq!(
            decode(&before),
            Some(NotesData {
                chats,
                ..NotesData::default()
            })
        );
        // and the activity of a chat not kept passed over
        let mut stray = before.clone();
        stray.push(super::SECTION_CHAT_ACTIVITY);
        let mut activity = Vec::new();
        super::put(&mut activity, b"chat-9");
        super::put_time(&mut activity, SystemTime::UNIX_EPOCH);
        super::put(&mut stray, &activity);
        assert_eq!(decode(&stray), decode(&before));

        // a section of a kind not known passed over
        let mut later = encode(&data);
        later.push(99);
        later.extend_from_slice(&3u32.to_be_bytes());
        later.extend_from_slice(b"new");
        assert_eq!(decode(&later), Some(data.clone()));
    }

    #[test]
    fn what_was_being_done_to_a_group_as_the_device_stopped_is_due_again() {
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let heal = |ongoing| Heal {
            ongoing: Some(ongoing),
            attempts: vec![then],
            ..Heal::default()
        };
        let kept = NotesData {
            heals: BTreeMap::from([
                (String::from("healing"), heal(Ongoing::Healing)),
                (
                    String::from("making-era"),
                    heal(Ongoing::MakingEra(NextEra::Encrypted)),
                ),
                (
                    String::from("making-singleton"),
                    heal(Ongoing::MakingEra(NextEra::Singleton(
                        EndMlsReason::CannotFetchKeypackages,
                    ))),
                ),
            ]),
            ..NotesData::default()
        };
        let read = decode(&encode(&kept)).unwrap();
        let attempted = Heal {
            attempts: vec![then],
            ..Heal::default()
        };
        assert_eq!(
            read.heals,
            BTreeMap::from([
                (
                    String::from("healing"),
                    Heal {
                        wanted: true,
                        ..attempted.clone()
                    }
                ),
                (
                    String::from("making-era"),
                    Heal {
                        failed: true,
                        ..attempted.clone()
                    }
                ),
                (
                    String::from("making-singleton"),
                    Heal {
                        singleton: Some(EndMlsReason::CannotFetchKeypackages),
                        ..attempted
                    }
                ),
            ])
        );
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
