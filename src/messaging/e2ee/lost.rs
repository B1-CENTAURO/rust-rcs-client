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

//! The messages of encrypted group chats that could not be decrypted: their
//! senders told so once the group is healed, and the messages taken when they
//! are re-sent (RCC.16 sections 10.2, 10.4)
//!
//! They are kept with the MLS state, as the notes of the device, for a
//! message to be taken when it is re-sent after the device restarted. A
//! change to them is kept before anything it brings is given out.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::cpim::CPIMInfo;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::imdn::notification::{Dispositions, Notification, Status};
use rust_rcs_core::mls::rcs::imdn::negative_delivery;
use rust_rcs_core::mls::rcs::ClientFailureReason;
use rust_rcs_core::mls::{Credential, ErrorKind};

use crate::messaging::cpm::encryption::FailedToDecrypt;

use super::device::{is_of, participant_tel_uri, E2eeDevice};
use super::store::{MlsStore, StoreError};

const LOG_TAG: &str = "e2ee";

/// How long a message not decrypted is kept note of: its sender does not
/// re-send it once it is older (RCC.16 section 10.3)
const LOST_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How many messages not decrypted are kept note of at most, the oldest
/// forgotten first
const LOST_MOST: usize = 1024;

/// Starts the notes of the device, which hold the messages not decrypted
const NOTES_VERSION: u8 = 1;

/// A message not decrypted
#[derive(Clone, Debug, PartialEq)]
struct Lost {
    conversation_id: String,
    /// The Message-ID of the Original Message
    message_id: String,
    /// The URI of the participant who sent it, as its CPIM From tells
    sender_uri: String,
    /// When it was taken
    taken: SystemTime,
    /// The negative delivery to send of it, of the Original Message or of the
    /// last Re-Sent Message of it whose inner layer was not decrypted, until
    /// it is sent
    to_tell: Option<FailedToDecrypt>,
    /// Whether one was sent, without which a Re-Sent Message of it is not
    /// taken (section 10.4)
    told: bool,
}

/// The messages not decrypted, of every group, as the store keeps them
pub(super) struct LostMessages(Mutex<Vec<Lost>>);

impl LostMessages {
    /// Those `store` kept; none if it kept notes that cannot be read, as
    /// losing those is better than losing the MLS state they came with
    pub(super) fn kept_by(store: &MlsStore) -> LostMessages {
        let lost = decode(&store.notes()).unwrap_or_else(|| {
            platform_log(LOG_TAG, "messages not decrypted not read, forgotten");
            Vec::new()
        });
        LostMessages(Mutex::new(lost))
    }

    /// Changes the messages as `change` does, kept by `store` first; none
    /// changed if they cannot be
    fn change<R>(
        &self,
        store: &MlsStore,
        change: impl FnOnce(&mut Vec<Lost>) -> R,
    ) -> Result<R, StoreError> {
        let mut lost = self.0.lock().unwrap();
        let mut changed = lost.clone();
        let result = change(&mut changed);
        if changed != *lost {
            store.keep_notes(encode(&changed))?;
            *lost = changed;
        }
        Ok(result)
    }

    /// Whether any message of the group `conversation_id` is as `what` tells
    fn any(&self, conversation_id: &str, what: impl Fn(&Lost) -> bool) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|lost| lost.conversation_id == conversation_id && what(lost))
    }

    /// Takes note of the message `message_id` of the group `conversation_id`
    /// not being decrypted, sent at `datetime` by `sender_uri`, its sender to
    /// be told so; once only
    fn lose(
        &self,
        store: &MlsStore,
        conversation_id: &str,
        message_id: &str,
        sender_uri: &str,
        datetime: &str,
        now: SystemTime,
    ) -> Result<(), StoreError> {
        self.change(store, |lost| {
            lost.retain(|lost| {
                now.duration_since(lost.taken)
                    .is_ok_and(|age| age <= LOST_FOR)
            });
            if lost.iter().any(|lost| {
                lost.conversation_id == conversation_id && lost.message_id == message_id
            }) {
                return;
            }
            if lost.len() == LOST_MOST {
                lost.remove(0);
            }
            lost.push(Lost {
                conversation_id: String::from(conversation_id),
                message_id: String::from(message_id),
                sender_uri: String::from(sender_uri),
                taken: now,
                to_tell: Some(FailedToDecrypt {
                    imdn: negative_delivery(
                        message_id,
                        datetime,
                        ClientFailureReason::FailureToDecrypt,
                    ),
                    sender_uri: String::from(sender_uri),
                    original_message_id: None,
                }),
                told: false,
            });
        })
    }

    /// Where the message `original_message_id` of the group
    /// `conversation_id` is, told as not decrypted to its sender, who
    /// `is_sender` tells
    fn told_of(
        lost: &[Lost],
        conversation_id: &str,
        original_message_id: &str,
        is_sender: impl Fn(&str) -> bool,
    ) -> Option<usize> {
        lost.iter().position(|lost| {
            lost.conversation_id == conversation_id
                && lost.message_id == original_message_id
                && lost.told
                && is_sender(&lost.sender_uri)
        })
    }

    /// Takes note of a Re-Sent Message `message_id` of the message
    /// `original_message_id`, sent at `datetime` by whom `is_sender` tells,
    /// whose inner layer was not decrypted, its sender to be told so; false
    /// if this client did not ask for it
    fn lose_resent(
        &self,
        store: &MlsStore,
        conversation_id: &str,
        original_message_id: &str,
        message_id: &str,
        datetime: &str,
        is_sender: impl Fn(&str) -> bool,
    ) -> Result<bool, StoreError> {
        self.change(store, |lost| {
            let Some(told_of) =
                Self::told_of(lost, conversation_id, original_message_id, is_sender)
            else {
                return false;
            };
            let lost = &mut lost[told_of];
            lost.to_tell = Some(FailedToDecrypt {
                imdn: negative_delivery(
                    message_id,
                    datetime,
                    ClientFailureReason::InnerResentMessageFailureToDecrypt,
                ),
                sender_uri: lost.sender_uri.clone(),
                original_message_id: Some(String::from(original_message_id)),
            });
            true
        })
    }

    /// Lets go of the message `original_message_id` of the group
    /// `conversation_id`, re-sent by whom `is_sender` tells; false if this
    /// client did not ask for it
    fn found(
        &self,
        store: &MlsStore,
        conversation_id: &str,
        original_message_id: &str,
        is_sender: impl Fn(&str) -> bool,
    ) -> Result<bool, StoreError> {
        self.change(store, |lost| {
            let Some(found) = Self::told_of(lost, conversation_id, original_message_id, is_sender)
            else {
                return false;
            };
            lost.remove(found);
            true
        })
    }

    /// The negative deliveries to send of the group `conversation_id`, taken
    /// as sent
    fn to_tell(
        &self,
        store: &MlsStore,
        conversation_id: &str,
    ) -> Result<Vec<FailedToDecrypt>, StoreError> {
        if !self.any(conversation_id, |lost| lost.to_tell.is_some()) {
            return Ok(Vec::new());
        }
        self.change(store, |lost| {
            lost.iter_mut()
                .filter(|lost| lost.conversation_id == conversation_id)
                .filter_map(|lost| {
                    let to_tell = lost.to_tell.take()?;
                    lost.told = true;
                    Some(to_tell)
                })
                .collect()
        })
    }

    /// Lets go of the messages of the group `conversation_id`
    fn forget(&self, store: &MlsStore, conversation_id: &str) -> Result<(), StoreError> {
        if !self.any(conversation_id, |_| true) {
            return Ok(());
        }
        self.change(store, |lost| {
            lost.retain(|lost| lost.conversation_id != conversation_id)
        })
    }
}

/// `bytes`, their length first on four bytes
fn put(data: &mut Vec<u8>, bytes: &[u8]) {
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(bytes);
}

/// The notes of the device holding the messages `lost`: none for none, else
/// NOTES_VERSION, then each message
fn encode(lost: &[Lost]) -> Vec<u8> {
    if lost.is_empty() {
        return Vec::new();
    }
    let mut data = vec![NOTES_VERSION];
    for lost in lost {
        put(&mut data, lost.conversation_id.as_bytes());
        put(&mut data, lost.message_id.as_bytes());
        put(&mut data, lost.sender_uri.as_bytes());
        let taken = lost
            .taken
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|taken| taken.as_secs())
            .unwrap_or_default();
        data.extend_from_slice(&taken.to_be_bytes());
        data.push(u8::from(lost.told));
        match &lost.to_tell {
            None => data.push(0),
            Some(to_tell) => {
                data.push(1);
                put(&mut data, to_tell.imdn.as_bytes());
                put(&mut data, to_tell.sender_uri.as_bytes());
                match &to_tell.original_message_id {
                    None => data.push(0),
                    Some(original_message_id) => {
                        data.push(1);
                        put(&mut data, original_message_id.as_bytes());
                    }
                }
            }
        }
    }
    data
}

/// What is left to read of notes
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        (self.0.len() >= length).then(|| {
            let (bytes, rest) = self.0.split_at(length);
            self.0 = rest;
            bytes
        })
    }

    fn byte(&mut self) -> Option<u8> {
        self.bytes(1).map(|bytes| bytes[0])
    }

    fn flag(&mut self) -> Option<bool> {
        match self.byte()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        let length = u32::from_be_bytes(self.bytes(4)?.try_into().ok()?) as usize;
        String::from_utf8(self.bytes(length)?.to_vec()).ok()
    }

    fn secs(&mut self) -> Option<SystemTime> {
        let secs = u64::from_be_bytes(self.bytes(8)?.try_into().ok()?);
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
    }
}

/// The messages the notes of the device `data` hold; None if they cannot be
/// read
fn decode(data: &[u8]) -> Option<Vec<Lost>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let mut reader = Reader(data);
    if reader.byte()? != NOTES_VERSION {
        return None;
    }
    let mut lost = Vec::new();
    while !reader.0.is_empty() {
        let conversation_id = reader.string()?;
        let message_id = reader.string()?;
        let sender_uri = reader.string()?;
        let taken = reader.secs()?;
        let told = reader.flag()?;
        let to_tell = match reader.flag()? {
            false => None,
            true => Some(FailedToDecrypt {
                imdn: reader.string()?,
                sender_uri: reader.string()?,
                original_message_id: match reader.flag()? {
                    false => None,
                    true => Some(reader.string()?),
                },
            }),
        };
        lost.push(Lost {
            conversation_id,
            message_id,
            sender_uri,
            taken,
            to_tell,
            told,
        });
    }
    Some(lost)
}

/// Whether `sender` is of the participant `sender_uri`, as a CPIM From tells
/// it
fn sent_by(sender: &Credential, sender_uri: &str) -> bool {
    participant_tel_uri(std::iter::once(sender_uri), None).is_some_and(|told| is_of(sender, &told))
}

/// The URI of the sender of the CPIM message `cpim_info` tells of
fn sender_uri(cpim_info: &CPIMInfo) -> Option<String> {
    let uri = cpim_info.from_uri.as_ref()?;
    Some(
        String::from_utf8_lossy(&uri.string_representation_without_query_and_fragment())
            .into_owned(),
    )
}

impl E2eeDevice {
    /// Takes note of the message of the group `conversation_id` that
    /// `cpim_info` tells of not being decrypted, its sender to be told so
    /// once the group is healed, if it asked to be told of a negative
    /// delivery (RCC.16 sections 7.5.6, 10.2)
    pub(super) fn lose_message(&self, conversation_id: &str, cpim_info: &CPIMInfo) {
        let asks = cpim_info.disposition_notification.is_some_and(|value| {
            Dispositions::parse(value).ask_for(Notification::Delivery, Status::Failed)
        });
        let Some(sender_uri) = sender_uri(cpim_info).filter(|_| asks) else {
            return;
        };
        if let Err(e) = self.lost().lose(
            self.store(),
            conversation_id,
            &String::from_utf8_lossy(cpim_info.imdn_message_id),
            &sender_uri,
            &String::from_utf8_lossy(cpim_info.date),
            self.store().now(),
        ) {
            platform_log(LOG_TAG, format!("message not decrypted not kept: {:?}", e));
        }
    }

    /// Takes note of the Re-Sent Message of the group `conversation_id`
    /// that `cpim_info` tells of, of the message `original_message_id`,
    /// sent by `sender`, not being decrypted, its sender to be told so;
    /// false if this client did not ask for it (RCC.16 sections 10.2, 10.4)
    pub(super) fn lose_resent(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        original_message_id: &str,
        sender: &Credential,
    ) -> Result<bool, StoreError> {
        self.lost().lose_resent(
            self.store(),
            conversation_id,
            original_message_id,
            &String::from_utf8_lossy(cpim_info.imdn_message_id),
            &String::from_utf8_lossy(cpim_info.date),
            |sender_uri| sent_by(sender, sender_uri),
        )
    }

    /// Whether the message `original_message_id` of the group
    /// `conversation_id`, re-sent by `sender`, is one this client asked for,
    /// which is let go of then (RCC.16 section 10.4)
    pub(super) fn found_resent(
        &self,
        conversation_id: &str,
        original_message_id: &str,
        sender: &Credential,
    ) -> Result<bool, StoreError> {
        self.lost().found(
            self.store(),
            conversation_id,
            original_message_id,
            |sender_uri| sent_by(sender, sender_uri),
        )
    }

    /// The negative deliveries to send in the group chat `conversation_id`,
    /// telling senders that messages of theirs could not be decrypted, once
    /// the group is encrypted and in step with its Conversation Focus:
    /// not while it is to be self-healed or being, nor while a control
    /// message of this client waits for the Focus, as the External Commit
    /// healing it does (RCC.16 sections 7.7.2.2, 10.1.1, 10.2, 10.4). Those of
    /// a group moved to unencrypted, or let go of, are forgotten, its
    /// messages not to be re-sent unencrypted (section 10.3). None are given
    /// out unless their being sent is kept.
    pub fn failed_to_decrypt(&self, conversation_id: &str) -> Vec<FailedToDecrypt> {
        if self.encryption_ended(conversation_id) {
            self.forget_lost(conversation_id);
            return Vec::new();
        }
        if self.heals().ongoing(conversation_id)
            || self.needs_healing(conversation_id)
            || self
                .control_messages()
                .lock()
                .unwrap()
                .contains_key(conversation_id)
        {
            return Vec::new();
        }
        let pending = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                conversation.has_pending_commit()
            });
        match pending {
            Ok(false) => self
                .lost()
                .to_tell(self.store(), conversation_id)
                .unwrap_or_else(|e| {
                    platform_log(LOG_TAG, format!("negative deliveries not kept: {:?}", e));
                    Vec::new()
                }),
            Err(StoreError::Mls(ErrorKind::UnknownGroup)) => {
                self.forget_lost(conversation_id);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn forget_lost(&self, conversation_id: &str) {
        if let Err(e) = self.lost().forget(self.store(), conversation_id) {
            platform_log(
                LOG_TAG,
                format!("messages not decrypted not let go of: {:?}", e),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    use rust_rcs_core::mls::{Credential, CredentialValidator, MlsConfig};

    use crate::messaging::cpm::encryption::FailedToDecrypt;

    use super::super::store::{MlsStore, StoreError};
    use super::{decode, encode, Lost, LostMessages, LOST_FOR, LOST_MOST};

    const BOB: &str = "tel:+491707654321";

    struct AllowAll;

    impl CredentialValidator for AllowAll {
        fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
            true
        }
    }

    /// The state the app last kept, and whether it refuses to keep any
    #[derive(Default)]
    struct App {
        last: Mutex<Vec<u8>>,
        refusing: AtomicBool,
    }

    fn store(app: &Arc<App>) -> MlsStore {
        let app = Arc::clone(app);
        MlsStore::new(
            MlsConfig::default(),
            Arc::new(AllowAll),
            Box::new(move |state| {
                if app.refusing.load(Ordering::SeqCst) {
                    return false;
                }
                *app.last.lock().unwrap() = state.to_vec();
                true
            }),
        )
    }

    fn told(lost: &LostMessages, store: &MlsStore, conversation_id: &str) -> Vec<String> {
        lost.to_tell(store, conversation_id)
            .unwrap()
            .into_iter()
            .map(|told| told.imdn)
            .collect()
    }

    const THEN: Duration = Duration::from_secs(1_000_000_000);

    #[test]
    fn a_message_lost_is_told_of_once_and_taken_once_re_sent() {
        let app = Arc::new(App::default());
        let store = store(&app);
        let lost = LostMessages::kept_by(&store);
        let now = SystemTime::UNIX_EPOCH + THEN;
        for conversation_id in ["group-1", "group-1", "group-2"] {
            lost.lose(
                &store,
                conversation_id,
                "m1",
                BOB,
                "2026-10-25T12:00:00Z",
                now,
            )
            .unwrap();
        }

        // by group, once
        assert_eq!(lost.found(&store, "group-1", "m1", |_| true), Ok(false));
        assert_eq!(told(&lost, &store, "group-1").len(), 1);
        assert_eq!(told(&lost, &store, "group-1").len(), 0);
        // by whom it was from
        assert_eq!(
            lost.found(&store, "group-1", "m1", |sender| sender != BOB),
            Ok(false)
        );
        assert_eq!(
            lost.found(&store, "group-1", "m1", |sender| sender == BOB),
            Ok(true)
        );
        assert_eq!(lost.found(&store, "group-1", "m1", |_| true), Ok(false));
        assert_eq!(told(&lost, &store, "group-2").len(), 1);
        lost.forget(&store, "group-2").unwrap();
        assert_eq!(lost.found(&store, "group-2", "m1", |_| true), Ok(false));
    }

    #[test]
    fn messages_lost_are_kept_for_30_days_and_1024_at_most() {
        let app = Arc::new(App::default());
        let store = store(&app);
        let lost = LostMessages::kept_by(&store);
        let then = SystemTime::UNIX_EPOCH + THEN;
        lost.lose(&store, "group-1", "old", BOB, "", then).unwrap();
        lost.lose(
            &store,
            "group-1",
            "recent",
            BOB,
            "",
            then + Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(told(&lost, &store, "group-1").len(), 2);

        // the sender re-sends none older (RCC.16 section 10.3)
        lost.lose(
            &store,
            "group-1",
            "new",
            BOB,
            "",
            then + LOST_FOR + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(lost.found(&store, "group-1", "old", |_| true), Ok(false));
        assert_eq!(lost.found(&store, "group-1", "recent", |_| true), Ok(true));

        // the oldest forgotten first
        let lost = LostMessages::kept_by(&store);
        lost.forget(&store, "group-1").unwrap();
        for n in 0..=LOST_MOST {
            lost.lose(&store, "group-1", &format!("m{}", n), BOB, "", then)
                .unwrap();
        }
        assert_eq!(told(&lost, &store, "group-1").len(), LOST_MOST);
        assert_eq!(lost.found(&store, "group-1", "m0", |_| true), Ok(false));
        assert_eq!(lost.found(&store, "group-1", "m1", |_| true), Ok(true));
    }

    #[test]
    fn messages_lost_are_kept_with_the_state_of_the_device() {
        let app = Arc::new(App::default());
        let store = store(&app);
        let lost = LostMessages::kept_by(&store);
        let then = SystemTime::UNIX_EPOCH + THEN;
        lost.lose(&store, "group-1", "m1", BOB, "2026-10-25T12:00:00Z", then)
            .unwrap();
        lost.lose(&store, "group-1", "m2", BOB, "2026-10-25T12:00:01Z", then)
            .unwrap();
        assert_eq!(told(&lost, &store, "group-1").len(), 2);
        assert_eq!(
            lost.lose_resent(
                &store,
                "group-1",
                "m2",
                "m3",
                "2026-10-25T12:05:00Z",
                |_| true
            ),
            Ok(true)
        );

        // as they are, once the state is restored
        let again = self::store(&app);
        again.restore(&app.last.lock().unwrap()).unwrap();
        let restored = LostMessages::kept_by(&again);
        assert_eq!(*restored.0.lock().unwrap(), *lost.0.lock().unwrap());
        let resent = restored.to_tell(&again, "group-1").unwrap();
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0].original_message_id.as_deref(), Some("m2"));
        assert_eq!(restored.found(&again, "group-1", "m1", |_| true), Ok(true));

        // and changes the app does not keep are not made
        app.refusing.store(true, Ordering::SeqCst);
        assert_eq!(
            restored.found(&again, "group-1", "m2", |_| true),
            Err(StoreError::NotSaved)
        );
        assert_eq!(
            restored.lose(&again, "group-1", "m4", BOB, "", then),
            Err(StoreError::NotSaved)
        );
        app.refusing.store(false, Ordering::SeqCst);
        assert_eq!(restored.found(&again, "group-1", "m4", |_| true), Ok(false));
        assert_eq!(told(&restored, &again, "group-1"), Vec::<String>::new());
        assert_eq!(restored.found(&again, "group-1", "m2", |_| true), Ok(true));
        assert!(again.notes().is_empty(), "none left, none kept");
    }

    #[test]
    fn notes_that_cannot_be_read_have_no_message() {
        let then = SystemTime::UNIX_EPOCH + THEN;
        let lost = vec![
            Lost {
                conversation_id: String::from("group-1"),
                message_id: String::from("m1"),
                sender_uri: String::from(BOB),
                taken: then,
                to_tell: None,
                told: true,
            },
            Lost {
                conversation_id: String::from("group-2"),
                message_id: String::from("m2"),
                sender_uri: String::from(BOB),
                taken: then + Duration::from_secs(1),
                to_tell: Some(FailedToDecrypt {
                    imdn: String::from("<imdn/>"),
                    sender_uri: String::from(BOB),
                    original_message_id: Some(String::from("m0")),
                }),
                told: false,
            },
        ];
        let notes = encode(&lost);
        assert_eq!(decode(&notes), Some(lost));
        assert_eq!(encode(&[]), Vec::<u8>::new());
        assert_eq!(decode(&[]), Some(Vec::new()));

        // cut, of another version, or with a flag that is none
        let mut another_version = notes.clone();
        another_version[0] = 2;
        // the told flag of the first, after the version, its strings and time
        let told_at = 1 + (4 + "group-1".len()) + (4 + "m1".len()) + (4 + BOB.len()) + 8;
        assert_eq!(notes[told_at], 1);
        let mut not_a_flag = notes.clone();
        not_a_flag[told_at] = 2;
        for notes in [
            notes[..notes.len() - 1].to_vec(),
            another_version,
            not_a_flag,
        ] {
            assert_eq!(decode(&notes), None);
        }

        // and none taken from a state holding such notes
        let app = Arc::new(App::default());
        let store = store(&app);
        store.keep_notes(vec![2, 0]).unwrap();
        let lost = LostMessages::kept_by(&store);
        assert!(lost.0.lock().unwrap().is_empty());
    }
}
