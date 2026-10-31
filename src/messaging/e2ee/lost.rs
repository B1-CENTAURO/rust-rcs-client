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

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::cpim::CPIMInfo;
use rust_rcs_core::imdn::notification::{Dispositions, Notification, Status};
use rust_rcs_core::mls::rcs::imdn::negative_delivery;
use rust_rcs_core::mls::rcs::ClientFailureReason;
use rust_rcs_core::mls::{Credential, ErrorKind};

use crate::messaging::cpm::encryption::FailedToDecrypt;

use super::device::{is_of, participant_tel_uri, E2eeDevice};
use super::store::StoreError;

/// How long a message not decrypted is kept note of: its sender does not
/// re-send it once it is older (RCC.16 section 10.3)
const LOST_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How many messages not decrypted are kept note of at most, the oldest
/// forgotten first
const LOST_MOST: usize = 1024;

/// A message not decrypted
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

/// The messages not decrypted, of every group
#[derive(Default)]
pub(super) struct LostMessages(Mutex<Vec<Lost>>);

impl LostMessages {
    /// Takes note of the message `message_id` of the group `conversation_id`
    /// not being decrypted, sent at `datetime` by `sender_uri`, its sender to
    /// be told so; once only
    fn lose(
        &self,
        conversation_id: &str,
        message_id: &str,
        sender_uri: &str,
        datetime: &str,
        now: SystemTime,
    ) {
        let mut lost = self.0.lock().unwrap();
        lost.retain(|lost| {
            now.duration_since(lost.taken)
                .is_ok_and(|age| age <= LOST_FOR)
        });
        if lost
            .iter()
            .any(|lost| lost.conversation_id == conversation_id && lost.message_id == message_id)
        {
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
        conversation_id: &str,
        original_message_id: &str,
        message_id: &str,
        datetime: &str,
        is_sender: impl Fn(&str) -> bool,
    ) -> bool {
        let mut lost = self.0.lock().unwrap();
        let Some(told_of) = Self::told_of(&lost, conversation_id, original_message_id, is_sender)
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
    }

    /// Lets go of the message `original_message_id` of the group
    /// `conversation_id`, re-sent by whom `is_sender` tells; false if this
    /// client did not ask for it
    fn found(
        &self,
        conversation_id: &str,
        original_message_id: &str,
        is_sender: impl Fn(&str) -> bool,
    ) -> bool {
        let mut lost = self.0.lock().unwrap();
        let Some(found) = Self::told_of(&lost, conversation_id, original_message_id, is_sender)
        else {
            return false;
        };
        lost.remove(found);
        true
    }

    /// The negative deliveries to send of the group `conversation_id`, taken
    /// as sent
    fn to_tell(&self, conversation_id: &str) -> Vec<FailedToDecrypt> {
        let mut lost = self.0.lock().unwrap();
        lost.iter_mut()
            .filter(|lost| lost.conversation_id == conversation_id)
            .filter_map(|lost| {
                let to_tell = lost.to_tell.take()?;
                lost.told = true;
                Some(to_tell)
            })
            .collect()
    }

    /// Lets go of the messages of the group `conversation_id`
    fn forget(&self, conversation_id: &str) {
        self.0
            .lock()
            .unwrap()
            .retain(|lost| lost.conversation_id != conversation_id);
    }
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
        self.lost().lose(
            conversation_id,
            &String::from_utf8_lossy(cpim_info.imdn_message_id),
            &sender_uri,
            &String::from_utf8_lossy(cpim_info.date),
            self.store().now(),
        );
    }

    /// Takes note of the Re-Sent Message of the group `conversation_id`
    /// that `cpim_info` tells of, of the message `original_message_id`,
    /// sent by `sender`, not being decrypted, its sender to be told so, if
    /// this client asked for it (RCC.16 sections 10.2, 10.4)
    pub(super) fn lose_resent(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        original_message_id: &str,
        sender: &Credential,
    ) -> bool {
        self.lost().lose_resent(
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
    ) -> bool {
        self.lost()
            .found(conversation_id, original_message_id, |sender_uri| {
                sent_by(sender, sender_uri)
            })
    }

    /// The negative deliveries to send in the group chat `conversation_id`,
    /// telling senders that messages of theirs could not be decrypted, once
    /// the group is encrypted and in step with its Conversation Focus:
    /// not while it is to be self-healed or being, nor while a control
    /// message of this client waits for the Focus, as the External Commit
    /// healing it does (RCC.16 sections 7.7.2.2, 10.1.1, 10.2, 10.4). Those of
    /// a group moved to unencrypted, or let go of, are forgotten, its
    /// messages not to be re-sent unencrypted (section 10.3).
    pub fn failed_to_decrypt(&self, conversation_id: &str) -> Vec<FailedToDecrypt> {
        if self.encryption_ended(conversation_id) {
            self.lost().forget(conversation_id);
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
            Ok(false) => self.lost().to_tell(conversation_id),
            Err(StoreError::Mls(ErrorKind::UnknownGroup)) => {
                self.lost().forget(conversation_id);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{LostMessages, LOST_FOR, LOST_MOST};

    const BOB: &str = "tel:+491707654321";

    fn told(lost: &LostMessages, conversation_id: &str) -> Vec<String> {
        lost.to_tell(conversation_id)
            .into_iter()
            .map(|told| told.imdn)
            .collect()
    }

    #[test]
    fn a_message_lost_is_told_of_once_and_taken_once_re_sent() {
        let lost = LostMessages::default();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        lost.lose("group-1", "m1", BOB, "2026-10-25T12:00:00Z", now);
        lost.lose("group-1", "m1", BOB, "2026-10-25T12:00:00Z", now);
        lost.lose("group-2", "m1", BOB, "2026-10-25T12:00:00Z", now);

        // by group, once
        assert!(!lost.found("group-1", "m1", |_| true));
        assert_eq!(told(&lost, "group-1").len(), 1);
        assert_eq!(told(&lost, "group-1").len(), 0);
        // by whom it was from
        assert!(!lost.found("group-1", "m1", |sender| sender != BOB));
        assert!(lost.found("group-1", "m1", |sender| sender == BOB));
        assert!(!lost.found("group-1", "m1", |_| true));
        assert_eq!(told(&lost, "group-2").len(), 1);
        lost.forget("group-2");
        assert!(!lost.found("group-2", "m1", |_| true));
    }

    #[test]
    fn messages_lost_are_kept_for_30_days_and_1024_at_most() {
        let lost = LostMessages::default();
        let then = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        lost.lose("group-1", "old", BOB, "", then);
        lost.lose("group-1", "recent", BOB, "", then + Duration::from_secs(60));
        assert_eq!(told(&lost, "group-1").len(), 2);

        // the sender re-sends none older (RCC.16 section 10.3)
        lost.lose(
            "group-1",
            "new",
            BOB,
            "",
            then + LOST_FOR + Duration::from_secs(1),
        );
        assert!(!lost.found("group-1", "old", |_| true));
        assert!(lost.found("group-1", "recent", |_| true));

        // the oldest forgotten first
        let lost = LostMessages::default();
        for n in 0..=LOST_MOST {
            lost.lose("group-1", &format!("m{}", n), BOB, "", then);
        }
        assert_eq!(told(&lost, "group-1").len(), LOST_MOST);
        assert!(!lost.found("group-1", "m0", |_| true));
        assert!(lost.found("group-1", "m1", |_| true));
    }
}
