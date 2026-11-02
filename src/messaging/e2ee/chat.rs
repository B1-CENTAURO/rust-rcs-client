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

//! The 1-to-1 chats of the device encrypted end to end (RCC.16 section 8.1.1)
//!
//! Each has an MLS group of its own, its group ID a random GUID (section
//! 6.1.1). It is kept with the MLS state, by the tel URI of the contact, with
//! the MLS-Opaque-Token its Conversation Focus gave, which the requests of
//! the chat carry (section 6.1.3).
//!
//! A contact found not to take an encrypted chat, as it does not advertise
//! E2EE v1 or the Home KDS has no KeyPackages of it, is not asked again for
//! UNENCRYPTED_FOR (section 8.1).
//!
//! A chat with no message sent or taken in it for CHAT_INACTIVE_FOR starts
//! its next session in a new Era of its MLS group, as its Conversation Focus
//! lets go of the group by then (sections 6.1.2, 8.3).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::era::EraBase;
use rust_rcs_core::mls::rcs::proto::{self, server_mls_rcs_message, ServerMlsRcsMessage};
use rust_rcs_core::mls::rcs::same_tel_uri;
use rust_rcs_core::mls::ErrorKind;

use crate::capability::CapabilityQuery;

use super::device::{is_of, participant_tel_uri, same_participant, E2eeDevice};
use super::group::recipients;
use super::notes::{put, put_time, Reader as NotesReader};
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

/// How long a contact found not to take an encrypted chat is not asked again
pub(super) const UNENCRYPTED_FOR: Duration = Duration::from_secs(60 * 60);

/// How long a chat may go with no message sent or taken in it before its
/// next session starts in a new Era, as its Conversation Focus lets go of
/// its MLS group by then (RCC.16 sections 6.1.2, 8.3)
pub(super) const CHAT_INACTIVE_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How often the last message of a chat is noted, at most, so that the MLS
/// state is not kept again for each
const ACTIVITY_NOTED_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// An encrypted 1-to-1 chat, as kept in the notes of the device
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Chat {
    /// The tel URI of the contact
    pub(super) contact: String,
    /// The ID of its MLS group
    pub(super) group_id: String,
    /// The MLS-Opaque-Token its Conversation Focus gave, if it did
    pub(super) mls_opaque_token: Option<String>,
    /// When a message was last sent or taken in it, or it was kept, as noted
    /// at most every ACTIVITY_NOTED_EVERY; None if not noted, as by a device
    /// before it noted it
    pub(super) active: Option<SystemTime>,
}

/// The contacts found not to take an encrypted chat, by tel URI, and when,
/// for as long as the device runs
#[derive(Default)]
pub(super) struct Unencrypted(Mutex<HashMap<String, SystemTime>>);

impl Unencrypted {
    /// Whether `contact` was found not to take an encrypted chat within
    /// UNENCRYPTED_FOR of `now`
    pub(super) fn lately(&self, contact: &str, now: SystemTime) -> bool {
        let mut found = self.0.lock().unwrap();
        found.retain(|_, when| {
            now.duration_since(*when)
                .map_or(true, |since| since < UNENCRYPTED_FOR)
        });
        found.contains_key(contact)
    }

    /// Takes note of `contact` found not to take an encrypted chat at `now`
    pub(super) fn found(&self, contact: &str, now: SystemTime) {
        self.0.lock().unwrap().insert(String::from(contact), now);
    }
}

/// The tel URI of `contact`, a tel URI or a SIP URI of a number
pub(super) fn contact_tel_uri(contact: &str) -> Option<String> {
    participant_tel_uri(std::iter::once(contact), None)
}

impl E2eeDevice {
    /// Whether a file to send to `contact` is to be encrypted before it is
    /// uploaded, as the message sending it goes in an encrypted 1-to-1 chat
    /// (RCC.16 sections 8.1.1, 9.1.2.1): in the one kept with the contact,
    /// while it is encrypted; else in a new one, if the device is enrolled
    /// and the contact advertises E2EE v1, asked with `capabilities`, unless
    /// it was found lately not to take one
    pub async fn seals_chat_files(&self, contact: &str, capabilities: &CapabilityQuery) -> bool {
        let Some(tel_uri) = contact_tel_uri(contact) else {
            return false;
        };
        if self.mls_feature_tags().is_none() {
            return false;
        }
        if let Some((group_id, _)) = self.chat_group(contact) {
            return self.encrypts_files(&group_id);
        }
        if self
            .unencrypted_chats()
            .lately(&tel_uri, self.store().now())
        {
            return false;
        }
        recipients(&[String::from(contact)], capabilities)
            .await
            .is_some()
    }

    /// The ID of the MLS group of the encrypted 1-to-1 chat with `contact`,
    /// and the MLS-Opaque-Token given for it if one was (RCC.16 sections
    /// 6.1.3, 8.1.1); None if none is kept, or if its MLS group no longer is
    pub fn chat_group(&self, contact: &str) -> Option<(String, Option<String>)> {
        let contact = contact_tel_uri(contact)?;
        let chat = self.notes().read(|data| {
            data.chats
                .iter()
                .find(|chat| same_tel_uri(&chat.contact, &contact))
                .cloned()
        })?;
        self.store()
            .has_conversation(chat.group_id.as_bytes())
            .then_some((chat.group_id, chat.mls_opaque_token))
    }

    /// Takes note of the MLS group `group_id` as that of the encrypted 1-to-1
    /// chat with `contact`, in place of any other, its Conversation Focus
    /// having given `mls_opaque_token` if it did; kept with the MLS state
    pub fn keep_chat(
        &self,
        contact: &str,
        group_id: &str,
        mls_opaque_token: Option<&str>,
    ) -> Result<(), StoreError> {
        let Some(contact) = contact_tel_uri(contact) else {
            platform_log(LOG_TAG, "chat with a contact of no number not kept");
            return Ok(());
        };
        let chat = Chat {
            contact,
            group_id: String::from(group_id),
            mls_opaque_token: mls_opaque_token.map(String::from),
            active: Some(self.store().now()),
        };
        self.notes().change(self.store(), |data| {
            data.chats
                .retain(|kept| !same_tel_uri(&kept.contact, &chat.contact));
            data.chats.push(chat);
        })
    }

    /// Joins the MLS group of the encrypted 1-to-1 chat `contact` started,
    /// with the Welcome its Conversation Focus sent in `server_message`, the
    /// group of whatever ID (RCC.16 sections 6.1.1, 8.1, 8.1.1): its ID; kept
    /// as the chat with `contact`, with the MLS-Opaque-Token the INVITE
    /// carried if it did (section 6.1.3), in place of any other, whose MLS
    /// group is let go of
    ///
    /// Not joined if a member is a Client of a Participant other than the
    /// contact and the user, as a 1-to-1 chat has no other; nor if the
    /// contact has no number. A message bundled with the Welcome is
    /// decrypted, as joining a group does.
    pub fn join_chat(
        &self,
        contact: &str,
        server_message: &[u8],
        mls_opaque_token: Option<&str>,
    ) -> Result<String, StoreError> {
        let contact_tel = contact_tel_uri(contact).ok_or(StoreError::Mls(ErrorKind::Rejected))?;
        let message: ServerMlsRcsMessage =
            proto::decode(server_message).map_err(StoreError::Mls)?;
        let bundle = match message.payload {
            Some(server_mls_rcs_message::Payload::ServerCommitBundle(bundle))
                if !bundle.welcome.is_empty() =>
            {
                bundle
            }
            _ => return Err(StoreError::Mls(ErrorKind::UnexpectedMessage)),
        };

        let previous = self.chat_group(contact).map(|(group_id, _)| group_id);
        let had = previous
            .as_deref()
            .and_then(|group_id| self.era_and_token(group_id));
        let (group_id, ()) = self.store().add_conversation(|client| {
            let mut conversation =
                client.join_conversation(&bundle.welcome, &bundle.ratchet_tree)?;
            // of the contact's Clients and the user's only
            let of_the_chat = conversation.members().iter().all(|member| {
                is_of(member, &contact_tel) || same_participant(member, client.credential())
            });
            let joined = if !of_the_chat || std::str::from_utf8(conversation.group_id()).is_err() {
                Err(ErrorKind::Rejected)
            } else if bundle.private_message.is_empty() {
                Ok(())
            } else {
                conversation
                    .process(client, &bundle.private_message)
                    .map(|_| ())
            };
            match joined {
                Ok(()) => Ok((conversation, ())),
                Err(e) => {
                    let _ = conversation.delete(client);
                    Err(e)
                }
            }
        })?;
        let group_id = String::from_utf8_lossy(&group_id).into_owned();

        // a new Era of the chat kept has its keys checked, as a group's has
        // (section 10.5.1); another chat in its place, the one kept let go of
        match previous {
            Some(previous) if previous == group_id => {
                if let (Some((era, token)), Some((new_era, new_token))) =
                    (had, self.era_and_token(&group_id))
                {
                    if new_era > era {
                        self.recoveries().check(&group_id, token != new_token);
                    }
                }
            }
            Some(previous) => {
                if let Err(e) = self.abandon(&previous) {
                    platform_log(LOG_TAG, format!("chat replaced not let go of: {:?}", e));
                }
            }
            None => {}
        }
        self.keep_chat(contact, &group_id, mls_opaque_token)?;
        Ok(group_id)
    }

    /// Takes note of a message sent or taken in the MLS group `group_id`, if
    /// it is that of a chat, as the last of the chat, every
    /// ACTIVITY_NOTED_EVERY at most
    pub(super) fn chat_used(&self, group_id: &str) {
        let now = self.store().now();
        let due = self.notes().read(|data| {
            data.chats.iter().any(|chat| {
                chat.group_id == group_id
                    && chat.active.map_or(true, |active| {
                        now.duration_since(active)
                            .is_ok_and(|since| since >= ACTIVITY_NOTED_EVERY)
                    })
            })
        });
        if !due {
            return;
        }
        let noted = self.notes().change(self.store(), |data| {
            for chat in data.chats.iter_mut() {
                if chat.group_id == group_id {
                    chat.active = Some(now);
                }
            }
        });
        if let Err(e) = noted {
            platform_log(LOG_TAG, format!("chat activity not noted: {:?}", e));
        }
    }

    /// Whether the encrypted 1-to-1 chat kept with `contact` is to start its
    /// next session in a new Era of its MLS group, no message having been
    /// sent or taken in it for CHAT_INACTIVE_FOR, as its Conversation Focus
    /// lets go of the group by then (RCC.16 sections 6.1.2, 8.3); not if its
    /// MLS group was moved to unencrypted
    pub fn chat_era_due(&self, contact: &str) -> bool {
        let Some(contact) = contact_tel_uri(contact) else {
            return false;
        };
        let now = self.store().now();
        let chat = self.notes().read(|data| {
            data.chats
                .iter()
                .find(|chat| same_tel_uri(&chat.contact, &contact))
                .cloned()
        });
        let Some(chat) = chat else {
            return false;
        };
        let inactive = chat.active.is_some_and(|active| {
            now.duration_since(active)
                .is_ok_and(|since| since > CHAT_INACTIVE_FOR)
        });
        inactive
            && self.store().has_conversation(chat.group_id.as_bytes())
            && !self.encryption_ended(&chat.group_id)
    }

    /// Makes the next Era of the MLS group of the chat kept with `contact`,
    /// if one is due as chat_era_due() tells, with the contact's Clients, as
    /// the Home KDS gives their KeyPackages, the contact asked for its
    /// capabilities with `capabilities` (RCC.16 sections 5.2, 8.3.1): the ID
    /// of the group, and the CPIM message, from `from` to `contact`, of its
    /// Commit, GroupInfo and Welcome that the INVITE starting the chat's
    /// session is to carry (sections 7.9.2, 8.1.1)
    ///
    /// The Era follows that of the group the device has, whose GroupContext
    /// extensions it copies: a chat not started has no session to ask its
    /// Conversation Focus for the GroupInfo in, which the Focus no longer has
    /// by then. Its Participant is the contact, whatever the group of the
    /// device has left of it. None if the Era cannot be made, as when the
    /// contact no longer advertises E2EE, or its KeyPackages cannot be had.
    /// The Commit is applied once the Focus accepts it.
    pub async fn make_chat_era(
        &self,
        contact: &str,
        from: &str,
        capabilities: &CapabilityQuery,
    ) -> Option<(String, Vec<u8>)> {
        if !self.chat_era_due(contact) {
            return None;
        }
        let (group_id, _) = self.chat_group(contact)?;
        let base = match self
            .store()
            .peek_conversation(group_id.as_bytes(), |conversation, _| {
                EraBase::of_conversation(conversation)
            }) {
            Ok(base) => base,
            Err(e) => {
                platform_log(LOG_TAG, format!("chat Era not made: {:?}", e));
                return None;
            }
        };
        let Some(recipients) = recipients(&[String::from(contact)], capabilities).await else {
            platform_log(LOG_TAG, "chat Era not made, the contact not E2EE capable");
            return None;
        };
        match self
            .next_era(&group_id, from, contact, recipients, &base)
            .await
        {
            Ok(cpim) => Some((group_id, cpim)),
            Err(e) => {
                platform_log(LOG_TAG, format!("chat Era not made: {:?}", e));
                None
            }
        }
    }

    /// Lets go of the 1-to-1 chat whose MLS group is `group_id`, if one's is
    pub(super) fn forget_chat(&self, group_id: &str) {
        let forgotten = self.notes().change(self.store(), |data| {
            data.chats.retain(|chat| chat.group_id != group_id)
        });
        if let Err(e) = forgotten {
            platform_log(LOG_TAG, format!("chat not forgotten: {:?}", e));
        }
    }
}

/// The chats `chats`, as the notes of the device hold them
pub(super) fn encode(chats: &[Chat]) -> Vec<u8> {
    let mut data = Vec::new();
    for chat in chats {
        put(&mut data, chat.contact.as_bytes());
        put(&mut data, chat.group_id.as_bytes());
        match &chat.mls_opaque_token {
            Some(token) => {
                data.push(1);
                put(&mut data, token.as_bytes());
            }
            None => data.push(0),
        }
    }
    data
}

/// The chats `reader` reads, as encode() puts them
pub(super) fn decode(reader: &mut NotesReader) -> Option<Vec<Chat>> {
    let mut chats = Vec::new();
    while !reader.is_empty() {
        let contact = reader.string()?;
        let group_id = reader.string()?;
        let mls_opaque_token = match reader.flag()? {
            true => Some(reader.string()?),
            false => None,
        };
        chats.push(Chat {
            contact,
            group_id,
            mls_opaque_token,
            active: None,
        });
    }
    Some(chats)
}

/// When the chats `chats` were last active, by the ID of their MLS group, as
/// the notes of the device hold it apart from them: notes kept before it was
/// noted are read as they were, and a device before it was noted reads the
/// chats all the same
pub(super) fn encode_activity(chats: &[Chat]) -> Vec<u8> {
    let mut data = Vec::new();
    for chat in chats {
        if let Some(active) = chat.active {
            put(&mut data, chat.group_id.as_bytes());
            put_time(&mut data, active);
        }
    }
    data
}

/// When each chat `reader` reads of was last active, by the ID of its MLS
/// group, as encode_activity() puts it
pub(super) fn decode_activity(reader: &mut NotesReader) -> Option<Vec<(String, SystemTime)>> {
    let mut activity = Vec::new();
    while !reader.is_empty() {
        let group_id = reader.string()?;
        activity.push((group_id, reader.time()?));
    }
    Some(activity)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{contact_tel_uri, Unencrypted, UNENCRYPTED_FOR};

    #[test]
    fn a_contact_is_known_by_its_tel_uri() {
        assert_eq!(
            contact_tel_uri("tel:+491707654321").as_deref(),
            Some("tel:+491707654321")
        );
        assert_eq!(
            contact_tel_uri("sip:+491707654321@ims.example.com;user=phone").as_deref(),
            Some("tel:+491707654321")
        );
        assert_eq!(contact_tel_uri("sip:bob@example.com"), None);
    }

    #[test]
    fn a_contact_found_not_to_take_an_encrypted_chat_is_not_asked_again_for_a_while() {
        let unencrypted = Unencrypted::default();
        let now = SystemTime::now();
        assert!(!unencrypted.lately("tel:+491707654321", now));
        unencrypted.found("tel:+491707654321", now);
        assert!(unencrypted.lately("tel:+491707654321", now));
        assert!(!unencrypted.lately("tel:+491701111111", now));
        assert!(unencrypted.lately(
            "tel:+491707654321",
            now + UNENCRYPTED_FOR - Duration::from_secs(1)
        ));

        // no longer once that long ago
        assert!(!unencrypted.lately("tel:+491707654321", now + UNENCRYPTED_FOR));
        assert!(!unencrypted.lately("tel:+491707654321", now));
    }
}
