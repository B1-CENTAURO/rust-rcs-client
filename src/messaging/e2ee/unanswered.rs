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

//! The new groups and 1-to-1 chats whose INVITE, carrying their first
//! Commit, the Conversation Focus has not answered yet (RCC.16 sections 8.1,
//! 8.2.1), kept across a restart of the device
//!
//! The Focus makes a group only once it validated its first Commit, and
//! answers the INVITE with 200 OK then. A client stopping before that answer
//! does not know whether the Focus made it, nor, for a group, at which URI.
//! Its first Commit is kept pending, and applied once the Focus invites the
//! device into the group, or the contact of the chat invites it into a new
//! session: either shows the Focus made it.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::same_tel_uri;

use super::chat::contact_tel_uri;
use super::device::E2eeDevice;
use super::notes::{put, put_time, Notes, Reader};
use super::store::{MlsStore, StoreError};

const LOG_TAG: &str = "e2ee";

/// How long a group or chat is waited for once its INVITE went unanswered:
/// as long as one is kept unused before it restarts in a new Era (RCC.16
/// section 8.3)
pub(super) const UNANSWERED_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The INVITE starting a new group or chat, not answered
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Invite {
    /// The tel URI of the contact of a 1-to-1 chat; None for a group
    pub(super) contact: Option<String>,
    /// When its INVITE was made
    pub(super) since: SystemTime,
}

/// The new groups and chats whose INVITE was not answered, by MLS group, as
/// the notes of the device keep them for it to restart with
pub(super) struct Unanswered<'a> {
    pub(super) notes: &'a Notes,
    pub(super) store: &'a MlsStore,
}

impl Unanswered<'_> {
    /// Takes note of the INVITE starting the group `conversation_id`, made
    /// at `now`, of a chat with `contact` if it is one
    pub(super) fn sent(&self, conversation_id: &str, contact: Option<&str>, now: SystemTime) {
        let contact = contact.and_then(contact_tel_uri);
        self.notes.hold(self.store, |data| {
            data.unanswered.insert(
                String::from(conversation_id),
                Invite {
                    contact,
                    since: now,
                },
            );
        });
    }

    /// Whether the INVITE starting the group, not a chat, `conversation_id`
    /// was not answered
    pub(super) fn group(&self, conversation_id: &str) -> bool {
        self.notes.read(|data| {
            data.unanswered
                .get(conversation_id)
                .is_some_and(|unanswered| unanswered.contact.is_none())
        })
    }

    /// The MLS group of the chat with the tel URI `contact` whose INVITE was
    /// not answered, the latest if there are more
    pub(super) fn chat(&self, contact: &str) -> Option<String> {
        self.notes.read(|data| {
            data.unanswered
                .iter()
                .filter(|(_, unanswered)| {
                    unanswered
                        .contact
                        .as_deref()
                        .is_some_and(|with| same_tel_uri(with, contact))
                })
                .max_by_key(|(_, unanswered)| unanswered.since)
                .map(|(conversation_id, _)| conversation_id.clone())
        })
    }

    /// All those whose INVITE was not answered
    pub(super) fn all(&self) -> Vec<String> {
        self.notes
            .read(|data| data.unanswered.keys().cloned().collect())
    }

    /// Those whose INVITE was made UNANSWERED_FOR before `now` or more
    pub(super) fn expired(&self, now: SystemTime) -> Vec<String> {
        self.notes.read(|data| {
            data.unanswered
                .iter()
                .filter(|(_, unanswered)| {
                    now.duration_since(unanswered.since)
                        .is_ok_and(|waited| waited >= UNANSWERED_FOR)
                })
                .map(|(conversation_id, _)| conversation_id.clone())
                .collect()
        })
    }

    /// Lets go of the group or chat `conversation_id`, whose INVITE was
    /// answered, or which is let go of
    pub(super) fn forget(&self, conversation_id: &str) {
        self.notes.hold(self.store, |data| {
            data.unanswered.remove(conversation_id);
        });
    }
}

impl E2eeDevice {
    /// Applies the first Commit of the group `conversation_id`, which its
    /// Conversation Focus invites the device into without a Welcome, if the
    /// INVITE starting it was not answered before the device stopped: the
    /// Focus has the group, which it made only once it validated that Commit
    /// (RCC.16 section 8.2.1); whether it was
    pub fn group_invited(&self, conversation_id: &str) -> Result<bool, StoreError> {
        if !self.unanswered().group(conversation_id) {
            return Ok(false);
        }
        self.first_commit_accepted(conversation_id)?;
        Ok(true)
    }

    /// The MLS group of the chat `contact` invites the device into without a
    /// Welcome, if the device keeps none with the contact but started one
    /// whose INVITE was not answered before it stopped: its first Commit is
    /// applied, as the contact taking part in it shows the Focus made it
    /// (RCC.16 section 8.2.1), and the chat kept, with the MLS-Opaque-Token
    /// the INVITE carries if it does (section 6.1.3)
    pub fn chat_invited(
        &self,
        contact: &str,
        mls_opaque_token: Option<&str>,
    ) -> Result<Option<String>, StoreError> {
        if self.chat_group(contact).is_some() {
            return Ok(None);
        }
        let Some(group_id) =
            contact_tel_uri(contact).and_then(|tel_uri| self.unanswered().chat(&tel_uri))
        else {
            return Ok(None);
        };
        self.first_commit_accepted(&group_id)?;
        self.keep_chat(contact, &group_id, mls_opaque_token)?;
        Ok(Some(group_id))
    }

    /// Takes note of the INVITE starting the group `conversation_id`, of a
    /// chat with `contact` if it is one, for its first Commit to be applied
    /// as the Focus invites the device into it should the device stop before
    /// the Focus answers; those noted UNANSWERED_FOR before or more are let
    /// go of, their first Commit discarded as that of any group is once the
    /// device restarts
    pub(super) fn invite_sent(&self, conversation_id: &str, contact: Option<&str>) {
        let now = self.store().now();
        for expired in self.unanswered().expired(now) {
            // its note let go of with it, though its MLS group went
            // otherwise, its control message still known, for a refusal
            if let Err(e) = self.discard_pending(&expired, true) {
                platform_log(
                    LOG_TAG,
                    format!(
                        "first Commit of a group not answered not discarded: {:?}",
                        e
                    ),
                );
            }
        }
        self.unanswered().sent(conversation_id, contact, now);
    }
}

/// The groups and chats `unanswered`, as decode() reads them
pub(super) fn encode(unanswered: &BTreeMap<String, Invite>) -> Vec<u8> {
    let mut data = Vec::new();
    for (conversation_id, invite) in unanswered {
        put(&mut data, conversation_id.as_bytes());
        match &invite.contact {
            Some(contact) => {
                data.push(1);
                put(&mut data, contact.as_bytes());
            }
            None => data.push(0),
        }
        put_time(&mut data, invite.since);
    }
    data
}

/// The groups and chats `reader` reads to its end, as encode() puts them;
/// None if they cannot be read
pub(super) fn decode(reader: &mut Reader) -> Option<BTreeMap<String, Invite>> {
    let mut all = BTreeMap::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let contact = match reader.flag()? {
            true => Some(reader.string()?),
            false => None,
        };
        let since = reader.time()?;
        all.insert(conversation_id, Invite { contact, since });
    }
    Some(all)
}
