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

//! Recovering the Group Metadata keys of a group chat, the keys of its icon
//! and subject and its continuity token, from its other members, and sending
//! them those they ask for (RCC.16 section 10.5)
//!
//! The device checks its keys once it self-healed by rejoining the group, and
//! once it joined a new Era of a group it had (section 10.5.1). Out of sync,
//! it asks for them with a Commit of its own (section 10.5.2), once nothing
//! of it waits for the Conversation Focus; a new Era it makes asks for them
//! in its GroupContext instead (rust-rcs-core `create_next_era()`).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::{self, IncomingMessage, MlsClient, MlsConversation};

use super::device::E2eeDevice;
use super::group::GroupError;

const LOG_TAG: &str = "e2ee";

/// How many Commits asking for or sending the keys the device makes in a
/// group within COMMITS_PERIOD at most, as the Conversation Focus may refuse
/// each, another member having answered first
const COMMITS_MOST: usize = 5;
const COMMITS_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// What the device is to do of the Group Metadata keys of a group
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum KeysDue {
    /// Ask the other members for those it misses (RCC.16 section 10.5.2)
    Request,
    /// Send those another member asked for (section 10.5.3)
    Send,
}

/// Where recovering the keys of a group stands
#[derive(Default)]
struct Recovery {
    /// The keys of the device are to be checked, and asked for if out of
    /// sync, once nothing of the device waits for the Conversation Focus
    /// (RCC.16 section 10.5.1)
    check: bool,
    /// The continuity token kept is not the one the group commits to, or
    /// that the keys received last had: the device has no keys to send then
    /// (sections 10.1.1, 10.5.4)
    token_mismatch: bool,
    /// When Commits asking for or sending the keys were made, within
    /// COMMITS_PERIOD
    commits: Vec<Instant>,
}

/// The groups whose keys the device recovers, by Conversation-ID, for as
/// long as it runs
#[derive(Default)]
pub(super) struct Recoveries(Mutex<HashMap<String, Recovery>>);

impl Recoveries {
    /// Takes note of the keys of the group `conversation_id` to be checked,
    /// its continuity token found mismatched if `token_mismatch`
    pub(super) fn check(&self, conversation_id: &str, token_mismatch: bool) {
        let mut recoveries = self.0.lock().unwrap();
        let recovery = recoveries.entry(String::from(conversation_id)).or_default();
        recovery.check = true;
        recovery.token_mismatch |= token_mismatch;
    }

    /// Takes note of the keys received in the group `conversation_id` with a
    /// continuity token, matching the one kept or not, as a member sends them
    /// once asked (sections 10.5.3, 10.5.4): the check is done with, and a
    /// token still mismatched not asked for again
    fn token_received(&self, conversation_id: &str, matches: bool) {
        let mut recoveries = self.0.lock().unwrap();
        let recovery = recoveries.entry(String::from(conversation_id)).or_default();
        recovery.check = false;
        recovery.token_mismatch = !matches;
    }

    /// Lets go of the group `conversation_id`
    pub(super) fn forget(&self, conversation_id: &str) {
        self.0.lock().unwrap().remove(conversation_id);
    }

    /// What is due of the keys of the group `conversation_id`, the group
    /// asking for them if `requested`, and the device keeping all those the
    /// group has if `complete`; the check of the keys done with it
    fn due(&self, conversation_id: &str, requested: bool, complete: bool) -> Option<KeysDue> {
        let mut recoveries = self.0.lock().unwrap();
        let recovery = recoveries.entry(String::from(conversation_id)).or_default();
        let complete = complete && !recovery.token_mismatch;
        let due = match requested {
            // whoever asked, the answer is for all
            true => {
                recovery.check = false;
                complete.then_some(KeysDue::Send)
            }
            false if recovery.check && complete => {
                recovery.check = false;
                None
            }
            false => recovery.check.then_some(KeysDue::Request),
        }?;
        let now = Instant::now();
        recovery
            .commits
            .retain(|commit| now.duration_since(*commit) < COMMITS_PERIOD);
        if recovery.commits.len() >= COMMITS_MOST {
            platform_log(LOG_TAG, "metadata keys not exchanged, tried too often");
            return None;
        }
        Some(due)
    }

    /// Takes note of a Commit asking for or sending the keys of the group
    /// `conversation_id` made
    fn committed(&self, conversation_id: &str) {
        let mut recoveries = self.0.lock().unwrap();
        let recovery = recoveries.entry(String::from(conversation_id)).or_default();
        recovery.commits.push(Instant::now());
    }
}

impl E2eeDevice {
    /// Takes note of the Group Metadata keys received in the group chat
    /// `conversation_id`, among the messages `taken` of its Conversation
    /// Focus: those of its icon and subject are kept, as the continuity
    /// token is if none was (RCC.16 section 10.5.4)
    ///
    /// A continuity token other than the one kept leaves the one kept, and
    /// the group encrypted, which section 10.5.4 leaves to the client: the
    /// device sends no keys then.
    pub(super) fn metadata_keys_received(&self, conversation_id: &str, taken: &[IncomingMessage]) {
        for message in taken {
            if let IncomingMessage::GroupMetadataKeys {
                continuity_token_matches: Some(matches),
                ..
            } = message
            {
                if !matches {
                    platform_log(
                        LOG_TAG,
                        "continuity token received not the one kept, which stays",
                    );
                }
                self.recoveries().token_received(conversation_id, *matches);
            }
        }
    }

    /// Whether the device is to ask the other members of the group chat
    /// `conversation_id` for the Group Metadata keys it misses, or to send
    /// them those one of them asked for (RCC.16 sections 10.5.2, 10.5.3), as
    /// metadata_keys() does
    pub fn metadata_keys_due(&self, conversation_id: &str) -> bool {
        self.keys_due(conversation_id).is_some()
    }

    /// What is due of the keys of the group `conversation_id`, once nothing
    /// of the device waits for the Conversation Focus: those of its icon and
    /// subject, and its continuity token, sent if the group asks for them and
    /// the device keeps all the group has, or else asked for if they are to
    /// be checked and the device misses one
    fn keys_due(&self, conversation_id: &str) -> Option<KeysDue> {
        if self.encryption_ended(conversation_id)
            || self.heals().ongoing(conversation_id)
            || self.needs_healing(conversation_id)
            || self.new_era_due(conversation_id)
            || self
                .control_messages()
                .lock()
                .unwrap()
                .contains_key(conversation_id)
        {
            return None;
        }
        self.store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                self.keys_due_in(conversation_id, conversation, client)
            })
            .ok()
            .flatten()
    }

    fn keys_due_in(
        &self,
        conversation_id: &str,
        conversation: &MlsConversation,
        client: &MlsClient,
    ) -> Option<KeysDue> {
        if conversation.has_pending_commit() || !conversation.is_active() {
            return None;
        }
        let complete = conversation.group_metadata_in_sync(client).ok()?
            && !conversation
                .group_metadata(client)
                .ok()?
                .continuity_token
                .is_empty();
        self.recoveries().due(
            conversation_id,
            conversation.group_metadata_keys_requested(),
            complete,
        )
    }

    /// Asks the other members of the group chat `conversation_id` for the
    /// Group Metadata keys the device misses, or sends them those one of
    /// them asked for, as metadata_keys_due() tells: the CPIM message,
    /// `from` and `to` its own, carrying the `message/mls-rcs-client` to send
    /// to the Conversation Focus over MSRP (RCC.16 sections 9.5.1, 10.5.2,
    /// 10.5.3); None if neither is due
    ///
    /// The keys are asked for with a Commit adding the
    /// group_metadata_keys_requested extension, and sent with one removing
    /// it, bundled with a PrivateMessage carrying them. Not while a Commit of
    /// the device waits for the Focus to accept it.
    pub fn metadata_keys(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
    ) -> Result<Option<Vec<u8>>, GroupError> {
        if self.keys_due(conversation_id).is_none() {
            return Ok(None);
        }
        let message_id = super::group::new_message_id();
        let client_message = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                if conversation.has_pending_commit() {
                    return Ok(Err(GroupError::Pending));
                }
                let output = match self.keys_due_in(conversation_id, conversation, client) {
                    Some(KeysDue::Request) => conversation.request_group_metadata_keys(client)?,
                    Some(KeysDue::Send) => {
                        conversation.send_group_metadata_keys(client, message_id.as_bytes())?
                    }
                    None => return Ok(Ok(None)),
                };
                match output.to_client_message() {
                    Ok(client_message) => Ok(Ok(Some(client_message))),
                    Err(e) => {
                        conversation.discard_pending_commit(client)?;
                        Err(e)
                    }
                }
            })
            .map_err(GroupError::Store)??;

        Ok(client_message.map(|client_message| {
            self.recoveries().committed(conversation_id);
            self.sent_as(conversation_id, from, to, message_id, &client_message)
        }))
    }

    /// Whether the continuity token kept for the group chat
    /// `conversation_id` is not the one the GroupInfo `group_info` of its
    /// Conversation Focus commits to, at `epoch_authenticator` (RCC.16
    /// sections 7.11.12.2, 10.5.1); false if that cannot be told
    pub(super) fn token_mismatched(
        &self,
        conversation_id: &str,
        group_info: &[u8],
        epoch_authenticator: &[u8],
    ) -> bool {
        self.store()
            .peek_conversation(conversation_id.as_bytes(), |_, client| {
                client.continuity_token_matches(group_info, epoch_authenticator)
            })
            .is_ok_and(|matches| matches == Ok(Some(false)))
    }
}

/// The continuity token kept for the group `group_id` by `client`, empty if
/// none is
pub(super) fn continuity_token(client: &MlsClient, group_id: &[u8]) -> mls::Result<Vec<u8>> {
    Ok(client.group_metadata(group_id)?.continuity_token)
}

#[cfg(test)]
mod tests {
    use super::{KeysDue, Recoveries, COMMITS_MOST};

    const GROUP: &str = "group-1";

    #[test]
    fn keys_are_asked_for_once_checked_and_missed() {
        let recoveries = Recoveries::default();
        // not checked, nothing is asked for
        assert_eq!(recoveries.due(GROUP, false, false), None);

        // checked and complete, nothing is, nor later
        recoveries.check(GROUP, false);
        assert_eq!(recoveries.due(GROUP, false, true), None);
        assert_eq!(recoveries.due(GROUP, false, false), None);

        // checked and missing, until the group asks for them
        recoveries.check(GROUP, false);
        assert_eq!(recoveries.due(GROUP, false, false), Some(KeysDue::Request));
        assert_eq!(recoveries.due(GROUP, false, false), Some(KeysDue::Request));
        assert_eq!(recoveries.due(GROUP, true, false), None);
        assert_eq!(recoveries.due(GROUP, false, false), None);
        // of another group, nothing
        recoveries.check("group-2", false);
        assert_eq!(recoveries.due(GROUP, false, false), None);
    }

    #[test]
    fn keys_asked_for_are_sent_by_who_has_them_all_with_its_token_matching() {
        let recoveries = Recoveries::default();
        assert_eq!(recoveries.due(GROUP, true, true), Some(KeysDue::Send));
        assert_eq!(recoveries.due(GROUP, true, false), None);

        // the token found mismatched, the device asks rather than send
        recoveries.check(GROUP, true);
        assert_eq!(recoveries.due(GROUP, true, true), None);
        assert_eq!(recoveries.due(GROUP, false, true), None);
        recoveries.check(GROUP, false);
        assert_eq!(recoveries.due(GROUP, false, true), Some(KeysDue::Request));
        // until keys come with a token, which ends the check, and matches
        recoveries.token_received(GROUP, true);
        assert_eq!(recoveries.due(GROUP, false, true), None);
        assert_eq!(recoveries.due(GROUP, true, true), Some(KeysDue::Send));
        recoveries.check(GROUP, false);
        recoveries.token_received(GROUP, false);
        assert_eq!(recoveries.due(GROUP, false, false), None);
        recoveries.token_received(GROUP, false);
        assert_eq!(recoveries.due(GROUP, true, true), None);
        recoveries.token_received(GROUP, true);

        // the group let go of, its check is
        recoveries.check(GROUP, true);
        recoveries.forget(GROUP);
        assert_eq!(recoveries.due(GROUP, false, false), None);
        assert_eq!(recoveries.due(GROUP, true, true), Some(KeysDue::Send));
    }

    #[test]
    fn so_many_commits_are_made_a_day_at_most() {
        let recoveries = Recoveries::default();
        recoveries.check(GROUP, false);
        for _ in 0..COMMITS_MOST {
            assert_eq!(recoveries.due(GROUP, false, false), Some(KeysDue::Request));
            recoveries.committed(GROUP);
        }
        assert_eq!(recoveries.due(GROUP, false, false), None);
        assert_eq!(recoveries.due(GROUP, true, true), None);
        // still to be checked, in another group too
        assert_eq!(recoveries.due("group-2", true, true), Some(KeysDue::Send));
    }
}
