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

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::{self, CommitOutput, IncomingMessage, MlsClient, MlsConversation};

use super::device::E2eeDevice;
use super::group::GroupError;
use super::notes::{put, put_times, Notes, Reader};
use super::store::MlsStore;

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

/// Where recovering the keys of a group stands, as the notes of the device
/// keep it
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Recovery {
    /// The keys of the device are to be checked, and asked for if out of
    /// sync, once nothing of the device waits for the Conversation Focus
    /// (RCC.16 section 10.5.1)
    pub(super) check: bool,
    /// The continuity token kept is not the one the group commits to, or
    /// that the keys received last had: the device has no keys to send then
    /// (sections 10.1.1, 10.5.4)
    pub(super) token_mismatch: bool,
    /// When Commits asking for or sending the keys were made, by the
    /// device's clock, within COMMITS_PERIOD
    pub(super) commits: Vec<SystemTime>,
}

/// Whether `commit`, made at that time, was made within COMMITS_PERIOD of
/// `now`, as it is if made later than `now`
fn lately(commit: SystemTime, now: SystemTime) -> bool {
    now.duration_since(commit)
        .map_or(true, |since| since < COMMITS_PERIOD)
}

/// The groups whose keys the device recovers, by Conversation-ID, as the
/// notes of the device keep them for it to restart with
///
/// What changes them is not to be called while the store is in use, as
/// they are kept through it.
pub(super) struct Recoveries<'a> {
    pub(super) notes: &'a Notes,
    pub(super) store: &'a MlsStore,
}

impl Recoveries<'_> {
    /// Changes the Recovery of the group `conversation_id` as `change` does,
    /// one made for it if it has none, kept as the notes are; one left as a
    /// new one is let go of
    fn change(&self, conversation_id: &str, change: impl FnOnce(&mut Recovery)) {
        self.notes.hold(self.store, |data| {
            let recovery = data
                .recoveries
                .entry(String::from(conversation_id))
                .or_default();
            change(recovery);
            if *recovery == Recovery::default() {
                data.recoveries.remove(conversation_id);
            }
        });
    }

    /// Takes note of the keys of the group `conversation_id` to be checked,
    /// its continuity token found mismatched if `token_mismatch`
    pub(super) fn check(&self, conversation_id: &str, token_mismatch: bool) {
        self.change(conversation_id, |recovery| {
            recovery.check = true;
            recovery.token_mismatch |= token_mismatch;
        });
    }

    /// Takes note of the keys received in the group `conversation_id` with a
    /// continuity token, matching the one kept or not, as a member sends them
    /// once asked (sections 10.5.3, 10.5.4): the check is done with, and a
    /// token still mismatched not asked for again
    fn token_received(&self, conversation_id: &str, matches: bool) {
        self.change(conversation_id, |recovery| {
            recovery.check = false;
            recovery.token_mismatch = !matches;
        });
    }

    /// Lets go of the group `conversation_id`
    pub(super) fn forget(&self, conversation_id: &str) {
        if self
            .notes
            .read(|data| data.recoveries.contains_key(conversation_id))
        {
            self.notes
                .hold(self.store, |data| data.recoveries.remove(conversation_id));
        }
    }

    /// What is due of the keys of the group `conversation_id` at `now`, the
    /// group asking for them if `requested`, and the device keeping all
    /// those the group has if `complete`; and whether the check of the keys
    /// is done with, which checked() is to take note of. Nothing is changed,
    /// as it is called while the store is in use.
    fn due(
        &self,
        conversation_id: &str,
        requested: bool,
        complete: bool,
        now: SystemTime,
    ) -> (Option<KeysDue>, bool) {
        let recovery = self
            .notes
            .read(|data| data.recoveries.get(conversation_id).cloned())
            .unwrap_or_default();
        let complete = complete && !recovery.token_mismatch;
        let (due, checked) = match requested {
            // whoever asked, the answer is for all
            true => (complete.then_some(KeysDue::Send), recovery.check),
            false if recovery.check && complete => (None, true),
            false => (recovery.check.then_some(KeysDue::Request), false),
        };
        let made = recovery
            .commits
            .iter()
            .filter(|commit| lately(**commit, now))
            .count();
        if due.is_some() && made >= COMMITS_MOST {
            platform_log(LOG_TAG, "metadata keys not exchanged, tried too often");
            return (None, checked);
        }
        (due, checked)
    }

    /// Takes note of the check of the keys of the group `conversation_id`
    /// done with, as due() told
    fn checked(&self, conversation_id: &str) {
        self.change(conversation_id, |recovery| recovery.check = false);
    }

    /// Takes note of a Commit asking for or sending the keys of the group
    /// `conversation_id` made at `now`, letting go of those made earlier than
    /// COMMITS_PERIOD
    fn committed(&self, conversation_id: &str, now: SystemTime) {
        self.change(conversation_id, |recovery| {
            recovery.commits.retain(|commit| lately(*commit, now));
            recovery.commits.push(now);
        });
    }
}

/// The Recoveries `recoveries`, as the notes of the device hold them
pub(super) fn encode(recoveries: &BTreeMap<String, Recovery>) -> Vec<u8> {
    let mut data = Vec::new();
    for (conversation_id, recovery) in recoveries {
        put(&mut data, conversation_id.as_bytes());
        data.push(u8::from(recovery.check));
        data.push(u8::from(recovery.token_mismatch));
        put_times(&mut data, &recovery.commits);
    }
    data
}

/// The Recoveries `reader` reads to its end, as encode() puts them; None if
/// they cannot be read
pub(super) fn decode(reader: &mut Reader) -> Option<BTreeMap<String, Recovery>> {
    let mut recoveries = BTreeMap::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let recovery = Recovery {
            check: reader.flag()?,
            token_mismatch: reader.flag()?,
            commits: reader.times()?,
        };
        recoveries.insert(conversation_id, recovery);
    }
    Some(recoveries)
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
            || self.control_messages().contains(conversation_id)
        {
            return None;
        }
        let (due, checked) = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                self.keys_due_in(conversation_id, conversation, client)
            })
            .ok()?;
        if checked {
            self.recoveries().checked(conversation_id);
        }
        due
    }

    /// What is due of the keys of the group `conversation_id`, in the state
    /// `conversation`, as Recoveries::due() tells, and whether the check of
    /// its keys is done with; called while the store is in use, it changes
    /// nothing
    fn keys_due_in(
        &self,
        conversation_id: &str,
        conversation: &MlsConversation,
        client: &MlsClient,
    ) -> (Option<KeysDue>, bool) {
        if conversation.has_pending_commit() || !conversation.is_active() {
            return (None, false);
        }
        let complete = || {
            Some(
                conversation.group_metadata_in_sync(client).ok()?
                    && !conversation
                        .group_metadata(client)
                        .ok()?
                        .continuity_token
                        .is_empty(),
            )
        };
        let Some(complete) = complete() else {
            return (None, false);
        };
        self.recoveries().due(
            conversation_id,
            conversation.group_metadata_keys_requested(),
            complete,
            self.store().now(),
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
                // a check done with taken note of by keys_due() already
                let (due, _) = self.keys_due_in(conversation_id, conversation, client);
                let output = match due {
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
            self.recoveries()
                .committed(conversation_id, self.store().now());
            self.sent_as(conversation_id, from, to, message_id, &client_message)
        }))
    }

    /// The External Commit `rejoined` the device rejoined the group chat
    /// `conversation_id` with, as it is to go to the Conversation Focus: the
    /// keys of the device checked against the group `conversation` it
    /// rejoined, and asked for in the same CommitList, after the External
    /// Commit, if they are out of sync and may be asked for still (RCC.16
    /// sections 10.5.1, 10.5.2); with whether the check is done with, and
    /// whether the keys are asked for, which keys_checked() takes note of
    ///
    /// Called while the store is in use, it changes nothing else. The
    /// External Commit goes alone if the group asks for the keys already.
    pub(super) fn asking_with(
        &self,
        conversation_id: &str,
        conversation: &mut MlsConversation,
        client: &MlsClient,
        rejoined: CommitOutput,
    ) -> (CommitOutput, bool, bool) {
        let (due, checked) = self.keys_due_in(conversation_id, conversation, client);
        if !matches!(due, Some(KeysDue::Request)) {
            return (rejoined, checked, false);
        }
        match conversation.request_group_metadata_keys_with(client, &rejoined) {
            Ok(asking) => (asking, true, true),
            Err(e) => {
                platform_log(LOG_TAG, format!("metadata keys not asked for: {:?}", e));
                (rejoined, checked, false)
            }
        }
    }

    /// Takes note of the check of the keys of the group chat
    /// `conversation_id` done with, if `checked`, and of a Commit asking for
    /// them made, if `asked`, as asking_with() tells
    pub(super) fn keys_checked(&self, conversation_id: &str, checked: bool, asked: bool) {
        if checked {
            self.recoveries().checked(conversation_id);
        }
        if asked {
            self.recoveries()
                .committed(conversation_id, self.store().now());
        }
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
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::super::lost::tests::{store, App};
    use super::super::notes::Notes;
    use super::super::store::MlsStore;
    use super::{KeysDue, Recoveries, COMMITS_MOST, COMMITS_PERIOD};

    const GROUP: &str = "group-1";

    const THEN: Duration = Duration::from_secs(1_000_000_000);

    fn then() -> SystemTime {
        SystemTime::UNIX_EPOCH + THEN
    }

    /// The notes of a device, and its store
    fn kept() -> (Notes, MlsStore) {
        let store = store(&Arc::new(App::default()));
        (Notes::kept_by(&store), store)
    }

    /// What is due of the keys of `group` at `now`, as the device tells it,
    /// the check done with taken note of once the store is no longer in use
    fn due_at(
        recoveries: &Recoveries,
        group: &str,
        requested: bool,
        complete: bool,
        now: SystemTime,
    ) -> Option<KeysDue> {
        let (due, checked) = recoveries.due(group, requested, complete, now);
        if checked {
            recoveries.checked(group);
        }
        due
    }

    fn due(
        recoveries: &Recoveries,
        group: &str,
        requested: bool,
        complete: bool,
    ) -> Option<KeysDue> {
        due_at(recoveries, group, requested, complete, then())
    }

    #[test]
    fn keys_are_asked_for_once_checked_and_missed() {
        let (notes, store) = kept();
        let recoveries = Recoveries {
            notes: &notes,
            store: &store,
        };
        // not checked, nothing is asked for
        assert_eq!(due(&recoveries, GROUP, false, false), None);

        // checked and complete, nothing is, nor later
        recoveries.check(GROUP, false);
        assert_eq!(due(&recoveries, GROUP, false, true), None);
        assert_eq!(due(&recoveries, GROUP, false, false), None);

        // checked and missing, until the group asks for them
        recoveries.check(GROUP, false);
        assert_eq!(
            due(&recoveries, GROUP, false, false),
            Some(KeysDue::Request)
        );
        assert_eq!(
            due(&recoveries, GROUP, false, false),
            Some(KeysDue::Request)
        );
        assert_eq!(due(&recoveries, GROUP, true, false), None);
        assert_eq!(due(&recoveries, GROUP, false, false), None);
        // of another group, nothing
        recoveries.check("group-2", false);
        assert_eq!(due(&recoveries, GROUP, false, false), None);
        // nor anything left of a group whose check is done with
        assert_eq!(
            notes.read(|data| data.recoveries.keys().cloned().collect::<Vec<_>>()),
            ["group-2"]
        );
    }

    #[test]
    fn what_is_due_is_told_without_a_change() {
        let (notes, store) = kept();
        let recoveries = Recoveries {
            notes: &notes,
            store: &store,
        };
        // the check done with told, not taken note of, as the store may be
        // in use
        recoveries.check(GROUP, false);
        let before = notes.read(|data| data.clone());
        assert_eq!(recoveries.due(GROUP, false, true, then()), (None, true));
        assert_eq!(
            recoveries.due(GROUP, true, true, then()),
            (Some(KeysDue::Send), true)
        );
        assert_eq!(
            recoveries.due(GROUP, false, false, then()),
            (Some(KeysDue::Request), false)
        );
        assert_eq!(notes.read(|data| data.clone()), before);
    }

    #[test]
    fn keys_asked_for_are_sent_by_who_has_them_all_with_its_token_matching() {
        let (notes, store) = kept();
        let recoveries = Recoveries {
            notes: &notes,
            store: &store,
        };
        assert_eq!(due(&recoveries, GROUP, true, true), Some(KeysDue::Send));
        assert_eq!(due(&recoveries, GROUP, true, false), None);

        // the token found mismatched, the device asks rather than send
        recoveries.check(GROUP, true);
        assert_eq!(due(&recoveries, GROUP, true, true), None);
        assert_eq!(due(&recoveries, GROUP, false, true), None);
        recoveries.check(GROUP, false);
        assert_eq!(due(&recoveries, GROUP, false, true), Some(KeysDue::Request));
        // until keys come with a token, which ends the check, and matches
        recoveries.token_received(GROUP, true);
        assert_eq!(due(&recoveries, GROUP, false, true), None);
        assert_eq!(due(&recoveries, GROUP, true, true), Some(KeysDue::Send));
        recoveries.check(GROUP, false);
        recoveries.token_received(GROUP, false);
        assert_eq!(due(&recoveries, GROUP, false, false), None);
        recoveries.token_received(GROUP, false);
        assert_eq!(due(&recoveries, GROUP, true, true), None);
        recoveries.token_received(GROUP, true);

        // the group let go of, its check is
        recoveries.check(GROUP, true);
        recoveries.forget(GROUP);
        assert_eq!(due(&recoveries, GROUP, false, false), None);
        assert_eq!(due(&recoveries, GROUP, true, true), Some(KeysDue::Send));
        assert!(notes.read(|data| data.recoveries.is_empty()));
    }

    #[test]
    fn so_many_commits_are_made_a_day_at_most() {
        let (notes, store) = kept();
        let recoveries = Recoveries {
            notes: &notes,
            store: &store,
        };
        recoveries.check(GROUP, false);
        for _ in 0..COMMITS_MOST {
            assert_eq!(
                due(&recoveries, GROUP, false, false),
                Some(KeysDue::Request)
            );
            recoveries.committed(GROUP, then());
        }
        assert_eq!(due(&recoveries, GROUP, false, false), None);
        assert_eq!(due(&recoveries, GROUP, true, true), None);
        // still to be checked, in another group too
        assert_eq!(due(&recoveries, "group-2", true, true), Some(KeysDue::Send));

        // a day on, again, those of the day before let go of as one is made;
        // the check, done with as the group asked, made again
        recoveries.check(GROUP, false);
        let later = then() + COMMITS_PERIOD;
        assert_eq!(
            due_at(&recoveries, GROUP, false, false, later),
            Some(KeysDue::Request)
        );
        recoveries.committed(GROUP, later);
        assert_eq!(
            notes.read(|data| data.recoveries[GROUP].commits.clone()),
            [later]
        );
    }
}
