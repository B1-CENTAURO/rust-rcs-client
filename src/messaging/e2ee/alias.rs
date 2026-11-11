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

//! The user alias of the device encrypted for its conversations, and those
//! of other Participants decrypted (RCC.16 section 9.1.5)

use super::chat::contact_tel_uri;
use super::device::{is_of, E2eeDevice};

impl E2eeDevice {
    /// `alias` encrypted for the MLS group `group_id`, for the
    /// `encrypted-alias` parameter of a SIP URI (RCC.16 section 9.1.5)
    ///
    /// None if the group is not encrypted, or moved to unencrypted, or self-
    /// healed, or while a Commit of the device is pending, as the alias would
    /// be in the epoch before it, which those the Commit adds could not
    /// decrypt: seal_alias_after_commit() seals it in the epoch after.
    pub fn seal_alias(&self, group_id: &str, alias: &str) -> Option<String> {
        if self.heals().ongoing(group_id) || self.upgrades().without_group(group_id) {
            return None;
        }
        self.store()
            .with_conversation(group_id.as_bytes(), |conversation, client| {
                if conversation.has_pending_commit()
                    || conversation.is_encryption_ended()
                    || conversation.epoch() == 0
                {
                    return Ok(None);
                }
                conversation.encrypt_alias(client, alias).map(Some)
            })
            .ok()
            .flatten()
    }

    /// `alias` encrypted for the MLS group `group_id` in the epoch the
    /// pending Commit of the device leads to, for the INVITE carrying the
    /// group's first Commit, or that of its next Era: those it invites join
    /// the group in that epoch (RCC.16 section 9.1.5)
    ///
    /// None if no Commit of the device is pending for the group.
    pub fn seal_alias_after_commit(&self, group_id: &str, alias: &str) -> Option<String> {
        self.store()
            .with_conversation(group_id.as_bytes(), |conversation, client| {
                conversation.encrypt_alias_after_commit(client, alias)
            })
            .ok()
    }

    /// The alias `uri` gives itself, which the `encrypted-alias` parameter
    /// `encrypted` of the URI carries, decrypted in the MLS group `group_id`
    /// (RCC.16 section 9.1.5)
    ///
    /// None if it cannot be decrypted, or was not encrypted by a Client of
    /// the Participant of `uri`, as another member could otherwise give that
    /// Participant an alias of its choosing.
    pub fn open_alias(&self, group_id: &str, uri: &str, encrypted: &[u8]) -> Option<String> {
        let tel_uri = contact_tel_uri(uri)?;
        let (sender, alias) = self
            .store()
            .with_conversation(group_id.as_bytes(), |conversation, client| {
                conversation.decrypt_alias(client, encrypted)
            })
            .ok()?;
        is_of(&sender, &tel_uri).then_some(alias)
    }
}
