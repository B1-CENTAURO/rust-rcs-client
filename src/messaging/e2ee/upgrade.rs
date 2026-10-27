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

//! Moving the MLS group of a group chat that was moved to unencrypted back
//! to encrypted (RCC.16 section 11.1)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::same_tel_uri;
use rust_rcs_core::mls::Credential;

use crate::capability::CapabilityQuery;

use super::device::{is_of, participant_tel_uri, same_participant, E2eeDevice};
use super::group::{recipients, GroupError};
use super::kds::Recipient;

const LOG_TAG: &str = "e2ee";

/// How long a group is not moved back to encrypted after it was moved to
/// unencrypted, and after the device last tried (RCC.16 section 11.2)
const UPGRADE_BACKOFF: Duration = Duration::from_secs(2 * 60 * 60);

/// How long the capabilities of the Participants of a group are not asked
/// again after one was found not to advertise E2EE (RCC.16 section 11.1.1)
const CAPABILITY_REFRESH: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Where moving a group back to encrypted stands
#[derive(Default)]
struct Upgrade {
    /// When the device saw it moved to unencrypted
    ended: Option<SystemTime>,
    /// When the device last tried to move it back
    attempted: Option<SystemTime>,
    /// When a Participant was last found not to advertise E2EE
    incapable: Option<SystemTime>,
    ongoing: bool,
}

/// The groups moved to unencrypted and moved back, by Conversation-ID
#[derive(Default)]
pub(super) struct Upgrades(Mutex<HashMap<String, Upgrade>>);

impl Upgrades {
    /// Takes note of the device seeing the group `conversation_id` moved to
    /// unencrypted at `now`
    pub(super) fn ended(&self, conversation_id: &str, now: SystemTime) {
        let mut upgrades = self.0.lock().unwrap();
        upgrades
            .entry(String::from(conversation_id))
            .or_default()
            .ended = Some(now);
    }

    /// Takes note of the membership of the group `conversation_id` changing,
    /// which lifts the waits but that between two tries (RCC.16 sections
    /// 11.1.1, 11.2)
    fn membership_changed(&self, conversation_id: &str) {
        if let Some(upgrade) = self.0.lock().unwrap().get_mut(conversation_id) {
            upgrade.ended = None;
            upgrade.incapable = None;
        }
    }

    /// Whether the group `conversation_id` may be moved back to encrypted
    /// at `now`, as far as the time tells
    fn due(&self, conversation_id: &str, now: SystemTime) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(conversation_id)
            .is_none_or(|upgrade| due(upgrade, now))
    }

    /// Starts moving the group `conversation_id` back to encrypted at `now`;
    /// false if it is not due, or is being moved back already
    fn begin(&self, conversation_id: &str, now: SystemTime) -> bool {
        let mut upgrades = self.0.lock().unwrap();
        let upgrade = upgrades.entry(String::from(conversation_id)).or_default();
        if !due(upgrade, now) {
            return false;
        }
        upgrade.ongoing = true;
        upgrade.attempted = Some(now);
        true
    }

    /// Ends moving the group `conversation_id` back to encrypted, a
    /// Participant found then not to advertise E2EE if `incapable` tells
    /// when
    fn end(&self, conversation_id: &str, incapable: Option<SystemTime>) {
        if let Some(upgrade) = self.0.lock().unwrap().get_mut(conversation_id) {
            upgrade.ongoing = false;
            if incapable.is_some() {
                upgrade.incapable = incapable;
            }
        }
    }
}

/// Whether `upgrade` may be tried at `now`
fn due(upgrade: &Upgrade, now: SystemTime) -> bool {
    !upgrade.ongoing
        && waited(upgrade.ended, UPGRADE_BACKOFF, now)
        && waited(upgrade.attempted, UPGRADE_BACKOFF, now)
        && waited(upgrade.incapable, CAPABILITY_REFRESH, now)
}

/// Whether `wait` passed since `since` at `now`, or nothing is to be waited
/// for
fn waited(since: Option<SystemTime>, wait: Duration, now: SystemTime) -> bool {
    since.is_none_or(|since| now.duration_since(since).is_ok_and(|waited| waited >= wait))
}

/// Why a group is not moved back to encrypted
enum NotMoved {
    /// A Participant does not advertise E2EE
    Incapable,
    Group(GroupError),
}

impl E2eeDevice {
    /// Whether the device is to move the group chat `conversation_id` back to
    /// encrypted, as it was moved to unencrypted (RCC.16 section 11.1)
    ///
    /// Not for two hours after the device saw it moved to unencrypted, unless
    /// its membership changed since, nor for two hours after the device last
    /// tried (section 11.2), nor for a week after a Participant was found not
    /// to advertise E2EE, unless the membership changed since (section
    /// 11.1.1). Not while a Commit of the device waits for the Conversation
    /// Focus to accept it, nor while other members are leaving, as their
    /// leave is to be committed first (section 9.4), nor while the
    /// certificate of the device has less than 30 days left (Annex A.4.1.5).
    pub fn upgrade_due(&self, conversation_id: &str) -> bool {
        self.resurrectable(conversation_id)
            && self.certificate_lasting()
            && self.upgrades().due(conversation_id, self.store().now())
    }

    /// Whether the MLS group `conversation_id` is one moved to unencrypted
    /// that can be moved back as it is
    fn resurrectable(&self, conversation_id: &str) -> bool {
        self.store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                conversation.is_encryption_ended()
                    && conversation.is_active()
                    && !conversation.has_pending_commit()
                    && conversation.leaving_members().is_empty()
            })
            .unwrap_or(false)
    }

    /// Takes note of the membership of the group chat `conversation_id`
    /// changing, after which it may be moved back to encrypted sooner, as
    /// upgrade_due() tells
    pub fn membership_changed(&self, conversation_id: &str) {
        self.upgrades().membership_changed(conversation_id);
    }

    /// Moves the group chat `conversation_id` back to encrypted, if that is
    /// due as upgrade_due() tells, `participants` the URIs of its
    /// Participants as its Conversation Focus tells them, the user among
    /// them: the CPIM message, `from` and `to` its own, carrying the
    /// `message/mls-rcs-client` with a Commit resurrecting its MLS group, to
    /// send to the Focus over MSRP (RCC.16 sections 9.5.1, 11.1.2)
    ///
    /// Each Participant is asked for its capabilities with `capabilities`
    /// (section 11.1). The Commit removes end_mls, and the Clients of members
    /// who are no longer Participants, the user's aside; it replaces the
    /// Clients whose certificate expired, and adds the Clients of the
    /// Participants missing from the group, with the KeyPackages of all the
    /// Clients of their Participants (section 5.3). It is applied once the
    /// Focus accepts it.
    ///
    /// None if it is not due, if a Participant does not advertise E2EE,
    /// which the next try waits a week for, or if the KeyPackages cannot be
    /// had or the Commit made, which the next try waits two hours for.
    pub async fn upgrade_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        participants: &[String],
        capabilities: &CapabilityQuery,
    ) -> Option<Vec<u8>> {
        if !self.resurrectable(conversation_id) || !self.certificate_lasting() {
            return None;
        }
        if !self.upgrades().begin(conversation_id, self.store().now()) {
            return None;
        }
        let resurrected = self
            .resurrect(conversation_id, from, to, participants, capabilities)
            .await;
        let incapable = matches!(resurrected, Err(NotMoved::Incapable));
        self.upgrades()
            .end(conversation_id, incapable.then(|| self.store().now()));
        match resurrected {
            Ok(cpim) => Some(cpim),
            Err(NotMoved::Incapable) => {
                platform_log(
                    LOG_TAG,
                    "group not moved back to encrypted, a Participant not E2EE capable",
                );
                None
            }
            Err(NotMoved::Group(e)) => {
                platform_log(
                    LOG_TAG,
                    format!("group not moved back to encrypted: {:?}", e),
                );
                None
            }
        }
    }

    /// The CPIM message carrying the Commit resurrecting the MLS group
    /// `conversation_id`, as upgrade_group() makes it
    async fn resurrect(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        participants: &[String],
        capabilities: &CapabilityQuery,
    ) -> Result<Vec<u8>, NotMoved> {
        let own = self.store().credential();
        let of_user = |tel_uri: &str| own.as_ref().is_some_and(|own| is_of(own, tel_uri));

        // the Participants besides the user, by tel URI, once each
        let mut tel_uris: Vec<String> = Vec::new();
        for participant in participants {
            let Some(tel_uri) = participant_tel_uri(std::iter::once(participant.as_str()), None)
            else {
                continue;
            };
            if !of_user(&tel_uri) && !tel_uris.iter().any(|known| same_tel_uri(known, &tel_uri)) {
                tel_uris.push(tel_uri);
            }
        }
        let recipients = recipients(&tel_uris, capabilities)
            .await
            .ok_or(NotMoved::Incapable)?;

        let (members, expired) = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                (conversation.members(), conversation.expired_members(client))
            })
            .map_err(|e| NotMoved::Group(GroupError::Store(e)))?;
        // the Clients of those no longer Participants, the user's aside, and
        // those whose certificate expired
        let users_client = |member: &Credential| {
            own.as_ref()
                .is_some_and(|own| same_participant(own, member))
        };
        let removed: Vec<Credential> = members
            .iter()
            .filter(|member| {
                expired.contains(member)
                    || (!users_client(member)
                        && !tel_uris.iter().any(|tel_uri| is_of(member, tel_uri)))
            })
            .cloned()
            .collect();
        // the Participants missing from the group, and those with a Client
        // whose certificate expired
        let added: Vec<Recipient> = recipients
            .into_iter()
            .filter(|recipient| {
                !members
                    .iter()
                    .any(|member| is_of(member, &recipient.tel_uri))
                    || expired
                        .iter()
                        .any(|member| is_of(member, &recipient.tel_uri))
            })
            .collect();
        let key_packages = match added.is_empty() {
            true => Vec::new(),
            false => self.key_packages(added).await.map_err(NotMoved::Group)?,
        };

        let client_message = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                let key_packages: Vec<&[u8]> = key_packages.iter().map(|kp| &kp[..]).collect();
                let output = conversation.resurrect(client, &removed, &key_packages)?;
                match output.to_client_message() {
                    Ok(client_message) => Ok(client_message),
                    Err(e) => {
                        conversation.discard_pending_commit(client)?;
                        Err(e)
                    }
                }
            })
            .map_err(|e| NotMoved::Group(GroupError::Store(e)))?;
        Ok(self.sent_in(conversation_id, from, to, &client_message))
    }
}
