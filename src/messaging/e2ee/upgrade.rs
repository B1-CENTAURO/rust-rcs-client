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

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::era::EraBase;
use rust_rcs_core::mls::rcs::same_tel_uri;
use rust_rcs_core::mls::{Credential, ErrorKind};
use uuid::Uuid;

use crate::capability::CapabilityQuery;
use crate::messaging::cpm::encryption::Upgrade;

use super::device::{is_of, participant_tel_uri, same_participant, E2eeDevice};
use super::group::{recipients, GroupError};
use super::kds::Recipient;
use super::notes::{put, put_time, Notes, Reader};
use super::store::{MlsStore, StoreError};

const LOG_TAG: &str = "e2ee";

/// How long a group is not moved back to encrypted after it was moved to
/// unencrypted, and after the device last tried (RCC.16 section 11.2)
const UPGRADE_BACKOFF: Duration = Duration::from_secs(2 * 60 * 60);

/// How long the capabilities of the Participants of a group are not asked
/// again after one was found not to advertise E2EE (RCC.16 section 11.1.1)
const CAPABILITY_REFRESH: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long a group is active after a user message was sent or received in
/// it last: its Participants' capabilities are refreshed meanwhile only
/// (RCC.16 sections 1.3, 11.1.1)
const ACTIVE_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How often the use of a group is noted at most
const USE_NOTED_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How long after the capabilities of the Participants of an active group
/// were refreshed they are refreshed again on schedule, a random backoff of
/// up to REFRESH_BACKOFF added (RCC.16 section 11.1.1: at least once a
/// month, once a week recommended)
const REFRESH_EVERY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const REFRESH_BACKOFF: Duration = Duration::from_secs(24 * 60 * 60);

/// Where moving a group back to encrypted stands, kept in the notes of the
/// device
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct UpgradeState {
    /// When the device saw it moved to unencrypted
    pub(super) ended: Option<SystemTime>,
    /// When the device last tried to move it back
    pub(super) attempted: Option<SystemTime>,
    /// When a Participant was last found not to advertise E2EE
    pub(super) incapable: Option<SystemTime>,
    /// The Conversation Focus has no MLS group for it: unencrypted, though
    /// the device may keep one (RCC.16 section 10.1)
    pub(super) without_group: bool,
    /// An Era moving it back to encrypted waits for the Focus to accept the
    /// INVITE restarting the group with it
    pub(super) restarting: bool,
}

/// The groups moved to unencrypted and moved back, by Conversation-ID, as
/// the notes of the device keep them for it to restart with
pub(super) struct Upgrades<'a> {
    pub(super) notes: &'a Notes,
    pub(super) store: &'a MlsStore,
}

impl Upgrades<'_> {
    /// What `read` reads of the group `conversation_id`, if it has an
    /// UpgradeState
    fn read<R>(&self, conversation_id: &str, read: impl FnOnce(&UpgradeState) -> R) -> Option<R> {
        self.notes
            .read(|data| data.upgrades.get(conversation_id).map(read))
    }

    /// Changes the UpgradeState of the group `conversation_id` as `change`
    /// does, one made for it if `make` and it has none, kept as the notes
    /// are; one left as a new one is let go of
    fn change(&self, conversation_id: &str, make: bool, change: impl FnOnce(&mut UpgradeState)) {
        self.notes.hold(self.store, |data| {
            if make && !data.upgrades.contains_key(conversation_id) {
                data.upgrades
                    .insert(String::from(conversation_id), UpgradeState::default());
            }
            if let Some(upgrade) = data.upgrades.get_mut(conversation_id) {
                change(upgrade);
                if *upgrade == UpgradeState::default() {
                    data.upgrades.remove(conversation_id);
                }
            }
        });
    }

    /// Takes note of the device seeing the group `conversation_id` moved to
    /// unencrypted at `now`
    pub(super) fn ended(&self, conversation_id: &str, now: SystemTime) {
        self.change(conversation_id, true, |upgrade| upgrade.ended = Some(now));
    }

    /// Takes note of the membership of the group `conversation_id` changing,
    /// which lifts the waits but that between two tries (RCC.16 sections
    /// 11.1.1, 11.2)
    fn membership_changed(&self, conversation_id: &str) {
        self.change(conversation_id, false, |upgrade| {
            upgrade.ended = None;
            upgrade.incapable = None;
        });
    }

    /// Whether the group `conversation_id` may be moved back to encrypted
    /// at `now`, as far as the time tells
    fn due(&self, conversation_id: &str, now: SystemTime) -> bool {
        self.read(conversation_id, |upgrade| due(upgrade, now))
            .unwrap_or(true)
    }

    /// Starts moving the group `conversation_id` back to encrypted at `now`,
    /// after which it is not due for two hours; false if it is not due
    fn begin(&self, conversation_id: &str, now: SystemTime) -> bool {
        if !self.due(conversation_id, now) {
            return false;
        }
        self.change(conversation_id, true, |upgrade| {
            upgrade.attempted = Some(now)
        });
        true
    }

    /// Takes note of a Participant of the group `conversation_id` found not
    /// to advertise E2EE at `now`
    fn incapable(&self, conversation_id: &str, now: SystemTime) {
        self.change(conversation_id, false, |upgrade| {
            upgrade.incapable = Some(now)
        });
    }

    /// Takes note of the Conversation Focus having no MLS group for the
    /// group `conversation_id`, found at `now`
    fn lost_group(&self, conversation_id: &str, now: SystemTime) {
        self.change(conversation_id, true, |upgrade| {
            upgrade.without_group = true;
            upgrade.ended = Some(now);
        });
    }

    /// Whether the Conversation Focus has no MLS group for the group
    /// `conversation_id`, an Era moving it back to encrypted being made or not
    pub(super) fn without_group(&self, conversation_id: &str) -> bool {
        self.read(conversation_id, |upgrade| upgrade.without_group)
            .unwrap_or(false)
    }

    /// Whether an Era moving the group `conversation_id` back to encrypted
    /// waits for the Conversation Focus
    pub(super) fn restarting(&self, conversation_id: &str) -> bool {
        self.read(conversation_id, |upgrade| upgrade.restarting)
            .unwrap_or(false)
    }

    /// The groups an Era moving them back to encrypted waits for the
    /// Conversation Focus of
    pub(super) fn all_restarting(&self) -> Vec<String> {
        self.notes.read(|data| {
            data.upgrades
                .iter()
                .filter(|(_, upgrade)| upgrade.restarting)
                .map(|(conversation_id, _)| conversation_id.clone())
                .collect()
        })
    }

    /// Takes note of an Era moving the group `conversation_id` back to
    /// encrypted made, unencrypted until the Conversation Focus accepts it
    fn restart(&self, conversation_id: &str) {
        self.change(conversation_id, true, |upgrade| {
            upgrade.without_group = true;
            upgrade.restarting = true;
        });
    }

    /// Takes note of the Era moving the group `conversation_id` back to
    /// encrypted being accepted by the Conversation Focus, or let go of if
    /// not `accepted`
    pub(super) fn restart_ended(&self, conversation_id: &str, accepted: bool) {
        if !self.restarting(conversation_id) {
            return;
        }
        self.change(conversation_id, false, |upgrade| {
            upgrade.restarting = false;
            upgrade.without_group &= !accepted;
        });
    }

    /// Lets go of what stands for the group `conversation_id`
    pub(super) fn forget(&self, conversation_id: &str) {
        self.notes.hold(self.store, |data| {
            data.upgrades.remove(conversation_id);
            data.groups.remove(conversation_id);
        });
    }
}

/// When a group was last used, and what its Conversation Focus last told of
/// its Participants, kept in the notes of the device for its capabilities
/// to be refreshed on schedule (RCC.16 section 11.1.1)
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct GroupUse {
    /// When a user message was last sent or received in it, at most a day
    /// late
    pub(super) used: Option<SystemTime>,
    /// The URIs of its Participants, the user among them, as its Focus last
    /// told them
    pub(super) participants: Vec<String>,
    /// When the capabilities of its Participants are to be refreshed next;
    /// at once if never
    pub(super) refresh_at: Option<SystemTime>,
}

/// Whether `group` was used within ACTIVE_FOR of `now`
fn active(group: &GroupUse, now: SystemTime) -> bool {
    group.used.is_some_and(|used| {
        now.duration_since(used)
            .map_or(true, |since| since < ACTIVE_FOR)
    })
}

/// When the capabilities refreshed at `now` are to be refreshed next: after
/// REFRESH_EVERY, and a random backoff of up to REFRESH_BACKOFF
fn next_refresh(now: SystemTime) -> SystemTime {
    let random = u64::from_be_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    now + REFRESH_EVERY + Duration::from_secs(random % REFRESH_BACKOFF.as_secs())
}

/// The GroupUses `groups`, as the notes of the device hold them
pub(super) fn encode_groups(groups: &BTreeMap<String, GroupUse>) -> Vec<u8> {
    let mut data = Vec::new();
    for (conversation_id, group) in groups {
        put(&mut data, conversation_id.as_bytes());
        for time in [group.used, group.refresh_at] {
            match time {
                None => data.push(0),
                Some(time) => {
                    data.push(1);
                    put_time(&mut data, time);
                }
            }
        }
        data.extend_from_slice(&(group.participants.len() as u32).to_be_bytes());
        for participant in &group.participants {
            put(&mut data, participant.as_bytes());
        }
    }
    data
}

/// The GroupUses `reader` reads to its end, as encode_groups() puts them;
/// None if they cannot be read
pub(super) fn decode_groups(reader: &mut Reader) -> Option<BTreeMap<String, GroupUse>> {
    let mut groups = BTreeMap::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let mut time = || match reader.flag()? {
            false => Some(None),
            true => Some(Some(reader.time()?)),
        };
        let (used, refresh_at) = (time()?, time()?);
        let count = reader.u32()?;
        let participants = (0..count)
            .map(|_| reader.string())
            .collect::<Option<Vec<_>>>()?;
        groups.insert(
            conversation_id,
            GroupUse {
                used,
                participants,
                refresh_at,
            },
        );
    }
    Some(groups)
}

/// The UpgradeStates `upgrades`, as the notes of the device hold them
pub(super) fn encode(upgrades: &BTreeMap<String, UpgradeState>) -> Vec<u8> {
    let mut data = Vec::new();
    for (conversation_id, upgrade) in upgrades {
        put(&mut data, conversation_id.as_bytes());
        for time in [upgrade.ended, upgrade.attempted, upgrade.incapable] {
            match time {
                None => data.push(0),
                Some(time) => {
                    data.push(1);
                    put_time(&mut data, time);
                }
            }
        }
        data.push(u8::from(upgrade.without_group));
        data.push(u8::from(upgrade.restarting));
    }
    data
}

/// The UpgradeStates `reader` reads to its end, as encode() puts them;
/// None if they cannot be read
pub(super) fn decode(reader: &mut Reader) -> Option<BTreeMap<String, UpgradeState>> {
    let mut upgrades = BTreeMap::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let mut time = || match reader.flag()? {
            false => Some(None),
            true => Some(Some(reader.time()?)),
        };
        let (ended, attempted, incapable) = (time()?, time()?, time()?);
        upgrades.insert(
            conversation_id,
            UpgradeState {
                ended,
                attempted,
                incapable,
                without_group: reader.flag()?,
                restarting: reader.flag()?,
            },
        );
    }
    Some(upgrades)
}

/// Whether `upgrade` may be tried at `now`
fn due(upgrade: &UpgradeState, now: SystemTime) -> bool {
    waited(upgrade.ended, UPGRADE_BACKOFF, now)
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
        (self.resurrectable(conversation_id) || self.era_upgradable(conversation_id))
            && self.certificate_lasting()
            && self.upgrades().due(conversation_id, self.store().now())
    }

    /// Whether the group chat `conversation_id` is unencrypted for want of an
    /// MLS group the Conversation Focus has, as it never had one or lost it,
    /// so that an Era of its own is to move it back to encrypted (RCC.16
    /// sections 10.1, 11.1); not while one waits for the Focus, its Commit
    /// pending
    fn era_upgradable(&self, conversation_id: &str) -> bool {
        match self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                !conversation.has_pending_commit()
            }) {
            Ok(settled) => settled && self.upgrades().without_group(conversation_id),
            Err(StoreError::Mls(ErrorKind::UnknownGroup)) => true,
            Err(_) => false,
        }
    }

    /// Takes note of the Conversation Focus having no MLS group for the group
    /// chat `conversation_id`, as it answers an MLS-Group-Info-Pull with 469:
    /// unencrypted from now on, though the device keeps its group, until
    /// moved back to encrypted with an Era of its own (RCC.16 sections 6.3.1,
    /// 10.1, 11.1)
    pub fn lost_group(&self, conversation_id: &str) {
        self.upgrades()
            .lost_group(conversation_id, self.store().now());
    }

    /// Whether the MLS group `conversation_id` is one moved to unencrypted
    /// that can be moved back as it is, its Conversation Focus having it
    fn resurrectable(&self, conversation_id: &str) -> bool {
        if self.upgrades().without_group(conversation_id) {
            return false;
        }
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
    /// `message/mls-rcs-client` of the move (RCC.16 section 11.1)
    ///
    /// Each Participant is asked for its capabilities with `capabilities`
    /// (section 11.1). A group the Focus has is resurrected with a Commit to
    /// send to the Focus over MSRP (sections 9.5.1, 11.1.2): it removes
    /// end_mls, and the Clients of members who are no longer Participants,
    /// the user's aside; it replaces the Clients whose certificate expired,
    /// and adds the Clients of the Participants missing from the group, with
    /// the KeyPackages of all the Clients of their Participants (section 5.3).
    /// A group the Focus has none of is made anew in an Era of all the
    /// Clients of its Participants, for the INVITE restarting the group to
    /// carry: the next Era after the group of the device, without end_mls,
    /// or the first of the conversation if the device has none (sections
    /// 8.3.1, 11.1); messages are sent unencrypted until the Focus accepts it.
    /// The Commit is applied once the Focus accepts it.
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
    ) -> Option<Upgrade> {
        if !self.certificate_lasting() {
            return None;
        }
        let resurrectable = self.resurrectable(conversation_id);
        if !resurrectable && !self.era_upgradable(conversation_id) {
            return None;
        }
        if !self.upgrades().begin(conversation_id, self.store().now()) {
            return None;
        }
        // its Participants' capabilities refreshed, as on schedule (section
        // 11.1.1)
        self.refreshed(conversation_id);
        let moved = match resurrectable {
            true => self
                .resurrect(conversation_id, from, to, participants, capabilities)
                .await
                .map(Upgrade::InSession),
            false => self
                .era_moving_back(conversation_id, from, to, participants, capabilities)
                .await
                .map(Upgrade::Restart),
        };
        match moved {
            Ok(upgrade) => Some(upgrade),
            Err(NotMoved::Incapable) => {
                self.upgrades()
                    .incapable(conversation_id, self.store().now());
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

    /// The Participants of `participants` besides the user, by tel URI, once
    /// each
    fn participants_besides_user(&self, participants: &[String]) -> Vec<String> {
        let own = self.store().credential();
        let mut tel_uris: Vec<String> = Vec::new();
        for participant in participants {
            let Some(tel_uri) = participant_tel_uri(std::iter::once(participant.as_str()), None)
            else {
                continue;
            };
            let of_user = own.as_ref().is_some_and(|own| is_of(own, &tel_uri));
            if !of_user && !tel_uris.iter().any(|known| same_tel_uri(known, &tel_uri)) {
                tel_uris.push(tel_uri);
            }
        }
        tel_uris
    }

    /// The CPIM message carrying the Era moving the group chat
    /// `conversation_id` back to encrypted, as upgrade_group() makes it
    async fn era_moving_back(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        participants: &[String],
        capabilities: &CapabilityQuery,
    ) -> Result<Vec<u8>, NotMoved> {
        let tel_uris = self.participants_besides_user(participants);
        let recipients = recipients(&tel_uris, capabilities)
            .await
            .ok_or(NotMoved::Incapable)?;

        let base = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                EraBase::of_conversation(conversation)
            })
            .ok();
        let cpim = match base {
            Some(base) => {
                self.next_era(
                    conversation_id,
                    from,
                    to,
                    recipients,
                    &base.without_encryption_end(),
                )
                .await
            }
            None => {
                self.create_group(conversation_id, from, to, recipients)
                    .await
            }
        }
        .map_err(NotMoved::Group)?;
        self.upgrades().restart(conversation_id);
        Ok(cpim)
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
        let tel_uris = self.participants_besides_user(participants);
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

impl E2eeDevice {
    /// Takes note of a user message sent or received in the group chat
    /// `conversation_id`, which keeps it active for 30 days (RCC.16 sections
    /// 1.3, 11.1.1); once a day at most. Groups no longer active are let go
    /// of then.
    pub fn group_used(&self, conversation_id: &str) {
        let now = self.store().now();
        let noted = self.notes().read(|data| {
            data.groups
                .get(conversation_id)
                .and_then(|group| group.used)
                .is_some_and(|used| {
                    now.duration_since(used)
                        .is_ok_and(|since| since < USE_NOTED_EVERY)
                })
        });
        if noted {
            return;
        }
        self.notes().hold(self.store(), |data| {
            data.groups
                .retain(|group_id, group| group_id == conversation_id || active(group, now));
            data.groups
                .entry(String::from(conversation_id))
                .or_default()
                .used = Some(now);
        });
    }

    /// Takes note of `participants` as the URIs of the Participants of the
    /// group chat `conversation_id`, as its Conversation Focus tells them,
    /// for their capabilities to be refreshed while there is no session of
    /// it (RCC.16 section 11.1.1)
    pub fn participants_told(&self, conversation_id: &str, participants: &[String]) {
        let known = self.notes().read(|data| {
            data.groups
                .get(conversation_id)
                .is_some_and(|group| group.participants == participants)
        });
        if !known {
            self.notes().hold(self.store(), |data| {
                data.groups
                    .entry(String::from(conversation_id))
                    .or_default()
                    .participants = participants.to_vec();
            });
        }
    }

    /// Takes note of the capabilities of the Participants of the group chat
    /// `conversation_id` refreshed now, the next refresh due a week on and a
    /// random backoff after (RCC.16 section 11.1.1)
    fn refreshed(&self, conversation_id: &str) {
        let refresh_at = next_refresh(self.store().now());
        self.notes().hold(self.store(), |data| {
            if let Some(group) = data.groups.get_mut(conversation_id) {
                group.refresh_at = Some(refresh_at);
            }
        });
    }

    /// The group chats whose Participants' capabilities are to be refreshed
    /// now on schedule, each with the URIs of its Participants as last told,
    /// taken as refreshed (RCC.16 section 11.1.1): those used in the last 30
    /// days, whose last refresh was a week and a random backoff ago, and
    /// that are to be moved back to encrypted as upgrade_due() tells, as
    /// upgrade_group() does then
    pub fn scheduled_upgrades(&self) -> Vec<(String, Vec<String>)> {
        let now = self.store().now();
        let due: Vec<(String, Vec<String>)> = self.notes().read(|data| {
            data.groups
                .iter()
                .filter(|(_, group)| {
                    active(group, now)
                        && !group.participants.is_empty()
                        && group.refresh_at.is_none_or(|refresh_at| refresh_at <= now)
                })
                .map(|(conversation_id, group)| {
                    (conversation_id.clone(), group.participants.clone())
                })
                .collect()
        });
        due.into_iter()
            .filter(|(conversation_id, _)| self.upgrade_due(conversation_id))
            .inspect(|(conversation_id, _)| self.refreshed(conversation_id))
            .collect()
    }
}
