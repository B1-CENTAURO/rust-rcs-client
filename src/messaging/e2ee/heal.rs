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

//! Self-healing the MLS group of a group chat whose state fell out of step
//! with that of its Conversation Focus, and making it anew in its next Era
//! when that fails (RCC.16 sections 6.3, 7.10, 8.3, 10.1, 11.2)

use std::collections::BTreeMap;
use std::sync::Weak;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::heal::SelfHealProgress;
use rust_rcs_core::mls::rcs::proto::{
    self, server_mls_rcs_message, EndMlsReason, MlsGroupInfo, ServerMlsRcsMessage,
};
use rust_rcs_core::mls::rcs::{
    INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL, INFO_PACKAGE_MLS_GROUP_INFO_PULL,
};
use rust_rcs_core::mls::ErrorKind;

use crate::messaging::cpm::encryption::GroupInfoPull;

use super::device::E2eeDevice;
use super::era::NO_MLS_GROUP;
use super::group::GroupError;
use super::notes::{put, put_times, Notes, Reader};
use super::store::{MlsStore, StoreError};

const LOG_TAG: &str = "e2ee";

/// How many times a group is self-healed within HEAL_PERIOD at most, the
/// procedure taken to have failed beyond (RCC.16 section 10.1)
const HEAL_ATTEMPTS: usize = 5;
const HEAL_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// How many Eras of a group, besides Unencrypted Singleton ones, are made
/// within ERA_PERIOD at most (RCC.16 section 11.2.3)
const ERA_QUOTA: usize = 30;
const ERA_PERIOD: Duration = Duration::from_secs(24 * 60 * 60);

/// The next Era of a group to make
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum NextEra {
    /// With all its Participants (RCC.16 section 8.3)
    Encrypted,
    /// With the device alone, the group moved to unencrypted for the reason
    /// given (section 11.2.1)
    Singleton(EndMlsReason),
}

/// What is being done to a group
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Ongoing {
    /// It is being self-healed
    Healing,
    /// Its next Era is being made
    MakingEra(NextEra),
}

/// Where self-healing a group stands, and making it anew in its next Era,
/// kept in the notes of the device
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Heal {
    /// Its state is out of step with that of its Conversation Focus; never
    /// while it is being self-healed
    pub(super) wanted: bool,
    pub(super) ongoing: Option<Ongoing>,
    /// When it was self-healed, within HEAL_PERIOD
    pub(super) attempts: Vec<SystemTime>,
    /// Self-healing it failed, tried too often lately, or its Focus asks
    /// for it: it is to be made anew in its next Era (RCC.16 sections 8.3,
    /// 10.1, 11.2.2)
    pub(super) failed: bool,
    /// It is to move to an Unencrypted Singleton Era, for the reason given,
    /// rather than to one of all its Participants (sections 10.1, 11.2,
    /// 11.2.1)
    pub(super) singleton: Option<EndMlsReason>,
    /// When an Era of it was made, besides Unencrypted Singleton ones, within
    /// ERA_PERIOD (section 11.2.3)
    pub(super) eras: Vec<SystemTime>,
}

/// Whether `then` is within `period` of `now`, as a time to come is
fn within(then: SystemTime, period: Duration, now: SystemTime) -> bool {
    now.duration_since(then)
        .map_or(true, |passed| passed < period)
}

/// The groups to self-heal and those being self-healed, by Conversation-ID,
/// as the notes of the device keep them for it to restart with
pub(super) struct Heals<'a> {
    pub(super) notes: &'a Notes,
    pub(super) store: &'a MlsStore,
}

impl Heals<'_> {
    /// What `read` reads of the group `conversation_id`, if it has a Heal
    fn read<R>(&self, conversation_id: &str, read: impl FnOnce(&Heal) -> R) -> Option<R> {
        self.notes
            .read(|data| data.heals.get(conversation_id).map(read))
    }

    /// Changes the Heal of the group `conversation_id` as `change` does, one
    /// made for it if `make` and it has none, kept as the notes are; one
    /// left as a new one is let go of
    fn change<R>(
        &self,
        conversation_id: &str,
        make: bool,
        change: impl FnOnce(&mut Heal) -> R,
    ) -> Option<R> {
        self.notes.hold(self.store, |data| {
            if make && !data.heals.contains_key(conversation_id) {
                data.heals
                    .insert(String::from(conversation_id), Heal::default());
            }
            let heal = data.heals.get_mut(conversation_id)?;
            let changed = change(heal);
            if *heal == Heal::default() {
                data.heals.remove(conversation_id);
            }
            Some(changed)
        })
    }

    /// Takes note of the group `conversation_id` falling out of step with
    /// its Conversation Focus, unless it is being self-healed, which what
    /// fails meanwhile may be of
    pub(super) fn want(&self, conversation_id: &str) {
        self.change(conversation_id, true, |heal| {
            if heal.ongoing.is_none() {
                heal.wanted = true;
            }
        });
    }

    /// Whether the group `conversation_id` is to be self-healed, which it is
    /// not while it is being
    fn wanted(&self, conversation_id: &str) -> bool {
        self.read(conversation_id, |heal| heal.wanted)
            .unwrap_or(false)
    }

    /// Whether the group `conversation_id` is being self-healed, or made
    /// anew in its next Era
    pub(super) fn ongoing(&self, conversation_id: &str) -> bool {
        self.read(conversation_id, |heal| heal.ongoing.is_some())
            .unwrap_or(false)
    }

    /// Starts self-healing the group `conversation_id`; false if it is not
    /// to be, if it is being already, or if it was too often lately
    fn begin(&self, conversation_id: &str) -> bool {
        let now = self.store.now();
        self.change(conversation_id, false, |heal| {
            if !heal.wanted {
                return false;
            }
            heal.wanted = false;
            heal.attempts
                .retain(|attempt| within(*attempt, HEAL_PERIOD, now));
            if heal.attempts.len() >= HEAL_ATTEMPTS {
                platform_log(LOG_TAG, "self-healing failed, tried too often");
                heal.failed = true;
                return false;
            }
            heal.attempts.push(now);
            heal.ongoing = Some(Ongoing::Healing);
            true
        })
        .unwrap_or(false)
    }

    /// Takes note of the group `conversation_id` to be made anew in its next
    /// Era, as when its Conversation Focus refused the Era made last for not
    /// following the latest, or once the device moved its epoch on too often
    /// (RCC.16 sections 6.2.5, 8.3.1, 11.2.2)
    pub(super) fn want_new_era(&self, conversation_id: &str) {
        self.change(conversation_id, true, |heal| heal.failed = true);
    }

    /// Takes note of the group `conversation_id` to move to an Unencrypted
    /// Singleton Era for `reason` (RCC.16 sections 10.1, 11.2, 11.2.1)
    pub(super) fn want_singleton(&self, conversation_id: &str, reason: EndMlsReason) {
        self.change(conversation_id, true, |heal| heal.singleton = Some(reason));
    }

    /// Whether a next Era of the group `conversation_id` is to be made
    /// (RCC.16 sections 8.3, 10.1, 11.2.1)
    pub(super) fn era_due(&self, conversation_id: &str) -> bool {
        self.read(conversation_id, |heal| {
            heal.failed || heal.singleton.is_some()
        })
        .unwrap_or(false)
    }

    /// Starts making the next Era of the group `conversation_id`, during
    /// which it is not self-healed and no other is due: an Unencrypted
    /// Singleton one if one is due, or if ERA_QUOTA Eras of it were made
    /// lately (RCC.16 section 11.2.3); None if none is due, or while the
    /// group is being self-healed or made anew
    pub(super) fn begin_new_era(&self, conversation_id: &str) -> Option<NextEra> {
        let now = self.store.now();
        self.change(conversation_id, false, |heal| {
            if heal.ongoing.is_some() {
                return None;
            }
            let next = match heal.singleton {
                Some(reason) => NextEra::Singleton(reason),
                None if heal.failed => {
                    heal.eras.retain(|era| within(*era, ERA_PERIOD, now));
                    if heal.eras.len() >= ERA_QUOTA {
                        platform_log(LOG_TAG, "too many Eras made lately");
                        NextEra::Singleton(EndMlsReason::ServerFailureEraAdvancementQuotaReached)
                    } else {
                        NextEra::Encrypted
                    }
                }
                None => return None,
            };
            heal.singleton = None;
            heal.failed = false;
            heal.wanted = false;
            heal.ongoing = Some(Ongoing::MakingEra(next));
            Some(next)
        })
        .flatten()
    }

    /// Takes note of the Era `next` of the group `conversation_id` that
    /// could not be begun for now, to be tried again
    pub(super) fn put_off_new_era(&self, conversation_id: &str, next: NextEra) {
        self.change(conversation_id, false, |heal| {
            put_back(heal, next);
            heal.ongoing = None;
        });
    }

    /// Takes note of an Era of the group `conversation_id` made, besides an
    /// Unencrypted Singleton one, which ERA_QUOTA counts
    pub(super) fn era_made(&self, conversation_id: &str) {
        let now = self.store.now();
        self.change(conversation_id, true, |heal| heal.eras.push(now));
    }

    /// Self-heals the group `conversation_id` from scratch from now on, as
    /// once a new Era of it was tried, the Eras made of it still counted
    pub(super) fn start_over(&self, conversation_id: &str) {
        self.change(conversation_id, false, |heal| {
            *heal = Heal {
                eras: std::mem::take(&mut heal.eras),
                ..Heal::default()
            };
        });
    }

    fn end(&self, conversation_id: &str) {
        self.change(conversation_id, false, |heal| heal.ongoing = None);
    }

    /// Lets go of what stands for the group `conversation_id`
    pub(super) fn forget(&self, conversation_id: &str) {
        self.notes
            .hold(self.store, |data| data.heals.remove(conversation_id));
    }
}

/// `heal` to make the Era `next` again
fn put_back(heal: &mut Heal, next: NextEra) {
    match next {
        NextEra::Encrypted => heal.failed = true,
        NextEra::Singleton(reason) => heal.singleton = Some(reason),
    }
}

/// The Heals `heals`, as the notes of the device hold them
pub(super) fn encode(heals: &BTreeMap<String, Heal>) -> Vec<u8> {
    let mut data = Vec::new();
    for (conversation_id, heal) in heals {
        put(&mut data, conversation_id.as_bytes());
        data.push(u8::from(heal.wanted));
        data.push(u8::from(heal.failed));
        put_reason(&mut data, heal.singleton);
        match heal.ongoing {
            None => data.push(0),
            Some(Ongoing::Healing) => data.push(1),
            Some(Ongoing::MakingEra(NextEra::Encrypted)) => data.push(2),
            Some(Ongoing::MakingEra(NextEra::Singleton(reason))) => {
                data.push(3);
                data.extend_from_slice(&(reason as i32).to_be_bytes());
            }
        }
        put_times(&mut data, &heal.attempts);
        put_times(&mut data, &heal.eras);
    }
    data
}

/// The Heals `reader` reads to its end, as encode() puts them; None if they
/// cannot be read
///
/// What was being done when the device stopped is to be done again: a group
/// being self-healed is to be self-healed, and one being made anew is to
/// be made anew.
pub(super) fn decode(reader: &mut Reader) -> Option<BTreeMap<String, Heal>> {
    let mut heals = BTreeMap::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let mut heal = Heal {
            wanted: reader.flag()?,
            failed: reader.flag()?,
            singleton: read_reason(reader)?,
            ..Heal::default()
        };
        match reader.byte()? {
            0 => {}
            1 => heal.wanted = true,
            2 => put_back(&mut heal, NextEra::Encrypted),
            3 => put_back(&mut heal, NextEra::Singleton(reason(reader.u32()?)?)),
            _ => return None,
        }
        heal.attempts = reader.times()?;
        heal.eras = reader.times()?;
        heals.insert(conversation_id, heal);
    }
    Some(heals)
}

/// `reason` if there is one, as read_reason() reads it
fn put_reason(data: &mut Vec<u8>, reason: Option<EndMlsReason>) {
    match reason {
        None => data.push(0),
        Some(reason) => {
            data.push(1);
            data.extend_from_slice(&(reason as i32).to_be_bytes());
        }
    }
}

fn read_reason(reader: &mut Reader) -> Option<Option<EndMlsReason>> {
    match reader.flag()? {
        false => Some(None),
        true => Some(Some(reason(reader.u32()?)?)),
    }
}

fn reason(value: u32) -> Option<EndMlsReason> {
    EndMlsReason::try_from(value as i32).ok()
}

impl E2eeDevice {
    /// Whether the MLS group `conversation_id` fell out of step with that of
    /// its Conversation Focus and is to be self-healed, as when a message
    /// could not be decrypted, a control message could not be applied, or the
    /// Focus found its epoch authenticator or confirmation tag wrong (RCC.16
    /// sections 6.2.5, 10.1); false while it is being self-healed
    pub fn needs_healing(&self, conversation_id: &str) -> bool {
        self.heals().wanted(conversation_id)
    }

    /// The body of an MLS-Enhanced-Group-Info-Pull INFO request, asking for
    /// what came after the epoch the group `conversation_id` is in (RCC.16
    /// sections 6.3.2, 7.10.2)
    pub fn enhanced_group_info_request(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<u8>, StoreError> {
        self.store()
            .with_conversation(conversation_id.as_bytes(), |conversation, _| {
                Ok(conversation.enhanced_group_info_request())
            })
    }

    /// Applies the control messages the MlsEnhancedGroupInfo `body` of the
    /// Conversation Focus carries to the group `conversation_id`, telling
    /// whether it is up to date, more are to be asked for, or it is to be
    /// rejoined (RCC.16 section 10.1.2), and the epoch authenticator of the
    /// latest epoch of the Focus, that of the GroupInfo to rejoin with
    pub fn process_enhanced_group_info(
        &self,
        conversation_id: &str,
        body: &[u8],
    ) -> Result<(SelfHealProgress, Vec<u8>), StoreError> {
        let (healed, pending) = self.store().with_conversation(
            conversation_id.as_bytes(),
            |conversation, client| {
                let healed = conversation.process_enhanced_group_info(client, body);
                Ok((healed, conversation.has_pending_commit()))
            },
        )?;
        // a Commit of the device among those applied
        if !pending {
            self.control_messages().remove(conversation_id);
        }
        let healed = healed.map_err(StoreError::Mls)?;
        for (_, taken) in &healed.applied {
            self.metadata_keys_received(conversation_id, taken);
        }
        Ok((healed.progress, healed.latest_epoch.epoch_authenticator))
    }

    /// Rejoins the MLS group `conversation_id` with an External Commit, from
    /// the GroupInfo `group_info` of the Conversation Focus, its leaf taking
    /// the place of the one the device had: the CPIM message, `from` and `to`
    /// its own, carrying the `message/mls-rcs-client` to send to the Focus
    /// over MSRP (RCC.16 sections 9.5.1, 10.1.1)
    ///
    /// Unlike other Commits, the External Commit is applied at once. A Focus
    /// refusing it leaves the group to be self-healed again.
    ///
    /// The Group Metadata keys of the device are checked against the group
    /// rejoined, and asked for if out of sync, in the same CommitList, with
    /// a Commit after the External Commit (sections 10.1.1, 10.5.1, 10.5.2):
    /// if it misses the key of the icon or subject the group commits to, if
    /// it keeps no continuity token, or if the one it keeps is not the one
    /// the GroupInfo commits to. That is told by the epoch authenticator of
    /// the GroupInfo, `epoch_authenticator`, which the enhanced GroupInfo of
    /// the Focus gives alone.
    pub fn rejoin_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        group_info: &MlsGroupInfo,
        epoch_authenticator: Option<&[u8]>,
    ) -> Result<Vec<u8>, GroupError> {
        let token_mismatch = epoch_authenticator.is_some_and(|epoch_authenticator| {
            self.token_mismatched(conversation_id, &group_info.group_info, epoch_authenticator)
        });
        self.recoveries().check(conversation_id, token_mismatch);
        let (group_id, (client_message, checked, asked)) = self
            .store()
            .add_conversation(|client| {
                let (mut conversation, output) = client.rejoin_conversation(group_info)?;
                let (output, checked, asked) = match conversation.group_id()
                    == conversation_id.as_bytes()
                {
                    true => self.asking_with(conversation_id, &mut conversation, client, output),
                    false => (output, false, false),
                };
                let client_message = output.to_client_message()?;
                Ok((conversation, (client_message, checked, asked)))
            })
            .map_err(GroupError::Store)?;
        // the GroupInfo of another group, which no control message is sent for
        if group_id != conversation_id.as_bytes() {
            return Err(GroupError::Store(StoreError::Mls(
                ErrorKind::UnexpectedMessage,
            )));
        }
        self.keys_checked(conversation_id, checked, asked);
        Ok(self.sent_in(conversation_id, from, to, &client_message))
    }
}

/// The MlsGroupInfo of the `message/mls-rcs-server` `body` of the 200 OK to an
/// MLS-Group-Info-Pull INFO request (RCC.16 section 7.10.1)
pub(super) fn pulled_group_info(body: &[u8]) -> Option<MlsGroupInfo> {
    match proto::decode::<ServerMlsRcsMessage>(body).ok()?.payload {
        Some(server_mls_rcs_message::Payload::MlsGroupInfo(group_info)) => Some(group_info),
        _ => None,
    }
}

/// Self-heals the MLS group `conversation_id` of the device, asking its
/// Conversation Focus with `pull` (RCC.16 section 10.1): applying the control
/// messages it missed if the Focus gives them, else rejoining the group with
/// an External Commit, whose CPIM message, `from` and `to` its own, is given
/// out to send
///
/// None once the group is up to date, or if it cannot be healed, as when the
/// Focus has no MLS group for the conversation, which moving to unencrypted
/// is for (section 10.1).
pub(super) async fn heal(
    device: &Weak<E2eeDevice>,
    conversation_id: &str,
    from: &str,
    to: &str,
    pull: &GroupInfoPull,
) -> Option<Vec<u8>> {
    // the enhanced way first, page by page (section 10.1.2)
    let mut asked: Option<Vec<u8>> = None;
    loop {
        let request = device
            .upgrade()?
            .enhanced_group_info_request(conversation_id)
            .ok()?;
        // a page that brought nothing new
        if asked.as_ref() == Some(&request) {
            break;
        }
        asked = Some(request.clone());

        let answer = pull(INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL, Some(request)).await;
        let progress = match answer {
            Some((200, body)) => device
                .upgrade()?
                .process_enhanced_group_info(conversation_id, &body),
            _ => break,
        };
        match progress {
            Ok((SelfHealProgress::UpToDate, _)) => return None,
            Ok((SelfHealProgress::NextPage, _)) => {}
            Ok((SelfHealProgress::Rejoin(group_info), epoch_authenticator)) => {
                return rejoin(
                    device,
                    conversation_id,
                    from,
                    to,
                    &group_info,
                    Some(&epoch_authenticator),
                )
            }
            Err(e) => {
                platform_log(LOG_TAG, format!("enhanced GroupInfo not taken: {:?}", e));
                break;
            }
        }
    }

    // the GroupInfo then (section 10.1.1)
    let group_info = match pull(INFO_PACKAGE_MLS_GROUP_INFO_PULL, None).await {
        Some((200, body)) => pulled_group_info(&body),
        // the Focus has no MLS group for the conversation, which is
        // unencrypted from now on (sections 6.3.1, 10.1)
        Some((NO_MLS_GROUP, _)) => {
            platform_log(LOG_TAG, "group not healed, the focus has no MLS group");
            device.upgrade()?.lost_group(conversation_id);
            return None;
        }
        answer => {
            platform_log(
                LOG_TAG,
                format!(
                    "group not healed, its GroupInfo not given: {:?}",
                    answer.map(|(status_code, _)| status_code)
                ),
            );
            return None;
        }
    };
    match group_info {
        Some(group_info) => rejoin(device, conversation_id, from, to, &group_info, None),
        None => {
            platform_log(LOG_TAG, "group not healed, its GroupInfo not read");
            None
        }
    }
}

fn rejoin(
    device: &Weak<E2eeDevice>,
    conversation_id: &str,
    from: &str,
    to: &str,
    group_info: &MlsGroupInfo,
    epoch_authenticator: Option<&[u8]>,
) -> Option<Vec<u8>> {
    match device
        .upgrade()?
        .rejoin_group(conversation_id, from, to, group_info, epoch_authenticator)
    {
        Ok(cpim) => Some(cpim),
        Err(e) => {
            platform_log(LOG_TAG, format!("group not rejoined: {:?}", e));
            None
        }
    }
}

/// Self-heals the group `conversation_id` of `device` as heal() does, if it
/// is to be and is not being already, within the limits of RCC.16 section
/// 10.1; `healed` is told once done
pub(super) async fn heal_once(
    device: Weak<E2eeDevice>,
    conversation_id: String,
    from: String,
    to: String,
    pull: GroupInfoPull,
    healed: impl FnOnce(),
) -> Option<Vec<u8>> {
    if !device.upgrade()?.heals().begin(&conversation_id) {
        return None;
    }
    let cpim = heal(&device, &conversation_id, &from, &to, &pull).await;
    if let Some(device) = device.upgrade() {
        device.heals().end(&conversation_id);
    }
    healed();
    cpim
}
