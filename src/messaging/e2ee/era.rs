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

//! New Eras of the MLS groups of group chats (RCC.16 section 8.3)

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::credential_tel_uris;
use rust_rcs_core::mls::rcs::era::EraBase;
use rust_rcs_core::mls::rcs::proto::{EndMlsReason, MlsGroupInfo};
use rust_rcs_core::mls::rcs::INFO_PACKAGE_MLS_GROUP_INFO_PULL;
use rust_rcs_core::mls::{self, CommitOutput, ErrorKind, MlsClient, MlsConversation};

use crate::capability::CapabilityQuery;
use crate::messaging::cpm::encryption::GroupInfoPull;

use super::device::{is_of, E2eeDevice};
use super::group::{recipients, GroupError};
use super::heal::{pulled_group_info, NextEra};
use super::kds::Recipient;
use super::metadata::continuity_token;
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

/// What the Conversation Focus answers an MLS-Group-Info-Pull with when the
/// conversation has no MLS group (RCC.16 section 6.3.1)
pub(super) const NO_MLS_GROUP: u16 = 469;

/// What the Conversation Focus answers the INVITE carrying a new Era with
/// when it is not the Era after the latest (RCC.16 section 8.3.1)
const CONFLICT: u16 = 409;

impl E2eeDevice {
    /// Makes the next Era of the MLS group of the group chat
    /// `conversation_id`, with all the Clients of `recipients`, its
    /// Participants besides the user, as the Home KDS is asked for their
    /// KeyPackages: the CPIM message, `from` and `to` its own, carrying the
    /// `message/mls-rcs-client` the INVITE restarting the group is to carry
    /// (RCC.16 sections 7.9.2, 8.1.2, 8.3.1)
    ///
    /// The Era follows that of `group_info`, the MlsGroupInfo its Conversation
    /// Focus gave, or else that of the group the device has, whose GroupContext
    /// extensions it copies. The continuity token goes on in it, unless a
    /// Participant is not a member of that group, or the group has members the
    /// group of the device does not have (section 8.3.1.2).
    ///
    /// The Era asks its members for the Group Metadata keys the device
    /// misses (sections 8.3, 10.5.2): the key of the icon or subject it
    /// commits to, or the continuity token if none is kept and each
    /// Participant is a member of that group (section 8.3.1.3); a new token
    /// is made otherwise.
    ///
    /// The group of the Era before is let go of once the KeyPackages are
    /// fetched. The Commit is applied once the Focus accepts it.
    pub async fn create_next_era(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        recipients: Vec<Recipient>,
        group_info: Option<&MlsGroupInfo>,
    ) -> Result<Vec<u8>, GroupError> {
        let base = self.era_base(conversation_id, group_info)?;
        self.next_era(conversation_id, from, to, recipients, &base)
            .await
    }

    /// Makes the next Era of the MLS group of the group chat
    /// `conversation_id` an Unencrypted Singleton Era, moved to unencrypted
    /// for `reason`, the device its only member: the CPIM message, `from` and
    /// `to` its own, carrying the `message/mls-rcs-client` the INVITE
    /// restarting the group is to carry (RCC.16 sections 8.3.1, 11.2.1)
    ///
    /// The Era follows that of `group_info`, or else that of the group the
    /// device has, as with create_next_era(), without KeyPackages. The
    /// Commit, adding end_mls, is applied once the Focus accepts it.
    pub fn create_singleton_era(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        group_info: Option<&MlsGroupInfo>,
        reason: EndMlsReason,
    ) -> Result<Vec<u8>, GroupError> {
        let base = self.era_base(conversation_id, group_info)?;
        self.singleton_era(conversation_id, from, to, &base, reason)
    }

    /// What the next Era of the group `conversation_id` follows: the group
    /// as `group_info` tells it, or else as the device has it
    fn era_base(
        &self,
        conversation_id: &str,
        group_info: Option<&MlsGroupInfo>,
    ) -> Result<EraBase, GroupError> {
        let base = match group_info {
            Some(group_info) => EraBase::of_group_info(group_info)
                .map_err(|e| GroupError::Store(StoreError::Mls(e)))?,
            None => self
                .store()
                .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                    EraBase::of_conversation(conversation)
                })
                .map_err(GroupError::Store)?,
        };
        if base.group_id() != conversation_id.as_bytes() {
            return Err(GroupError::Store(StoreError::Mls(
                ErrorKind::UnexpectedMessage,
            )));
        }
        Ok(base)
    }

    /// The next Era after `base` with all the Clients of `recipients`, as
    /// create_next_era() makes it
    pub(super) async fn next_era(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        recipients: Vec<Recipient>,
        base: &EraBase,
    ) -> Result<Vec<u8>, GroupError> {
        let participants = recipients
            .iter()
            .map(|recipient| recipient.tel_uri.clone())
            .collect();
        let key_packages = self.key_packages(recipients).await?;
        self.era_after(
            conversation_id,
            from,
            to,
            base,
            participants,
            |conversation, client| {
                let key_packages: Vec<&[u8]> = key_packages.iter().map(|kp| &kp[..]).collect();
                conversation.add_members(client, &key_packages)
            },
        )
    }

    /// The Unencrypted Singleton Era after `base`, as create_singleton_era()
    /// makes it
    fn singleton_era(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        base: &EraBase,
        reason: EndMlsReason,
    ) -> Result<Vec<u8>, GroupError> {
        self.era_after(
            conversation_id,
            from,
            to,
            base,
            Vec::new(),
            |conversation, client| conversation.set_encryption_ended(client, Some(reason)),
        )
    }

    /// The Era after `base`, `participants` its Participants besides the
    /// user, made with the Commit `commit` makes, in place of the group of the
    /// Era before: the CPIM message, `from` and `to` its own, carrying it
    /// (RCC.16 sections 7.9.2, 8.3.1)
    fn era_after(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        base: &EraBase,
        mut participants: Vec<String>,
        commit: impl FnOnce(&mut MlsConversation, &MlsClient) -> mls::Result<CommitOutput>,
    ) -> Result<Vec<u8>, GroupError> {
        // the Participants of the RCS conversation, the user among them
        participants.extend(
            self.store()
                .credential()
                .and_then(|credential| credential_tel_uris(&credential).ok())
                .and_then(|tel_uris| tel_uris.into_iter().next()),
        );

        let (_, client_message) = self
            .store()
            .add_conversation(|client| {
                let participants: Vec<&str> = participants.iter().map(|p| &p[..]).collect();
                let kept = client.load_conversation(base.group_id()).ok();
                let renew = match continuity_token(client, base.group_id())?.is_empty() {
                    false => !base.continuity_holds(kept.as_ref(), &participants),
                    // asked for of the members, if the Participants are
                    // members (section 8.3.1.3)
                    true => !base.has_participants(&participants),
                };
                drop(kept);

                let mut conversation = client.create_next_era(base, renew)?;
                let made =
                    commit(&mut conversation, client).and_then(|output| output.to_client_message());
                match made {
                    Ok(client_message) => Ok((conversation, client_message)),
                    Err(e) => {
                        let _ = conversation.delete(client);
                        Err(e)
                    }
                }
            })
            .map_err(GroupError::Store)?;

        Ok(self.sent_in(conversation_id, from, to, &client_message))
    }

    /// Whether the MLS group of the group chat `conversation_id` is to be
    /// made anew in its next Era, self-healing it having failed, or to move
    /// to an Unencrypted Singleton Era (RCC.16 sections 8.3, 10.1, 11.2.1)
    pub fn new_era_due(&self, conversation_id: &str) -> bool {
        self.heals().era_due(conversation_id)
    }

    /// Makes the next Era of the MLS group of the group chat
    /// `conversation_id`, if one is due as new_era_due() tells: the CPIM
    /// message, `from` and `to` its own, that the INVITE restarting the group
    /// is to carry, as create_next_era() or create_singleton_era() makes it
    /// (RCC.16 sections 8.3, 10.1, 11.2.1)
    ///
    /// The Era follows that of the GroupInfo asked of the Conversation Focus
    /// with `pull`, or that of the group of the device if the Focus has none.
    /// Its Participants are the members of that group besides the user, as
    /// the Focus keeps its MLS group to the membership of the conversation;
    /// each is asked for its capabilities with `capabilities` (section 5.2).
    /// It is an Unencrypted Singleton Era if one is due, if 30 Eras were made
    /// in the day (section 11.2.3), or if the Era of all the Participants
    /// cannot be made: when one no longer advertises E2EE, or when their
    /// KeyPackages cannot be had (section 10.1).
    ///
    /// The group is not self-healed while the Era is made, nor is another
    /// made at the same time. Self-healing starts over once the GroupInfo is
    /// had, whether the Era can be made or not. None if no new Era is due, if
    /// the Focus gives no GroupInfo for now, which leaves it due, or if its
    /// group was moved to unencrypted already: the group is then self-healed
    /// into it (section 10.1).
    pub async fn make_due_era(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        capabilities: &CapabilityQuery,
        pull: &GroupInfoPull,
    ) -> Option<Vec<u8>> {
        let next = self.heals().begin_new_era(conversation_id)?;
        let group_info = match pull(INFO_PACKAGE_MLS_GROUP_INFO_PULL, None).await {
            Some((200, body)) => match pulled_group_info(&body) {
                Some(group_info) => Some(group_info),
                None => {
                    platform_log(LOG_TAG, "new Era not made, its GroupInfo not read");
                    self.heals().put_off_new_era(conversation_id, next);
                    return None;
                }
            },
            Some((NO_MLS_GROUP, _)) => None,
            answer => {
                platform_log(
                    LOG_TAG,
                    format!(
                        "new Era not made, its GroupInfo not given: {:?}",
                        answer.map(|(status_code, _)| status_code)
                    ),
                );
                self.heals().put_off_new_era(conversation_id, next);
                return None;
            }
        };
        let base = self.era_base(conversation_id, group_info.as_ref());
        self.heals().start_over(conversation_id);
        let base = match base {
            Ok(base) => base,
            Err(e) => {
                platform_log(LOG_TAG, format!("new Era not made: {:?}", e));
                return None;
            }
        };
        if base.is_encryption_ended() {
            platform_log(LOG_TAG, "new Era not made, the group unencrypted already");
            if group_info.is_some() {
                self.heals().want(conversation_id);
            }
            return None;
        }

        let reason = match next {
            NextEra::Singleton(reason) => reason,
            NextEra::Encrypted => {
                match self
                    .era_of_participants(conversation_id, from, to, &base, capabilities)
                    .await
                {
                    Ok(cpim) => {
                        self.heals().era_made(conversation_id);
                        return Some(cpim);
                    }
                    Err(reason) => reason,
                }
            }
        };
        match self.singleton_era(conversation_id, from, to, &base, reason) {
            Ok(cpim) => Some(cpim),
            Err(e) => {
                platform_log(
                    LOG_TAG,
                    format!("Unencrypted Singleton Era not made: {:?}", e),
                );
                None
            }
        }
    }

    /// The next Era after `base` of its members besides the user, each asked
    /// for its capabilities with `capabilities`, as make_due_era() makes it;
    /// or the reason the group moves to unencrypted instead
    async fn era_of_participants(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        base: &EraBase,
        capabilities: &CapabilityQuery,
    ) -> Result<Vec<u8>, EndMlsReason> {
        let own = self.store().credential();
        let mut participants: Vec<String> = Vec::new();
        for member in base.members() {
            let Some(tel_uri) = credential_tel_uris(member)
                .ok()
                .and_then(|tel_uris| tel_uris.into_iter().next())
            else {
                continue;
            };
            let known = participants.iter().any(|known| is_of(member, known));
            let user = own
                .as_ref()
                .is_some_and(|credential| is_of(credential, &tel_uri));
            if !known && !user {
                participants.push(tel_uri);
            }
        }
        let Some(recipients) = recipients(&participants, capabilities).await else {
            platform_log(LOG_TAG, "new Era not made, a Participant not E2EE capable");
            return Err(EndMlsReason::GroupMemberFailsCapabilitiesCheck);
        };

        self.next_era(conversation_id, from, to, recipients, base)
            .await
            .map_err(|e| {
                platform_log(LOG_TAG, format!("new Era not made: {:?}", e));
                match e {
                    GroupError::Kds(_) | GroupError::NotEncryptable(..) => {
                        EndMlsReason::CannotFetchKeypackages
                    }
                    _ => EndMlsReason::InternalClientError,
                }
            })
    }

    /// Takes note of the Conversation Focus refusing with `status_code` the
    /// INVITE restarting the group chat `conversation_id` in the Era the
    /// device made of it last, whose Commit is discarded (RCC.16 sections
    /// 8.3.1, 10.1, 11.2.1)
    ///
    /// Another Era is then due: with 409, the Era did not follow the latest
    /// and is made again from the latest GroupInfo; otherwise the group moves
    /// to an Unencrypted Singleton Era, made again if that is what the Focus
    /// refused.
    pub fn era_refused(&self, conversation_id: &str, status_code: u16) {
        // one moving the group back to encrypted, which stays unencrypted
        // until the next try (section 11.1)
        if self.upgrades().restarting(conversation_id) {
            if let Err(e) = self.discard_pending(conversation_id, false) {
                platform_log(LOG_TAG, format!("refused Era not discarded: {:?}", e));
            }
            return;
        }
        let ending = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                conversation.pending_encryption_end()
            })
            .ok()
            .flatten();
        if let Err(e) = self.discard_pending(conversation_id, false) {
            platform_log(LOG_TAG, format!("refused Era not discarded: {:?}", e));
        }
        match (ending, status_code) {
            (Some(reason), _) => self.heals().want_singleton(conversation_id, reason),
            (None, CONFLICT) => self.heals().want_new_era(conversation_id),
            (None, _) => self
                .heals()
                .want_singleton(conversation_id, EndMlsReason::InternalClientError),
        }
    }
}
