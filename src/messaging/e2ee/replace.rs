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

//! KeyPackage Updates: replacing the leaves of the Clients of other members
//! whose certificate expired, or who did not update their keys in over 30
//! days, with new ones from their KeyPackages (RCC.16 section 9.5.4)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use futures::future::join_all;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::internet::parameter::ParameterParser;
use rust_rcs_core::mls::rcs::proto::EndMlsReason;
use rust_rcs_core::mls::rcs::{credential_tel_uris, MlsCapability, MLS_VERSION_V1};
use rust_rcs_core::mls::Credential;

use crate::capability::{Capabilities, CapabilityQuery};

use super::device::{is_of, E2eeDevice, CIPHERSUITE};
use super::group::GroupError;
use super::kds::{fetch_key_packages, Fetched, Recipient};

const LOG_TAG: &str = "e2ee";

/// How long a KeyPackage Update that could not be made for now is put off
const REPLACEMENT_RETRY: Duration = Duration::from_secs(60 * 60);

/// The groups whose KeyPackage Update could not be made for now, by
/// Conversation-ID, with the time until which it is put off
#[derive(Default)]
pub(super) struct Replacements(Mutex<HashMap<String, SystemTime>>);

impl Replacements {
    fn put_off(&self, conversation_id: &str, until: SystemTime) {
        self.0
            .lock()
            .unwrap()
            .insert(String::from(conversation_id), until);
    }

    /// Whether the KeyPackage Update of the group `conversation_id` is put
    /// off at `now`
    fn put_off_at(&self, conversation_id: &str, now: SystemTime) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(conversation_id)
            .is_some_and(|until| now < *until)
    }
}

/// Why the KeyPackages of the Participants to replace Clients of cannot be
/// had
enum Unavailable {
    /// Not for now: the capabilities or the Home KDS may answer later
    ForNow,
    /// Not at all, the group chat moved to unencrypted for this reason
    Never(EndMlsReason),
}

impl E2eeDevice {
    /// Whether the device is to replace the leaves of Clients of other
    /// members of the group chat `conversation_id` with a KeyPackage Update,
    /// as replace_members() does (RCC.16 section 9.5.4): for a certificate
    /// that expired, or keys not updated in over 30 days
    ///
    /// Not while a Commit of the device waits for the Conversation Focus to
    /// accept it, nor while other members are leaving, as their leave is to
    /// be committed first (section 9.4), nor while the certificate of the
    /// device has less than 30 days left, as its leaf is updated too (Annex
    /// A.4.1.5), nor for an hour after one could not be made for now.
    pub fn replacement_due(&self, conversation_id: &str) -> bool {
        self.certificate_lasting()
            && !self
                .replacements()
                .put_off_at(conversation_id, self.store().now())
            && !self.stale_members(conversation_id).is_empty()
    }

    /// The Clients of other members to replace in the group chat
    /// `conversation_id`, none while a Commit of the device is pending or
    /// other members are leaving
    fn stale_members(&self, conversation_id: &str) -> Vec<Credential> {
        self.store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                if conversation.has_pending_commit() || !conversation.leaving_members().is_empty() {
                    return Vec::new();
                }
                conversation.stale_members(client).unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Replaces the leaves of the Clients of other members of the group chat
    /// `conversation_id`, if it is due as replacement_due() tells, with the
    /// KeyPackages of their Participants: a Commit removing those leaves and
    /// adding the Clients of the KeyPackages, with a Welcome for them (RCC.16
    /// section 9.5.4). The CPIM message, `from` and `to` its own, carrying
    /// the `message/mls-rcs-client` to send to the Conversation Focus over
    /// MSRP (sections 7.9.2, 9.5.1); None if it is not due
    ///
    /// The KeyPackages of each Participant are fetched from the Home KDS
    /// with the Home KDS its capabilities tell, asked for with
    /// `capabilities`; that of the user is the one of the device (sections
    /// 5.2, 5.3). If a Participant no longer advertises E2EE, or the Home
    /// KDS has no KeyPackages for it, the group chat is moved to unencrypted
    /// instead: the control message carries the Commit doing so (section
    /// 11.2). If the capabilities or KeyPackages cannot be had for now, or
    /// the Commit cannot be made, the KeyPackage Update is put off for an
    /// hour.
    ///
    /// Not while a Commit of the device waits for the Focus to accept it.
    pub async fn replace_members(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        capabilities: &CapabilityQuery,
    ) -> Result<Option<Vec<u8>>, GroupError> {
        let pending = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                conversation.has_pending_commit()
            })
            .map_err(GroupError::Store)?;
        if pending {
            return Err(GroupError::Pending);
        }
        if !self.replacement_due(conversation_id) {
            return Ok(None);
        }

        let mut participants: Vec<String> = Vec::new();
        for member in self.stale_members(conversation_id) {
            let tel_uri = credential_tel_uris(&member)
                .ok()
                .and_then(|tel_uris| tel_uris.into_iter().next());
            if let Some(tel_uri) = tel_uri {
                if !participants.iter().any(|known| is_of(&member, known)) {
                    participants.push(tel_uri);
                }
            }
        }

        let replaced = match self.key_packages_of(&participants, capabilities).await {
            Ok(key_packages) => {
                self.commit_replacement(conversation_id, &participants, &key_packages)
            }
            Err(Unavailable::ForNow) => {
                platform_log(LOG_TAG, "KeyPackage Update put off, no KeyPackages for now");
                Ok(None)
            }
            Err(Unavailable::Never(reason)) => {
                platform_log(LOG_TAG, format!("no KeyPackage Update: {:?}", reason));
                return self.end_encryption(conversation_id, from, to, reason);
            }
        };
        match replaced {
            Ok(Some(client_message)) => Ok(Some(self.sent_in(
                conversation_id,
                from,
                to,
                &client_message,
            ))),
            Err(GroupError::Pending) => Err(GroupError::Pending),
            other => {
                self.replacements()
                    .put_off(conversation_id, self.store().now() + REPLACEMENT_RETRY);
                other
            }
        }
    }

    /// The KeyPackages of all the Clients of each of `participants`, by tel
    /// URI, as their Home KDS gives them (RCC.16 sections 5.2, 5.3)
    async fn key_packages_of(
        &self,
        participants: &[String],
        capabilities: &CapabilityQuery,
    ) -> Result<Vec<Vec<u8>>, Unavailable> {
        let own = self.store().credential();
        let answers = join_all(participants.iter().map(|participant| {
            let own = own
                .as_ref()
                .is_some_and(|credential| is_of(credential, participant));
            let asked = (!own).then(|| capabilities(participant.clone()));
            async move {
                match asked {
                    Some(asked) => Some(asked.await),
                    None => None,
                }
            }
        }))
        .await;

        let mut recipients = Vec::with_capacity(participants.len());
        for (participant, answer) in participants.iter().zip(answers) {
            recipients.push(match answer {
                Some(answer) => recipient(participant, &answer)?,
                None => Recipient {
                    tel_uri: participant.clone(),
                    home_kds: self.home_kds().to_string(),
                },
            });
        }

        let fetched =
            fetch_key_packages(self.kds(), self.validator(), vec![CIPHERSUITE], recipients)
                .await
                .map_err(|_| Unavailable::ForNow)?;
        let mut key_packages = Vec::new();
        for participant in participants {
            match fetched
                .iter()
                .find(|(fetched_for, _)| fetched_for == participant)
            {
                Some((_, Fetched::KeyPackages(of_participant))) => {
                    key_packages.extend(of_participant.iter().cloned())
                }
                Some((_, Fetched::Unavailable)) => return Err(Unavailable::ForNow),
                _ => return Err(Unavailable::Never(EndMlsReason::CannotFetchKeypackages)),
            }
        }
        Ok(key_packages)
    }

    /// The `message/mls-rcs-client` of the Commit replacing the Clients to
    /// replace in the group chat `conversation_id` as they are now, those of
    /// `participants`, with the Clients of `key_packages`; None if there are
    /// none any more, as when another member replaced them first
    fn commit_replacement(
        &self,
        conversation_id: &str,
        participants: &[String],
        key_packages: &[Vec<u8>],
    ) -> Result<Option<Vec<u8>>, GroupError> {
        self.store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                if conversation.has_pending_commit() {
                    return Ok(Err(GroupError::Pending));
                }
                // a leave received meanwhile is committed first
                if !conversation.leaving_members().is_empty() {
                    return Ok(Ok(None));
                }
                let stale: Vec<_> = conversation
                    .stale_members(client)?
                    .into_iter()
                    .filter(|member| participants.iter().any(|tel_uri| is_of(member, tel_uri)))
                    .collect();
                if stale.is_empty() {
                    return Ok(Ok(None));
                }
                let key_packages: Vec<&[u8]> = key_packages.iter().map(|kp| &kp[..]).collect();
                let output = conversation.replace_members(client, &stale, &key_packages)?;
                match output.to_client_message() {
                    Ok(client_message) => Ok(Ok(Some(client_message))),
                    Err(e) => {
                        conversation.discard_pending_commit(client)?;
                        Err(e)
                    }
                }
            })
            .map_err(GroupError::Store)?
    }
}

/// The Participant at `tel_uri` as the Home KDS is to be asked for its
/// KeyPackages, by the capabilities it answered with `answer` (RCC.16
/// section 5.2)
fn recipient(tel_uri: &str, answer: &Capabilities) -> Result<Recipient, Unavailable> {
    if answer.status_code != 200 {
        return Err(Unavailable::ForNow);
    }
    MlsCapability::from_parameters(ParameterParser::new(
        answer.feature_tags.as_bytes(),
        b';',
        false,
    ))
    .filter(|capability| capability.version == MLS_VERSION_V1)
    .and_then(|capability| capability.home_kds)
    .map(|home_kds| Recipient {
        tel_uri: String::from(tel_uri),
        home_kds: home_kds.to_string(),
    })
    .ok_or(Unavailable::Never(
        EndMlsReason::GroupMemberFailsCapabilitiesCheck,
    ))
}
