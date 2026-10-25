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

//! The encrypted group chats of the device: those it creates, those it
//! joins, and what their Conversation Focus sends of them (RCC.16 sections
//! 6.2, 8.1)

use std::io::Read;
use std::sync::{Arc, Weak};
use std::time::Duration;

use chrono::{Local, SecondsFormat};
use futures::future::{join_all, BoxFuture};
use rust_rcs_core::cpim::{CPIMInfo, CPIMMessage};
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::imdn::notification::{Imdn, Status};
use rust_rcs_core::internet::body::message_body::MessageBody;
use rust_rcs_core::internet::parameter::ParameterParser;
use rust_rcs_core::internet::{Body, Header};
use rust_rcs_core::io::DynamicChain;
use rust_rcs_core::mls::rcs::imdn::{failure_reason, FailureReason};
use rust_rcs_core::mls::rcs::proto::{self, server_mls_rcs_message, ServerMlsRcsMessage};
use rust_rcs_core::mls::rcs::{
    MlsCapability, ServerFailureReason, CONTENT_TYPE_MLS_RCS_CLIENT, MLS_VERSION_V1,
};
use rust_rcs_core::mls::{ErrorKind, IncomingMessage};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::capability::CapabilityQuery;
use crate::messaging::cpm::encryption::GroupEncryption;

use super::device::{is_of, participant_tel_uri, E2eeDevice, CIPHERSUITE};
use super::kds::{fetch_key_packages, Fetched, KdsError, Recipient};
use super::message::MessageError;
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

/// How long a message waits for a Commit of this client to be accepted by
/// the Conversation Focus before it is not sent
const ACCEPTANCE_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupError {
    Kds(KdsError),
    /// The Home KDS has no KeyPackages to add the Participant with, by its
    /// tel URI, for what it said instead
    NotEncryptable(String, Fetched),
    /// A Commit of the device waits for the Conversation Focus to accept it
    Pending,
    /// No Client of the Participant, by its tel URI, is a member the device
    /// can remove: the user leaves instead (RCC.16 section 9.4)
    NotMember(String),
    Store(StoreError),
}

/// The participants of a new group as the Home KDS is to be asked for their
/// KeyPackages: by tel URI, with the Home KDS each advertises; None if one of
/// them does not advertise E2EE of this version (RCC.16 sections 5.2, 8.1)
pub async fn recipients(
    participants: &[String],
    capabilities: &CapabilityQuery,
) -> Option<Vec<Recipient>> {
    let answers = join_all(
        participants
            .iter()
            .map(|participant| capabilities(participant.clone())),
    )
    .await;

    participants
        .iter()
        .zip(answers)
        .map(|(participant, answer)| {
            if answer.status_code != 200 {
                return None;
            }
            let capability = MlsCapability::from_parameters(ParameterParser::new(
                answer.feature_tags.as_bytes(),
                b';',
                false,
            ))
            .filter(|capability| capability.version == MLS_VERSION_V1)?;
            Some(Recipient {
                tel_uri: participant_tel_uri(std::iter::once(participant.as_str()), None)?,
                home_kds: capability.home_kds?.to_string(),
            })
        })
        .collect()
}

impl E2eeDevice {
    /// Makes the MLS group of a new group chat with `recipients`, in Era 0,
    /// its group ID the Conversation-ID `conversation_id`, each of them
    /// added with all of their Clients: the CPIM message, `from` and `to` its
    /// own, carrying the `message/mls-rcs-client` its INVITE is to carry
    /// (RCC.16 sections 7.9.2, 8.1, 8.1.2)
    ///
    /// The Commit is applied once the Conversation Focus accepts it, or
    /// discarded if it refuses it.
    pub async fn create_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        recipients: Vec<Recipient>,
    ) -> Result<Vec<u8>, GroupError> {
        let key_packages = self.key_packages(recipients).await?;

        let (_, client_message) = self
            .store()
            .add_conversation(|client| {
                let mut conversation =
                    client.create_conversation(Some(conversation_id.as_bytes()), 0)?;
                let key_packages: Vec<&[u8]> = key_packages.iter().map(|kp| &kp[..]).collect();
                let made = conversation
                    .add_members(client, &key_packages)
                    .and_then(|output| output.to_client_message());
                match made {
                    Ok(client_message) => Ok((conversation, client_message)),
                    Err(e) => {
                        let _ = conversation.delete(client);
                        Err(e)
                    }
                }
            })
            .map_err(GroupError::Store)?;

        let (message_id, cpim) = control_message(from, to, &client_message);
        self.control_messages()
            .lock()
            .unwrap()
            .insert(String::from(conversation_id), message_id);
        Ok(cpim)
    }

    /// Adds the participants `recipients` to the MLS group `conversation_id`,
    /// each with all of their Clients: the CPIM message, `from` and `to` its
    /// own, carrying the `message/mls-rcs-client` the REFER inviting them is
    /// to carry (RCC.16 sections 7.9.2, 9.2)
    ///
    /// Not while a Commit of the device waits for the Conversation Focus to
    /// accept it. The Commit is applied once the Focus accepts it or forwards
    /// it back, or discarded if it refuses it.
    pub async fn add_to_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        recipients: Vec<Recipient>,
    ) -> Result<Vec<u8>, GroupError> {
        let pending = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, _| {
                Ok(conversation.has_pending_commit())
            })
            .map_err(GroupError::Store)?;
        if pending {
            return Err(GroupError::Pending);
        }
        let key_packages = self.key_packages(recipients).await?;

        let client_message = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                // one made meanwhile
                if conversation.has_pending_commit() {
                    return Err(ErrorKind::InvalidState);
                }
                let key_packages: Vec<&[u8]> = key_packages.iter().map(|kp| &kp[..]).collect();
                let output = conversation.add_members(client, &key_packages)?;
                output.to_client_message().or_else(|e| {
                    conversation.discard_pending_commit(client)?;
                    Err(e)
                })
            })
            .map_err(GroupError::Store)?;

        let (message_id, cpim) = control_message(from, to, &client_message);
        self.control_messages()
            .lock()
            .unwrap()
            .insert(String::from(conversation_id), message_id);
        Ok(cpim)
    }

    /// Removes all the Clients of the participant at `tel_uri` from the MLS
    /// group `conversation_id`: the CPIM message, `from` and `to` its own,
    /// carrying the `message/mls-rcs-client` the REFER removing the
    /// participant is to carry (RCC.16 sections 7.9.2, 9.3)
    ///
    /// Not while a Commit of the device waits for the Conversation Focus to
    /// accept it. The Commit is applied once the Focus accepts it or forwards
    /// it back, or discarded if it refuses it.
    pub fn remove_from_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        tel_uri: &str,
    ) -> Result<Vec<u8>, GroupError> {
        let client_message = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                if conversation.has_pending_commit() {
                    return Ok(Err(GroupError::Pending));
                }
                // the user leaves rather than removes itself
                if is_of(client.credential(), tel_uri) {
                    return Ok(Err(GroupError::NotMember(String::from(tel_uri))));
                }
                let removed: Vec<_> = conversation
                    .members()
                    .into_iter()
                    .filter(|member| is_of(member, tel_uri))
                    .collect();
                if removed.is_empty() {
                    return Ok(Err(GroupError::NotMember(String::from(tel_uri))));
                }
                let output = conversation.remove_members(client, &removed)?;
                match output.to_client_message() {
                    Ok(client_message) => Ok(Ok(client_message)),
                    Err(e) => {
                        conversation.discard_pending_commit(client)?;
                        Err(e)
                    }
                }
            })
            .map_err(GroupError::Store)??;

        let (message_id, cpim) = control_message(from, to, &client_message);
        self.control_messages()
            .lock()
            .unwrap()
            .insert(String::from(conversation_id), message_id);
        Ok(cpim)
    }

    /// The control message for the BYE of the user `from` leaving the group
    /// chat `conversation_id`, the group `to`, for good: a ProposalList of
    /// the self_remove Proposal of the device, which another member commits
    /// (RCC.16 sections 7.9.4, 9.4)
    ///
    /// The other Clients of the user stay for that member to remove, as a
    /// self_remove only ever removes the Client proposing it, and the
    /// Conversation Focus takes no other Proposal (section 6.2.3). The MLS
    /// group is kept until the Focus agrees to the leave.
    pub fn leave_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
    ) -> Result<Vec<u8>, GroupError> {
        let client_message = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                // a self_remove of an epoch the Commit is to end
                if conversation.has_pending_commit() {
                    return Ok(Err(GroupError::Pending));
                }
                conversation.leave_message(client).map(Ok)
            })
            .map_err(GroupError::Store)??;

        let (message_id, cpim) = control_message(from, to, &client_message);
        self.control_messages()
            .lock()
            .unwrap()
            .insert(String::from(conversation_id), message_id);
        Ok(cpim)
    }

    /// The KeyPackages of all the Clients of each of `recipients`, as their
    /// Home KDS gives them (RCC.16 section 5.3)
    async fn key_packages(&self, recipients: Vec<Recipient>) -> Result<Vec<Vec<u8>>, GroupError> {
        let asked: Vec<String> = recipients.iter().map(|r| r.tel_uri.clone()).collect();
        let fetched =
            fetch_key_packages(self.kds(), self.validator(), vec![CIPHERSUITE], recipients)
                .await
                .map_err(GroupError::Kds)?;

        let mut key_packages = Vec::new();
        for tel_uri in asked {
            match fetched
                .iter()
                .find(|(fetched_for, _)| *fetched_for == tel_uri)
            {
                Some((_, Fetched::KeyPackages(of_participant))) => {
                    key_packages.extend(of_participant.iter().cloned())
                }
                Some((_, other)) => return Err(GroupError::NotEncryptable(tel_uri, other.clone())),
                None => return Err(GroupError::NotEncryptable(tel_uri, Fetched::NotFound)),
            }
        }
        Ok(key_packages)
    }

    /// Joins the MLS group of the group chat `conversation_id` with the
    /// Welcome the Conversation Focus sent in `server_message`, the group the
    /// one of the conversation, and any message bundled with it decrypted in
    /// it (RCC.16 sections 6.1.1, 6.2.6, 7.9.3, 8.1)
    ///
    /// The members' certificates are checked as joining does (Annex
    /// A.4.1.4); the Commit that added the device is for those who were
    /// members before it.
    pub fn join_group(
        &self,
        conversation_id: &str,
        server_message: &[u8],
    ) -> Result<(), StoreError> {
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

        self.store()
            .add_conversation(|client| {
                let mut conversation =
                    client.join_conversation(&bundle.welcome, &bundle.ratchet_tree)?;
                let joined = if conversation.group_id() != conversation_id.as_bytes() {
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
            })
            .map(|_| ())
    }

    /// Takes what the Conversation Focus of the group `conversation_id` sent
    /// of its MLS group: its acceptance of the Commit of the device, the
    /// Commits it accepted, own ones included, and the Proposals (RCC.16
    /// sections 6.2.4, 7.9.3, 9.2)
    ///
    /// A bundle or list is applied as a whole once it is checked, else none
    /// of it is (section 6.2.6). A Commit of another applied first voids the
    /// one of the device. The GroupInfo only answers a request for it
    /// (section 7.10.1).
    pub fn on_server_message(
        &self,
        conversation_id: &str,
        body: &[u8],
    ) -> Result<Vec<IncomingMessage>, StoreError> {
        let (taken, pending) = self.store().with_conversation(
            conversation_id.as_bytes(),
            |conversation, client| {
                let taken = conversation.process_server_message(client, body);
                Ok((taken, conversation.has_pending_commit()))
            },
        )?;
        if !pending {
            self.control_messages()
                .lock()
                .unwrap()
                .remove(conversation_id);
        }
        taken.map_err(StoreError::Mls)
    }

    /// The reason the Conversation Focus of the group `conversation_id`
    /// gives in the IMDN `imdn` for refusing the control message carrying
    /// the pending Commit of the device, if it is that: the Commit is then
    /// discarded, as the Focus does not apply it (RCC.16 sections 6.2.5,
    /// 7.7.2.1)
    pub fn on_imdn(
        &self,
        conversation_id: &str,
        imdn: &[u8],
    ) -> Result<Option<ServerFailureReason>, StoreError> {
        // a failed status is of a delivery notification
        let refused = Imdn::from_xml(imdn).filter(|imdn| imdn.status == Status::Failed);
        let (Some(refused), Some(FailureReason::Server(reason))) = (refused, failure_reason(imdn))
        else {
            return Ok(None);
        };
        {
            let mut control_messages = self.control_messages().lock().unwrap();
            if control_messages.get(conversation_id) != Some(&refused.message_id) {
                return Ok(None);
            }
            control_messages.remove(conversation_id);
        }

        self.drop_pending(conversation_id)?;
        Ok(Some(reason))
    }

    /// Discards what the device has pending in the group `conversation_id`,
    /// its Commit or the self_remove Proposal of its leave, the request
    /// carrying it answered with an error by the Conversation Focus; its
    /// control message is forgotten unless a refusal of it is to follow
    /// (RCC.16 sections 6.2.5, 7.2.6)
    pub fn discard_pending(
        &self,
        conversation_id: &str,
        refusal_follows: bool,
    ) -> Result<(), StoreError> {
        if !refusal_follows {
            self.control_messages()
                .lock()
                .unwrap()
                .remove(conversation_id);
        }
        self.drop_pending(conversation_id)
    }

    /// Drops the pending Commit and Proposals of the device in the group
    /// `conversation_id`, which the Conversation Focus did not take
    fn drop_pending(&self, conversation_id: &str) -> Result<(), StoreError> {
        self.store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                conversation.discard_pending_commit(client)?;
                // no Commit is made while its own self_remove is pending
                conversation.withdraw_own_proposals(client)
            })
    }

    /// Lets go of the MLS group `conversation_id`
    pub fn abandon(&self, conversation_id: &str) -> Result<(), StoreError> {
        self.control_messages()
            .lock()
            .unwrap()
            .remove(conversation_id);
        self.store().delete_conversation(conversation_id.as_bytes())
    }
}

/// A CPIM message carrying the `message/mls-rcs-client` `client_message`,
/// with only the headers left unencrypted, asking to be told if it is
/// refused (RCC.16 sections 6.2.5, 7.5.6, 7.5.7, 7.9), and its Message-ID
fn control_message(from: &str, to: &str, client_message: &[u8]) -> (String, Vec<u8>) {
    let message_id = Uuid::new_v4()
        .as_hyphenated()
        .encode_lower(&mut Uuid::encode_buffer())
        .to_string();
    let message = CPIMMessage::new(
        &[(b"imdn", b"urn:ietf:params:imdn")],
        vec![
            Header::new(b"From", format!("<{}>", from)),
            Header::new(b"To", format!("<{}>", to)),
            Header::new(
                b"DateTime",
                Local::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            ),
            Header::new(b"imdn.Message-ID", message_id.clone()),
            Header::new(b"imdn.Disposition-Notification", b"negative-delivery"),
        ],
        Body::Message(MessageBody {
            headers: vec![
                Header::new(b"Content-Type", CONTENT_TYPE_MLS_RCS_CLIENT),
                Header::new(b"Content-Length", format!("{}", client_message.len())),
            ],
            body: Arc::new(Body::Raw(client_message.to_vec())),
        }),
    );
    let mut readers = Vec::new();
    let mut data = Vec::new();
    // in memory, it does not fail
    if message.get_readers(&mut readers).is_ok() {
        let _ = DynamicChain::new(readers).read_to_end(&mut data);
    }
    (message_id, data)
}

/// The group chats created encrypted by the device, for as long as it is kept
pub struct DeviceGroups {
    device: Weak<E2eeDevice>,
    capabilities: CapabilityQuery,
    /// Told once what the Conversation Focus sent is taken
    taken: Arc<Notify>,
    acceptance_wait: Duration,
}

impl DeviceGroups {
    /// Those of `device`, which asks participants for their capabilities with
    /// `capabilities`
    pub fn new(device: &Arc<E2eeDevice>, capabilities: CapabilityQuery) -> DeviceGroups {
        DeviceGroups {
            device: Arc::downgrade(device),
            capabilities,
            taken: Arc::new(Notify::new()),
            acceptance_wait: ACCEPTANCE_WAIT,
        }
    }

    /// Has messages wait `acceptance_wait` for a Commit to be accepted
    #[cfg(test)]
    pub fn with_acceptance_wait(mut self, acceptance_wait: Duration) -> DeviceGroups {
        self.acceptance_wait = acceptance_wait;
        self
    }

    /// What `make` makes of the CPIM message `cpim` in the group
    /// `conversation_id`, once a Commit of the device the Conversation Focus
    /// is yet to accept is, waiting for it no longer than the acceptance
    /// wait; `failed` tells of it not made
    fn once_accepted(
        &self,
        conversation_id: &str,
        cpim: &[u8],
        make: fn(&E2eeDevice, &str, &[u8]) -> Result<Vec<u8>, MessageError>,
        failed: &'static str,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        let device = self.device.clone();
        let taken = Arc::clone(&self.taken);
        let deadline = tokio::time::Instant::now() + self.acceptance_wait;
        let conversation_id = String::from(conversation_id);
        let cpim = cpim.to_vec();
        Box::pin(async move {
            loop {
                // told of what is taken from now on
                let notified = taken.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                match make(&*device.upgrade()?, &conversation_id, &cpim) {
                    Ok(made) => return Some(made),
                    Err(MessageError::Pending) => {}
                    Err(e) => {
                        platform_log(LOG_TAG, format!("{}: {:?}", failed, e));
                        return None;
                    }
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    platform_log(LOG_TAG, format!("{}, the Commit not accepted", failed));
                    return None;
                }
            }
        })
    }
}

impl GroupEncryption for DeviceGroups {
    fn prepare(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        let device = self.device.clone();
        let capabilities = Arc::clone(&self.capabilities);
        Box::pin(async move {
            let device = device.upgrade()?;
            // only while others can add it
            device.mls_feature_tags()?;
            let recipients = recipients(&participants, &capabilities).await?;
            match device
                .create_group(&conversation_id, &from, &to, recipients)
                .await
            {
                Ok(cpim) => Some(cpim),
                Err(e) => {
                    platform_log(LOG_TAG, format!("group created unencrypted: {:?}", e));
                    None
                }
            }
        })
    }

    fn prepare_add(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        let device = self.device.clone();
        let capabilities = Arc::clone(&self.capabilities);
        let taken = Arc::clone(&self.taken);
        let deadline = tokio::time::Instant::now() + self.acceptance_wait;
        Box::pin(async move {
            let recipients = recipients(&participants, &capabilities).await?;
            loop {
                // told of what is taken from now on
                let notified = taken.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                let device = device.upgrade()?;
                match device
                    .add_to_group(&conversation_id, &from, &to, recipients.clone())
                    .await
                {
                    Ok(cpim) => return Some(cpim),
                    Err(GroupError::Pending) => {}
                    Err(e) => {
                        platform_log(LOG_TAG, format!("participants not added: {:?}", e));
                        return None;
                    }
                }
                drop(device);
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    platform_log(LOG_TAG, "participants not added, the Commit not accepted");
                    return None;
                }
            }
        })
    }

    fn prepare_remove(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        let device = self.device.clone();
        let taken = Arc::clone(&self.taken);
        let deadline = tokio::time::Instant::now() + self.acceptance_wait;
        Box::pin(async move {
            let tel_uri = participant_tel_uri(std::iter::once(participant.as_str()), None)?;
            loop {
                // told of what is taken from now on
                let notified = taken.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                match device
                    .upgrade()?
                    .remove_from_group(&conversation_id, &from, &to, &tel_uri)
                {
                    Ok(cpim) => return Some(cpim),
                    Err(GroupError::Pending) => {}
                    Err(e) => {
                        platform_log(LOG_TAG, format!("participant not removed: {:?}", e));
                        return None;
                    }
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    platform_log(LOG_TAG, "participant not removed, the Commit not accepted");
                    return None;
                }
            }
        })
    }

    fn prepare_leave(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        let device = self.device.clone();
        let taken = Arc::clone(&self.taken);
        let deadline = tokio::time::Instant::now() + self.acceptance_wait;
        Box::pin(async move {
            loop {
                // told of what is taken from now on
                let notified = taken.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                match device.upgrade()?.leave_group(&conversation_id, &from, &to) {
                    Ok(cpim) => return Some(cpim),
                    Err(GroupError::Pending) => {}
                    Err(e) => {
                        platform_log(LOG_TAG, format!("group not left: {:?}", e));
                        return None;
                    }
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    platform_log(LOG_TAG, "group not left, the Commit not accepted");
                    return None;
                }
            }
        })
    }

    fn discard(&self, conversation_id: &str, refusal_follows: bool) {
        if let Some(device) = self.device.upgrade() {
            if let Err(e) = device.discard_pending(conversation_id, refusal_follows) {
                platform_log(LOG_TAG, format!("Commit or leave not discarded: {:?}", e));
            }
        }
        // what waits for it is sent, or not, without it
        self.taken.notify_waiters();
    }

    fn join(&self, conversation_id: &str, server_message: &[u8]) -> bool {
        let Some(device) = self.device.upgrade() else {
            return false;
        };
        match device.join_group(conversation_id, server_message) {
            Ok(()) => true,
            Err(e) => {
                platform_log(LOG_TAG, format!("group not joined: {:?}", e));
                false
            }
        }
    }

    fn on_server_message(&self, conversation_id: &str, body: &[u8]) {
        if let Some(device) = self.device.upgrade() {
            if let Err(e) = device.on_server_message(conversation_id, body) {
                platform_log(LOG_TAG, format!("message of the focus not taken: {:?}", e));
            }
        }
        self.taken.notify_waiters();
    }

    fn on_imdn(&self, conversation_id: &str, imdn: &[u8]) -> bool {
        let Some(device) = self.device.upgrade() else {
            return false;
        };
        let refused = match device.on_imdn(conversation_id, imdn) {
            Ok(None) => return false,
            Ok(Some(reason)) => format!("Commit refused by the focus: {:?}", reason),
            Err(e) => format!("Commit refused by the focus, not discarded: {:?}", e),
        };
        platform_log(LOG_TAG, refused);
        // what waits for it is sent, or not, without it
        self.taken.notify_waiters();
        true
    }

    fn abandon(&self, conversation_id: &str) {
        if let Some(device) = self.device.upgrade() {
            let _ = device.abandon(conversation_id);
        }
    }

    fn encrypts(&self, conversation_id: &str) -> bool {
        self.device
            .upgrade()
            .is_some_and(|device| device.store().has_conversation(conversation_id.as_bytes()))
    }

    fn encrypt(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.once_accepted(
            conversation_id,
            cpim,
            E2eeDevice::encrypt_message,
            "message not encrypted",
        )
    }

    fn sign(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.once_accepted(
            conversation_id,
            cpim,
            E2eeDevice::sign_notification,
            "notification not signed",
        )
    }

    fn verify(&self, conversation_id: &str, cpim_info: &CPIMInfo, imdn: &[u8]) -> bool {
        let Some(device) = self.device.upgrade() else {
            return false;
        };
        match device.verify_notification(conversation_id, cpim_info, imdn) {
            Ok(()) => true,
            Err(e) => {
                platform_log(LOG_TAG, format!("notification not verified: {:?}", e));
                false
            }
        }
    }

    fn decrypt(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        mls_message: &[u8],
    ) -> Option<Vec<u8>> {
        let device = self.device.upgrade()?;
        match device.decrypt_message(conversation_id, cpim_info, mls_message) {
            Ok(cpim) => Some(cpim),
            Err(e) => {
                platform_log(LOG_TAG, format!("message not decrypted: {:?}", e));
                None
            }
        }
    }
}
