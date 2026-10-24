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

//! The group chats this client creates encrypted (RCC.16 section 8.1)

use std::io::Read;
use std::sync::{Arc, Weak};

use chrono::{Local, SecondsFormat};
use futures::future::{join_all, BoxFuture};
use rust_rcs_core::cpim::CPIMMessage;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::internet::body::message_body::MessageBody;
use rust_rcs_core::internet::parameter::ParameterParser;
use rust_rcs_core::internet::{Body, Header};
use rust_rcs_core::io::DynamicChain;
use rust_rcs_core::mls::rcs::proto::{self, server_mls_rcs_message, ServerMlsRcsMessage};
use rust_rcs_core::mls::rcs::{MlsCapability, CONTENT_TYPE_MLS_RCS_CLIENT, MLS_VERSION_V1};
use rust_rcs_core::mls::{ErrorKind, IncomingMessage};
use uuid::Uuid;

use crate::capability::CapabilityQuery;
use crate::messaging::cpm::encryption::GroupEncryption;

use super::device::{participant_tel_uri, E2eeDevice, CIPHERSUITE};
use super::kds::{fetch_key_packages, Fetched, KdsError, Recipient};
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupError {
    Kds(KdsError),
    /// The Home KDS has no KeyPackages to add the Participant with, by its
    /// tel URI, for what it said instead
    NotEncryptable(String, Fetched),
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
    /// The Commit is applied once the Conversation Focus accepts it.
    pub async fn create_group(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        recipients: Vec<Recipient>,
    ) -> Result<Vec<u8>, GroupError> {
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

        Ok(control_message(from, to, &client_message))
    }

    /// Takes what the Conversation Focus of the group `conversation_id` sent
    /// of its MLS group (RCC.16 sections 6.2.4, 7.9)
    pub fn on_server_message(
        &self,
        conversation_id: &str,
        body: &[u8],
    ) -> Result<IncomingMessage, StoreError> {
        let message: ServerMlsRcsMessage = proto::decode(body).map_err(StoreError::Mls)?;
        match message.payload {
            Some(server_mls_rcs_message::Payload::AcceptedMlsRcsMessage(accepted)) => self
                .store()
                .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                    conversation.process_accepted(client, &accepted)
                }),
            // the Commits and Proposals of others, and the GroupInfo, are
            // for the members of a group
            _ => Err(StoreError::Mls(ErrorKind::UnexpectedMessage)),
        }
    }

    /// Lets go of the MLS group `conversation_id`
    pub fn abandon(&self, conversation_id: &str) -> Result<(), StoreError> {
        self.store().delete_conversation(conversation_id.as_bytes())
    }
}

/// A CPIM message carrying the `message/mls-rcs-client` `client_message`,
/// with only the headers left unencrypted, asking to be told if it is
/// refused (RCC.16 sections 6.2.5, 7.5.6, 7.5.7, 7.9)
fn control_message(from: &str, to: &str, client_message: &[u8]) -> Vec<u8> {
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
            Header::new(b"imdn.Message-ID", message_id),
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
    data
}

/// The group chats created encrypted by the device, for as long as it is kept
pub struct DeviceGroups {
    device: Weak<E2eeDevice>,
    capabilities: CapabilityQuery,
}

impl DeviceGroups {
    /// Those of `device`, which asks participants for their capabilities with
    /// `capabilities`
    pub fn new(device: &Arc<E2eeDevice>, capabilities: CapabilityQuery) -> DeviceGroups {
        DeviceGroups {
            device: Arc::downgrade(device),
            capabilities,
        }
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

    fn on_server_message(&self, conversation_id: &str, body: &[u8]) {
        if let Some(device) = self.device.upgrade() {
            if let Err(e) = device.on_server_message(conversation_id, body) {
                platform_log(LOG_TAG, format!("message of the focus not taken: {:?}", e));
            }
        }
    }

    fn abandon(&self, conversation_id: &str) {
        if let Some(device) = self.device.upgrade() {
            let _ = device.abandon(conversation_id);
        }
    }
}
