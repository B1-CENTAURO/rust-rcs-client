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

//! The messages of the encrypted group chats (RCC.16 sections 7.5, 9.1.1)

use std::collections::BTreeMap;
use std::io::Read;

use base64::{engine::general_purpose, Engine as _};
use rust_rcs_core::cpim::cpim_namespace::CPIMNamespace;
use rust_rcs_core::cpim::{CPIMHeaders, CPIMInfo, CPIMMessage};
use rust_rcs_core::internet::Body;
use rust_rcs_core::mls::rcs::{
    credential_tel_uris, is_unencrypted_cpim_header, same_tel_uri, SecretPayloadType,
    CPIM_HEADER_EPOCH_AUTHENTICATOR, CPIM_HEADER_ERA_ID, CPIM_NAMESPACE, CPIM_NAMESPACE_PREFIX,
};
use rust_rcs_core::mls::ErrorKind;

use super::device::{participant_tel_uri, E2eeDevice};
use super::store::StoreError;

const IMDN_NAMESPACE: &[u8] = b"urn:ietf:params:imdn";
const RCS_NAMESPACE: &[u8] = b"http://www.gsma.com/rcs";
const DISPOSITION_NOTIFICATION: &[u8] = b"<urn:ietf:params:imdn>.Disposition-Notification";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// A Commit of this client waits for the Conversation Focus to accept it,
    /// the group not yet in the epoch the others are in
    Pending,
    /// The Conversation Focus refused the Commit that made the group, which
    /// is in no epoch the others are in
    NotCreated,
    /// What was to be encrypted is not a CPIM message with an IMDN Message-ID
    NotCpim,
    Store(StoreError),
}

/// The namespaces the unencrypted CPIM headers of an encrypted message are in
/// (RCC.16 section 7.5.6)
fn outer_namespaces() -> CPIMNamespace {
    let mut namespaces = CPIMNamespace::new();
    namespaces.register(b"imdn", IMDN_NAMESPACE);
    namespaces.register(b"rcs", RCS_NAMESPACE);
    namespaces.register(CPIM_NAMESPACE_PREFIX, CPIM_NAMESPACE);
    namespaces
}

fn header_line(data: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    data.extend_from_slice(name);
    data.extend_from_slice(b": ");
    data.extend_from_slice(value);
    data.extend_from_slice(b"\r\n");
}

/// `disposition`, asking to be told of a negative delivery too (RCC.16
/// section 7.5.6)
fn with_negative_delivery(disposition: Option<&[u8]>) -> Vec<u8> {
    match disposition {
        Some(disposition)
            if disposition
                .split(|b| *b == b',')
                .any(|d| d.trim_ascii().eq_ignore_ascii_case(b"negative-delivery")) =>
        {
            disposition.to_vec()
        }
        Some(disposition) => [disposition, b", negative-delivery"].concat(),
        None => b"negative-delivery".to_vec(),
    }
}

impl E2eeDevice {
    /// The CPIM message `cpim` encrypted in the MLS group `conversation_id`,
    /// in a CPIM message of its unencrypted headers, the Epoch-Authenticator
    /// and Era-ID of the group, asking to be told of a negative delivery, and
    /// carrying it as `message/mls` (RCC.16 sections 7.5, 7.5.1.2, 7.5.5 to
    /// 7.5.7)
    ///
    /// Not while a Commit of this client waits for the Conversation Focus to
    /// accept it, as the message would be of an epoch the others leave, nor
    /// once the Focus refused the Commit that made the group.
    pub fn encrypt_message(
        &self,
        conversation_id: &str,
        cpim: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        let body = Body::construct_message(cpim).map_err(|_| MessageError::NotCpim)?;
        let message = CPIMMessage::try_from(&body).map_err(|_| MessageError::NotCpim)?;
        let message_id = message
            .get_info()
            .map_err(|_| MessageError::NotCpim)?
            .imdn_message_id
            .to_vec();
        let CPIMHeaders::Inflated(headers) = &message.headers else {
            return Err(MessageError::NotCpim);
        };
        if message_id.is_empty() {
            return Err(MessageError::NotCpim);
        }

        // the headers left unencrypted, and the CPIM message of the others
        // and the MIME body (sections 7.5.1.2, 7.5.7)
        let outer = outer_namespaces();
        let mut unencrypted = Vec::new();
        let mut disposition = None;
        let mut namespaces = BTreeMap::new();
        let mut encrypted_headers = Vec::new();
        for header in headers {
            let (name, value) = (header.get_name(), header.get_value());
            if name.eq_ignore_ascii_case(DISPOSITION_NOTIFICATION) {
                disposition = Some(value);
            } else if is_unencrypted_cpim_header(name) {
                unencrypted.push((outer.deflate(name), value));
            } else {
                let deflated = message.ns.deflate(name);
                if let Some(position) = deflated.iter().position(|b| *b == b'.') {
                    if let Some(uri) = message.ns.uri(&deflated[..position]) {
                        namespaces.insert(deflated[..position].to_vec(), uri.to_vec());
                    }
                }
                encrypted_headers.push((deflated, value));
            }
        }

        let mut payload = Vec::new();
        for (prefix, uri) in &namespaces {
            header_line(
                &mut payload,
                b"NS",
                &[prefix, &b" <"[..], uri, b">"].concat(),
            );
        }
        for (name, value) in encrypted_headers {
            header_line(&mut payload, &name, value);
        }
        payload.extend_from_slice(b"\r\n");
        if let Ok(mut reader) = message.body.reader() {
            // in memory, it does not fail
            let _ = reader.read_to_end(&mut payload);
        }

        let (pending, epoch) = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, _| {
                Ok((conversation.has_pending_commit(), conversation.epoch()))
            })
            .map_err(MessageError::Store)?;
        if pending {
            return Err(MessageError::Pending);
        }
        // the group of the device alone, as no Commit was applied to it
        if epoch == 0 {
            return Err(MessageError::NotCreated);
        }
        let (mls_message, epoch_authenticator, era) = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                let era = conversation.era().ok_or(ErrorKind::InvalidState)?;
                let mls_message = conversation.encrypt_cpim(client, &payload, &message_id, b"")?;
                Ok((
                    mls_message,
                    conversation.epoch_authenticator().to_vec(),
                    era,
                ))
            })
            .map_err(MessageError::Store)?;

        let mut data = Vec::new();
        let (core, prefixed): (Vec<_>, Vec<_>) = unencrypted
            .iter()
            .partition(|(name, _)| !name.contains(&b'.'));
        for (name, value) in core {
            header_line(&mut data, name, value);
        }
        header_line(&mut data, b"NS", b"imdn <urn:ietf:params:imdn>");
        if prefixed.iter().any(|(name, _)| name.starts_with(b"rcs.")) {
            header_line(&mut data, b"NS", b"rcs <http://www.gsma.com/rcs>");
        }
        header_line(&mut data, b"NS", b"mls <http://www.gsma.com/rcs/mls>");
        for (name, value) in prefixed {
            header_line(&mut data, name, value);
        }
        header_line(
            &mut data,
            b"imdn.Disposition-Notification",
            &with_negative_delivery(disposition),
        );
        header_line(
            &mut data,
            &[&b"mls."[..], CPIM_HEADER_EPOCH_AUTHENTICATOR].concat(),
            general_purpose::STANDARD
                .encode(epoch_authenticator)
                .as_bytes(),
        );
        header_line(
            &mut data,
            &[&b"mls."[..], CPIM_HEADER_ERA_ID].concat(),
            era.to_string().as_bytes(),
        );
        data.extend_from_slice(b"\r\n");
        header_line(&mut data, b"Content-Type", b"message/mls");
        header_line(
            &mut data,
            b"Content-Length",
            mls_message.len().to_string().as_bytes(),
        );
        data.extend_from_slice(b"\r\n");
        data.extend_from_slice(&mls_message);
        Ok(data)
    }

    /// The CPIM message the `message/mls` `mls_message` of the MLS group
    /// `conversation_id` carried, delivered in the CPIM message `cpim_info`
    /// tells of: its unencrypted headers and what was encrypted, its From the
    /// MLS identity of the sender if that is another (RCC.16 sections
    /// 7.5.3.1, 9.1.1)
    pub fn decrypt_message(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        mls_message: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        let decrypted = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                conversation.decrypt(client, mls_message, cpim_info.imdn_message_id)
            })
            .map_err(MessageError::Store)?;
        let payload = match (decrypted.payload_type, decrypted.payload) {
            (SecretPayloadType::Application, Some(payload)) => payload,
            // Re-Sent Messages are not taken yet
            _ => {
                return Err(MessageError::Store(StoreError::Mls(
                    ErrorKind::UnexpectedMessage,
                )))
            }
        };

        // the sender as the RCS sender identity tells, else as MLS does
        let tel_uris = credential_tel_uris(&decrypted.sender).unwrap_or_default();
        let told = cpim_info
            .from_uri
            .as_ref()
            .map(|uri| {
                String::from_utf8_lossy(&uri.string_representation_without_query_and_fragment())
                    .into_owned()
            })
            .and_then(|uri| participant_tel_uri(std::iter::once(uri.as_str()), None));
        let from = match (told, tel_uris.first()) {
            (Some(told), _) if tel_uris.iter().any(|uri| same_tel_uri(uri, &told)) => {
                cpim_info.from.to_vec()
            }
            (_, Some(sender)) => format!("<{}>", sender).into_bytes(),
            (_, None) => cpim_info.from.to_vec(),
        };

        let mut data = Vec::new();
        header_line(&mut data, b"From", &from);
        header_line(&mut data, b"To", cpim_info.to);
        header_line(&mut data, b"DateTime", cpim_info.date);
        header_line(&mut data, b"NS", b"imdn <urn:ietf:params:imdn>");
        header_line(&mut data, b"imdn.Message-ID", cpim_info.imdn_message_id);
        if let Some(disposition) = cpim_info.disposition_notification {
            header_line(&mut data, b"imdn.Disposition-Notification", disposition);
        }
        // the headers encrypted, then the MIME body
        data.extend_from_slice(&payload);
        Ok(data)
    }
}
