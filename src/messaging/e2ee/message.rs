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

//! The messages of the encrypted group chats, and their signed notifications
//! (RCC.16 sections 7.5, 7.6, 9.1.1, 9.1.3, 9.1.4)

use std::collections::BTreeMap;
use std::io::Read;

use base64::{engine::general_purpose, Engine as _};
use rust_rcs_core::cpim::cpim_namespace::CPIMNamespace;
use rust_rcs_core::cpim::{CPIMHeaders, CPIMInfo, CPIMMessage};
use rust_rcs_core::imdn::notification::{Imdn, Notification, Status};
use rust_rcs_core::internet::Body;
use rust_rcs_core::mls::rcs::imdn::{failure_reason, FailureReason};
use rust_rcs_core::mls::rcs::proto;
use rust_rcs_core::mls::rcs::wire::{
    self, AuthenticatedData, DeliveryNotificationStatus, DisplayNotificationStatus,
    VerifiableDeliveryImdn, VerifiableDerivedContent, VerifiableDisplayImdn,
};
use rust_rcs_core::mls::rcs::{
    credential_tel_uris, is_unencrypted_cpim_header, ClientFailureReason, ResentFailure,
    SecretPayloadType, CONTENT_TYPE_MLS_RCS_FILE_INFO, CPIM_HEADER_DERIVED_CONTENT_SIGNATURE,
    CPIM_HEADER_EPOCH_AUTHENTICATOR, CPIM_HEADER_ERA_ID, CPIM_HEADER_ORIGINAL_MESSAGE_ID,
    CPIM_NAMESPACE, CPIM_NAMESPACE_PREFIX,
};
use rust_rcs_core::mls::{Credential, ErrorKind};

use super::device::{is_of, participant_tel_uri, E2eeDevice};
use super::file::{file_urls, with_mls_file, CONTENT_TYPE_FT_HTTP};
use super::sent::{members_besides, note_sent};
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
    /// What was to be encrypted is not a CPIM message with an IMDN Message-ID,
    /// or what was to be signed or checked not one carrying a delivery or
    /// display notification
    NotCpim,
    /// A notification not signed, that is to be (RCC.16 sections 9.1.3, 9.1.4)
    NotSigned,
    /// A notification signed by another member than the participant it is
    /// from
    NotFromSigner,
    /// The group chat is no longer encrypted, its MLS group having the
    /// end_mls extension (RCC.16 section 11.2)
    NotEncrypted,
    /// A Re-Sent Message of a message this client did not tell its sender
    /// it could not decrypt, or not re-sent by that sender (RCC.16 section
    /// 10.4)
    NotAskedFor,
    /// A Re-Sent Message to this client that gave no Original Message: its
    /// sender is told of one not decrypted, not of one not matching its
    /// HMAC (sections 10.2, 10.4, Annex C.4.2)
    ResentNotOpened(ResentFailure),
    /// A file transfer message telling of a file not uploaded as the group
    /// chat is: not encrypted for it while it is encrypted, as when it was
    /// uploaded otherwise or over a day before, or encrypted for it once it
    /// is no longer (RCC.16 section 9.1.2.1)
    FileNotFit,
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

/// The CPIM message carrying the `message/mls` `mls_message`, of the CPIM
/// headers `headers` left unencrypted, the name of each as they are sent,
/// asking to be told as `disposition` tells, with the Original-Message-ID
/// `original_message_id` if it is a Re-Sent Message, and the Epoch-Authenticator
/// and Era-ID of the group (RCC.16 sections 7.2.3, 7.5.5 to 7.5.7)
pub(super) fn outer_cpim(
    headers: &[(Vec<u8>, Vec<u8>)],
    disposition: &[u8],
    original_message_id: Option<&[u8]>,
    epoch_authenticator: &[u8],
    era: u32,
    mls_message: &[u8],
) -> Vec<u8> {
    outer_cpim_of(
        headers,
        disposition,
        original_message_id,
        epoch_authenticator,
        era,
        b"message/mls",
        mls_message,
    )
}

/// The CPIM message carrying `body`, of `content_type`, of the headers
/// outer_cpim() is of
fn outer_cpim_of(
    headers: &[(Vec<u8>, Vec<u8>)],
    disposition: &[u8],
    original_message_id: Option<&[u8]>,
    epoch_authenticator: &[u8],
    era: u32,
    content_type: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    let (core, prefixed): (Vec<_>, Vec<_>) =
        headers.iter().partition(|(name, _)| !name.contains(&b'.'));
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
    header_line(&mut data, b"imdn.Disposition-Notification", disposition);
    if let Some(original_message_id) = original_message_id {
        header_line(
            &mut data,
            &[&b"mls."[..], CPIM_HEADER_ORIGINAL_MESSAGE_ID].concat(),
            original_message_id,
        );
    }
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
    header_line(&mut data, b"Content-Type", content_type);
    header_line(
        &mut data,
        b"Content-Length",
        body.len().to_string().as_bytes(),
    );
    data.extend_from_slice(b"\r\n");
    data.extend_from_slice(body);
    data
}

/// Whether the Content-Type `content_type` is of the media type `media_type`
fn is_of_type(content_type: &[u8], media_type: &[u8]) -> bool {
    content_type
        .split(|b| *b == b';')
        .next()
        .is_some_and(|t| t.trim_ascii().eq_ignore_ascii_case(media_type))
}

/// The tel URI of the participant the CPIM From of `cpim_info` gives, if any
fn told_sender(cpim_info: &CPIMInfo) -> Option<String> {
    let uri = cpim_info.from_uri.as_ref()?;
    let uri = String::from_utf8_lossy(&uri.string_representation_without_query_and_fragment())
        .into_owned();
    participant_tel_uri(std::iter::once(uri.as_str()), None)
}

/// What the signature of the notification `imdn` covers, sent in the CPIM
/// message of Message-ID `message_id` in Era `era`, with the
/// Original-Message-ID `original_message_id` if it tells of a Re-Sent
/// Message, else empty (RCC.16 sections 7.5.3.2, 7.5.3.3, 7.6.3); None if it
/// is no delivery or display notification
fn signed_content(
    message_id: &[u8],
    original_message_id: &[u8],
    era: u32,
    imdn: &[u8],
) -> Option<Vec<u8>> {
    let notification = Imdn::from_xml(imdn)?;
    let told_of = notification.message_id.as_bytes();
    let content = match (notification.notification, notification.status) {
        (Notification::Delivery, status) => {
            let status = match status {
                Status::Delivered => DeliveryNotificationStatus::Delivered,
                Status::Failed => DeliveryNotificationStatus::Failed,
                Status::Forbidden => DeliveryNotificationStatus::Forbidden,
                Status::Error => DeliveryNotificationStatus::Error,
                _ => return None,
            };
            let reason = match failure_reason(imdn) {
                Some(FailureReason::Client(reason)) => reason,
                _ => ClientFailureReason::Unset,
            };
            VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
                status,
                told_of,
                original_message_id,
                reason,
            ))
        }
        (Notification::Display, status) => {
            let status = match status {
                Status::Displayed => DisplayNotificationStatus::Displayed,
                Status::Forbidden => DisplayNotificationStatus::Forbidden,
                Status::Error => DisplayNotificationStatus::Error,
                _ => return None,
            };
            VerifiableDerivedContent::DisplayImdn(VerifiableDisplayImdn::new(
                status,
                told_of,
                original_message_id,
            ))
        }
        (Notification::Processing, _) => return None,
    };
    wire::encode(&AuthenticatedData::new(message_id, b"", era, content)).ok()
}

impl E2eeDevice {
    /// The CPIM message `cpim` encrypted in the MLS group `conversation_id`,
    /// in a CPIM message of its unencrypted headers, the Epoch-Authenticator
    /// and Era-ID of the group, asking to be told of a negative delivery, and
    /// carrying it as `message/mls` (RCC.16 sections 7.5, 7.5.1.2, 7.5.5 to
    /// 7.5.7)
    ///
    /// A file transfer message carries the XML telling where the file is in
    /// its stead, with the mls-file element carrying the MlsMessage: what is
    /// encrypted carries the FileInfo of the file and its thumbnail, as
    /// `message/mls-rcs-file-info` (sections 7.8, 9.1.2.1). They are to be
    /// uploaded encrypted for the group within a day, as upload_group_file()
    /// of the engine does; such a message is not kept to be re-sent.
    ///
    /// Not while a Commit of this client waits for the Conversation Focus to
    /// accept it, as the message would be of an epoch the others leave, nor
    /// once the Focus refused the Commit that made the group.
    pub fn encrypt_message(
        &self,
        conversation_id: &str,
        cpim: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        // nothing is sent while the group is self-healed (RCC.16 section
        // 10.1.1)
        if self.heals().ongoing(conversation_id) {
            return Err(MessageError::Pending);
        }
        let body = Body::construct_message(cpim).map_err(|_| MessageError::NotCpim)?;
        let message = CPIMMessage::try_from(&body).map_err(|_| MessageError::NotCpim)?;
        // a file transfer message, of a file encrypted for the group, whose
        // FileInfo is encrypted in place of what it carries (sections 7.8,
        // 9.1.2.1)
        let file_transfer = match message.get_message_body() {
            Some((Some(content_type), xml, false))
                if is_of_type(content_type, CONTENT_TYPE_FT_HTTP) =>
            {
                let file_info = file_urls(xml)
                    .0
                    .and_then(|url| self.uploaded_file_info(conversation_id, &url));
                Some((xml.to_vec(), file_info))
            }
            _ => None,
        };
        let not_encrypted = || match &file_transfer {
            Some((_, Some(_))) => MessageError::FileNotFit,
            _ => MessageError::NotEncrypted,
        };
        // nor encrypted while the Focus has no MLS group for it, an Era of
        // the device moving it back to encrypted waiting or not (sections
        // 10.1, 11.1)
        if self.upgrades().without_group(conversation_id) {
            return Err(not_encrypted());
        }
        let file_transfer = match file_transfer {
            Some((xml, Some(file_info))) if with_mls_file(&xml, b"").is_some() => {
                Some((xml, file_info))
            }
            // one not sealed is sent as it is once the group is unencrypted
            // (section 11.2)
            Some((_, None)) if self.encryption_ended(conversation_id) => {
                return Err(MessageError::NotEncrypted)
            }
            Some(_) => return Err(MessageError::FileNotFit),
            None => None,
        };
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
        match &file_transfer {
            Some((_, file_info)) => {
                let file_info = proto::encode(file_info);
                header_line(
                    &mut payload,
                    b"Content-Type",
                    CONTENT_TYPE_MLS_RCS_FILE_INFO,
                );
                header_line(
                    &mut payload,
                    b"Content-Length",
                    file_info.len().to_string().as_bytes(),
                );
                payload.extend_from_slice(b"\r\n");
                payload.extend_from_slice(&file_info);
            }
            None => {
                if let Ok(mut reader) = message.body.reader() {
                    // in memory, it does not fail
                    let _ = reader.read_to_end(&mut payload);
                }
            }
        }

        let (pending, epoch, ended) = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, _| {
                Ok((
                    conversation.has_pending_commit(),
                    conversation.epoch(),
                    conversation.is_encryption_ended(),
                ))
            })
            .map_err(MessageError::Store)?;
        if pending {
            return Err(MessageError::Pending);
        }
        if ended {
            return Err(match file_transfer {
                Some(_) => MessageError::FileNotFit,
                None => MessageError::NotEncrypted,
            });
        }
        // the group of the device alone, as no Commit was applied to it
        if epoch == 0 {
            return Err(MessageError::NotCreated);
        }
        // kept along with the message, for it to be re-sent to a member that
        // could not decrypt it (section 10.3)
        let disposition = with_negative_delivery(disposition);
        let kept_headers: Vec<(Vec<u8>, Vec<u8>)> = unencrypted
            .iter()
            .filter(|(name, _)| {
                !name.eq_ignore_ascii_case(b"DateTime")
                    && !name.eq_ignore_ascii_case(b"imdn.Message-ID")
            })
            .map(|(name, value)| (name.clone(), value.to_vec()))
            .collect();
        let message_id_text = String::from_utf8_lossy(&message_id).into_owned();
        let now = self.store().now();
        let ((mls_message, epoch_authenticator, era), ()) = self
            .notes()
            .change_with_conversation(
                self.store(),
                conversation_id.as_bytes(),
                |conversation, client| {
                    let era = conversation.era().ok_or(ErrorKind::InvalidState)?;
                    let mls_message =
                        conversation.encrypt_cpim(client, &payload, &message_id, b"")?;
                    Ok((
                        (
                            mls_message,
                            conversation.epoch_authenticator().to_vec(),
                            era,
                        ),
                        members_besides(conversation, client),
                    ))
                },
                |data, (_, members)| {
                    // not a file transfer message, whose Re-Sent Message
                    // would not tell where the file is
                    if file_transfer.is_none() {
                        note_sent(
                            data,
                            conversation_id,
                            &message_id_text,
                            &payload,
                            kept_headers,
                            &disposition,
                            members.clone(),
                            now,
                        )
                    }
                },
            )
            .map(|((made, _), noted)| (made, noted))
            .map_err(MessageError::Store)?;

        let unencrypted: Vec<(Vec<u8>, Vec<u8>)> = unencrypted
            .into_iter()
            .map(|(name, value)| (name, value.to_vec()))
            .collect();
        Ok(match file_transfer {
            // the XML telling where the file is, with the MlsMessage
            // (section 7.8.2)
            Some((xml, _)) => outer_cpim_of(
                &unencrypted,
                &disposition,
                None,
                &epoch_authenticator,
                era,
                CONTENT_TYPE_FT_HTTP,
                &with_mls_file(&xml, &mls_message).ok_or(MessageError::FileNotFit)?,
            ),
            None => outer_cpim(
                &unencrypted,
                &disposition,
                None,
                &epoch_authenticator,
                era,
                &mls_message,
            ),
        })
    }

    /// The CPIM message the `message/mls` `mls_message` of the MLS group
    /// `conversation_id` carried, delivered in the CPIM message `cpim_info`
    /// tells of: its unencrypted headers and what was encrypted, its From the
    /// MLS identity of the sender if that is another (RCC.16 sections
    /// 7.5.3.1, 9.1.1)
    ///
    /// A message not decrypted has its sender told so once the group is
    /// healed (section 10.2). A Re-Sent Message of it to this client gives
    /// the Original Message, with the Message-ID of the Re-Sent Message and
    /// the Original-Message-ID of the other, if this client asked for it from
    /// its sender (section 10.4); one that could not be decrypted has its
    /// sender told so too. Those to other clients are not taken.
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
            .map_err(|e| {
                // as when the group missed a Commit (RCC.16 section 10.1)
                if e == StoreError::Mls(ErrorKind::Rejected) {
                    self.heals().want(conversation_id);
                    self.lose_message(conversation_id, cpim_info);
                }
                MessageError::Store(e)
            })?;
        let original_message_id = String::from_utf8_lossy(&decrypted.original_message_id);
        let (payload, resent) = match (
            decrypted.payload_type,
            decrypted.payload,
            decrypted.resent_failure,
        ) {
            (SecretPayloadType::Application, Some(payload), _) => (payload, false),
            (SecretPayloadType::Hpke1To1Message, Some(payload), _) => {
                if !self
                    .found_resent(conversation_id, &original_message_id, &decrypted.sender)
                    .map_err(MessageError::Store)?
                {
                    return Err(MessageError::NotAskedFor);
                }
                (payload, true)
            }
            (SecretPayloadType::Hpke1To1Message, None, Some(failure)) => {
                // its sender told of one not decrypted (sections 10.2, 10.4)
                if failure == ResentFailure::NotDecrypted
                    && !self
                        .lose_resent(
                            conversation_id,
                            cpim_info,
                            &original_message_id,
                            &decrypted.sender,
                        )
                        .map_err(MessageError::Store)?
                {
                    return Err(MessageError::NotAskedFor);
                }
                return Err(MessageError::ResentNotOpened(failure));
            }
            // to another client
            _ => {
                return Err(MessageError::Store(StoreError::Mls(
                    ErrorKind::UnexpectedMessage,
                )))
            }
        };

        // the sender as the RCS sender identity tells, else as MLS does
        let tel_uris = credential_tel_uris(&decrypted.sender).unwrap_or_default();
        let from = match (told_sender(cpim_info), tel_uris.first()) {
            (Some(told), _) if is_of(&decrypted.sender, &told) => cpim_info.from.to_vec(),
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
        if resent {
            header_line(&mut data, b"NS", b"mls <http://www.gsma.com/rcs/mls>");
            header_line(
                &mut data,
                &[&b"mls."[..], CPIM_HEADER_ORIGINAL_MESSAGE_ID].concat(),
                original_message_id.as_bytes(),
            );
        }
        // the headers encrypted, then the MIME body
        data.extend_from_slice(&payload);
        Ok(data)
    }

    /// The CPIM message `cpim` carrying a delivery or display notification,
    /// signed in the MLS group `conversation_id` over what it tells of, with
    /// the Era-ID of the group (RCC.16 sections 7.5.3.3, 7.6.1, 9.1.3, 9.1.4)
    ///
    /// Not while a Commit of this client waits for the Conversation Focus to
    /// accept it, nor once the Focus refused the Commit that made the group.
    pub fn sign_notification(
        &self,
        conversation_id: &str,
        cpim: &[u8],
    ) -> Result<Vec<u8>, MessageError> {
        if self.heals().ongoing(conversation_id) {
            return Err(MessageError::Pending);
        }
        if self.upgrades().without_group(conversation_id) {
            return Err(MessageError::NotEncrypted);
        }
        let body = Body::construct_message(cpim).map_err(|_| MessageError::NotCpim)?;
        let message = CPIMMessage::try_from(&body).map_err(|_| MessageError::NotCpim)?;
        let info = message.get_info().map_err(|_| MessageError::NotCpim)?;
        // as the client makes them, not Base64 encoded
        let (_, imdn, _) = message.get_message_body().ok_or(MessageError::NotCpim)?;
        // the end of the headers, after which the MIME body comes
        let end = cpim
            .windows(4)
            .position(|crlfs| crlfs == b"\r\n\r\n")
            .ok_or(MessageError::NotCpim)?
            + 2;

        let (pending, epoch, era, ended) = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, _| {
                Ok((
                    conversation.has_pending_commit(),
                    conversation.epoch(),
                    conversation.era(),
                    conversation.is_encryption_ended(),
                ))
            })
            .map_err(MessageError::Store)?;
        if pending {
            return Err(MessageError::Pending);
        }
        // sent unsigned, as in an unencrypted group chat
        if ended {
            return Err(MessageError::NotEncrypted);
        }
        if epoch == 0 {
            return Err(MessageError::NotCreated);
        }
        let era = era.ok_or(MessageError::Store(StoreError::Mls(
            ErrorKind::InvalidState,
        )))?;
        let content = signed_content(
            info.imdn_message_id,
            info.mls_original_message_id.unwrap_or_default(),
            era,
            imdn,
        )
        .ok_or(MessageError::NotCpim)?;
        let signature = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                conversation.sign(client, &content)
            })
            .map_err(MessageError::Store)?;

        let mut data = cpim[..end].to_vec();
        header_line(&mut data, b"NS", b"mls <http://www.gsma.com/rcs/mls>");
        header_line(
            &mut data,
            &[&b"mls."[..], CPIM_HEADER_DERIVED_CONTENT_SIGNATURE].concat(),
            general_purpose::STANDARD.encode(signature).as_bytes(),
        );
        header_line(
            &mut data,
            &[&b"mls."[..], CPIM_HEADER_ERA_ID].concat(),
            era.to_string().as_bytes(),
        );
        data.extend_from_slice(&cpim[end..]);
        Ok(data)
    }

    /// Whether the notification `imdn` received in the MLS group
    /// `conversation_id`, in the CPIM message `cpim_info` tells of, is signed
    /// over what it tells of by the participant it is from (RCC.16 sections
    /// 7.6.2, 9.1.3, 9.1.4)
    ///
    /// A negative delivery may come unsigned: the Conversation Focus sends
    /// its own so, and a client that cannot sign one (section 7.7.2). Any
    /// notification may, once the group chat is unencrypted (section 11.2).
    pub fn verify_notification(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        imdn: &[u8],
    ) -> Result<(), MessageError> {
        if self.encryption_ended(conversation_id) {
            return Ok(());
        }
        if cpim_info.mls_derived_content_signature.is_none() {
            return match Imdn::from_xml(imdn) {
                Some(notification) if notification.status == Status::Failed => Ok(()),
                _ => Err(MessageError::NotSigned),
            };
        }
        self.notification_signer(conversation_id, cpim_info, imdn)
            .map(|_| ())
    }

    /// The Client that signed the notification `imdn` received in the MLS
    /// group `conversation_id`, in the CPIM message `cpim_info` tells of,
    /// over what it tells of, if it is of the participant the notification
    /// is from (RCC.16 sections 7.6.2, 9.1.3, 9.1.4)
    pub(super) fn notification_signer(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        imdn: &[u8],
    ) -> Result<Credential, MessageError> {
        let signature = cpim_info
            .mls_derived_content_signature
            .ok_or(MessageError::NotSigned)?;
        let signature = general_purpose::STANDARD
            .decode(signature)
            .map_err(|_| MessageError::Store(StoreError::Mls(ErrorKind::BadFormat)))?;

        let signer = self
            .store()
            .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                let era = conversation.era().ok_or(ErrorKind::InvalidState)?;
                let content = signed_content(
                    cpim_info.imdn_message_id,
                    cpim_info.mls_original_message_id.unwrap_or_default(),
                    era,
                    imdn,
                )
                .ok_or(ErrorKind::BadFormat)?;
                conversation.verify_signature(client, &signature, &content)
            })
            .map_err(MessageError::Store)?;
        match told_sender(cpim_info) {
            Some(told) if is_of(&signer, &told) => Ok(signer),
            _ => Err(MessageError::NotFromSigner),
        }
    }
}
