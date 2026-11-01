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

//! The messages the device sent encrypted, re-sent to a member that tells it
//! could not decrypt one (RCC.16 section 10.3)
//!
//! They are kept with the MLS state, in the notes of the device, with the
//! members of their group when each was sent.

use std::time::{Duration, SystemTime};

use chrono::SecondsFormat;
use rust_rcs_core::cpim::CPIMInfo;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::imdn::notification::{Imdn, Notification, Status};
use rust_rcs_core::mls::rcs::imdn::{failure_reason, FailureReason};
use rust_rcs_core::mls::rcs::{
    credential_tel_uris, participant_keys, same_tel_uri, ClientFailureReason,
};
use rust_rcs_core::mls::{Credential, ErrorKind, MlsClient, MlsConversation};

use crate::messaging::cpm::encryption::FtdAnswer;
use crate::messaging::cpm::new_message_id;

use super::device::E2eeDevice;
use super::message::outer_cpim;
use super::notes::{put, put_time, NotesData, Reader};

const LOG_TAG: &str = "e2ee";

/// How long a message sent is kept: one older is not re-sent (RCC.16
/// section 10.3)
const SENT_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How many messages sent are kept at most, the oldest forgotten first
const SENT_MOST: usize = 256;

/// How many bytes of messages sent are kept at most, the oldest forgotten
/// first, as they are kept with the MLS state
const SENT_BYTES: usize = 512 * 1024;

/// How many times a message is re-sent at most (RCC.16 section 10.3)
const RESENT_MOST: usize = 5;

/// For how long after a message was sent a member whose Participant Key
/// changed, other than by a key roll, is still re-sent it (RCC.16 section
/// 10.3)
const KEY_CHANGE_GRACE: Duration = Duration::from_secs(60 * 60);

/// A message sent encrypted
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Sent {
    pub(super) conversation_id: String,
    pub(super) message_id: String,
    /// What was encrypted: the CPIM headers encrypted, then the MIME body
    pub(super) payload: Vec<u8>,
    /// The CPIM headers it was sent with unencrypted, but its Message-ID,
    /// DateTime and Disposition-Notification: the name of each as sent, and
    /// its value
    pub(super) headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// Its Disposition-Notification
    pub(super) disposition: Vec<u8>,
    pub(super) sent: SystemTime,
    /// The id of the Membership of its group when it was sent
    pub(super) membership: u32,
    /// Its Re-Sent Messages: the Message-ID of each, and the content of the
    /// credential of the Client it was sealed to
    pub(super) resent: Vec<(String, Vec<u8>)>,
}

/// The members of a group, but the device, when messages were sent
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Membership {
    pub(super) conversation_id: String,
    pub(super) id: u32,
    /// The tel URI and the Participant Key of each Client
    pub(super) members: Vec<(String, Vec<u8>)>,
}

/// The other Clients of the group `conversation`, of `client`: the tel URI
/// and the Participant Key of each, as their Client Certificate tells
pub(super) fn members_besides(
    conversation: &MlsConversation,
    client: &MlsClient,
) -> Vec<(String, Vec<u8>)> {
    let own = client.credential();
    conversation
        .members()
        .iter()
        .filter(|credential| *credential != own)
        .filter_map(|credential| {
            Some((
                credential_tel_uris(credential).ok()?.into_iter().next()?,
                participant_keys(credential).ok()?.into_iter().next()?,
            ))
        })
        .collect()
}

/// Takes note in `data` of the message `message_id` of the group
/// `conversation_id` sent at `now`, `members` the other Clients of its group
/// then; those too old or too many are forgotten, with the memberships
/// none refers to
#[allow(clippy::too_many_arguments)]
pub(super) fn note_sent(
    data: &mut NotesData,
    conversation_id: &str,
    message_id: &str,
    payload: &[u8],
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    disposition: &[u8],
    members: Vec<(String, Vec<u8>)>,
    now: SystemTime,
) {
    data.sent.retain(|sent| {
        now.duration_since(sent.sent)
            .is_ok_and(|age| age <= SENT_FOR)
    });
    let membership = match data.memberships.iter().find(|membership| {
        membership.conversation_id == conversation_id && membership.members == members
    }) {
        Some(membership) => membership.id,
        None => {
            let id = data
                .memberships
                .iter()
                .map(|membership| membership.id)
                .max()
                .map_or(0, |id| id.wrapping_add(1));
            data.memberships.push(Membership {
                conversation_id: String::from(conversation_id),
                id,
                members,
            });
            id
        }
    };
    data.sent.push(Sent {
        conversation_id: String::from(conversation_id),
        message_id: String::from(message_id),
        payload: payload.to_vec(),
        headers,
        disposition: disposition.to_vec(),
        sent: now,
        membership,
        resent: Vec::new(),
    });
    while data.sent.len() > SENT_MOST
        || data
            .sent
            .iter()
            .map(|sent| sent.payload.len())
            .sum::<usize>()
            > SENT_BYTES
    {
        data.sent.remove(0);
    }
    let sent = &data.sent;
    data.memberships.retain(|membership| {
        sent.iter().any(|sent| {
            sent.conversation_id == membership.conversation_id && sent.membership == membership.id
        })
    });
}

/// Whether a member whose Participant Key was `then` when a message was sent
/// at `sent`, and whose Participant Key and older keys its key rolls vouch
/// for are `keys` now, is still re-sent it at `now`: unless its key changed
/// other than by a key roll, over an hour after it was sent (RCC.16 section
/// 10.3, Annex A.3.8.9)
fn key_still_vouched(then: &[u8], keys: &[Vec<u8>], sent: SystemTime, now: SystemTime) -> bool {
    keys.iter().any(|key| key == then)
        || now
            .duration_since(sent)
            .map_or(true, |age| age <= KEY_CHANGE_GRACE)
}

/// What is to be re-sent of a message, to whom it is
struct ToResend {
    payload: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    disposition: Vec<u8>,
}

/// The message `original_message_id` of the group `conversation_id` that
/// `data` holds, if it is to be re-sent to `signer` at `now`, in answer to
/// a negative delivery of it, or of its Re-Sent Message `resent_message_id`
/// if given (RCC.16 section 10.3); else why not
fn to_resend(
    data: &NotesData,
    conversation_id: &str,
    original_message_id: &str,
    resent_message_id: Option<&str>,
    signer: &Credential,
    now: SystemTime,
) -> Result<ToResend, &'static str> {
    let sent = data
        .sent
        .iter()
        .find(|sent| {
            sent.conversation_id == conversation_id && sent.message_id == original_message_id
        })
        .ok_or("not of a message sent encrypted lately")?;
    if !now
        .duration_since(sent.sent)
        .is_ok_and(|age| age <= SENT_FOR)
    {
        return Err("of a message sent over 30 days ago");
    }
    if sent.resent.len() >= RESENT_MOST {
        return Err("of a message re-sent too often");
    }
    if let Some(resent_message_id) = resent_message_id {
        let content = signer.serialized_content();
        if !sent
            .resent
            .iter()
            .any(|(message_id, sealed_to)| message_id == resent_message_id && sealed_to == content)
        {
            return Err("not from the Client the message was re-sent to");
        }
    }

    let tel_uris = credential_tel_uris(signer).unwrap_or_default();
    let (_, then) = data
        .memberships
        .iter()
        .find(|membership| {
            membership.conversation_id == conversation_id && membership.id == sent.membership
        })
        .and_then(|membership| {
            membership.members.iter().find(|(tel_uri, _)| {
                tel_uris
                    .iter()
                    .any(|signer_uri| same_tel_uri(signer_uri, tel_uri))
            })
        })
        .ok_or("from one not a member when the message was sent")?;
    let keys = participant_keys(signer).unwrap_or_default();
    if !key_still_vouched(then, &keys, sent.sent, now) {
        return Err("from one whose Participant Key changed since");
    }

    Ok(ToResend {
        payload: sent.payload.clone(),
        headers: sent.headers.clone(),
        disposition: sent.disposition.clone(),
    })
}

impl E2eeDevice {
    /// What the device makes of the notification `imdn` received in the
    /// group `conversation_id`, in the CPIM message `cpim_info` tells of, if
    /// it is a negative delivery telling that a message of the device, or a
    /// Re-Sent Message of it, could not be decrypted (RCC.16 section 10.3)
    ///
    /// The message is re-sent, in a Re-Sent Message to the Client that
    /// signed the notification, with the CPIM headers the message was sent
    /// with, and a key update of the device is due. Not if:
    /// - the group is no longer encrypted;
    /// - the message is not one the device sent encrypted, in the 30 days
    ///   before;
    /// - the Client was not a member when it was sent;
    /// - its Participant Key changed since, other than by a key roll, and it
    ///   was sent over an hour before;
    /// - the notification is of a Re-Sent Message sealed to another Client;
    /// - it was re-sent 5 times already.
    ///
    /// A notification not signed, or not by the participant it is from, has
    /// the group self-healed instead.
    pub fn answer_failed_to_decrypt(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        imdn: &[u8],
    ) -> FtdAnswer {
        let Some(notification) = Imdn::from_xml(imdn) else {
            return FtdAnswer::NotOne;
        };
        if notification.notification != Notification::Delivery
            || notification.status != Status::Failed
        {
            return FtdAnswer::NotOne;
        }
        let of_resent = match failure_reason(imdn) {
            Some(FailureReason::Client(ClientFailureReason::FailureToDecrypt)) => false,
            Some(FailureReason::Client(
                ClientFailureReason::InnerResentMessageFailureToDecrypt,
            )) => true,
            _ => return FtdAnswer::NotOne,
        };
        // not re-sent unencrypted (section 10.3)
        if self.encryption_ended(conversation_id) {
            return FtdAnswer::Ignored;
        }
        let signer = match self.notification_signer(conversation_id, cpim_info, imdn) {
            Ok(signer) => signer,
            Err(e) => {
                platform_log(
                    LOG_TAG,
                    format!(
                        "negative delivery not taken, its signature not good: {:?}",
                        e
                    ),
                );
                self.heals().want(conversation_id);
                return FtdAnswer::Heal;
            }
        };
        let (original_message_id, resent_message_id) = match of_resent {
            false => (notification.message_id, None),
            true => match cpim_info.mls_original_message_id {
                Some(original_message_id) => (
                    String::from_utf8_lossy(original_message_id).into_owned(),
                    Some(notification.message_id),
                ),
                None => return FtdAnswer::Ignored,
            },
        };

        let now = self.store().now();
        let to_resend = self.notes().read(|data| {
            to_resend(
                data,
                conversation_id,
                &original_message_id,
                resent_message_id.as_deref(),
                &signer,
                now,
            )
        });
        let to_resend = match to_resend {
            Ok(to_resend) => to_resend,
            Err(why) => {
                platform_log(LOG_TAG, format!("negative delivery not answered: {}", why));
                return FtdAnswer::Ignored;
            }
        };

        // a key update follows (section 10.3)
        let message_id = new_message_id();
        let made = self.notes().change_with_conversation(
            self.store(),
            conversation_id.as_bytes(),
            |conversation, client| {
                let era = conversation.era().ok_or(ErrorKind::InvalidState)?;
                let mls_message = conversation.encrypt_resent(
                    client,
                    &to_resend.payload,
                    &signer,
                    message_id.as_bytes(),
                    original_message_id.as_bytes(),
                )?;
                conversation.want_key_update(client)?;
                Ok((
                    mls_message,
                    conversation.epoch_authenticator().to_vec(),
                    era,
                ))
            },
            |data, _| {
                if let Some(sent) = data.sent.iter_mut().find(|sent| {
                    sent.conversation_id == conversation_id
                        && sent.message_id == original_message_id
                }) {
                    sent.resent
                        .push((message_id.clone(), signer.serialized_content().to_vec()));
                }
            },
        );
        let (mls_message, epoch_authenticator, era) = match made {
            Ok((made, ())) => made,
            Err(e) => {
                platform_log(LOG_TAG, format!("message not re-sent: {:?}", e));
                return FtdAnswer::Ignored;
            }
        };

        let datetime = chrono::DateTime::<chrono::Utc>::from(now)
            .to_rfc3339_opts(SecondsFormat::Millis, false);
        let mut headers = to_resend.headers;
        headers.push((b"DateTime".to_vec(), datetime.into_bytes()));
        headers.push((b"imdn.Message-ID".to_vec(), message_id.into_bytes()));
        FtdAnswer::Resend(outer_cpim(
            &headers,
            &to_resend.disposition,
            Some(original_message_id.as_bytes()),
            &epoch_authenticator,
            era,
            &mls_message,
        ))
    }
}

/// The messages sent `sent`, as the notes of the device hold them
pub(super) fn encode(sent: &[Sent]) -> Vec<u8> {
    let mut data = Vec::new();
    for sent in sent {
        put(&mut data, sent.conversation_id.as_bytes());
        put(&mut data, sent.message_id.as_bytes());
        put(&mut data, &sent.payload);
        data.extend_from_slice(&(sent.headers.len() as u32).to_be_bytes());
        for (name, value) in &sent.headers {
            put(&mut data, name);
            put(&mut data, value);
        }
        put(&mut data, &sent.disposition);
        put_time(&mut data, sent.sent);
        data.extend_from_slice(&sent.membership.to_be_bytes());
        data.extend_from_slice(&(sent.resent.len() as u32).to_be_bytes());
        for (message_id, sealed_to) in &sent.resent {
            put(&mut data, message_id.as_bytes());
            put(&mut data, sealed_to);
        }
    }
    data
}

/// The messages sent `reader` reads to its end; None if they cannot be read
pub(super) fn decode(reader: &mut Reader) -> Option<Vec<Sent>> {
    let mut sent = Vec::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let message_id = reader.string()?;
        let payload = reader.vec()?;
        let headers = (0..reader.u32()?)
            .map(|_| Some((reader.vec()?, reader.vec()?)))
            .collect::<Option<Vec<_>>>()?;
        let disposition = reader.vec()?;
        let time = reader.time()?;
        let membership = reader.u32()?;
        let resent = (0..reader.u32()?)
            .map(|_| Some((reader.string()?, reader.vec()?)))
            .collect::<Option<Vec<_>>>()?;
        sent.push(Sent {
            conversation_id,
            message_id,
            payload,
            headers,
            disposition,
            sent: time,
            membership,
            resent,
        });
    }
    Some(sent)
}

/// The memberships `memberships`, as the notes of the device hold them
pub(super) fn encode_memberships(memberships: &[Membership]) -> Vec<u8> {
    let mut data = Vec::new();
    for membership in memberships {
        put(&mut data, membership.conversation_id.as_bytes());
        data.extend_from_slice(&membership.id.to_be_bytes());
        data.extend_from_slice(&(membership.members.len() as u32).to_be_bytes());
        for (tel_uri, participant_key) in &membership.members {
            put(&mut data, tel_uri.as_bytes());
            put(&mut data, participant_key);
        }
    }
    data
}

/// The memberships `reader` reads to its end; None if they cannot be read
pub(super) fn decode_memberships(reader: &mut Reader) -> Option<Vec<Membership>> {
    let mut memberships = Vec::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let id = reader.u32()?;
        let members = (0..reader.u32()?)
            .map(|_| Some((reader.string()?, reader.vec()?)))
            .collect::<Option<Vec<_>>>()?;
        memberships.push(Membership {
            conversation_id,
            id,
            members,
        });
    }
    Some(memberships)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::super::notes::NotesData;
    use super::{key_still_vouched, note_sent, KEY_CHANGE_GRACE, SENT_BYTES, SENT_FOR, SENT_MOST};

    const BOB: &str = "tel:+491707654321";
    const CAROL: &str = "tel:+491700000001";

    fn then() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    fn members(of: &[&str]) -> Vec<(String, Vec<u8>)> {
        of.iter()
            .map(|tel_uri| (String::from(*tel_uri), tel_uri.as_bytes().to_vec()))
            .collect()
    }

    fn note(data: &mut NotesData, message_id: &str, payload: usize, of: &[&str], at: SystemTime) {
        note_sent(
            data,
            "group-1",
            message_id,
            &vec![0; payload],
            Vec::new(),
            b"negative-delivery",
            members(of),
            at,
        );
    }

    fn message_ids(data: &NotesData) -> Vec<&str> {
        data.sent
            .iter()
            .map(|sent| sent.message_id.as_str())
            .collect()
    }

    #[test]
    fn the_members_of_a_group_are_kept_once_for_the_messages_sent_then() {
        let mut data = NotesData::default();
        note(&mut data, "m1", 10, &[BOB], then());
        note(&mut data, "m2", 10, &[BOB], then());
        note(&mut data, "m3", 10, &[BOB, CAROL], then());
        assert_eq!(data.memberships.len(), 2);
        assert_eq!(data.sent[0].membership, data.sent[1].membership);
        assert_ne!(data.sent[1].membership, data.sent[2].membership);
        assert_eq!(data.memberships[1].members, members(&[BOB, CAROL]));

        // those of no message kept are let go of
        let later = then() + SENT_FOR + Duration::from_secs(1);
        note(&mut data, "m4", 10, &[BOB, CAROL], later);
        assert_eq!(message_ids(&data), ["m4"]);
        assert_eq!(data.memberships.len(), 1);
        assert_eq!(data.memberships[0].members, members(&[BOB, CAROL]));
    }

    #[test]
    fn messages_sent_are_kept_for_30_days_256_and_512_kib_at_most() {
        let mut data = NotesData::default();
        note(&mut data, "old", 10, &[BOB], then());
        note(&mut data, "recent", 10, &[BOB], then() + SENT_FOR);
        assert_eq!(message_ids(&data), ["old", "recent"]);
        note(
            &mut data,
            "new",
            10,
            &[BOB],
            then() + SENT_FOR + Duration::from_secs(1),
        );
        assert_eq!(message_ids(&data), ["recent", "new"]);

        let mut data = NotesData::default();
        for n in 0..=SENT_MOST {
            note(&mut data, &format!("m{}", n), 10, &[BOB], then());
        }
        assert_eq!(data.sent.len(), SENT_MOST);
        assert_eq!(data.sent[0].message_id, "m1");

        let mut data = NotesData::default();
        note(&mut data, "m1", SENT_BYTES / 2, &[BOB], then());
        note(&mut data, "m2", SENT_BYTES / 2, &[BOB], then());
        assert_eq!(message_ids(&data), ["m1", "m2"]);
        note(&mut data, "m3", 1, &[BOB], then());
        assert_eq!(message_ids(&data), ["m2", "m3"]);
    }

    #[test]
    fn a_participant_key_changed_but_by_a_key_roll_is_not_re_sent_to_over_an_hour_on() {
        let keys = vec![b"new".to_vec(), b"older".to_vec(), b"oldest".to_vec()];
        let at = |after: Duration| then() + after;
        // the same key, or one the key rolls vouch for (RCC.16 section 10.3,
        // Annex A.3.8.9)
        for then_key in [&b"new"[..], b"older", b"oldest"] {
            assert!(key_still_vouched(
                then_key,
                &keys,
                then(),
                at(2 * KEY_CHANGE_GRACE)
            ));
        }
        // another, within an hour
        assert!(key_still_vouched(
            b"other",
            &keys,
            then(),
            at(KEY_CHANGE_GRACE)
        ));
        assert!(!key_still_vouched(
            b"other",
            &keys,
            then(),
            at(KEY_CHANGE_GRACE + Duration::from_secs(1))
        ));
        // none known now
        assert!(!key_still_vouched(
            b"new",
            &[],
            then(),
            at(2 * KEY_CHANGE_GRACE)
        ));
        // the clock gone back
        assert!(key_still_vouched(
            b"other",
            &keys,
            then(),
            then() - Duration::from_secs(1)
        ));
    }
}
