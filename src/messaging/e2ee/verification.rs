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

//! The identity verification code of the user and a contact, which both are
//! shown to compare (RCC.16 section 5.5, Annex C.5)
//!
//! Each is taken as its Client Certificate tells it: the number of its tel
//! URI, and its Participant Key. The user's is the certificate of the
//! device. The contact's are those of its Clients in the MLS groups the
//! device has with it: the encrypted 1-to-1 chat with it, and the group the
//! app names; the one issued last is taken. Its KeyPackages are not fetched
//! from the Home KDS for it, as each one fetched is used up.

use rust_rcs_core::mls::rcs::certificate::ClientCertificate;
use rust_rcs_core::mls::rcs::same_tel_uri;
use rust_rcs_core::mls::rcs::verification::{identity_verification_code, VerifiedParticipant};

use super::chat::contact_tel_uri;
use super::device::{is_of, E2eeDevice};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The device holds no certificate valid now, of the user provisioned
    NotEnrolled,
    /// The device knows of no certificate of the contact valid now
    ContactUnknown,
}

/// The MSISDN of `tel_uri`, its E.164 number with the `+`, its parameters
/// left out; None if it has no such number
fn msisdn(tel_uri: &str) -> Option<&str> {
    let number = tel_uri.strip_prefix("tel:")?.split(';').next()?;
    let digits = number.strip_prefix('+')?;
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(number)
}

/// The MSISDN of the tel URI of `certificate` that `told` is
fn msisdn_told(certificate: &ClientCertificate, told: &str) -> Option<String> {
    certificate
        .tel_uris
        .iter()
        .find(|uri| same_tel_uri(uri, told))
        .and_then(|uri| msisdn(uri))
        .map(String::from)
}

/// Of the certificates `found`, each with the MSISDN it is for, the one
/// issued last
fn issued_last(found: Vec<(ClientCertificate, String)>) -> Option<(ClientCertificate, String)> {
    found
        .into_iter()
        .max_by_key(|(certificate, _)| certificate.not_before)
}

impl E2eeDevice {
    /// The identity verification code of the user and `contact`, a tel or
    /// SIP URI: 80 decimal digits, the same whichever of the two asks (RCC.16
    /// section 5.5, Annex C.5)
    ///
    /// The contact's Participant Key is taken from the certificates of its
    /// Clients in the encrypted 1-to-1 chat with it, and in the group
    /// `conversation_id` if given, valid now: of those, the one issued last.
    pub fn identity_verification_code(
        &self,
        contact: &str,
        conversation_id: Option<&str>,
    ) -> Result<String, VerificationError> {
        let store = self.store();
        let (credential, signature_key) = store
            .credential()
            .zip(store.signature_key())
            .ok_or(VerificationError::NotEnrolled)?;
        let own = self
            .validator()
            .validate_credential(&credential, &signature_key)
            .map_err(|_| VerificationError::NotEnrolled)?;
        let own_msisdn = match self.provisioned_tel_uri() {
            Some(tel_uri) => msisdn_told(&own, &tel_uri),
            None => own
                .tel_uris
                .first()
                .and_then(|uri| msisdn(uri))
                .map(String::from),
        }
        .ok_or(VerificationError::NotEnrolled)?;

        let contact = contact_tel_uri(contact).ok_or(VerificationError::ContactUnknown)?;
        let groups = self
            .chat_group(&contact)
            .map(|(group_id, _)| group_id)
            .into_iter()
            .chain(conversation_id.map(String::from));
        let mut found = Vec::new();
        for group_id in groups {
            let Ok(members) = store.peek_conversation(group_id.as_bytes(), |conversation, _| {
                conversation.members_with_signature_keys()
            }) else {
                continue;
            };
            for (credential, signature_key) in members {
                if !is_of(&credential, &contact) {
                    continue;
                }
                let Ok(certificate) = self
                    .validator()
                    .validate_credential(&credential, &signature_key)
                else {
                    continue;
                };
                if let Some(number) = msisdn_told(&certificate, &contact) {
                    found.push((certificate, number));
                }
            }
        }
        let (theirs, their_msisdn) = issued_last(found).ok_or(VerificationError::ContactUnknown)?;

        identity_verification_code(
            &VerifiedParticipant {
                msisdn: &own_msisdn,
                participant_key: &own.participant_key,
            },
            &VerifiedParticipant {
                msisdn: &their_msisdn,
                participant_key: &theirs.participant_key,
            },
        )
        .map_err(|_| VerificationError::ContactUnknown)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use rust_rcs_core::mls::rcs::certificate::ClientCertificate;

    use super::{issued_last, msisdn};

    fn issued(day: u64, participant_key: &[u8]) -> (ClientCertificate, String) {
        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(day * 24 * 60 * 60);
        let certificate = ClientCertificate {
            tel_uris: vec![String::from("tel:+491707654321")],
            vendor_id: 42,
            not_before,
            not_after: not_before + Duration::from_secs(60 * 24 * 60 * 60),
            participant_key: participant_key.to_vec(),
        };
        (certificate, String::from("+491707654321"))
    }

    #[test]
    fn of_the_contact_s_certificates_the_one_issued_last_is_taken() {
        let key = |found: Vec<(ClientCertificate, String)>| {
            issued_last(found).map(|(certificate, _)| certificate.participant_key)
        };
        assert_eq!(key(Vec::new()), None);
        assert_eq!(key(vec![issued(1, b"one")]), Some(b"one".to_vec()));
        assert_eq!(
            key(vec![
                issued(1, b"one"),
                issued(3, b"three"),
                issued(2, b"two")
            ]),
            Some(b"three".to_vec())
        );
        assert_eq!(
            key(vec![issued(3, b"three"), issued(1, b"one")]),
            Some(b"three".to_vec())
        );
    }

    #[test]
    fn the_msisdn_is_the_number_of_a_tel_uri() {
        assert_eq!(msisdn("tel:+491701234567"), Some("+491701234567"));
        assert_eq!(
            msisdn("tel:+491701234567;phone-context=ims.example.com"),
            Some("+491701234567")
        );
        for not_one in [
            "tel:491701234567",
            "tel:+",
            "tel:+4917a",
            "sip:+491701234567@ims.example.com",
            "+491701234567",
        ] {
            assert_eq!(msisdn(not_one), None, "{}", not_one);
        }
    }
}
