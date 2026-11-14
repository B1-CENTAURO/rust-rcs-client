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

//! The E2EE of the device: its MLS state, its Home KDS, and its enrolment
//! once provisioned (RCC.16 sections 4, 5.1)

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::certificate::RcsCredentialValidator;
use rust_rcs_core::mls::rcs::{credential_tel_uris, same_tel_uri, MlsCapability, MLS_VERSION_V1};
use rust_rcs_core::mls::{
    Ciphersuite, Credential, CredentialValidator, ErrorKind, MlsConfig, SignatureKeyPair,
};

use crate::provisioning::ims_application::ImsApplication;
use crate::provisioning::rcs_application::RcsApplication;
use crate::rcs_engine::RcsEngine;

use super::chat::Unencrypted;
use super::description::Descriptions;
use super::file::Uploads;
use super::heal::Heals;
use super::kds::{self, EnrolmentError, KeyDistribution};
use super::metadata::Recoveries;
use super::notes::{put, Notes, Reader};
use super::provisioning;
use super::replace::Replacements;
use super::store::{MlsStore, SaveState, StoreError};
use super::unanswered::Unanswered;
use super::upgrade::Upgrades;
use super::video::VideoCalls;

/// The Cipher Suite the device enrols in: Client Certificates are ECDSA
/// P-256 or P-384 (RCC.16 Annex A.3.7)
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

/// KeyPackages uploaded at enrolment, besides the one of last resort
const KEY_PACKAGES: usize = 10;

/// How long a certificate has left at least for the device to keep it,
/// rather than have it renewed (RCC.16 section 9.5.3)
const RENEWAL_LEAD: Duration = Duration::from_secs(60 * 24 * 60 * 60);

type MakeSigner = Box<dyn Fn() -> Option<SignatureKeyPair> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enrolled {
    /// With a certificate just issued
    Now,
    /// Already, with a certificate others would still add the device with
    Already,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// The device was not provisioned with a tel URI of its user yet
    NotProvisioned,
    Enrolment(EnrolmentError),
}

const LOG_TAG: &str = "e2ee";

/// By group, the Message-ID of the control message carrying the Commit of
/// the device last sent, as the notes of the device keep them for it to
/// restart with: a refusal of it from the Conversation Focus is known then
/// too (RCC.16 sections 6.2.5, 7.7.2.1)
pub(super) struct ControlMessages<'a> {
    notes: &'a Notes,
    store: &'a MlsStore,
}

impl ControlMessages<'_> {
    /// Takes note of `message_id` sent last in the group `conversation_id`
    pub(super) fn insert(&self, conversation_id: &str, message_id: String) {
        self.notes.hold(self.store, |data| {
            data.control_messages
                .insert(String::from(conversation_id), message_id)
        });
    }

    /// The groups one of which waits for the Focus
    pub(super) fn groups(&self) -> Vec<String> {
        self.notes
            .read(|data| data.control_messages.keys().cloned().collect())
    }

    /// The Message-ID of the one of the group `conversation_id` waiting for
    /// the Focus, if one does
    pub(super) fn get(&self, conversation_id: &str) -> Option<String> {
        self.notes
            .read(|data| data.control_messages.get(conversation_id).cloned())
    }

    /// Whether one of the group `conversation_id` waits for the Focus
    pub(super) fn contains(&self, conversation_id: &str) -> bool {
        self.notes
            .read(|data| data.control_messages.contains_key(conversation_id))
    }

    /// Lets go of that of the group `conversation_id`
    pub(super) fn remove(&self, conversation_id: &str) {
        if self.contains(conversation_id) {
            self.notes.hold(self.store, |data| {
                data.control_messages.remove(conversation_id)
            });
        }
    }

    /// Lets go of that of the group `conversation_id` if it is `message_id`;
    /// whether it was
    pub(super) fn take(&self, conversation_id: &str, message_id: &str) -> bool {
        let sent = self.notes.read(|data| {
            data.control_messages
                .get(conversation_id)
                .is_some_and(|sent| sent == message_id)
        });
        if sent {
            self.remove(conversation_id);
        }
        sent
    }
}

/// The control messages `control_messages`, as the notes of the device hold
/// them
pub(super) fn encode_control_messages(control_messages: &BTreeMap<String, String>) -> Vec<u8> {
    let mut data = Vec::new();
    for (conversation_id, message_id) in control_messages {
        put(&mut data, conversation_id.as_bytes());
        put(&mut data, message_id.as_bytes());
    }
    data
}

/// The control messages `reader` reads to its end, as
/// encode_control_messages() puts them; None if they cannot be read
pub(super) fn decode_control_messages(reader: &mut Reader) -> Option<BTreeMap<String, String>> {
    let mut control_messages = BTreeMap::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        control_messages.insert(conversation_id, reader.string()?);
    }
    Some(control_messages)
}

pub struct E2eeDevice {
    store: MlsStore,
    validator: Arc<RcsCredentialValidator>,
    kds: Arc<dyn KeyDistribution>,
    home_kds: u32,
    /// The tel URI of the user, and the ACS Signed Encryption Identity Proof
    /// if ACS gave one
    provisioned: Mutex<Option<(String, Option<Vec<u8>>)>>,
    make_signer: MakeSigner,
    /// What the device keeps besides MLS, with the MLS state: the messages
    /// not decrypted, and those sent; the control messages it waits for the
    /// Conversation Focus to take; the groups to self-heal, being
    /// self-healed and made anew; those moved to unencrypted, and being
    /// moved back; those whose KeyPackage Update is put off, and whose Group
    /// Metadata keys are recovered; the contacts found lately not to take
    /// an encrypted 1-to-1 chat; the subjects and icons of groups that did
    /// not open yet; and the keys of the files uploaded for the messages
    /// sending them
    notes: Notes,
    /// The keys of the media of the Group RCS Video Chats taken part in
    video_calls: VideoCalls,
}

impl E2eeDevice {
    /// The device with the Home KDS `kds`, whose Vendor ID is `home_kds`,
    /// its MLS state kept with `save`, and taken from `saved` if the app kept
    /// one
    pub fn new(
        validator: RcsCredentialValidator,
        home_kds: u32,
        kds: Arc<dyn KeyDistribution>,
        save: SaveState,
        saved: Option<&[u8]>,
    ) -> Result<E2eeDevice, StoreError> {
        let validator = Arc::new(validator);
        let shared: Arc<dyn CredentialValidator> = Arc::clone(&validator) as _;
        let store = MlsStore::new(MlsConfig::default(), shared, save);
        if let Some(saved) = saved.filter(|saved| !saved.is_empty()) {
            store.restore(saved)?;
        }

        let notes = Notes::kept_by(&store);
        let device = E2eeDevice {
            store,
            validator,
            kds,
            home_kds,
            provisioned: Mutex::new(None),
            make_signer: Box::new(|| SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).ok()),
            notes,
            video_calls: VideoCalls::default(),
        };
        device.settle_restarts();
        Ok(device)
    }

    /// Lets go of what the device had pending for the Conversation Focus
    /// before it restarted, as discard_unaccepted() does: the sessions that
    /// were to carry its acceptance went with the device
    fn settle_restarts(&self) {
        let mut groups = self.upgrades().all_restarting();
        groups.extend(self.control_messages().groups());
        groups.sort();
        groups.dedup();
        // but the first Commit of a new group or chat whose INVITE was not
        // answered, which the Focus may have taken: kept until the Focus
        // invites the device into it (RCC.16 section 8.2.1)
        let unanswered = self.unanswered().all();
        groups.retain(|conversation_id| !unanswered.contains(conversation_id));
        for conversation_id in groups {
            if let Err(e) = self.discard_unaccepted(&conversation_id) {
                platform_log(
                    LOG_TAG,
                    format!(
                        "Commit made before the device restarted not discarded: {:?}",
                        e
                    ),
                );
            }
        }
    }

    /// Lets go of what the device has pending for the Conversation Focus in
    /// the group `conversation_id`, which the Focus is to accept no more, as
    /// the session that was to carry its acceptance ended: its Commit, or the
    /// self_remove Proposal of its leave. The Focus accepts a control message
    /// by an AcceptedMlsRcsMessage in the session it came in, and never sends
    /// a Commit back to its sender (RCC.16 section 6.2.4). Kept, a Commit
    /// would stay pending for good, and the device would encrypt and sign
    /// nothing in the group. Had the Focus accepted it, the group is out of
    /// step, and self-healed once that shows (section 10.1).
    ///
    /// The control message is still known, for a refusal of it coming after
    /// to be taken (sections 6.2.5, 7.7.2.1), but that of an Era moving the
    /// group back to encrypted, which the Focus refuses by its answer to the
    /// INVITE restarting the group: the group stays unencrypted until moved
    /// back again (section 11.1).
    pub fn discard_unaccepted(&self, conversation_id: &str) -> Result<(), StoreError> {
        if self.upgrades().restarting(conversation_id) {
            self.discard_pending(conversation_id, false)
        } else if self.control_messages().contains(conversation_id) {
            self.discard_pending(conversation_id, true)
        } else {
            Ok(())
        }
    }

    pub fn store(&self) -> &MlsStore {
        &self.store
    }

    pub(super) fn video_calls(&self) -> &VideoCalls {
        &self.video_calls
    }

    pub(super) fn control_messages(&self) -> ControlMessages<'_> {
        ControlMessages {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn heals(&self) -> Heals<'_> {
        Heals {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn replacements(&self) -> Replacements<'_> {
        Replacements {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn notes(&self) -> &Notes {
        &self.notes
    }

    pub(super) fn upgrades(&self) -> Upgrades<'_> {
        Upgrades {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn recoveries(&self) -> Recoveries<'_> {
        Recoveries {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn uploads(&self) -> Uploads<'_> {
        Uploads {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn descriptions(&self) -> Descriptions<'_> {
        Descriptions {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn unanswered(&self) -> Unanswered<'_> {
        Unanswered {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn unencrypted_chats(&self) -> Unencrypted<'_> {
        Unencrypted {
            notes: &self.notes,
            store: &self.store,
        }
    }

    pub(super) fn home_kds(&self) -> u32 {
        self.home_kds
    }

    pub(super) fn kds(&self) -> &dyn KeyDistribution {
        &*self.kds
    }

    pub(super) fn validator(&self) -> &RcsCredentialValidator {
        &self.validator
    }

    /// The tel URI of the user provisioned, if one was
    pub(super) fn provisioned_tel_uri(&self) -> Option<String> {
        self.provisioned
            .lock()
            .unwrap()
            .as_ref()
            .map(|(tel_uri, _)| tel_uri.clone())
    }

    /// The parameters of the configuration request for ACS to sign the
    /// encryption identity of the device (RCC.16 section 4.1)
    pub fn acs_parameters(&self) -> Result<Vec<(String, String)>, StoreError> {
        provisioning::acs_parameters(&self.store, self.home_kds)
    }

    /// Takes in what provisioning gave: the tel URI of the user, out of the
    /// public user identities or else `msisdn`, and the ACS Signed Encryption
    /// Identity Proof
    pub fn provisioned(&self, ims: &ImsApplication, rcs: &RcsApplication, msisdn: Option<&str>) {
        let tel_uri = participant_tel_uri(ims.get_public_user_identity_list(), msisdn);
        let identity_proof = rcs
            .get_messaging_config()
            .and_then(|messaging| provisioning::identity_proof(&messaging));
        *self.provisioned.lock().unwrap() = tel_uri.map(|tel_uri| (tel_uri, identity_proof));
    }

    /// Enrols the device with its Home KDS, unless it holds a certificate
    /// others would still add it with, for the tel URI provisioned, with 60
    /// days left at least (RCC.16 sections 4.2, 5.1, 9.5.3, Annex A.4.1.2)
    ///
    /// A certificate with less left, or expired, of the same Participant is
    /// renewed, for a new signature key: the client takes on both, keeping
    /// its groups, which take them on with their next key update. One of
    /// another Participant is replaced, and its groups dropped.
    pub async fn enrol(&self) -> Result<Enrolled, DeviceError> {
        let (tel_uri, identity_proof) = self
            .provisioned
            .lock()
            .unwrap()
            .clone()
            .ok_or(DeviceError::NotProvisioned)?;

        let renewing = if let (Some(credential), Some(signature_key)) =
            (self.store.credential(), self.store.signature_key())
        {
            let lasting = self
                .validator
                .validate_query(&credential, &signature_key, &tel_uri)
                .is_ok_and(|certificate| {
                    certificate.not_after >= self.validator.now() + RENEWAL_LEAD
                });
            if lasting {
                if self.store.key_packages_uploaded() {
                    return Ok(Enrolled::Already);
                }
                // certified, but none of its KeyPackages reached the Home KDS
                return kds::upload_key_packages(&self.store, &*self.kds, KEY_PACKAGES, true)
                    .await
                    .map(|()| Enrolled::Now)
                    .map_err(DeviceError::Enrolment);
            }
            // renewed while the Participant is the same, its groups kept
            credential_tel_uris(&credential)
                .is_ok_and(|tel_uris| tel_uris.iter().any(|uri| same_tel_uri(uri, &tel_uri)))
        } else {
            false
        };

        let signer = (self.make_signer)().ok_or(DeviceError::Enrolment(EnrolmentError::Store(
            StoreError::Mls(ErrorKind::Crypto),
        )))?;
        if renewing {
            return kds::renew(
                &self.store,
                &*self.kds,
                &self.validator,
                self.home_kds,
                &tel_uri,
                identity_proof,
                CIPHERSUITE,
                signer,
                KEY_PACKAGES,
            )
            .await
            .map(|()| Enrolled::Now)
            .map_err(DeviceError::Enrolment);
        }
        kds::enrol(
            &self.store,
            &*self.kds,
            &self.validator,
            self.home_kds,
            &tel_uri,
            identity_proof,
            CIPHERSUITE,
            signer,
            KEY_PACKAGES,
        )
        .await
        .map(|()| Enrolled::Now)
        .map_err(DeviceError::Enrolment)
    }

    /// The feature tags of the E2EE capability of the device, while the Home
    /// KDS holds KeyPackages of its client with an unexpired certificate
    /// (RCC.16 sections 5.1, 5.2)
    pub fn mls_feature_tags(&self) -> Option<String> {
        let credential = self.store.credential()?;
        let signature_key = self.store.signature_key()?;
        if !self.store.key_packages_uploaded()
            || self
                .validator
                .validate_credential(&credential, &signature_key)
                .is_err()
        {
            return None;
        }
        let capability = MlsCapability {
            version: MLS_VERSION_V1.to_vec(),
            home_kds: Some(self.home_kds),
        };
        Some(capability.feature_tags().join(";"))
    }

    /// Has `engine` tell the E2EE capability of the device in OPTIONS
    /// exchanges while it applies, for as long as the device is kept
    pub fn advertise_on(self: &Arc<Self>, engine: &RcsEngine) {
        let device = Arc::downgrade(self);
        engine.set_extra_feature_tags(move || {
            device
                .upgrade()
                .and_then(|device| device.mls_feature_tags())
        });
    }

    /// Has the device enrol with the keys `make_signer` makes
    #[cfg(test)]
    pub fn with_signer(
        mut self,
        make_signer: impl Fn() -> Option<SignatureKeyPair> + Send + Sync + 'static,
    ) -> E2eeDevice {
        self.make_signer = Box::new(make_signer);
        self
    }

    /// The device telling the time with `clock` rather than the system
    /// clock, as for when key updates are due
    pub fn with_clock(self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> E2eeDevice {
        self.store.set_clock(Arc::new(clock));
        self
    }
}

/// Whether `told`, the tel URI of a participant, is one of those of the
/// credential `credential`
pub(super) fn is_of(credential: &Credential, told: &str) -> bool {
    credential_tel_uris(credential)
        .unwrap_or_default()
        .iter()
        .any(|uri| same_tel_uri(uri, told))
}

/// Whether the credentials `a` and `b` are of Clients of the same
/// Participant, having a tel URI in common
pub(super) fn same_participant(a: &Credential, b: &Credential) -> bool {
    credential_tel_uris(a)
        .unwrap_or_default()
        .iter()
        .any(|uri| is_of(b, uri))
}

/// The tel URI of the user: one of its public user identities, else the
/// number of a SIP URI among them, else `msisdn`
pub fn participant_tel_uri<'a>(
    public_user_identities: impl Iterator<Item = &'a str>,
    msisdn: Option<&str>,
) -> Option<String> {
    let mut from_sip = None;
    for identity in public_user_identities {
        if identity.starts_with("tel:") {
            return Some(String::from(identity));
        }
        if from_sip.is_none() {
            from_sip = identity
                .strip_prefix("sip:")
                .and_then(|uri| uri.split(['@', ';']).next())
                .filter(|user| {
                    user.strip_prefix('+').is_some_and(|digits| {
                        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
                    })
                })
                .map(|number| format!("tel:{}", number));
        }
    }
    from_sip.or_else(|| {
        msisdn
            .filter(|msisdn| !msisdn.is_empty())
            .map(|msisdn| format!("tel:{}", msisdn))
    })
}
