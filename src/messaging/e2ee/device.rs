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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rust_rcs_core::mls::rcs::certificate::RcsCredentialValidator;
use rust_rcs_core::mls::rcs::{credential_tel_uris, same_tel_uri, MlsCapability, MLS_VERSION_V1};
use rust_rcs_core::mls::{
    Ciphersuite, Credential, CredentialValidator, ErrorKind, MlsConfig, SignatureKeyPair,
};

use crate::provisioning::ims_application::ImsApplication;
use crate::provisioning::rcs_application::RcsApplication;
use crate::rcs_engine::RcsEngine;

use super::heal::Heals;
use super::kds::{self, EnrolmentError, KeyDistribution};
use super::lost::LostMessages;
use super::provisioning;
use super::replace::Replacements;
use super::store::{MlsStore, SaveState, StoreError};
use super::upgrade::Upgrades;

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

pub struct E2eeDevice {
    store: MlsStore,
    validator: Arc<RcsCredentialValidator>,
    kds: Arc<dyn KeyDistribution>,
    home_kds: u32,
    /// The tel URI of the user, and the ACS Signed Encryption Identity Proof
    /// if ACS gave one
    provisioned: Mutex<Option<(String, Option<Vec<u8>>)>>,
    make_signer: MakeSigner,
    /// By group, the Message-ID of the control message carrying the Commit
    /// of the device last sent, for as long as the device runs
    control_messages: Mutex<HashMap<String, String>>,
    /// The groups to self-heal and being self-healed
    heals: Heals,
    /// The groups whose KeyPackage Update is put off for now
    replacements: Replacements,
    /// The groups moved to unencrypted, and being moved back
    upgrades: Upgrades,
    /// The messages not decrypted, kept with the MLS state
    lost: LostMessages,
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

        let lost = LostMessages::kept_by(&store);
        Ok(E2eeDevice {
            store,
            validator,
            kds,
            home_kds,
            provisioned: Mutex::new(None),
            make_signer: Box::new(|| SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).ok()),
            control_messages: Mutex::new(HashMap::new()),
            heals: Heals::default(),
            replacements: Replacements::default(),
            upgrades: Upgrades::default(),
            lost,
        })
    }

    pub fn store(&self) -> &MlsStore {
        &self.store
    }

    pub(super) fn control_messages(&self) -> &Mutex<HashMap<String, String>> {
        &self.control_messages
    }

    pub(super) fn heals(&self) -> &Heals {
        &self.heals
    }

    pub(super) fn replacements(&self) -> &Replacements {
        &self.replacements
    }

    pub(super) fn lost(&self) -> &LostMessages {
        &self.lost
    }

    pub(super) fn upgrades(&self) -> &Upgrades {
        &self.upgrades
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
