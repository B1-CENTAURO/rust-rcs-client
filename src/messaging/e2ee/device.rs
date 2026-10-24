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

use std::sync::{Arc, Mutex};

use rust_rcs_core::mls::rcs::certificate::RcsCredentialValidator;
use rust_rcs_core::mls::rcs::{MlsCapability, MLS_VERSION_V1};
use rust_rcs_core::mls::{
    Ciphersuite, CredentialValidator, ErrorKind, MlsConfig, SignatureKeyPair,
};

use crate::provisioning::ims_application::ImsApplication;
use crate::provisioning::rcs_application::RcsApplication;
use crate::rcs_engine::RcsEngine;

use super::kds::{self, EnrolmentError, KeyDistribution};
use super::provisioning;
use super::store::{MlsStore, SaveState, StoreError};

/// The Cipher Suite the device enrols in: Client Certificates are ECDSA
/// P-256 or P-384 (RCC.16 Annex A.3.7)
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

/// KeyPackages uploaded at enrolment, besides the one of last resort
const KEY_PACKAGES: usize = 10;

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

        Ok(E2eeDevice {
            store,
            validator,
            kds,
            home_kds,
            provisioned: Mutex::new(None),
            make_signer: Box::new(|| SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).ok()),
        })
    }

    pub fn store(&self) -> &MlsStore {
        &self.store
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
    /// others would still add it with, for the tel URI provisioned (RCC.16
    /// sections 4.2, 5.1, Annex A.4.1.2)
    pub async fn enrol(&self) -> Result<Enrolled, DeviceError> {
        let (tel_uri, identity_proof) = self
            .provisioned
            .lock()
            .unwrap()
            .clone()
            .ok_or(DeviceError::NotProvisioned)?;

        if let (Some(credential), Some(signature_key)) =
            (self.store.credential(), self.store.signature_key())
        {
            if self
                .validator
                .validate_query(&credential, &signature_key, &tel_uri)
                .is_ok()
            {
                if self.store.key_packages_uploaded() {
                    return Ok(Enrolled::Already);
                }
                // certified, but none of its KeyPackages reached the Home KDS
                return kds::upload_key_packages(&self.store, &*self.kds, KEY_PACKAGES, true)
                    .await
                    .map(|()| Enrolled::Now)
                    .map_err(DeviceError::Enrolment);
            }
        }

        let signer = (self.make_signer)().ok_or(DeviceError::Enrolment(EnrolmentError::Store(
            StoreError::Mls(ErrorKind::Crypto),
        )))?;
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
