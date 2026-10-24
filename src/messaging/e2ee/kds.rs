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

//! The Home KDS of the client (RCC.16 section 5): enrolling the device,
//! uploading its KeyPackages, fetching those of others
//!
//! RCC.16 leaves the interface between clients and their Home KDS vendor
//! specific (sections 5.1, 5.3): `KeyDistribution` is what a vendor's is
//! adapted to.

use std::future::Future;
use std::iter;
use std::pin::Pin;
use std::time::SystemTime;

use rust_rcs_core::mls::rcs::certificate::{
    x509_credential, CertificateError, RcsCredentialValidator,
};
use rust_rcs_core::mls::rcs::ClientIdentity;
use rust_rcs_core::mls::{self, key_package_info, Ciphersuite, MlsClient, SignatureKeyPair};
use uuid::Uuid;

use super::store::{MlsStore, StoreError};

pub type KdsFuture<T> = Pin<Box<dyn Future<Output = Result<T, KdsError>> + Send>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KdsError {
    /// The Home KDS could not be reached, or did not answer as it should;
    /// worth trying again later
    Unavailable,
    /// The Home KDS refused the request, for the reason given
    Refused(String),
}

/// What the device asks its Home KDS to certify (RCC.16 sections 4.2, 5.1,
/// Annex A.3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolment {
    /// The Participant, by the tel URI its certificate is for
    pub tel_uri: String,
    pub ciphersuite: Ciphersuite,
    /// The public key of the MLS signature key of the device
    pub signature_key: Vec<u8>,
    /// The Client ID, a UUIDv4, for the commonName of the Subject (A.3.6)
    pub client_id: String,
    /// The ParticipantInformation extension, DER encoded, signed for the
    /// Client ID, the Vendor ID of the Home KDS, the signature key and the tel
    /// URI (A.3.8.9)
    pub participant_information: Vec<u8>,
    /// The Signed Encryption Identity Proof, if ACS gave one (section 4.1),
    /// for the ACS Participant Information extension (A.3.8.10)
    pub identity_proof: Option<Vec<u8>>,
}

/// A Participant whose KeyPackages are asked for (RCC.16 section 5.3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub tel_uri: String,
    /// Its Encryption Home KDS capability value (section 5.2)
    pub home_kds: String,
}

/// What the Home KDS has for a Participant (RCC.16 section 5.3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// The KeyPackages of all its Clients, in the Cipher Suite chosen
    KeyPackages(Vec<Vec<u8>>),
    NotFound,
    MalformedId,
    /// No Cipher Suite in common
    UnsupportedCipherSuite,
    /// Currently unavailable, worth asking for again
    Unavailable,
    /// KeyPackages a client is not to add, as one does not pass Query
    /// Validation (Annex A.4.1.2); all of a Participant's Clients being added
    /// together, the Participant cannot be added encrypted
    Refused(CertificateError),
}

/// The Home KDS of the client, its interface vendor specific
pub trait KeyDistribution: Send + Sync {
    /// Enrols the device: the certificate chain of its Client Certificate,
    /// Client Certificate first, as the Home KDS issued it (sections 4.2, 5.1)
    fn enrol(&self, enrolment: Enrolment) -> KdsFuture<Vec<Vec<u8>>>;

    /// Uploads KeyPackages of the device for others to add it with (section
    /// 5.1)
    fn upload(&self, key_packages: Vec<Vec<u8>>) -> KdsFuture<()>;

    /// The KeyPackages of `recipients`, in the first of `ciphersuites` all of
    /// them have, by tel URI (section 5.3)
    fn fetch(
        &self,
        ciphersuites: Vec<Ciphersuite>,
        recipients: Vec<Recipient>,
    ) -> KdsFuture<Vec<(String, Fetched)>>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrolmentError {
    Kds(KdsError),
    /// The certificate the Home KDS issued is not one others would add the
    /// device with, for the reason given (Annex A.4.1.2)
    Certificate(CertificateError),
    Store(StoreError),
}

/// Enrols the device with its Home KDS, whose Vendor ID is `home_kds`, for
/// the Participant at `tel_uri`, with `signer` as its MLS signature key: the
/// client made with the certificate issued takes the place of any in `store`,
/// and `key_packages` KeyPackages of it are uploaded, with one of last resort
/// (RCC.16 sections 4.2, 5.1)
///
/// `validator` is the one of `store`. Once the client is made, the device is
/// enrolled: KeyPackages that could not be uploaded are to be uploaded again
/// with upload_key_packages().
pub async fn enrol(
    store: &MlsStore,
    kds: &dyn KeyDistribution,
    validator: &RcsCredentialValidator,
    home_kds: u32,
    tel_uri: &str,
    identity_proof: Option<Vec<u8>>,
    ciphersuite: Ciphersuite,
    signer: SignatureKeyPair,
    key_packages: usize,
) -> Result<(), EnrolmentError> {
    let client_id = Uuid::new_v4().to_string();
    let participant_information = store
        .participant_information(
            &ClientIdentity {
                client_id: &client_id,
                vendor_id: u64::from(home_kds),
                signature_key: signer.public(),
                tel_uris: &[tel_uri],
            },
            SystemTime::now(),
        )
        .map_err(EnrolmentError::Store)?;

    let chain = kds
        .enrol(Enrolment {
            tel_uri: String::from(tel_uri),
            ciphersuite,
            signature_key: signer.public().to_vec(),
            client_id,
            participant_information,
            identity_proof,
        })
        .await
        .map_err(EnrolmentError::Kds)?;
    let chain: Vec<&[u8]> = chain.iter().map(|certificate| &certificate[..]).collect();
    let credential = x509_credential(&chain);

    // as others will find it when given the device's KeyPackages
    validator
        .validate_query(&credential, signer.public(), tel_uri)
        .map_err(EnrolmentError::Certificate)?;
    store
        .create(|config, validator| {
            MlsClient::with_credential(credential, signer, ciphersuite, config, validator)
        })
        .map_err(EnrolmentError::Store)?;

    upload_key_packages(store, kds, key_packages, true).await
}

/// Uploads `count` new KeyPackages of the client in `store`, and one of last
/// resort if `last_resort` (RCC.16 section 5.1)
pub async fn upload_key_packages(
    store: &MlsStore,
    kds: &dyn KeyDistribution,
    count: usize,
    last_resort: bool,
) -> Result<(), EnrolmentError> {
    // kept, before others are given them to add the device with
    let key_packages = store
        .with_client(|client| {
            iter::repeat(false)
                .take(count)
                .chain(iter::once(true).filter(|_| last_resort))
                .map(|last_resort| client.generate_key_package(last_resort))
                .collect::<mls::Result<Vec<Vec<u8>>>>()
        })
        .map_err(EnrolmentError::Store)?;

    kds.upload(key_packages).await.map_err(EnrolmentError::Kds)
}

/// The KeyPackages of `recipients` the Home KDS returns, each in one of
/// `ciphersuites` and for the Participant asked for, with 30 days left at
/// least on its certificate (RCC.16 section 5.3, Annex A.4.1.2)
pub async fn fetch_key_packages(
    kds: &dyn KeyDistribution,
    validator: &RcsCredentialValidator,
    ciphersuites: Vec<Ciphersuite>,
    recipients: Vec<Recipient>,
) -> Result<Vec<(String, Fetched)>, KdsError> {
    let fetched = kds.fetch(ciphersuites.clone(), recipients).await?;

    Ok(fetched
        .into_iter()
        .map(|(tel_uri, fetched)| {
            let fetched = match fetched {
                // no Client to add the Participant with
                Fetched::KeyPackages(key_packages) if key_packages.is_empty() => Fetched::NotFound,
                Fetched::KeyPackages(key_packages) => {
                    match key_packages.iter().try_for_each(|key_package| {
                        check_key_package(validator, &ciphersuites, key_package, &tel_uri)
                    }) {
                        Ok(()) => Fetched::KeyPackages(key_packages),
                        Err(e) => Fetched::Refused(e),
                    }
                }
                fetched => fetched,
            };
            (tel_uri, fetched)
        })
        .collect())
}

/// Query Validation of `key_package`, which the Home KDS returned for the
/// Participant at `tel_uri`
fn check_key_package(
    validator: &RcsCredentialValidator,
    ciphersuites: &[Ciphersuite],
    key_package: &[u8],
    tel_uri: &str,
) -> Result<(), CertificateError> {
    let info = key_package_info(key_package).map_err(|_| CertificateError::Malformed)?;
    if !ciphersuites.contains(&info.ciphersuite) {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    validator
        .validate_query(&info.credential, &info.signature_key, tel_uri)
        .map(|_| ())
}
