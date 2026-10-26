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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures::executor::block_on;
use uuid::{Uuid, Version};

use rust_rcs_core::mls::rcs::certificate::{
    x509_credential, CertificateError, RcsCredentialValidator,
};
use rust_rcs_core::mls::rcs::ClientIdentity;
use rust_rcs_core::mls::{
    key_package_info, Ciphersuite, Credential, MlsClient, MlsConfig, SignatureKeyPair,
};

use super::kds::{
    enrol, fetch_key_packages, upload_key_packages, Enrolment, EnrolmentError, Fetched, KdsError,
    KdsFuture, KeyDistribution, Recipient,
};
use super::provisioning::acs_parameters;
use super::store::{MlsStore, StoreError};

// the certificates rust-rcs-core is tested with, beside which the client is
// built
#[allow(dead_code)]
#[path = "../../../../rust-rcs-core/src/mls/rcs/testdata/certificates.rs"]
pub(super) mod certificates;

use certificates::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

pub(super) const ALICE_TEL: &str = "tel:+491701234567";
/// The Vendor ID of the root of the test certificates
pub(super) const HOME_KDS: u32 = 42;
pub(super) const BOB_TEL: &str = "tel:+491707654321";

/// When the certificates have more than 60 days left, as a device keeps
/// its own without having it renewed (RCC.16 section 9.5.3)
pub(super) const EARLY: &str = "2026-09-01";
/// When the certificates have 30 days left at least
pub(super) const TODAY: &str = "2026-09-15";
/// When they have less
pub(super) const LATER: &str = "2026-10-15";

pub(super) fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub(super) fn validator(date: &str) -> RcsCredentialValidator {
    let now: SystemTime = chrono::DateTime::parse_from_rfc3339(&format!("{}T00:00:00Z", date))
        .unwrap()
        .into();
    RcsCredentialValidator::new(&[&bytes(ROOT)])
        .unwrap()
        .with_clock(move || now)
}

fn chain(certificates: &[&str]) -> Vec<Vec<u8>> {
    certificates.iter().map(|c| bytes(c)).collect()
}

pub(super) fn credential(certificates: &[&str]) -> Credential {
    let chain = chain(certificates);
    let chain: Vec<&[u8]> = chain.iter().map(|c| &c[..]).collect();
    x509_credential(&chain)
}

pub(super) fn signer(key: &str, public_key: &str) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(
        CIPHERSUITE.signature_algorithm(),
        bytes(key),
        bytes(public_key),
    )
}

/// What the app keeps of the state, as it is given it
#[derive(Default)]
pub(super) struct App {
    pub(super) kept: Mutex<Vec<Vec<u8>>>,
}

impl App {
    pub(super) fn kept(&self) -> usize {
        self.kept.lock().unwrap().len()
    }

    pub(super) fn last(&self) -> Option<Vec<u8>> {
        self.kept.lock().unwrap().last().cloned()
    }
}

/// A store keeping the state with `app`, validating as `validator`
fn store(app: &Arc<App>, validator: RcsCredentialValidator) -> MlsStore {
    let app = Arc::clone(app);
    MlsStore::new(
        MlsConfig::default(),
        Arc::new(validator),
        Box::new(move |state| {
            app.kept.lock().unwrap().push(state.to_vec());
            true
        }),
    )
}

/// A Home KDS of the tests
#[derive(Default)]
pub(super) struct Kds {
    /// The chain it issues; unavailable without
    issuing: Option<Vec<Vec<u8>>>,
    /// Whether it takes KeyPackages
    pub(super) taking: AtomicBool,
    /// What it has for the Participants asked for; unavailable without
    pub(super) directory: Mutex<Option<Vec<(String, Fetched)>>>,
    /// The app, to tell what it had kept by an upload
    app: Option<Arc<App>>,
    pub(super) enrolments: Mutex<Vec<Enrolment>>,
    /// The KeyPackages uploaded, with the state the app had kept by then
    uploads: Mutex<Vec<(Vec<Vec<u8>>, Option<Vec<u8>>)>>,
    pub(super) queries: Mutex<Vec<(Vec<Ciphersuite>, Vec<Recipient>)>>,
}

impl Kds {
    pub(super) fn issuing(certificates: &[&str], app: &Arc<App>) -> Kds {
        Kds {
            issuing: Some(chain(certificates)),
            taking: AtomicBool::new(true),
            app: Some(Arc::clone(app)),
            ..Kds::default()
        }
    }

    fn knowing(directory: Vec<(&str, Fetched)>) -> Kds {
        Kds::default().knowing_too(directory)
    }

    /// The KDS, having `directory` for the Participants asked for too
    pub(super) fn knowing_too(self, directory: Vec<(&str, Fetched)>) -> Kds {
        self.now_knowing(directory);
        self
    }

    /// Has the KDS have `directory` for the Participants asked for from now
    /// on
    pub(super) fn now_knowing(&self, directory: Vec<(&str, Fetched)>) {
        *self.directory.lock().unwrap() = Some(
            directory
                .into_iter()
                .map(|(tel_uri, fetched)| (String::from(tel_uri), fetched))
                .collect(),
        );
    }

    pub(super) fn uploads(&self) -> Vec<(Vec<Vec<u8>>, Option<Vec<u8>>)> {
        self.uploads.lock().unwrap().clone()
    }
}

impl KeyDistribution for Kds {
    fn enrol(&self, enrolment: Enrolment) -> KdsFuture<Vec<Vec<u8>>> {
        self.enrolments.lock().unwrap().push(enrolment);
        let issuing = self.issuing.clone();
        Box::pin(async move { issuing.ok_or(KdsError::Unavailable) })
    }

    fn upload(&self, key_packages: Vec<Vec<u8>>) -> KdsFuture<()> {
        let taking = self.taking.load(Ordering::SeqCst);
        if taking {
            let kept = self.app.as_ref().and_then(|app| app.last());
            self.uploads.lock().unwrap().push((key_packages, kept));
        }
        Box::pin(async move {
            if taking {
                Ok(())
            } else {
                Err(KdsError::Refused(String::from("quota")))
            }
        })
    }

    fn fetch(
        &self,
        ciphersuites: Vec<Ciphersuite>,
        recipients: Vec<Recipient>,
    ) -> KdsFuture<Vec<(String, Fetched)>> {
        self.queries
            .lock()
            .unwrap()
            .push((ciphersuites, recipients));
        let directory = self.directory.lock().unwrap().clone();
        Box::pin(async move { directory.ok_or(KdsError::Unavailable) })
    }
}

/// Alice's device enrolled with `kds` for `tel_uri`, on `date`
fn enrolling(
    app: &Arc<App>,
    kds: &Kds,
    tel_uri: &str,
    date: &str,
) -> (MlsStore, Result<(), EnrolmentError>) {
    let device = store(app, validator(date));
    let enrolled = block_on(enrol(
        &device,
        kds,
        &validator(date),
        HOME_KDS,
        tel_uri,
        Some(b"identity proof".to_vec()),
        CIPHERSUITE,
        signer(ALICE_KEY, ALICE_PUBLIC_KEY),
        3,
    ));
    (device, enrolled)
}

/// Whether the ParticipantInformation of `enrolment`, made since `before`,
/// is the one the Participant Key of `device` signs for its Client ID, the
/// Vendor ID of the Home KDS, Alice's key and `tel_uri`
fn signed_for(
    device: &MlsStore,
    enrolment: &Enrolment,
    tel_uri: &str,
    before: &SystemTime,
) -> bool {
    let identity = ClientIdentity {
        client_id: &enrolment.client_id,
        vendor_id: u64::from(HOME_KDS),
        signature_key: &bytes(ALICE_PUBLIC_KEY),
        tel_uris: &[tel_uri],
    };
    // ECDSA signatures of P-256 keys are deterministic (RFC 6979), and the
    // signature is valid from a whole second
    let since = before
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let until = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (since..=until).any(|second| {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(second);
        device.participant_information(&identity, at)
            == Ok(enrolment.participant_information.clone())
    })
}

/// Bob, as a client of his own
pub(super) fn bob() -> MlsClient {
    MlsClient::with_credential(
        credential(&[BOB, CA]),
        signer(BOB_KEY, BOB_PUBLIC_KEY),
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(validator(TODAY)),
    )
    .unwrap()
}

/// The device as the app kept it in `kept`
fn restored(kept: &[u8]) -> MlsStore {
    let device = store(&Arc::new(App::default()), validator(TODAY));
    device.restore(kept).unwrap();
    device
}

/// Whether `device` joins the group Bob adds it to with `key_package`
fn joins(device: &MlsStore, bob: &MlsClient, key_package: &[u8]) -> bool {
    let mut conversation = bob.create_conversation(None, 0).unwrap();
    let output = conversation.add_members(bob, &[key_package]).unwrap();
    conversation.merge_pending_commit(bob).unwrap();

    device
        .add_conversation(|client| {
            let joined = client.join_conversation(
                output.welcome.as_ref().unwrap(),
                output.ratchet_tree.as_ref().unwrap(),
            )?;
            Ok((joined, ()))
        })
        .is_ok()
}

#[test]
fn an_enrolled_device_is_certified_and_others_can_add_it() {
    let app = Arc::new(App::default());
    let kds = Kds::issuing(&[ALICE, CA], &app);
    let before = SystemTime::now();
    let (device, enrolled) = enrolling(&app, &kds, ALICE_TEL, TODAY);
    assert_eq!(enrolled, Ok(()));

    let enrolments = kds.enrolments.lock().unwrap().clone();
    assert_eq!(enrolments.len(), 1);
    let enrolment = &enrolments[0];
    assert_eq!(enrolment.tel_uri, ALICE_TEL);
    assert_eq!(enrolment.ciphersuite, CIPHERSUITE);
    assert_eq!(enrolment.signature_key, bytes(ALICE_PUBLIC_KEY));
    assert_eq!(enrolment.identity_proof, Some(b"identity proof".to_vec()));
    assert_eq!(
        Uuid::parse_str(&enrolment.client_id).unwrap().get_version(),
        Some(Version::Random)
    );
    assert!(signed_for(&device, enrolment, ALICE_TEL, &before));
    assert_eq!(device.credential(), Some(credential(&[ALICE, CA])));

    let uploads = kds.uploads();
    assert_eq!(uploads.len(), 1);
    let (key_packages, kept) = &uploads[0];
    assert_eq!(key_packages.len(), 4, "3, and one of last resort");
    for key_package in key_packages {
        let info = key_package_info(key_package).unwrap();
        assert_eq!(info.credential, credential(&[ALICE, CA]));
        assert_eq!(info.ciphersuite, CIPHERSUITE);
        assert_eq!(info.signature_key, bytes(ALICE_PUBLIC_KEY));
    }

    // the device as kept by the upload can join with each, the one of last
    // resort more than once
    let device = restored(kept.as_ref().expect("kept before the upload"));
    let bob = bob();
    for key_package in key_packages {
        assert!(joins(&device, &bob, key_package));
    }
    assert!(!joins(&device, &bob, &key_packages[0]), "used up");
    assert!(joins(&device, &bob, &key_packages[3]));
}

#[test]
fn a_certificate_others_would_refuse_is_not_taken_on() {
    for (certificates, tel_uri, date, refused) in [
        (&[BOB, CA], ALICE_TEL, TODAY, CertificateError::KeyMismatch),
        (&[ALICE, CA], BOB_TEL, TODAY, CertificateError::Identity),
        (&[ALICE, CA], ALICE_TEL, LATER, CertificateError::Expired),
        (
            &[ALICE, OTHER_CA],
            ALICE_TEL,
            TODAY,
            CertificateError::Untrusted,
        ),
    ] {
        let app = Arc::new(App::default());
        let kds = Kds::issuing(certificates, &app);
        let (device, enrolled) = enrolling(&app, &kds, tel_uri, date);
        assert_eq!(enrolled, Err(EnrolmentError::Certificate(refused)));
        assert_eq!(device.credential(), None);
        assert_eq!(app.kept(), 1, "the Participant Key only");
        assert_eq!(restored(&app.last().unwrap()).credential(), None);
        assert!(kds.uploads().is_empty());
    }
}

#[test]
fn a_device_the_kds_does_not_enrol_is_left_as_it_was() {
    let app = Arc::new(App::default());
    let kds = Kds::default();
    let (device, enrolled) = enrolling(&app, &kds, ALICE_TEL, TODAY);
    assert_eq!(enrolled, Err(EnrolmentError::Kds(KdsError::Unavailable)));
    assert_eq!(device.credential(), None);
    assert_eq!(app.kept(), 1, "the Participant Key only");
}

#[test]
fn key_packages_not_uploaded_are_uploaded_again() {
    let app = Arc::new(App::default());
    let kds = Kds::issuing(&[ALICE, CA], &app);
    kds.taking.store(false, Ordering::SeqCst);
    let (device, enrolled) = enrolling(&app, &kds, ALICE_TEL, TODAY);
    assert_eq!(
        enrolled,
        Err(EnrolmentError::Kds(KdsError::Refused(String::from(
            "quota"
        ))))
    );
    assert_eq!(
        device.credential(),
        Some(credential(&[ALICE, CA])),
        "enrolled"
    );

    kds.taking.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(upload_key_packages(&device, &kds, 2, false)),
        Ok(())
    );
    let uploads = kds.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0].0.len(), 2);
    let device = restored(uploads[0].1.as_ref().unwrap());
    let bob = bob();
    assert!(joins(&device, &bob, &uploads[0].0[1]));
    assert!(
        !joins(&device, &bob, &uploads[0].0[1]),
        "not of last resort"
    );
}

#[test]
fn key_packages_are_not_made_without_a_client() {
    let app = Arc::new(App::default());
    let kds = Kds::issuing(&[ALICE, CA], &app);
    let device = store(&app, validator(TODAY));
    assert_eq!(
        block_on(upload_key_packages(&device, &kds, 2, true)),
        Err(EnrolmentError::Store(StoreError::NoClient))
    );
    assert!(kds.uploads().is_empty());
}

fn recipient(tel_uri: &str) -> Recipient {
    Recipient {
        tel_uri: String::from(tel_uri),
        home_kds: String::from("kds.example.com"),
    }
}

/// What `fetch_key_packages()` makes of what `kds` returns, on `date`
fn fetching(
    kds: &Kds,
    date: &str,
    ciphersuites: &[Ciphersuite],
) -> Result<Vec<(String, Fetched)>, KdsError> {
    block_on(fetch_key_packages(
        kds,
        &validator(date),
        ciphersuites.to_vec(),
        vec![recipient(BOB_TEL), recipient(ALICE_TEL)],
    ))
}

#[test]
fn key_packages_fetched_are_those_of_the_participant_asked_for() {
    let bobs = bob().generate_key_package(false).unwrap();
    let kds = Kds::knowing(vec![
        (BOB_TEL, Fetched::KeyPackages(vec![bobs.clone()])),
        // Bob's, for Alice
        (ALICE_TEL, Fetched::KeyPackages(vec![bobs.clone()])),
        ("tel:+491700000001", Fetched::NotFound),
        ("tel:+491700000002", Fetched::Unavailable),
        ("tel:+491700000003", Fetched::KeyPackages(Vec::new())),
    ]);

    assert_eq!(
        fetching(&kds, TODAY, &[CIPHERSUITE]),
        Ok(vec![
            (
                String::from(BOB_TEL),
                Fetched::KeyPackages(vec![bobs.clone()])
            ),
            (
                String::from(ALICE_TEL),
                Fetched::Refused(CertificateError::Identity)
            ),
            (String::from("tel:+491700000001"), Fetched::NotFound),
            (String::from("tel:+491700000002"), Fetched::Unavailable),
            (String::from("tel:+491700000003"), Fetched::NotFound),
        ])
    );
    assert_eq!(
        *kds.queries.lock().unwrap(),
        vec![(
            vec![CIPHERSUITE],
            vec![recipient(BOB_TEL), recipient(ALICE_TEL)]
        )]
    );
}

#[test]
fn a_participant_is_refused_for_any_key_package_that_fails() {
    let bob = bob();
    let bobs = bob.generate_key_package(false).unwrap();
    let others = bob.generate_key_package(false).unwrap();
    let kds = Kds::knowing(vec![(
        BOB_TEL,
        Fetched::KeyPackages(vec![bobs, others, b"not a KeyPackage".to_vec()]),
    )]);
    assert_eq!(
        fetching(&kds, TODAY, &[CIPHERSUITE]),
        Ok(vec![(
            String::from(BOB_TEL),
            Fetched::Refused(CertificateError::Malformed)
        )])
    );
}

#[test]
fn key_packages_in_a_cipher_suite_not_asked_for_are_refused() {
    let bobs = bob().generate_key_package(false).unwrap();
    let kds = Kds::knowing(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]);
    assert_eq!(
        fetching(
            &kds,
            TODAY,
            &[Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]
        ),
        Ok(vec![(
            String::from(BOB_TEL),
            Fetched::Refused(CertificateError::UnsupportedAlgorithm)
        )])
    );
}

#[test]
fn key_packages_with_less_than_30_days_left_are_refused() {
    let bobs = bob().generate_key_package(false).unwrap();
    let kds = Kds::knowing(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]);
    assert_eq!(
        fetching(&kds, LATER, &[CIPHERSUITE]),
        Ok(vec![(
            String::from(BOB_TEL),
            Fetched::Refused(CertificateError::Expired)
        )])
    );
}

#[test]
fn an_unreachable_kds_is_told() {
    assert_eq!(
        fetching(&Kds::default(), TODAY, &[CIPHERSUITE]),
        Err(KdsError::Unavailable)
    );
}

#[test]
fn the_participant_key_given_to_acs_signs_at_enrolment() {
    let app = Arc::new(App::default());
    let kds = Kds::issuing(&[ALICE, CA], &app);
    let device = store(&app, validator(TODAY));
    let given = acs_parameters(&device, HOME_KDS).unwrap();
    let given = URL_SAFE_NO_PAD.decode(&given[0].1).unwrap();

    let before = SystemTime::now();
    let enrolled = block_on(enrol(
        &device,
        &kds,
        &validator(TODAY),
        HOME_KDS,
        ALICE_TEL,
        None,
        CIPHERSUITE,
        signer(ALICE_KEY, ALICE_PUBLIC_KEY),
        1,
    ));
    assert_eq!(enrolled, Ok(()));
    let enrolment = kds.enrolments.lock().unwrap()[0].clone();
    assert!(signed_for(&device, &enrolment, ALICE_TEL, &before));
    assert!(enrolment
        .participant_information
        .windows(given.len())
        .any(|w| w == given));
    assert_eq!(enrolment.identity_proof, None);

    // and still does once the device is restored
    assert_eq!(
        restored(&app.last().unwrap()).participant_public_key(),
        Ok(given)
    );
}
