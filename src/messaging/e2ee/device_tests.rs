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

use std::sync::Arc;

use futures::executor::block_on;
use rust_rcs_core::mls::rcs::certificate::CertificateError;
use rust_rcs_core::mls::ErrorKind;

use crate::provisioning::characteristic::Characteristic;
use crate::provisioning::ims_application::ImsApplication;
use crate::provisioning::rcs_application::RcsApplication;

use super::device::{participant_tel_uri, DeviceError, E2eeDevice, Enrolled, CIPHERSUITE};
use super::kds::{EnrolmentError, KeyDistribution};
use super::kds_tests::certificates::*;
use super::kds_tests::{
    credential, signer, validator, App, Kds, ALICE_TEL, HOME_KDS, LATER, TODAY,
};
use super::store::StoreError;

/// An IMS configuration with the public user identities `identities`
pub(super) fn ims_config(identities: &[&str]) -> String {
    let nodes: String = identities
        .iter()
        .map(|identity| {
            format!(
                r#"<characteristic type="NODE"><parm name="Public_User_Identity" value="{}"/></characteristic>"#,
                identity
            )
        })
        .collect();
    format!(
        r#"<characteristic type="APPLICATION"><parm name="AppID" value="ap2001"/><characteristic type="Public_User_Identity_List">{}</characteristic></characteristic>"#,
        nodes
    )
}

/// An RCS configuration with `proof` as the ACS Signed Encryption Identity
/// Proof, if there is one
pub(super) fn rcs_config(proof: Option<&str>) -> String {
    let proof = proof
        .map(|proof| {
            format!(
                r#"<parm name="signedEncryptionIdentityProof" value="{}"/>"#,
                proof
            )
        })
        .unwrap_or_default();
    format!(
        r#"<characteristic type="APPLICATION"><parm name="AppID" value="ap2002"/><characteristic type="MESSAGING">{}</characteristic></characteristic>"#,
        proof
    )
}

fn provision(device: &E2eeDevice, identities: &[&str], proof: Option<&str>) {
    let ims = ims_config(identities).parse::<Characteristic>().unwrap();
    let rcs = rcs_config(proof).parse::<Characteristic>().unwrap();
    device.provisioned(&ImsApplication::new(&ims), &RcsApplication::new(&rcs), None);
}

/// Alice's device, kept by `app`, on `date`, from `saved` if given
fn alice(app: &Arc<App>, kds: &Arc<Kds>, date: &str, saved: Option<&[u8]>) -> E2eeDevice {
    let keeping = Arc::clone(app);
    E2eeDevice::new(
        validator(date),
        HOME_KDS,
        Arc::clone(kds) as Arc<dyn KeyDistribution>,
        Box::new(move |state| {
            keeping.kept.lock().unwrap().push(state.to_vec());
            true
        }),
        saved,
    )
    .unwrap()
    .with_signer(|| Some(signer(ALICE_KEY, ALICE_PUBLIC_KEY)))
}

#[test]
fn the_participant_is_known_by_a_tel_uri_of_the_user() {
    let tel_uri =
        |identities: &[&str], msisdn| participant_tel_uri(identities.iter().copied(), msisdn);

    assert_eq!(
        tel_uri(
            &["sip:+491701234567@ims.example.com", "tel:+491701234560"],
            None
        ),
        Some(String::from("tel:+491701234560")),
        "a tel URI first"
    );
    assert_eq!(
        tel_uri(
            &["sip:+491701234567@ims.example.com;user=phone"],
            Some("+491709999999")
        ),
        Some(String::from("tel:+491701234567")),
        "then the number of a SIP URI"
    );
    assert_eq!(
        tel_uri(
            &[
                "sip:alice@example.com",
                "sip:+@example.com",
                "sip:+49x@example.com"
            ],
            Some("+491709999999")
        ),
        Some(String::from("tel:+491709999999")),
        "then the MSISDN"
    );
    assert_eq!(tel_uri(&["sip:alice@example.com"], None), None);
    assert_eq!(tel_uri(&[], Some("")), None);
}

#[test]
fn a_device_enrols_once_provisioned_and_only_once() {
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let device = alice(&app, &kds, TODAY, None);

    assert_eq!(block_on(device.enrol()), Err(DeviceError::NotProvisioned));
    assert!(kds.enrolments.lock().unwrap().is_empty());

    provision(
        &device,
        &["sip:+491701234567@ims.example.com"],
        Some("AAAAAA=="),
    );
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    let enrolment = kds.enrolments.lock().unwrap()[0].clone();
    assert_eq!(enrolment.tel_uri, ALICE_TEL);
    assert_eq!(enrolment.ciphersuite, CIPHERSUITE);
    assert_eq!(enrolment.identity_proof, Some(vec![0; 4]));
    assert_eq!(device.store().credential(), Some(credential(&[ALICE, CA])));
    assert_eq!(kds.uploads()[0].0.len(), 11, "10, and one of last resort");

    // with a certificate others would still add it with
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Already));
    assert_eq!(kds.enrolments.lock().unwrap().len(), 1);
    assert_eq!(kds.uploads().len(), 1);
}

#[test]
fn a_device_restored_enrols_again_only_when_its_certificate_would_not_do() {
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let device = alice(&app, &kds, TODAY, None);
    provision(&device, &["tel:+491701234567"], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    let saved = app.last().unwrap();

    let again = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let restored = alice(&app, &again, TODAY, Some(&saved));
    provision(&restored, &["tel:+491701234567"], None);
    assert_eq!(block_on(restored.enrol()), Ok(Enrolled::Already));
    assert!(again.enrolments.lock().unwrap().is_empty());

    // for another number
    provision(&restored, &["tel:+491707654321"], None);
    assert_eq!(
        block_on(restored.enrol()),
        Err(DeviceError::Enrolment(EnrolmentError::Certificate(
            CertificateError::Identity
        )))
    );
    assert_eq!(again.enrolments.lock().unwrap().len(), 1);

    // with less than 30 days left
    let later = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let restored = alice(&app, &later, LATER, Some(&saved));
    provision(&restored, &["tel:+491701234567"], None);
    assert_eq!(
        block_on(restored.enrol()),
        Err(DeviceError::Enrolment(EnrolmentError::Certificate(
            CertificateError::Expired
        )))
    );
    assert_eq!(later.enrolments.lock().unwrap().len(), 1);
}

#[test]
fn a_device_gives_acs_its_participant_key_and_home_kds() {
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let device = alice(&app, &kds, TODAY, None);
    let parameters = device.acs_parameters().unwrap();
    assert_eq!(parameters[0].0, "participant_public_key");
    assert_eq!(
        parameters[1],
        (String::from("home_kds"), String::from("42"))
    );

    // kept with the state
    let restored = alice(&app, &kds, TODAY, Some(&app.last().unwrap()));
    assert_eq!(restored.acs_parameters(), Ok(parameters));
}

#[test]
fn a_saved_state_that_is_not_one_is_refused() {
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let device = E2eeDevice::new(
        validator(TODAY),
        HOME_KDS,
        kds,
        Box::new(|_| true),
        Some(b"not a state"),
    );
    assert_eq!(device.err(), Some(StoreError::Mls(ErrorKind::BadFormat)));
}
