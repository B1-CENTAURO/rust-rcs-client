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

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rust_rcs_core::mls::{Credential, CredentialValidator, MlsConfig};

use crate::provisioning::characteristic::Characteristic;
use crate::provisioning::rcs_application::RcsApplication;

use super::provisioning::{acs_parameters, identity_proof};
use super::store::MlsStore;

struct AllowAll;

impl CredentialValidator for AllowAll {
    fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
        true
    }
}

fn store(kept: &Arc<Mutex<usize>>) -> MlsStore {
    let kept = Arc::clone(kept);
    MlsStore::new(
        MlsConfig::default(),
        Arc::new(AllowAll),
        Box::new(move |_| {
            *kept.lock().unwrap() += 1;
            true
        }),
    )
}

#[test]
fn acs_is_given_the_participant_key_and_the_home_kds() {
    let kept = Arc::new(Mutex::new(0));
    let device = store(&kept);
    let parameters = acs_parameters(&device, 42).unwrap();
    assert_eq!(*kept.lock().unwrap(), 1, "the Participant Key made");

    let names: Vec<&str> = parameters.iter().map(|(name, _)| &name[..]).collect();
    assert_eq!(names, ["participant_public_key", "home_kds"]);
    let participant_public_key = &parameters[0].1;
    assert!(participant_public_key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    assert_eq!(
        URL_SAFE_NO_PAD.decode(participant_public_key).unwrap(),
        device.participant_public_key().unwrap()
    );
    assert_eq!(parameters[1].1, "42");

    // the same each time
    assert_eq!(acs_parameters(&device, 42), Ok(parameters));
    assert_eq!(*kept.lock().unwrap(), 1);
}

/// The identity proof of a configuration document whose Messaging has
/// `parameters`
fn proof_in(parameters: &str) -> Option<Vec<u8>> {
    let document = format!(
        r#"<characteristic type="APPLICATION">
             <parm name="AppID" value="ap2002"/>
             <characteristic type="MESSAGING">
               <parm name="max1ToManyRecipients" value="20"/>
               {}
             </characteristic>
           </characteristic>"#,
        parameters
    );
    let application = document.parse::<Characteristic>().unwrap();
    let application = RcsApplication::new(&application);
    identity_proof(&application.get_messaging_config().unwrap())
}

#[test]
fn the_identity_proof_is_read_from_the_configuration() {
    let proof = b"\x00\x00\x00\x00\x6a\x5c\x0b\x80 signature".to_vec();
    assert_eq!(
        proof_in(
            r#"<parm name="signedEncryptionIdentityProof" value="AAAAAGpcC4Agc2lnbmF0dXJl"/>"#
        ),
        Some(proof.clone())
    );
    // padded, or folded over lines
    assert_eq!(
        proof_in(r#"<parm name="signedEncryptionIdentityProof" value="AAAAAA=="/>"#),
        Some(vec![0; 4])
    );
    assert_eq!(
        proof_in(r#"<parm name="signedEncryptionIdentityProof" value="AAAAAA"/>"#),
        Some(vec![0; 4])
    );
    assert_eq!(
        proof_in(
            "<parm name=\"signedEncryptionIdentityProof\" value=\"AAAAAGpc\n  C4Agc2lnbmF0dXJl\"/>"
        ),
        Some(proof)
    );

    assert_eq!(proof_in(""), None);
    assert_eq!(
        proof_in(r#"<parm name="signedEncryptionIdentityProof" value=""/>"#),
        None
    );
    assert_eq!(
        proof_in(r#"<parm name="signedEncryptionIdentityProof" value="not base64!"/>"#),
        None
    );
}
