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

//! What E2EE adds to the provisioning of the client by ACS (RCC.16 section
//! 4.1): the Participant Key and the Home KDS go in the configuration request,
//! the ACS Signed Encryption Identity Proof comes back in the configuration
//! document, for the enrolment with the Home KDS

use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use rust_rcs_core::mls::rcs::{ACS_PARAMETER_HOME_KDS, ACS_PARAMETER_PARTICIPANT_PUBLIC_KEY};

use crate::provisioning::rcs_application::Messaging;

use super::store::{MlsStore, StoreError};

/// Base64, padded or not
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The parameters by which ACS is to sign the encryption identity of the
/// device: the Participant Key, made if there is none yet, and the Vendor ID
/// of the Home KDS (RCC.07 section 2.3.2.2)
pub fn acs_parameters(
    store: &MlsStore,
    home_kds: u32,
) -> Result<Vec<(String, String)>, StoreError> {
    let participant_public_key = store.participant_public_key()?;
    Ok(vec![
        (
            String::from(ACS_PARAMETER_PARTICIPANT_PUBLIC_KEY),
            URL_SAFE_NO_PAD.encode(participant_public_key),
        ),
        (String::from(ACS_PARAMETER_HOME_KDS), home_kds.to_string()),
    ])
}

/// The ACS Signed Encryption Identity Proof of the configuration, if ACS gave
/// one (RCC.07 section A.2.4)
pub fn identity_proof(messaging: &Messaging) -> Option<Vec<u8>> {
    let proof: String = messaging
        .get_signed_encryption_identity_proof()?
        .split_ascii_whitespace()
        .collect();
    BASE64.decode(proof).ok().filter(|proof| !proof.is_empty())
}
