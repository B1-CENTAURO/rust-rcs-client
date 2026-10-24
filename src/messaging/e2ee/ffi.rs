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

//! The Home KDS and the keeping of the MLS state, as the app does them
//!
//! The interface to the Home KDS is vendor specific (RCC.16 sections 5.1,
//! 5.3): the app is asked to enrol, upload or fetch, and answers each request
//! with one of the rcs_kds_request_*() functions, at once or later, from any
//! thread.

use std::ffi::{CStr, CString};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};

use futures::channel::oneshot;
use libc::c_char;
use rust_rcs_core::mls::Ciphersuite;

use crate::messaging::ffi::{MessageResultCallbackContext, MessageResultCallbackContextWrapper};

use super::device::{DeviceError, Enrolled};
use super::kds::{
    Enrolment, EnrolmentError, Fetched, KdsError, KdsFuture, KeyDistribution, Recipient,
};
use super::store::SaveState;

/// Asks the app to enrol the device (RCC.16 sections 4.2, 5.1): the tel URI
/// and Cipher Suite, the MLS signature key, the Client ID and the DER encoded
/// ParticipantInformation for the Client Certificate, and the ACS Signed
/// Encryption Identity Proof, NULL if there is none; answered with
/// rcs_kds_request_enrolled() or rcs_kds_request_failed()
pub type KdsEnrolFunction = extern "C" fn(
    tel_uri: *const c_char,
    ciphersuite: u16,
    signature_key: *const u8,
    signature_key_len: usize,
    client_id: *const c_char,
    participant_information: *const u8,
    participant_information_len: usize,
    identity_proof: *const u8,
    identity_proof_len: usize,
    request: *mut KdsRequest,
    context: *mut MessageResultCallbackContext,
);

/// Asks the app to upload KeyPackages of the device (RCC.16 section 5.1);
/// answered with rcs_kds_request_uploaded() or rcs_kds_request_failed()
pub type KdsUploadFunction = extern "C" fn(
    key_packages: *const *const u8,
    key_package_lens: *const usize,
    count: usize,
    request: *mut KdsRequest,
    context: *mut MessageResultCallbackContext,
);

/// Asks the app for the KeyPackages of Participants, by tel URI and Home KDS
/// capability value, in the first of the Cipher Suites all of them have
/// (RCC.16 section 5.3); answered with rcs_kds_request_add_key_packages()
/// for each Participant, then rcs_kds_request_fetched(), or with
/// rcs_kds_request_failed()
pub type KdsFetchFunction = extern "C" fn(
    ciphersuites: *const u16,
    ciphersuite_count: usize,
    tel_uris: *const *const c_char,
    home_kds: *const *const c_char,
    recipient_count: usize,
    request: *mut KdsRequest,
    context: *mut MessageResultCallbackContext,
);

/// Has the app keep the MLS state of the device, encrypted, in place of the
/// one kept before; not 0 if it did. It must not call into the client.
pub type SaveStateFunction = extern "C" fn(
    state: *const u8,
    state_len: usize,
    context: *mut MessageResultCallbackContext,
) -> i32;

/// Told how enrolling the device went, as rcs_client_e2ee_enrol() says
pub type E2eeEnrolResultCallback =
    extern "C" fn(status: i32, context: *mut MessageResultCallbackContext);

/// The status rcs_client_e2ee_enrol() tells of `enrolled`
pub fn enrolment_status(enrolled: &Result<Enrolled, DeviceError>) -> i32 {
    match enrolled {
        Ok(Enrolled::Now) => 0,
        Ok(Enrolled::Already) => 1,
        Err(DeviceError::NotProvisioned) => -1,
        Err(DeviceError::Enrolment(EnrolmentError::Kds(KdsError::Unavailable))) => -2,
        Err(DeviceError::Enrolment(EnrolmentError::Kds(KdsError::Refused(_)))) => -3,
        Err(DeviceError::Enrolment(EnrolmentError::Certificate(_))) => -4,
        Err(DeviceError::Enrolment(EnrolmentError::Store(_))) => -5,
    }
}

/// A request to the app, to be answered once
pub struct KdsRequest(Pending);

#[cfg(test)]
impl KdsRequest {
    pub fn enrolment_for_tests(
        tx: oneshot::Sender<Result<Vec<Vec<u8>>, KdsError>>,
    ) -> *mut KdsRequest {
        Box::into_raw(Box::new(KdsRequest(Pending::Enrolment(tx))))
    }

    pub fn upload_for_tests(tx: oneshot::Sender<Result<(), KdsError>>) -> *mut KdsRequest {
        Box::into_raw(Box::new(KdsRequest(Pending::Upload(tx))))
    }
}

enum Pending {
    Enrolment(oneshot::Sender<Result<Vec<Vec<u8>>, KdsError>>),
    Upload(oneshot::Sender<Result<(), KdsError>>),
    Fetch(
        oneshot::Sender<Result<Vec<(String, Fetched)>, KdsError>>,
        Vec<(String, Fetched)>,
    ),
}

impl Pending {
    fn fail(self, error: KdsError) {
        let _ = match self {
            Pending::Enrolment(tx) => tx.send(Err(error)).map_err(|_| ()),
            Pending::Upload(tx) => tx.send(Err(error)).map_err(|_| ()),
            Pending::Fetch(tx, _) => tx.send(Err(error)).map_err(|_| ()),
        };
    }
}

/// The Home KDS as the app gives it
pub struct AppKds {
    enrol: KdsEnrolFunction,
    upload: KdsUploadFunction,
    fetch: KdsFetchFunction,
    context: Option<Arc<Mutex<MessageResultCallbackContextWrapper>>>,
}

impl AppKds {
    pub fn new(
        enrol: KdsEnrolFunction,
        upload: KdsUploadFunction,
        fetch: KdsFetchFunction,
        context: Option<Arc<Mutex<MessageResultCallbackContextWrapper>>>,
    ) -> AppKds {
        AppKds {
            enrol,
            upload,
            fetch,
            context,
        }
    }

    fn context(&self) -> *mut MessageResultCallbackContext {
        context_ptr(&self.context)
    }
}

fn context_ptr(
    context: &Option<Arc<Mutex<MessageResultCallbackContextWrapper>>>,
) -> *mut MessageResultCallbackContext {
    context.as_ref().map_or(ptr::null_mut(), |context| {
        context.lock().unwrap().0.as_ptr()
    })
}

impl KeyDistribution for AppKds {
    fn enrol(&self, enrolment: Enrolment) -> KdsFuture<Vec<Vec<u8>>> {
        let (tx, rx) = oneshot::channel();
        let request = Box::into_raw(Box::new(KdsRequest(Pending::Enrolment(tx))));
        let tel_uri = c_string(&enrolment.tel_uri);
        let client_id = c_string(&enrolment.client_id);
        let (identity_proof, identity_proof_len) = enrolment
            .identity_proof
            .as_ref()
            .map_or((ptr::null(), 0), |proof| (proof.as_ptr(), proof.len()));
        (self.enrol)(
            tel_uri.as_ptr(),
            u16::from(enrolment.ciphersuite),
            enrolment.signature_key.as_ptr(),
            enrolment.signature_key.len(),
            client_id.as_ptr(),
            enrolment.participant_information.as_ptr(),
            enrolment.participant_information.len(),
            identity_proof,
            identity_proof_len,
            request,
            self.context(),
        );
        Box::pin(async move { rx.await.unwrap_or(Err(KdsError::Unavailable)) })
    }

    fn upload(&self, key_packages: Vec<Vec<u8>>) -> KdsFuture<()> {
        let (tx, rx) = oneshot::channel();
        let request = Box::into_raw(Box::new(KdsRequest(Pending::Upload(tx))));
        let pointers: Vec<*const u8> = key_packages.iter().map(|kp| kp.as_ptr()).collect();
        let lens: Vec<usize> = key_packages.iter().map(Vec::len).collect();
        (self.upload)(
            pointers.as_ptr(),
            lens.as_ptr(),
            key_packages.len(),
            request,
            self.context(),
        );
        Box::pin(async move { rx.await.unwrap_or(Err(KdsError::Unavailable)) })
    }

    fn fetch(
        &self,
        ciphersuites: Vec<Ciphersuite>,
        recipients: Vec<Recipient>,
    ) -> KdsFuture<Vec<(String, Fetched)>> {
        let (tx, rx) = oneshot::channel();
        let request = Box::into_raw(Box::new(KdsRequest(Pending::Fetch(tx, Vec::new()))));
        let ciphersuites: Vec<u16> = ciphersuites.into_iter().map(u16::from).collect();
        let tel_uris: Vec<CString> = recipients.iter().map(|r| c_string(&r.tel_uri)).collect();
        let home_kds: Vec<CString> = recipients.iter().map(|r| c_string(&r.home_kds)).collect();
        let tel_uri_pointers: Vec<*const c_char> = tel_uris.iter().map(|s| s.as_ptr()).collect();
        let home_kds_pointers: Vec<*const c_char> = home_kds.iter().map(|s| s.as_ptr()).collect();
        (self.fetch)(
            ciphersuites.as_ptr(),
            ciphersuites.len(),
            tel_uri_pointers.as_ptr(),
            home_kds_pointers.as_ptr(),
            recipients.len(),
            request,
            self.context(),
        );
        Box::pin(async move { rx.await.unwrap_or(Err(KdsError::Unavailable)) })
    }
}

/// Keeps the MLS state with the app's `save`
pub fn app_save_state(
    save: SaveStateFunction,
    context: Option<Arc<Mutex<MessageResultCallbackContextWrapper>>>,
) -> SaveState {
    Box::new(move |state| save(state.as_ptr(), state.len(), context_ptr(&context)) != 0)
}

/// Answers an enrolment with the certificate chain the Home KDS issued,
/// Client Certificate first
#[no_mangle]
pub unsafe extern "C" fn rcs_kds_request_enrolled(
    request: *mut KdsRequest,
    certificates: *const *const u8,
    certificate_lens: *const usize,
    count: usize,
) {
    let Some(request) = take(request) else {
        return;
    };
    match (
        request.0,
        byte_arrays(certificates, certificate_lens, count),
    ) {
        (Pending::Enrolment(tx), Some(chain)) => {
            let _ = tx.send(Ok(chain));
        }
        (pending, _) => pending.fail(KdsError::Unavailable),
    }
}

/// Answers an upload as done
#[no_mangle]
pub unsafe extern "C" fn rcs_kds_request_uploaded(request: *mut KdsRequest) {
    let Some(request) = take(request) else {
        return;
    };
    match request.0 {
        Pending::Upload(tx) => {
            let _ = tx.send(Ok(()));
        }
        pending => pending.fail(KdsError::Unavailable),
    }
}

/// Adds to the answer of a fetch what the Home KDS has for the Participant at
/// `tel_uri`: its KeyPackages (status 0), or that it was not found (1), its
/// number was malformed (2), it has no Cipher Suite in common (3), or it is
/// unavailable (4)
#[no_mangle]
pub unsafe extern "C" fn rcs_kds_request_add_key_packages(
    request: *mut KdsRequest,
    tel_uri: *const c_char,
    status: i32,
    key_packages: *const *const u8,
    key_package_lens: *const usize,
    count: usize,
) {
    let (Some(request), false) = (request.as_mut(), tel_uri.is_null()) else {
        return;
    };
    if let Pending::Fetch(_, fetched) = &mut request.0 {
        let tel_uri = CStr::from_ptr(tel_uri).to_string_lossy().into_owned();
        let found = match status {
            0 => byte_arrays(key_packages, key_package_lens, count).map(Fetched::KeyPackages),
            1 => Some(Fetched::NotFound),
            2 => Some(Fetched::MalformedId),
            3 => Some(Fetched::UnsupportedCipherSuite),
            _ => None,
        };
        fetched.push((tel_uri, found.unwrap_or(Fetched::Unavailable)));
    }
}

/// Answers a fetch with what was added to it
#[no_mangle]
pub unsafe extern "C" fn rcs_kds_request_fetched(request: *mut KdsRequest) {
    let Some(request) = take(request) else {
        return;
    };
    match request.0 {
        Pending::Fetch(tx, fetched) => {
            let _ = tx.send(Ok(fetched));
        }
        pending => pending.fail(KdsError::Unavailable),
    }
}

/// Answers a request as failed: the Home KDS could not be reached (refused
/// 0), or refused it for `reason`, which may be NULL
#[no_mangle]
pub unsafe extern "C" fn rcs_kds_request_failed(
    request: *mut KdsRequest,
    refused: i32,
    reason: *const c_char,
) {
    let Some(request) = take(request) else {
        return;
    };
    request.0.fail(if refused == 0 {
        KdsError::Unavailable
    } else if reason.is_null() {
        KdsError::Refused(String::new())
    } else {
        KdsError::Refused(CStr::from_ptr(reason).to_string_lossy().into_owned())
    });
}

unsafe fn take(request: *mut KdsRequest) -> Option<Box<KdsRequest>> {
    (!request.is_null()).then(|| Box::from_raw(request))
}

/// `count` byte arrays given by pointers and lengths, unless one is NULL
pub unsafe fn byte_arrays(
    pointers: *const *const u8,
    lens: *const usize,
    count: usize,
) -> Option<Vec<Vec<u8>>> {
    if count == 0 {
        return Some(Vec::new());
    }
    if pointers.is_null() || lens.is_null() {
        return None;
    }
    slice::from_raw_parts(pointers, count)
        .iter()
        .zip(slice::from_raw_parts(lens, count))
        .map(|(pointer, len)| match (pointer.is_null(), *len) {
            (_, 0) => Some(Vec::new()),
            (true, _) => None,
            (false, len) => Some(slice::from_raw_parts(*pointer, len).to_vec()),
        })
        .collect()
}

fn c_string(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}
