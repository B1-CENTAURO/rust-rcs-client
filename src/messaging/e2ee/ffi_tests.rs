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

use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use futures::executor::block_on;
use libc::c_char;
use rust_rcs_core::mls::rcs::certificate::CertificateError;
use rust_rcs_core::mls::{Ciphersuite, ErrorKind};
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::capability::FEATURE_TAGS;
use crate::messaging::ffi::{MessageResultCallbackContext, MessageResultCallbackContextWrapper};
use crate::{
    destroy_rcs_client, new_rcs_client, rcs_client_e2ee_enrol, rcs_client_query_capabilities,
    rcs_client_set_e2ee, rcs_client_setup, RcsRuntime,
};

use super::device::{DeviceError, Enrolled};
use super::device_tests::{alice, provision};
use super::device_tests::{ims_config, rcs_config};
use super::ffi::{
    app_save_state, enrolment_status, rcs_kds_request_add_key_packages, rcs_kds_request_enrolled,
    rcs_kds_request_failed, rcs_kds_request_fetched, rcs_kds_request_uploaded, AppKds, KdsRequest,
};
use super::kds::{Enrolment, EnrolmentError, Fetched, KdsError, KeyDistribution, Recipient};
use super::kds_tests::certificates::*;
use super::kds_tests::{bytes, App as Keeping, Kds, ALICE_TEL, TODAY};
use super::store::StoreError;

/// How the app answers
#[derive(Clone, Copy, Default, PartialEq)]
enum Answer {
    /// As asked
    #[default]
    AsAsked,
    /// From another thread, a little later
    Later,
    /// As unreachable
    Unreachable,
    /// As the wrong kind of answer
    Wrongly,
}

/// The app, whose address is the context of its functions
#[derive(Default)]
struct App {
    answer: Mutex<Answer>,
    enrolments: Mutex<Vec<(String, u16, Vec<u8>, String, Vec<u8>, Option<Vec<u8>>)>>,
    uploads: Mutex<Vec<Vec<Vec<u8>>>>,
    fetches: Mutex<Vec<(Vec<u16>, Vec<(String, String)>)>>,
    kept: Mutex<Vec<Vec<u8>>>,
    refusing: AtomicBool,
    statuses: Mutex<Vec<i32>>,
    capabilities: Mutex<Vec<(u16, String)>>,
}

impl App {
    fn context(&self) -> *mut MessageResultCallbackContext {
        self as *const App as *mut MessageResultCallbackContext
    }

    fn wrapped(&self) -> Option<Arc<Mutex<MessageResultCallbackContextWrapper>>> {
        NonNull::new(self.context())
            .map(|context| Arc::new(Mutex::new(MessageResultCallbackContextWrapper(context))))
    }

    fn kds(&self) -> AppKds {
        AppKds::new(enrol, upload, fetch, self.wrapped())
    }

    fn answering(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }

    /// The statuses told, once `count` were
    fn statuses(&self, count: usize) -> Vec<i32> {
        let start = Instant::now();
        while self.statuses.lock().unwrap().len() < count && start.elapsed().as_secs() < 10 {
            thread::sleep(Duration::from_millis(10));
        }
        self.statuses.lock().unwrap().clone()
    }
}

unsafe fn app<'a>(context: *mut MessageResultCallbackContext) -> &'a App {
    &*(context as *const App)
}

unsafe fn bytes_of(pointer: *const u8, len: usize) -> Vec<u8> {
    if pointer.is_null() {
        Vec::new()
    } else {
        slice::from_raw_parts(pointer, len).to_vec()
    }
}

/// Requests, to be answered from another thread
struct Sent(*mut KdsRequest);
unsafe impl Send for Sent {}

/// Answers `request` with `answer`, or the wrong kind of answer
fn answer(
    app: &App,
    request: *mut KdsRequest,
    answer: impl FnOnce(*mut KdsRequest) + Send + 'static,
) {
    match *app.answer.lock().unwrap() {
        Answer::AsAsked => answer(request),
        Answer::Later => {
            let request = Sent(request);
            thread::spawn(move || {
                let request = request;
                thread::sleep(Duration::from_millis(50));
                answer(request.0);
            });
        }
        Answer::Unreachable => unsafe { rcs_kds_request_failed(request, 0, ptr::null()) },
        Answer::Wrongly => unsafe { rcs_kds_request_fetched(request) },
    }
}

extern "C" fn enrol(
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
) {
    let app = unsafe { app(context) };
    unsafe {
        app.enrolments.lock().unwrap().push((
            CStr::from_ptr(tel_uri).to_string_lossy().into_owned(),
            ciphersuite,
            bytes_of(signature_key, signature_key_len),
            CStr::from_ptr(client_id).to_string_lossy().into_owned(),
            bytes_of(participant_information, participant_information_len),
            (!identity_proof.is_null()).then(|| bytes_of(identity_proof, identity_proof_len)),
        ));
    }
    answer(app, request, |request| {
        let chain = [bytes(ALICE), bytes(CA)];
        let pointers = [chain[0].as_ptr(), chain[1].as_ptr()];
        let lens = [chain[0].len(), chain[1].len()];
        unsafe { rcs_kds_request_enrolled(request, pointers.as_ptr(), lens.as_ptr(), 2) };
    });
}

extern "C" fn upload(
    key_packages: *const *const u8,
    key_package_lens: *const usize,
    count: usize,
    request: *mut KdsRequest,
    context: *mut MessageResultCallbackContext,
) {
    let app = unsafe { app(context) };
    let uploaded = unsafe {
        slice::from_raw_parts(key_packages, count)
            .iter()
            .zip(slice::from_raw_parts(key_package_lens, count))
            .map(|(pointer, len)| bytes_of(*pointer, *len))
            .collect()
    };
    app.uploads.lock().unwrap().push(uploaded);
    answer(app, request, |request| unsafe {
        rcs_kds_request_uploaded(request)
    });
}

extern "C" fn fetch(
    ciphersuites: *const u16,
    ciphersuite_count: usize,
    tel_uris: *const *const c_char,
    home_kds: *const *const c_char,
    recipient_count: usize,
    request: *mut KdsRequest,
    context: *mut MessageResultCallbackContext,
) {
    let app = unsafe { app(context) };
    unsafe {
        let recipients = slice::from_raw_parts(tel_uris, recipient_count)
            .iter()
            .zip(slice::from_raw_parts(home_kds, recipient_count))
            .map(|(tel_uri, home_kds)| {
                (
                    CStr::from_ptr(*tel_uri).to_string_lossy().into_owned(),
                    CStr::from_ptr(*home_kds).to_string_lossy().into_owned(),
                )
            })
            .collect();
        app.fetches.lock().unwrap().push((
            slice::from_raw_parts(ciphersuites, ciphersuite_count).to_vec(),
            recipients,
        ));
    }
    answer(app, request, |request| {
        let add = |tel_uri: &str, status, key_packages: &[&[u8]]| {
            let tel_uri = CString::new(tel_uri).unwrap();
            let pointers: Vec<*const u8> = key_packages.iter().map(|kp| kp.as_ptr()).collect();
            let lens: Vec<usize> = key_packages.iter().map(|kp| kp.len()).collect();
            unsafe {
                rcs_kds_request_add_key_packages(
                    request,
                    tel_uri.as_ptr(),
                    status,
                    pointers.as_ptr(),
                    lens.as_ptr(),
                    key_packages.len(),
                )
            };
        };
        add("tel:+491707654321", 0, &[b"one", b"two"]);
        add("tel:+491700000001", 1, &[]);
        add("tel:+491700000002", 2, &[]);
        add("tel:+491700000003", 3, &[]);
        add("tel:+491700000004", 4, &[]);
        add("tel:+491700000005", 9, &[]);
        unsafe { rcs_kds_request_fetched(request) };
    });
}

extern "C" fn save(
    state: *const u8,
    state_len: usize,
    context: *mut MessageResultCallbackContext,
) -> i32 {
    let app = unsafe { app(context) };
    if app.refusing.load(Ordering::SeqCst) {
        return 0;
    }
    app.kept
        .lock()
        .unwrap()
        .push(unsafe { bytes_of(state, state_len) });
    1
}

extern "C" fn capable(
    status_code: u16,
    feature_tags: *const c_char,
    context: *mut MessageResultCallbackContext,
) {
    let feature_tags = unsafe { CStr::from_ptr(feature_tags) }
        .to_string_lossy()
        .into_owned();
    unsafe { app(context) }
        .capabilities
        .lock()
        .unwrap()
        .push((status_code, feature_tags));
}

extern "C" fn told(status: i32, context: *mut MessageResultCallbackContext) {
    unsafe { app(context) }
        .statuses
        .lock()
        .unwrap()
        .push(status);
}

fn enrolment(identity_proof: Option<Vec<u8>>) -> Enrolment {
    Enrolment {
        tel_uri: String::from(ALICE_TEL),
        ciphersuite: Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        signature_key: bytes(ALICE_PUBLIC_KEY),
        client_id: String::from("3f0a6a4e-2d6c-4b8e-9b38-2b1f0d6f2c11"),
        participant_information: vec![0x30, 0x00],
        identity_proof,
    }
}

#[test]
fn an_enrolment_is_asked_of_the_app_and_answered() {
    let app = App::default();
    let kds = app.kds();
    assert_eq!(
        block_on(kds.enrol(enrolment(Some(b"proof".to_vec())))),
        Ok(vec![bytes(ALICE), bytes(CA)])
    );
    assert_eq!(
        block_on(kds.enrol(enrolment(None))).map(|chain| chain.len()),
        Ok(2)
    );

    let enrolments = app.enrolments.lock().unwrap();
    assert_eq!(
        enrolments[0],
        (
            String::from(ALICE_TEL),
            2,
            bytes(ALICE_PUBLIC_KEY),
            String::from("3f0a6a4e-2d6c-4b8e-9b38-2b1f0d6f2c11"),
            vec![0x30, 0x00],
            Some(b"proof".to_vec()),
        )
    );
    assert_eq!(enrolments[1].5, None, "no proof");
}

#[test]
fn an_upload_gives_the_app_every_key_package() {
    let app = App::default();
    let key_packages = vec![vec![1; 3], Vec::new(), vec![2; 300]];
    assert_eq!(block_on(app.kds().upload(key_packages.clone())), Ok(()));
    assert_eq!(*app.uploads.lock().unwrap(), vec![key_packages]);
}

#[test]
fn a_fetch_is_answered_participant_by_participant() {
    let app = App::default();
    let recipient = |tel_uri: &str| Recipient {
        tel_uri: String::from(tel_uri),
        home_kds: String::from("42"),
    };
    let fetched = block_on(app.kds().fetch(
        vec![
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        ],
        vec![
            recipient("tel:+491707654321"),
            recipient("tel:+491700000001"),
        ],
    ));
    assert_eq!(
        fetched,
        Ok(vec![
            (
                String::from("tel:+491707654321"),
                Fetched::KeyPackages(vec![b"one".to_vec(), b"two".to_vec()])
            ),
            (String::from("tel:+491700000001"), Fetched::NotFound),
            (String::from("tel:+491700000002"), Fetched::MalformedId),
            (
                String::from("tel:+491700000003"),
                Fetched::UnsupportedCipherSuite
            ),
            (String::from("tel:+491700000004"), Fetched::Unavailable),
            (String::from("tel:+491700000005"), Fetched::Unavailable),
        ])
    );
    assert_eq!(
        *app.fetches.lock().unwrap(),
        vec![(
            vec![2, 1],
            vec![
                (String::from("tel:+491707654321"), String::from("42")),
                (String::from("tel:+491700000001"), String::from("42")),
            ]
        )]
    );
}

#[test]
fn answers_may_come_later_from_another_thread() {
    let app = App::default();
    app.answering(Answer::Later);
    let kds = app.kds();
    assert_eq!(
        block_on(kds.enrol(enrolment(None))).map(|chain| chain.len()),
        Ok(2)
    );
    assert_eq!(block_on(kds.upload(vec![vec![1]])), Ok(()));
    assert_eq!(
        block_on(kds.fetch(vec![], vec![])).map(|fetched| fetched.len()),
        Ok(6)
    );
}

#[test]
fn a_request_failed_is_told() {
    let app = App::default();
    app.answering(Answer::Unreachable);
    let kds = app.kds();
    assert_eq!(
        block_on(kds.enrol(enrolment(None))),
        Err(KdsError::Unavailable)
    );
    assert_eq!(block_on(kds.upload(vec![])), Err(KdsError::Unavailable));
    assert_eq!(
        block_on(kds.fetch(vec![], vec![])),
        Err(KdsError::Unavailable)
    );

    // refused, with a reason or none
    for (reason, told) in [(Some("quota"), "quota"), (None, "")] {
        let reason = reason.map(|reason| CString::new(reason).unwrap());
        let (tx, rx) = futures::channel::oneshot::channel();
        let request = KdsRequest::upload_for_tests(tx);
        unsafe {
            rcs_kds_request_failed(
                request,
                1,
                reason
                    .as_ref()
                    .map_or(ptr::null(), |reason| reason.as_ptr()),
            )
        };
        assert_eq!(
            block_on(rx).unwrap(),
            Err(KdsError::Refused(String::from(told)))
        );
    }
}

#[test]
fn a_request_answered_as_another_fails() {
    let app = App::default();
    app.answering(Answer::Wrongly);
    let kds = app.kds();
    assert_eq!(
        block_on(kds.enrol(enrolment(None))),
        Err(KdsError::Unavailable)
    );
    assert_eq!(block_on(kds.upload(vec![])), Err(KdsError::Unavailable));

    // KeyPackages added to what is not a fetch are not taken
    let (tx, rx) = futures::channel::oneshot::channel();
    let request = KdsRequest::upload_for_tests(tx);
    let tel_uri = CString::new(ALICE_TEL).unwrap();
    unsafe {
        rcs_kds_request_add_key_packages(request, tel_uri.as_ptr(), 1, ptr::null(), ptr::null(), 0);
        rcs_kds_request_uploaded(request);
    }
    assert_eq!(block_on(rx).unwrap(), Ok(()));
}

#[test]
fn a_certificate_chain_with_a_null_certificate_fails_the_enrolment() {
    let (tx, rx) = futures::channel::oneshot::channel();
    let request = KdsRequest::enrolment_for_tests(tx);
    let ca = bytes(CA);
    let pointers = [ptr::null(), ca.as_ptr()];
    let lens = [10, ca.len()];
    unsafe { rcs_kds_request_enrolled(request, pointers.as_ptr(), lens.as_ptr(), 2) };
    assert_eq!(block_on(rx).unwrap(), Err(KdsError::Unavailable));

    // and so does no chain at all
    let (tx, rx) = futures::channel::oneshot::channel();
    let request = KdsRequest::enrolment_for_tests(tx);
    unsafe { rcs_kds_request_enrolled(request, ptr::null(), ptr::null(), 2) };
    assert_eq!(block_on(rx).unwrap(), Err(KdsError::Unavailable));
}

#[test]
fn null_requests_are_let_be() {
    let tel_uri = CString::new(ALICE_TEL).unwrap();
    unsafe {
        rcs_kds_request_enrolled(ptr::null_mut(), ptr::null(), ptr::null(), 0);
        rcs_kds_request_uploaded(ptr::null_mut());
        rcs_kds_request_add_key_packages(
            ptr::null_mut(),
            tel_uri.as_ptr(),
            0,
            ptr::null(),
            ptr::null(),
            0,
        );
        rcs_kds_request_fetched(ptr::null_mut());
        rcs_kds_request_failed(ptr::null_mut(), 1, ptr::null());
    }
}

#[test]
fn the_state_is_kept_as_the_app_says() {
    let app = App::default();
    let keep = app_save_state(save, app.wrapped());
    assert!(keep(b"state"));
    app.refusing.store(true, Ordering::SeqCst);
    assert!(!keep(b"other"));
    assert_eq!(*app.kept.lock().unwrap(), vec![b"state".to_vec()]);
}

#[test]
fn an_enrolment_is_told_by_its_status() {
    let enrolment = |error| Err(DeviceError::Enrolment(error));
    for (enrolled, status) in [
        (Ok(Enrolled::Now), 0),
        (Ok(Enrolled::Already), 1),
        (Err(DeviceError::NotProvisioned), -1),
        (enrolment(EnrolmentError::Kds(KdsError::Unavailable)), -2),
        (
            enrolment(EnrolmentError::Kds(KdsError::Refused(String::new()))),
            -3,
        ),
        (
            enrolment(EnrolmentError::Certificate(CertificateError::Expired)),
            -4,
        ),
        (enrolment(EnrolmentError::Store(StoreError::NotSaved)), -5),
        (
            enrolment(EnrolmentError::Store(StoreError::Mls(ErrorKind::Crypto))),
            -5,
        ),
    ] {
        assert_eq!(enrolment_status(&enrolled), status, "{:?}", enrolled);
    }
}

/// A client of the library, as an app makes it
struct Client {
    runtime: Box<RcsRuntime>,
    client: *mut crate::RcsClient,
    directory: PathBuf,
}

impl Client {
    fn new() -> Client {
        let directory = std::env::temp_dir().join(format!("e2ee-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let mut runtime = Box::new(RcsRuntime {
            rt: Arc::new(Runtime::new().unwrap()),
        });
        let imsi = CString::new("262011234567890").unwrap();
        let imei = CString::new("35000000000000").unwrap();
        let root = CString::new(directory.to_str().unwrap()).unwrap();
        let client = unsafe {
            new_rcs_client(
                &mut *runtime,
                0,
                262,
                1,
                imsi.as_ptr(),
                imei.as_ptr(),
                ptr::null(),
                root.as_ptr(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            )
        }
        .unwrap();
        Client {
            runtime,
            client: Box::into_raw(client),
            directory,
        }
    }

    fn set_e2ee(&self, app: &App, roots: &[Vec<u8>], saved: Option<&[u8]>) -> i32 {
        let pointers: Vec<*const u8> = roots.iter().map(|root| root.as_ptr()).collect();
        let lens: Vec<usize> = roots.iter().map(Vec::len).collect();
        unsafe {
            rcs_client_set_e2ee(
                self.client,
                42,
                pointers.as_ptr(),
                lens.as_ptr(),
                roots.len(),
                saved.map_or(ptr::null(), |saved| saved.as_ptr()),
                saved.map_or(0, |saved| saved.len()),
                Some(save),
                Some(enrol),
                Some(upload),
                Some(fetch),
                app.context(),
            )
        }
    }

    fn acs_parameters(&self) -> Vec<(String, String)> {
        unsafe { &*self.client }.context.get_acs_parameters()
    }

    fn feature_tags(&self) -> String {
        unsafe { &*self.client }.engine.feature_tags()
    }

    fn has_e2ee(&self) -> bool {
        unsafe { &*self.client }.e2ee.is_some()
    }

    fn setup(&self, identities: &[&str], proof: Option<&str>) {
        let ims = CString::new(ims_config(identities)).unwrap();
        let rcs = CString::new(rcs_config(proof)).unwrap();
        unsafe {
            rcs_client_setup(
                &*self.runtime as *const _ as *mut _,
                self.client,
                ims.as_ptr(),
                rcs.as_ptr(),
            )
        };
    }

    fn enrol(&self, app: &App) {
        unsafe {
            rcs_client_e2ee_enrol(
                &*self.runtime as *const _ as *mut _,
                self.client,
                Some(told),
                app.context(),
            )
        };
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { destroy_rcs_client(self.client) };
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn an_app_sets_e2ee_and_enrols_once_configured() {
    let app = App::default();
    let client = Client::new();

    // not set, not configured
    client.enrol(&app);
    assert_eq!(app.statuses(1), vec![-1]);
    assert!(client.acs_parameters().is_empty());

    assert_eq!(client.set_e2ee(&app, &[bytes(ROOT)], None), 0);
    assert_eq!(
        client.feature_tags(),
        FEATURE_TAGS,
        "not told before enrolling"
    );
    let parameters = client.acs_parameters();
    let names: Vec<&str> = parameters.iter().map(|(name, _)| &name[..]).collect();
    assert_eq!(names, ["participant_public_key", "home_kds"]);
    assert_eq!(parameters[1].1, "42");
    assert_eq!(
        app.kept.lock().unwrap().len(),
        1,
        "the Participant Key made"
    );

    client.enrol(&app);
    assert_eq!(app.statuses(2), vec![-1, -1], "not configured yet");

    // the identity configured goes to the Home KDS, which issues Alice's
    // certificate, not one for the key the device made
    client.setup(&["sip:+491701234567@ims.example.com"], Some("AAAAAA=="));
    client.enrol(&app);
    assert_eq!(app.statuses(3), vec![-1, -1, -4]);
    let enrolments = app.enrolments.lock().unwrap();
    assert_eq!(enrolments.len(), 1);
    assert_eq!(enrolments[0].0, ALICE_TEL);
    assert_eq!(enrolments[0].1, 2);
    assert_eq!(enrolments[0].5, Some(vec![0; 4]));
}

#[test]
fn e2ee_is_not_set_with_what_is_not_right() {
    let app = App::default();
    let client = Client::new();

    // a root that is not one, a state that is not one
    assert_eq!(client.set_e2ee(&app, &[b"not a root".to_vec()], None), -1);
    assert_eq!(
        client.set_e2ee(&app, &[bytes(ROOT)], Some(b"not a state")),
        -2
    );
    // a state that cannot be kept
    app.refusing.store(true, Ordering::SeqCst);
    assert_eq!(client.set_e2ee(&app, &[bytes(ROOT)], None), -3);
    assert!(!client.has_e2ee());
    assert!(client.acs_parameters().is_empty());

    // nor without the app's functions
    let root = bytes(ROOT);
    let pointers = [root.as_ptr()];
    let lens = [root.len()];
    let set = unsafe {
        rcs_client_set_e2ee(
            client.client,
            42,
            pointers.as_ptr(),
            lens.as_ptr(),
            1,
            ptr::null(),
            0,
            Some(save),
            None,
            Some(upload),
            Some(fetch),
            app.context(),
        )
    };
    assert_eq!(set, -1);

    // a state kept is taken back
    app.refusing.store(false, Ordering::SeqCst);
    assert_eq!(client.set_e2ee(&app, &[bytes(ROOT)], None), 0);
    let kept = app.kept.lock().unwrap().last().unwrap().clone();
    let parameters = client.acs_parameters();
    let again = Client::new();
    assert_eq!(again.set_e2ee(&app, &[bytes(ROOT)], Some(&kept)), 0);
    assert_eq!(again.acs_parameters(), parameters);
}

#[test]
fn a_device_tells_its_e2ee_capability_on_the_client_once_enrolled() {
    let client = Client::new();
    let keeping = Arc::new(Keeping::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &keeping));
    let device = Arc::new(alice(&keeping, &kds, TODAY, None));
    device.advertise_on(&unsafe { &*client.client }.engine);
    assert_eq!(client.feature_tags(), FEATURE_TAGS, "not enrolled");

    provision(&device, &[ALICE_TEL], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    assert_eq!(
        client.feature_tags(),
        format!(
            "{};+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"42\"",
            FEATURE_TAGS
        )
    );

    drop(device);
    assert_eq!(client.feature_tags(), FEATURE_TAGS, "the device let go of");
}

#[test]
fn capabilities_are_asked_through_the_client() {
    let app = App::default();
    let client = Client::new();
    let runtime = &*client.runtime as *const RcsRuntime as *mut RcsRuntime;

    // not registered, then with no contact
    let contact = CString::new("sip:+15559876@example.com").unwrap();
    unsafe {
        rcs_client_query_capabilities(
            runtime,
            client.client,
            contact.as_ptr(),
            Some(capable),
            app.context(),
        );
        rcs_client_query_capabilities(
            runtime,
            client.client,
            ptr::null(),
            Some(capable),
            app.context(),
        );
    }
    assert_eq!(
        *app.capabilities.lock().unwrap(),
        vec![(403, String::new()), (400, String::new())]
    );
}
