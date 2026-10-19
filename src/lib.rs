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

pub mod chat_bot;
pub mod conference;
pub mod connection;
pub mod connectivity;
pub mod contact;
pub mod context;
pub mod ffi;
pub mod messaging;
pub mod provisioning;
pub mod rcs_engine;

use std::ffi::{CStr, CString};
use std::ptr::{self, null_mut, NonNull};
use std::sync::{Arc, Mutex};

// use backtrace::Backtrace;

use libc::c_char;
use messaging::cpm::session::CPMGroupEvent;
use messaging::cpm::MessagingSessionHandle;
use rust_rcs_core::security::gba::GbaContext;
use rust_rcs_core::third_gen_pp::ThreeDigit;
use tokio::runtime::Runtime;

use rust_rcs_core::ffi::log::platform_log;

use chat_bot::ffi::{
    RetrieveChatbotInfoResultCallback, RetrieveChatbotInfoResultCallbackContext,
    RetrieveChatbotInfoResultCallbackContextWrapper, RetrieveSpecificChatbotsResultCallback,
    RetrieveSpecificChatbotsResultCallbackContext,
    RetrieveSpecificChatbotsResultCallbackContextWrapper, SearchChatbotResultCallback,
    SearchChatbotResultCallbackContext, SearchChatbotResultCallbackContextWrapper,
};
use conference::ffi::{
    MultiConferenceCreateResultCallback, MultiConferenceCreateResultCallbackContext,
    MultiConferenceCreateResultCallbackContextWrapper, MultiConferenceEventListener,
    MultiConferenceEventListenerContext, MultiConferenceEventListenerContextWrapper,
    MultiConferenceJoinResultCallback, MultiConferenceJoinResultCallbackContext,
    MultiConferenceJoinResultCallbackContextWrapper, MultiConferenceV1InviteHandlerContext,
    MultiConferenceV1InviteHandlerContextWrapper, MultiConferenceV1InviteHandlerFunction,
};
use conference::MultiConferenceV1;
use context::Context;
use ffi::{
    MessageCallback, MessageCallbackContext, MessageCallbackContextWrapper, StateChangeCallback,
    StateChangeCallbackContext, StateChangeCallbackContextWrapper,
};
use messaging::ffi::{
    get_recipient_type, DownloadFileProgressCallback, DownloadFileProgressCallbackContext,
    DownloadFileResultCallback, DownloadFileResultCallbackContext,
    DownloadFileResultCallbackContextWrapper, DownloadileProgressCallbackContextWrapper,
    GroupChatEventCallback, GroupChatInvitationCallback, GroupChatResultCallback,
    MessageResultCallback, MessageResultCallbackContext, MessageResultCallbackContextWrapper,
    SendImdnReportResultCallback, SendImdnReportResultCallbackContext,
    SendImdnReportResultCallbackContextWrapper, UploadFileProgressCallback,
    UploadFileProgressCallbackContext, UploadFileProgressCallbackContextWrapper,
    UploadFileResultCallback, UploadFileResultCallbackContext,
    UploadFileResultCallbackContextWrapper,
};
use provisioning::device_configuration::{
    start_auto_config, DeviceConfigurationStatus, RetryReason,
};

use rcs_engine::{DownloadOrigin, RcsEngine};

const LOG_TAG: &str = "librust_rcs_client";

pub struct RcsRuntime {
    pub rt: Arc<Runtime>,
    // context: Arc<Context>,
}

impl RcsRuntime {
    pub fn new() -> Result<RcsRuntime, ()> {
        std::panic::set_hook(Box::new(|info| {
            platform_log(LOG_TAG, format!("panic! {}", info));

            // let bt = Backtrace::new();

            // platform_log(LOG_TAG, format!("{:?}", bt));
        }));

        // let context = Context::new("fs_root_dir");
        if let Ok(rt) = Runtime::new() {
            // return Ok(RcsRuntime { rt, context: Arc::new(context) });
            return Ok(RcsRuntime { rt: Arc::new(rt) });
        }

        Err(())
    }
}

/// `text` as a C string, without the NUL bytes it cannot hold, which text
/// from the network may have
fn c_string<T: Into<Vec<u8>>>(text: T) -> CString {
    let mut bytes = text.into();
    bytes.retain(|b| *b != 0);
    CString::new(bytes).unwrap_or_default()
}

pub struct RcsClient {
    subscription_id: i32,
    mcc: u16,
    mnc: u16,
    imsi: String,
    imei: String,
    msisdn: Option<String>,

    context: Arc<Context>,

    // cb: Option<StateChangeCallback>,
    // cb_context: Arc<Mutex<StateChangeCallbackContextWrapper>>,
    engine: RcsEngine,
    // engine_itf: RcsEngineInterface,
    engine_gba_context: Option<Arc<GbaContext>>,
}

impl RcsClient {
    pub fn new(
        subscription_id: i32,
        mcc: u16,
        mnc: u16,
        imsi: &str,
        imei: &str,
        msisdn: Option<&str>,
        context: Arc<Context>,
        state_cb: Option<StateChangeCallback>,
        state_cb_context: *mut StateChangeCallbackContext,
        message_cb: Option<MessageCallback>,
        message_cb_context: *mut MessageCallbackContext,
        multi_conference_v1_invite_handler: Option<MultiConferenceV1InviteHandlerFunction>,
        multi_conference_v1_invite_handler_context: *mut MultiConferenceV1InviteHandlerContext,
        rt: Arc<Runtime>,
    ) -> RcsClient {
        let state_cb_context = Arc::new(Mutex::new(
            NonNull::new(state_cb_context).map(StateChangeCallbackContextWrapper),
        ));
        let message_cb_context = Arc::new(Mutex::new(
            NonNull::new(message_cb_context).map(MessageCallbackContextWrapper),
        ));
        let multi_conference_v1_invite_handler_context = Arc::new(Mutex::new(
            NonNull::new(multi_conference_v1_invite_handler_context)
                .map(MultiConferenceV1InviteHandlerContextWrapper),
        ));
        let context_ = Arc::clone(&context);
        let engine = RcsEngine::new(
            subscription_id,
            rt,
            context_,
            move |state| {
                if let Some(state_cb) = state_cb {
                    let state_cb_context = state_cb_context.lock().unwrap();
                    let state_cb_context_ptr = state_cb_context
                        .as_ref()
                        .map_or(ptr::null_mut(), |c| c.0.as_ptr());
                    match state {
                        rcs_engine::RcsEngineRegistrationState::NONE => {
                            state_cb(0, state_cb_context_ptr)
                        }
                        rcs_engine::RcsEngineRegistrationState::AUTHENTICATED(_) => {
                            state_cb(1, state_cb_context_ptr)
                        }
                        rcs_engine::RcsEngineRegistrationState::MAINTAINED(_) => {
                            state_cb(2, state_cb_context_ptr)
                        }
                    }
                }
            },
            move |service_type,
                  session_handle,
                  contact_uri,
                  content_type,
                  content_body,
                  imdn_message_id,
                  cpim_date,
                  cpim_from| {
                if let Some(messag_cb) = message_cb {
                    let session_handle = match session_handle {
                        Some(session_handle) => Some(Box::new(session_handle)),
                        None => None,
                    };
                    let contact_uri = c_string(contact_uri);
                    let content_type = c_string(content_type);
                    let content_body = c_string(content_body);
                    let imdn_message_id = c_string(imdn_message_id);
                    let cpim_date = c_string(cpim_date);
                    if let Some(cpim_from) = cpim_from {
                        let cpim_from = c_string(cpim_from);
                        let message_cb_context = message_cb_context.lock().unwrap();
                        let message_cb_context_ptr = message_cb_context
                            .as_ref()
                            .map_or(ptr::null_mut(), |c| c.0.as_ptr());
                        messag_cb(
                            service_type,
                            session_handle,
                            contact_uri.as_ptr(),
                            content_type.as_ptr(),
                            content_body.as_ptr(),
                            imdn_message_id.as_ptr(),
                            cpim_date.as_ptr(),
                            cpim_from.as_ptr(),
                            message_cb_context_ptr,
                        );
                    } else {
                        let message_cb_context = message_cb_context.lock().unwrap();
                        let message_cb_context_ptr = message_cb_context
                            .as_ref()
                            .map_or(ptr::null_mut(), |c| c.0.as_ptr());
                        messag_cb(
                            service_type,
                            session_handle,
                            contact_uri.as_ptr(),
                            content_type.as_ptr(),
                            content_body.as_ptr(),
                            imdn_message_id.as_ptr(),
                            cpim_date.as_ptr(),
                            ptr::null(),
                            message_cb_context_ptr,
                        );
                    };
                }
            },
            move |conference_v1, offer_sdp, response_receiver| {
                if let Some(multi_conference_v1_invite_handler) = multi_conference_v1_invite_handler
                {
                    let multi_conference_v1_invite_handler_context =
                        multi_conference_v1_invite_handler_context.lock().unwrap();
                    let multi_conference_v1_invite_handler_context_ptr =
                        multi_conference_v1_invite_handler_context
                            .as_ref()
                            .map_or(ptr::null_mut(), |c| c.0.as_ptr());
                    let offer_sdp_ptr = offer_sdp.as_ptr();
                    let offer_sdp_len = offer_sdp.len();
                    multi_conference_v1_invite_handler(
                        Some(Box::new(conference_v1)),
                        offer_sdp_ptr,
                        offer_sdp_len,
                        Some(Box::new(response_receiver)),
                        multi_conference_v1_invite_handler_context_ptr,
                    );
                }
            },
        );
        RcsClient {
            subscription_id,
            mcc,
            mnc,
            imsi: imsi.to_string(),
            imei: imei.to_string(),
            msisdn: match msisdn {
                Some(msisdn) => Some(String::from(msisdn)),
                None => None,
            },
            context,
            // cb,
            // cb_context: Arc::new(Mutex::new(StateChangeCallbackContextWrapper(
            //     NonNull::new(cb_context).unwrap(),
            // ))),
            engine,
            // engine_itf,
            engine_gba_context: None,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn new_rcs_runtime() -> Option<Box<RcsRuntime>> {
    if let Ok(rcs_runtime) = RcsRuntime::new() {
        return Some(Box::new(rcs_runtime));
    }
    None
}

#[no_mangle]
pub unsafe extern "C" fn new_rcs_client(
    rcs_runtime: *mut RcsRuntime,
    subscription_id: i32,
    mcc: u16,
    mnc: u16,
    imsi: *const c_char,
    imei: *const c_char,
    msisdn: *const c_char,
    fs_root_dir: *const c_char,
    state_cb: Option<StateChangeCallback>,
    state_cb_context: *mut StateChangeCallbackContext,
    message_cb: Option<MessageCallback>,
    message_cb_context: *mut MessageCallbackContext,
    conference_v1_invite_handler: Option<MultiConferenceV1InviteHandlerFunction>,
    conference_v1_invite_handler_context: *mut MultiConferenceV1InviteHandlerContext,
) -> Option<Box<RcsClient>> {
    let imsi = CStr::from_ptr(imsi).to_string_lossy().into_owned();
    let imei = CStr::from_ptr(imei).to_string_lossy().into_owned();
    let msisdn = if msisdn.is_null() {
        None
    } else {
        Some(CStr::from_ptr(msisdn).to_string_lossy())
    };
    let fs_root_dir = CStr::from_ptr(fs_root_dir).to_string_lossy().into_owned();
    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        platform_log(LOG_TAG, "creating context");
        let rt = Arc::clone(&rcs_runtime.rt);
        let context = Arc::new(Context::new(&fs_root_dir, rt));
        return Some(Box::new(RcsClient::new(
            subscription_id,
            mcc,
            mnc,
            &imsi,
            &imei,
            msisdn.as_deref(),
            context,
            state_cb,
            state_cb_context,
            message_cb,
            message_cb_context,
            conference_v1_invite_handler,
            conference_v1_invite_handler_context,
            Arc::clone(&rcs_runtime.rt),
        )));
    }
    None
}

type AutoConfigProgressCallback =
    extern "C" fn(status_code: i32, context: *mut AutoConfigCallbackContext);

type AutoConfigResultCallback = extern "C" fn(
    status_code: i32,
    ims_config: *const c_char,
    rcs_config: *const c_char,
    extra: *const c_char,
    // extra_host: *const c_char,
    // extra_cookie: *const c_char,
    context: *mut AutoConfigCallbackContext,
);

#[repr(C)]
pub struct AutoConfigCallbackContext {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
extern "C" {
    fn auto_config_callback_context_release(context: *mut AutoConfigCallbackContext);
}

struct AutoConfigCallbackContextWrapper(NonNull<AutoConfigCallbackContext>);

impl Drop for AutoConfigCallbackContextWrapper {
    fn drop(&mut self) {
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        let cb_context = self.0.as_ptr();
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        unsafe {
            auto_config_callback_context_release(cb_context);
        }
    }
}

unsafe impl Send for AutoConfigCallbackContextWrapper {}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_start_config(
    rcs_runtime: *mut RcsRuntime,
    client: *const RcsClient,
    p_cb: Option<AutoConfigProgressCallback>,
    r_cb: Option<AutoConfigResultCallback>,
    cb_context: *mut AutoConfigCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_start_config()");

    let cb_context = AutoConfigCallbackContextWrapper(NonNull::new(cb_context).unwrap());

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        if let Some(client) = client.as_ref() {
            let subscription_id = client.subscription_id;

            let mcc = client.mcc;
            let mnc = client.mnc;
            let imsi = String::from(&client.imsi);
            let imei = String::from(&client.imei);

            let context = Arc::clone(&client.context);

            let p_cb_context = Arc::new(Mutex::new(cb_context));
            let r_cb_context: Arc<Mutex<AutoConfigCallbackContextWrapper>> =
                Arc::clone(&p_cb_context);

            // let cb = client.cb;
            // let cb_context = client.cb_context.clone();
            rcs_runtime.rt.spawn(async move {
                match start_auto_config(
                    subscription_id,
                    mcc,
                    mnc,
                    &imei,
                    &imsi,
                    None,
                    context,
                    move |status| {
                        if let Some(cb) = p_cb {
                            let cb_context = p_cb_context.lock().unwrap();
                            let cb_context_ptr = cb_context.0.as_ptr();
                            cb(status, cb_context_ptr);
                        }
                    },
                )
                .await
                {
                    Ok((
                        msisdn,
                        rcs_application_characteristic,
                        ims_application_characteristic,
                    )) => {
                        platform_log(
                            LOG_TAG,
                            format!("on configuration success with provided msisdn {:?}", msisdn),
                        );

                        if let (
                            Ok(ims_application_characteristic_string),
                            Ok(rcs_application_characteristic_string),
                        ) = (
                            ims_application_characteristic.to_c_string(),
                            rcs_application_characteristic.to_c_string(),
                        ) {
                            platform_log(
                                LOG_TAG,
                                format!("with ims-app {:?}", ims_application_characteristic_string),
                            );

                            platform_log(
                                LOG_TAG,
                                format!("with rcs-app {:?}", rcs_application_characteristic_string),
                            );

                            // to-do: provide msisdn to callback
                            if let Some(cb) = r_cb {
                                let ims_config = ims_application_characteristic_string.as_ptr();
                                let rcs_config = rcs_application_characteristic_string.as_ptr();
                                let extra = ptr::null();
                                let cb_context: std::sync::MutexGuard<
                                    '_,
                                    AutoConfigCallbackContextWrapper,
                                > = r_cb_context.lock().unwrap();
                                let cb_context_ptr = cb_context.0.as_ptr();
                                cb(0, ims_config, rcs_config, extra, cb_context_ptr);
                            }
                        } else {
                            if let Some(cb) = r_cb {
                                let ims_config = ptr::null();
                                let rcs_config = ptr::null();
                                let extra = ptr::null();
                                let cb_context = r_cb_context.lock().unwrap();
                                let cb_context_ptr = cb_context.0.as_ptr();
                                cb(-1, ims_config, rcs_config, extra, cb_context_ptr);
                            }
                        }
                    }

                    Err(status) => {
                        platform_log(LOG_TAG, format!("on configuration error {:?}", status));

                        match status {
                            DeviceConfigurationStatus::InvalidArgument => {
                                if let Some(cb) = r_cb {
                                    let ims_config = ptr::null();
                                    let rcs_config = ptr::null();
                                    let extra = ptr::null();
                                    let cb_context = r_cb_context.lock().unwrap();
                                    let cb_context_ptr = cb_context.0.as_ptr();
                                    cb(-1, ims_config, rcs_config, extra, cb_context_ptr);
                                }
                            }

                            DeviceConfigurationStatus::Forbidden => {
                                if let Some(cb) = r_cb {
                                    let ims_config = ptr::null();
                                    let rcs_config = ptr::null();
                                    let extra = ptr::null();
                                    let cb_context = r_cb_context.lock().unwrap();
                                    let cb_context_ptr = cb_context.0.as_ptr();
                                    cb(-1, ims_config, rcs_config, extra, cb_context_ptr);
                                }
                            }

                            DeviceConfigurationStatus::Retry(reason, timeout) => {
                                if let Some(cb) = r_cb {
                                    let ims_config = ptr::null();
                                    let rcs_config = ptr::null();
                                    let extra = ptr::null();
                                    let cb_context = r_cb_context.lock().unwrap();
                                    let cb_context_ptr = cb_context.0.as_ptr();
                                    cb(-1, ims_config, rcs_config, extra, cb_context_ptr);
                                }
                            } // DeviceConfigurationStatus::Retry(reason, timeout) => match reason {
                              //     RetryReason::RequireOtp(port, session_host, session_cookie) => {
                              //         if let Some(cb) = cb {
                              //             let ims_config = ptr::null();
                              //             let rcs_config = ptr::null();
                              //             let session_host = session_host.as_str();
                              //             let session_cookie = session_cookie.as_str();
                              //             if let (Ok(extra_host), Ok(extra_cookie)) = (CString::new(session_host), CString::new(session_cookie)) {
                              //                 let extra_host = extra_host.as_ptr();
                              //                 let extra_cookie = extra_cookie.as_ptr();
                              //                 let cb_context = cb_context.lock().unwrap();
                              //                 let cb_context_ptr: *mut AutoConfigCallbackContext =
                              //                     cb_context.0.as_ptr();
                              //                 if port == 0 {
                              //                     cb(2, ims_config, rcs_config, extra_host, extra_cookie, cb_context_ptr);
                              //                 } else {
                              //                     cb(1, ims_config, rcs_config, extra_host, extra_cookie, cb_context_ptr);
                              //                 }
                              //             }
                              //         }
                              //     }
                              //     _ => {
                              //         if let Some(cb) = cb {
                              //             let ims_config = ptr::null();
                              //             let rcs_config = ptr::null();
                              //             let extra_host = ptr::null();
                              //             let extra_cookie = ptr::null();
                              //             let cb_context = cb_context.lock().unwrap();
                              //             let cb_context_ptr = cb_context.0.as_ptr();
                              //             cb(-1, ims_config, rcs_config, extra_host, extra_cookie, cb_context_ptr);
                              //         }
                              //     }
                              // },
                        }
                    }
                }
            });
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_input_otp(
    rcs_runtime: *mut RcsRuntime,
    client: *const RcsClient,
    otp: *const c_char,
) {
    platform_log(LOG_TAG, "calling rcs_client_input_otp()");

    if let Some(client) = client.as_ref() {
        let otp = CStr::from_ptr(otp).to_string_lossy().into_owned();

        client.context.broadcast_otp(&otp);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_setup(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    ims_config: *const c_char,
    rcs_config: *const c_char,
) {
    platform_log(LOG_TAG, "calling rcs_client_setup()");

    if let Some(client) = client.as_mut() {
        let ims_config = CStr::from_ptr(ims_config).to_string_lossy().into_owned();
        let rcs_config = CStr::from_ptr(rcs_config).to_string_lossy().into_owned();

        let gba_context = client.context.make_gba_context(
            &client.imsi,
            client.mcc,
            client.mnc,
            client.subscription_id,
        );
        let gba_context = Arc::new(gba_context);

        client.engine.configure(ims_config, rcs_config);
        client.engine_gba_context.replace(gba_context);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_connect(rcs_runtime: *mut RcsRuntime, client: *mut RcsClient) {
    platform_log(LOG_TAG, "calling rcs_client_connect()");

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_mut() {
            client.engine.connect(rt);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_disconnect(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
) {
    platform_log(LOG_TAG, "calling rcs_client_disconnect()");

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_mut() {
            client.engine.disconnect(rt);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_send_message(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    message_type: *const c_char,
    message_content: *const c_char,
    recipient: *const c_char,
    recipient_type: i8,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_send_message()");

    send_message(
        rcs_runtime,
        client,
        message_type,
        message_content,
        recipient,
        recipient_type,
        ptr::null(),
        cb,
        cb_context,
    );
}

/// As rcs_client_send_message(), the message sent with the imdn.Message-ID
/// `imdn_message_id`, which notifications of it give, or with a new one if
/// NULL
#[no_mangle]
pub unsafe extern "C" fn rcs_client_send_message_with_imdn_id(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    message_type: *const c_char,
    message_content: *const c_char,
    recipient: *const c_char,
    recipient_type: i8,
    imdn_message_id: *const c_char,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_send_message_with_imdn_id()");

    send_message(
        rcs_runtime,
        client,
        message_type,
        message_content,
        recipient,
        recipient_type,
        imdn_message_id,
        cb,
        cb_context,
    );
}

unsafe fn send_message(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    message_type: *const c_char,
    message_content: *const c_char,
    recipient: *const c_char,
    recipient_type: i8,
    imdn_message_id: *const c_char,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    let cb_context = if cb_context.is_null() {
        None
    } else {
        Some(MessageResultCallbackContextWrapper(
            NonNull::new(cb_context).unwrap(),
        ))
    };

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        if let Some(client) = client.as_ref() {
            let message_type = CStr::from_ptr(message_type).to_string_lossy();
            let message_content = CStr::from_ptr(message_content).to_string_lossy();
            let recipient = CStr::from_ptr(recipient).to_string_lossy();
            let recipient_type = get_recipient_type(recipient_type);
            let imdn_message_id = if imdn_message_id.is_null() {
                None
            } else {
                Some(CStr::from_ptr(imdn_message_id).to_string_lossy())
            };

            if let Some(recipient_type) = recipient_type {
                let cb_context_ = if let Some(cb_context) = cb_context {
                    Some(Arc::new(Mutex::new(cb_context)))
                } else {
                    None
                };

                client.engine.send_message(
                    &message_type,
                    &message_content,
                    imdn_message_id.as_deref(),
                    &recipient,
                    recipient_type,
                    move |status_code, reason_phrase| {
                        if let Some(cb) = cb {
                            let reason_phrase = c_string(reason_phrase);
                            if let Some(cb_context_) = cb_context_ {
                                let cb_context = cb_context_.lock().unwrap();
                                cb(status_code, reason_phrase.as_ptr(), cb_context.0.as_ptr());
                            } else {
                                cb(status_code, reason_phrase.as_ptr(), ptr::null_mut());
                            }
                        }
                    },
                    &rcs_runtime.rt,
                );

                return;
            }
        }
    }

    if let Some(cb) = cb {
        let reason_phrase = c_string("Forbidden");
        cb(
            403,
            reason_phrase.as_ptr(),
            if let Some(cb_context) = cb_context {
                cb_context.0.as_ptr()
            } else {
                ptr::null_mut()
            },
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_send_imdn_report(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    imdn_content: *const c_char,
    sender_uri: *const c_char,
    sender_service_type: i32,
    sender_session_handle: *mut MessagingSessionHandle,
    cb: Option<SendImdnReportResultCallback>,
    cb_context: *mut SendImdnReportResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_send_imdn_report()");

    let cb_context = if cb_context.is_null() {
        None
    } else {
        Some(SendImdnReportResultCallbackContextWrapper(
            NonNull::new(cb_context).unwrap(),
        ))
    };

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_ref() {
            let cb_context_ = if let Some(cb_context) = cb_context {
                Some(Arc::new(Mutex::new(cb_context)))
            } else {
                None
            };

            let imdn_content = CStr::from_ptr(imdn_content).to_string_lossy();
            let sender_uri = CStr::from_ptr(sender_uri).to_string_lossy();

            client.engine.send_imdn_report(
                &imdn_content,
                &sender_uri,
                sender_service_type,
                sender_session_handle,
                rt,
                move |status_code, reason_phrase| {
                    if let Some(cb) = cb {
                        let reason_phrase = c_string(reason_phrase);
                        if let Some(cb_context_) = cb_context_ {
                            let cb_context = cb_context_.lock().unwrap();
                            cb(status_code, reason_phrase.as_ptr(), cb_context.0.as_ptr());
                        } else {
                            cb(status_code, reason_phrase.as_ptr(), ptr::null_mut());
                        }
                    }
                },
            );

            return;
        }
    }

    if let Some(cb) = cb {
        let reason_phrase = c_string("Forbidden");
        cb(
            403,
            reason_phrase.as_ptr(),
            if let Some(cb_context) = cb_context {
                cb_context.0.as_ptr()
            } else {
                ptr::null_mut()
            },
        );
    }
}

/// Tells the sender of the message `imdn_message_id`, taken lately, that it
/// was displayed, if it asked to be told: 404 if the message is not known,
/// 403 if it did not ask
#[no_mangle]
pub unsafe extern "C" fn rcs_client_send_display_notification(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    imdn_message_id: *const c_char,
    cb: Option<SendImdnReportResultCallback>,
    cb_context: *mut SendImdnReportResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_send_display_notification()");

    let cb_context = if cb_context.is_null() {
        None
    } else {
        Some(SendImdnReportResultCallbackContextWrapper(
            NonNull::new(cb_context).unwrap(),
        ))
    };

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_ref() {
            let cb_context_ = cb_context.map(|cb_context| Arc::new(Mutex::new(cb_context)));

            let imdn_message_id = CStr::from_ptr(imdn_message_id).to_string_lossy();

            client.engine.send_display_notification(
                &imdn_message_id,
                rt,
                move |status_code, reason_phrase| {
                    if let Some(cb) = cb {
                        let reason_phrase = c_string(reason_phrase);
                        if let Some(cb_context_) = cb_context_ {
                            let cb_context = cb_context_.lock().unwrap();
                            cb(status_code, reason_phrase.as_ptr(), cb_context.0.as_ptr());
                        } else {
                            cb(status_code, reason_phrase.as_ptr(), ptr::null_mut());
                        }
                    }
                },
            );

            return;
        }
    }

    if let Some(cb) = cb {
        let reason_phrase = c_string("Forbidden");
        cb(
            403,
            reason_phrase.as_ptr(),
            if let Some(cb_context) = cb_context {
                cb_context.0.as_ptr()
            } else {
                ptr::null_mut()
            },
        );
    }
}

/// `cb` with `cb_context`, which is let go of when the closure is
fn message_result_closure(
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) -> impl FnOnce(u16, String) + Send + Sync + 'static {
    let cb_context = NonNull::new(cb_context)
        .map(|cb_context| Arc::new(Mutex::new(MessageResultCallbackContextWrapper(cb_context))));
    move |status_code, reason_phrase| {
        if let Some(cb) = cb {
            let reason_phrase = c_string(reason_phrase);
            match &cb_context {
                Some(cb_context) => {
                    let cb_context = cb_context.lock().unwrap();
                    cb(status_code, reason_phrase.as_ptr(), cb_context.0.as_ptr());
                }
                None => cb(status_code, reason_phrase.as_ptr(), ptr::null_mut()),
            }
        }
    }
}

/// Starts a new group chat with the `participant_count` URIs at
/// `participants`, about `subject` unless NULL. `cb` is told the URI of the
/// group once its session starts, which messages to it are sent to as to a
/// recipient of the group type, or NULL if it did not start.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_create_group_chat(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    participants: *const *const c_char,
    participant_count: usize,
    subject: *const c_char,
    cb: Option<GroupChatResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_create_group_chat()");

    let cb_context = NonNull::new(cb_context)
        .map(|cb_context| Arc::new(Mutex::new(MessageResultCallbackContextWrapper(cb_context))));
    let callback =
        move |status_code: u16, reason_phrase: String, conference_uri: Option<String>| {
            if let Some(cb) = cb {
                let reason_phrase = c_string(reason_phrase);
                let conference_uri = conference_uri.map(c_string);
                let conference_uri = match &conference_uri {
                    Some(conference_uri) => conference_uri.as_ptr(),
                    None => ptr::null(),
                };
                match &cb_context {
                    Some(cb_context) => {
                        let cb_context = cb_context.lock().unwrap();
                        cb(
                            status_code,
                            reason_phrase.as_ptr(),
                            conference_uri,
                            cb_context.0.as_ptr(),
                        );
                    }
                    None => cb(
                        status_code,
                        reason_phrase.as_ptr(),
                        conference_uri,
                        ptr::null_mut(),
                    ),
                }
            }
        };

    if let (Some(rcs_runtime), Some(client)) = (rcs_runtime.as_ref(), client.as_ref()) {
        let participants = participant_list(participants, participant_count);
        let subject = if subject.is_null() {
            None
        } else {
            Some(CStr::from_ptr(subject).to_string_lossy())
        };

        client.engine.create_group_chat(
            participants,
            subject.as_deref(),
            callback,
            &rcs_runtime.rt,
        );
        return;
    }

    callback(403, String::from("Forbidden"), None);
}

/// The participant URIs at `participants`, `participant_count` of them
unsafe fn participant_list(
    participants: *const *const c_char,
    participant_count: usize,
) -> Vec<String> {
    if participants.is_null() {
        return Vec::new();
    }
    std::slice::from_raw_parts(participants, participant_count)
        .iter()
        .filter(|participant| !participant.is_null())
        .map(|participant| CStr::from_ptr(*participant).to_string_lossy().into_owned())
        .collect()
}

/// Sets what is told of the group chats taken part in: joined (0), a
/// participant's status (1), left (2), and of an invitation that waited for
/// the user's answer being withdrawn (3). The context of one set before is
/// let go of.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_set_group_chat_listener(
    client: *mut RcsClient,
    cb: Option<GroupChatEventCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_set_group_chat_listener()");

    let cb_context = NonNull::new(cb_context)
        .map(|cb_context| Arc::new(Mutex::new(MessageResultCallbackContextWrapper(cb_context))));

    if let (Some(client), Some(cb)) = (client.as_ref(), cb) {
        client.engine.set_group_chat_listener(move |event| {
            let (event, conference_uri, participant) = match event {
                CPMGroupEvent::Joined(conference_uri) => (0, conference_uri, None),
                CPMGroupEvent::Participant(conference_uri, participant) => {
                    (1, conference_uri, Some(participant))
                }
                CPMGroupEvent::Left(conference_uri) => (2, conference_uri, None),
                CPMGroupEvent::InvitationWithdrawn(conference_uri) => (3, conference_uri, None),
                // told through the invitation listener
                CPMGroupEvent::Invited(_) => return,
            };
            let conference_uri = c_string(conference_uri);
            let (uri, display_name, status) = match participant {
                Some(participant) => (
                    Some(c_string(participant.uri)),
                    participant.display_name.map(c_string),
                    Some(c_string(participant.status)),
                ),
                None => (None, None, None),
            };
            let as_ptr = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
            let cb_context = cb_context
                .as_ref()
                .map(|cb_context| cb_context.lock().unwrap());
            cb(
                event,
                conference_uri.as_ptr(),
                as_ptr(&uri),
                as_ptr(&display_name),
                as_ptr(&status),
                cb_context.map_or(ptr::null_mut(), |cb_context| cb_context.0.as_ptr()),
            );
        });
    }
}

/// Sets what is told of the invitations to group chats not known before. The
/// context of one set before is let go of.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_set_group_chat_invitation_listener(
    client: *mut RcsClient,
    cb: Option<GroupChatInvitationCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(
        LOG_TAG,
        "calling rcs_client_set_group_chat_invitation_listener()",
    );

    let cb_context = NonNull::new(cb_context)
        .map(|cb_context| Arc::new(Mutex::new(MessageResultCallbackContextWrapper(cb_context))));

    if let (Some(client), Some(cb)) = (client.as_ref(), cb) {
        client
            .engine
            .set_group_chat_invitation_listener(move |invitation| {
                let conference_uri = c_string(invitation.conference_uri);
                let conversation_id = c_string(invitation.conversation_id);
                let subject = invitation.subject.map(c_string);
                let inviter_uri = invitation.inviter_uri.map(c_string);
                let inviter_name = invitation.inviter_name.map(c_string);
                let as_ptr = |s: &Option<CString>| s.as_ref().map_or(ptr::null(), |s| s.as_ptr());
                let cb_context = cb_context
                    .as_ref()
                    .map(|cb_context| cb_context.lock().unwrap());
                cb(
                    conference_uri.as_ptr(),
                    conversation_id.as_ptr(),
                    as_ptr(&subject),
                    as_ptr(&inviter_uri),
                    as_ptr(&inviter_name),
                    i32::from(invitation.pending),
                    cb_context.map_or(ptr::null_mut(), |cb_context| cb_context.0.as_ptr()),
                );
            });
    }
}

/// Accepts the invitation to the group chat at `conference_uri` that waits
/// for the user's answer if `accept` is not 0, or declines it: 404 if there
/// is none
#[no_mangle]
pub unsafe extern "C" fn rcs_client_answer_group_chat_invitation(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    conference_uri: *const c_char,
    accept: i32,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_answer_group_chat_invitation()");

    let callback = message_result_closure(cb, cb_context);

    if let (Some(rcs_runtime), Some(client)) = (rcs_runtime.as_ref(), client.as_ref()) {
        let conference_uri = CStr::from_ptr(conference_uri).to_string_lossy();
        client.engine.answer_group_chat_invitation(
            &conference_uri,
            accept != 0,
            callback,
            &rcs_runtime.rt,
        );
        return;
    }

    callback(403, String::from("Forbidden"));
}

/// Asks the focus of the group at `conference_uri`, in the session there is
/// with it, to invite the `participant_count` URIs at `participants`: 404 if
/// there is no session
#[no_mangle]
pub unsafe extern "C" fn rcs_client_add_group_chat_participants(
    client: *mut RcsClient,
    conference_uri: *const c_char,
    participants: *const *const c_char,
    participant_count: usize,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_add_group_chat_participants()");

    let callback = message_result_closure(cb, cb_context);

    if let Some(client) = client.as_ref() {
        let conference_uri = CStr::from_ptr(conference_uri).to_string_lossy();
        let participants = participant_list(participants, participant_count);
        client
            .engine
            .add_group_chat_participants(&conference_uri, &participants, callback);
        return;
    }

    callback(403, String::from("Forbidden"));
}

/// Tells `recipient`, in the chat session there is with it, that the user is
/// composing a message if `active` is not 0, or no longer is. No session is
/// started for it: 404 if there is none.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_send_is_composing(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    recipient: *const c_char,
    recipient_type: i8,
    active: i32,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_send_is_composing()");

    let callback = message_result_closure(cb, cb_context);

    if let (Some(rcs_runtime), Some(client), Some(recipient_type)) = (
        rcs_runtime.as_ref(),
        client.as_ref(),
        get_recipient_type(recipient_type),
    ) {
        let recipient = CStr::from_ptr(recipient).to_string_lossy();
        client.engine.send_is_composing(
            &recipient,
            recipient_type,
            active != 0,
            callback,
            &rcs_runtime.rt,
        );
        return;
    }

    callback(403, String::from("Forbidden"));
}

/// Leaves the group chat at `conference_uri` for good, where ending its
/// session leaves it only until the next; its session is restarted first if
/// there is none. A restart refused with 404 or 403 means the user already
/// takes no part in the group.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_leave_group_chat(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    conference_uri: *const c_char,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_leave_group_chat()");

    let callback = message_result_closure(cb, cb_context);

    if let (Some(rcs_runtime), Some(client)) = (rcs_runtime.as_ref(), client.as_ref()) {
        let conference_uri = CStr::from_ptr(conference_uri).to_string_lossy();
        client
            .engine
            .leave_group_chat(&conference_uri, callback, &rcs_runtime.rt);
        return;
    }

    callback(403, String::from("Forbidden"));
}

/// Ends the chat session with `recipient`, a contact or a group: 404 if there
/// is none. A message sent to it from now on starts another.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_end_chat_session(
    client: *mut RcsClient,
    recipient: *const c_char,
    cb: Option<MessageResultCallback>,
    cb_context: *mut MessageResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_end_chat_session()");

    let callback = message_result_closure(cb, cb_context);

    if let Some(client) = client.as_ref() {
        let recipient = CStr::from_ptr(recipient).to_string_lossy();
        client.engine.end_chat_session(&recipient, callback);
        return;
    }

    callback(403, String::from("Forbidden"));
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_upload_file(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    tid: *const c_char,
    file_path: *const c_char,
    file_name: *const c_char,
    file_mime: *const c_char,
    file_hash: *const c_char,
    thumbnail_path: *const c_char,
    thumbnail_name: *const c_char,
    thumbnail_mime: *const c_char,
    thumbnail_hash: *const c_char,
    progress_cb: Option<UploadFileProgressCallback>,
    progress_cb_context: *mut UploadFileProgressCallbackContext,
    result_cb: Option<UploadFileResultCallback>,
    result_cb_context: *mut UploadFileResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_upload_file()");

    let progress_cb_context = if progress_cb_context.is_null() {
        None
    } else {
        Some(UploadFileProgressCallbackContextWrapper(
            NonNull::new(progress_cb_context).unwrap(),
        ))
    };

    let result_cb_context = if result_cb_context.is_null() {
        None
    } else {
        Some(UploadFileResultCallbackContextWrapper(
            NonNull::new(result_cb_context).unwrap(),
        ))
    };

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_ref() {
            let msisdn = client.msisdn.as_deref();

            if let Some(gba_context) = &client.engine_gba_context {
                let gba_context = Arc::clone(gba_context);
                let http_client = client.context.get_http_client();
                let security_context = client.context.get_security_context();

                let tid = CStr::from_ptr(tid).to_string_lossy();

                let file_path = CStr::from_ptr(file_path).to_string_lossy();
                let file_name = CStr::from_ptr(file_name).to_string_lossy();
                let file_mime = CStr::from_ptr(file_mime).to_string_lossy();
                let file_hash = if file_hash.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(file_hash).to_string_lossy())
                };

                let thumbnail_path = if thumbnail_path.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(thumbnail_path).to_string_lossy())
                };

                let thumbnail_name = if thumbnail_name.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(thumbnail_name).to_string_lossy())
                };

                let thumbnail_mime = if thumbnail_mime.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(thumbnail_mime).to_string_lossy())
                };

                let thumbnail_hash = if thumbnail_hash.is_null() {
                    None
                } else {
                    Some(CStr::from_ptr(thumbnail_hash).to_string_lossy())
                };

                let progress_cb_context_ = if let Some(progress_cb_context) = progress_cb_context {
                    Some(Arc::new(Mutex::new(progress_cb_context)))
                } else {
                    None
                };

                let result_cb_context_ = if let Some(result_cb_context) = result_cb_context {
                    Some(Arc::new(Mutex::new(result_cb_context)))
                } else {
                    None
                };

                client.engine.upload_file(
                    &tid,
                    &file_path,
                    &file_name,
                    &file_mime,
                    file_hash.as_deref(),
                    thumbnail_path.as_deref(),
                    thumbnail_name.as_deref(),
                    thumbnail_mime.as_deref(),
                    thumbnail_hash.as_deref(),
                    msisdn,
                    http_client,
                    gba_context,
                    security_context,
                    rt,
                    move |current, total| {
                        platform_log(
                            LOG_TAG,
                            format!("upload_file_progress_callback() {}/{}", current, total),
                        );
                        if let Some(progress_cb) = progress_cb {
                            if let Some(progress_cb_context_) = &progress_cb_context_ {
                                let progress_cb_context = progress_cb_context_.lock().unwrap();
                                progress_cb(current, total, progress_cb_context.0.as_ptr());
                            } else {
                                progress_cb(current, total, ptr::null_mut());
                            }
                        }
                    },
                    move |status_code, reason_phrase, result_xml| {
                        platform_log(
                            LOG_TAG,
                            format!(
                                "upload_file_result_callback() {} {} {:?}",
                                status_code, reason_phrase, result_xml
                            ),
                        );
                        if let Some(result_cb) = result_cb {
                            let reason_phrase = c_string(reason_phrase);
                            let result_xml = if let Some(result_xml) = result_xml {
                                let result_xml = c_string(result_xml);
                                Some(result_xml)
                            } else {
                                None
                            };
                            if let Some(result_cb_context_) = result_cb_context_ {
                                let result_cb_context = result_cb_context_.lock().unwrap();
                                result_cb(
                                    status_code,
                                    reason_phrase.as_ptr(),
                                    if let Some(result_xml) = &result_xml {
                                        result_xml.as_ptr()
                                    } else {
                                        ptr::null()
                                    },
                                    result_cb_context.0.as_ptr(),
                                );
                            } else {
                                result_cb(
                                    status_code,
                                    reason_phrase.as_ptr(),
                                    if let Some(result_xml) = &result_xml {
                                        result_xml.as_ptr()
                                    } else {
                                        ptr::null()
                                    },
                                    ptr::null_mut(),
                                );
                            }
                        }
                    },
                );

                return;
            }
        }
    }

    if let Some(result_cb) = result_cb {
        let reason_phrase = c_string("Forbidden");
        let xml = ptr::null();
        let result_cb_context_ptr = if let Some(result_cb_context) = result_cb_context {
            result_cb_context.0.as_ptr()
        } else {
            ptr::null_mut()
        };
        result_cb(403, reason_phrase.as_ptr(), xml, result_cb_context_ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_download_file(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    file_uri: *const c_char,
    download_path: *const c_char,
    start: u32,
    total: i32,
    progress_cb: Option<DownloadFileProgressCallback>,
    progress_cb_context: *mut DownloadFileProgressCallbackContext,
    result_cb: Option<DownloadFileResultCallback>,
    result_cb_context: *mut DownloadFileResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_download_file()");

    download_file(
        rcs_runtime,
        client,
        file_uri,
        download_path,
        start,
        total,
        DownloadOrigin::default(),
        progress_cb,
        progress_cb_context,
        result_cb,
        result_cb_context,
    );
}

/// As rcs_client_download_file(), with what the message that brought the
/// file's URL tells, for the download proxy to be told if one is provisioned
/// (RCC.07 section 4.2.3): its imdn.Message-ID, its other party, a contact or
/// a group by its URI, and the Conversation-ID of the group chat it came in,
/// each NULL if not known. That of a group the client has had a session with
/// is told without being given.
#[no_mangle]
pub unsafe extern "C" fn rcs_client_download_message_file(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    file_uri: *const c_char,
    download_path: *const c_char,
    start: u32,
    total: i32,
    imdn_message_id: *const c_char,
    other_party: *const c_char,
    conversation_id: *const c_char,
    progress_cb: Option<DownloadFileProgressCallback>,
    progress_cb_context: *mut DownloadFileProgressCallbackContext,
    result_cb: Option<DownloadFileResultCallback>,
    result_cb_context: *mut DownloadFileResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_download_message_file()");

    let imdn_message_id = optional_string(imdn_message_id);
    let other_party = optional_string(other_party);
    let conversation_id = optional_string(conversation_id);

    download_file(
        rcs_runtime,
        client,
        file_uri,
        download_path,
        start,
        total,
        DownloadOrigin {
            message_id: imdn_message_id.as_deref(),
            other_party: other_party.as_deref(),
            conversation_id: conversation_id.as_deref(),
        },
        progress_cb,
        progress_cb_context,
        result_cb,
        result_cb_context,
    );
}

/// The text at `s`, None if NULL or empty
unsafe fn optional_string(s: *const c_char) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let s = CStr::from_ptr(s).to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(s.into_owned())
    }
}

unsafe fn download_file(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    file_uri: *const c_char,
    download_path: *const c_char,
    start: u32,
    total: i32,
    origin: DownloadOrigin<'_>,
    progress_cb: Option<DownloadFileProgressCallback>,
    progress_cb_context: *mut DownloadFileProgressCallbackContext,
    result_cb: Option<DownloadFileResultCallback>,
    result_cb_context: *mut DownloadFileResultCallbackContext,
) {
    let progress_cb_context = if progress_cb_context.is_null() {
        None
    } else {
        Some(DownloadileProgressCallbackContextWrapper(
            NonNull::new(progress_cb_context).unwrap(),
        ))
    };

    let result_cb_context = if result_cb_context.is_null() {
        None
    } else {
        Some(DownloadFileResultCallbackContextWrapper(
            NonNull::new(result_cb_context).unwrap(),
        ))
    };

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_ref() {
            let msisdn = client.msisdn.as_deref();

            if let Some(gba_context) = &client.engine_gba_context {
                let gba_context = Arc::clone(gba_context);
                let http_client = client.context.get_http_client();
                let security_context = client.context.get_security_context();

                let file_uri = CStr::from_ptr(file_uri).to_string_lossy();
                let download_path = CStr::from_ptr(download_path).to_string_lossy();

                if let Ok(start) = usize::try_from(start) {
                    let total = if total > 0 {
                        if let Ok(total) = usize::try_from(total) {
                            Some(total)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let progress_cb_context_ =
                        if let Some(progress_cb_context) = progress_cb_context {
                            Some(Arc::new(Mutex::new(progress_cb_context)))
                        } else {
                            None
                        };

                    let result_cb_context_ = if let Some(result_cb_context) = result_cb_context {
                        Some(Arc::new(Mutex::new(result_cb_context)))
                    } else {
                        None
                    };

                    client.engine.download_file(
                        &file_uri,
                        &download_path,
                        start,
                        total,
                        origin,
                        msisdn,
                        http_client,
                        gba_context,
                        security_context,
                        rt,
                        move |current, total| {
                            if let Some(progress_cb) = progress_cb {
                                if let Some(progress_cb_context_) = &progress_cb_context_ {
                                    let progress_cb_context = progress_cb_context_.lock().unwrap();
                                    progress_cb(current, total, progress_cb_context.0.as_ptr());
                                } else {
                                    progress_cb(current, total, ptr::null_mut());
                                }
                            }
                        },
                        move |status_code, reason_phrase| {
                            if let Some(result_cb) = result_cb {
                                let reason_phrase = c_string(reason_phrase);
                                if let Some(result_cb_context_) = result_cb_context_ {
                                    let result_cb_context = result_cb_context_.lock().unwrap();
                                    result_cb(
                                        status_code,
                                        reason_phrase.as_ptr(),
                                        result_cb_context.0.as_ptr(),
                                    );
                                } else {
                                    result_cb(status_code, reason_phrase.as_ptr(), ptr::null_mut());
                                }
                            }
                        },
                    );

                    return;
                }
            }
        }
    }

    if let Some(cb) = result_cb {
        let reason_phrase = c_string("Forbidden");
        let result_cb_context_ptr = if let Some(result_cb_context) = result_cb_context {
            result_cb_context.0.as_ptr()
        } else {
            ptr::null_mut()
        };
        cb(403, reason_phrase.as_ptr(), result_cb_context_ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_rcs_messaging_session(
    session_handle: *mut MessagingSessionHandle,
) {
    let _ = Box::from_raw(session_handle);
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_create_multi_conference_v1(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    recipients: *const c_char,
    offer_sdp: *const c_char,
    event_cb: Option<MultiConferenceEventListener>,
    event_cb_context: *mut MultiConferenceEventListenerContext,
    result_cb: Option<MultiConferenceCreateResultCallback>,
    result_cb_context: *mut MultiConferenceCreateResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_create_multi_conference_v1()");

    let event_cb_context =
        MultiConferenceEventListenerContextWrapper(NonNull::new(event_cb_context).unwrap());

    let result_cb_context =
        MultiConferenceCreateResultCallbackContextWrapper(NonNull::new(result_cb_context).unwrap());

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        if let Some(client) = client.as_ref() {
            let recipients = CStr::from_ptr(recipients).to_string_lossy();
            let offer_sdp = CStr::from_ptr(offer_sdp).to_string_lossy();

            let result_cb_context = Arc::new(Mutex::new(result_cb_context));

            client.engine.create_conference_v1(
                &recipients,
                &offer_sdp,
                event_cb,
                event_cb_context,
                &rcs_runtime.rt,
                move |result| {
                    if let Some(cb) = result_cb {
                        let cb_context = result_cb_context.lock().unwrap();
                        let cb_context_ptr = cb_context.0.as_ptr();
                        if let Some((conf, sdp)) = result {
                            let sdp_ptr = sdp.as_ptr();
                            let sdp_len = sdp.len();
                            cb(Some(Box::new(conf)), sdp_ptr, sdp_len, cb_context_ptr);
                        } else {
                            cb(None, ptr::null(), 0, cb_context_ptr);
                        }
                    }
                },
            );

            return;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_join_multi_conference_v1(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    conference_id: *const c_char,
    offer_sdp: *const c_char,
    event_cb: Option<MultiConferenceEventListener>,
    event_cb_context: *mut MultiConferenceEventListenerContext,
    result_cb: Option<MultiConferenceJoinResultCallback>,
    result_cb_context: *mut MultiConferenceJoinResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_join_multi_conference_v1()");

    let _ = MultiConferenceEventListenerContextWrapper(NonNull::new(event_cb_context).unwrap());
    let _ =
        MultiConferenceJoinResultCallbackContextWrapper(NonNull::new(result_cb_context).unwrap());
}

// #[no_mangle]
// pub unsafe extern "C" fn rcs_multi_conference_register_event_listener(
//     rcs_runtime: *mut RcsRuntime,
//     conference: *mut MultiConferenceV1,
//     cb: Option<MultiConferenceEventCallback>,
//     cb_context: *mut MultiConferenceEventCallbackContext,
// ) {
//     let cb_context = MultiConferenceEventCallbackContextWrapper(NonNull::new(cb_context).unwrap());

//     if let Some(rcs_runtime) = rcs_runtime.as_ref() {
//         if let Some(conference) = conference.as_mut() {
//             if let Some(cb) = cb {
//                 conference.register_event_listener(cb, cb_context);
//             }
//         }
//     }
// }

#[no_mangle]
pub unsafe extern "C" fn rcs_multi_conference_v1_keep_alive(
    rcs_runtime: *mut RcsRuntime,
    conference: *mut MultiConferenceV1,
) {
    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        if let Some(conference) = conference.as_mut() {
            conference.keep_alive(&rcs_runtime.rt);
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_retrieve_specific_chatbots(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    local_etag: *const c_char,
    cb: Option<RetrieveSpecificChatbotsResultCallback>,
    cb_context: *mut RetrieveSpecificChatbotsResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_retrieve_specific_chatbots()");

    let cb_context =
        RetrieveSpecificChatbotsResultCallbackContextWrapper(NonNull::new(cb_context).unwrap());

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_mut() {
            let local_etag = if local_etag.is_null() {
                None
            } else {
                Some(CStr::from_ptr(local_etag).to_string_lossy())
            };

            let msisdn = client.msisdn.as_deref();

            if let Some(gba_context) = &client.engine_gba_context {
                let gba_context = Arc::clone(gba_context);
                let http_client = client.context.get_http_client();
                let security_context = client.context.get_security_context();

                let cb_context_ = Arc::new(Mutex::new(cb_context));

                client.engine.retrieve_specific_chatbots(
                    local_etag.as_deref(),
                    msisdn,
                    http_client,
                    gba_context,
                    security_context,
                    rt,
                    move |status_code, reason_phrase, specific_chatbots, response_etag, expiry| {
                        if let Some(cb) = cb {
                            let reason_phrase = c_string(reason_phrase);

                            let specific_chatbots = match specific_chatbots {
                                Some(specific_chatbots) => Some(c_string(specific_chatbots)),
                                None => None,
                            };
                            let response_etag = match response_etag {
                                Some(response_etag) => Some(c_string(response_etag)),
                                None => None,
                            };

                            let cb_context = cb_context_.lock().unwrap();
                            let cb_context_ptr = cb_context.0.as_ptr();
                            cb(
                                status_code,
                                reason_phrase.as_ptr(),
                                if let Some(specific_chatbots) = &specific_chatbots {
                                    specific_chatbots.as_ptr()
                                } else {
                                    std::ptr::null()
                                },
                                if let Some(response_etag) = &response_etag {
                                    response_etag.as_ptr()
                                } else {
                                    std::ptr::null()
                                },
                                expiry,
                                cb_context_ptr,
                            );
                        }
                    },
                );

                return;
            }
        }
    }

    if let Some(cb) = cb {
        let reason_phrase = c_string("Forbidden");
        let cb_context_ptr = cb_context.0.as_ptr();
        cb(
            403,
            reason_phrase.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            cb_context_ptr,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_search_chatbot(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    query: *const c_char,
    start: u32,
    num: u32,
    cb: Option<SearchChatbotResultCallback>,
    cb_context: *mut SearchChatbotResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_search_chatbot()");

    let cb_context = SearchChatbotResultCallbackContextWrapper(NonNull::new(cb_context).unwrap());

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_mut() {
            let query = CStr::from_ptr(query).to_string_lossy();
            let home_operator = format!("{}{}", client.mcc.string_repr(), client.mnc.string_repr());
            let msisdn = client.msisdn.as_deref();

            if let Some(gba_context) = &client.engine_gba_context {
                let gba_context = Arc::clone(gba_context);
                let http_client = client.context.get_http_client();
                let security_context = client.context.get_security_context();

                let cb_context_ = Arc::new(Mutex::new(cb_context));

                client.engine.search_chatbot(
                    &query,
                    start,
                    num,
                    &home_operator,
                    msisdn,
                    http_client,
                    gba_context,
                    security_context,
                    rt,
                    move |status_code, reason_phrase, json| {
                        if let Some(cb) = cb {
                            let reason_phrase = c_string(reason_phrase);
                            let json = match json {
                                Some(json) => Some(c_string(json)),
                                None => None,
                            };

                            let cb_context = cb_context_.lock().unwrap();
                            let cb_context_ptr = cb_context.0.as_ptr();
                            cb(
                                status_code,
                                reason_phrase.as_ptr(),
                                if let Some(json) = &json {
                                    json.as_ptr()
                                } else {
                                    std::ptr::null()
                                },
                                cb_context_ptr,
                            );
                        }
                    },
                );

                return;
            }
        }
    }

    if let Some(cb) = cb {
        let reason_phrase = c_string("Forbidden");
        let json = ptr::null();
        let cb_context_ptr = cb_context.0.as_ptr();
        cb(403, reason_phrase.as_ptr(), json, cb_context_ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn rcs_client_retrieve_chatbot_info(
    rcs_runtime: *mut RcsRuntime,
    client: *mut RcsClient,
    chatbot_sip_uri: *const c_char,
    local_etag: *const c_char,
    cb: Option<RetrieveChatbotInfoResultCallback>,
    cb_context: *mut RetrieveChatbotInfoResultCallbackContext,
) {
    platform_log(LOG_TAG, "calling rcs_client_retrieve_chatbot_info()");

    let cb_context =
        RetrieveChatbotInfoResultCallbackContextWrapper(NonNull::new(cb_context).unwrap());

    if let Some(rcs_runtime) = rcs_runtime.as_ref() {
        let rt = Arc::clone(&rcs_runtime.rt);
        if let Some(client) = client.as_mut() {
            let chatbot_sip_uri = CStr::from_ptr(chatbot_sip_uri).to_string_lossy();
            let local_etag = if local_etag.is_null() {
                None
            } else {
                Some(CStr::from_ptr(local_etag).to_string_lossy())
            };
            let home_operator = format!("{}{}", client.mcc.string_repr(), client.mnc.string_repr());
            let home_language = String::from("zh"); // to-do: might want to pass it down
            let msisdn = client.msisdn.as_deref();

            if let Some(gba_context) = &client.engine_gba_context {
                let gba_context = Arc::clone(gba_context);
                let http_client = client.context.get_http_client();
                let security_context = client.context.get_security_context();

                let cb_context_ = Arc::new(Mutex::new(cb_context));

                client.engine.retrieve_chatbot_info(
                    &chatbot_sip_uri,
                    local_etag.as_deref(),
                    &home_operator,
                    &home_language,
                    msisdn,
                    http_client,
                    gba_context,
                    security_context,
                    rt,
                    move |status_code, reason_phrase, chatbot_info, response_etag, expiry| {
                        if let Some(cb) = cb {
                            let reason_phrase = c_string(reason_phrase);

                            let chatbot_info = match chatbot_info {
                                Some(chatbot_info) => Some(c_string(chatbot_info)),
                                None => None,
                            };
                            let response_etag = match response_etag {
                                Some(response_etag) => Some(c_string(response_etag)),
                                None => None,
                            };

                            let cb_context = cb_context_.lock().unwrap();
                            let cb_context_ptr = cb_context.0.as_ptr();
                            cb(
                                status_code,
                                reason_phrase.as_ptr(),
                                if let Some(chatbot_info) = &chatbot_info {
                                    chatbot_info.as_ptr()
                                } else {
                                    std::ptr::null()
                                },
                                if let Some(response_etag) = &response_etag {
                                    response_etag.as_ptr()
                                } else {
                                    std::ptr::null()
                                },
                                expiry,
                                cb_context_ptr,
                            );
                        }
                    },
                );

                return;
            }
        }
    }

    if let Some(cb) = cb {
        let reason_phrase = c_string("Forbidden");
        let cb_context_ptr = cb_context.0.as_ptr();
        cb(
            403,
            reason_phrase.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            cb_context_ptr,
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_rcs_client(client: *mut RcsClient) {
    let _ = Box::from_raw(client);
}

#[cfg(test)]
mod tests {
    use super::c_string;

    #[test]
    fn text_with_nul_bytes_becomes_a_c_string_without_them() {
        assert_eq!(c_string("plain").as_bytes(), b"plain");
        assert_eq!(c_string("a\0b\0").as_bytes(), b"ab");
        assert_eq!(c_string(vec![0u8, 0]).as_bytes(), b"");
    }
}
