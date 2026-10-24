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

use std::{
    ops::Add,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use base64::{engine::general_purpose, Engine};
use tokio::{
    runtime::Runtime,
    time::{sleep, Instant},
};

use uuid::Uuid;

use rust_rcs_core::{
    ffi::log::platform_log,
    internet::{
        header::{search, HeaderSearch},
        name_addr::AsNameAddr,
        syntax, AsHeaderField, Header,
    },
    security::{
        aka::{aka_do_challenge, AkaChallenge, AkaResponse, AsAkaAlgorithm},
        authentication::{
            challenge::ChallengeParser,
            digest::{DigestAnswerParams, DigestChallengeParams, DigestCredentials},
        },
    },
    sip::{ClientTransactionCallbacks, SipCore, SipMessage, SipTransport, REGISTER},
    third_gen_pp::addressing,
    util::{
        rand,
        raw_string::{FromRawStr, ToInt},
    },
};

use crate::capability::FEATURE_TAGS;

use super::{
    authentication_type::AuthenticationType,
    flow::{on_registration_authenticated, FlowManager, SubscriptionEvent},
    retry::Reconnect,
};

const LOG_TAG: &str = "librust_rcs_client";

/// The registration time a REGISTER asks for
const REQUESTED_EXPIRES: u32 = 3000;

pub enum RegistrationState {
    IDLE,
    REQUESTING,
    REGISTERED(String, Instant), // (un-barred IMPU, expiration)
    RELEASED,
}

pub enum RegistrationEvent {
    Registered(String),
    Refreshed,
    /// The registration ended, failing or lost, and when to register again
    Released(Reconnect),
}

/// What a REGISTER answered a challenge with, which decides whether the
/// challenge in a 401 to it can be answered again
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// No challenge: a REGISTER first sent, or a refresh
    Nothing,
    /// The response to a challenge; a new challenge to it means the response
    /// was refused, unless the nonce was stale
    Response,
    /// The AUTS of an AKA resynchronisation, which a new challenge follows
    Resync,
}

struct RegState {
    seq: u32,
    state: RegistrationState,
    auth: DigestAnswerParams,
    /// The registration time asked for, raised by a 423 Min-Expires
    expires: u32,
    /// Registering as RFC 5626 has it, with a reg-id and outbound supported,
    /// until a 439
    outbound: bool,
    /// The refresh scheduled last, which only it may send
    refresh: u64,
}

pub struct Registration {
    reg_state: Arc<Mutex<RegState>>,

    transport: Arc<SipTransport>,
    transport_address: String,

    registration_id: u32,

    sip_instance_id: Uuid,

    subscription_id: i32,

    impi: String,
    impu: String,

    home_domain: String,

    authentication_type: AuthenticationType,

    call_id: Uuid,
}

impl Registration {
    pub fn new(
        subscription_id: i32,
        impi: String,
        impu: String,
        home_domain: String,
        authentication_type: AuthenticationType,
        transport: Arc<SipTransport>,
        transport_address: String,
        registration_id: u32,
        sip_instance_id: Uuid,
    ) -> Registration {
        let authorization_params = DigestAnswerParams {
            realm: match &authentication_type {
                AuthenticationType::Aka(_, realm, _) => realm.as_bytes().to_vec(),

                AuthenticationType::Digest(_, realm, _, _) => realm.as_bytes().to_vec(),
            },

            algorithm: match &authentication_type {
                AuthenticationType::Aka(algorithm, _, _) => Some(algorithm.as_bytes().to_vec()),

                AuthenticationType::Digest(algorithm, _, _, _) => {
                    Some(algorithm.as_bytes().to_vec())
                }
            },

            username: match &authentication_type {
                AuthenticationType::Aka(_, _, username) => username.as_bytes().to_vec(),

                AuthenticationType::Digest(_, _, username, _) => username.as_bytes().to_vec(),
            },

            uri: format!("sip:{}", home_domain).into_bytes(),

            challenge: None,
            credentials: None,
        };

        Registration {
            reg_state: Arc::new(Mutex::new(RegState {
                seq: 0,
                state: RegistrationState::IDLE,
                auth: authorization_params,
                expires: REQUESTED_EXPIRES,
                outbound: true,
                refresh: 0,
            })),

            transport,
            transport_address,

            registration_id,

            sip_instance_id,

            subscription_id,

            impi,
            impu,

            home_domain,

            authentication_type,

            call_id: Uuid::new_v4(),
        }
    }

    /// The URI the registration binds: the user of the IMPU at the transport's
    /// address
    pub fn contact_uri(&self) -> String {
        contact_uri(&self.impu, &self.transport_address)
    }
}

/// The contact URI of the user of `impu`, a sip: or tel: URI, at
/// `transport_address`
pub fn contact_uri(impu: &str, transport_address: &str) -> String {
    let user = impu
        .strip_prefix("sips:")
        .or_else(|| impu.strip_prefix("sip:"))
        .or_else(|| impu.strip_prefix("tel:"))
        .unwrap_or(impu);
    let user = user.split(|c| c == '@' || c == ';').next().unwrap_or(user);
    format!("sip:{}@{}", user, transport_address)
}

/// When to refresh a registration granted for `expires` seconds: 600 s
/// before it ends if it was granted for more than 1200 s, when half of it
/// has gone otherwise (TS 24.229 section 5.1.1.4.1)
pub fn refresh_delay(expires: u32) -> Duration {
    if expires > 1200 {
        Duration::from_secs((expires - 600) as u64)
    } else {
        Duration::from_secs(expires as u64) / 2
    }
}

type StateCallback = Arc<Box<dyn Fn(RegistrationEvent) + Send + Sync>>;

pub fn start_register<CB>(
    registration: &Arc<Registration>,
    flow_manager: &Arc<FlowManager>,
    core: &Arc<SipCore>,
    rt: &Arc<Runtime>,
    state_callback: CB,
) where
    CB: Fn(RegistrationEvent) + Send + Sync + 'static,
{
    platform_log(LOG_TAG, "calling registration->start_register()");

    let mut guard = registration.reg_state.lock().unwrap();

    match &guard.state {
        RegistrationState::IDLE => {
            guard.state = RegistrationState::REQUESTING;
        }
        RegistrationState::REQUESTING => return,
        RegistrationState::REGISTERED(_, _) => return,
        RegistrationState::RELEASED => return,
    }

    send_register(
        registration,
        &mut guard,
        Answer::Nothing,
        flow_manager,
        core,
        rt,
        &Arc::new(Box::new(state_callback)),
    );
}

fn send_register(
    registration: &Arc<Registration>,
    guard: &mut MutexGuard<RegState>,
    answer: Answer,
    flow_manager: &Arc<FlowManager>,
    core: &Arc<SipCore>,
    rt: &Arc<Runtime>,
    state_callback: &StateCallback,
) {
    let req_message = make_request(registration, guard, false);

    core.get_transaction_manager().send_request(
        req_message,
        &registration.transport,
        RegisterContext {
            answer,
            registration: Arc::clone(registration),
            flow_manager: Arc::clone(flow_manager),
            core: Arc::clone(core),
            rt: Arc::clone(rt),
            state_callback: Arc::clone(state_callback),
        },
        rt,
    );
}

struct RegisterContext {
    answer: Answer,
    registration: Arc<Registration>,
    flow_manager: Arc<FlowManager>,
    core: Arc<SipCore>,
    rt: Arc<Runtime>,
    state_callback: StateCallback,
}

impl RegisterContext {
    /// Ends the registration, unless it ended already
    fn fail(&self, reconnect: Reconnect) {
        {
            let mut guard = self.registration.reg_state.lock().unwrap();
            if let RegistrationState::RELEASED = guard.state {
                return;
            }
            guard.state = RegistrationState::RELEASED;
            guard.refresh += 1;
        }

        (self.state_callback)(RegistrationEvent::Released(reconnect));
    }

    fn resend(&self, guard: &mut MutexGuard<RegState>, answer: Answer) {
        send_register(
            &self.registration,
            guard,
            answer,
            &self.flow_manager,
            &self.core,
            &self.rt,
            &self.state_callback,
        );
    }

    fn on_success(&self, headers: &[Header]) {
        let mut default_public_identity: Option<String> = None; // to-do: we should also have a preferred IMPU (MSISDN) to use in P-Preferred-Identity header
        for associated_uri_header in HeaderSearch::new(headers, b"P-Associated-URI", true) {
            for associated_uri in associated_uri_header.get_value().as_name_addresses() {
                if let Some(uri_part) = associated_uri.uri_part {
                    if let Ok(s) = std::str::from_utf8(uri_part.uri) {
                        platform_log(LOG_TAG, format!("unbarred IMPU {}", s));
                        if uri_part.uri.starts_with(b"sip:") && default_public_identity.is_none() {
                            default_public_identity.replace(String::from(s));
                        }
                    }
                }
            }
        }

        let unbarred_impu = match default_public_identity {
            Some(default_public_identity) => default_public_identity,
            None => addressing::tmpu_from_impi(&self.registration.impi),
        };

        // the requests the client starts take it as their Route
        self.registration.transport.set_service_route(
            HeaderSearch::new(headers, b"Service-Route", true)
                .map(|h| h.get_value().to_vec())
                .collect(),
        );

        let expires = own_contact_expires(
            headers,
            &self.registration.contact_uri(),
            self.registration.sip_instance_id,
        )
        .or_else(|| {
            search(headers, b"Expires", true).and_then(|h| h.get_value().to_int::<u32>().ok())
        });

        let expires = match expires {
            Some(expires) if expires > 0 => expires,
            _ => {
                platform_log(LOG_TAG, "registered, but not for any time");
                self.fail(Reconnect::Backoff);
                return;
            }
        };

        platform_log(
            LOG_TAG,
            format!(
                "registered with first unbarred IMPU {} for {} s",
                &unbarred_impu, expires
            ),
        );

        let expiration = Instant::now().add(Duration::from_secs(expires as u64));

        let first = {
            let mut guard = self.registration.reg_state.lock().unwrap();
            match &guard.state {
                RegistrationState::REQUESTING => {
                    guard.state = RegistrationState::REGISTERED(unbarred_impu.clone(), expiration);
                    true
                }
                RegistrationState::REGISTERED(impu, _) => {
                    guard.state = RegistrationState::REGISTERED(impu.clone(), expiration);
                    false
                }
                _ => return, // deregistered meanwhile
            }
        };

        schedule_refresh(
            &self.registration,
            refresh_delay(expires),
            &self.flow_manager,
            &self.core,
            &self.rt,
            &self.state_callback,
        );

        if first {
            (self.state_callback)(RegistrationEvent::Registered(unbarred_impu.clone()));

            let registration = Arc::clone(&self.registration);
            let flow_manager = Arc::clone(&self.flow_manager);
            let core = Arc::clone(&self.core);
            let rt = Arc::clone(&self.rt);
            let state_callback = Arc::clone(&self.state_callback);

            on_registration_authenticated(
                &self.flow_manager,
                unbarred_impu,
                &self.registration.transport,
                self.registration.transport_address.clone(),
                &self.registration,
                self.registration.sip_instance_id,
                &self.core,
                &self.rt,
                move |ev| match ev {
                    // a network-initiated re-authentication
                    SubscriptionEvent::Shortened(remaining) => schedule_refresh(
                        &registration,
                        refresh_delay(remaining),
                        &flow_manager,
                        &core,
                        &rt,
                        &state_callback,
                    ),
                },
            );
        } else {
            (self.state_callback)(RegistrationEvent::Refreshed);
        }
    }

    fn on_challenge(&self, headers: &[Header]) {
        let mut guard = self.registration.reg_state.lock().unwrap();

        guard.auth.challenge.take();
        guard.auth.credentials.take();

        let mut stale = false;

        if let Some(www_authenticate_header) = search(headers, b"WWW-Authenticate", true) {
            let www_authenticate_header_value = www_authenticate_header.get_value();
            platform_log(
                LOG_TAG,
                format!(
                    "on_final_response with WWW-Authenticate: {}",
                    String::from_utf8_lossy(www_authenticate_header_value)
                ),
            );
            let parser = ChallengeParser::new(www_authenticate_header_value);

            for challenge in parser {
                stale = challenge.get_params().any(|param| {
                    param.name.eq_ignore_ascii_case(b"stale")
                        && param
                            .value
                            .map_or(false, |v| syntax::unquote(v).eq_ignore_ascii_case(b"true"))
                });
                if let Some(params) = DigestChallengeParams::from_challenge(challenge) {
                    let digest_challenge = params.to_challenge();

                    guard.auth.challenge.replace(digest_challenge);

                    break;
                }
            }
        }

        // a challenge to a response is a refusal, unless only the nonce was
        // stale (RFC 7616 section 3.3)
        if self.answer == Answer::Response && !stale {
            drop(guard);
            platform_log(LOG_TAG, "authentication refused");
            self.fail(Reconnect::Backoff);
            return;
        }

        let nonce = match &guard.auth.challenge {
            Some(challenge) => (challenge.algorithm.clone(), challenge.nonce.clone()),
            None => {
                drop(guard);
                self.fail(Reconnect::Backoff);
                return;
            }
        };

        let answer = match &self.registration.authentication_type {
            AuthenticationType::Aka(_, _, _) => {
                let response = match (
                    nonce.0.as_aka_algorithm(),
                    AkaChallenge::from_raw_str(&nonce.1),
                ) {
                    (Ok(_), Ok(aka_challenge)) => {
                        aka_do_challenge(&aka_challenge, self.registration.subscription_id).ok()
                    }
                    _ => None,
                };

                match response {
                    Some(AkaResponse::Successful(res, _k)) => {
                        let client_nonce = rand::create_raw_alpha_numeric_string(8);

                        guard.auth.credentials.replace(DigestCredentials {
                            password: res,
                            client_data: Some(b"REGISTER".to_vec()),
                            client_nonce: Some((client_nonce, 0)),
                            entity_digest: None,
                            extra_params: Vec::new(),
                        });

                        Answer::Response
                    }

                    Some(AkaResponse::SyncFailure(auts)) => {
                        let mut extra_params = Vec::new();

                        let encoded = general_purpose::STANDARD.encode(&auts);
                        let encoded = Vec::from(encoded);

                        extra_params.push((b"auts".to_vec(), encoded));

                        let client_nonce = rand::create_raw_alpha_numeric_string(8);

                        guard.auth.credentials.replace(DigestCredentials {
                            password: Vec::new(),
                            client_data: Some(b"REGISTER".to_vec()),
                            client_nonce: Some((client_nonce, 0)),
                            entity_digest: None,
                            extra_params,
                        });

                        Answer::Resync
                    }

                    None => {
                        drop(guard);
                        platform_log(LOG_TAG, "AKA challenge failed");
                        self.fail(Reconnect::Backoff);
                        return;
                    }
                }
            }

            AuthenticationType::Digest(_, _, _, password) => {
                let client_nonce = rand::create_raw_alpha_numeric_string(8);

                guard.auth.credentials.replace(DigestCredentials {
                    password: password.as_bytes().to_vec(),
                    client_data: Some(b"REGISTER".to_vec()),
                    client_nonce: Some((client_nonce, 0)),
                    entity_digest: None,
                    extra_params: Vec::new(),
                });

                Answer::Response
            }
        };

        self.resend(&mut guard, answer);
    }
}

impl ClientTransactionCallbacks for RegisterContext {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        if let SipMessage::Response(l, headers, _) = &message {
            platform_log(
                LOG_TAG,
                format!("registration->on_final_response(): {}", l.status_code),
            );

            let empty = Vec::new();
            let headers = headers.as_ref().unwrap_or(&empty);

            match l.status_code {
                200..=299 => self.on_success(headers),

                401 => self.on_challenge(headers),

                // Interval Too Brief: ask for the Min-Expires given
                423 => {
                    let min_expires = search(headers, b"Min-Expires", true)
                        .and_then(|h| h.get_value().to_int::<u32>().ok());
                    let mut guard = self.registration.reg_state.lock().unwrap();
                    match min_expires {
                        Some(min_expires) if min_expires > guard.expires => {
                            guard.expires = min_expires;
                            self.resend(&mut guard, Answer::Nothing);
                        }
                        _ => {
                            drop(guard);
                            self.fail(Reconnect::Backoff);
                        }
                    }
                }

                // First Hop Lacks Outbound Support (RFC 5626 section 11.6):
                // register without outbound
                439 => {
                    let mut guard = self.registration.reg_state.lock().unwrap();
                    if guard.outbound {
                        guard.outbound = false;
                        self.resend(&mut guard, Answer::Nothing);
                    } else {
                        drop(guard);
                        self.fail(Reconnect::Backoff);
                    }
                }

                _ => {
                    let retry_after = search(headers, b"Retry-After", true)
                        .and_then(|h| retry_after(h.get_value()));
                    self.fail(match retry_after {
                        Some(retry_after) => Reconnect::After(Duration::from_secs(retry_after)),
                        None => Reconnect::Backoff,
                    });
                }
            }
        }
    }

    fn on_transport_error(&self) {
        self.fail(Reconnect::Backoff)
    }
}

/// The seconds of a Retry-After value, which a comment and parameters may
/// follow (RFC 3261 section 20.33)
fn retry_after(value: &[u8]) -> Option<u64> {
    let value = syntax::trim(value);
    let digits = value
        .iter()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(value.len());
    value[..digits].to_int::<u64>().ok()
}

/// The registration time a 200 to a REGISTER gives the contact of `uri` or
/// of the instance `sip_instance_id`, among all those it lists
fn own_contact_expires(headers: &[Header], uri: &str, sip_instance_id: Uuid) -> Option<u32> {
    let instance = format!(
        "<urn:uuid:{}>",
        sip_instance_id
            .hyphenated()
            .encode_lower(&mut Uuid::encode_buffer())
    );

    for contact_header in HeaderSearch::new(headers, b"Contact", true) {
        for contact in split_list(contact_header.get_value()) {
            let field = contact.as_header_field();

            let mut ours = false;
            let mut expires = None;
            for parameter in field.get_parameter_iterator() {
                if parameter.name.eq_ignore_ascii_case(b"expires") {
                    expires = parameter.value.and_then(|v| v.to_int::<u32>().ok());
                } else if parameter.name.eq_ignore_ascii_case(b"+sip.instance") {
                    if let Some(value) = parameter.value {
                        if syntax::unquote(value).eq_ignore_ascii_case(instance.as_bytes()) {
                            ours = true;
                        }
                    }
                }
            }

            if !ours {
                if let Some(address) = field.value.as_name_addresses().first() {
                    if let Some(uri_part) = &address.uri_part {
                        ours = uri_part.uri.eq_ignore_ascii_case(uri.as_bytes());
                    }
                }
            }

            if ours {
                return expires;
            }
        }
    }

    None
}

/// The entries of a comma separated header value, such as the contacts of a
/// Contact
fn split_list(value: &[u8]) -> Vec<&[u8]> {
    let mut entries = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut angled = false;
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'\\' if quoted => i = i + 1,
            b'"' => quoted = !quoted,
            b'<' if !quoted => angled = true,
            b'>' if !quoted => angled = false,
            b',' if !quoted && !angled => {
                entries.push(syntax::trim(&value[start..i]));
                start = i + 1;
            }
            _ => {}
        }
        i = i + 1;
    }
    entries.push(syntax::trim(&value[start.min(value.len())..]));
    entries
}

/// Schedules the refresh of a registration after `delay`, in place of any
/// refresh scheduled before
pub fn schedule_refresh(
    registration: &Arc<Registration>,
    delay: Duration,
    flow_manager: &Arc<FlowManager>,
    core: &Arc<SipCore>,
    rt: &Arc<Runtime>,
    state_callback: &StateCallback,
) {
    platform_log(LOG_TAG, format!("refreshing in {:?}", delay));

    let refresh = {
        let mut guard = registration.reg_state.lock().unwrap();
        guard.refresh += 1;
        guard.refresh
    };

    let registration = Arc::clone(registration);
    let flow_manager = Arc::clone(flow_manager);
    let core = Arc::clone(core);
    let rt_ = Arc::clone(rt);
    let state_callback = Arc::clone(state_callback);

    rt.spawn(async move {
        sleep(delay).await;

        let mut guard = registration.reg_state.lock().unwrap();

        if guard.refresh == refresh {
            if let RegistrationState::REGISTERED(_, _) = guard.state {
                send_register(
                    &registration,
                    &mut guard,
                    Answer::Nothing,
                    &flow_manager,
                    &core,
                    &rt_,
                    &state_callback,
                );
            }
        }
    });
}

fn create_next_authorization_header(
    auth: &mut DigestAnswerParams,
    is_aka_algorithm: bool,
) -> Option<Vec<u8>> {
    if let Some(credentials) = &mut auth.credentials {
        if let Some((ref mut client_nonce, ref mut nc)) = credentials.client_nonce {
            *client_nonce = rand::create_raw_alpha_numeric_string(8);
            *nc += 1;
        }
    }

    let mut base_algorithm = None;

    if let Some(challenge) = &auth.challenge {
        base_algorithm = Some(&challenge.algorithm);
    } else if let Some(algorithm) = &auth.algorithm {
        base_algorithm = Some(algorithm);
    }

    if let Some(base_algorithm) = base_algorithm {
        if is_aka_algorithm {
            match base_algorithm.as_aka_algorithm() {
                Ok(aka) => {
                    if let Ok(v) = auth.make_authorization_header(Some(aka.algorithm), false, true) {
                        return Some(v);
                    }
                }
                Err(()) => {
                    platform_log(LOG_TAG, "create_next_authorization_header error: cannot get base algorithm as aka algorithm")
                }
            }
        } else {
            if let Ok(v) = auth.make_authorization_header(Some(base_algorithm), false, true) {
                return Some(v);
            }
        }
    }

    None
}

fn make_request(
    registration: &Registration,
    guard: &mut MutexGuard<RegState>,
    de_register: bool,
) -> SipMessage {
    let mut req_message = SipMessage::new_request(
        REGISTER,
        format!("sip:{}", registration.home_domain).as_bytes(),
    );

    req_message.add_header(Header::new(
        b"Call-ID",
        String::from(
            registration
                .call_id
                .as_hyphenated()
                .encode_lower(&mut Uuid::encode_buffer()),
        ),
    ));

    guard.seq += 1;

    req_message.add_header(Header::new(b"CSeq", format!("{} REGISTER", guard.seq)));

    req_message.add_header(Header::new(
        b"Contact",
        format!(
            "<{}>;+sip.instance=\"<urn:uuid:{}>\";{}{};expires={}",
            registration.contact_uri(),
            registration
                .sip_instance_id
                .hyphenated()
                .encode_lower(&mut Uuid::encode_buffer()),
            FEATURE_TAGS,
            if guard.outbound {
                format!(";reg-id={}", registration.registration_id)
            } else {
                String::new()
            },
            if de_register { 0 } else { guard.expires },
        ),
    ));

    req_message.add_header(Header::new(
        b"Allow",
        b"NOTIFY, OPTIONS, INVITE, UPDATE, CANCEL, BYE, ACK, MESSAGE",
    ));

    // a reg-id goes with outbound supported (RFC 5626 section 4.2)
    req_message.add_header(Header::new(
        b"Supported",
        if guard.outbound {
            "path,gruu,outbound"
        } else {
            "path,gruu"
        },
    ));

    if let Some(authorizaiton) = create_next_authorization_header(
        &mut guard.auth,
        match registration.authentication_type {
            AuthenticationType::Aka(_, _, _) => true,
            AuthenticationType::Digest(_, _, _, _) => false,
        },
    ) {
        platform_log(
            LOG_TAG,
            format!(
                "create_next_authorization_header returns: {}",
                String::from_utf8_lossy(&authorizaiton)
            ),
        );
        req_message.add_header(Header::new(b"Authorization", authorizaiton));
    } else {
        req_message.add_header(Header::new(b"Authorization", match &registration.authentication_type {
            AuthenticationType::Aka(algorithm, realm, username) => {
                format!("Digest username=\"{}\",algorithm={},nonce=\"\",response=\"\",uri=\"sip:{}\",realm=\"{}\"", username, algorithm, realm, realm)
            }
            AuthenticationType::Digest(algorithm, realm, username, _) => {
                format!("Digest username=\"{}\",algorithm={},nonce=\"\",response=\"\",uri=\"sip:{}\",realm=\"{}\"", username, algorithm, realm, realm)
            }
        }));
    }

    let tag = rand::create_raw_alpha_numeric_string(16);
    let tag = String::from_utf8_lossy(&tag);

    req_message.add_header(Header::new(
        b"From",
        format!("<{}>;tag={}", registration.impu, tag),
    ));

    req_message.add_header(Header::new(b"To", format!("<{}>", registration.impu)));

    req_message
}

/// De-registers `registration`, if registered, leaving its connection once
/// answered, and whether it was registered
pub fn deregister(
    registration: &Arc<Registration>,
    core: &Arc<SipCore>,
    rt: &Arc<Runtime>,
) -> bool {
    platform_log(LOG_TAG, "calling registration->deregister()");

    let mut guard = registration.reg_state.lock().unwrap();

    match &guard.state {
        RegistrationState::IDLE => return false,
        RegistrationState::REQUESTING => return false,
        RegistrationState::REGISTERED(_, _) => guard.state = RegistrationState::RELEASED,
        RegistrationState::RELEASED => return false,
    }

    guard.refresh += 1;

    let req_message = make_request(registration, &mut guard, true);

    drop(guard);

    core.get_transaction_manager().send_request(
        req_message,
        &registration.transport,
        DeregisterContext {
            registration: Arc::clone(registration),
            core: Arc::clone(core),
            rt: Arc::clone(rt),
        },
        rt,
    );

    true
}

struct DeregisterContext {
    registration: Arc<Registration>,
    core: Arc<SipCore>,
    rt: Arc<Runtime>,
}

impl ClientTransactionCallbacks for DeregisterContext {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        if let SipMessage::Response(l, _headers, _) = &message {
            platform_log(
                LOG_TAG,
                format!("de-registration->on_final_response(): {}", l.status_code),
            );
        }

        let tm = self.core.get_transaction_manager();
        tm.unregister_sip_transport(&self.registration.transport, &self.rt);
    }

    fn on_transport_error(&self) {
        platform_log(LOG_TAG, "de-registration->on_transport_error()");
        let tm = self.core.get_transaction_manager();
        tm.unregister_sip_transport(&self.registration.transport, &self.rt);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{contact_uri, refresh_delay, retry_after, split_list};

    #[test]
    fn a_registration_is_refreshed_ahead_of_its_end() {
        assert_eq!(refresh_delay(600000), Duration::from_secs(599400));
        assert_eq!(refresh_delay(3600), Duration::from_secs(3000));
        assert_eq!(refresh_delay(1201), Duration::from_secs(601));
        assert_eq!(refresh_delay(1200), Duration::from_secs(600));
        assert_eq!(refresh_delay(3), Duration::from_millis(1500));
    }

    #[test]
    fn the_contact_is_the_user_of_the_impu_at_the_transport() {
        for impu in [
            "sip:+15551234@example.com",
            "tel:+15551234",
            "tel:+15551234;phone-context=example.com",
        ] {
            assert_eq!(
                contact_uri(impu, "192.0.2.10:5060"),
                "sip:+15551234@192.0.2.10:5060",
                "{}",
                impu
            );
        }
    }

    #[test]
    fn retry_after_is_read_without_its_comment_and_parameters() {
        assert_eq!(retry_after(b"120"), Some(120));
        assert_eq!(retry_after(b" 120 (maintenance);duration=60"), Some(120));
        assert_eq!(retry_after(b"120;duration=60"), Some(120));
        assert_eq!(retry_after(b"soon"), None);
        assert_eq!(retry_after(b""), None);
    }

    #[test]
    fn contacts_are_split_outside_quotes_and_brackets() {
        assert_eq!(
            split_list(
                b"<sip:a@b;x=1,2>;expires=60, \"x, y\" <sip:c@d>;+sip.instance=\"<urn:uuid:1>\""
            ),
            [
                &b"<sip:a@b;x=1,2>;expires=60"[..],
                b"\"x, y\" <sip:c@d>;+sip.instance=\"<urn:uuid:1>\"",
            ]
        );
    }
}
