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

//! A registration run against a registrar the test scripts, over a pipe in
//! place of the connection to the P-CSCF

use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::runtime::Runtime;
use uuid::Uuid;

use rust_rcs_core::internet::header;
use rust_rcs_core::sip::sip_parser::SipParser;
use rust_rcs_core::sip::sip_subscription::SubscriptionManager;
use rust_rcs_core::sip::sip_transaction::SipTransactionManager;
use rust_rcs_core::sip::sip_transport::{setup_sip_transport, SipTransportType};
use rust_rcs_core::sip::{SipCore, SipMessage, SipTransport, NOTIFY};

use super::authentication_type::AuthenticationType;
use super::flow::{FlowEvent, FlowManager};
use super::registration::{start_register, Registration, RegistrationEvent};

const IMPU: &str = "sip:+15551234@example.com";
const TRANSPORT_ADDRESS: &str = "192.0.2.10:5060";
const CONTACT: &str = "sip:+15551234@192.0.2.10:5060";
const OTHER_CONTACT: &str = "sip:+15551234@198.51.100.7:5060";

struct Registrar {
    rt: Arc<Runtime>,
    stream: DuplexStream,
    parser: SipParser,
    /// What start_register() reports
    registration_events: Receiver<String>,
    /// What the flow manager reports
    flow_events: Receiver<String>,
}

impl Registrar {
    /// A registration started over a pipe to the registrar
    fn start() -> Registrar {
        let rt = Arc::new(Runtime::new().unwrap());
        let (tm, tm_events) = SipTransactionManager::new(&rt);
        let tm = Arc::new(tm);
        let sm = Arc::new(SubscriptionManager::new(500));
        let core = Arc::new(SipCore::new(
            &sm,
            &tm,
            tm_events,
            vec![NOTIFY],
            Vec::new(),
            &rt,
        ));

        let transport = Arc::new(SipTransport::new::<DuplexStream>(
            String::from(TRANSPORT_ADDRESS),
            SipTransportType::TCP,
        ));
        let (ours, theirs) = tokio::io::duplex(65536);
        let tx = setup_sip_transport(&transport, ours, tm.get_ctrl_itf(), Arc::clone(&rt), || {});
        tm.register_sip_transport(Arc::clone(&transport), tx);

        let (flow_tx, flow_events) = mpsc::channel();
        let flow_manager = Arc::new(FlowManager::new(&sm, &tm, move |event, _, _| {
            let _ = flow_tx.send(match event {
                FlowEvent::Registered(impu) => format!("Registered {}", impu),
                FlowEvent::Lost(reconnect) => format!("Lost {:?}", reconnect),
            });
        }));

        let registration = Arc::new(Registration::new(
            1,
            String::from("alice@example.com"),
            String::from(IMPU),
            String::from("example.com"),
            AuthenticationType::Digest(
                String::from("MD5"),
                String::from("example.com"),
                String::from("alice@example.com"),
                String::from("secret"),
            ),
            Arc::clone(&transport),
            String::from(TRANSPORT_ADDRESS),
            1,
            Uuid::new_v4(),
        ));

        flow_manager.observe_registration(
            &transport,
            String::from(TRANSPORT_ADDRESS),
            &registration,
            &core,
            &rt,
        );

        let (registration_tx, registration_events) = mpsc::channel();
        start_register(&registration, &flow_manager, &core, &rt, move |event| {
            let _ = registration_tx.send(match event {
                RegistrationEvent::Registered(impu) => format!("Registered {}", impu),
                RegistrationEvent::Refreshed => String::from("Refreshed"),
                RegistrationEvent::Released(reconnect) => format!("Released {:?}", reconnect),
            });
        });

        Registrar {
            rt,
            stream: theirs,
            parser: SipParser::new(),
            registration_events,
            flow_events,
        }
    }

    /// The next message the client sends, within `timeout`
    fn next_within(&mut self, timeout: Duration) -> Option<SipMessage> {
        let Registrar {
            rt, stream, parser, ..
        } = self;
        rt.block_on(async {
            tokio::time::timeout(timeout, async {
                loop {
                    match parser.produce().unwrap() {
                        Some(SipMessage::Ping) | Some(SipMessage::Pong) => {}
                        Some(message) => return message,
                        None => {
                            let mut data = [0; 4096];
                            let size = stream.read(&mut data).await.unwrap();
                            assert!(size > 0, "the transport closed");
                            parser.feed(&data[..size]);
                        }
                    }
                }
            })
            .await
            .ok()
        })
    }

    fn next(&mut self) -> SipMessage {
        self.next_within(Duration::from_secs(5))
            .expect("a message from the client")
    }

    /// The next request the client sends, of `method`
    fn next_request(&mut self, method: &str) -> SipMessage {
        let message = self.next();
        match &message {
            SipMessage::Request(line, _, _) => {
                assert_eq!(line.method, method.as_bytes(), "the request sent");
            }
            _ => panic!("not a request"),
        }
        message
    }

    /// Checks that the client says nothing for a while
    fn silence(&mut self) {
        if let Some(message) = self.next_within(Duration::from_millis(500)) {
            panic!("unexpected: {:?}", first_line(&message));
        }
    }

    fn send(&mut self, data: &str) {
        self.rt
            .block_on(self.stream.write_all(data.as_bytes()))
            .unwrap();
    }

    /// The response of `status` to `request`, with `headers`
    fn respond(&mut self, request: &SipMessage, status: &str, headers: &str) {
        let mut data = format!("SIP/2.0 {}\r\n", status);
        for header in request.headers().unwrap() {
            let name = String::from_utf8_lossy(header.get_name());
            let value = String::from_utf8_lossy(header.get_value());
            match &name.to_ascii_lowercase()[..] {
                "via" | "from" | "call-id" | "cseq" => {
                    data += &format!("{}: {}\r\n", name, value);
                }
                "to" => data += &format!("To: {};tag=registrar\r\n", value),
                _ => {}
            }
        }
        data += headers;
        data += "Content-Length: 0\r\n\r\n";
        self.send(&data);
    }

    /// Answers a REGISTER with a 200 binding our contact for `expires`
    /// seconds, along with another device's
    fn registered(&mut self, register: &SipMessage, expires: u32) {
        self.respond(
            register,
            "200 OK",
            &format!(
                "Contact: <{}>;expires=3600, <{}>;expires={}\r\n\
P-Associated-URI: <{}>, <tel:+15551234>\r\n",
                OTHER_CONTACT, CONTACT, expires, IMPU
            ),
        );
    }

    fn registration_event(&self) -> String {
        self.registration_events
            .recv_timeout(Duration::from_secs(5))
            .expect("a registration event")
    }

    fn flow_event(&self) -> String {
        self.flow_events
            .recv_timeout(Duration::from_secs(5))
            .expect("a flow event")
    }

    /// Registers, answering the challenge, and accepts the subscription to
    /// the registration state, the dialog of which it gives
    fn register(&mut self, expires: u32) -> Subscription {
        let register = self.next_request("REGISTER");
        self.respond(
            &register,
            "401 Unauthorized",
            "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n1\", algorithm=MD5, qop=\"auth\"\r\n",
        );
        let register = self.next_request("REGISTER");
        assert!(header_value(&register, "Authorization").contains("nonce=\"n1\""));
        self.registered(&register, expires);
        assert_eq!(self.registration_event(), format!("Registered {}", IMPU));

        let subscribe = self.next_request("SUBSCRIBE");
        assert_eq!(header_value(&subscribe, "Event"), "reg");
        self.respond(
            &subscribe,
            "200 OK",
            "Expires: 600\r\nContact: <sip:registrar@192.0.2.1:5060;transport=tcp>\r\n",
        );

        Subscription {
            call_id: header_value(&subscribe, "Call-ID"),
            from: header_value(&subscribe, "From"),
            seq: 0,
        }
    }

    /// Sends a NOTIFY in `subscription` and checks it is answered
    fn notify(&mut self, subscription: &mut Subscription, state: &str, body: &str) {
        self.send_notify(subscription, state, body);

        let response = self.next();
        match &response {
            SipMessage::Response(line, _, _) => assert_eq!(line.status_code, 200),
            _ => panic!("not a response: {:?}", first_line(&response)),
        }
    }

    fn send_notify(&mut self, subscription: &mut Subscription, state: &str, body: &str) {
        subscription.seq += 1;
        let notify = format!(
            "NOTIFY {};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKnotify{}\r\n\
From: <{}>;tag=registrar\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {} NOTIFY\r\n\
Contact: <sip:registrar@192.0.2.1:5060;transport=tcp>\r\n\
Event: reg\r\n\
Subscription-State: {}\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/reginfo+xml\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
            CONTACT,
            subscription.seq,
            IMPU,
            subscription.from,
            subscription.call_id,
            subscription.seq,
            state,
            body.len(),
            body
        );
        self.send(&notify);
    }
}

/// The dialog of the subscription to the registration state
struct Subscription {
    call_id: String,
    from: String,
    seq: u32,
}

fn first_line(message: &SipMessage) -> String {
    match message {
        SipMessage::Request(line, _, _) => String::from_utf8_lossy(&line.method).into_owned(),
        SipMessage::Response(line, _, _) => line.status_code.to_string(),
        _ => String::from("ping or pong"),
    }
}

fn header_value(message: &SipMessage, name: &str) -> String {
    let headers = message.headers().unwrap();
    match header::search(headers, name.as_bytes(), true) {
        Some(header) => String::from_utf8_lossy(header.get_value()).into_owned(),
        None => String::new(),
    }
}

/// A reginfo document with our contact, and another device's, in the states
/// and with the events given
fn reginfo(state: &str, ours: Option<(&str, &str, &str)>, other: Option<(&str, &str)>) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\"?>\
<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"0\" state=\"{}\">\
<registration aor=\"{}\" id=\"a7\" state=\"active\">",
        state, IMPU
    );
    if let Some((state, event, extra)) = ours {
        xml += &format!(
            "<contact id=\"1\" state=\"{}\" event=\"{}\" {}><uri>{}</uri></contact>",
            state, event, extra, CONTACT
        );
    }
    if let Some((state, event)) = other {
        xml += &format!(
            "<contact id=\"2\" state=\"{}\" event=\"{}\"><uri>{}</uri></contact>",
            state, event, OTHER_CONTACT
        );
    }
    xml + "</registration></reginfo>"
}

#[test]
fn a_registration_is_refreshed_before_it_ends() {
    let mut registrar = Registrar::start();

    // the time our contact is given, not the other device's
    registrar.register(4);

    // half of the 4 s
    let refresh = registrar.next_request("REGISTER");
    assert!(header_value(&refresh, "Contact").ends_with(";expires=3000"));
    assert!(header_value(&refresh, "Authorization").contains("nonce=\"n1\""));
    registrar.registered(&refresh, 4);
    assert_eq!(registrar.registration_event(), "Refreshed");

    // and again
    let refresh = registrar.next_request("REGISTER");
    registrar.registered(&refresh, 3600);
    assert_eq!(registrar.registration_event(), "Refreshed");
    registrar.silence();
}

#[test]
fn a_registration_too_brief_or_with_outbound_is_made_again_as_the_registrar_asks() {
    let mut registrar = Registrar::start();

    let register = registrar.next_request("REGISTER");
    let contact = header_value(&register, "Contact");
    assert!(contact.contains(";reg-id=1;"), "{}", contact);
    assert!(contact.ends_with(";expires=3000"), "{}", contact);
    assert_eq!(header_value(&register, "Supported"), "path,gruu,outbound");
    registrar.respond(&register, "423 Interval Too Brief", "Min-Expires: 3600\r\n");

    let register = registrar.next_request("REGISTER");
    let contact = header_value(&register, "Contact");
    assert!(contact.ends_with(";expires=3600"), "{}", contact);
    registrar.respond(&register, "439 First Hop Lacks Outbound Support", "");

    let register = registrar.next_request("REGISTER");
    let contact = header_value(&register, "Contact");
    assert!(!contact.contains("reg-id"), "{}", contact);
    assert!(contact.ends_with(";expires=3600"), "{}", contact);
    assert_eq!(header_value(&register, "Supported"), "path,gruu");
    registrar.registered(&register, 3600);
    assert_eq!(
        registrar.registration_event(),
        format!("Registered {}", IMPU)
    );

    // a Min-Expires no longer than asked for already ends it
    let mut registrar = Registrar::start();
    let register = registrar.next_request("REGISTER");
    registrar.respond(&register, "423 Interval Too Brief", "Min-Expires: 3000\r\n");
    assert_eq!(registrar.registration_event(), "Released Backoff");
    registrar.silence();
}

#[test]
fn a_challenge_to_an_answer_refuses_it_unless_the_nonce_was_stale() {
    let mut registrar = Registrar::start();

    let register = registrar.next_request("REGISTER");
    registrar.respond(
        &register,
        "401 Unauthorized",
        "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n1\", algorithm=MD5, qop=\"auth\"\r\n",
    );

    let register = registrar.next_request("REGISTER");
    assert!(header_value(&register, "Authorization").contains("nonce=\"n1\""));
    registrar.respond(
        &register,
        "401 Unauthorized",
        "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n2\", algorithm=MD5, qop=\"auth\", stale=true\r\n",
    );

    let register = registrar.next_request("REGISTER");
    assert!(header_value(&register, "Authorization").contains("nonce=\"n2\""));
    registrar.respond(
        &register,
        "401 Unauthorized",
        "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n3\", algorithm=MD5, qop=\"auth\"\r\n",
    );

    assert_eq!(registrar.registration_event(), "Released Backoff");
    registrar.silence();
}

#[test]
fn a_refusal_says_when_to_register_again() {
    for (status, headers, expected) in [
        (
            "503 Service Unavailable",
            "Retry-After: 120\r\n",
            "Released After(120s)",
        ),
        (
            "503 Service Unavailable",
            "Retry-After: 120 (maintenance);duration=60\r\n",
            "Released After(120s)",
        ),
        ("403 Forbidden", "", "Released Backoff"),
        ("200 OK", "Expires: 0\r\n", "Released Backoff"),
    ] {
        let mut registrar = Registrar::start();
        let register = registrar.next_request("REGISTER");
        registrar.respond(&register, status, headers);
        assert_eq!(registrar.registration_event(), expected, "{}", status);
    }
}

#[test]
fn the_registration_state_is_followed() {
    let mut registrar = Registrar::start();
    let mut subscription = registrar.register(3600);

    registrar.notify(
        &mut subscription,
        "active;expires=600",
        &reginfo(
            "full",
            Some(("active", "registered", "")),
            Some(("active", "registered")),
        ),
    );
    assert_eq!(registrar.flow_event(), format!("Registered {}", IMPU));

    // another device leaving is none of ours
    registrar.notify(
        &mut subscription,
        "active;expires=600",
        &reginfo("partial", None, Some(("terminated", "deactivated"))),
    );
    assert_eq!(
        registrar
            .flow_events
            .recv_timeout(Duration::from_millis(500)),
        Err(RecvTimeoutError::Timeout)
    );

    // the network shortens ours, to have it authenticated again: a REGISTER
    // in half the time left
    registrar.notify(
        &mut subscription,
        "active;expires=600",
        &reginfo(
            "partial",
            Some(("active", "shortened", "expires=\"2\"")),
            None,
        ),
    );
    assert_eq!(registrar.flow_event(), format!("Registered {}", IMPU));
    let register = registrar.next_request("REGISTER");
    registrar.registered(&register, 3600);
    assert_eq!(registrar.registration_event(), "Refreshed");

    // and deactivates it: register again at once
    registrar.notify(
        &mut subscription,
        "active;expires=600",
        &reginfo("partial", Some(("terminated", "deactivated", "")), None),
    );
    assert_eq!(registrar.flow_event(), "Lost Now");
}

#[test]
fn a_registration_on_probation_is_made_again_once_the_time_given_is_over() {
    let mut registrar = Registrar::start();
    let mut subscription = registrar.register(3600);

    registrar.notify(
        &mut subscription,
        "active;expires=600",
        &reginfo(
            "partial",
            Some(("terminated", "probation", "retry-after=\"300\"")),
            None,
        ),
    );
    assert_eq!(registrar.flow_event(), "Lost After(300s)");
}

#[test]
fn a_full_state_without_our_contact_has_it_lost() {
    let mut registrar = Registrar::start();
    let mut subscription = registrar.register(3600);

    registrar.notify(
        &mut subscription,
        "active;expires=600",
        &reginfo("full", None, Some(("active", "registered"))),
    );
    assert_eq!(registrar.flow_event(), "Lost Now");
}

#[test]
fn a_subscription_terminated_is_made_again() {
    let mut registrar = Registrar::start();
    let mut subscription = registrar.register(3600);

    registrar.send_notify(
        &mut subscription,
        "terminated;reason=timeout",
        &reginfo("full", Some(("active", "registered", "")), None),
    );
    assert_eq!(registrar.flow_event(), format!("Registered {}", IMPU));

    // the registration stands, and its state is subscribed to again, the
    // SUBSCRIBE perhaps sent ahead of the 200 to the NOTIFY
    let mut messages = [registrar.next(), registrar.next()];
    messages.sort_by_key(|message| first_line(message) != "200");
    assert_eq!(first_line(&messages[0]), "200");
    assert_eq!(first_line(&messages[1]), "SUBSCRIBE");
    assert_eq!(header_value(&messages[1], "Event"), "reg");
    assert_ne!(header_value(&messages[1], "Call-ID"), subscription.call_id);
}
