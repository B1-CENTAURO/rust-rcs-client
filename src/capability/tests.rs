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

//! OPTIONS exchanged with a peer the test scripts, over a pipe in place of
//! the connection to the P-CSCF

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_rcs_core::sip::sip_subscription::SubscriptionManager;
use rust_rcs_core::sip::sip_transaction::SipTransactionManager;
use rust_rcs_core::sip::sip_transport::{setup_sip_transport, SipTransportType};
use rust_rcs_core::sip::{SipCore, SipMessage, SipTransport, TransactionHandler, MESSAGE, OPTIONS};
use tokio::runtime::Runtime;

use crate::messaging::cpm::session_tests::{
    body, header_value, request_uri, status_code, to_tag, Peer, IMPU, INSTANCE, PEER,
    TRANSPORT_ADDRESS,
};

use rust_rcs_core::sip::ClientTransactionCallbacks;

use super::{
    Capabilities, CapabilityService, CapabilityServiceWrapper, OptionsQuery, FEATURE_TAGS,
};

struct Client {
    rt: Arc<Runtime>,
    tm: Arc<SipTransactionManager>,
    service: Arc<CapabilityService>,
    _core: Arc<SipCore>,
}

impl Client {
    /// Asks `PEER` for its capabilities, and a receiver of what it answered
    fn query(&self) -> mpsc::Receiver<Capabilities> {
        let (tx, rx) = mpsc::channel();
        self.service.query(
            PEER,
            move |capabilities| {
                let _ = tx.send(capabilities);
            },
            &self.tm,
            &self.rt,
        );
        rx
    }
}

/// A client with the capability service, `registered` or not
fn start(registered: bool) -> (Client, Peer) {
    let rt = Arc::new(Runtime::new().unwrap());
    let (tm, tm_events) = SipTransactionManager::new(&rt);
    let tm = Arc::new(tm);
    let sm = Arc::new(SubscriptionManager::new(500));
    let service = Arc::new(CapabilityService::new());
    let handlers: Vec<Box<dyn TransactionHandler + Send + Sync>> =
        vec![Box::new(CapabilityServiceWrapper {
            service: Arc::clone(&service),
        })];
    let core = Arc::new(SipCore::new(
        &sm,
        &tm,
        tm_events,
        vec![MESSAGE, OPTIONS],
        handlers,
        &rt,
    ));

    let transport = Arc::new(SipTransport::new::<tokio::io::DuplexStream>(
        String::from(TRANSPORT_ADDRESS),
        SipTransportType::TCP,
    ));
    let (ours, theirs) = tokio::io::duplex(65536);
    let tx = setup_sip_transport(&transport, ours, tm.get_ctrl_itf(), Arc::clone(&rt), || {});
    tm.register_sip_transport(Arc::clone(&transport), tx);

    if registered {
        core.set_default_public_identity(
            String::from(IMPU),
            String::from(INSTANCE),
            Arc::clone(&transport),
        );
        service.set_registered_public_identity(
            String::from(IMPU),
            String::from(INSTANCE),
            Arc::clone(&transport),
        );
    }

    (
        Client {
            rt: Arc::clone(&rt),
            tm,
            service,
            _core: core,
        },
        Peer::over(rt, theirs),
    )
}

/// An OPTIONS of the peer
fn options(call_id: &str) -> String {
    format!(
        "OPTIONS {} SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
Max-Forwards: 70\r\n\
From: <{}>;tag=peer\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 OPTIONS\r\n\
Contact: <sip:+15559876@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"\r\n\
Content-Length: 0\r\n\
\r\n",
        IMPU, call_id, PEER, IMPU, call_id
    )
}

/// The peer's answer to `request`, with `contact` if given
fn answer(request: &SipMessage, status: &str, contact: Option<&str>) -> String {
    let mut answer = format!("SIP/2.0 {}\r\n", status);
    for name in ["Via", "From", "Call-ID", "CSeq"] {
        answer.push_str(&format!("{}: {}\r\n", name, header_value(request, name)));
    }
    answer.push_str(&format!("To: {};tag=them\r\n", header_value(request, "To")));
    if let Some(contact) = contact {
        answer.push_str(&format!("Contact: {}\r\n", contact));
    }
    answer.push_str("Content-Length: 0\r\n\r\n");
    answer
}

fn our_contact(extra: &str) -> String {
    format!(
        "<{}>;+sip.instance=\"{}\";{}{}",
        IMPU, INSTANCE, FEATURE_TAGS, extra
    )
}

#[test]
fn an_options_is_answered_with_the_capabilities_of_this_client() {
    let (_client, mut peer) = start(true);
    peer.send(&options("options-1"));

    let response = peer.next_response();
    assert_eq!(status_code(&response), 200);
    assert_eq!(header_value(&response, "Contact"), our_contact(""));
    assert!(header_value(&response, "Allow").contains("OPTIONS"));
    assert_eq!(header_value(&response, "Call-ID"), "options-1");
    assert!(!to_tag(&response).is_empty());
    assert_eq!(header_value(&response, "Content-Length"), "0");
    assert_eq!(body(&response), "");
}

#[test]
fn an_options_while_not_registered_is_answered_as_unavailable() {
    let (_client, mut peer) = start(false);
    peer.send(&options("options-2"));
    assert_eq!(status_code(&peer.next_response()), 480);
}

#[test]
fn feature_tags_besides_are_told_while_they_apply() {
    let (client, mut peer) = start(true);
    let applying = Arc::new(AtomicBool::new(true));
    let applies = Arc::clone(&applying);
    client.service.set_extra_feature_tags(move || {
        applies.load(Ordering::SeqCst).then(|| {
            String::from("+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"42\"")
        })
    });

    peer.send(&options("options-3"));
    assert_eq!(
        header_value(&peer.next_response(), "Contact"),
        our_contact(";+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"42\"")
    );

    // in what is asked too
    let _answered = client.query();
    let request = peer.next_request("OPTIONS");
    assert!(header_value(&request, "Contact").ends_with("+g.gsma.rcs.mls.mls-kds=\"42\""));

    applying.store(false, Ordering::SeqCst);
    peer.send(&options("options-4"));
    assert_eq!(
        header_value(&peer.next_response(), "Contact"),
        our_contact("")
    );

    // none given are none told
    client
        .service
        .set_extra_feature_tags(|| Some(String::new()));
    peer.send(&options("options-5"));
    assert_eq!(
        header_value(&peer.next_response(), "Contact"),
        our_contact("")
    );
}

#[test]
fn other_requests_are_left_to_other_services() {
    let (_client, mut peer) = start(true);
    peer.send(&options("options-6").replace("OPTIONS", "MESSAGE"));
    let response = peer.next_response();
    assert_ne!(status_code(&response), 200);
    assert_eq!(header_value(&response, "Contact"), "");
}

#[test]
fn a_query_tells_the_feature_tags_the_contact_answers_with() {
    let (client, mut peer) = start(true);
    let answered = client.query();

    let request = peer.next_request("OPTIONS");
    assert_eq!(request_uri(&request), PEER);
    assert_eq!(header_value(&request, "To"), format!("<{}>", PEER));
    assert!(header_value(&request, "From").starts_with(&format!("<{}>;tag=", IMPU)));
    assert_eq!(header_value(&request, "Contact"), our_contact(""));
    assert_eq!(header_value(&request, "P-Preferred-Identity"), IMPU);
    assert_eq!(header_value(&request, "CSeq"), "1 OPTIONS");
    assert_eq!(body(&request), "", "no SDP");

    peer.send(&answer(
        &request,
        "200 OK",
        Some("<sip:+15559876@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"42\";automata"),
    ));
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(5)),
        Ok(Capabilities {
            status_code: 200,
            feature_tags: String::from("+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"42\";automata"),
        })
    );
}

#[test]
fn a_query_answered_otherwise_tells_its_status() {
    let (client, mut peer) = start(true);
    for (status, code) in [
        ("480 Temporarily Unavailable", 480),
        ("404 Not Found", 404),
        ("200 OK", 200),
    ] {
        let answered = client.query();
        let request = peer.next_request("OPTIONS");
        // the Contact of other answers is not taken
        let contact = (code != 200).then_some(
            "<sip:+15559876@192.0.2.1:5060>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        );
        peer.send(&answer(&request, status, contact));
        assert_eq!(
            answered.recv_timeout(Duration::from_secs(5)),
            Ok(Capabilities {
                status_code: code,
                feature_tags: String::new(),
            }),
            "{}",
            status
        );
    }
}

#[test]
fn a_query_while_not_registered_is_forbidden() {
    let (client, mut peer) = start(false);
    assert_eq!(
        client.query().recv_timeout(Duration::from_secs(5)),
        Ok(Capabilities {
            status_code: 403,
            feature_tags: String::new(),
        })
    );
    peer.silence();
}

#[test]
fn a_query_that_cannot_be_sent_is_told_as_unanswered_once() {
    let (tx, rx) = mpsc::channel();
    let query = OptionsQuery {
        callback: Mutex::new(Some(Box::new(move |capabilities| {
            let _ = tx.send(capabilities);
        }))),
    };
    query.on_transport_error();
    query.on_transport_error();
    assert_eq!(
        rx.try_iter().collect::<Vec<Capabilities>>(),
        vec![Capabilities {
            status_code: 0,
            feature_tags: String::new(),
        }]
    );
}
