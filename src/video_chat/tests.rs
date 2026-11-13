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
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use prost::Message;
use tokio::runtime::{Builder, Runtime};

use crate::provisioning::characteristic::Characteristic;
use crate::provisioning::rcs_application::RcsApplication;

use super::proto::video_chat_message::Event as Signal;
use super::proto::*;
use super::*;
// the event told to the app, not the one reported
use super::VideoChatEvent;

const BOB: &str = "tel:+15550002";
const ME: &str = "tel:+15550001";
const REPORTING_URI: &str = "sip:mivc@example.com";

/// What the service sent and reported, the status code sends are answered
/// with
struct Link {
    sent: Mutex<Vec<(String, VideoChatMessage)>>,
    reports: Mutex<Vec<VideoChatEventNotification>>,
    status_code: Mutex<u16>,
}

impl VideoChatLink for Link {
    fn send(&self, contact: &str, message: Vec<u8>, sent: Box<dyn FnOnce(u16) + Send + Sync>) {
        let message = VideoChatMessage::decode(&message[..]).unwrap();
        self.sent
            .lock()
            .unwrap()
            .push((String::from(contact), message));
        let status_code = *self.status_code.lock().unwrap();
        sent(status_code);
    }

    fn report(&self, reporting_uri: &str, notification: Vec<u8>) {
        assert_eq!(reporting_uri, REPORTING_URI);
        let notification = VideoChatEventNotification::decode(&notification[..]).unwrap();
        self.reports.lock().unwrap().push(notification);
    }

    fn registered_uri(&self) -> Option<String> {
        Some(String::from(ME))
    }
}

type Told = Arc<Mutex<Vec<(String, String, VideoChatEvent)>>>;

struct Device {
    service: Arc<VideoChatService>,
    link: Arc<Link>,
    told: Told,
    rt: Runtime,
}

/// A device taking RCS Video Chats, with the configuration of `technology`,
/// on a clock that moves only as the test has it
fn device_with(technology: i32) -> Device {
    let rt = Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap();
    let link = Arc::new(Link {
        sent: Mutex::new(Vec::new()),
        reports: Mutex::new(Vec::new()),
        status_code: Mutex::new(200),
    });
    let service = VideoChatService::new(
        Arc::clone(&link) as Arc<dyn VideoChatLink>,
        rt.handle().clone(),
    );
    service.set_config(VideoChatConfig {
        technology,
        reporting_uri: Some(String::from(REPORTING_URI)),
        ..VideoChatConfig::default()
    });
    let told: Told = Arc::new(Mutex::new(Vec::new()));
    let telling = Arc::clone(&told);
    service.set_listener(Arc::new(move |call_id, contact, event| {
        telling
            .lock()
            .unwrap()
            .push((String::from(call_id), String::from(contact), event));
    }));
    Device {
        service,
        link,
        told,
        rt,
    }
}

fn a_device() -> Device {
    device_with(3)
}

impl Device {
    /// The signals sent since last asked, to whom
    fn sent(&self) -> Vec<(String, String, Signal)> {
        std::mem::take(&mut *self.link.sent.lock().unwrap())
            .into_iter()
            .map(|(contact, message)| (contact, message.call_id, message.event.unwrap()))
            .collect()
    }

    /// The events told since last asked
    fn told(&self) -> Vec<(String, String, VideoChatEvent)> {
        std::mem::take(&mut *self.told.lock().unwrap())
    }

    /// The JOINs and LEAVEs reported since last asked, with their callee
    fn reports(&self) -> Vec<(i32, String)> {
        std::mem::take(&mut *self.link.reports.lock().unwrap())
            .into_iter()
            .map(|report| (report.video_chat_event, report.one_to_one_participant_uri))
            .collect()
    }

    /// `signal` of the call `call_id` from `contact`, sent now
    fn receive(&self, contact: &str, call_id: &str, signal: Signal) {
        self.receive_sent(contact, call_id, signal, &date(Duration::ZERO));
    }

    fn receive_sent(&self, contact: &str, call_id: &str, signal: Signal, date: &str) {
        let message = VideoChatMessage {
            call_id: String::from(call_id),
            event: Some(signal),
        };
        self.service
            .on_message(contact, date, &message.encode_to_vec());
    }

    /// The clock moved on by `by`, the timers due run
    fn after(&self, by: Duration) {
        self.rt
            .block_on(async move { tokio::time::sleep(by).await });
    }
}

/// The CPIM DateTime of a message sent `ago`
fn date(ago: Duration) -> String {
    DateTime::<Utc>::from(SystemTime::now() - ago).to_rfc3339_opts(SecondsFormat::Millis, true)
}

const MS: Duration = Duration::from_millis(1);

fn offer(sdp: &str) -> Signal {
    Signal::CallInvitation(CallInvitation {
        sdp_offer: String::from(sdp),
    })
}

fn accept(sdp: &str) -> Signal {
    Signal::AcceptInvitation(AcceptInvitation {
        sdp_answer: String::from(sdp),
    })
}

fn hangup(reason: HangupReason) -> Signal {
    Signal::Hangup(Hangup {
        hangup_reason: reason as i32,
    })
}

fn cancel(reason: CancelReason) -> Signal {
    Signal::CancelInvitation(CancelInvitation {
        cancel_reason: reason as i32,
    })
}

fn reject(reason: RejectReason) -> Signal {
    Signal::RejectInvitation(RejectInvitation {
        reject_reason: reason as i32,
    })
}

const JOIN: i32 = proto::VideoChatEvent::Join as i32;
const LEAVE: i32 = proto::VideoChatEvent::Leave as i32;

/// A device in a call with Bob it started, Bob alerted
fn calling_bob() -> (Device, String) {
    let device = a_device();
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    device.sent();
    device.receive(BOB, &call_id, Signal::AckInvitation(AckInvitation {}));
    device.told();
    (device, call_id)
}

/// A device in a call with Bob that Bob offered, ringing
fn called_by_bob() -> Device {
    let device = a_device();
    device.receive(BOB, "bob-call", offer("bob's offer"));
    device.sent();
    device.told();
    device
}

#[test]
fn a_call_is_offered_with_the_sdp_offer_of_the_app() {
    let device = a_device();
    let call_id = device.service.start_call(BOB, "v=0 offer").unwrap();
    assert_eq!(
        device.sent(),
        [(String::from(BOB), call_id.clone(), offer("v=0 offer"))]
    );
    assert!(device.told().is_empty());

    // one at a time
    assert_eq!(device.service.start_call("tel:+15550003", "offer"), None);
    device.service.hang_up(&call_id);
    assert!(device
        .service
        .start_call("tel:+15550003", "offer")
        .is_some());
}

#[test]
fn calls_are_taken_while_the_service_provider_enables_rcs_video_chat_and_the_app_takes_them() {
    for (technology, enabled) in [(0, false), (1, false), (2, true), (3, true)] {
        let device = device_with(technology);
        assert_eq!(
            device.service.feature_tag(),
            enabled.then_some("+g.gsma.rcs.videochat"),
            "{}",
            technology
        );
        assert_eq!(
            device.service.start_call(BOB, "offer").is_some(),
            enabled,
            "{}",
            technology
        );
    }

    // nor without a listener, offered calls going unanswered then
    let rt = Builder::new_current_thread().enable_time().build().unwrap();
    let link = Arc::new(Link {
        sent: Mutex::new(Vec::new()),
        reports: Mutex::new(Vec::new()),
        status_code: Mutex::new(200),
    });
    let service = VideoChatService::new(
        Arc::clone(&link) as Arc<dyn VideoChatLink>,
        rt.handle().clone(),
    );
    service.set_config(VideoChatConfig {
        technology: 3,
        ..VideoChatConfig::default()
    });
    assert_eq!(service.feature_tag(), None);
    assert_eq!(service.start_call(BOB, "offer"), None);
    let message = VideoChatMessage {
        call_id: String::from("bob-call"),
        event: Some(offer("offer")),
    };
    service.on_message(BOB, &date(Duration::ZERO), &message.encode_to_vec());
    assert!(link.sent.lock().unwrap().is_empty());
}

#[test]
fn the_caller_is_told_the_callee_is_alerted_and_answers() {
    let device = a_device();
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    device.sent();

    // RCC.07 v18.0 sections 3.7.5.4.2, 3.7.5.4.3
    device.receive(BOB, &call_id, Signal::AckInvitation(AckInvitation {}));
    assert_eq!(
        device.told(),
        [(call_id.clone(), String::from(BOB), VideoChatEvent::Alerting)]
    );
    // told once, though acknowledged again
    device.receive(BOB, &call_id, Signal::AckInvitation(AckInvitation {}));
    assert!(device.told().is_empty());
    device.receive(BOB, &call_id, accept("bob's answer"));
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::Answered {
                sdp_answer: String::from("bob's answer")
            }
        )]
    );

    // joined once the media connects, Bob its callee (section 3.7.5.2.5)
    assert!(device.service.media_connected(&call_id));
    assert_eq!(device.reports(), [(JOIN, String::from(BOB))]);
    assert!(device.service.media_connected(&call_id));
    assert!(device.reports().is_empty());

    // hung up, and left (section 3.7.5.4.4)
    assert!(device.service.hang_up(&call_id));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            hangup(HangupReason::UserInitiated)
        )]
    );
    assert_eq!(device.reports(), [(LEAVE, String::from(BOB))]);
    // Bob's Hangup in turn is let go of
    device.receive(BOB, &call_id, hangup(HangupReason::UserInitiated));
    assert!(device.sent().is_empty());
    assert!(device.told().is_empty());
    assert!(!device.service.hang_up(&call_id));

    // nothing reported without an MIVC REPORTING URI
    let (device, call_id) = calling_bob();
    device.service.set_config(VideoChatConfig {
        technology: 3,
        ..VideoChatConfig::default()
    });
    device.receive(BOB, &call_id, accept("bob's answer"));
    assert!(device.service.media_connected(&call_id));
    assert!(device.service.hang_up(&call_id));
    assert!(device.reports().is_empty());
}

#[test]
fn a_call_offered_is_acknowledged_and_answered_with_the_sdp_answer_of_the_app() {
    let device = a_device();
    device.receive(BOB, "bob-call", offer("bob's offer"));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            Signal::AckInvitation(AckInvitation {})
        )]
    );
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Incoming {
                sdp_offer: String::from("bob's offer")
            }
        )]
    );
    // sent again, let go of
    device.receive(BOB, "bob-call", offer("bob's offer"));
    assert!(device.sent().is_empty());
    assert!(device.told().is_empty());

    assert!(device.service.accept_call("bob-call", "my answer"));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            accept("my answer")
        )]
    );
    // answered once only
    assert!(!device.service.accept_call("bob-call", "my answer"));
    assert!(device.sent().is_empty());

    // joined, the device its callee
    assert!(device.service.media_connected("bob-call"));
    assert_eq!(device.reports(), [(JOIN, String::from(ME))]);

    // Bob hangs up, which is answered in turn with the same reason
    device.receive(BOB, "bob-call", hangup(HangupReason::UserInitiated));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            hangup(HangupReason::UserInitiated)
        )]
    );
    assert_eq!(device.reports(), [(LEAVE, String::from(ME))]);
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Ended(HangupReason::UserInitiated as i32)
        )]
    );
    assert!(!device.service.media_connected("bob-call"));
}

#[test]
fn a_call_not_acknowledged_or_not_answered_in_time_is_cancelled() {
    // no AckInvitation within Timer_Alpha (section 3.7.5.4.8.1.1)
    let device = a_device();
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    device.sent();
    device.after(ANSWERED_WITHIN - MS);
    assert!(device.sent().is_empty());
    device.after(2 * MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            cancel(CancelReason::Timeout)
        )]
    );
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::NotAnswered
        )]
    );
    assert!(!device.service.hang_up(&call_id));

    // acknowledged, but not answered within Timer_Beta (section 3.7.5.4.7)
    let (device, call_id) = calling_bob();
    device.after(ANSWERED_WITHIN - MS);
    assert!(device.sent().is_empty());
    device.after(2 * MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            cancel(CancelReason::Timeout)
        )]
    );
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::NotAnswered
        )]
    );

    // answered in time
    let (device, call_id) = calling_bob();
    device.after(ANSWERED_WITHIN - MS);
    device.receive(BOB, &call_id, accept("answer"));
    device.told();
    device.after(2 * MS);
    assert!(device.sent().is_empty());
    assert!(device.told().is_empty());
}

#[test]
fn a_call_offered_rings_until_too_old_to_answer() {
    // sent 20 s ago: rings 12 s more (Timer_Gamma, section 3.7.5.2.4.3)
    let device = a_device();
    let sent = Duration::from_secs(20);
    device.receive_sent(BOB, "bob-call", offer("offer"), &date(sent));
    assert_eq!(device.sent().len(), 1, "acknowledged");
    device.told();
    device.after(ANSWERED_WITHIN - sent - Duration::from_millis(100));
    assert!(device.told().is_empty());
    device.after(Duration::from_millis(200));
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Missed
        )]
    );
    assert!(device.sent().is_empty(), "the caller cancels it");
    assert!(!device.service.accept_call("bob-call", "answer"));

    // stored and forwarded too long ago: missed, not acknowledged (section
    // 3.7.5.4.8.1.4)
    let device = a_device();
    device.receive_sent(BOB, "bob-call", offer("offer"), &date(ANSWERED_WITHIN + MS));
    assert!(device.sent().is_empty());
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Missed
        )]
    );
    assert!(!device.service.accept_call("bob-call", "answer"));

    // from a clock ahead, or a DateTime not read: rings Timer_Gamma long
    for date in [
        DateTime::<Utc>::from(SystemTime::now() + Duration::from_secs(600)).to_rfc3339(),
        String::from("not a date"),
    ] {
        let device = a_device();
        device.receive_sent(BOB, "bob-call", offer("offer"), &date);
        device.told();
        device.after(ANSWERED_WITHIN - MS);
        assert!(device.told().is_empty(), "{}", date);
        device.after(2 * MS);
        assert_eq!(device.told().len(), 1, "{}", date);
    }
}

#[test]
fn a_call_offered_is_rejected_by_the_user_or_while_another_goes_on() {
    // section 3.7.5.4.5
    let device = called_by_bob();
    assert!(device.service.hang_up("bob-call"));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            reject(RejectReason::UserReject)
        )]
    );
    assert!(device.told().is_empty());
    assert!(device.reports().is_empty());

    // REJECT_REASON_ALREADY_IN_PROGRESS, the call missed
    let device = called_by_bob();
    device.receive("tel:+15550003", "carol-call", offer("offer"));
    assert_eq!(
        device.sent(),
        [(
            String::from("tel:+15550003"),
            String::from("carol-call"),
            reject(RejectReason::AlreadyInProgress)
        )]
    );
    assert_eq!(
        device.told(),
        [(
            String::from("carol-call"),
            String::from("tel:+15550003"),
            VideoChatEvent::Missed
        )]
    );
    // Bob's goes on
    assert!(device.service.accept_call("bob-call", "answer"));

    // the caller told
    let device = a_device();
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    device.receive(BOB, &call_id, reject(RejectReason::UserReject));
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::Rejected(RejectReason::UserReject as i32)
        )]
    );
    // no timer runs on
    device.sent();
    device.after(ANSWERED_WITHIN + MS);
    assert!(device.sent().is_empty());
    assert!(device.told().is_empty());
}

#[test]
fn a_call_hung_up_by_the_callee_before_it_answers_ends_without_a_hangup_in_turn() {
    let (device, call_id) = calling_bob();
    device.receive(BOB, &call_id, hangup(HangupReason::UserInitiated));
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::Ended(HangupReason::UserInitiated as i32)
        )]
    );
    assert!(device.sent().is_empty());
    assert!(device.reports().is_empty());
    device.after(ANSWERED_WITHIN + MS);
    assert!(device.sent().is_empty());
    assert!(!device.service.hang_up(&call_id));
}

#[test]
fn a_call_is_cancelled_before_it_is_answered() {
    // section 3.7.5.4.6
    let (device, call_id) = calling_bob();
    assert!(device.service.hang_up(&call_id));
    assert_eq!(
        device.sent(),
        [(String::from(BOB), call_id, cancel(CancelReason::UserCancel))]
    );
    device.after(ANSWERED_WITHIN + MS);
    assert!(device.sent().is_empty());
    assert!(device.told().is_empty());

    // the callee told it missed, as of a Hangup before it answered
    for signal in [
        cancel(CancelReason::UserCancel),
        hangup(HangupReason::UserInitiated),
    ] {
        let device = called_by_bob();
        device.receive(BOB, "bob-call", signal);
        assert_eq!(
            device.told(),
            [(
                String::from("bob-call"),
                String::from(BOB),
                VideoChatEvent::Missed
            )]
        );
        assert!(device.sent().is_empty());
        assert!(!device.service.accept_call("bob-call", "answer"));
    }
}

#[test]
fn a_call_whose_media_does_not_connect_in_time_fails() {
    // Timer_Delta of the caller (section 3.7.5.4.8.1.2)
    let (device, call_id) = calling_bob();
    device.receive(BOB, &call_id, accept("answer"));
    device.told();
    device.after(CONNECTED_WITHIN - MS);
    assert!(device.sent().is_empty());
    device.after(2 * MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            hangup(HangupReason::ClientTimeout)
        )]
    );
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::Ended(HangupReason::ClientTimeout as i32)
        )]
    );
    // never joined
    assert!(device.reports().is_empty());

    // of the callee
    let device = called_by_bob();
    device.service.accept_call("bob-call", "answer");
    device.sent();
    device.after(CONNECTED_WITHIN + MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            hangup(HangupReason::ClientTimeout)
        )]
    );

    // connected in time
    let device = called_by_bob();
    device.service.accept_call("bob-call", "answer");
    device.after(CONNECTED_WITHIN - MS);
    device.service.media_connected("bob-call");
    device.sent();
    device.after(CONNECTED_WITHIN);
    assert!(device.sent().is_empty());

    // Bob's Hangup for the same reason, answered in turn
    let device = called_by_bob();
    device.service.accept_call("bob-call", "answer");
    device.sent();
    device.receive(BOB, "bob-call", hangup(HangupReason::ClientTimeout));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            hangup(HangupReason::ClientTimeout)
        )]
    );
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Ended(HangupReason::ClientTimeout as i32)
        )]
    );
}

#[test]
fn a_call_whose_media_does_not_connect_again_in_time_fails() {
    // Timer_Epsilon (section 3.7.5.4.8.1.6)
    let (device, call_id) = calling_bob();
    device.receive(BOB, &call_id, accept("answer"));
    device.service.media_connected(&call_id);
    device.told();
    device.reports();
    assert!(device.service.media_disconnected(&call_id));
    device.after(CONNECTED_WITHIN - MS);
    assert!(device.sent().is_empty());
    device.after(2 * MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            hangup(HangupReason::ClientTimeout)
        )]
    );
    assert_eq!(device.reports(), [(LEAVE, String::from(BOB))]);
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::Ended(HangupReason::ClientTimeout as i32)
        )]
    );

    // connected again in time, joined once
    let (device, call_id) = calling_bob();
    device.receive(BOB, &call_id, accept("answer"));
    device.service.media_connected(&call_id);
    device.reports();
    device.service.media_disconnected(&call_id);
    device.after(CONNECTED_WITHIN - MS);
    assert!(device.service.media_connected(&call_id));
    assert!(device.reports().is_empty());
    device.sent();
    device.after(CONNECTED_WITHIN);
    assert!(device.sent().is_empty());

    // not before the call is answered
    let (device, call_id) = calling_bob();
    assert!(!device.service.media_disconnected(&call_id));
    assert!(!device.service.media_connected(&call_id));
}

#[test]
fn ice_candidates_are_updated_the_media_connecting_again_within_timer_delta() {
    // after an IP address change (section 3.7.5.4.8.2)
    let (device, call_id) = calling_bob();
    device.receive(BOB, &call_id, accept("answer"));
    device.service.media_connected(&call_id);
    device.told();
    assert!(device.service.update_ice_candidates(
        &call_id,
        vec![String::from("candidate:1")],
        vec![String::from("candidate:0")]
    ));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            Signal::IceCandidatesUpdate(IceCandidatesUpdate {
                add_ice_candidates: vec![String::from("candidate:1")],
                remove_ice_candidates: vec![String::from("candidate:0")],
            })
        )]
    );
    device.after(CONNECTED_WITHIN + MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            hangup(HangupReason::ClientTimeout)
        )]
    );

    // Bob's, told as reconnecting once the media connected
    let device = called_by_bob();
    device.receive(
        BOB,
        "bob-call",
        Signal::IceCandidatesUpdate(IceCandidatesUpdate {
            add_ice_candidates: vec![String::from("candidate:1")],
            remove_ice_candidates: Vec::new(),
        }),
    );
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::IceCandidates {
                add: vec![String::from("candidate:1")],
                remove: Vec::new(),
                reconnecting: false,
            }
        )]
    );
    // nor before the media first connects, which Timer_Delta waits for
    // still
    device.service.accept_call("bob-call", "answer");
    device.after(CONNECTED_WITHIN / 2);
    device.receive(
        BOB,
        "bob-call",
        Signal::IceCandidatesUpdate(IceCandidatesUpdate {
            add_ice_candidates: vec![String::from("candidate:3")],
            remove_ice_candidates: Vec::new(),
        }),
    );
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::IceCandidates {
                add: vec![String::from("candidate:3")],
                remove: Vec::new(),
                reconnecting: false,
            }
        )]
    );
    device.sent();
    device.after(CONNECTED_WITHIN / 2 + MS);
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            String::from("bob-call"),
            hangup(HangupReason::ClientTimeout)
        )]
    );

    let device = called_by_bob();
    device.service.accept_call("bob-call", "answer");
    device.service.media_connected("bob-call");
    device.sent();
    device.receive(
        BOB,
        "bob-call",
        Signal::IceCandidatesUpdate(IceCandidatesUpdate {
            add_ice_candidates: vec![String::from("candidate:2")],
            remove_ice_candidates: vec![String::from("candidate:1")],
        }),
    );
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::IceCandidates {
                add: vec![String::from("candidate:2")],
                remove: vec![String::from("candidate:1")],
                reconnecting: true,
            }
        )]
    );
    device.after(CONNECTED_WITHIN - MS);
    assert!(device.service.media_connected("bob-call"));
    device.after(CONNECTED_WITHIN);
    assert!(device.sent().is_empty());
}

#[test]
fn media_updates_go_both_ways() {
    // section 3.7.5.4.8.3
    let update = UpdateMedia {
        view_request: vec![ViewRequest {
            stream_id: Some(MediaStreamId {
                media_stream_id: String::from("user-456-video-main"),
                media_type: MediaType::Video as i32,
            }),
            resolution: Some(VideoResolution {
                height: 720,
                width: 1280,
                frame_rate: 30,
            }),
        }],
        bandwidth_constraints: Some(BandwidthConstraints {
            max_bandwidth_kbps: 2500,
            min_bandwidth_kbps: 500,
            start_bandwidth_kbps: 1000,
        }),
    };
    let (device, call_id) = calling_bob();
    assert!(device.service.update_media(&call_id, update.clone()));
    assert_eq!(
        device.sent(),
        [(
            String::from(BOB),
            call_id.clone(),
            Signal::UpdateMedia(update.clone())
        )]
    );
    device.receive(BOB, &call_id, Signal::UpdateMedia(update.clone()));
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::MediaUpdate(update.clone())
        )]
    );
    assert!(!device.service.update_media("another call", update));
}

#[test]
fn the_signals_of_a_call_are_taken_from_its_contact_alone() {
    let device = a_device();
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    device.receive("tel:+15550003", &call_id, accept("carol's answer"));
    assert!(device.told().is_empty());
    // nor for another call
    device.receive(BOB, "another call", accept("answer"));
    assert!(device.told().is_empty());
    // the contact known by a SIP URI of its number
    device.receive(
        "sip:+15550002@ims.example.com;user=phone",
        &call_id,
        accept("bob's answer"),
    );
    assert_eq!(device.told().len(), 1);
}

#[test]
fn a_call_whose_signal_cannot_be_sent_fails() {
    // the CallInvitation
    let device = a_device();
    *device.link.status_code.lock().unwrap() = 480;
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    assert_eq!(
        device.told(),
        [(
            call_id.clone(),
            String::from(BOB),
            VideoChatEvent::Failed(480)
        )]
    );
    // no timer runs on, and another call can be made
    device.after(ANSWERED_WITHIN + MS);
    assert!(device.told().is_empty());
    *device.link.status_code.lock().unwrap() = 200;
    assert!(device.service.start_call(BOB, "offer").is_some());

    // the AcceptInvitation
    let device = called_by_bob();
    *device.link.status_code.lock().unwrap() = 500;
    device.service.accept_call("bob-call", "answer");
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Failed(500)
        )]
    );

    // not the others
    let device = called_by_bob();
    *device.link.status_code.lock().unwrap() = 500;
    device
        .service
        .update_ice_candidates("bob-call", Vec::new(), Vec::new());
    assert!(device.told().is_empty());
    assert!(device.service.hang_up("bob-call"));
}

/// The video chat configuration of the Messaging of a configuration
/// document, with `parameters`
fn config_of(parameters: &str) -> VideoChatConfig {
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
    VideoChatConfig::of(&RcsApplication::new(&application))
}

#[test]
fn the_mivc_configuration_is_read_from_the_messaging_of_the_configuration() {
    // RCC.07 sections A.1.3, A.2.4
    assert_eq!(config_of(""), VideoChatConfig::default());
    assert_eq!(
        config_of(""),
        VideoChatConfig {
            technology: 0,
            turn_mandatory: false,
            turn_credentials: Vec::new(),
            reporting_uri: None,
        }
    );
    // ViLTE preferred, RCS Video Chat fallback by default
    assert_eq!(config_of(r#"<characteristic type="MIVC"/>"#).technology, 2);
    let config = config_of(
        r#"<characteristic type="MIVC">
             <parm name="mivcTechnology" value="3"/>
             <parm name="rcsVideoChatTurn" value="1"/>
             <characteristic type="TurnCredentials">
               <parm name="rcsVideoChatTurnURI" value="turn:turn1.example.com"/>
               <parm name="rcsVideoChatTurnUri" value="turns:turn2.example.com:5349"/>
               <parm name="rcsVideoChatTurnUsername" value="user"/>
               <parm name="rcsVideoChatTurnPassword" value="secret"/>
             </characteristic>
             <characteristic type="TurnCredentials">
               <parm name="rcsVideoChatTurnUri" value="turn:turn3.example.com"/>
             </characteristic>
             <parm name="mivcReportingUri" value="sip:mivc@example.com"/>
           </characteristic>"#,
    );
    assert_eq!(
        config,
        VideoChatConfig {
            technology: 3,
            turn_mandatory: true,
            turn_credentials: vec![
                TurnCredential {
                    uris: vec![
                        String::from("turn:turn1.example.com"),
                        String::from("turns:turn2.example.com:5349")
                    ],
                    username: Some(String::from("user")),
                    password: Some(String::from("secret")),
                },
                TurnCredential {
                    uris: vec![String::from("turn:turn3.example.com")],
                    username: None,
                    password: None,
                },
            ],
            reporting_uri: Some(String::from("sip:mivc@example.com")),
        }
    );
    assert!(config.enables_video_chat());
}

#[test]
fn contacts_are_the_same_by_their_uri_or_global_number() {
    assert!(same_contact(BOB, "TEL:+15550002"));
    assert!(same_contact(
        BOB,
        "sip:+15550002@ims.example.com;user=phone"
    ));
    assert!(same_contact("tel:+1-555-000-2", BOB));
    assert!(!same_contact(BOB, "tel:+15550003"));
    assert!(!same_contact(
        "sip:bob@example.com",
        "sip:alice@example.com"
    ));
    assert!(!same_contact(
        "tel:5550002;phone-context=example.com",
        "tel:5550002"
    ));
}

#[test]
fn the_app_is_told_each_event_by_its_code() {
    use super::ffi::video_chat_event_code;

    let code = |event| {
        video_chat_event_code(&event)
            .map(|(code, sdp, reason)| (code, sdp.map(String::from), reason))
    };
    assert_eq!(
        code(VideoChatEvent::Incoming {
            sdp_offer: String::from("offer")
        }),
        Some((0, Some(String::from("offer")), 0))
    );
    assert_eq!(code(VideoChatEvent::Alerting), Some((1, None, 0)));
    assert_eq!(
        code(VideoChatEvent::Answered {
            sdp_answer: String::from("answer")
        }),
        Some((2, Some(String::from("answer")), 0))
    );
    assert_eq!(code(VideoChatEvent::Rejected(2)), Some((3, None, 2)));
    assert_eq!(code(VideoChatEvent::NotAnswered), Some((4, None, 0)));
    assert_eq!(code(VideoChatEvent::Missed), Some((5, None, 0)));
    assert_eq!(code(VideoChatEvent::Ended(2)), Some((6, None, 2)));
    assert_eq!(code(VideoChatEvent::Failed(480)), Some((7, None, 480)));
    // told by callbacks of their own
    assert_eq!(
        code(VideoChatEvent::IceCandidates {
            add: Vec::new(),
            remove: Vec::new(),
            reconnecting: false
        }),
        None
    );
    assert_eq!(
        code(VideoChatEvent::MediaUpdate(UpdateMedia::default())),
        None
    );
}
