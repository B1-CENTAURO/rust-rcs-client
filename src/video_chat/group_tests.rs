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

//! Group RCS Video Chats (RCC.07 v18.0 section 3.7.5.5), on the devices of
//! the 1-to-1 tests

use std::time::Duration;

use prost::Message;

use super::proto::video_chat_message::Event as Signal;
use super::proto::*;
use super::tests::{
    a_device, accept, cancel, date, hangup, reject, Device, Keys, CONVERSATION, GROUP, JOIN, LEAVE,
    ME, MS,
};
use super::{ForServer, GroupVideoChatEvent, VideoChatEvent, ANSWERED_WITHIN, CONNECTED_WITHIN};

const BOB: &str = "tel:+15550002";
const CAROL: &str = "tel:+15550003";

/// What a device sent the Controlling Function of a group: the call_id and
/// signal of its VideoChatMessage, its SDP, and its event for the
/// Controlling Function
type GroupSent = (String, String, Option<Signal>, String, Option<ForServer>);

impl Device {
    /// What was sent to Controlling Functions since last asked
    fn group_sent(&self) -> Vec<GroupSent> {
        std::mem::take(&mut *self.link.group_sent.lock().unwrap())
            .into_iter()
            .map(|(conference_uri, message)| {
                let signalled = VideoChatMessage::decode(&message.video_chat_message[..]).unwrap();
                (
                    conference_uri,
                    signalled.call_id,
                    signalled.event,
                    message.sdp,
                    message.event,
                )
            })
            .collect()
    }

    /// What was told of the participants since last asked
    fn group_told(&self) -> Vec<(String, String, GroupVideoChatEvent)> {
        std::mem::take(&mut *self.group_told.lock().unwrap())
    }

    /// The ServerGroupVideoMessage `message` of GROUP, of `from`, sent now
    fn relayed(&self, from: &str, message: ServerGroupVideoMessage) {
        self.relayed_sent(from, message, &date(Duration::ZERO));
    }

    fn relayed_sent(&self, from: &str, message: ServerGroupVideoMessage, date: &str) {
        self.service
            .on_group_message(GROUP, from, date, &message.encode_to_vec(), None);
    }
}

/// The ServerGroupVideoMessage relaying `signal` of the call `call_id`,
/// with `sdp`
fn relaying(call_id: &str, signal: Signal, sdp: &str) -> ServerGroupVideoMessage {
    ServerGroupVideoMessage {
        video_chat_message: VideoChatMessage {
            call_id: String::from(call_id),
            event: Some(signal),
        }
        .encode_to_vec(),
        sdp: String::from(sdp),
        ..ServerGroupVideoMessage::default()
    }
}

/// A participant of the call, as the Controlling Function has it
fn member(msisdn: &str, sfu_user_id: &str, joined: bool) -> MemberInfo {
    MemberInfo {
        user_id: Some(RcsId {
            msisdn: String::from(msisdn),
        }),
        sfu_user_id: Some(SfuUserId {
            sfu_user_id: String::from(sfu_user_id),
        }),
        stream_identifiers: Some(StreamIdentifiers {
            media_stream_ids: vec![MediaStreamId {
                media_stream_id: format!("{}-video", sfu_user_id),
                media_type: MediaType::Video as i32,
            }],
        }),
        user_call_state: match joined {
            true => UserCallState::Joined as i32,
            false => UserCallState::NotJoined as i32,
        },
    }
}

fn invitation() -> Signal {
    Signal::CallInvitation(CallInvitation {
        sdp_offer: String::new(),
    })
}

fn ack() -> Signal {
    Signal::AckInvitation(AckInvitation {})
}

fn tell(call_id: &str, event: VideoChatEvent) -> (String, String, VideoChatEvent) {
    (String::from(call_id), String::from(GROUP), event)
}

fn tell_group(call_id: &str, event: GroupVideoChatEvent) -> (String, String, GroupVideoChatEvent) {
    (String::from(call_id), String::from(GROUP), event)
}

fn to_group(call_id: &str, signal: Signal, sdp: &str) -> GroupSent {
    (
        String::from(GROUP),
        String::from(call_id),
        Some(signal),
        String::from(sdp),
        None,
    )
}

/// A device calling GROUP, the SFU answered and the media connected
fn calling_the_group() -> (Device, String) {
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    device.relayed(ME, relaying(&call_id, invitation(), "sfu answer"));
    device.service.media_connected(&call_id);
    device.group_sent();
    device.told();
    device.group_told();
    (device, call_id)
}

/// A device that Bob calls in GROUP, ringing
fn called_in_the_group() -> Device {
    let device = a_device();
    device.relayed(BOB, relaying("bob-call", invitation(), "sfu offer"));
    device.group_sent();
    device.told();
    device.group_told();
    device
}

#[test]
fn a_group_call_is_offered_and_answered_through_the_controlling_function() {
    // RCC.07 v18.0 section 3.7.5.5.1: the SDP offer in the
    // ClientGroupVideoMessage, not in the CallInvitation
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    assert_eq!(
        device.group_sent(),
        [to_group(&call_id, invitation(), "offer")]
    );
    assert!(device.told().is_empty());

    // the SFU's answer, with the participants, the media to connect
    let members = vec![
        member(ME, "sfu-me", false),
        member(BOB, "sfu-bob", false),
        member(CAROL, "sfu-carol", false),
    ];
    device.relayed(
        ME,
        ServerGroupVideoMessage {
            member_info: members.clone(),
            ..relaying(&call_id, invitation(), "sfu answer")
        },
    );
    assert_eq!(
        device.told(),
        [tell(
            &call_id,
            VideoChatEvent::Connect {
                sdp_answer: String::from("sfu answer")
            }
        )]
    );
    assert_eq!(
        device.group_told(),
        [tell_group(&call_id, GroupVideoChatEvent::Members(members))]
    );
    // not answered yet: not joined though connected
    assert!(device.service.media_connected(&call_id));
    assert!(device.group_reports().is_empty());

    // the first participant alerted (section 3.7.5.5.2), each told
    device.relayed(BOB, relaying(&call_id, ack(), ""));
    assert_eq!(device.told(), [tell(&call_id, VideoChatEvent::Alerting)]);
    assert_eq!(
        device.group_told(),
        [tell_group(
            &call_id,
            GroupVideoChatEvent::Ringing(String::from(BOB))
        )]
    );
    device.relayed(CAROL, relaying(&call_id, ack(), ""));
    assert!(device.told().is_empty());
    assert_eq!(
        device.group_told(),
        [tell_group(
            &call_id,
            GroupVideoChatEvent::Ringing(String::from(CAROL))
        )]
    );

    // the first participant answered (section 3.7.5.5.3), joined then
    device.relayed(BOB, relaying(&call_id, accept(""), "bob's answer"));
    assert_eq!(
        device.told(),
        [tell(
            &call_id,
            VideoChatEvent::Answered {
                sdp_answer: String::from("bob's answer")
            }
        )]
    );
    assert_eq!(
        device.group_told(),
        [tell_group(
            &call_id,
            GroupVideoChatEvent::Joined(String::from(BOB))
        )]
    );
    assert_eq!(device.group_reports(), [(JOIN, String::from(CONVERSATION))]);
    // answered once
    device.relayed("tel:+15550004", relaying(&call_id, accept(""), ""));
    assert!(device.told().is_empty());
    assert_eq!(
        device.group_told(),
        [tell_group(
            &call_id,
            GroupVideoChatEvent::Joined(String::from("tel:+15550004"))
        )]
    );
    assert!(device.group_reports().is_empty());

    // Carol rejects, Bob hangs up, the call going on (sections 3.7.5.5.4,
    // 3.7.5.5.6), nothing sent in turn
    device.relayed(
        CAROL,
        relaying(&call_id, reject(RejectReason::UserReject), ""),
    );
    device.relayed(
        BOB,
        relaying(&call_id, hangup(HangupReason::UserInitiated), ""),
    );
    assert_eq!(
        device.group_told(),
        [
            tell_group(
                &call_id,
                GroupVideoChatEvent::Rejected(String::from(CAROL), 1)
            ),
            tell_group(&call_id, GroupVideoChatEvent::Left(String::from(BOB), 1)),
        ]
    );
    assert!(device.told().is_empty());
    assert!(device.group_sent().is_empty());

    // hung up, and left
    assert!(device.service.hang_up(&call_id));
    assert_eq!(
        device.group_sent(),
        [to_group(&call_id, hangup(HangupReason::UserInitiated), "")]
    );
    assert_eq!(
        device.group_reports(),
        [(LEAVE, String::from(CONVERSATION))]
    );
    assert!(!device.service.hang_up(&call_id));
}

#[test]
fn the_sfu_answer_may_come_without_a_video_chat_message() {
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    device.relayed(
        "sip:conf-factory@example.com",
        ServerGroupVideoMessage {
            sdp: String::from("sfu answer"),
            ..ServerGroupVideoMessage::default()
        },
    );
    assert_eq!(
        device.told(),
        [tell(
            &call_id,
            VideoChatEvent::Connect {
                sdp_answer: String::from("sfu answer")
            }
        )]
    );
    // once
    device.relayed(ME, relaying(&call_id, invitation(), "another answer"));
    assert!(device.told().is_empty());

    // nor without a call of the group
    let device = a_device();
    device.relayed(
        ME,
        ServerGroupVideoMessage {
            sdp: String::from("sfu answer"),
            member_info: vec![member(BOB, "sfu-bob", true)],
            ..ServerGroupVideoMessage::default()
        },
    );
    assert!(device.told().is_empty());
    assert!(device.group_told().is_empty());
}

#[test]
fn a_group_call_offered_is_acknowledged_and_answered_with_the_sdp_answer_of_the_app() {
    // RCC.07 v18.0 sections 3.7.5.5.2, 3.7.5.5.3
    let device = a_device();
    let members = vec![member(BOB, "sfu-bob", true), member(ME, "sfu-me", false)];
    device.relayed(
        BOB,
        ServerGroupVideoMessage {
            member_info: members.clone(),
            call_invite_type: CallInviteType::Ring as i32,
            ..relaying("bob-call", invitation(), "sfu offer")
        },
    );
    assert_eq!(device.group_sent(), [to_group("bob-call", ack(), "")]);
    assert_eq!(
        device.told(),
        [tell(
            "bob-call",
            VideoChatEvent::Incoming {
                sdp_offer: String::from("sfu offer"),
                ongoing: false,
            }
        )]
    );
    assert_eq!(
        device.group_told(),
        [tell_group(
            "bob-call",
            GroupVideoChatEvent::Members(members)
        )]
    );
    // its own AckInvitation, sent back, let go of
    device.relayed(ME, relaying("bob-call", ack(), ""));
    assert!(device.group_told().is_empty());
    // sent again, let go of
    device.relayed(BOB, relaying("bob-call", invitation(), "sfu offer"));
    assert!(device.group_sent().is_empty());
    assert!(device.told().is_empty());

    // the SDP answer in the ClientGroupVideoMessage, as the user answers,
    // which the SFU needs to connect
    assert!(!device.service.media_connected("bob-call"));
    assert!(!device.service.media_disconnected("bob-call"));
    assert!(device.service.accept_call("bob-call", "my answer"));
    assert_eq!(
        device.group_sent(),
        [to_group("bob-call", accept(""), "my answer")]
    );
    assert!(!device.service.accept_call("bob-call", "my answer"));
    assert!(device.service.media_connected("bob-call"));
    assert_eq!(device.group_reports(), [(JOIN, String::from(CONVERSATION))]);
    assert!(device.service.media_connected("bob-call"));
    assert!(device.group_reports().is_empty());

    // Carol joins
    device.relayed(CAROL, relaying("bob-call", accept(""), ""));
    assert!(device.told().is_empty());
    assert_eq!(
        device.group_told(),
        [tell_group(
            "bob-call",
            GroupVideoChatEvent::Joined(String::from(CAROL))
        )]
    );

    // hung up, and left, the call going on for the others
    assert!(device.service.hang_up("bob-call"));
    assert_eq!(
        device.group_sent(),
        [to_group(
            "bob-call",
            hangup(HangupReason::UserInitiated),
            ""
        )]
    );
    assert_eq!(
        device.group_reports(),
        [(LEAVE, String::from(CONVERSATION))]
    );
}

#[test]
fn a_participant_added_during_a_group_call_is_offered_it_ongoing() {
    // RCC.07 v18.0 section 3.7.5.5.7
    let device = a_device();
    device.relayed(
        BOB,
        ServerGroupVideoMessage {
            call_invite_type: CallInviteType::Ongoing as i32,
            ..relaying("bob-call", invitation(), "sfu offer")
        },
    );
    assert_eq!(
        device.told(),
        [tell(
            "bob-call",
            VideoChatEvent::Incoming {
                sdp_offer: String::from("sfu offer"),
                ongoing: true,
            }
        )]
    );
    assert_eq!(
        super::ffi::video_chat_event_code(&VideoChatEvent::Incoming {
            sdp_offer: String::from("sfu offer"),
            ongoing: true,
        }),
        Some((0, Some("sfu offer"), 1))
    );
}

#[test]
fn a_group_call_offered_is_rejected_cancelled_or_too_old() {
    // rejected by the user (section 3.7.5.5.4)
    let device = called_in_the_group();
    assert!(device.service.hang_up("bob-call"));
    assert_eq!(
        device.group_sent(),
        [to_group("bob-call", reject(RejectReason::UserReject), "")]
    );

    // cancelled by the caller (section 3.7.5.5.5), or hung up by it before
    // the device answered
    for signal in [
        cancel(CancelReason::UserCancel),
        hangup(HangupReason::UserInitiated),
    ] {
        let device = called_in_the_group();
        device.relayed(BOB, relaying("bob-call", signal, ""));
        assert_eq!(device.told(), [tell("bob-call", VideoChatEvent::Missed)]);
        assert!(!device.service.accept_call("bob-call", "answer"));
    }

    // another participant hanging up: rings on
    let device = called_in_the_group();
    device.relayed(
        CAROL,
        relaying("bob-call", hangup(HangupReason::UserInitiated), ""),
    );
    assert!(device.told().is_empty());
    assert_eq!(
        device.group_told(),
        [tell_group(
            "bob-call",
            GroupVideoChatEvent::Left(String::from(CAROL), 1)
        )]
    );
    assert!(device.service.accept_call("bob-call", "answer"));

    // stored and forwarded too long ago (section 3.7.5.5.9.1.2)
    let device = a_device();
    device.relayed_sent(
        BOB,
        relaying("bob-call", invitation(), "sfu offer"),
        &date(ANSWERED_WITHIN + MS),
    );
    assert!(device.group_sent().is_empty());
    assert_eq!(device.told(), [tell("bob-call", VideoChatEvent::Missed)]);

    // too late to answer (Timer_Gamma)
    let device = called_in_the_group();
    device.after(ANSWERED_WITHIN - MS);
    assert!(device.told().is_empty());
    device.after(2 * MS);
    assert_eq!(device.told(), [tell("bob-call", VideoChatEvent::Missed)]);
    assert!(device.group_sent().is_empty());
}

#[test]
fn a_group_call_not_alerted_or_not_answered_in_time_is_cancelled() {
    // RCC.07 v18.0 section 3.7.5.5.9.2
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    device.relayed(ME, relaying(&call_id, invitation(), "sfu answer"));
    device.service.media_connected(&call_id);
    device.group_sent();
    device.told();
    device.after(ANSWERED_WITHIN - MS);
    assert!(device.group_sent().is_empty());
    device.after(2 * MS);
    assert_eq!(
        device.group_sent(),
        [to_group(&call_id, cancel(CancelReason::Timeout), "")]
    );
    assert_eq!(device.told(), [tell(&call_id, VideoChatEvent::NotAnswered)]);

    // alerted, not answered
    let (device, call_id) = calling_the_group();
    device.relayed(BOB, relaying(&call_id, ack(), ""));
    device.after(ANSWERED_WITHIN + MS);
    assert_eq!(
        device.group_sent(),
        [to_group(&call_id, cancel(CancelReason::Timeout), "")]
    );

    // answered in time
    let (device, call_id) = calling_the_group();
    device.relayed(BOB, relaying(&call_id, accept(""), ""));
    device.after(ANSWERED_WITHIN + MS);
    assert!(device.group_sent().is_empty());

    // cancelled by the user before then
    let (device, call_id) = calling_the_group();
    assert!(device.service.hang_up(&call_id));
    assert_eq!(
        device.group_sent(),
        [to_group(&call_id, cancel(CancelReason::UserCancel), "")]
    );
    device.after(ANSWERED_WITHIN + MS);
    assert!(device.group_sent().is_empty());
}

#[test]
fn a_group_call_whose_media_does_not_connect_to_the_sfu_in_time_ends() {
    // the caller's, not answered yet: cancelled
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    device.relayed(ME, relaying(&call_id, invitation(), "sfu answer"));
    device.group_sent();
    device.told();
    device.after(CONNECTED_WITHIN - MS);
    assert!(device.group_sent().is_empty());
    device.after(2 * MS);
    assert_eq!(
        device.group_sent(),
        [to_group(&call_id, cancel(CancelReason::Timeout), "")]
    );
    assert_eq!(
        device.told(),
        [tell(
            &call_id,
            VideoChatEvent::Ended(HangupReason::ClientTimeout as i32)
        )]
    );

    // a participant's: hung up
    let device = called_in_the_group();
    device.service.accept_call("bob-call", "answer");
    device.group_sent();
    device.after(CONNECTED_WITHIN + MS);
    assert_eq!(
        device.group_sent(),
        [to_group(
            "bob-call",
            hangup(HangupReason::ClientTimeout),
            ""
        )]
    );
    assert!(device.group_reports().is_empty());

    // gone down: the SFU waits for it (Timer_Zeta), not the client
    let device = called_in_the_group();
    device.service.accept_call("bob-call", "answer");
    device.service.media_connected("bob-call");
    device.group_sent();
    device.group_reports();
    assert!(device.service.media_disconnected("bob-call"));
    device.after(10 * CONNECTED_WITHIN);
    assert!(device.group_sent().is_empty());
    assert!(device.service.media_connected("bob-call"));
    assert!(device.group_reports().is_empty());

    // found disconnected by the SFU, which hangs up the device's
    device.relayed(
        ME,
        relaying(
            "bob-call",
            hangup(HangupReason::ServerDetectedDisconnect),
            "",
        ),
    );
    assert_eq!(
        device.told(),
        [tell(
            "bob-call",
            VideoChatEvent::Ended(HangupReason::ServerDetectedDisconnect as i32)
        )]
    );
    assert_eq!(
        device.group_reports(),
        [(LEAVE, String::from(CONVERSATION))]
    );
    assert!(device.group_sent().is_empty());
}

#[test]
fn ice_candidates_and_media_updates_go_to_the_controlling_function_alone() {
    // RCC.07 v18.0 section 3.7.5.2.3.3
    let (device, call_id) = calling_the_group();
    device.relayed(BOB, relaying(&call_id, accept(""), ""));
    device.told();
    device.group_told();
    device.group_reports();
    let update = IceCandidatesUpdate {
        add_ice_candidates: vec![String::from("candidate:1")],
        remove_ice_candidates: Vec::new(),
    };
    assert!(device.service.update_ice_candidates(
        &call_id,
        update.add_ice_candidates.clone(),
        Vec::new()
    ));
    // the call_id alone in the VideoChatMessage
    assert_eq!(
        device.group_sent(),
        [(
            String::from(GROUP),
            call_id.clone(),
            None,
            String::new(),
            Some(ForServer::IceCandidatesUpdate(update))
        )]
    );
    assert!(device
        .service
        .update_media(&call_id, UpdateMedia::default()));
    assert_eq!(
        device.group_sent(),
        [(
            String::from(GROUP),
            call_id.clone(),
            None,
            String::new(),
            Some(ForServer::UpdateMedia(UpdateMedia::default()))
        )]
    );

    // those of the Controlling Function, of the call of the group
    device.relayed(
        "sip:conf-factory@example.com",
        ServerGroupVideoMessage {
            event: Some(server_group_video_message::Event::IceCandidatesUpdate(
                IceCandidatesUpdate {
                    add_ice_candidates: vec![String::from("candidate:sfu")],
                    remove_ice_candidates: Vec::new(),
                },
            )),
            ..ServerGroupVideoMessage::default()
        },
    );
    device.relayed(
        "sip:conf-factory@example.com",
        ServerGroupVideoMessage {
            event: Some(server_group_video_message::Event::UpdateMedia(
                UpdateMedia::default(),
            )),
            ..ServerGroupVideoMessage::default()
        },
    );
    assert_eq!(
        device.told(),
        [
            tell(
                &call_id,
                VideoChatEvent::IceCandidates {
                    add: vec![String::from("candidate:sfu")],
                    remove: Vec::new(),
                    reconnecting: false,
                }
            ),
            tell(
                &call_id,
                VideoChatEvent::MediaUpdate(UpdateMedia::default())
            ),
        ]
    );
    // not restarting Timer_Delta
    device.after(10 * CONNECTED_WITHIN);
    assert!(device.group_sent().is_empty());
}

#[test]
fn one_call_goes_on_at_a_time_of_any_kind() {
    // a group call offered during a 1-to-1 call
    let device = a_device();
    let call_id = device.service.start_call(BOB, "offer").unwrap();
    device.relayed(CAROL, relaying("carol-call", invitation(), "sfu offer"));
    assert_eq!(
        device.group_sent(),
        [to_group(
            "carol-call",
            reject(RejectReason::AlreadyInProgress),
            ""
        )]
    );
    assert_eq!(device.told(), [tell("carol-call", VideoChatEvent::Missed)]);
    assert_eq!(device.service.start_group_call(GROUP, "offer"), None);
    device.service.hang_up(&call_id);

    // a 1-to-1 call during a group call
    let (device, _call_id) = calling_the_group();
    assert_eq!(device.service.start_call(BOB, "offer"), None);
    assert_eq!(device.service.start_group_call(GROUP, "offer"), None);
    let message = VideoChatMessage {
        call_id: String::from("bob-call"),
        event: Some(Signal::CallInvitation(CallInvitation {
            sdp_offer: String::from("offer"),
        })),
    };
    device
        .service
        .on_message(BOB, &date(Duration::ZERO), &message.encode_to_vec());
    assert_eq!(
        device.told(),
        [(
            String::from("bob-call"),
            String::from(BOB),
            VideoChatEvent::Missed
        )]
    );
}

#[test]
fn the_signals_of_a_group_call_are_taken_from_its_group_alone() {
    let (device, call_id) = calling_the_group();
    let message = relaying(&call_id, ack(), "");
    device.service.on_group_message(
        "sip:group-2@conf.example.com",
        BOB,
        &date(Duration::ZERO),
        &message.encode_to_vec(),
        None,
    );
    assert!(device.told().is_empty());
    assert!(device.group_told().is_empty());
    // nor of another call
    device.relayed(BOB, relaying("another call", ack(), ""));
    assert!(device.group_told().is_empty());
    // nor what cannot be read
    device
        .service
        .on_group_message(GROUP, BOB, &date(Duration::ZERO), b"\xff\xff", None);
    device.relayed(
        BOB,
        ServerGroupVideoMessage {
            video_chat_message: b"\xff\xff".to_vec(),
            ..ServerGroupVideoMessage::default()
        },
    );
    assert!(device.told().is_empty());
    // its own invitation, of a call no longer known
    let device = a_device();
    device.relayed(ME, relaying("gone", invitation(), "sfu answer"));
    assert!(device.told().is_empty());
    assert!(device.group_sent().is_empty());
}

#[test]
fn a_group_call_whose_signal_cannot_be_sent_fails() {
    let device = a_device();
    *device.link.status_code.lock().unwrap() = 488;
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    assert_eq!(device.told(), [tell(&call_id, VideoChatEvent::Failed(488))]);
    *device.link.status_code.lock().unwrap() = 200;
    assert!(device.service.start_group_call(GROUP, "offer").is_some());

    let device = called_in_the_group();
    *device.link.status_code.lock().unwrap() = 403;
    device.service.accept_call("bob-call", "answer");
    assert_eq!(
        device.told(),
        [tell("bob-call", VideoChatEvent::Failed(403))]
    );

    // not the others
    let (device, call_id) = calling_the_group();
    *device.link.status_code.lock().unwrap() = 500;
    device
        .service
        .update_media(&call_id, UpdateMedia::default());
    assert!(device.told().is_empty());
    assert!(device.service.hang_up(&call_id));
}

#[test]
fn a_group_call_is_reported_by_the_conversation_id_of_its_group() {
    // and not reported if it is not known
    let device = a_device();
    device.service.on_group_message(
        "sip:unknown@conf.example.com",
        BOB,
        &date(Duration::ZERO),
        &relaying("bob-call", invitation(), "sfu offer").encode_to_vec(),
        None,
    );
    device.service.accept_call("bob-call", "answer");
    assert!(device.service.media_connected("bob-call"));
    device.service.hang_up("bob-call");
    assert!(device.group_reports().is_empty());
}

#[test]
fn the_app_is_told_each_participant_event_by_its_code() {
    use super::ffi::group_video_chat_event_code as code;

    assert_eq!(
        code(&GroupVideoChatEvent::Ringing(String::from(BOB))),
        Some((0, BOB, 0))
    );
    assert_eq!(
        code(&GroupVideoChatEvent::Joined(String::from(BOB))),
        Some((1, BOB, 0))
    );
    assert_eq!(
        code(&GroupVideoChatEvent::Rejected(String::from(BOB), 2)),
        Some((2, BOB, 2))
    );
    assert_eq!(
        code(&GroupVideoChatEvent::Left(String::from(BOB), 3)),
        Some((3, BOB, 3))
    );
    // told by a callback of their own
    assert_eq!(code(&GroupVideoChatEvent::Members(Vec::new())), None);
    assert_eq!(
        super::ffi::video_chat_event_code(&VideoChatEvent::Connect {
            sdp_answer: String::from("sfu answer")
        }),
        Some((8, Some("sfu answer"), 0))
    );
}

#[test]
fn the_caller_joins_once_answered_and_connected_to_the_sfu() {
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    // the participants told, without the SFU's answer
    device.relayed(
        ME,
        ServerGroupVideoMessage {
            member_info: vec![member(BOB, "sfu-bob", false)],
            ..relaying(&call_id, invitation(), "")
        },
    );
    assert!(device.told().is_empty());
    assert!(!device.service.media_connected(&call_id));
    device.relayed(ME, relaying(&call_id, invitation(), "sfu answer"));
    assert_eq!(device.told().len(), 1, "connect");

    // answered before the media connected: joined once it does
    device.relayed(BOB, relaying(&call_id, accept(""), ""));
    device.told();
    assert!(device.group_reports().is_empty());
    assert!(device.service.media_connected(&call_id));
    assert_eq!(device.group_reports(), [(JOIN, String::from(CONVERSATION))]);
}

impl Device {
    /// What the keys of the media of group calls were asked since last asked
    fn keys(&self) -> Vec<Keys> {
        std::mem::take(&mut *self.link.keys.lock().unwrap())
    }
}

fn started(call_id: &str) -> Keys {
    Keys::Started(String::from(call_id), String::from(GROUP))
}

fn ended(call_id: &str) -> Keys {
    Keys::Ended(String::from(call_id))
}

#[test]
fn the_media_keys_of_a_group_call_are_made_as_it_starts_or_is_answered() {
    // RCC.16 section 9.8.2: those the app encrypts the media with in a group
    // encrypted end to end, made before the media connects
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    assert_eq!(device.keys(), [started(&call_id)]);
    assert!(device.service.hang_up(&call_id));
    assert_eq!(device.keys(), [ended(&call_id)]);

    // not while offered, the user not having answered
    let device = called_in_the_group();
    assert!(device.keys().is_empty());
    assert!(device.service.accept_call("bob-call", "answer"));
    assert_eq!(device.keys(), [started("bob-call")]);
    // let go of as the call ends for this client, not for another
    device.relayed(
        BOB,
        relaying("bob-call", hangup(HangupReason::UserInitiated), ""),
    );
    assert!(device.keys().is_empty());
    assert!(device.service.hang_up("bob-call"));
    assert_eq!(device.keys(), [ended("bob-call")]);

    // nor for a call rejected
    let device = called_in_the_group();
    assert!(device.service.hang_up("bob-call"));
    assert_eq!(device.keys(), [ended("bob-call")]);

    // one started while another goes on not kept
    let (device, _) = calling_the_group();
    device.keys();
    assert!(device.service.start_group_call(GROUP, "offer").is_none());
    match device.keys().as_slice() {
        [Keys::Started(call_id, _), Keys::Ended(ended)] => assert_eq!(call_id, ended),
        other => panic!("{:?}", other),
    }
}

#[test]
fn the_media_keys_of_a_group_call_are_let_go_of_however_it_ends() {
    // not answered in time
    let device = a_device();
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    device.keys();
    device.after(ANSWERED_WITHIN + MS);
    assert_eq!(device.keys(), [ended(&call_id)]);

    // the media not connected in time
    let device = called_in_the_group();
    device.service.accept_call("bob-call", "answer");
    device.keys();
    device.after(CONNECTED_WITHIN + MS);
    assert_eq!(device.keys(), [ended("bob-call")]);

    // found disconnected by the SFU
    let (device, call_id) = calling_the_group();
    device.keys();
    device.relayed(
        ME,
        relaying(&call_id, hangup(HangupReason::ServerDetectedDisconnect), ""),
    );
    assert_eq!(device.keys(), [ended(&call_id)]);

    // what it needed not sent
    let device = called_in_the_group();
    *device.link.status_code.lock().unwrap() = 403;
    device.service.accept_call("bob-call", "answer");
    assert_eq!(device.keys(), [started("bob-call"), ended("bob-call")]);
}

#[test]
fn a_group_call_whose_media_keys_cannot_be_made_fails() {
    let device = a_device();
    *device.link.making_keys.lock().unwrap() = None;
    let call_id = device.service.start_group_call(GROUP, "offer").unwrap();
    assert_eq!(device.told(), [tell(&call_id, VideoChatEvent::Failed(488))]);
    assert!(device.group_sent().is_empty());
    assert!(!device.service.hang_up(&call_id), "no call");

    // nor answered
    let device = called_in_the_group();
    *device.link.making_keys.lock().unwrap() = None;
    assert!(device.service.accept_call("bob-call", "answer"));
    assert_eq!(
        device.told(),
        [tell("bob-call", VideoChatEvent::Failed(488))]
    );
    assert!(device.group_sent().is_empty());
    assert!(!device.service.hang_up("bob-call"), "no call");
    // another call goes on then
    assert!(device.service.start_group_call(GROUP, "offer").is_some());
}

#[test]
fn the_media_keys_are_told_the_participants_joined_but_this_client() {
    // whose delivery of a Commit of this client they wait for (RCC.16
    // section 9.8.2)
    let (device, call_id) = calling_the_group();
    device.keys();
    let members = vec![
        member("+15550001", "sfu-me", true),
        member("+15550002", "sfu-bob", true),
        member("+15550003", "sfu-carol", false),
        member("", "sfu-unknown", true),
    ];
    device.relayed(
        BOB,
        ServerGroupVideoMessage {
            member_info: members,
            ..ServerGroupVideoMessage::default()
        },
    );
    assert_eq!(
        device.keys(),
        [Keys::Participants(
            call_id.clone(),
            vec![String::from("tel:+15550002")]
        )]
    );
    // and none, without the participants
    device.relayed(BOB, relaying(&call_id, ack(), ""));
    assert!(device.keys().is_empty());
}

#[test]
fn the_signals_of_the_others_in_an_encrypted_group_are_taken_signed_alone() {
    // RCC.16 section 9.8.2
    let (device, call_id) = calling_the_group();
    let signed_by = |signed: bool| {
        let checked = std::sync::Mutex::new(Vec::new());
        let check = |video_chat_message: &[u8]| {
            checked.lock().unwrap().push(video_chat_message.to_vec());
            signed
        };
        device.service.on_group_message(
            GROUP,
            BOB,
            &date(Duration::ZERO),
            &relaying(&call_id, ack(), "").encode_to_vec(),
            Some(&check),
        );
        checked.into_inner().unwrap()
    };
    let ack_of_bob = VideoChatMessage {
        call_id: call_id.clone(),
        event: Some(ack()),
    }
    .encode_to_vec();

    assert_eq!(signed_by(false), std::slice::from_ref(&ack_of_bob));
    assert!(device.told().is_empty());
    assert!(device.group_told().is_empty());
    assert_eq!(signed_by(true), [ack_of_bob]);
    assert_eq!(device.told(), [tell(&call_id, VideoChatEvent::Alerting)]);
    assert_eq!(
        device.group_told(),
        [tell_group(
            &call_id,
            GroupVideoChatEvent::Ringing(String::from(BOB))
        )]
    );

    // what the Controlling Function adds of its own, and what it relays of
    // this client, which cannot be signed by another
    let unsigned = |_: &[u8]| false;
    device.service.on_group_message(
        GROUP,
        BOB,
        &date(Duration::ZERO),
        &ServerGroupVideoMessage {
            member_info: vec![member("+15550002", "sfu-bob", true)],
            ..ServerGroupVideoMessage::default()
        }
        .encode_to_vec(),
        Some(&unsigned),
    );
    assert_eq!(device.group_told().len(), 1);
    device.service.on_group_message(
        GROUP,
        ME,
        &date(Duration::ZERO),
        &relaying(&call_id, hangup(HangupReason::ServerDetectedDisconnect), "").encode_to_vec(),
        Some(&unsigned),
    );
    assert_eq!(
        device.told(),
        [tell(
            &call_id,
            VideoChatEvent::Ended(HangupReason::ServerDetectedDisconnect as i32)
        )]
    );
}
