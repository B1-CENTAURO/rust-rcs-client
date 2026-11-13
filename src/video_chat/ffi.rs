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

//! The C types of RCS Video Chat, as librust_rcs_client.h declares them

use libc::{c_char, c_void};

use crate::messaging::ffi::MessageResultCallbackContext;

use super::{GroupVideoChatEvent, VideoChatEvent};

/// The size of the buffer a call_id is written to, with its NUL: a UUID
pub const CALL_ID_SIZE: usize = 37;

/// Told of each TurnCredential of the configuration: the URIs of its TURN
/// servers, and its username and password, NULL if none
pub type VideoChatTurnServerCallback = extern "C" fn(
    uris: *const *const c_char,
    uri_count: usize,
    username: *const c_char,
    password: *const c_char,
    context: *mut c_void,
);

/// Told of a call: the event as video_chat_event_code() has it, the call_id,
/// the contact, an SDP, and a reason
pub type VideoChatCallback = extern "C" fn(
    event: i32,
    call_id: *const c_char,
    contact_uri: *const c_char,
    sdp: *const c_char,
    reason: i32,
    context: *mut MessageResultCallbackContext,
);

/// Told of the ICE candidates of the contact of a call
pub type VideoChatIceCandidatesCallback = extern "C" fn(
    call_id: *const c_char,
    add: *const *const c_char,
    add_count: usize,
    remove: *const *const c_char,
    remove_count: usize,
    reconnecting: i32,
    context: *mut MessageResultCallbackContext,
);

/// A ViewRequest of an UpdateMedia (RCC.07 section 3.7.5.2.3.2.8.1); the
/// resolution 0 if none, as for audio
#[repr(C)]
pub struct VideoChatViewRequest {
    pub media_stream_id: *const c_char,
    /// A MediaType: 1 audio, 2 video
    pub media_type: i32,
    pub height: i32,
    pub width: i32,
    pub frame_rate: i32,
}

/// Told of the media the contact of a call prefers, and the bandwidth it can
/// take, 0 each if it gave none
pub type VideoChatMediaUpdateCallback = extern "C" fn(
    call_id: *const c_char,
    view_requests: *const VideoChatViewRequest,
    view_request_count: usize,
    max_bandwidth_kbps: i32,
    min_bandwidth_kbps: i32,
    start_bandwidth_kbps: i32,
    context: *mut MessageResultCallbackContext,
);

/// The event code of `event` as the app is told it, with its SDP and its
/// reason: incoming 0 with the SDP offer, 1 if a group call ongoing not to
/// ring, alerting 1, answered 2 with the SDP answer, rejected 3 with a
/// RejectReason, not answered 4, missed 5, ended 6 with a HangupReason,
/// failed 7 with the status code, connect 8 with the SDP answer of the SFU;
/// None for those told otherwise
pub fn video_chat_event_code(event: &VideoChatEvent) -> Option<(i32, Option<&str>, i32)> {
    match event {
        VideoChatEvent::Incoming { sdp_offer, ongoing } => {
            Some((0, Some(sdp_offer), i32::from(*ongoing)))
        }
        VideoChatEvent::Alerting => Some((1, None, 0)),
        VideoChatEvent::Answered { sdp_answer } => Some((2, Some(sdp_answer), 0)),
        VideoChatEvent::Rejected(reason) => Some((3, None, *reason)),
        VideoChatEvent::NotAnswered => Some((4, None, 0)),
        VideoChatEvent::Missed => Some((5, None, 0)),
        VideoChatEvent::Ended(reason) => Some((6, None, *reason)),
        VideoChatEvent::Failed(status_code) => Some((7, None, i32::from(*status_code))),
        VideoChatEvent::Connect { sdp_answer } => Some((8, Some(sdp_answer), 0)),
        VideoChatEvent::IceCandidates { .. } | VideoChatEvent::MediaUpdate(_) => None,
    }
}

/// Told of a participant of a group call: the event as
/// group_video_chat_event_code() has it, the call_id, the URI of the group,
/// the participant, and a reason
pub type VideoChatParticipantCallback = extern "C" fn(
    event: i32,
    call_id: *const c_char,
    conference_uri: *const c_char,
    participant_uri: *const c_char,
    reason: i32,
    context: *mut MessageResultCallbackContext,
);

/// A stream of a participant, as the SFU knows it (RCC.07 section
/// 3.7.5.2.3.2.8.1.1)
#[repr(C)]
pub struct VideoChatStream {
    pub media_stream_id: *const c_char,
    /// A MediaType: 1 audio, 2 video
    pub media_type: i32,
}

/// A participant of a group call, as the Controlling Function has it
/// (RCC.07 section 3.7.5.2.3.3.2.1)
#[repr(C)]
pub struct VideoChatMember {
    /// E.164
    pub msisdn: *const c_char,
    pub sfu_user_id: *const c_char,
    /// A UserCallState: 1 joined, 2 not joined
    pub call_state: i32,
    pub streams: *const VideoChatStream,
    pub stream_count: usize,
}

/// Told of the participants of a group call
pub type VideoChatMembersCallback = extern "C" fn(
    call_id: *const c_char,
    conference_uri: *const c_char,
    members: *const VideoChatMember,
    member_count: usize,
    context: *mut MessageResultCallbackContext,
);

/// The event code of the participant event `event`, with its participant
/// and its reason: ringing 0, joined 1, rejected 2 with a RejectReason, left
/// 3 with a HangupReason; None for the participants, told otherwise
pub fn group_video_chat_event_code(event: &GroupVideoChatEvent) -> Option<(i32, &str, i32)> {
    match event {
        GroupVideoChatEvent::Ringing(participant) => Some((0, participant, 0)),
        GroupVideoChatEvent::Joined(participant) => Some((1, participant, 0)),
        GroupVideoChatEvent::Rejected(participant, reason) => Some((2, participant, *reason)),
        GroupVideoChatEvent::Left(participant, reason) => Some((3, participant, *reason)),
        GroupVideoChatEvent::Members(_) => None,
    }
}
