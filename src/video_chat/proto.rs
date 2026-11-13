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

//! The Protocol Buffer messages of RCS Video Chat signalling (RCC.07 v18.0
//! sections 3.7.5.2.3.2 and 3.7.5.2.3.4)

/// The container of each event of a 1-to-1 RCS Video Chat, the body of an
/// `rcs/video-chat+proto` CPIM message (RCC.07 section 3.7.5.2.3.2)
#[derive(Clone, PartialEq, prost::Message)]
pub struct VideoChatMessage {
    /// The identifier of the call, unique to it
    #[prost(string, tag = "1")]
    pub call_id: String,
    #[prost(
        oneof = "video_chat_message::Event",
        tags = "101, 102, 103, 104, 105, 106, 107, 108"
    )]
    pub event: Option<video_chat_message::Event>,
}

pub mod video_chat_message {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Event {
        #[prost(message, tag = "101")]
        CallInvitation(super::CallInvitation),
        #[prost(message, tag = "102")]
        AckInvitation(super::AckInvitation),
        #[prost(message, tag = "103")]
        AcceptInvitation(super::AcceptInvitation),
        #[prost(message, tag = "104")]
        RejectInvitation(super::RejectInvitation),
        #[prost(message, tag = "105")]
        Hangup(super::Hangup),
        #[prost(message, tag = "106")]
        CancelInvitation(super::CancelInvitation),
        #[prost(message, tag = "107")]
        UpdateMedia(super::UpdateMedia),
        #[prost(message, tag = "108")]
        IceCandidatesUpdate(super::IceCandidatesUpdate),
    }
}

/// A call offered, with the SDP offer of the caller for a 1-to-1 call
/// (section 3.7.5.2.3.2.1)
#[derive(Clone, PartialEq, prost::Message)]
pub struct CallInvitation {
    #[prost(string, tag = "1")]
    pub sdp_offer: String,
}

/// A CallInvitation received, the callee being alerted (section
/// 3.7.5.2.3.2.2)
#[derive(Clone, PartialEq, prost::Message)]
pub struct AckInvitation {}

/// A call answered, with the SDP answer of the callee for a 1-to-1 call
/// (section 3.7.5.2.3.2.3)
#[derive(Clone, PartialEq, prost::Message)]
pub struct AcceptInvitation {
    #[prost(string, tag = "1")]
    pub sdp_answer: String,
}

/// A call rejected by the callee (section 3.7.5.2.3.2.4)
#[derive(Clone, PartialEq, prost::Message)]
pub struct RejectInvitation {
    #[prost(enumeration = "RejectReason", tag = "1")]
    pub reject_reason: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum RejectReason {
    Unspecified = 0,
    /// The callee rejected the call
    UserReject = 1,
    /// An RCS Video Chat was in progress already
    AlreadyInProgress = 2,
}

/// A call hung up (section 3.7.5.2.3.2.5)
#[derive(Clone, PartialEq, prost::Message)]
pub struct Hangup {
    #[prost(enumeration = "HangupReason", tag = "1")]
    pub hangup_reason: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum HangupReason {
    Unspecified = 0,
    /// The participant hung up
    UserInitiated = 1,
    /// A timer of the client ran out
    ClientTimeout = 2,
    /// The SFU found a participant of a group call disconnected
    ServerDetectedDisconnect = 3,
}

/// A call cancelled by the caller before it was answered (section
/// 3.7.5.2.3.2.6)
#[derive(Clone, PartialEq, prost::Message)]
pub struct CancelInvitation {
    #[prost(enumeration = "CancelReason", tag = "1")]
    pub cancel_reason: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum CancelReason {
    Unspecified = 0,
    /// The caller cancelled the call
    UserCancel = 1,
    /// The call went unanswered too long
    Timeout = 2,
}

/// The ICE candidates to add and remove, as after an IP address change
/// (section 3.7.5.2.3.2.7)
#[derive(Clone, PartialEq, prost::Message)]
pub struct IceCandidatesUpdate {
    #[prost(string, repeated, tag = "1")]
    pub add_ice_candidates: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub remove_ice_candidates: Vec<String>,
}

/// The video a participant prefers to receive, and the bandwidth it can take
/// (section 3.7.5.2.3.2.8)
#[derive(Clone, PartialEq, prost::Message)]
pub struct UpdateMedia {
    #[prost(message, repeated, tag = "1")]
    pub view_request: Vec<ViewRequest>,
    #[prost(message, optional, tag = "2")]
    pub bandwidth_constraints: Option<BandwidthConstraints>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ViewRequest {
    #[prost(message, optional, tag = "1")]
    pub stream_id: Option<MediaStreamId>,
    /// For a stream of video only
    #[prost(message, optional, tag = "2")]
    pub resolution: Option<VideoResolution>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MediaStreamId {
    #[prost(string, tag = "1")]
    pub media_stream_id: String,
    #[prost(enumeration = "MediaType", tag = "2")]
    pub media_type: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum MediaType {
    Unspecified = 0,
    Audio = 1,
    Video = 2,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct VideoResolution {
    #[prost(int32, tag = "1")]
    pub height: i32,
    #[prost(int32, tag = "2")]
    pub width: i32,
    #[prost(int32, tag = "3")]
    pub frame_rate: i32,
}

/// In kilobits per second
#[derive(Clone, PartialEq, prost::Message)]
pub struct BandwidthConstraints {
    #[prost(int32, tag = "1")]
    pub max_bandwidth_kbps: i32,
    #[prost(int32, tag = "2")]
    pub min_bandwidth_kbps: i32,
    #[prost(int32, tag = "3")]
    pub start_bandwidth_kbps: i32,
}

/// The body of the SIP MESSAGE telling the Service Provider Network that the
/// client joined or left an RCS Video Chat (section 3.7.5.2.3.4)
#[derive(Clone, PartialEq, prost::Message)]
pub struct VideoChatEventNotification {
    /// The callee of a 1-to-1 RCS Video Chat
    #[prost(string, tag = "1")]
    pub one_to_one_participant_uri: String,
    /// The Conversation-ID of a Group RCS Video Chat
    #[prost(string, tag = "2")]
    pub group_conversation_id: String,
    #[prost(enumeration = "VideoChatEvent", tag = "3")]
    pub video_chat_event: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum VideoChatEvent {
    Unspecified = 0,
    Join = 1,
    Leave = 2,
}
