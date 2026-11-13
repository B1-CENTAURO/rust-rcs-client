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

//! Group RCS Video Chat (RCC.07 v18.0 section 3.7.5.5): the calls of a group
//! chat, which go through its Controlling Function, the media through the
//! SFU it provides
//!
//! A client sends the Controlling Function ClientGroupVideoMessages in the
//! group chat, each with its VideoChatMessage and its SDP, and takes the
//! ServerGroupVideoMessages it relays, of the other participants or of its
//! own (sections 3.7.5.2.3.3). The call goes on for the others as one
//! participant hangs up; Timer_Zeta, which the SFU keeps, takes the place of
//! Timer_Epsilon.

use std::collections::HashMap;
use std::time::SystemTime;

use prost::Message;

use rust_rcs_core::ffi::log::platform_log;

use super::proto::server_group_video_message::Event as FromServer;
use super::proto::video_chat_message::Event as Signal;
use super::proto::{
    AcceptInvitation, AckInvitation, CallInvitation, CallInviteType, CancelInvitation,
    CancelReason, Hangup, HangupReason, RejectInvitation, RejectReason, ServerGroupVideoMessage,
    VideoChatMessage,
};
use super::{
    new_call_id, proto, ringing_for, same_contact, Action, Call, ForServer, GroupVideoChatEvent,
    Reported, VideoChatEvent, VideoChatService, ANSWERED_WITHIN, CONNECTED_WITHIN, LOG_TAG,
};

/// A call of a group chat
pub(super) struct GroupCall {
    conference_uri: String,
    /// The Conversation-ID of the group chat, which JOIN and LEAVE are
    /// reported with (section 3.7.5.2.3.4)
    conversation_id: Option<String>,
    outgoing: bool,
    /// Who offered a call this client did not
    caller: Option<String>,
    answer: Answer,
    media: Media,
    /// Whether answered and connected, the JOIN told (section 3.7.5.2.5)
    joined: bool,
}

/// Where a group call stands with its participants; each timer known by a
/// token, which it fires with
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// The caller waiting for a first participant to be alerted
    /// (Timer_Alpha), and to answer (Timer_Beta)
    Inviting {
        alpha: Option<u64>,
        beta: u64,
    },
    /// A participant alerted, until the call offered is too old to answer
    /// (Timer_Gamma)
    Ringing {
        gamma: u64,
    },
    Answered,
}

/// Where the media of a group call stands with the SFU
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Media {
    Idle,
    /// To connect within Timer_Delta
    Connecting {
        delta: u64,
    },
    /// Connected, or gone down for the SFU to wait for it to connect again
    /// (Timer_Zeta), which is alike to the client
    Connected,
}

impl VideoChatService {
    pub(super) fn is_group_call(&self, call_id: &str) -> bool {
        self.group_calls.lock().unwrap().contains_key(call_id)
    }

    /// Calls the participants of the group chat at `conference_uri`, with
    /// the SDP offer `sdp_offer` of the app to the SFU (RCC.07 section
    /// 3.7.5.5.1): the call_id of the call, or None if the client takes no
    /// calls, or another goes on
    pub fn start_group_call(&self, conference_uri: &str, sdp_offer: &str) -> Option<String> {
        self.feature_tag()?;
        let call_id = new_call_id();
        let conversation_id = self.link.group_conversation_id(conference_uri);
        let actions = {
            let calls = self.calls.lock().unwrap();
            let mut group_calls = self.group_calls.lock().unwrap();
            if !calls.is_empty() || !group_calls.is_empty() {
                return None;
            }
            let (alpha, beta) = (self.new_timer(), self.new_timer());
            group_calls.insert(
                call_id.clone(),
                GroupCall {
                    conference_uri: String::from(conference_uri),
                    conversation_id,
                    outgoing: true,
                    caller: None,
                    answer: Answer::Inviting {
                        alpha: Some(alpha),
                        beta,
                    },
                    media: Media::Idle,
                    joined: false,
                },
            );
            vec![
                // the SDP offer in the ClientGroupVideoMessage, not in the
                // CallInvitation (section 3.7.5.2.3.2.1)
                to_group(
                    &call_id,
                    conference_uri,
                    Some(Signal::CallInvitation(CallInvitation {
                        sdp_offer: String::new(),
                    })),
                    sdp_offer,
                    true,
                ),
                Action::Schedule(call_id.clone(), alpha, ANSWERED_WITHIN),
                Action::Schedule(call_id.clone(), beta, ANSWERED_WITHIN),
            ]
        };
        self.act(actions);
        Some(call_id)
    }

    /// Answers the group call `call_id` offered, with the SDP answer
    /// `sdp_answer` of the app to the SFU (RCC.07 section 3.7.5.5.3), the
    /// media to connect within Timer_Delta
    ///
    /// The AcceptInvitation goes as the user answers, with the SDP answer
    /// the SFU needs to connect, where section 3.7.5.5.3 has it sent once
    /// the media connected.
    pub(super) fn accept_group_call(&self, call_id: &str, sdp_answer: &str) -> bool {
        let actions = {
            let mut group_calls = self.group_calls.lock().unwrap();
            let Some(call) = group_calls.get_mut(call_id) else {
                return false;
            };
            let Answer::Ringing { .. } = call.answer else {
                return false;
            };
            let delta = self.new_timer();
            call.answer = Answer::Answered;
            call.media = Media::Connecting { delta };
            vec![
                to_group(
                    call_id,
                    &call.conference_uri,
                    Some(Signal::AcceptInvitation(AcceptInvitation {
                        sdp_answer: String::new(),
                    })),
                    sdp_answer,
                    true,
                ),
                Action::Schedule(String::from(call_id), delta, CONNECTED_WITHIN),
            ]
        };
        self.act(actions);
        true
    }

    /// Ends the group call `call_id` for this client as the user chose:
    /// cancels it if no participant answered yet, rejects it if offered,
    /// hangs up otherwise, the call going on for the others (RCC.07 sections
    /// 3.7.5.5.4 to 3.7.5.5.6)
    pub(super) fn hang_up_group_call(&self, call_id: &str) -> bool {
        let actions = {
            let mut group_calls = self.group_calls.lock().unwrap();
            let Some(call) = group_calls.remove(call_id) else {
                return false;
            };
            let signal = match call.answer {
                Answer::Inviting { .. } => Signal::CancelInvitation(CancelInvitation {
                    cancel_reason: CancelReason::UserCancel as i32,
                }),
                Answer::Ringing { .. } => Signal::RejectInvitation(RejectInvitation {
                    reject_reason: RejectReason::UserReject as i32,
                }),
                Answer::Answered => Signal::Hangup(Hangup {
                    hangup_reason: HangupReason::UserInitiated as i32,
                }),
            };
            let mut actions = vec![to_group(
                call_id,
                &call.conference_uri,
                Some(signal),
                "",
                false,
            )];
            actions.extend(group_left(&call));
            actions
        };
        self.act(actions);
        true
    }

    /// Sends the Controlling Function of the group call `call_id` `event`,
    /// an UpdateMedia or IceCandidatesUpdate, which is for it alone (RCC.07
    /// section 3.7.5.2.3.3.1)
    pub(super) fn tell_group_server(&self, call_id: &str, event: ForServer) -> bool {
        let actions = {
            let group_calls = self.group_calls.lock().unwrap();
            let Some(call) = group_calls.get(call_id) else {
                return false;
            };
            vec![Action::SendGroup {
                call_id: String::from(call_id),
                conference_uri: call.conference_uri.clone(),
                signal: None,
                sdp: String::new(),
                event: Some(event),
                fatal: false,
            }]
        };
        self.act(actions);
        true
    }

    /// Takes note of the media of the group call `call_id` connected to the
    /// SFU, or connected again, telling the Service Provider Network the
    /// client joined once the call is answered too (RCC.07 section
    /// 3.7.5.2.5)
    pub(super) fn group_media_connected(&self, call_id: &str) -> bool {
        let actions = {
            let mut group_calls = self.group_calls.lock().unwrap();
            let Some(call) = group_calls.get_mut(call_id) else {
                return false;
            };
            match call.media {
                Media::Connecting { .. } => call.media = Media::Connected,
                Media::Connected => {}
                Media::Idle => return false,
            }
            group_joined(call)
        };
        self.act(actions);
        true
    }

    /// Whether the media of the group call `call_id` gone down is of a call
    /// answered, for the SFU, not the client, to wait for it to connect again
    /// (Timer_Zeta, RCC.07 section 3.7.5.2.4.6)
    pub(super) fn group_media_disconnected(&self, call_id: &str) -> bool {
        let group_calls = self.group_calls.lock().unwrap();
        group_calls
            .get(call_id)
            .is_some_and(|call| call.media != Media::Idle)
    }

    /// Takes the ServerGroupVideoMessage `body` of the group chat at
    /// `conference_uri`, from `from`, the participant its VideoChatMessage
    /// is of, its CPIM DateTime `date`
    pub fn on_group_message(&self, conference_uri: &str, from: &str, date: &str, body: &[u8]) {
        let message = match ServerGroupVideoMessage::decode(body) {
            Ok(message) => message,
            Err(e) => {
                platform_log(
                    LOG_TAG,
                    format!("group video chat message not read: {:?}", e),
                );
                return;
            }
        };
        if self.listener.lock().unwrap().is_none() {
            return;
        }
        let signalled = match message.video_chat_message.is_empty() {
            true => None,
            false => match VideoChatMessage::decode(&message.video_chat_message[..]) {
                Ok(signalled) => Some(signalled),
                Err(e) => {
                    platform_log(LOG_TAG, format!("video chat message not read: {:?}", e));
                    return;
                }
            },
        };
        // of this client, as the Controlling Function sends it
        let own = self
            .link
            .registered_uri()
            .is_some_and(|registered| same_contact(&registered, from));
        let conversation_id = self.link.group_conversation_id(conference_uri);
        let actions = {
            let calls = self.calls.lock().unwrap();
            let mut group_calls = self.group_calls.lock().unwrap();
            // the call of the group, by its call_id if given
            let call_id = signalled
                .as_ref()
                .map(|signalled| signalled.call_id.clone())
                .filter(|call_id| !call_id.is_empty())
                .or_else(|| {
                    group_calls
                        .iter()
                        .find(|(_, call)| call.conference_uri.eq_ignore_ascii_case(conference_uri))
                        .map(|(call_id, _)| call_id.clone())
                });
            let Some(call_id) = call_id else {
                return;
            };
            if group_calls
                .get(&call_id)
                .is_some_and(|call| !call.conference_uri.eq_ignore_ascii_case(conference_uri))
            {
                platform_log(LOG_TAG, "group video chat message of another group");
                return;
            }
            let mut actions = match signalled.and_then(|signalled| signalled.event) {
                Some(Signal::CallInvitation(_)) if !group_calls.contains_key(&call_id) => {
                    // its own, of a call no longer known
                    if own {
                        return;
                    }
                    self.group_invited(
                        &calls,
                        &mut group_calls,
                        &call_id,
                        conference_uri,
                        conversation_id,
                        from,
                        date,
                        &message,
                    )
                }
                Some(signal) => {
                    self.group_signalled(&mut group_calls, &call_id, from, own, signal, &message)
                }
                // the SDP answer of the SFU, maybe
                None => match group_calls.get_mut(&call_id) {
                    Some(call) => self.sfu_answered(&call_id, call, &message.sdp),
                    None => Vec::new(),
                },
            };
            // and what the Controlling Function tells of the call
            if let Some(call) = group_calls.get(&call_id) {
                let told = match message.event {
                    Some(FromServer::IceCandidatesUpdate(update)) => {
                        Some(VideoChatEvent::IceCandidates {
                            add: update.add_ice_candidates,
                            remove: update.remove_ice_candidates,
                            reconnecting: false,
                        })
                    }
                    Some(FromServer::UpdateMedia(update)) => {
                        Some(VideoChatEvent::MediaUpdate(update))
                    }
                    None => None,
                };
                if let Some(told) = told {
                    actions.push(Action::Tell(
                        call_id.clone(),
                        call.conference_uri.clone(),
                        told,
                    ));
                }
                if !message.member_info.is_empty() {
                    actions.push(Action::TellGroup(
                        call_id.clone(),
                        call.conference_uri.clone(),
                        GroupVideoChatEvent::Members(message.member_info),
                    ));
                }
            }
            actions
        };
        self.act(actions);
    }

    /// The group call `call_id` of the group chat at `conference_uri` that
    /// `from` offers, as the Controlling Function relays it at `date`
    /// (RCC.07 sections 3.7.5.5.2, 3.7.5.5.7, 3.7.5.5.9.1)
    #[allow(clippy::too_many_arguments)]
    fn group_invited(
        &self,
        calls: &HashMap<String, Call>,
        group_calls: &mut HashMap<String, GroupCall>,
        call_id: &str,
        conference_uri: &str,
        conversation_id: Option<String>,
        from: &str,
        date: &str,
        message: &ServerGroupVideoMessage,
    ) -> Vec<Action> {
        let missed = Action::Tell(
            String::from(call_id),
            String::from(conference_uri),
            VideoChatEvent::Missed,
        );
        // too old to ring, as one stored and forwarded (Timer_Gamma)
        let Some(ringing_for) = ringing_for(date, SystemTime::now()) else {
            return vec![missed];
        };
        if !calls.is_empty() || !group_calls.is_empty() {
            return vec![
                to_group(
                    call_id,
                    conference_uri,
                    Some(Signal::RejectInvitation(RejectInvitation {
                        reject_reason: RejectReason::AlreadyInProgress as i32,
                    })),
                    "",
                    false,
                ),
                missed,
            ];
        }
        let gamma = self.new_timer();
        group_calls.insert(
            String::from(call_id),
            GroupCall {
                conference_uri: String::from(conference_uri),
                conversation_id,
                outgoing: false,
                caller: Some(String::from(from)),
                answer: Answer::Ringing { gamma },
                media: Media::Idle,
                joined: false,
            },
        );
        vec![
            to_group(
                call_id,
                conference_uri,
                Some(Signal::AckInvitation(AckInvitation {})),
                "",
                false,
            ),
            Action::Schedule(String::from(call_id), gamma, ringing_for),
            Action::Tell(
                String::from(call_id),
                String::from(conference_uri),
                VideoChatEvent::Incoming {
                    sdp_offer: message.sdp.clone(),
                    ongoing: message.call_invite_type == CallInviteType::Ongoing as i32,
                },
            ),
        ]
    }

    /// `signal` of the group call `call_id`, of the participant `from`, of
    /// this client if `own`, as the Controlling Function relays it in
    /// `message` (RCC.07 sections 3.7.5.5.1 to 3.7.5.5.6)
    fn group_signalled(
        &self,
        group_calls: &mut HashMap<String, GroupCall>,
        call_id: &str,
        from: &str,
        own: bool,
        signal: Signal,
        message: &ServerGroupVideoMessage,
    ) -> Vec<Action> {
        let Some(call) = group_calls.get_mut(call_id) else {
            return Vec::new();
        };
        let conference_uri = call.conference_uri.clone();
        let tell = |event| Action::Tell(String::from(call_id), conference_uri.clone(), event);
        let tell_group =
            |event| Action::TellGroup(String::from(call_id), conference_uri.clone(), event);
        let (actions, ended) = match signal {
            // its own, with the SDP answer of the SFU (section 3.7.5.5.1)
            Signal::CallInvitation(_) => (self.sfu_answered(call_id, call, &message.sdp), false),
            // a Hangup of this client's but its own: the SFU found it
            // disconnected
            Signal::Hangup(hangup) if own => {
                let mut actions = group_left(call);
                actions.push(tell(VideoChatEvent::Ended(hangup.hangup_reason)));
                (actions, true)
            }
            // its own others, sent back
            _ if own => (Vec::new(), false),
            Signal::AckInvitation(_) => {
                let mut actions = Vec::new();
                // the first participant alerted (section 3.7.5.5.2)
                if let (
                    true,
                    Answer::Inviting {
                        alpha: Some(_),
                        beta,
                    },
                ) = (call.outgoing, call.answer)
                {
                    call.answer = Answer::Inviting { alpha: None, beta };
                    actions.push(tell(VideoChatEvent::Alerting));
                }
                actions.push(tell_group(GroupVideoChatEvent::Ringing(String::from(from))));
                (actions, false)
            }
            Signal::AcceptInvitation(_) => {
                let mut actions = Vec::new();
                // the first participant answered (section 3.7.5.5.3)
                if let (true, Answer::Inviting { .. }) = (call.outgoing, call.answer) {
                    call.answer = Answer::Answered;
                    actions.push(tell(VideoChatEvent::Answered {
                        sdp_answer: message.sdp.clone(),
                    }));
                    actions.extend(group_joined(call));
                }
                actions.push(tell_group(GroupVideoChatEvent::Joined(String::from(from))));
                (actions, false)
            }
            // the call waiting for the others still (section 3.7.5.5.4)
            Signal::RejectInvitation(reject) => (
                vec![tell_group(GroupVideoChatEvent::Rejected(
                    String::from(from),
                    reject.reject_reason,
                ))],
                false,
            ),
            // cancelled before it was answered (sections 3.7.5.5.5,
            // 3.7.5.5.9.2)
            Signal::CancelInvitation(_) => match call.answer {
                Answer::Ringing { .. } => (vec![tell(VideoChatEvent::Missed)], true),
                _ => (Vec::new(), false),
            },
            // the caller hung up before this client answered
            Signal::Hangup(_)
                if matches!(call.answer, Answer::Ringing { .. })
                    && call
                        .caller
                        .as_deref()
                        .is_some_and(|caller| same_contact(caller, from)) =>
            {
                (vec![tell(VideoChatEvent::Missed)], true)
            }
            // the call going on for the others (section 3.7.5.5.6)
            Signal::Hangup(hangup) => (
                vec![tell_group(GroupVideoChatEvent::Left(
                    String::from(from),
                    hangup.hangup_reason,
                ))],
                false,
            ),
            Signal::IceCandidatesUpdate(update) => (
                vec![tell(VideoChatEvent::IceCandidates {
                    add: update.add_ice_candidates,
                    remove: update.remove_ice_candidates,
                    reconnecting: false,
                })],
                false,
            ),
            Signal::UpdateMedia(update) => (vec![tell(VideoChatEvent::MediaUpdate(update))], false),
        };
        if ended {
            group_calls.remove(call_id);
        }
        actions
    }

    /// The SDP answer `sdp` of the SFU to the caller of the group call
    /// `call_id`, the media to connect to it within Timer_Delta (RCC.07
    /// section 3.7.5.5.1), if it is the caller's and has none yet
    fn sfu_answered(&self, call_id: &str, call: &mut GroupCall, sdp: &str) -> Vec<Action> {
        if !call.outgoing || call.media != Media::Idle || sdp.is_empty() {
            return Vec::new();
        }
        let delta = self.new_timer();
        call.media = Media::Connecting { delta };
        vec![
            Action::Schedule(String::from(call_id), delta, CONNECTED_WITHIN),
            Action::Tell(
                String::from(call_id),
                call.conference_uri.clone(),
                VideoChatEvent::Connect {
                    sdp_answer: String::from(sdp),
                },
            ),
        ]
    }

    /// The timer `timer` of the group call `call_id` run out, if the call
    /// still waits for it (RCC.07 section 3.7.5.2.4)
    pub(super) fn group_timed_out(&self, call_id: &str, timer: u64) {
        let actions = {
            let mut group_calls = self.group_calls.lock().unwrap();
            let Some(call) = group_calls.get(call_id) else {
                return;
            };
            let send = |signal| to_group(call_id, &call.conference_uri, Some(signal), "", false);
            let tell =
                |event| Action::Tell(String::from(call_id), call.conference_uri.clone(), event);
            let actions = match (call.answer, call.media) {
                // no participant alerted, or none answered: Timer_Alpha or
                // Timer_Beta (section 3.7.5.5.9.2)
                (Answer::Inviting { alpha, beta }, _) if alpha == Some(timer) || beta == timer => {
                    vec![
                        send(Signal::CancelInvitation(CancelInvitation {
                            cancel_reason: CancelReason::Timeout as i32,
                        })),
                        tell(VideoChatEvent::NotAnswered),
                    ]
                }
                // too late to answer: Timer_Gamma
                (Answer::Ringing { gamma }, _) if gamma == timer => {
                    vec![tell(VideoChatEvent::Missed)]
                }
                // the media not connected to the SFU: Timer_Delta; the
                // caller's cancelling the call if no one answered yet
                (answer, Media::Connecting { delta }) if delta == timer => {
                    let signal = match answer {
                        Answer::Answered => Signal::Hangup(Hangup {
                            hangup_reason: HangupReason::ClientTimeout as i32,
                        }),
                        _ => Signal::CancelInvitation(CancelInvitation {
                            cancel_reason: CancelReason::Timeout as i32,
                        }),
                    };
                    let mut actions = vec![send(signal)];
                    actions.extend(group_left(call));
                    actions.push(tell(VideoChatEvent::Ended(
                        HangupReason::ClientTimeout as i32,
                    )));
                    actions
                }
                _ => return,
            };
            group_calls.remove(call_id);
            actions
        };
        self.act(actions);
    }

    /// The group call `call_id` failed, as what it needed sending was not
    /// sent, with `status_code`
    pub(super) fn group_failed(&self, call_id: &str, status_code: u16) {
        let actions = {
            let mut group_calls = self.group_calls.lock().unwrap();
            let Some(call) = group_calls.remove(call_id) else {
                return;
            };
            let mut actions = group_left(&call);
            actions.push(Action::Tell(
                String::from(call_id),
                call.conference_uri,
                VideoChatEvent::Failed(status_code),
            ));
            actions
        };
        self.act(actions);
    }
}

/// The ClientGroupVideoMessage of the group call `call_id` with `signal`
/// and `sdp`, to the Controlling Function of the group chat at
/// `conference_uri`; the call failing unless sent, if it is `fatal` to it
fn to_group(
    call_id: &str,
    conference_uri: &str,
    signal: Option<Signal>,
    sdp: &str,
    fatal: bool,
) -> Action {
    Action::SendGroup {
        call_id: String::from(call_id),
        conference_uri: String::from(conference_uri),
        signal,
        sdp: String::from(sdp),
        event: None,
        fatal,
    }
}

/// The JOIN of `call`, once answered and connected the first time (RCC.07
/// section 3.7.5.2.5)
fn group_joined(call: &mut GroupCall) -> Vec<Action> {
    if call.joined || call.answer != Answer::Answered || call.media != Media::Connected {
        return Vec::new();
    }
    call.joined = true;
    vec![Action::Report(
        proto::VideoChatEvent::Join,
        Reported::Group(call.conversation_id.clone()),
    )]
}

/// The LEAVE of `call` to report as it ends, if it was joined
fn group_left(call: &GroupCall) -> Vec<Action> {
    match call.joined {
        true => vec![Action::Report(
            proto::VideoChatEvent::Leave,
            Reported::Group(call.conversation_id.clone()),
        )],
        false => Vec::new(),
    }
}
