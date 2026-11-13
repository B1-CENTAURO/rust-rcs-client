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

//! RCS Video Chat, the WebRTC Messaging-Initiated Video Call of RCC.07 v18.0
//! section 3.7.5: its signalling in the 1-to-1 chat with a contact, for the
//! media the app sets up with its WebRTC stack
//!
//! The client carries the SDP offer and answer, the ICE candidates and the
//! media updates of the app between the two sides, as `rcs/video-chat+proto`
//! messages of the chat, and keeps the timers of each call (section
//! 3.7.5.2.4). Gathering ICE candidates, the DTLS-SRTP connection and the
//! codecs are the app's (sections 3.7.5.2.1, 3.7.5.3).

pub mod ffi;
pub mod proto;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

use chrono::DateTime;
use prost::Message;
use tokio::runtime::Handle;
use uuid::Uuid;

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::sip::sip_transaction::T1;

use crate::provisioning::rcs_application::RcsApplication;

use self::proto::video_chat_message::Event as Signal;
use self::proto::{
    AcceptInvitation, AckInvitation, CallInvitation, CancelInvitation, CancelReason, Hangup,
    HangupReason, IceCandidatesUpdate, RejectInvitation, RejectReason, UpdateMedia,
    VideoChatEventNotification, VideoChatMessage,
};

const LOG_TAG: &str = "video_chat";

/// The content type of the CPIM messages of RCS Video Chat (RCC.07 section
/// 3.7.5.2.3.1.1)
pub const CONTENT_TYPE: &str = "rcs/video-chat+proto";

/// The feature tag of RCS Video Chat (RCC.07 section 2.6.1.3)
pub const FEATURE_TAG: &str = "+g.gsma.rcs.videochat";

/// Timer_Alpha, Timer_Beta and Timer_Gamma: how long a call is offered for
/// before it goes unanswered, 64 times Timer_T1 (RCC.07 section 3.7.5.2.4)
pub const ANSWERED_WITHIN: Duration = Duration::from_millis(64 * T1.as_millis() as u64);

/// Timer_Delta and Timer_Epsilon: how long the media has to connect, or to
/// connect again, before the call fails, 20 times Timer_T1
pub const CONNECTED_WITHIN: Duration = Duration::from_millis(20 * T1.as_millis() as u64);

/// A TurnCredential of the configuration: TURN servers sharing a username
/// and password (RCC.07 sections 3.7.5.2.1.1, A.2.4)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnCredential {
    /// As RFC 7065 has them
    pub uris: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// The MIVC configuration of the Service Provider (RCC.07 sections 3.7.2,
/// A.1.3)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VideoChatConfig {
    /// MIVC TECHNOLOGY: 0 if the Service Provider enables no MIVCs, 1 for
    /// ViLTE alone, 2 for ViLTE with RCS Video Chat as fallback, 3 for RCS
    /// Video Chat alone
    pub technology: i32,
    /// RCS VIDEO CHAT TURN: whether the ICE candidates offered are to be
    /// those of the TURN servers of `turn_credentials` alone
    pub turn_mandatory: bool,
    pub turn_credentials: Vec<TurnCredential>,
    /// MIVC REPORTING URI: where the client tells it joined or left a call
    pub reporting_uri: Option<String>,
}

impl VideoChatConfig {
    /// The MIVC configuration of `rcs_app`; MIVC TECHNOLOGY 0 if it has no
    /// MIVC node, as the Service Provider then enables no MIVCs
    pub fn of(rcs_app: &RcsApplication) -> VideoChatConfig {
        let messaging = rcs_app.get_messaging_config();
        let Some(mivc) = messaging
            .as_ref()
            .and_then(|messaging| messaging.get_mivc_config())
        else {
            return VideoChatConfig::default();
        };
        VideoChatConfig {
            technology: mivc.get_mivc_technology(),
            turn_mandatory: mivc.get_rcs_video_chat_turn() == 1,
            turn_credentials: mivc
                .get_turn_credentials()
                .into_iter()
                .map(|(uris, username, password)| TurnCredential {
                    uris,
                    username,
                    password,
                })
                .collect(),
            reporting_uri: mivc.get_mivc_reporting_uri(),
        }
    }

    /// Whether the Service Provider enables RCS Video Chat for MIVCs, alone
    /// or as the fallback of ViLTE (RCC.07 sections 3.7.3.3, 3.7.3.4)
    pub fn enables_video_chat(&self) -> bool {
        matches!(self.technology, 2 | 3)
    }
}

/// What the app is told of a call
#[derive(Clone, Debug, PartialEq)]
pub enum VideoChatEvent {
    /// A call offered by the contact, its callee alerted (RCC.07 section
    /// 3.7.5.4.2)
    Incoming { sdp_offer: String },
    /// The callee is alerted (section 3.7.5.4.2)
    Alerting,
    /// The callee answered, the media to be connected (section 3.7.5.4.3)
    Answered { sdp_answer: String },
    /// The callee rejected the call, with a RejectReason (section 3.7.5.4.5)
    Rejected(i32),
    /// The callee did not answer in time, and the call was cancelled
    /// (sections 3.7.5.4.7, 3.7.5.4.8.1.1)
    NotAnswered,
    /// A call offered was cancelled, or went unanswered, or came too late, or
    /// while another call went on (sections 3.7.5.4.6, 3.7.5.4.7,
    /// 3.7.5.4.8.1)
    Missed,
    /// The call ended, with a HangupReason: hung up by the contact, or
    /// failed, as the media did not connect in time (sections 3.7.5.4.4,
    /// 3.7.5.4.8.1.2, 3.7.5.4.8.1.6)
    Ended(i32),
    /// What the call needed sending could not be sent, with the status code
    /// of the chat message; the call is over
    Failed(u16),
    /// ICE candidates of the contact to add and remove, the media to connect
    /// again if it had connected (section 3.7.5.4.8.2)
    IceCandidates {
        add: Vec<String>,
        remove: Vec<String>,
        reconnecting: bool,
    },
    /// The video the contact prefers to receive, and the bandwidth it can
    /// take (section 3.7.5.4.8.3)
    MediaUpdate(UpdateMedia),
}

/// Told of each call: its call_id, the contact, and what happened
pub type VideoChatListener = Arc<dyn Fn(&str, &str, VideoChatEvent) + Send + Sync>;

/// What the signalling of RCS Video Chat goes through
pub trait VideoChatLink: Send + Sync {
    /// Sends the VideoChatMessage `message`, encoded, to `contact` in the
    /// 1-to-1 chat with it (RCC.07 section 3.7.5.2.2), telling `sent` the
    /// status code it was sent with
    fn send(&self, contact: &str, message: Vec<u8>, sent: Box<dyn FnOnce(u16) + Send + Sync>);

    /// Tells the Service Provider Network at the MIVC REPORTING URI
    /// `reporting_uri` that the client joined or left a call, with the
    /// VideoChatEventNotification `notification`, encoded (section
    /// 3.7.5.2.5)
    fn report(&self, reporting_uri: &str, notification: Vec<u8>);

    /// The public user identity the client is registered with
    fn registered_uri(&self) -> Option<String>;
}

/// Where a call stands; each timer known by a token, which it fires with
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The caller waiting for an answer: Timer_Alpha until the callee is
    /// alerted, Timer_Beta until it answers
    Inviting {
        alpha: Option<u64>,
        beta: u64,
    },
    /// The callee alerted, until the call offered is too old to answer
    /// (Timer_Gamma)
    Ringing {
        gamma: u64,
    },
    /// Answered, the media to connect within Timer_Delta
    Connecting {
        delta: u64,
    },
    Connected,
    /// The media to connect again: within Timer_Delta after an ICE update,
    /// within Timer_Epsilon after it went down
    Reconnecting {
        timer: u64,
    },
}

struct Call {
    contact: String,
    outgoing: bool,
    state: State,
    /// Whether the media connected, the JOIN told (section 3.7.5.2.5)
    joined: bool,
}

/// What a change to a call has done, once the calls are no longer held
enum Action {
    /// The signal sent to the contact; the call failing unless sent, if it
    /// is `fatal` to it
    Send {
        call_id: String,
        contact: String,
        signal: Signal,
        fatal: bool,
    },
    Tell(String, String, VideoChatEvent),
    /// A JOIN or LEAVE of the call reported, with its callee if not this
    /// client
    Report(proto::VideoChatEvent, Option<String>),
    Schedule(String, u64, Duration),
}

/// The RCS Video Chats of the client
pub struct VideoChatService {
    calls: Mutex<HashMap<String, Call>>,
    config: Mutex<VideoChatConfig>,
    listener: Mutex<Option<VideoChatListener>>,
    link: Arc<dyn VideoChatLink>,
    next_timer: AtomicU64,
    rt: Handle,
    this: Weak<VideoChatService>,
}

impl VideoChatService {
    /// The service signalling through `link`, its timers kept on `rt`
    pub fn new(link: Arc<dyn VideoChatLink>, rt: Handle) -> Arc<VideoChatService> {
        Arc::new_cyclic(|this| VideoChatService {
            calls: Mutex::new(HashMap::new()),
            config: Mutex::new(VideoChatConfig::default()),
            listener: Mutex::new(None),
            link,
            next_timer: AtomicU64::new(0),
            rt,
            this: Weak::clone(this),
        })
    }

    pub fn set_config(&self, config: VideoChatConfig) {
        *self.config.lock().unwrap() = config;
    }

    pub fn config(&self) -> VideoChatConfig {
        self.config.lock().unwrap().clone()
    }

    /// Has the calls told to `listener`, the app taking RCS Video Chats from
    /// now on
    pub fn set_listener(&self, listener: VideoChatListener) {
        *self.listener.lock().unwrap() = Some(listener);
    }

    /// The feature tag of RCS Video Chat, while the Service Provider enables
    /// it and the app takes calls (RCC.07 section 3.7.3.6)
    pub fn feature_tag(&self) -> Option<&'static str> {
        let enabled = self.config.lock().unwrap().enables_video_chat();
        let listening = self.listener.lock().unwrap().is_some();
        (enabled && listening).then_some(FEATURE_TAG)
    }

    /// Calls `contact` with the SDP offer `sdp_offer` of the app (RCC.07
    /// section 3.7.5.4.1): the call_id of the call, or None if the client
    /// takes no calls, or another goes on
    pub fn start_call(&self, contact: &str, sdp_offer: &str) -> Option<String> {
        if self.feature_tag().is_none() {
            return None;
        }
        let call_id = new_call_id();
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            if !calls.is_empty() {
                return None;
            }
            let (alpha, beta) = (self.new_timer(), self.new_timer());
            calls.insert(
                call_id.clone(),
                Call {
                    contact: String::from(contact),
                    outgoing: true,
                    state: State::Inviting {
                        alpha: Some(alpha),
                        beta,
                    },
                    joined: false,
                },
            );
            vec![
                Action::Send {
                    call_id: call_id.clone(),
                    contact: String::from(contact),
                    signal: Signal::CallInvitation(CallInvitation {
                        sdp_offer: String::from(sdp_offer),
                    }),
                    fatal: true,
                },
                Action::Schedule(call_id.clone(), alpha, ANSWERED_WITHIN),
                Action::Schedule(call_id.clone(), beta, ANSWERED_WITHIN),
            ]
        };
        self.act(actions);
        Some(call_id)
    }

    /// Answers the call `call_id` offered, with the SDP answer `sdp_answer`
    /// of the app (RCC.07 section 3.7.5.4.3); whether it was offered still
    pub fn accept_call(&self, call_id: &str, sdp_answer: &str) -> bool {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.get_mut(call_id) else {
                return false;
            };
            let State::Ringing { .. } = call.state else {
                return false;
            };
            let delta = self.new_timer();
            call.state = State::Connecting { delta };
            vec![
                Action::Send {
                    call_id: String::from(call_id),
                    contact: call.contact.clone(),
                    signal: Signal::AcceptInvitation(AcceptInvitation {
                        sdp_answer: String::from(sdp_answer),
                    }),
                    fatal: true,
                },
                Action::Schedule(String::from(call_id), delta, CONNECTED_WITHIN),
            ]
        };
        self.act(actions);
        true
    }

    /// Ends the call `call_id` as the user chose: cancels it if it is not
    /// answered yet, rejects it if it is offered, hangs it up otherwise
    /// (RCC.07 sections 3.7.5.4.4 to 3.7.5.4.6); whether it went on
    pub fn hang_up(&self, call_id: &str) -> bool {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.remove(call_id) else {
                return false;
            };
            let signal = match call.state {
                State::Inviting { .. } => Signal::CancelInvitation(CancelInvitation {
                    cancel_reason: CancelReason::UserCancel as i32,
                }),
                State::Ringing { .. } => Signal::RejectInvitation(RejectInvitation {
                    reject_reason: RejectReason::UserReject as i32,
                }),
                _ => Signal::Hangup(Hangup {
                    hangup_reason: HangupReason::UserInitiated as i32,
                }),
            };
            let mut actions = vec![Action::Send {
                call_id: String::from(call_id),
                contact: call.contact.clone(),
                signal,
                fatal: false,
            }];
            actions.extend(left(&call));
            actions
        };
        self.act(actions);
        true
    }

    /// Sends the contact of the call `call_id` the ICE candidates to add and
    /// remove, as after an IP address change, the media to connect again
    /// within Timer_Delta if it had connected (RCC.07 section 3.7.5.4.8.2);
    /// whether the call goes on
    pub fn update_ice_candidates(
        &self,
        call_id: &str,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> bool {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.get_mut(call_id) else {
                return false;
            };
            let mut actions = vec![Action::Send {
                call_id: String::from(call_id),
                contact: call.contact.clone(),
                signal: Signal::IceCandidatesUpdate(IceCandidatesUpdate {
                    add_ice_candidates: add,
                    remove_ice_candidates: remove,
                }),
                fatal: false,
            }];
            actions.extend(self.reconnecting(call_id, call));
            actions
        };
        self.act(actions);
        true
    }

    /// Sends the contact of the call `call_id` the video the app prefers to
    /// receive, and the bandwidth it can take (RCC.07 section 3.7.5.4.8.3);
    /// whether the call goes on
    pub fn update_media(&self, call_id: &str, update: UpdateMedia) -> bool {
        let actions = {
            let calls = self.calls.lock().unwrap();
            let Some(call) = calls.get(call_id) else {
                return false;
            };
            vec![Action::Send {
                call_id: String::from(call_id),
                contact: call.contact.clone(),
                signal: Signal::UpdateMedia(update),
                fatal: false,
            }]
        };
        self.act(actions);
        true
    }

    /// Takes note of the media of the call `call_id` connected, or connected
    /// again, telling the Service Provider Network the client joined it the
    /// first time (RCC.07 sections 3.7.5.2.5, 3.7.5.4.3); whether the call
    /// goes on
    pub fn media_connected(&self, call_id: &str) -> bool {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.get_mut(call_id) else {
                return false;
            };
            match call.state {
                State::Connecting { .. } | State::Reconnecting { .. } => {
                    call.state = State::Connected
                }
                State::Connected => {}
                // not answered yet
                _ => return false,
            }
            if call.joined {
                return true;
            }
            call.joined = true;
            vec![Action::Report(proto::VideoChatEvent::Join, callee(call))]
        };
        self.act(actions);
        true
    }

    /// Takes note of the media of the call `call_id` gone down, for it to
    /// connect again within Timer_Epsilon (RCC.07 section 3.7.5.4.8.1.6);
    /// whether the call goes on
    pub fn media_disconnected(&self, call_id: &str) -> bool {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.get_mut(call_id) else {
                return false;
            };
            match call.state {
                State::Connected => {
                    let epsilon = self.new_timer();
                    call.state = State::Reconnecting { timer: epsilon };
                    vec![Action::Schedule(
                        String::from(call_id),
                        epsilon,
                        CONNECTED_WITHIN,
                    )]
                }
                // the timer already running
                State::Connecting { .. } | State::Reconnecting { .. } => Vec::new(),
                _ => return false,
            }
        };
        self.act(actions);
        true
    }

    /// Takes the VideoChatMessage `body` of the 1-to-1 chat with `contact`,
    /// its CPIM DateTime `date` when the contact sent it
    pub fn on_message(&self, contact: &str, date: &str, body: &[u8]) {
        let message = match VideoChatMessage::decode(body) {
            Ok(message) => message,
            Err(e) => {
                platform_log(LOG_TAG, format!("video chat message not read: {:?}", e));
                return;
            }
        };
        let (Some(signal), false) = (message.event, message.call_id.is_empty()) else {
            return;
        };
        if self.listener.lock().unwrap().is_none() {
            return;
        }
        let call_id = message.call_id;
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            match signal {
                Signal::CallInvitation(invitation) => {
                    self.invited(&mut calls, call_id, contact, date, invitation)
                }
                signal => {
                    let Some(call) = calls.get_mut(&call_id) else {
                        return;
                    };
                    if !same_contact(&call.contact, contact) {
                        platform_log(LOG_TAG, "video chat message of another contact");
                        return;
                    }
                    self.signalled(&mut calls, call_id, signal)
                }
            }
        };
        self.act(actions);
    }

    /// The call `call_id` that `contact` offers, the CallInvitation sent at
    /// `date` (RCC.07 sections 3.7.5.4.2, 3.7.5.4.8.1)
    fn invited(
        &self,
        calls: &mut HashMap<String, Call>,
        call_id: String,
        contact: &str,
        date: &str,
        invitation: CallInvitation,
    ) -> Vec<Action> {
        // sent again
        if calls.contains_key(&call_id) {
            return Vec::new();
        }
        let missed = Action::Tell(
            call_id.clone(),
            String::from(contact),
            VideoChatEvent::Missed,
        );
        // too old to ring, as one stored and forwarded (Timer_Gamma)
        let Some(ringing_for) = ringing_for(date, SystemTime::now()) else {
            return vec![missed];
        };
        if !calls.is_empty() {
            return vec![
                Action::Send {
                    call_id,
                    contact: String::from(contact),
                    signal: Signal::RejectInvitation(RejectInvitation {
                        reject_reason: RejectReason::AlreadyInProgress as i32,
                    }),
                    fatal: false,
                },
                missed,
            ];
        }
        let gamma = self.new_timer();
        calls.insert(
            call_id.clone(),
            Call {
                contact: String::from(contact),
                outgoing: false,
                state: State::Ringing { gamma },
                joined: false,
            },
        );
        vec![
            Action::Send {
                call_id: call_id.clone(),
                contact: String::from(contact),
                signal: Signal::AckInvitation(AckInvitation {}),
                fatal: false,
            },
            Action::Schedule(call_id.clone(), gamma, ringing_for),
            Action::Tell(
                call_id,
                String::from(contact),
                VideoChatEvent::Incoming {
                    sdp_offer: invitation.sdp_offer,
                },
            ),
        ]
    }

    /// `signal` of the contact of the call `call_id`
    fn signalled(
        &self,
        calls: &mut HashMap<String, Call>,
        call_id: String,
        signal: Signal,
    ) -> Vec<Action> {
        let Some(call) = calls.get_mut(&call_id) else {
            return Vec::new();
        };
        let contact = call.contact.clone();
        let tell = |event| Action::Tell(call_id.clone(), contact.clone(), event);
        let (actions, ended) = match (signal, call.state, call.outgoing) {
            (Signal::AckInvitation(_), State::Inviting { alpha: Some(_), beta }, true) => {
                call.state = State::Inviting { alpha: None, beta };
                (vec![tell(VideoChatEvent::Alerting)], false)
            }
            (Signal::AcceptInvitation(accept), State::Inviting { .. }, true) => {
                let delta = self.new_timer();
                call.state = State::Connecting { delta };
                let answered = VideoChatEvent::Answered {
                    sdp_answer: accept.sdp_answer,
                };
                (
                    vec![
                        Action::Schedule(call_id.clone(), delta, CONNECTED_WITHIN),
                        tell(answered),
                    ],
                    false,
                )
            }
            (Signal::RejectInvitation(reject), State::Inviting { .. }, true) => (
                vec![tell(VideoChatEvent::Rejected(reject.reject_reason))],
                true,
            ),
            (Signal::CancelInvitation(_), State::Ringing { .. }, false)
            // hung up before it was answered
            | (Signal::Hangup(_), State::Ringing { .. }, false) => {
                (vec![tell(VideoChatEvent::Missed)], true)
            }
            (Signal::Hangup(hangup), State::Inviting { .. }, true) => {
                (vec![tell(VideoChatEvent::Ended(hangup.hangup_reason))], true)
            }
            // hung up in turn, with the same reason (sections 3.7.5.4.4,
            // 3.7.5.4.8.1.2)
            (Signal::Hangup(hangup), _, _) => {
                let reason = hangup.hangup_reason;
                let mut actions = vec![Action::Send {
                    call_id: call_id.clone(),
                    contact: contact.clone(),
                    signal: Signal::Hangup(hangup),
                    fatal: false,
                }];
                actions.extend(left(call));
                actions.push(tell(VideoChatEvent::Ended(reason)));
                (actions, true)
            }
            (Signal::IceCandidatesUpdate(update), _, _) => {
                let mut actions = self.reconnecting(&call_id, call);
                let reconnecting = !actions.is_empty();
                actions.push(tell(VideoChatEvent::IceCandidates {
                    add: update.add_ice_candidates,
                    remove: update.remove_ice_candidates,
                    reconnecting,
                }));
                (actions, false)
            }
            (Signal::UpdateMedia(update), _, _) => {
                (vec![tell(VideoChatEvent::MediaUpdate(update))], false)
            }
            _ => (Vec::new(), false),
        };
        if ended {
            calls.remove(&call_id);
        }
        actions
    }

    /// The call `call` to connect again within Timer_Delta, if it had
    /// connected, as after an IP address change (RCC.07 section
    /// 3.7.5.4.8.2)
    fn reconnecting(&self, call_id: &str, call: &mut Call) -> Vec<Action> {
        match call.state {
            State::Connected | State::Reconnecting { .. } => {
                let delta = self.new_timer();
                call.state = State::Reconnecting { timer: delta };
                vec![Action::Schedule(
                    String::from(call_id),
                    delta,
                    CONNECTED_WITHIN,
                )]
            }
            _ => Vec::new(),
        }
    }

    /// The timer `timer` of the call `call_id` run out, if the call still
    /// waits for it (RCC.07 section 3.7.5.2.4)
    fn timed_out(&self, call_id: &str, timer: u64) {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.get(call_id) else {
                return;
            };
            let send = |signal| Action::Send {
                call_id: String::from(call_id),
                contact: call.contact.clone(),
                signal,
                fatal: false,
            };
            let tell = |event| Action::Tell(String::from(call_id), call.contact.clone(), event);
            let actions = match call.state {
                // not answered: Timer_Alpha or Timer_Beta (sections
                // 3.7.5.4.7, 3.7.5.4.8.1.1)
                State::Inviting { alpha, beta } if alpha == Some(timer) || beta == timer => {
                    vec![
                        send(Signal::CancelInvitation(CancelInvitation {
                            cancel_reason: CancelReason::Timeout as i32,
                        })),
                        tell(VideoChatEvent::NotAnswered),
                    ]
                }
                // too late to answer: Timer_Gamma
                State::Ringing { gamma } if gamma == timer => vec![tell(VideoChatEvent::Missed)],
                // the media not connected: Timer_Delta or Timer_Epsilon
                // (sections 3.7.5.4.8.1.2, 3.7.5.4.8.1.6)
                State::Connecting { delta: running } | State::Reconnecting { timer: running }
                    if running == timer =>
                {
                    let mut actions = vec![send(Signal::Hangup(Hangup {
                        hangup_reason: HangupReason::ClientTimeout as i32,
                    }))];
                    actions.extend(left(call));
                    actions.push(tell(VideoChatEvent::Ended(
                        HangupReason::ClientTimeout as i32,
                    )));
                    actions
                }
                _ => return,
            };
            calls.remove(call_id);
            actions
        };
        self.act(actions);
    }

    /// The call `call_id` failed, as what it needed sending was not sent,
    /// with `status_code`
    fn failed(&self, call_id: &str, status_code: u16) {
        let actions = {
            let mut calls = self.calls.lock().unwrap();
            let Some(call) = calls.remove(call_id) else {
                return;
            };
            let mut actions = left(&call);
            actions.push(Action::Tell(
                String::from(call_id),
                call.contact,
                VideoChatEvent::Failed(status_code),
            ));
            actions
        };
        self.act(actions);
    }

    fn new_timer(&self) -> u64 {
        self.next_timer.fetch_add(1, Ordering::Relaxed)
    }

    /// Does `actions`, the calls no longer held
    fn act(&self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send {
                    call_id,
                    contact,
                    signal,
                    fatal,
                } => {
                    let message = VideoChatMessage {
                        call_id: call_id.clone(),
                        event: Some(signal),
                    };
                    let this = Weak::clone(&self.this);
                    self.link.send(
                        &contact,
                        message.encode_to_vec(),
                        Box::new(move |status_code| {
                            if (200..300).contains(&status_code) {
                                return;
                            }
                            platform_log(
                                LOG_TAG,
                                format!("video chat message not sent: {}", status_code),
                            );
                            if let (true, Some(this)) = (fatal, this.upgrade()) {
                                this.failed(&call_id, status_code);
                            }
                        }),
                    );
                }
                Action::Tell(call_id, contact, event) => {
                    let listener = self.listener.lock().unwrap().clone();
                    if let Some(listener) = listener {
                        listener(&call_id, &contact, event);
                    }
                }
                // if the configuration has where to
                Action::Report(event, callee) => {
                    let Some(reporting_uri) = self.config.lock().unwrap().reporting_uri.clone()
                    else {
                        continue;
                    };
                    let Some(callee) = callee.or_else(|| self.link.registered_uri()) else {
                        continue;
                    };
                    let notification = VideoChatEventNotification {
                        one_to_one_participant_uri: callee,
                        group_conversation_id: String::new(),
                        video_chat_event: event as i32,
                    };
                    self.link
                        .report(&reporting_uri, notification.encode_to_vec());
                }
                Action::Schedule(call_id, timer, after) => {
                    let this = Weak::clone(&self.this);
                    self.rt.spawn(async move {
                        tokio::time::sleep(after).await;
                        if let Some(this) = this.upgrade() {
                            this.timed_out(&call_id, timer);
                        }
                    });
                }
            }
        }
    }
}

/// The LEAVE of `call` to report as it ends, if it was joined (RCC.07
/// section 3.7.5.2.5)
fn left(call: &Call) -> Vec<Action> {
    match call.joined {
        true => vec![Action::Report(proto::VideoChatEvent::Leave, callee(call))],
        false => Vec::new(),
    }
}

/// The callee of `call`, unless it is this client, whose URI is the one it
/// is registered with: the one_to_one_participant_uri of a
/// VideoChatEventNotification (RCC.07 section 3.7.5.2.3.4)
fn callee(call: &Call) -> Option<String> {
    call.outgoing.then(|| call.contact.clone())
}

fn new_call_id() -> String {
    String::from(
        Uuid::new_v4()
            .as_hyphenated()
            .encode_lower(&mut Uuid::encode_buffer()),
    )
}

/// How long a callee is alerted of a call offered, given the CPIM DateTime
/// `date` of the CallInvitation, at `now`: until 64 times Timer_T1 after it
/// was sent, or None if that is past (RCC.07 section 3.7.5.2.4.3); at most
/// that long, should the clock of the caller be ahead, and that long if the
/// DateTime cannot be read
fn ringing_for(date: &str, now: SystemTime) -> Option<Duration> {
    let Ok(sent) = DateTime::parse_from_rfc3339(date.trim()) else {
        return Some(ANSWERED_WITHIN);
    };
    let sent = SystemTime::from(sent);
    match now.duration_since(sent) {
        Ok(age) => ANSWERED_WITHIN
            .checked_sub(age)
            .filter(|left| !left.is_zero()),
        Err(_) => Some(ANSWERED_WITHIN),
    }
}

/// Whether the URIs `a` and `b` are of the same contact: alike, or of the
/// same global number, as a tel URI and a SIP URI of a number may be
fn same_contact(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    matches!((global_number(a), global_number(b)), (Some(a), Some(b)) if a == b)
}

/// The global number of a tel URI, or of the user of a SIP URI, with its
/// visual separators left out
fn global_number(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("tel") && !scheme.eq_ignore_ascii_case("sip") {
        return None;
    }
    let user = rest.split(['@', ';']).next()?;
    let number: String = user
        .chars()
        .filter(|c| !matches!(c, '-' | '.' | '(' | ')'))
        .collect();
    (number.len() > 1 && number.starts_with('+') && number[1..].chars().all(|c| c.is_ascii_digit()))
        .then_some(number)
}
