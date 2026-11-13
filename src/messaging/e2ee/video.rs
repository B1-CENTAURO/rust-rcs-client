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

//! The keys of the media of the Group RCS Video Chats of the group chats
//! encrypted end to end (RCC.16 section 9.8.2)
//!
//! The media of such a call is encrypted with SFrame (RFC 9605), each frame
//! on its own, by the app, with the keys of its call: an SframeSession keyed
//! from the epochs of the MLS group (RFC 9605 section 5.2).
//!
//! As a Commit moves the group to a new epoch, the keys of the new epoch
//! are taken at once, frames of it decrypted from then on, but frames go on
//! being sent in the epoch before:
//! - the client that sent the Commit switches once all the other clients
//!   of the call delivered it, which it asks them to tell it of, and the app
//!   is told then, to send an empty frame if it sends none;
//! - the others once a frame of the committer in the new epoch comes.
//!
//! Each switches all the same once a wait runs out: RCC.16 asks no client to
//! tell of the delivery of a Commit, which reaches it in a message of the
//! Conversation Focus, nor a client that is not in the call to send a frame.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rust_rcs_core::cpim::CPIMInfo;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::imdn::notification::{Imdn, Notification, Status};
use rust_rcs_core::mls::rcs::same_tel_uri;
use rust_rcs_core::mls::rcs::sframe::{CipherSuite, SframeSession, DEFAULT_LAYOUT};
use rust_rcs_core::mls::{Credential, ErrorKind};
use rust_rcs_core::sip::sip_transaction::T1;
use uuid::Uuid;

use super::device::{participant_tel_uri, E2eeDevice};
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

/// The SFrame cipher suite of the calls, that of the MLS cipher suite of
/// RCC.16, MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (RFC 9605 section 4.5)
pub const SUITE: CipherSuite = CipherSuite::AesGcm128Sha256;

/// How many bytes SFrame adds to a frame at most: the header, a config byte
/// and a Key ID and a counter of up to 8 bytes each, then the authentication
/// tag (RFC 9605 sections 4.3, 4.5)
pub const FRAME_OVERHEAD: usize = 1 + 8 + 8 + 16;

/// How long the client that sent a Commit waits for all the others of the
/// call to deliver it before it switches all the same: 20·T1, as long as
/// Timer_Delta waits for media to connect (RCC.07 section 3.7.5.2.4.4)
pub const RECEIPTS_WAIT: Duration = Duration::from_millis(20 * T1.as_millis() as u64);

/// How long the others wait for a frame of the committer in the new epoch
/// before they switch all the same: 64·T1, longer than the committer waits
pub const COMMITTER_WAIT: Duration = Duration::from_millis(64 * T1.as_millis() as u64);

/// Told of the keys of the call `call_id` switched to the epoch `epoch`, a
/// Commit of this client moving its group there: an empty frame is to be
/// sent with them if no media is, for the others to switch (RCC.16 section
/// 9.8.2)
pub type CallKeysListener = Arc<dyn Fn(&str, u64) + Send + Sync>;

/// Why a frame of a call is not encrypted or decrypted
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The call has no keys: it is not of a group encrypted end to end, or
    /// it ended
    NoKeys,
    /// The frame is of no epoch kept, or does not open: it is not to be
    /// played
    Rejected,
    /// The frame was taken already, or is too old to tell (RFC 9605 section
    /// 9.3)
    Replayed,
}

/// The switch of the keys of a call to the epoch a Commit moved its group to
struct Switch {
    /// When the call switches at the latest
    deadline: SystemTime,
    /// For a Commit of this client, its Message-ID, and the participants of
    /// the call yet to deliver it
    receipts: Option<(String, Vec<String>)>,
}

/// The keys of a call
struct CallKeys {
    conversation_id: String,
    session: SframeSession,
    /// The Era of the MLS group the session was made from, and the leaf of
    /// this client in it, which the session sends as
    era: Option<u32>,
    leaf_index: u32,
    /// The participants of the call besides this client, as the
    /// Controlling Function tells them
    participants: Vec<String>,
    switch: Option<Switch>,
}

impl CallKeys {
    /// Sends in the epoch to switch to from now on if its deadline passed;
    /// the epoch if it is that of a Commit of this client, which the app is
    /// told of
    fn switch_if_due(&mut self, now: SystemTime) -> Option<u64> {
        if !self
            .switch
            .as_ref()
            .is_some_and(|switch| now >= switch.deadline)
        {
            return None;
        }
        self.switch_now()
    }

    /// Sends in the epoch to switch to from now on; the epoch if it is that
    /// of a Commit of this client
    fn switch_now(&mut self) -> Option<u64> {
        let switch = self.switch.take()?;
        (self.session.switch_to_new_epoch() && switch.receipts.is_some())
            .then(|| self.session.sending_epoch())
    }

    /// Switches if the participants left to deliver the Commit of this
    /// client are none
    fn switch_if_delivered(&mut self) -> Option<u64> {
        let delivered = self
            .switch
            .as_ref()
            .and_then(|switch| switch.receipts.as_ref())
            .is_some_and(|(_, waiting)| waiting.is_empty());
        match delivered {
            true => self.switch_now(),
            false => None,
        }
    }
}

/// The URI of the CPIM From of `cpim_info`
fn cpim_from(cpim_info: &CPIMInfo) -> String {
    match &cpim_info.from_uri {
        Some(uri) => {
            String::from_utf8_lossy(&uri.string_representation_without_query_and_fragment())
                .into_owned()
        }
        None => {
            let from = String::from_utf8_lossy(cpim_info.from);
            let from = from.trim();
            let uri = match (from.find('<'), from.rfind('>')) {
                (Some(start), Some(end)) if start < end => &from[start + 1..end],
                _ => from,
            };
            String::from(uri)
        }
    }
}

/// Whether the URIs `a` and `b` are of the same participant, by the tel URI
/// of each, or the same otherwise
pub(super) fn same_participant(a: &str, b: &str) -> bool {
    let tel_uri = |uri: &str| participant_tel_uri(std::iter::once(uri), None);
    match (tel_uri(a), tel_uri(b)) {
        (Some(a), Some(b)) => same_tel_uri(&a, &b),
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// A Context ID for a session, at random, so that one made again for the
/// same leaf in the same epoch never sends under the same Key IDs: those
/// bits of the Key ID DEFAULT_LAYOUT leaves for it
fn context_id() -> u64 {
    let bits = 64 - u32::from(DEFAULT_LAYOUT.epoch_bits()) - u32::from(DEFAULT_LAYOUT.index_bits());
    (Uuid::new_v4().as_u128() as u64) >> (64 - bits)
}

/// How many of the Commits sent asking for receipts are known by their
/// Message-ID, for their receipts not to go to the app
pub(super) const ASKED_KEPT: usize = 16;

/// The keys of the calls of the device, by call_id
#[derive(Default)]
pub(super) struct VideoCalls {
    calls: Mutex<HashMap<String, CallKeys>>,
    listener: Mutex<Option<CallKeysListener>>,
    /// The Message-IDs of the last control messages sent asking for
    /// receipts, with their group
    asked: Mutex<VecDeque<(String, String)>>,
}

impl VideoCalls {
    /// Takes note of the control message `message_id` of the group
    /// `conversation_id` asking for receipts
    pub(super) fn asked(&self, conversation_id: &str, message_id: &str) {
        let mut asked = self.asked.lock().unwrap();
        if asked.len() == ASKED_KEPT {
            asked.pop_front();
        }
        asked.push_back((String::from(conversation_id), String::from(message_id)));
    }

    /// Whether the control message `message_id` of the group
    /// `conversation_id` asked for receipts
    fn was_asked(&self, conversation_id: &str, message_id: &str) -> bool {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .any(|(group, asked)| group == conversation_id && asked == message_id)
    }

    /// Whether a call of the group `conversation_id` has keys
    pub(super) fn in_call(&self, conversation_id: &str) -> bool {
        self.calls
            .lock()
            .unwrap()
            .values()
            .any(|call| call.conversation_id == conversation_id)
    }

    /// Tells the listener of the calls `switched` switched to the epoch of a
    /// Commit of this client, outside the lock of the calls, as it may
    /// encrypt a frame at once
    fn tell(&self, switched: Vec<(String, u64)>) {
        if switched.is_empty() {
            return;
        }
        let listener = self.listener.lock().unwrap().clone();
        if let Some(listener) = listener {
            for (call_id, epoch) in switched {
                listener(&call_id, epoch);
            }
        }
    }
}

impl E2eeDevice {
    /// Has `listener` told of the keys of a call switched to the epoch of a
    /// Commit of this client
    pub fn set_call_keys_listener(&self, listener: CallKeysListener) {
        *self.video_calls().listener.lock().unwrap() = Some(listener);
    }

    /// Makes the keys of the Group RCS Video Chat `call_id` of the group
    /// chat `conversation_id`, if that is encrypted end to end: whether it
    /// is, or Err if its keys cannot be made (RCC.16 section 9.8.2)
    ///
    /// The keys are of the epoch the group is in. Those made again for a
    /// call replace those it had.
    pub fn start_call_keys(
        &self,
        call_id: &str,
        conversation_id: &str,
    ) -> Result<bool, StoreError> {
        if !self.store().has_conversation(conversation_id.as_bytes())
            || self.encryption_ended(conversation_id)
        {
            return Ok(false);
        }
        let call = self.call_keys_of(conversation_id)?;
        self.video_calls()
            .calls
            .lock()
            .unwrap()
            .insert(String::from(call_id), call);
        Ok(true)
    }

    /// New keys of a call of the group `conversation_id`, from the epoch it
    /// is in, of no participants yet
    fn call_keys_of(&self, conversation_id: &str) -> Result<CallKeys, StoreError> {
        let (session, era, leaf_index) = self
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                let session =
                    SframeSession::of(conversation, client, SUITE, DEFAULT_LAYOUT, context_id())?;
                Ok::<_, ErrorKind>((session, conversation.era(), conversation.own_leaf_index()))
            })?
            .map_err(StoreError::Mls)?;
        Ok(CallKeys {
            conversation_id: String::from(conversation_id),
            session,
            era,
            leaf_index,
            participants: Vec::new(),
            switch: None,
        })
    }

    /// Lets go of the keys of the call `call_id`, which ended
    pub fn end_call_keys(&self, call_id: &str) {
        self.video_calls().calls.lock().unwrap().remove(call_id);
    }

    /// Whether the media of the call `call_id` is encrypted, the call having
    /// keys
    pub fn encrypts_call(&self, call_id: &str) -> bool {
        self.video_calls()
            .calls
            .lock()
            .unwrap()
            .contains_key(call_id)
    }

    /// Takes `participants`, the URIs of the participants of the call
    /// `call_id` besides this client, as the Controlling Function tells
    /// them: a Commit of this client waits for those still in the call
    /// alone to deliver it
    pub fn call_participants(&self, call_id: &str, participants: Vec<String>) {
        let switched = {
            let mut calls = self.video_calls().calls.lock().unwrap();
            let Some(call) = calls.get_mut(call_id) else {
                return;
            };
            if let Some((_, waiting)) = call
                .switch
                .as_mut()
                .and_then(|switch| switch.receipts.as_mut())
            {
                waiting.retain(|participant| {
                    participants
                        .iter()
                        .any(|other| same_participant(participant, other))
                });
            }
            call.participants = participants;
            call.switch_if_delivered()
                .map(|epoch| (String::from(call_id), epoch))
        };
        self.video_calls().tell(switched.into_iter().collect());
    }

    /// Takes the group `conversation_id` in a new epoch, as a Commit of
    /// `committer` moved it there, of Message-ID `message_id` if it is a
    /// Commit of this client: the keys of its calls take those of the
    /// epoch, switched to as RCC.16 section 9.8.2 has it
    ///
    /// The keys of a call whose group is in a new Era, or which this client
    /// is at another leaf of, are made anew, from the epoch the group is in.
    pub(super) fn call_keys_advanced(
        &self,
        conversation_id: &str,
        committer: &Credential,
        message_id: Option<&str>,
    ) {
        let now = self.store().now();
        let switched: Vec<(String, u64)> = {
            let mut calls = self.video_calls().calls.lock().unwrap();
            let mut switched = Vec::new();
            for (call_id, call) in calls
                .iter_mut()
                .filter(|(_, call)| call.conversation_id == conversation_id)
            {
                let advanced = self
                    .store()
                    .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                        let base_key = conversation.sframe_base_key(client, SUITE)?;
                        Ok::<_, ErrorKind>((
                            conversation.era(),
                            conversation.epoch(),
                            conversation.own_leaf_index(),
                            conversation.leaf_index_of(committer),
                            base_key,
                        ))
                    })
                    .and_then(|advanced| advanced.map_err(StoreError::Mls));
                let (era, epoch, leaf_index, committer, base_key) = match advanced {
                    Ok(advanced) => advanced,
                    Err(e) => {
                        platform_log(LOG_TAG, format!("call keys not advanced: {:?}", e));
                        continue;
                    }
                };
                // in a new Era of the group, as one of this client the Focus
                // accepted, or at another leaf: made anew
                if era != call.era || leaf_index != call.leaf_index {
                    self.remake(call);
                    continue;
                }
                // one that left in it can send no frame of it
                let committer = committer.unwrap_or(u32::MAX);
                call.session.epoch_advanced(epoch, base_key, committer);
                call.switch = Some(match committer == leaf_index {
                    true => Switch {
                        deadline: now + RECEIPTS_WAIT,
                        receipts: Some((
                            String::from(message_id.unwrap_or_default()),
                            call.participants.clone(),
                        )),
                    },
                    false => Switch {
                        deadline: now + COMMITTER_WAIT,
                        receipts: None,
                    },
                });
                if let Some(epoch) = call.switch_if_delivered() {
                    switched.push((call_id.clone(), epoch));
                }
            }
            switched
        };
        self.video_calls().tell(switched);
    }

    /// Whether the notification `imdn` received in the group
    /// `conversation_id`, in the CPIM message `cpim_info` tells of, signed
    /// by whom it is from, tells of the delivery of a control message this
    /// client asked to be told the delivery of during a call: a call
    /// waiting for it switches once all its participants delivered it
    /// (RCC.16 section 9.8.2); not for the app
    pub fn commit_delivered(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        imdn: &[u8],
    ) -> bool {
        let Some(notification) = Imdn::from_xml(imdn) else {
            return false;
        };
        if notification.notification != Notification::Delivery
            || !self
                .video_calls()
                .was_asked(conversation_id, &notification.message_id)
        {
            return false;
        }
        if notification.status == Status::Delivered {
            let from = cpim_from(cpim_info);
            self.call_keys_delivered(conversation_id, &notification.message_id, &from);
        }
        true
    }

    /// Makes the keys of the calls of the group `conversation_id` anew, from
    /// the epoch it is in, as once the device joined it again, at another
    /// leaf: frames are sent in it at once
    pub(super) fn call_keys_remade(&self, conversation_id: &str) {
        let mut calls = self.video_calls().calls.lock().unwrap();
        for call in calls
            .values_mut()
            .filter(|call| call.conversation_id == conversation_id)
        {
            self.remake(call);
        }
    }

    /// Makes the keys `call` anew, from the epoch its group is in, keeping
    /// its participants
    fn remake(&self, call: &mut CallKeys) {
        match self.call_keys_of(&call.conversation_id) {
            Ok(mut made) => {
                made.participants = std::mem::take(&mut call.participants);
                *call = made;
            }
            Err(e) => platform_log(LOG_TAG, format!("call keys not made again: {:?}", e)),
        }
    }

    /// Takes the delivery of the message `message_id` in the group
    /// `conversation_id` by the participant `from`: a call waiting for it to
    /// deliver the Commit of this client switches once all its participants
    /// did (RCC.16 section 9.8.2)
    fn call_keys_delivered(&self, conversation_id: &str, message_id: &str, from: &str) {
        let switched: Vec<(String, u64)> = {
            let mut calls = self.video_calls().calls.lock().unwrap();
            calls
                .iter_mut()
                .filter(|(_, call)| call.conversation_id == conversation_id)
                .filter_map(|(call_id, call)| {
                    let (commit, waiting) = call
                        .switch
                        .as_mut()
                        .and_then(|switch| switch.receipts.as_mut())?;
                    if commit != message_id {
                        return None;
                    }
                    waiting.retain(|participant| !same_participant(participant, from));
                    call.switch_if_delivered()
                        .map(|epoch| (call_id.clone(), epoch))
                })
                .collect()
        };
        self.video_calls().tell(switched);
    }

    /// The frame `frame` of the call `call_id` encrypted with its keys,
    /// `metadata` authenticated with it, as an SFrame frame (RFC 9605
    /// section 4.4.3)
    pub fn encrypt_call_frame(
        &self,
        call_id: &str,
        metadata: &[u8],
        frame: &[u8],
    ) -> Result<Vec<u8>, FrameError> {
        let now = self.store().now();
        let (encrypted, switched) = {
            let mut calls = self.video_calls().calls.lock().unwrap();
            let call = calls.get_mut(call_id).ok_or(FrameError::NoKeys)?;
            let switched = call.switch_if_due(now);
            let encrypted = call
                .session
                .encrypt(metadata, frame)
                .map_err(|_| FrameError::Rejected);
            (encrypted, switched)
        };
        self.video_calls().tell(
            switched
                .map(|epoch| (String::from(call_id), epoch))
                .into_iter()
                .collect(),
        );
        encrypted
    }

    /// The frame the SFrame frame `encrypted` of the call `call_id` carries,
    /// `metadata` authenticated with it (RFC 9605 section 4.4.4); a frame of
    /// the committer in the epoch to switch to has the keys switch to it
    /// (RCC.16 section 9.8.2)
    pub fn decrypt_call_frame(
        &self,
        call_id: &str,
        metadata: &[u8],
        encrypted: &[u8],
    ) -> Result<Vec<u8>, FrameError> {
        let now = self.store().now();
        let (decrypted, switched) = {
            let mut calls = self.video_calls().calls.lock().unwrap();
            let call = calls.get_mut(call_id).ok_or(FrameError::NoKeys)?;
            let switched = call.switch_if_due(now);
            let decrypted = call.session.decrypt(metadata, encrypted);
            let decrypted = decrypted.map(|frame| frame.frame).map_err(|e| match e {
                ErrorKind::Replayed => FrameError::Replayed,
                _ => FrameError::Rejected,
            });
            (decrypted, switched)
        };
        self.video_calls().tell(
            switched
                .map(|epoch| (String::from(call_id), epoch))
                .into_iter()
                .collect(),
        );
        decrypted
    }
}
