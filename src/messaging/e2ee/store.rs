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

//! The MLS state of the device: the Participant Key of its user, one MLS
//! client, and the groups it takes part in, kept by the app with the notes
//! the device keeps besides: the messages it could not decrypt, and those
//! it sent, to re-send
//!
//! The state holds the private keys of the device and the secrets of every
//! group. A change to it has to be kept before anything it produced is sent:
//! sending again from an older state reuses message keys (see
//! `MlsClient::snapshot()`). Every call made through the store is followed by
//! the app keeping the state; one it cannot keep is undone, and what the call
//! produced is not given out.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rust_rcs_core::mls::rcs::{ClientIdentity, ParticipantKey};
use rust_rcs_core::mls::{
    self, Clock, Credential, CredentialValidator, ErrorKind, MlsClient, MlsConfig, MlsConversation,
    SignatureKeyPair,
};

/// Starts the state kept: the Participant Key, whether the KeyPackages of the
/// client were uploaded, the notes of the device, then the client
const STATE_MAGIC: &[u8] = b"RCS-E2EE3";

/// Starts a state kept before the device kept notes, taken on with none
const STATE_MAGIC_WITHOUT_NOTES: &[u8] = b"RCS-E2EE2";

/// Keeps the state given, encrypted, in place of the one kept before; false if
/// it could not. Called with the store locked, it must not call into it.
pub type SaveState = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// There is no MLS client yet
    NoClient,
    /// What MLS made of the call
    Mls(ErrorKind),
    /// The Participant Key could not sign for the client
    Participant,
    /// The state the call left could not be kept, and is undone
    NotSaved,
}

pub struct MlsStore {
    config: MlsConfig,
    validator: Arc<dyn CredentialValidator>,
    save: SaveState,
    state: Mutex<State>,
    /// What the clients tell the time by, if not the system clock
    clock: Mutex<Option<Clock>>,
}

struct State {
    /// The Participant Key, made the first time it is asked for
    participant: Option<ParticipantKey>,
    client: Option<MlsClient>,
    /// Whether KeyPackages of the client reached the Home KDS
    uploaded: bool,
    /// What the device keeps besides MLS, encoded as it does: the messages
    /// it could not decrypt
    notes: Vec<u8>,
    /// The state last kept, which a change that could not be kept is undone to
    saved: Vec<u8>,
    /// The groups loaded, as they hold what only lives in memory: a Commit of
    /// this client applied, to be recognised when the Conversation Focus
    /// delivers it back
    conversations: HashMap<Vec<u8>, MlsConversation>,
}

impl MlsStore {
    /// A store without a client yet, saving with `save`
    pub fn new(
        config: MlsConfig,
        validator: Arc<dyn CredentialValidator>,
        save: SaveState,
    ) -> MlsStore {
        MlsStore {
            config,
            validator,
            save,
            state: Mutex::new(State {
                participant: None,
                client: None,
                uploaded: false,
                notes: Vec::new(),
                saved: Vec::new(),
                conversations: HashMap::new(),
            }),
            clock: Mutex::new(None),
        }
    }

    /// Has the client, and those taken on from now on, tell the time by
    /// `clock` rather than the system clock
    pub fn set_clock(&self, clock: Clock) {
        let mut state = self.state.lock().unwrap();
        if let Some(client) = state.client.as_mut() {
            client.set_clock(clock.clone());
        }
        *self.clock.lock().unwrap() = Some(clock);
    }

    /// The time the client tells: by the clock of the store if it has one,
    /// else by the system clock
    pub fn now(&self) -> SystemTime {
        match self.clock.lock().unwrap().as_ref() {
            Some(clock) => clock(),
            None => SystemTime::now(),
        }
    }

    /// `client`, telling the time by the clock of the store if it has one
    fn timed(&self, mut client: MlsClient) -> MlsClient {
        if let Some(clock) = self.clock.lock().unwrap().clone() {
            client.set_clock(clock);
        }
        client
    }

    /// Takes on the client `make` makes with the store's configuration and
    /// validator, kept at once, in place of any before
    pub fn create<F>(&self, make: F) -> Result<(), StoreError>
    where
        F: FnOnce(MlsConfig, Box<dyn CredentialValidator>) -> mls::Result<MlsClient>,
    {
        // locked while kept, as the states are kept in the order they come
        let mut state = self.state.lock().unwrap();
        let client = make(self.config, self.shared_validator()).map_err(StoreError::Mls)?;
        let client = self.timed(client);
        let saved = pack(
            state.participant.as_ref(),
            Some(&client),
            false,
            &state.notes,
        )?;
        if !(self.save)(&saved) {
            return Err(StoreError::NotSaved);
        }

        state.client = Some(client);
        state.uploaded = false;
        state.saved = saved;
        state.conversations.clear();
        Ok(())
    }

    /// Has the client take on `credential`, a certificate renewed for the
    /// key of `signer`, its groups kept (RCC.16 section 9.5.3): its
    /// KeyPackages are to be uploaded again
    pub fn renew(
        &self,
        credential: Credential,
        signer: SignatureKeyPair,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap();
        let client = state.client.as_mut().ok_or(StoreError::NoClient)?;
        client.renew(credential, signer).map_err(StoreError::Mls)?;
        state.uploaded = false;
        self.save(&mut state)
    }

    /// Takes on the Participant Key, the client and the notes in `saved`, a
    /// state the app kept
    pub fn restore(&self, saved: &[u8]) -> Result<(), StoreError> {
        let (participant, client, uploaded, notes) = self.unpack(saved)?;

        let mut state = self.state.lock().unwrap();
        state.participant = participant;
        state.client = client;
        state.uploaded = uploaded;
        state.notes = notes;
        state.saved = saved.to_vec();
        state.conversations.clear();
        Ok(())
    }

    /// Whether KeyPackages of the client reached the Home KDS
    pub fn key_packages_uploaded(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.client.is_some() && state.uploaded
    }

    /// Keeps that KeyPackages of the client reached the Home KDS
    pub fn set_key_packages_uploaded(&self) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap();
        if state.client.is_none() {
            return Err(StoreError::NoClient);
        }
        if state.uploaded {
            return Ok(());
        }
        state.uploaded = true;
        self.save(&mut state)
    }

    /// What the device keeps besides MLS, as it last kept it
    pub fn notes(&self) -> Vec<u8> {
        self.state.lock().unwrap().notes.clone()
    }

    /// Keeps `notes`, what the device keeps besides MLS, along with the rest
    /// of the state; those kept before stay if they cannot be
    pub fn keep_notes(&self, notes: Vec<u8>) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap();
        if state.notes == notes {
            return Ok(());
        }
        let saved = pack(
            state.participant.as_ref(),
            state.client.as_ref(),
            state.uploaded,
            &notes,
        )?;
        if !(self.save)(&saved) {
            return Err(StoreError::NotSaved);
        }
        state.notes = notes;
        state.saved = saved;
        Ok(())
    }

    /// The public key of the MLS signature key of the client, if there is one
    pub fn signature_key(&self) -> Option<Vec<u8>> {
        let state = self.state.lock().unwrap();
        state
            .client
            .as_ref()
            .map(|client| client.signer().public().to_vec())
    }

    /// The public key of the Participant Key, as a DER encoded
    /// SubjectPublicKeyInfo (RCC.16 section 4.1)
    pub fn participant_public_key(&self) -> Result<Vec<u8>, StoreError> {
        let mut state = self.state.lock().unwrap();
        self.participant(&mut state).map(ParticipantKey::public_key)
    }

    /// The ParticipantInformation, DER encoded, the Client Certificate of
    /// `client` is to carry (RCC.16 Annex A.3.8.9)
    pub fn participant_information(
        &self,
        client: &ClientIdentity,
        now: SystemTime,
    ) -> Result<Vec<u8>, StoreError> {
        let mut state = self.state.lock().unwrap();
        self.participant(&mut state)?
            .participant_information(client, now)
            .map_err(|_| StoreError::Participant)
    }

    /// The credential of the client, if there is one
    pub fn credential(&self) -> Option<Credential> {
        let state = self.state.lock().unwrap();
        state
            .client
            .as_ref()
            .map(|client| client.credential().clone())
    }

    /// Calls `f` with the client, the state it leaves kept before its result
    /// is given out
    pub fn with_client<R, F>(&self, f: F) -> Result<R, StoreError>
    where
        F: FnOnce(&MlsClient) -> mls::Result<R>,
    {
        let mut state = self.state.lock().unwrap();
        let result = f(state.client.as_ref().ok_or(StoreError::NoClient)?);
        self.save(&mut state)?;
        result.map_err(StoreError::Mls)
    }

    /// Calls `f` with the client to create or join a group, which is kept for
    /// with_conversation(); its group ID is given out with what `f` gives
    pub fn add_conversation<R, F>(&self, f: F) -> Result<(Vec<u8>, R), StoreError>
    where
        F: FnOnce(&MlsClient) -> mls::Result<(MlsConversation, R)>,
    {
        let mut state = self.state.lock().unwrap();
        let result = f(state.client.as_ref().ok_or(StoreError::NoClient)?);
        // the handle kept, as it holds what only lives in memory
        let result = result.map(|(conversation, value)| {
            let group_id = conversation.group_id().to_vec();
            state.conversations.insert(group_id.clone(), conversation);
            (group_id, value)
        });
        self.save(&mut state)?;
        result.map_err(StoreError::Mls)
    }

    /// Calls `f` with the group `group_id` and the client, the state it leaves
    /// kept before its result is given out
    pub fn with_conversation<R, F>(&self, group_id: &[u8], f: F) -> Result<R, StoreError>
    where
        F: FnOnce(&mut MlsConversation, &MlsClient) -> mls::Result<R>,
    {
        let mut state = self.state.lock().unwrap();
        let State {
            client,
            conversations,
            ..
        } = &mut *state;
        let client = client.as_ref().ok_or(StoreError::NoClient)?;

        if !conversations.contains_key(group_id) {
            let conversation = client
                .load_conversation(group_id)
                .map_err(StoreError::Mls)?;
            conversations.insert(group_id.to_vec(), conversation);
        }
        let conversation = conversations.get_mut(group_id).unwrap();

        let result = f(conversation, client);
        self.save(&mut state)?;
        result.map_err(StoreError::Mls)
    }

    /// Calls `f` with the group `group_id` and the client, as
    /// with_conversation() does, and keeps along with the state it leaves
    /// the notes `notes` makes of its result, if any: both are kept, or
    /// neither
    pub fn with_conversation_and_notes<R, F, N>(
        &self,
        group_id: &[u8],
        f: F,
        notes: N,
    ) -> Result<R, StoreError>
    where
        F: FnOnce(&mut MlsConversation, &MlsClient) -> mls::Result<R>,
        N: FnOnce(&R) -> Option<Vec<u8>>,
    {
        let mut state = self.state.lock().unwrap();
        let State {
            client,
            conversations,
            ..
        } = &mut *state;
        let client = client.as_ref().ok_or(StoreError::NoClient)?;

        if !conversations.contains_key(group_id) {
            let conversation = client
                .load_conversation(group_id)
                .map_err(StoreError::Mls)?;
            conversations.insert(group_id.to_vec(), conversation);
        }
        let conversation = conversations.get_mut(group_id).unwrap();

        let result = f(conversation, client);
        match result.as_ref().ok().and_then(notes) {
            Some(notes) => {
                let before = std::mem::replace(&mut state.notes, notes);
                if let Err(e) = self.save(&mut state) {
                    state.notes = before;
                    return Err(e);
                }
            }
            None => self.save(&mut state)?,
        }
        result.map_err(StoreError::Mls)
    }

    /// What `f` reads of the group `group_id`, given the client, which it
    /// does not change, so that nothing is saved
    pub fn peek_conversation<R, F>(&self, group_id: &[u8], f: F) -> Result<R, StoreError>
    where
        F: FnOnce(&MlsConversation, &MlsClient) -> R,
    {
        let mut state = self.state.lock().unwrap();
        let State {
            client,
            conversations,
            ..
        } = &mut *state;
        let client = client.as_ref().ok_or(StoreError::NoClient)?;

        if !conversations.contains_key(group_id) {
            let conversation = client
                .load_conversation(group_id)
                .map_err(StoreError::Mls)?;
            conversations.insert(group_id.to_vec(), conversation);
        }
        Ok(f(conversations.get(group_id).unwrap(), client))
    }

    /// Whether the group `group_id` is kept, as with_conversation() would
    /// find it; nothing is changed or saved
    pub fn has_conversation(&self, group_id: &[u8]) -> bool {
        let state = self.state.lock().unwrap();
        state.conversations.contains_key(group_id)
            || state
                .client
                .as_ref()
                .is_some_and(|client| client.load_conversation(group_id).is_ok())
    }

    /// Deletes the group `group_id` and its secrets
    pub fn delete_conversation(&self, group_id: &[u8]) -> Result<(), StoreError> {
        let mut state = self.state.lock().unwrap();
        let State {
            client,
            conversations,
            ..
        } = &mut *state;
        let client = client.as_ref().ok_or(StoreError::NoClient)?;

        let conversation = match conversations.remove(group_id) {
            Some(conversation) => conversation,
            None => client
                .load_conversation(group_id)
                .map_err(StoreError::Mls)?,
        };
        let result = conversation.delete(client);
        self.save(&mut state)?;
        result.map_err(StoreError::Mls)
    }

    /// The Participant Key, made and kept if there is none yet
    fn participant<'a>(&self, state: &'a mut State) -> Result<&'a ParticipantKey, StoreError> {
        if state.participant.is_none() {
            let participant = ParticipantKey::generate();
            let saved = pack(
                Some(&participant),
                state.client.as_ref(),
                state.uploaded,
                &state.notes,
            )?;
            if !(self.save)(&saved) {
                return Err(StoreError::NotSaved);
            }
            state.participant = Some(participant);
            state.saved = saved;
        }
        Ok(state.participant.as_ref().unwrap())
    }

    /// Has the app keep the state of the client, or else undoes it to the
    /// one last kept
    fn save(&self, state: &mut State) -> Result<(), StoreError> {
        let client = match &state.client {
            Some(client) => client,
            None => return Err(StoreError::NoClient),
        };

        if let Ok(saved) = pack(
            state.participant.as_ref(),
            Some(client),
            state.uploaded,
            &state.notes,
        ) {
            if (self.save)(&saved) {
                state.saved = saved;
                return Ok(());
            }
        }

        // the groups as loaded hold the state undone
        state.conversations.clear();
        let (client, uploaded) = self
            .unpack(&state.saved)
            .map(|(_, client, uploaded, _)| (client, uploaded))
            .unwrap_or_default();
        state.client = client;
        state.uploaded = uploaded;
        Err(StoreError::NotSaved)
    }

    /// The Participant Key, the client, whether its KeyPackages were
    /// uploaded, and the notes of the device, of a state kept
    fn unpack(&self, saved: &[u8]) -> Result<Unpacked, StoreError> {
        let bad_format = StoreError::Mls(ErrorKind::BadFormat);
        let (with_notes, rest) = match saved.strip_prefix(STATE_MAGIC) {
            Some(rest) => (true, rest),
            None => (
                false,
                saved
                    .strip_prefix(STATE_MAGIC_WITHOUT_NOTES)
                    .ok_or(bad_format)?,
            ),
        };
        let (participant, uploaded, rest) = rest
            .split_first()
            .and_then(|(length, rest)| {
                (rest.len() > *length as usize).then(|| rest.split_at(*length as usize))
            })
            .and_then(|(participant, rest)| {
                let (uploaded, rest) = rest.split_first()?;
                Some((participant, *uploaded, rest))
            })
            .filter(|(_, uploaded, _)| *uploaded <= 1)
            .ok_or(bad_format)?;
        let (notes, client) = match with_notes {
            true => {
                let (length, rest) = rest.split_first_chunk::<4>().ok_or(bad_format)?;
                let length = u32::from_be_bytes(*length) as usize;
                (rest.len() >= length)
                    .then(|| rest.split_at(length))
                    .ok_or(bad_format)?
            }
            false => (&[][..], rest),
        };

        let participant = match participant {
            [] => None,
            key => Some(ParticipantKey::from_bytes(key).map_err(|_| bad_format)?),
        };
        let client = match client {
            [] => None,
            snapshot => Some(
                self.timed(
                    MlsClient::restore(snapshot, self.config, self.shared_validator())
                        .map_err(StoreError::Mls)?,
                ),
            ),
        };
        Ok((participant, client, uploaded == 1, notes.to_vec()))
    }

    fn shared_validator(&self) -> Box<dyn CredentialValidator> {
        Box::new(SharedValidator(Arc::clone(&self.validator)))
    }
}

/// What a state kept holds: the Participant Key, the client, whether its
/// KeyPackages were uploaded, and the notes of the device
type Unpacked = (Option<ParticipantKey>, Option<MlsClient>, bool, Vec<u8>);

/// The state to keep: the Participant Key, its length first, whether the
/// KeyPackages of the client were uploaded, the notes of the device, their
/// length first on four bytes, then the client
fn pack(
    participant: Option<&ParticipantKey>,
    client: Option<&MlsClient>,
    uploaded: bool,
    notes: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let participant = participant
        .map(ParticipantKey::to_bytes)
        .unwrap_or_default();
    let notes_length = u32::try_from(notes.len()).map_err(|_| StoreError::NotSaved)?;
    let mut saved = STATE_MAGIC.to_vec();
    saved.push(participant.len() as u8);
    saved.extend_from_slice(&participant);
    saved.push(u8::from(uploaded && client.is_some()));
    saved.extend_from_slice(&notes_length.to_be_bytes());
    saved.extend_from_slice(notes);
    if let Some(client) = client {
        saved.extend_from_slice(&client.snapshot().map_err(StoreError::Mls)?);
    }
    Ok(saved)
}

/// The validator of the store, for each client it makes or restores
struct SharedValidator(Arc<dyn CredentialValidator>);

impl CredentialValidator for SharedValidator {
    fn validate(&self, credential: &Credential, signature_key: &[u8]) -> bool {
        self.0.validate(credential, signature_key)
    }

    fn validate_addition(&self, credential: &Credential, signature_key: &[u8]) -> bool {
        self.0.validate_addition(credential, signature_key)
    }

    fn validate_replacement(
        &self,
        old: &Credential,
        new: &Credential,
        signature_key: &[u8],
    ) -> bool {
        self.0.validate_replacement(old, new, signature_key)
    }
}
