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
//! client, and the groups it takes part in, kept by the app
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
    self, Credential, CredentialValidator, ErrorKind, MlsClient, MlsConfig, MlsConversation,
};

/// Starts the state kept: the Participant Key, then the client
const STATE_MAGIC: &[u8] = b"RCS-E2EE1";

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
}

struct State {
    /// The Participant Key, made the first time it is asked for
    participant: Option<ParticipantKey>,
    client: Option<MlsClient>,
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
                saved: Vec::new(),
                conversations: HashMap::new(),
            }),
        }
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
        let saved = pack(state.participant.as_ref(), Some(&client))?;
        if !(self.save)(&saved) {
            return Err(StoreError::NotSaved);
        }

        state.client = Some(client);
        state.saved = saved;
        state.conversations.clear();
        Ok(())
    }

    /// Takes on the Participant Key and the client in `saved`, a state the app
    /// kept
    pub fn restore(&self, saved: &[u8]) -> Result<(), StoreError> {
        let (participant, client) = self.unpack(saved)?;

        let mut state = self.state.lock().unwrap();
        state.participant = participant;
        state.client = client;
        state.saved = saved.to_vec();
        state.conversations.clear();
        Ok(())
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
            let saved = pack(Some(&participant), state.client.as_ref())?;
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

        if let Ok(saved) = pack(state.participant.as_ref(), Some(client)) {
            if (self.save)(&saved) {
                state.saved = saved;
                return Ok(());
            }
        }

        // the groups as loaded hold the state undone
        state.conversations.clear();
        state.client = self
            .unpack(&state.saved)
            .ok()
            .and_then(|(_, client)| client);
        Err(StoreError::NotSaved)
    }

    /// The Participant Key and the client of a state kept
    fn unpack(
        &self,
        saved: &[u8],
    ) -> Result<(Option<ParticipantKey>, Option<MlsClient>), StoreError> {
        let bad_format = StoreError::Mls(ErrorKind::BadFormat);
        let (participant, client) = saved
            .strip_prefix(STATE_MAGIC)
            .and_then(|rest| rest.split_first())
            .and_then(|(length, rest)| {
                (rest.len() >= *length as usize).then(|| rest.split_at(*length as usize))
            })
            .ok_or(bad_format)?;

        let participant = match participant {
            [] => None,
            key => Some(ParticipantKey::from_bytes(key).map_err(|_| bad_format)?),
        };
        let client = match client {
            [] => None,
            snapshot => Some(
                MlsClient::restore(snapshot, self.config, self.shared_validator())
                    .map_err(StoreError::Mls)?,
            ),
        };
        Ok((participant, client))
    }

    fn shared_validator(&self) -> Box<dyn CredentialValidator> {
        Box::new(SharedValidator(Arc::clone(&self.validator)))
    }
}

/// The state to keep: the Participant Key, its length first, then the client
fn pack(
    participant: Option<&ParticipantKey>,
    client: Option<&MlsClient>,
) -> Result<Vec<u8>, StoreError> {
    let participant = participant
        .map(ParticipantKey::to_bytes)
        .unwrap_or_default();
    let mut saved = STATE_MAGIC.to_vec();
    saved.push(participant.len() as u8);
    saved.extend_from_slice(&participant);
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
