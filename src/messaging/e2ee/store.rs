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

//! The MLS state of the device: one MLS client, and the groups it takes part
//! in, kept by the app
//!
//! The state holds the private keys of the device and the secrets of every
//! group. A change to it has to be kept before anything it produced is sent:
//! sending again from an older state reuses message keys (see
//! `MlsClient::snapshot()`). Every call made through the store is followed by
//! the app keeping the state; one it cannot keep is undone, and what the call
//! produced is not given out.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rust_rcs_core::mls::{
    self, Credential, CredentialValidator, ErrorKind, MlsClient, MlsConfig, MlsConversation,
};

/// Keeps the state given, encrypted, in place of the one kept before; false if
/// it could not. Called with the store locked, it must not call into it.
pub type SaveState = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// There is no MLS client yet
    NoClient,
    /// What MLS made of the call
    Mls(ErrorKind),
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
        let saved = client.snapshot().map_err(StoreError::Mls)?;
        if !(self.save)(&saved) {
            return Err(StoreError::NotSaved);
        }

        state.client = Some(client);
        state.saved = saved;
        state.conversations.clear();
        Ok(())
    }

    /// Takes on the client in `saved`, a state the app kept
    pub fn restore(&self, saved: &[u8]) -> Result<(), StoreError> {
        let client = MlsClient::restore(saved, self.config, self.shared_validator())
            .map_err(StoreError::Mls)?;

        let mut state = self.state.lock().unwrap();
        state.client = Some(client);
        state.saved = saved.to_vec();
        state.conversations.clear();
        Ok(())
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

    /// Has the app keep the state of the client, or else undoes it to the
    /// one last kept
    fn save(&self, state: &mut State) -> Result<(), StoreError> {
        let client = match &state.client {
            Some(client) => client,
            None => return Err(StoreError::NoClient),
        };

        let snapshot = client.snapshot().map_err(StoreError::Mls);
        if let Ok(snapshot) = &snapshot {
            if (self.save)(snapshot) {
                state.saved = snapshot.clone();
                return Ok(());
            }
        }

        // the groups as loaded hold the state undone
        state.conversations.clear();
        state.client = MlsClient::restore(&state.saved, self.config, self.shared_validator()).ok();
        Err(StoreError::NotSaved)
    }

    fn shared_validator(&self) -> Box<dyn CredentialValidator> {
        Box::new(SharedValidator(Arc::clone(&self.validator)))
    }
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
