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

//! The 1-to-1 chats of the device encrypted end to end (RCC.16 section 8.1.1)
//!
//! Each has an MLS group of its own, its group ID a random GUID (section
//! 6.1.1). It is kept with the MLS state, by the tel URI of the contact, with
//! the MLS-Opaque-Token its Conversation Focus gave, which the requests of
//! the chat carry (section 6.1.3).
//!
//! A contact found not to take an encrypted chat, as it does not advertise
//! E2EE v1 or the Home KDS has no KeyPackages of it, is not asked again for
//! UNENCRYPTED_FOR (section 8.1).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::same_tel_uri;

use super::device::{participant_tel_uri, E2eeDevice};
use super::notes::{put, Reader as NotesReader};
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

/// How long a contact found not to take an encrypted chat is not asked again
pub(super) const UNENCRYPTED_FOR: Duration = Duration::from_secs(60 * 60);

/// An encrypted 1-to-1 chat, as kept in the notes of the device
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Chat {
    /// The tel URI of the contact
    pub(super) contact: String,
    /// The ID of its MLS group
    pub(super) group_id: String,
    /// The MLS-Opaque-Token its Conversation Focus gave, if it did
    pub(super) mls_opaque_token: Option<String>,
}

/// The contacts found not to take an encrypted chat, by tel URI, and when,
/// for as long as the device runs
#[derive(Default)]
pub(super) struct Unencrypted(Mutex<HashMap<String, SystemTime>>);

impl Unencrypted {
    /// Whether `contact` was found not to take an encrypted chat within
    /// UNENCRYPTED_FOR of `now`
    pub(super) fn lately(&self, contact: &str, now: SystemTime) -> bool {
        let mut found = self.0.lock().unwrap();
        found.retain(|_, when| {
            now.duration_since(*when)
                .map_or(true, |since| since < UNENCRYPTED_FOR)
        });
        found.contains_key(contact)
    }

    /// Takes note of `contact` found not to take an encrypted chat at `now`
    pub(super) fn found(&self, contact: &str, now: SystemTime) {
        self.0.lock().unwrap().insert(String::from(contact), now);
    }
}

/// The tel URI of `contact`, a tel URI or a SIP URI of a number
pub(super) fn contact_tel_uri(contact: &str) -> Option<String> {
    participant_tel_uri(std::iter::once(contact), None)
}

impl E2eeDevice {
    /// The ID of the MLS group of the encrypted 1-to-1 chat with `contact`,
    /// and the MLS-Opaque-Token given for it if one was (RCC.16 sections
    /// 6.1.3, 8.1.1); None if none is kept, or if its MLS group no longer is
    pub fn chat_group(&self, contact: &str) -> Option<(String, Option<String>)> {
        let contact = contact_tel_uri(contact)?;
        let chat = self.notes().read(|data| {
            data.chats
                .iter()
                .find(|chat| same_tel_uri(&chat.contact, &contact))
                .cloned()
        })?;
        self.store()
            .has_conversation(chat.group_id.as_bytes())
            .then_some((chat.group_id, chat.mls_opaque_token))
    }

    /// Takes note of the MLS group `group_id` as that of the encrypted 1-to-1
    /// chat with `contact`, in place of any other, its Conversation Focus
    /// having given `mls_opaque_token` if it did; kept with the MLS state
    pub fn keep_chat(
        &self,
        contact: &str,
        group_id: &str,
        mls_opaque_token: Option<&str>,
    ) -> Result<(), StoreError> {
        let Some(contact) = contact_tel_uri(contact) else {
            platform_log(LOG_TAG, "chat with a contact of no number not kept");
            return Ok(());
        };
        let chat = Chat {
            contact,
            group_id: String::from(group_id),
            mls_opaque_token: mls_opaque_token.map(String::from),
        };
        self.notes().change(self.store(), |data| {
            data.chats
                .retain(|kept| !same_tel_uri(&kept.contact, &chat.contact));
            data.chats.push(chat);
        })
    }

    /// Lets go of the 1-to-1 chat whose MLS group is `group_id`, if one's is
    pub(super) fn forget_chat(&self, group_id: &str) {
        let forgotten = self.notes().change(self.store(), |data| {
            data.chats.retain(|chat| chat.group_id != group_id)
        });
        if let Err(e) = forgotten {
            platform_log(LOG_TAG, format!("chat not forgotten: {:?}", e));
        }
    }
}

/// The chats `chats`, as the notes of the device hold them
pub(super) fn encode(chats: &[Chat]) -> Vec<u8> {
    let mut data = Vec::new();
    for chat in chats {
        put(&mut data, chat.contact.as_bytes());
        put(&mut data, chat.group_id.as_bytes());
        match &chat.mls_opaque_token {
            Some(token) => {
                data.push(1);
                put(&mut data, token.as_bytes());
            }
            None => data.push(0),
        }
    }
    data
}

/// The chats `reader` reads, as encode() puts them
pub(super) fn decode(reader: &mut NotesReader) -> Option<Vec<Chat>> {
    let mut chats = Vec::new();
    while !reader.is_empty() {
        let contact = reader.string()?;
        let group_id = reader.string()?;
        let mls_opaque_token = match reader.flag()? {
            true => Some(reader.string()?),
            false => None,
        };
        chats.push(Chat {
            contact,
            group_id,
            mls_opaque_token,
        });
    }
    Some(chats)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{contact_tel_uri, Unencrypted, UNENCRYPTED_FOR};

    #[test]
    fn a_contact_is_known_by_its_tel_uri() {
        assert_eq!(
            contact_tel_uri("tel:+491707654321").as_deref(),
            Some("tel:+491707654321")
        );
        assert_eq!(
            contact_tel_uri("sip:+491707654321@ims.example.com;user=phone").as_deref(),
            Some("tel:+491707654321")
        );
        assert_eq!(contact_tel_uri("sip:bob@example.com"), None);
    }

    #[test]
    fn a_contact_found_not_to_take_an_encrypted_chat_is_not_asked_again_for_a_while() {
        let unencrypted = Unencrypted::default();
        let now = SystemTime::now();
        assert!(!unencrypted.lately("tel:+491707654321", now));
        unencrypted.found("tel:+491707654321", now);
        assert!(unencrypted.lately("tel:+491707654321", now));
        assert!(!unencrypted.lately("tel:+491701111111", now));
        assert!(unencrypted.lately(
            "tel:+491707654321",
            now + UNENCRYPTED_FOR - Duration::from_secs(1)
        ));

        // no longer once that long ago
        assert!(!unencrypted.lately("tel:+491707654321", now + UNENCRYPTED_FOR));
        assert!(!unencrypted.lately("tel:+491707654321", now));
    }
}
