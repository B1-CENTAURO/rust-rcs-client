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

//! End-to-end encryption of the group chats this client creates, when it has
//! it (RCC.16 section 8.1)

use futures::future::BoxFuture;

/// Content-Type of what the Conversation Focus sends of the MLS group of a
/// conversation (RCC.16 section 7.9)
pub const CONTENT_TYPE_MLS_RCS_SERVER: &[u8] = b"message/mls-rcs-server";

pub trait GroupEncryption: Send + Sync {
    /// The CPIM message carrying a `message/mls-rcs-client` that a new group
    /// chat with `participants` is to be invited with to be encrypted, its
    /// MLS group made under its Conversation-ID `conversation_id`, `from` and
    /// `to` that of the CPIM message (RCC.16 sections 7.9.2, 8.1); None if it
    /// is not to be, as when one of the participants cannot encrypt
    fn prepare(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Takes what the Conversation Focus of the group `conversation_id` sent
    /// of its MLS group, as a `message/mls-rcs-server` (section 7.9)
    fn on_server_message(&self, conversation_id: &str, body: &[u8]);

    /// Lets go of the MLS group `conversation_id`, as its chat did not start
    fn abandon(&self, conversation_id: &str);
}
