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

//! End-to-end encryption of the group chats this client takes part in, when
//! it has it (RCC.16 sections 8.1, 9.1.1)

use futures::future::BoxFuture;
use rust_rcs_core::cpim::CPIMInfo;

/// Content-Type of what the Conversation Focus sends of the MLS group of a
/// conversation (RCC.16 section 7.9)
pub const CONTENT_TYPE_MLS_RCS_SERVER: &[u8] = b"message/mls-rcs-server";

/// Content-Type of an encrypted message (RCC.16 section 7.5.6)
pub const CONTENT_TYPE_MLS: &[u8] = b"message/mls";

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

    /// Joins the MLS group of the group chat `conversation_id` an invitation
    /// carries, as the `message/mls-rcs-server` `server_message` with the
    /// Welcome of the Conversation Focus (RCC.16 sections 6.2.6, 7.9.3, 8.1);
    /// false if it cannot be
    fn join(&self, conversation_id: &str, server_message: &[u8]) -> bool;

    /// Takes what the Conversation Focus of the group `conversation_id` sent
    /// of its MLS group, as a `message/mls-rcs-server`: its acceptance of a
    /// Commit of this client, and the Commits and Proposals of others
    /// (sections 6.2.4, 7.9)
    fn on_server_message(&self, conversation_id: &str, body: &[u8]);

    /// Takes the `message/imdn+xml` `imdn` received in the group chat
    /// `conversation_id`: true if it is the Conversation Focus refusing a
    /// control message of this client, which is not for the app (RCC.16
    /// sections 6.2.5, 7.7.2.1)
    fn on_imdn(&self, conversation_id: &str, imdn: &[u8]) -> bool;

    /// Lets go of the MLS group `conversation_id`, as its chat did not start
    /// or its invitation was not accepted
    fn abandon(&self, conversation_id: &str);

    /// Whether the group chat `conversation_id` is encrypted, its MLS group
    /// kept
    fn encrypts(&self, conversation_id: &str) -> bool;

    /// The CPIM message `cpim` encrypted in the group chat `conversation_id`,
    /// as the CPIM message carrying it as `message/mls` (RCC.16 sections 7.5,
    /// 9.1.1), once a Commit of this client the Conversation Focus is yet to
    /// accept is; None if it cannot be
    fn encrypt(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// The CPIM message the `message/mls` `mls_message` of the group chat
    /// `conversation_id` carried, delivered in the CPIM message `cpim_info`
    /// tells of; its From the MLS identity of the sender if that is another
    /// (RCC.16 sections 7.5.3.1, 9.1.1); None if it cannot be decrypted
    fn decrypt(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        mls_message: &[u8],
    ) -> Option<Vec<u8>>;
}
