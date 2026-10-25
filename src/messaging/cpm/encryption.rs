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
use rust_rcs_core::sip::SipMessage;

/// Content-Type of what the Conversation Focus sends of the MLS group of a
/// conversation (RCC.16 section 7.9)
pub const CONTENT_TYPE_MLS_RCS_SERVER: &[u8] = b"message/mls-rcs-server";

/// Content-Type of an encrypted message (RCC.16 section 7.5.6)
pub const CONTENT_TYPE_MLS: &[u8] = b"message/mls";

/// Text of the Warning by which a server tells that no Negative-Delivery
/// IMDN follows its error response (RCC.16 section 7.2.6)
const NON_MLS_ERROR: &[u8] = b"451 Non-MLS error";

/// Whether the response `response` tells, with a Warning of warn-code 399,
/// that no Negative-Delivery IMDN with an MLS failure reason follows it
/// (RCC.16 section 7.2.6)
pub fn says_no_refusal_follows(response: &SipMessage) -> bool {
    response.headers().is_some_and(|headers| {
        headers
            .iter()
            .filter(|header| header.get_name().eq_ignore_ascii_case(b"Warning"))
            .any(|header| warns_of_non_mls_error(header.get_value()))
    })
}

/// Whether the Warning header value `value`, of comma separated warn-code SP
/// warn-agent SP warn-text (RFC 3261 section 20.43), has the Non-MLS one
fn warns_of_non_mls_error(value: &[u8]) -> bool {
    let mut rest = value;
    loop {
        let Some(start) = rest
            .iter()
            .position(|b| !b.is_ascii_whitespace() && *b != b',')
        else {
            return false;
        };
        rest = &rest[start..];
        let code = rest.split(|b| *b == b' ').next().unwrap_or_default();
        let Some(open) = rest.iter().position(|b| *b == b'"') else {
            return false;
        };

        // the quoted text, up to its closing quote
        let mut text = Vec::new();
        let mut i = open + 1;
        while i < rest.len() && rest[i] != b'"' {
            if rest[i] == b'\\' && i + 1 < rest.len() {
                i += 1;
            }
            text.push(rest[i]);
            i += 1;
        }
        if i == rest.len() {
            return false;
        }
        if code == b"399" && text.eq_ignore_ascii_case(NON_MLS_ERROR) {
            return true;
        }
        rest = &rest[rest.len().min(i + 1)..];
    }
}

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

    /// The CPIM message carrying a `message/mls-rcs-client` that a REFER
    /// adding `participants` to the group chat `conversation_id` is to carry,
    /// `from` and `to` that of the CPIM message (RCC.16 sections 7.9.2, 9.2),
    /// once a Commit of this client the Conversation Focus is yet to accept
    /// is; None if they are not to be added, as when one of them cannot
    /// encrypt
    fn prepare_add(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// The CPIM message carrying a `message/mls-rcs-client` that a REFER
    /// removing `participant` from the group chat `conversation_id` is to
    /// carry, `from` and `to` that of the CPIM message (RCC.16 sections
    /// 7.9.2, 9.3), once a Commit of this client the Conversation Focus is
    /// yet to accept is; None if it is not to be removed, as when none of its
    /// Clients is a member
    fn prepare_remove(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Lets go of the Commit of this client in the group chat
    /// `conversation_id`, as the Conversation Focus answered the request
    /// carrying it with an error, a refusal of it to follow if
    /// `refusal_follows` (RCC.16 sections 6.2.5, 7.2.6)
    fn discard(&self, conversation_id: &str, refusal_follows: bool);

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

    /// The CPIM message `cpim` carrying a notification of the group chat
    /// `conversation_id`, signed over what it tells of (RCC.16 sections
    /// 7.6.1, 9.1.3, 9.1.4), once a Commit of this client the Conversation
    /// Focus is yet to accept is; None if it cannot be
    fn sign(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Whether the `message/imdn+xml` `imdn` received in the group chat
    /// `conversation_id`, delivered in the CPIM message `cpim_info` tells of,
    /// is for the app: signed over what it tells of by the participant it is
    /// from, or a negative delivery, which may come unsigned (RCC.16 sections
    /// 7.6.2, 7.7)
    fn verify(&self, conversation_id: &str, cpim_info: &CPIMInfo, imdn: &[u8]) -> bool;

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

#[cfg(test)]
mod tests {
    use super::warns_of_non_mls_error;

    #[test]
    fn the_non_mls_warning_is_found_among_others() {
        for value in [
            "399 operator.com \"451 Non-MLS error\"",
            "399 operator.com \"451 non-mls ERROR\"",
            "399 google.com \"122 Function not allowed\", 399 operator.com \"451 Non-MLS error\"",
            "  399 operator.com \"451 Non-MLS error\" ,399 google.com \"122, as it is\"",
            "399 operator.com \"451 Non-MLS e\\rror\"",
        ] {
            assert!(warns_of_non_mls_error(value.as_bytes()), "{}", value);
        }

        for value in [
            "",
            "399 operator.com \"122 Function not allowed\"",
            // another warn-code, or the text of another warning
            "301 operator.com \"451 Non-MLS error\"",
            "399 operator.com \"122 Function not allowed, 451 Non-MLS error\"",
            "399 operator.com \"451 Non-MLS error, more\"",
            "399 operator.com 451 Non-MLS error",
            "399 operator.com \"451 Non-MLS error",
        ] {
            assert!(!warns_of_non_mls_error(value.as_bytes()), "{}", value);
        }
    }
}
