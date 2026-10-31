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

use std::sync::Arc;

use futures::future::BoxFuture;
use rust_rcs_core::cpim::CPIMInfo;
use rust_rcs_core::sip::SipMessage;

/// Content-Type of what the Conversation Focus sends of the MLS group of a
/// conversation (RCC.16 section 7.9)
pub const CONTENT_TYPE_MLS_RCS_SERVER: &[u8] = b"message/mls-rcs-server";

/// Content-Type of an encrypted message (RCC.16 section 7.5.6)
pub const CONTENT_TYPE_MLS: &[u8] = b"message/mls";

/// Content-Type of the EpochIdentifier an MLS-Enhanced-Group-Info-Pull
/// request carries (RCC.16 section 7.10.2)
pub const CONTENT_TYPE_MLS_RCS: &[u8] = b"message/mls-rcs";

/// The Info-Packages of the INFO requests asking the Conversation Focus for
/// the GroupInfo of the MLS group of a conversation (RCC.16 sections 6.3.1,
/// 6.3.2)
pub const INFO_PACKAGE_GROUP_INFO_PULL: &[u8] = b"MLS-Group-Info-Pull";
pub const INFO_PACKAGE_ENHANCED_GROUP_INFO_PULL: &[u8] = b"MLS-Enhanced-Group-Info-Pull";

/// What became of a message to encrypt
#[derive(Debug, PartialEq)]
pub enum Sealed {
    /// The CPIM message carrying it as `message/mls`
    Encrypted(Vec<u8>),
    /// To send as it is, the group chat no longer encrypted (RCC.16 section
    /// 11.2)
    Unencrypted,
    /// Not to send
    Failed,
}

/// What the signature of a notification received in an encrypted group chat
/// tells (RCC.16 section 7.6.2)
#[derive(Debug, PartialEq)]
pub enum Verified {
    /// Signed by the participant it is from, or a negative delivery, which
    /// may come unsigned, as any may once the group chat is unencrypted
    Signed,
    /// Not signed, as a client not encrypting sends it, the group chat then
    /// to move to unencrypted (section 11.2)
    Unsigned,
    /// Signed otherwise, or badly: not for the app
    Forged,
}

/// What an IMDN received in an encrypted group chat tells the encryption
#[derive(Debug, PartialEq)]
pub enum ImdnTold {
    /// Nothing
    Nothing,
    /// The Conversation Focus refusing a control message of this client,
    /// which is not for the app (RCC.16 section 6.2.5)
    Refusal,
    /// A recipient cannot decrypt, the group chat then to move to unencrypted
    /// (sections 6.2.5, 11.2)
    EncryptionNotAvailable,
}

/// What a message of the Conversation Focus brought
#[derive(Debug, Default, PartialEq)]
pub struct Taken {
    /// Proposals, as the leaves commit_leaves() commits (RCC.16 section 9.4)
    pub proposals: bool,
    /// The end of encryption: the group chat is unencrypted from now on
    /// (section 11.2)
    pub encryption_ended: bool,
    /// The group chat moved back to encrypted (section 11.1.2)
    pub encryption_resumed: bool,
}

/// How a group chat is moved back to encrypted (RCC.16 section 11.1)
#[derive(Debug, PartialEq)]
pub enum Upgrade {
    /// With the CPIM message carrying a Commit to send to the Conversation
    /// Focus in the session (section 11.1.2)
    InSession(Vec<u8>),
    /// With the CPIM message carrying an Era of its MLS group for the INVITE
    /// restarting the group to carry, once its session ended (sections
    /// 8.3.1, 8.1)
    Restart(Vec<u8>),
}

/// Why a group chat moves to unencrypted (RCC.16 sections 7.11.2.2, 11.2)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EndReason {
    /// The Conversation Focus told that a recipient cannot decrypt
    ServerFailureEncryptionNotAvailable,
    /// A participant sent a message or a notification unencrypted
    ClientFailureEncryptionNotAvailable,
}

/// Sends the Conversation Focus of a session an INFO request of the
/// Info-Package it is given, carrying the body given if any, giving the status
/// code and body of its final response, or None if none came (RCC.16 sections
/// 6.3.1, 6.3.2)
pub type GroupInfoPull = Arc<
    dyn Fn(&'static [u8], Option<Vec<u8>>) -> BoxFuture<'static, Option<(u16, Vec<u8>)>>
        + Send
        + Sync,
>;

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

    /// The CPIM message carrying a `message/mls-rcs-client` that the BYE of
    /// the user leaving the group chat `conversation_id` for good is to
    /// carry, `from` and `to` that of the CPIM message: the self_remove
    /// Proposal of this client (RCC.16 sections 7.9.4, 9.4), once a Commit of
    /// this client the Conversation Focus is yet to accept is; None if it
    /// cannot be made. The MLS group is kept until abandoned once the Focus
    /// agrees to the leave.
    fn prepare_leave(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// The CPIM message carrying a `message/mls-rcs-client` with a Commit of
    /// the leaves of other members of the group chat `conversation_id`, whose
    /// self_remove Proposals the Conversation Focus forwarded, removing the
    /// other Clients of their Participants too, to send to the Focus in the
    /// session, `from` and `to` that of the CPIM message (RCC.16 sections
    /// 9.4, 9.5.1), once a Commit of this client the Focus is yet to accept
    /// is; None if there are none to commit
    fn commit_leaves(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// The CPIM message carrying a `message/mls-rcs-client` with a Commit
    /// removing with server_remove Proposals the Clients of `participant`,
    /// whom the Messaging Server removed from the group chat
    /// `conversation_id`, to send to the Conversation Focus in the session,
    /// `from` and `to` that of the CPIM message (RCC.16 sections 9.5.1, 9.6),
    /// once a Commit of this client the Focus is yet to accept is; None if
    /// none is left to remove, as when the Commit of another member removed
    /// them first
    fn remove_for_server(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Lets go of the Commit or the leave of this client in the group chat
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
    /// (sections 6.2.4, 7.9), telling what they brought
    fn on_server_message(&self, conversation_id: &str, body: &[u8]) -> Taken;

    /// Takes the `message/imdn+xml` `imdn` received in the group chat
    /// `conversation_id`, telling what it is to the encryption (RCC.16
    /// sections 6.2.5, 7.7.2.1)
    fn on_imdn(&self, conversation_id: &str, imdn: &[u8]) -> ImdnTold;

    /// The CPIM message carrying a `message/mls-rcs-client` with a Commit
    /// moving the group chat `conversation_id` to unencrypted for `reason`,
    /// by adding the end_mls extension to its MLS group, to send to the
    /// Conversation Focus in the session, `from` and `to` that of the CPIM
    /// message (RCC.16 sections 7.11.2.2, 9.5.1, 11.2), once a Commit of this
    /// client the Focus is yet to accept is; None if it is unencrypted
    /// already, or cannot be
    fn end_encryption(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        reason: EndReason,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Whether this client is to update keys in the group chat
    /// `conversation_id`: its own, by the days passed and the messages sent
    /// since it last did (RCC.16 section 9.5.2), or those of other members,
    /// whose certificate expired or who did not update theirs in over 30
    /// days, with a KeyPackage Update (section 9.5.4)
    fn key_update_due(&self, conversation_id: &str) -> bool;

    /// The CPIM message carrying a `message/mls-rcs-client` with a Commit
    /// updating keys in the group chat `conversation_id` as key_update_due()
    /// tells, to send to the Conversation Focus in the session, `from` and
    /// `to` that of the CPIM message (RCC.16 sections 9.5.1, 9.5.2, 9.5.4),
    /// once a Commit of this client the Focus is yet to accept is; None if
    /// no key update is due then, or it cannot be made
    ///
    /// A KeyPackage Update updates the keys of this client as well. One that
    /// cannot be made, as no KeyPackages can be had of another member, moves
    /// the group chat to unencrypted instead (section 11.2).
    fn update_keys(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Lets go of the MLS group `conversation_id`, as its chat did not start,
    /// its invitation was not accepted, or the user left it
    fn abandon(&self, conversation_id: &str);

    /// Whether the MLS group `conversation_id` fell out of step with that of
    /// its Conversation Focus and is to be self-healed, as when a message could
    /// not be decrypted (RCC.16 section 10.1); false while it is being
    fn needs_healing(&self, conversation_id: &str) -> bool;

    /// Self-heals the MLS group `conversation_id`, if it is to be and is not
    /// being already, asking the Conversation Focus with `pull` for what it
    /// missed or for its GroupInfo (RCC.16 sections 6.3, 10.1): the CPIM
    /// message carrying a `message/mls-rcs-client` with the External Commit
    /// rejoining the group, if it comes to that, to send to the Focus in the
    /// session, `from` and `to` that of the CPIM message. Messages to send in
    /// the group wait for it to end.
    fn heal(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        pull: GroupInfoPull,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Whether the MLS group `conversation_id` is to be made anew in its next
    /// Era, as self-healing it failed, or to move to an Unencrypted Singleton
    /// Era (RCC.16 sections 8.3, 10.1, 11.2.1)
    fn new_era_due(&self, conversation_id: &str) -> bool;

    /// Makes the next Era of the MLS group `conversation_id`, if one is due,
    /// after that of the GroupInfo asked of the Conversation Focus with
    /// `pull`, with the Clients of its Participants, or else an Unencrypted
    /// Singleton Era (RCC.16 sections 8.3.1, 10.1, 11.2.1): the CPIM message
    /// carrying a `message/mls-rcs-client` with its Commit, for the INVITE
    /// restarting the group to carry, `from` and `to` that of the CPIM
    /// message. The Commit is applied once the Focus accepts it, and is to be
    /// discarded if the group does not start otherwise than by the Focus
    /// refusing it, which era_refused() is for.
    fn prepare_next_era(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        pull: GroupInfoPull,
    ) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Takes note of the Conversation Focus refusing with `status_code` the
    /// INVITE restarting the group `conversation_id` in the Era
    /// prepare_next_era() made, whose Commit is discarded, another Era then
    /// due (RCC.16 sections 8.3.1, 10.1, 11.2.1)
    fn era_refused(&self, conversation_id: &str, status_code: u16);

    /// Whether the group `conversation_id`, moved to unencrypted, is to be
    /// moved back to encrypted with upgrade() (RCC.16 sections 11.1, 11.2)
    fn upgrade_due(&self, conversation_id: &str) -> bool;

    /// Takes note of the membership of the group `conversation_id`
    /// changing, after which it may be moved back to encrypted sooner
    /// (RCC.16 sections 11.1.1, 11.2)
    fn membership_changed(&self, conversation_id: &str);

    /// Moves the group `conversation_id` back to encrypted, if that is due,
    /// `participants` the URIs of those taking part in it as its Conversation
    /// Focus tells them (RCC.16 section 11.1): the CPIM message carrying a
    /// `message/mls-rcs-client`, `from` and `to` that of the CPIM message,
    /// with the Commit resurrecting its MLS group (section 11.1.2), or with
    /// an Era of its own if the Focus has no MLS group for it (sections
    /// 8.3.1, 10.1). The Commit is applied once the Focus accepts it, and
    /// that of an Era discarded if the group does not start otherwise than
    /// by the Focus refusing it, which era_refused() is for.
    fn upgrade(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Upgrade>>;

    /// Whether the group chat `conversation_id` is encrypted, its MLS group
    /// kept
    fn encrypts(&self, conversation_id: &str) -> bool;

    /// Whether the group chat `conversation_id` was moved to unencrypted, its
    /// MLS group kept all the same (RCC.16 section 11.2): messages are sent
    /// as they are then, and notifications unsigned
    fn encryption_ended(&self, conversation_id: &str) -> bool;

    /// The CPIM message `cpim` encrypted in the group chat `conversation_id`,
    /// as the CPIM message carrying it as `message/mls` (RCC.16 sections 7.5,
    /// 9.1.1), once a Commit of this client the Conversation Focus is yet to
    /// accept is, or to send as it is once the group chat is unencrypted
    /// (section 11.2)
    fn encrypt(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Sealed>;

    /// The CPIM message `cpim` carrying a notification of the group chat
    /// `conversation_id`, signed over what it tells of (RCC.16 sections
    /// 7.6.1, 9.1.3, 9.1.4), once a Commit of this client the Conversation
    /// Focus is yet to accept is; None if it cannot be
    fn sign(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>>;

    /// Whether the `message/imdn+xml` `imdn` received in the group chat
    /// `conversation_id`, delivered in the CPIM message `cpim_info` tells of,
    /// is signed over what it tells of by the participant it is from, or is a
    /// negative delivery, which may come unsigned (RCC.16 sections 7.6.2,
    /// 7.7), as any may once the group chat is unencrypted (section 11.2)
    fn verify(&self, conversation_id: &str, cpim_info: &CPIMInfo, imdn: &[u8]) -> Verified;

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
