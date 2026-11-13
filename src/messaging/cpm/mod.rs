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

pub mod encryption;
pub mod group_chat;
pub mod imdn;
pub mod session;
pub mod session_invitation;
pub mod sip;
pub mod standalone_messaging;

use std::sync::Arc;

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Local, SecondsFormat};
use rust_rcs_core::{
    cpim::CPIMMessage,
    ffi::log::platform_log,
    internet::{body::message_body::MessageBody, syntax, Body, Header},
    sip::sip_session::SipSession,
};
use uuid::Uuid;

use self::session::CPMSession;

use super::ffi::RecipientType;
use crate::video_chat;

const LOG_TAG: &str = "messaging";

/// The CPIM headers the client reads, through CPIMMessage::get_info()
const UNDERSTOOD_CPIM_HEADERS: [&[u8]; 6] = [
    b"From",
    b"To",
    b"DateTime",
    b"<urn:ietf:params:imdn>.Message-ID",
    b"<urn:ietf:params:imdn>.Disposition-Notification",
    b"<http://www.openmobilealliance.org/cpm/>.Payload-Type",
];

/// Whether the client understands all that `message` requires with Require
/// headers (RFC 3862 section 3.5), as it must to take the message
pub fn understands_cpim_requirements(message: &CPIMMessage) -> bool {
    let unmet = message.get_unmet_requirements(&UNDERSTOOD_CPIM_HEADERS);
    for name in &unmet {
        platform_log(
            LOG_TAG,
            format!(
                "CPIM message requires {:?}, which is not understood",
                String::from_utf8_lossy(name)
            ),
        );
    }
    unmet.is_empty()
}

/// `data` decoded from base64, as MIME writes it, in lines (RFC 2045
/// section 6.8)
pub fn decode_base64(data: &[u8]) -> Result<Vec<u8>, base64::DecodeError> {
    let data: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    general_purpose::STANDARD.decode(data)
}

pub struct MessagingSessionHandle {
    pub(crate) inner: Arc<SipSession<CPMSession>>,
}

pub struct CPMMessageParam {
    message_type: String,
    /// Text, or not, as a video chat message is
    message_content: Vec<u8>,
    /// The imdn.Message-ID it is sent with, which notifications of it give
    message_id: String,
    /// Sent as it is, of the type `message_type`, not in a CPIM message
    raw: Option<Vec<u8>>,
    /// A CPIM message carrying a notification, or the signalling of a Group
    /// RCS Video Chat, signed rather than encrypted in a group chat
    /// encrypted end to end
    signed: bool,
    recipient: String,
    recipient_type: RecipientType,
    recipient_uri: String,
    /// The user alias it is sent with, as the formal name of its CPIM From
    sender_alias: Option<String>,
    message_result_callback: Arc<dyn Fn(u16, String) + Send + Sync>, // to-do: use FnOnce in CPMSession ?
}

impl CPMMessageParam {
    pub fn new<F>(
        message_type: String,
        message_content: impl Into<Vec<u8>>,
        message_id: String,
        recipient: &str,
        recipient_type: &RecipientType,
        recipient_uri: &str,
        message_result_callback: F,
    ) -> CPMMessageParam
    where
        F: Fn(u16, String) + Send + Sync + 'static,
    {
        CPMMessageParam {
            message_type,
            message_content: message_content.into(),
            message_id,
            raw: None,
            signed: false,
            recipient: String::from(recipient),
            recipient_type: RecipientType::from(recipient_type),
            recipient_uri: String::from(recipient_uri),
            sender_alias: None,
            message_result_callback: Arc::new(message_result_callback),
        }
    }

    /// The message sent with the user alias `alias`, as the formal name of
    /// its CPIM From, as a group chat has it (RCC.07 section 2.5.3.3)
    pub(crate) fn with_alias(mut self, alias: Option<String>) -> CPMMessageParam {
        self.sender_alias = alias;
        self
    }

    /// The message sent as it is, not in a CPIM message
    pub fn raw(mut self) -> CPMMessageParam {
        self.raw = Some(self.message_content.clone());
        self
    }

    /// `data` sent as it is instead, which unlike the message's content need
    /// not be text, such as the CPIM message carrying a Commit (RCC.16
    /// section 9.5.1)
    pub(crate) fn raw_data(mut self, data: Vec<u8>) -> CPMMessageParam {
        self.raw = Some(data);
        self
    }

    /// The message signed rather than encrypted if the group chat it goes
    /// to is encrypted end to end, as the signalling of a Group RCS Video
    /// Chat is (RCC.16 section 9.8.2)
    pub(crate) fn signed(mut self) -> CPMMessageParam {
        self.signed = true;
        self
    }

    /// The CPIM message carrying a notification, sent as it is, and signed
    /// if the group chat it goes to is encrypted end to end (RCC.16 sections
    /// 9.1.3, 9.1.4)
    pub fn notification(self) -> CPMMessageParam {
        let mut message = self.raw();
        message.signed = true;
        message
    }
}

/// `alias` as the display name of a SIP name-addr, or the formal name of a
/// CPIM From: a quoted string, its quotes and backslashes escaped, and the
/// control characters it may not carry left out (RFC 3261 section 25.1,
/// RFC 3862 section 3.6.1)
pub fn quoted_alias(alias: &str) -> String {
    let mut quoted = String::with_capacity(alias.len() + 2);
    quoted.push('"');
    for c in alias.chars().filter(|c| !c.is_control()) {
        if c == '"' || c == '\\' {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// The name-addr of `uri` with the user alias `alias` as its display name,
/// if there is one (RCC.07 section 2.5.3.3)
pub fn name_addr(alias: Option<&str>, uri: &str) -> String {
    match alias {
        Some(alias) => format!("{} <{}>", quoted_alias(alias), uri),
        None => format!("<{}>", uri),
    }
}

/// The user alias a request or message of this client carries in its From
pub enum SenderAlias<'a> {
    None,
    /// In an unencrypted conversation, as the display name
    Plain(&'a str),
    /// In an encrypted one, encrypted for it, as the `encrypted-alias`
    /// parameter of the URI, never in the clear (RCC.16 section 9.1.5)
    Sealed(&'a str),
}

/// The From of `uri` carrying `alias` (RCC.07 section 2.5.3.3, RCC.16
/// section 9.1.5)
pub fn sender_name_addr(uri: &str, alias: &SenderAlias) -> String {
    match alias {
        SenderAlias::None => name_addr(None, uri),
        SenderAlias::Plain(alias) => name_addr(Some(alias), uri),
        SenderAlias::Sealed(sealed) => format!(
            "<{};{}={}>",
            uri,
            String::from_utf8_lossy(encryption::SIP_URI_PARAMETER_ENCRYPTED_ALIAS),
            sealed
        ),
    }
}

/// Told of the user alias a sender gives itself, as a request or message
/// from it carries it (RCC.07 section 2.5.3.3): its URI, the alias, and
/// whether the alias came encrypted end to end (RCC.16 section 9.1.5)
pub type AliasListener = Arc<dyn Fn(&str, &str, bool) + Send + Sync>;

/// The user alias the display name `display_name` of a name-addr gives, its
/// quoted pairs taken as the characters they escape; None if it is empty
pub fn alias_of(display_name: &[u8]) -> Option<String> {
    let mut alias = Vec::with_capacity(display_name.len());
    let mut escaped = false;
    for b in display_name {
        if *b == b'\\' && !escaped {
            escaped = true;
            continue;
        }
        escaped = false;
        alias.push(*b);
    }
    let alias = String::from_utf8_lossy(&alias).trim().to_string();
    (!alias.is_empty()).then_some(alias)
}

/// A new imdn.Message-ID
pub fn new_message_id() -> String {
    String::from(
        Uuid::new_v4()
            .as_hyphenated()
            .encode_lower(&mut Uuid::encode_buffer()),
    )
}

/// The media type of is-composing indications (RFC 3994)
pub const IS_COMPOSING: &str = "application/im-iscomposing+xml";

/// Whether `content_type`, parameters aside, is `media_type`
pub fn is_media_type(content_type: &[u8], media_type: &str) -> bool {
    let without_parameters = content_type
        .split(|c| *c == b';')
        .next()
        .unwrap_or_default();
    syntax::trim(without_parameters).eq_ignore_ascii_case(media_type.as_bytes())
}

/// An is-composing indication (RFC 3994 section 4): the user is composing a
/// text message if `active`, refreshed within 60 s, or no longer is
pub fn is_composing_document(active: bool) -> String {
    let state = if active {
        "<state>active</state><contenttype>text/plain</contenttype><refresh>60</refresh>"
    } else {
        "<state>idle</state>"
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<isComposing xmlns=\"urn:ietf:params:xml:ns:im-iscomposing\">{}</isComposing>",
        state
    )
}

/// Whether a message of `message_type` asks to be told of its delivery and
/// display, as all but an is-composing indication (RFC 3994 section 4) and
/// the signalling of an RCS Video Chat do, which tells of its own delivery
/// (RCC.07 section 3.7.5.2.3.2.2)
fn asks_for_notifications(message_type: &str) -> bool {
    !is_media_type(message_type.as_bytes(), IS_COMPOSING)
        && !is_media_type(message_type.as_bytes(), video_chat::CONTENT_TYPE)
}

pub fn make_cpim_message_content_body(
    message_type: &str,
    message_content: &[u8],
    recipient_type: &RecipientType,
    recipient_uri: &str,
    message_imdn_id: &str,
    public_user_identity: &str,
    sender_alias: &SenderAlias,
) -> Body {
    let encoded = general_purpose::STANDARD.encode(message_content);

    let content_body = Vec::from(encoded);
    let content_body_length = content_body.len();

    let mut content_headers = Vec::new();

    content_headers.push(Header::new("Content-Type", String::from(message_type)));

    content_headers.push(Header::new("Content-Transfer-Encoding", "base64"));

    content_headers.push(Header::new(
        "Content-Length",
        format!("{}", content_body_length),
    ));

    let cpim_content_body = Body::Message(MessageBody {
        headers: content_headers,
        body: Arc::new(Body::Raw(content_body)),
    });

    let mut cpim_headers = Vec::new();

    cpim_headers.push(Header::new(
        "From",
        sender_name_addr(public_user_identity, sender_alias),
    ));
    cpim_headers.push(Header::new("To", format!("<{}>", recipient_uri)));

    let utc: DateTime<Local> = Local::now();

    cpim_headers.push(Header::new(
        "DateTime",
        utc.to_rfc3339_opts(SecondsFormat::Millis, false),
    ));

    cpim_headers.push(Header::new("NS", "imdn <urn:ietf:params:imdn>"));

    cpim_headers.push(Header::new(
        "imdn.Message-ID",
        String::from(message_imdn_id),
    ));

    if asks_for_notifications(message_type) {
        cpim_headers.push(Header::new(
            "imdn.Disposition-Notification",
            "positive-delivery, display",
        ));
    }

    cpim_headers.push(Header::new(
        "NS",
        "cpm <http://www.openmobilealliance.org/cpm/>",
    ));

    cpim_headers.push(Header::new(b"cpm.Payload-Type", String::from(message_type)));

    // cpim_headers.push(Header {
    //     name: b"NS".to_vec(),
    //     value: b"cpim <http://www.openmobilealliance.org/cpm/cpim>".to_vec(),
    // });

    if let RecipientType::Chatbot = recipient_type {
        cpim_headers.push(Header::new("NS", "maap <http://www.gsma.com/rcs/maap/>"));
    }

    Body::Message(MessageBody {
        headers: cpim_headers,
        body: Arc::new(cpim_content_body),
    })
}

/// The CPIM message of the IMDN document `imdn_xml`, to `recipient_uri`: the
/// document as it is, as a notification (RFC 5438 section 7.1), and asking
/// for no notification of itself; with the Original-Message-ID
/// `original_message_id` if it tells of a Re-Sent Message
pub fn make_cpim_imdn_body(
    imdn_xml: &str,
    recipient_uri: &str,
    original_message_id: Option<&str>,
    public_user_identity: &str,
) -> Body {
    let content_body = Vec::from(imdn_xml);

    let content_headers = vec![
        Header::new("Content-Type", "message/imdn+xml"),
        Header::new("Content-Disposition", "notification"),
        Header::new("Content-Length", format!("{}", content_body.len())),
    ];

    let cpim_content_body = Body::Message(MessageBody {
        headers: content_headers,
        body: Arc::new(Body::Raw(content_body)),
    });

    let utc: DateTime<Local> = Local::now();

    let mut cpim_headers = vec![
        Header::new("From", format!("<{}>", public_user_identity)),
        Header::new("To", format!("<{}>", recipient_uri)),
        Header::new(
            "DateTime",
            utc.to_rfc3339_opts(SecondsFormat::Millis, false),
        ),
        Header::new("NS", "imdn <urn:ietf:params:imdn>"),
        Header::new("imdn.Message-ID", new_message_id()),
    ];
    // that of a Re-Sent Message, telling of its Original Message too (RCC.16
    // sections 7.2.3, 7.7.1, 7.7.3)
    if let Some(original_message_id) = original_message_id {
        cpim_headers.push(Header::new("NS", "mls <http://www.gsma.com/rcs/mls>"));
        cpim_headers.push(Header::new(
            "mls.Original-Message-ID",
            String::from(original_message_id),
        ));
    }

    Body::Message(MessageBody {
        headers: cpim_headers,
        body: Arc::new(cpim_content_body),
    })
}

#[cfg(test)]
pub(crate) mod session_tests;

#[cfg(test)]
mod tests {
    use rust_rcs_core::cpim::CPIMMessage;
    use rust_rcs_core::internet::Body;

    use super::{
        alias_of, quoted_alias, sender_name_addr, understands_cpim_requirements, SenderAlias,
    };

    #[test]
    fn an_alias_is_quoted_and_taken_back() {
        // its quotes and backslashes escaped, its control characters left
        // out, so that it cannot end the header it is in (RFC 3261 section
        // 25.1)
        assert_eq!(quoted_alias("Alice"), "\"Alice\"");
        assert_eq!(
            quoted_alias("A \"b\" \\ c\r\n\td"),
            "\"A \\\"b\\\" \\\\ cd\""
        );
        // and taken back from a display name, as the parser gives it
        for alias in ["Alice", "A \"b\" \\ c", "Alice ☺"] {
            let quoted = quoted_alias(alias);
            let display_name = &quoted.as_bytes()[1..quoted.len() - 1];
            assert_eq!(alias_of(display_name).as_deref(), Some(alias));
        }
        assert_eq!(alias_of(b"  "), None);
        assert_eq!(alias_of(b""), None);
    }

    #[test]
    fn an_encrypted_alias_is_found_among_the_parameters_of_a_uri() {
        use super::encryption::encrypted_alias;
        use rust_rcs_core::internet::name_addr::AsNameAddr;

        assert_eq!(
            encrypted_alias(b"user=phone;encrypted-alias=aGVsbG8gd29ybGQ"),
            Some(&b"aGVsbG8gd29ybGQ"[..])
        );
        assert_eq!(
            encrypted_alias(b"Encrypted-Alias=abc_-"),
            Some(&b"abc_-"[..])
        );
        for parameters in [
            &b""[..],
            b"user=phone",
            b"encrypted-alias",
            b"encrypted-alias=",
            b"encrypted-aliases=abc",
        ] {
            assert_eq!(encrypted_alias(parameters), None);
        }
        // as a name-addr gives them, in angle brackets or not
        for from in [
            &b"<sip:+1234578901@operator.com;user=phone;encrypted-alias=aGVsbG8>;tag=1"[..],
            b"sip:+1234578901@operator.com;user=phone;encrypted-alias=aGVsbG8",
        ] {
            let addresses = from.as_name_addresses();
            let uri_part = addresses[0].uri_part.as_ref().unwrap();
            assert_eq!(uri_part.uri, b"sip:+1234578901@operator.com");
            assert_eq!(
                encrypted_alias(uri_part.uri_parameters),
                Some(&b"aGVsbG8"[..])
            );
        }
    }

    #[test]
    fn the_from_carries_the_alias_in_the_clear_or_encrypted() {
        let uri = "sip:+15551234@example.com";
        assert_eq!(
            sender_name_addr(uri, &SenderAlias::None),
            format!("<{}>", uri)
        );
        assert_eq!(
            sender_name_addr(uri, &SenderAlias::Plain("Alice")),
            format!("\"Alice\" <{}>", uri)
        );
        // in the encrypted-alias parameter of the URI (RCC.16 section 9.1.5)
        assert_eq!(
            sender_name_addr(uri, &SenderAlias::Sealed("aGVsbG8")),
            format!("<{};encrypted-alias=aGVsbG8>", uri)
        );
    }

    fn message(require: &str) -> CPIMMessage {
        let data = format!(
            "From: <sip:anonymous@anonymous.invalid>\r\n\
To: <sip:anonymous@anonymous.invalid>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
NS: x <urn:example:x>\r\n\
{}\
imdn.Message-ID: Kn31\r\n\
DateTime: 2023-04-04T12:16:49.000+08:00\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi",
            require
        );
        CPIMMessage::try_from(&Body::construct_message(data.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn a_message_requiring_what_the_client_reads_is_taken() {
        assert!(understands_cpim_requirements(&message("")));
        assert!(understands_cpim_requirements(&message(
            "Require: imdn.Disposition-Notification, DateTime\r\n"
        )));
    }

    #[test]
    fn a_message_requiring_more_is_not() {
        assert!(!understands_cpim_requirements(&message(
            "Require: x.Vital\r\n"
        )));
        assert!(!understands_cpim_requirements(&message(
            "Require: DateTime, Subject\r\n"
        )));
    }
}
