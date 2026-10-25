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
    message_content: String,
    /// The imdn.Message-ID it is sent with, which notifications of it give
    message_id: String,
    /// Sent as it is, of the type `message_type`, not in a CPIM message
    raw: bool,
    /// A CPIM message carrying a notification, signed in a group chat
    /// encrypted end to end
    signed: bool,
    recipient: String,
    recipient_type: RecipientType,
    recipient_uri: String,
    message_result_callback: Arc<dyn Fn(u16, String) + Send + Sync>, // to-do: use FnOnce in CPMSession ?
}

impl CPMMessageParam {
    pub fn new<F>(
        message_type: String,
        message_content: String,
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
            message_content,
            message_id,
            raw: false,
            signed: false,
            recipient: String::from(recipient),
            recipient_type: RecipientType::from(recipient_type),
            recipient_uri: String::from(recipient_uri),
            message_result_callback: Arc::new(message_result_callback),
        }
    }

    /// The message sent as it is, not in a CPIM message
    pub fn raw(mut self) -> CPMMessageParam {
        self.raw = true;
        self
    }

    /// The CPIM message carrying a notification, sent as it is, and signed
    /// if the group chat it goes to is encrypted end to end (RCC.16 sections
    /// 9.1.3, 9.1.4)
    pub fn notification(mut self) -> CPMMessageParam {
        self.raw = true;
        self.signed = true;
        self
    }
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
/// display, as all but an is-composing indication do (RFC 3994 section 4)
fn asks_for_notifications(message_type: &str) -> bool {
    !is_media_type(message_type.as_bytes(), IS_COMPOSING)
}

pub fn make_cpim_message_content_body(
    message_type: &str,
    message_content: &str,
    recipient_type: &RecipientType,
    recipient_uri: &str,
    message_imdn_id: &str,
    public_user_identity: &str,
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

    cpim_headers.push(Header::new("From", format!("<{}>", public_user_identity)));
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
/// for no notification of itself
pub fn make_cpim_imdn_body(
    imdn_xml: &str,
    recipient_uri: &str,
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

    let cpim_headers = vec![
        Header::new("From", format!("<{}>", public_user_identity)),
        Header::new("To", format!("<{}>", recipient_uri)),
        Header::new(
            "DateTime",
            utc.to_rfc3339_opts(SecondsFormat::Millis, false),
        ),
        Header::new("NS", "imdn <urn:ietf:params:imdn>"),
        Header::new("imdn.Message-ID", new_message_id()),
    ];

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

    use super::understands_cpim_requirements;

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
