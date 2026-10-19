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

//! Delivery and display notifications (RFC 5438) of the messages taken, sent
//! to their sender in SIP MESSAGEs of the service the message came by

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Mutex};

use rust_rcs_core::cpim::CPIMInfo;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::imdn::notification::{Dispositions, Imdn, Notification, Status};
use rust_rcs_core::internet::Header;
use rust_rcs_core::io::Serializable;
use rust_rcs_core::sip::sip_session::SipSession;
use rust_rcs_core::sip::{SipMessage, SipTransactionManager, SipTransport, MESSAGE};
use rust_rcs_core::util::rand;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use super::session::CPMSession;
use super::sip::cpm_contact::CPMServiceType;
use super::standalone_messaging::OutgoingPagerModeContext;
use super::{
    is_media_type, make_cpim_imdn_body, new_message_id, CPMMessageParam, IS_COMPOSING, LOG_TAG,
};
use crate::messaging::ffi::RecipientType;

/// The service a message came by, which notifications of it go by
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImdnService {
    /// A one-to-one chat
    Chat,
    /// Standalone messaging, in pager or large mode
    Standalone,
}

impl ImdnService {
    /// The service of the messages taken in a chat of `service_type`, if
    /// they are told of: a group chat's are not, yet
    pub fn of_chat(service_type: &CPMServiceType) -> Option<ImdnService> {
        match service_type {
            CPMServiceType::OneToOne | CPMServiceType::Chatbot => Some(ImdnService::Chat),
            CPMServiceType::Group | CPMServiceType::System => None,
        }
    }

    fn icsi(&self) -> &'static str {
        match self {
            ImdnService::Chat => "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session",
            ImdnService::Standalone => "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg",
        }
    }
}

/// Sends the IMDN document `imdn_xml` to `recipient_uri` in a SIP MESSAGE of
/// `service`, `callback` called with the final status
pub fn send_imdn<F>(
    imdn_xml: &str,
    recipient_uri: &str,
    service: ImdnService,
    tm: &SipTransactionManager,
    transport: &Arc<SipTransport>,
    public_user_identity: &str,
    callback: F,
    rt: &Arc<Runtime>,
) where
    F: FnOnce(u16, String) + Send + Sync + 'static,
{
    let mut req_message = SipMessage::new_request(MESSAGE, recipient_uri.as_bytes());

    req_message.add_header(Header::new(b"Call-ID", new_message_id()));

    req_message.add_header(Header::new(b"CSeq", b"1 MESSAGE"));

    let tag = rand::create_raw_alpha_numeric_string(8);
    let tag = String::from_utf8_lossy(&tag);

    req_message.add_header(Header::new(
        b"From",
        format!("<{}>;tag={}", public_user_identity, tag),
    ));

    req_message.add_header(Header::new(b"To", format!("<{}>", recipient_uri)));

    let icsi = service.icsi();

    req_message.add_header(Header::new(
        b"Accept-Contact",
        format!("*;+g.3gpp.icsi-ref=\"{}\"", icsi.replace(':', "%3A")),
    ));

    req_message.add_header(Header::new(b"P-Preferred-Service", icsi));

    req_message.add_header(Header::new(
        b"P-Preferred-Identity",
        String::from(public_user_identity),
    ));

    let cpim_body = make_cpim_imdn_body(imdn_xml, recipient_uri, public_user_identity);

    let sip_body_len = cpim_body.estimated_size();

    req_message.set_body(Arc::new(cpim_body));

    req_message.add_header(Header::new(b"Content-Type", b"message/cpim"));

    req_message.add_header(Header::new(b"Content-Length", format!("{}", sip_body_len)));

    let (client_transaction_tx, mut client_transaction_rx) = mpsc::channel(1);

    rt.spawn(async move {
        if let Some((status_code, reason_phrase)) = client_transaction_rx.recv().await {
            callback(status_code, reason_phrase);
        }
    });

    tm.send_request(
        req_message,
        transport,
        OutgoingPagerModeContext {
            client_transaction_tx,
            rt: Arc::clone(rt),
        },
        rt,
    );
}

/// Notes a message taken from `sender_uri` by `service`, and tells the
/// sender it was delivered, if it asked to be told, from the identity and
/// over the transport `registered` gives
pub fn acknowledge_delivery<R>(
    received_messages: &ReceivedMessages,
    service: ImdnService,
    sender_uri: &str,
    cpim_info: &CPIMInfo,
    content_type: &[u8],
    registered: R,
    tm: &Arc<SipTransactionManager>,
    rt: &Arc<Runtime>,
) where
    R: FnOnce() -> Option<(Arc<SipTransport>, String)>,
{
    if let Some(imdn_xml) =
        received_messages.on_received(service, sender_uri, cpim_info, content_type)
    {
        if let Some((transport, public_user_identity)) = registered() {
            // after the message is answered, not from where it is taken
            let tm = Arc::clone(tm);
            let sender_uri = String::from(sender_uri);
            let rt_ = Arc::clone(rt);
            rt.spawn(async move {
                send_imdn(
                    &imdn_xml,
                    &sender_uri,
                    service,
                    &tm,
                    &transport,
                    &public_user_identity,
                    |status_code, reason_phrase| {
                        platform_log(
                            LOG_TAG,
                            format!(
                                "delivery notification answered with {} {}",
                                status_code, reason_phrase
                            ),
                        );
                    },
                    &rt_,
                );
            });
        }
    }
}

/// Notes a message taken in `sip_session`, with the group at
/// `conference_uri`, from the participant its CPIM From gives, and tells the
/// participant it was delivered, in the session, as `public_user_identity`
/// gives us, if it asked to be told
pub fn acknowledge_group_delivery<P>(
    received_messages: &ReceivedMessages,
    sip_session: &Arc<SipSession<CPMSession>>,
    conference_uri: &str,
    cpim_info: &CPIMInfo,
    content_type: &[u8],
    public_user_identity: P,
    rt: &Arc<Runtime>,
) where
    P: FnOnce() -> Option<String>,
{
    // the participant, whom the focus sends the notification on to
    let sender_uri = match &cpim_info.from_uri {
        Some(uri) => {
            String::from_utf8_lossy(&uri.string_representation_without_query_and_fragment())
                .into_owned()
        }
        None => return,
    };

    if let Some(imdn_xml) =
        received_messages.on_received_in_group(conference_uri, &sender_uri, cpim_info, content_type)
    {
        if let Some(public_user_identity) = public_user_identity() {
            send_group_imdn(
                &sip_session.get_inner(),
                &imdn_xml,
                &sender_uri,
                &public_user_identity,
                |status_code, reason_phrase| {
                    platform_log(
                        LOG_TAG,
                        format!(
                            "group delivery notification answered with {} {}",
                            status_code, reason_phrase
                        ),
                    );
                },
                rt,
            );
        }
    }
}

/// Sends the IMDN document `imdn_xml` in the session `session` with a group,
/// for its focus to send on to the participant `recipient_uri`, the CPIM To
/// (RFC 5438 section 9)
pub fn send_group_imdn<F>(
    session: &CPMSession,
    imdn_xml: &str,
    recipient_uri: &str,
    public_user_identity: &str,
    callback: F,
    rt: &Arc<Runtime>,
) where
    F: Fn(u16, String) + Send + Sync + 'static,
{
    let body = make_cpim_imdn_body(imdn_xml, recipient_uri, public_user_identity);
    let mut data = Vec::with_capacity(body.estimated_size());
    if let Ok(mut reader) = body.reader() {
        let _ = reader.read_to_end(&mut data);
    }

    let message = CPMMessageParam::new(
        String::from("message/cpim"),
        String::from_utf8_lossy(&data).into_owned(),
        new_message_id(),
        recipient_uri,
        &RecipientType::Group,
        recipient_uri,
        callback,
    )
    .raw();

    session.send_message(message, rt);
}

/// How many messages taken are kept note of, the oldest forgotten first
const NOTED: usize = 1024;

/// A message taken, as far as notifying its sender goes
struct Received {
    message_id: String,
    sender_uri: String,
    service: ImdnService,
    datetime: String,
    dispositions: Dispositions,
    /// The URI of the group it was taken in, if in one
    group: Option<String>,
}

/// A notification to send to `sender_uri`: in the session with `group` if
/// the message was taken in one, else by `service`
#[derive(Debug, PartialEq, Eq)]
pub struct Notice {
    pub xml: String,
    pub sender_uri: String,
    pub service: ImdnService,
    pub group: Option<String>,
}

/// What became of a notification asked for
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The message is not one of those noted
    Unknown,
    /// The message did not ask for it, and so it is not to be sent (RFC 5438
    /// section 7.2)
    NotAskedFor,
}

/// The messages last taken, and the notifications each asks for
pub struct ReceivedMessages {
    received: Mutex<VecDeque<Received>>,
}

impl ReceivedMessages {
    pub fn new() -> ReceivedMessages {
        ReceivedMessages {
            received: Mutex::new(VecDeque::new()),
        }
    }

    /// Notes the message of `cpim_info` and `content_type`, taken from
    /// `sender_uri` by `service`, and gives the notification of its delivery,
    /// if it asks for one. A notification is neither noted nor told of.
    pub fn on_received(
        &self,
        service: ImdnService,
        sender_uri: &str,
        cpim_info: &CPIMInfo,
        content_type: &[u8],
    ) -> Option<String> {
        self.note(service, sender_uri, None, cpim_info, content_type)
    }

    /// As on_received(), for a message taken in the session with the group
    /// at `conference_uri`, from its participant `sender_uri`
    pub fn on_received_in_group(
        &self,
        conference_uri: &str,
        sender_uri: &str,
        cpim_info: &CPIMInfo,
        content_type: &[u8],
    ) -> Option<String> {
        self.note(
            ImdnService::Chat,
            sender_uri,
            Some(conference_uri),
            cpim_info,
            content_type,
        )
    }

    fn note(
        &self,
        service: ImdnService,
        sender_uri: &str,
        group: Option<&str>,
        cpim_info: &CPIMInfo,
        content_type: &[u8],
    ) -> Option<String> {
        // nor an is-composing indication, which asks for nothing
        if is_media_type(content_type, "message/imdn+xml")
            || is_media_type(content_type, IS_COMPOSING)
        {
            return None;
        }

        let message_id = String::from_utf8_lossy(cpim_info.imdn_message_id).to_string();
        let datetime = String::from_utf8_lossy(cpim_info.date).to_string();
        let dispositions = match cpim_info.disposition_notification {
            Some(value) => Dispositions::parse(value),
            None => Dispositions::default(),
        };

        {
            let mut received = self.received.lock().unwrap();
            received.retain(|r| r.message_id != message_id);
            if received.len() == NOTED {
                received.pop_front();
            }
            received.push_back(Received {
                message_id: message_id.clone(),
                sender_uri: String::from(sender_uri),
                service,
                datetime: datetime.clone(),
                dispositions,
                group: group.map(String::from),
            });
        }

        if dispositions.ask_for(Notification::Delivery, Status::Delivered) {
            return Imdn {
                message_id,
                datetime,
                recipient_uri: None,
                original_recipient_uri: None,
                notification: Notification::Delivery,
                status: Status::Delivered,
            }
            .to_xml();
        }

        None
    }

    /// The notification that the message `message_id` was displayed, and
    /// where to send it
    pub fn displayed(&self, message_id: &str) -> Result<Notice, Refusal> {
        let received = self.received.lock().unwrap();
        let message = received
            .iter()
            .find(|r| r.message_id == message_id)
            .ok_or(Refusal::Unknown)?;

        if !message
            .dispositions
            .ask_for(Notification::Display, Status::Displayed)
        {
            return Err(Refusal::NotAskedFor);
        }

        let xml = Imdn {
            message_id: message.message_id.clone(),
            datetime: message.datetime.clone(),
            recipient_uri: None,
            original_recipient_uri: None,
            notification: Notification::Display,
            status: Status::Displayed,
        }
        .to_xml()
        .ok_or(Refusal::NotAskedFor)?;

        Ok(Notice {
            xml,
            sender_uri: message.sender_uri.clone(),
            service: message.service,
            group: message.group.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use rust_rcs_core::cpim::CPIMMessage;
    use rust_rcs_core::imdn::notification::{Imdn, Notification, Status};
    use rust_rcs_core::internet::Body;

    use super::{ImdnService, ReceivedMessages, Refusal, NOTED};

    const SENDER: &str = "sip:+15551234@example.com";

    fn message(message_id: &str, disposition_notification: Option<&str>) -> CPIMMessage {
        let data = format!(
            "From: <{}>\r\n\
To: <sip:+15559876@example.com>\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: {}\r\n\
{}\
DateTime: 2023-04-04T12:16:49.000+08:00\r\n\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
hi",
            SENDER,
            message_id,
            disposition_notification
                .map(|v| format!("imdn.Disposition-Notification: {}\r\n", v))
                .unwrap_or_default()
        );
        CPIMMessage::try_from(&Body::construct_message(data.as_bytes()).unwrap()).unwrap()
    }

    fn receive(
        received: &ReceivedMessages,
        message_id: &str,
        disposition_notification: Option<&str>,
        content_type: &[u8],
    ) -> Option<Imdn> {
        let message = message(message_id, disposition_notification);
        let info = message.get_info().unwrap();
        received
            .on_received(ImdnService::Standalone, SENDER, &info, content_type)
            .map(|xml| Imdn::from_xml(xml.as_bytes()).unwrap())
    }

    #[test]
    fn a_message_asking_to_be_told_of_its_delivery_is() {
        let received = ReceivedMessages::new();
        assert_eq!(
            receive(
                &received,
                "Kn31",
                Some("positive-delivery, display"),
                b"text/plain"
            ),
            Some(Imdn {
                message_id: String::from("Kn31"),
                datetime: String::from("2023-04-04T12:16:49.000+08:00"),
                recipient_uri: None,
                original_recipient_uri: None,
                notification: Notification::Delivery,
                status: Status::Delivered,
            })
        );
        assert_eq!(
            receive(&received, "Kn32", Some("display"), b"text/plain"),
            None
        );
        assert_eq!(receive(&received, "Kn33", None, b"text/plain"), None);
    }

    #[test]
    fn a_notification_is_not_told_of() {
        let received = ReceivedMessages::new();
        assert_eq!(
            receive(
                &received,
                "Kn31",
                Some("positive-delivery, display"),
                b"Message/IMDN+xml; charset=utf-8"
            ),
            None
        );
        assert_eq!(received.displayed("Kn31"), Err(Refusal::Unknown));

        // nor an is-composing indication
        assert_eq!(
            receive(
                &received,
                "Kn32",
                Some("positive-delivery, display"),
                b"application/im-iscomposing+xml"
            ),
            None
        );
        assert_eq!(received.displayed("Kn32"), Err(Refusal::Unknown));
    }

    #[test]
    fn a_display_is_told_of_only_when_asked_for() {
        let received = ReceivedMessages::new();
        receive(
            &received,
            "Kn31",
            Some("positive-delivery, display"),
            b"text/plain",
        );
        receive(&received, "Kn32", Some("positive-delivery"), b"text/plain");

        let notice = received.displayed("Kn31").unwrap();
        assert_eq!(notice.sender_uri, SENDER);
        assert_eq!(notice.service, ImdnService::Standalone);
        assert_eq!(notice.group, None);
        let imdn = Imdn::from_xml(notice.xml.as_bytes()).unwrap();
        assert_eq!(imdn.message_id, "Kn31");
        assert_eq!(imdn.datetime, "2023-04-04T12:16:49.000+08:00");
        assert_eq!(imdn.notification, Notification::Display);
        assert_eq!(imdn.status, Status::Displayed);

        assert_eq!(received.displayed("Kn32"), Err(Refusal::NotAskedFor));
        assert_eq!(received.displayed("Kn33"), Err(Refusal::Unknown));
    }

    #[test]
    fn the_oldest_messages_are_forgotten() {
        let received = ReceivedMessages::new();
        for i in 0..=NOTED {
            receive(
                &received,
                &format!("m{}", i),
                Some("display"),
                b"text/plain",
            );
        }

        assert_eq!(received.displayed("m0"), Err(Refusal::Unknown));
        assert!(received.displayed("m1").is_ok());
        assert!(received.displayed(&format!("m{}", NOTED)).is_ok());
        assert_eq!(received.received.lock().unwrap().len(), NOTED);
    }

    #[test]
    fn a_message_taken_again_is_noted_once_as_last_taken() {
        let received = ReceivedMessages::new();
        receive(&received, "Kn31", Some("display"), b"text/plain");
        receive(&received, "Kn31", Some("positive-delivery"), b"text/plain");

        assert_eq!(received.displayed("Kn31"), Err(Refusal::NotAskedFor));
        assert_eq!(received.received.lock().unwrap().len(), 1);
    }
}
