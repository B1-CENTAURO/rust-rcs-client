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

//! Chat sessions run against a peer the test scripts: SIP over a pipe in
//! place of the connection to the P-CSCF, MSRP over TCP on localhost

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::runtime::Runtime;

use rust_rcs_core::cpim::{CPIMInfo, CPIMMessage};
use rust_rcs_core::imdn::notification::{Dispositions, Imdn, Notification, Status};
use rust_rcs_core::internet::{header, Body};
use rust_rcs_core::io::network::stream::ClientSocket;
use rust_rcs_core::sip::sip_parser::SipParser;
use rust_rcs_core::sip::sip_subscription::SubscriptionManager;
use rust_rcs_core::sip::sip_transaction::SipTransactionManager;
use rust_rcs_core::sip::sip_transport::{setup_sip_transport, SipTransportType};
use rust_rcs_core::sip::{
    SipCore, SipMessage, SipTransport, TransactionHandler, ACK, BYE, CANCEL, INVITE, MESSAGE,
    NOTIFY, OPTIONS, UPDATE,
};

use crate::messaging::ffi::RecipientType;

use super::encryption::{
    EndReason, FailedToDecrypt, GroupEncryption, GroupInfoPull, ImdnTold, Sealed, Taken, Upgrade,
    Verified,
};
use super::group_chat::GroupIds;
use super::imdn::{
    acknowledge_delivery, acknowledge_group_delivery, ImdnService, ReceivedMessages,
};
use super::new_message_id;
use super::session::{CPMGroupEvent, CPMSessionService, CPMSessionServiceWrapper};
use super::standalone_messaging::{
    self, StandaloneMessagingService, StandaloneMessagingServiceWrapper,
};

pub const IMPU: &str = "sip:+15551234@example.com";
pub const INSTANCE: &str = "<urn:uuid:11111111-2222-3333-4444-555555555555>";
pub const TRANSPORT_ADDRESS: &str = "192.0.2.10:5060";
pub const PEER: &str = "sip:+15559876@example.com";

/// The client side: the chat service over SIP and MSRP
pub struct Client {
    pub rt: Arc<Runtime>,
    pub core: Arc<SipCore>,
    pub transport: Arc<SipTransport>,
    pub sessions: Arc<CPMSessionService>,
    pub standalone: Arc<StandaloneMessagingService>,
    /// (contact, content type, content) of each message the app is given
    pub received: Receiver<(String, String, String)>,
    /// (subject, referred-by name) of each group chat the app is invited to
    pub group_invites: Receiver<(String, String)>,
    /// The messages taken, noted as the engine notes them
    pub received_messages: Arc<ReceivedMessages>,
    /// What the app is told of the group chats taken part in
    pub group_events: Receiver<String>,
    /// How the app answers group chat invitations: 200, or 180 to answer
    /// later
    pub group_answer: Arc<AtomicU16>,
    /// The same, for one-to-one chat invitations
    pub chat_answer: Arc<AtomicU16>,
    /// The identifiers of groups the app is told to keep
    pub group_ids: Receiver<GroupIds>,
}

impl Client {
    /// Sends `content` to `recipient`, returning when send_message() does,
    /// within 5 s, and a receiver of its result
    pub fn send(
        &self,
        recipient: &str,
        recipient_type: RecipientType,
        content: &str,
    ) -> Receiver<(u16, String)> {
        self.send_with_id(recipient, recipient_type, content, &new_message_id())
    }

    /// As send(), with the imdn.Message-ID `message_id`
    pub fn send_with_id(
        &self,
        recipient: &str,
        recipient_type: RecipientType,
        content: &str,
        message_id: &str,
    ) -> Receiver<(u16, String)> {
        let (result_tx, result_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();

        let sessions = Arc::clone(&self.sessions);
        let core = Arc::clone(&self.core);
        let rt = Arc::clone(&self.rt);
        let recipient = String::from(recipient);
        let content = String::from(content);
        let message_id = String::from(message_id);
        std::thread::spawn(move || {
            sessions.send_message(
                "text/plain",
                &content,
                &message_id,
                &recipient,
                &recipient_type,
                &recipient,
                move |status_code, reason_phrase| {
                    let _ = result_tx.send((status_code, reason_phrase));
                },
                &core,
                &rt,
            );
            let _ = returned_tx.send(());
        });

        returned_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("send_message() to return");

        result_rx
    }
}

/// The other side of the SIP connection
pub struct Peer {
    pub rt: Arc<Runtime>,
    stream: DuplexStream,
    parser: SipParser,
}

impl Peer {
    /// The other side of `stream`, on `rt`
    pub fn over(rt: Arc<Runtime>, stream: DuplexStream) -> Peer {
        Peer {
            rt,
            stream,
            parser: SipParser::new(),
        }
    }

    pub fn next_within(&mut self, timeout: Duration) -> Option<SipMessage> {
        let Peer {
            rt, stream, parser, ..
        } = self;
        rt.block_on(async {
            tokio::time::timeout(timeout, async {
                loop {
                    match parser.produce().unwrap() {
                        Some(SipMessage::Ping) | Some(SipMessage::Pong) => {}
                        Some(message) => return message,
                        None => {
                            let mut data = [0; 4096];
                            let size = stream.read(&mut data).await.unwrap();
                            assert!(size > 0, "the transport closed");
                            parser.feed(&data[..size]);
                        }
                    }
                }
            })
            .await
            .ok()
        })
    }

    pub fn next(&mut self) -> SipMessage {
        self.next_within(Duration::from_secs(5))
            .expect("a message from the client")
    }

    pub fn next_request(&mut self, method: &str) -> SipMessage {
        let message = self.next();
        match &message {
            SipMessage::Request(line, _, _) => {
                assert_eq!(
                    String::from_utf8_lossy(&line.method),
                    method,
                    "the request sent"
                );
            }
            _ => panic!("not a request: {}", status_code(&message)),
        }
        message
    }

    pub fn next_response(&mut self) -> SipMessage {
        let message = self.next();
        match &message {
            SipMessage::Response(_, _, _) => message,
            _ => panic!("not a response"),
        }
    }

    /// Checks that the client says nothing for a while
    pub fn silence(&mut self) {
        if let Some(message) = self.next_within(Duration::from_millis(500)) {
            panic!("unexpected: {:?}", first_line(&message));
        }
    }

    pub fn send(&mut self, data: &str) {
        self.rt
            .block_on(self.stream.write_all(data.as_bytes()))
            .unwrap();
    }
}

/// A client with the chat and standalone messaging services, `registered`
/// or not on its connection, accepting invitations at once
pub fn start(registered: bool) -> (Client, Peer) {
    let rt = Arc::new(Runtime::new().unwrap());
    let (tm, tm_events) = SipTransactionManager::new(&rt);
    let tm = Arc::new(tm);
    let sm = Arc::new(SubscriptionManager::new(500));

    let (received_tx, received) = mpsc::channel();
    let received_tx = Arc::new(std::sync::Mutex::new(received_tx));
    let received_tx_ = Arc::clone(&received_tx);
    let (group_invites_tx, group_invites) = mpsc::channel();
    let group_invites_tx = std::sync::Mutex::new(group_invites_tx);
    let (group_events_tx, group_events) = mpsc::channel();
    let group_events_tx = std::sync::Mutex::new(group_events_tx);
    let (group_ids_tx, group_ids) = mpsc::channel();
    let group_ids_tx = std::sync::Mutex::new(group_ids_tx);
    let group_answer = Arc::new(AtomicU16::new(200));
    let group_answer_ = Arc::clone(&group_answer);
    let chat_answer = Arc::new(AtomicU16::new(200));
    let chat_answer_ = Arc::clone(&chat_answer);

    // the messages taken are acknowledged as the engine does, once the
    // transport is registered
    let received_messages = Arc::new(ReceivedMessages::new());
    let registered_transport: Arc<std::sync::Mutex<Option<Arc<SipTransport>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let registered_identity = {
        let registered_transport = Arc::clone(&registered_transport);
        move || {
            registered_transport
                .lock()
                .unwrap()
                .clone()
                .map(|transport| (transport, String::from(IMPU)))
        }
    };
    let registered_identity_ = registered_identity.clone();
    let (received_messages_1, tm_1, rt_1) = (
        Arc::clone(&received_messages),
        Arc::clone(&tm),
        Arc::clone(&rt),
    );
    let (received_messages_2, tm_2, rt_2) = (
        Arc::clone(&received_messages),
        Arc::clone(&tm),
        Arc::clone(&rt),
    );

    let sessions = Arc::new(CPMSessionService::new(
        move |session, contact, cpim_info, content_type, content| {
            let _ = received_tx.lock().unwrap().send((
                String::from_utf8_lossy(contact).into_owned(),
                String::from_utf8_lossy(content_type).into_owned(),
                String::from_utf8_lossy(content).into_owned(),
            ));
            if let Some(service) = ImdnService::of_chat(
                &session
                    .get_inner()
                    .get_session_info()
                    .cpm_contact
                    .service_type,
            ) {
                acknowledge_delivery(
                    &received_messages_1,
                    service,
                    &String::from_utf8_lossy(contact),
                    cpim_info,
                    content_type,
                    registered_identity.clone(),
                    &tm_1,
                    &rt_1,
                );
            } else {
                // in a group's session, the contact its focus
                acknowledge_group_delivery(
                    &received_messages_1,
                    session,
                    &String::from_utf8_lossy(contact),
                    cpim_info,
                    content_type,
                    || registered_identity().map(|(_, impu)| impu),
                    &rt_1,
                );
            }
        },
        |_msrp_info| allocate_msrp_socket(),
        |sock, raddr, rport, _tls| connect_msrp_socket(sock, raddr, rport),
        move |_, _, _, _, _| chat_answer_.load(Ordering::SeqCst),
        move |_, _, _, subject, referred_by_name, _, _| {
            let _ = group_invites_tx
                .lock()
                .unwrap()
                .send((String::from(subject), String::from(referred_by_name)));
            group_answer_.load(Ordering::SeqCst)
        },
        move |event| {
            let event = match event {
                CPMGroupEvent::Invited(invitation) => {
                    format!(
                        "invited {} {} {} {} {} {}",
                        invitation.conference_uri,
                        invitation.conversation_id,
                        invitation.subject.as_deref().unwrap_or("-"),
                        invitation.inviter_uri.as_deref().unwrap_or("-"),
                        invitation.inviter_name.as_deref().unwrap_or("-"),
                        if invitation.pending {
                            "pending"
                        } else {
                            "accepted"
                        }
                    ) + if invitation.encrypted {
                        " encrypted"
                    } else {
                        ""
                    }
                }
                CPMGroupEvent::Joined(group) => format!("joined {}", group),
                CPMGroupEvent::Participant(group, participant) => format!(
                    "participant {} {} {} {}",
                    group,
                    participant.uri,
                    participant.display_name.as_deref().unwrap_or("-"),
                    participant.status
                ),
                CPMGroupEvent::Left(group) => format!("left {}", group),
                CPMGroupEvent::InvitationWithdrawn(group) => format!("withdrawn {}", group),
                CPMGroupEvent::EncryptionEnded(group) => format!("unencrypted {}", group),
                CPMGroupEvent::EncryptionResumed(group) => format!("encrypted {}", group),
                // apart, as the app keeps them
                CPMGroupEvent::Ids(ids) => {
                    let _ = group_ids_tx.lock().unwrap().send(ids);
                    return;
                }
            };
            let _ = group_events_tx.lock().unwrap().send(event);
        },
    ));

    let standalone = Arc::new(StandaloneMessagingService::new(
        move |contact, cpim_info, content_type, content| {
            let _ = received_tx_.lock().unwrap().send((
                String::from_utf8_lossy(contact).into_owned(),
                String::from_utf8_lossy(content_type).into_owned(),
                String::from_utf8_lossy(content).into_owned(),
            ));
            acknowledge_delivery(
                &received_messages_2,
                ImdnService::Standalone,
                &String::from_utf8_lossy(contact),
                cpim_info,
                content_type,
                registered_identity_.clone(),
                &tm_2,
                &rt_2,
            );
        },
        |_msrp_info| allocate_msrp_socket(),
        |sock, raddr, rport, _tls| connect_msrp_socket(sock, raddr, rport),
    ));

    let handlers: Vec<Box<dyn TransactionHandler + Send + Sync>> = vec![
        Box::new(StandaloneMessagingServiceWrapper {
            service: Arc::clone(&standalone),
            tm: Arc::clone(&tm),
        }),
        Box::new(CPMSessionServiceWrapper {
            service: Arc::clone(&sessions),
            tm: Arc::clone(&tm),
        }),
    ];
    let core = Arc::new(SipCore::new(
        &sm,
        &tm,
        tm_events,
        vec![ACK, BYE, CANCEL, INVITE, MESSAGE, NOTIFY, OPTIONS, UPDATE],
        handlers,
        &rt,
    ));
    sessions.attach_core(&core, &rt);

    let transport = Arc::new(SipTransport::new::<DuplexStream>(
        String::from(TRANSPORT_ADDRESS),
        SipTransportType::TCP,
    ));
    let (ours, theirs) = tokio::io::duplex(65536);
    let tx = setup_sip_transport(&transport, ours, tm.get_ctrl_itf(), Arc::clone(&rt), || {});
    tm.register_sip_transport(Arc::clone(&transport), tx);

    if registered {
        core.set_default_public_identity(
            String::from(IMPU),
            String::from(INSTANCE),
            Arc::clone(&transport),
        );
        sessions.set_registered_public_identity(
            String::from(IMPU),
            String::from(INSTANCE),
            Arc::clone(&transport),
        );
        standalone.set_registered_public_identity(
            String::from(IMPU),
            String::from(INSTANCE),
            Arc::clone(&transport),
        );
        registered_transport
            .lock()
            .unwrap()
            .replace(Arc::clone(&transport));
    }

    (
        Client {
            rt: Arc::clone(&rt),
            core,
            transport,
            sessions,
            standalone,
            received,
            group_invites,
            received_messages,
            group_events,
            group_answer,
            chat_answer,
            group_ids,
        },
        Peer {
            rt,
            stream: theirs,
            parser: SipParser::new(),
        },
    )
}

fn connect_msrp_socket(
    sock: ClientSocket,
    raddr: &String,
    rport: u16,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<
                    rust_rcs_core::io::network::stream::ClientStream,
                    (u16, &'static str),
                >,
            > + Send,
    >,
> {
    let raddr = raddr.clone();
    Box::pin(async move {
        let ip = raddr
            .parse()
            .map_err(|_| (480, "Temporarily Unavailable"))?;
        sock.connect(ip, rport, None)
            .await
            .map_err(|_| (480, "Temporarily Unavailable"))
    })
}

fn allocate_msrp_socket(
) -> Result<(ClientSocket, String, u16, bool, bool, bool), (u16, &'static str)> {
    let sock = TcpSocket::new_v4().map_err(|_| (480, "Temporarily Unavailable"))?;
    sock.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .map_err(|_| (480, "Temporarily Unavailable"))?;
    let port = sock
        .local_addr()
        .map_err(|_| (480, "Temporarily Unavailable"))?
        .port();
    Ok((
        ClientSocket(sock),
        String::from("127.0.0.1"),
        port,
        false,
        true,
        false,
    ))
}

pub fn first_line(message: &SipMessage) -> String {
    match message {
        SipMessage::Request(line, _, _) => String::from_utf8_lossy(&line.method).into_owned(),
        SipMessage::Response(line, _, _) => line.status_code.to_string(),
        _ => String::from("ping or pong"),
    }
}

pub fn status_code(message: &SipMessage) -> u16 {
    match message {
        SipMessage::Response(line, _, _) => line.status_code,
        _ => 0,
    }
}

pub fn header_value(message: &SipMessage, name: &str) -> String {
    match header::search(message.headers().unwrap(), name.as_bytes(), true) {
        Some(header) => String::from_utf8_lossy(header.get_value()).into_owned(),
        None => String::new(),
    }
}

pub fn body(message: &SipMessage) -> String {
    match message.get_body().as_deref() {
        Some(rust_rcs_core::internet::Body::Raw(raw)) => String::from_utf8_lossy(raw).into_owned(),
        _ => String::new(),
    }
}

/// The To tag of a response
pub fn to_tag(message: &SipMessage) -> String {
    let to = header_value(message, "To");
    match to.split_once(";tag=") {
        Some((_, tag)) => String::from(tag.split(';').next().unwrap_or(tag)),
        None => String::new(),
    }
}

/// The URI of the first Contact
pub fn contact_uri(message: &SipMessage) -> String {
    let contact = header_value(message, "Contact");
    let start = contact.find('<').map_or(0, |i| i + 1);
    let end = contact.find('>').unwrap_or(contact.len());
    String::from(&contact[start..end])
}

/// An MSRP endpoint of the peer, listening on localhost
pub struct MsrpPeer {
    pub listener: TcpListener,
    pub port: u16,
    pub path: String,
}

impl MsrpPeer {
    pub fn listen(rt: &Runtime) -> MsrpPeer {
        let listener = rt
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("a listener");
        let port = listener.local_addr().unwrap().port();
        MsrpPeer {
            listener,
            port,
            path: format!("msrp://127.0.0.1:{}/peer1;tcp", port),
        }
    }

    /// An SDP offer or answer for a chat with this endpoint, which waits for
    /// the client to connect, at the port in a=path, not that in m= (RFC
    /// 4975 section 8.1)
    pub fn sdp(&self, direction: &str) -> String {
        format!(
            "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
c=IN IP4 127.0.0.1\r\n\
t=0 0\r\n\
m=message {} TCP/MSRP *\r\n\
a=accept-types:message/cpim\r\n\
a=accept-wrapped-types:text/plain message/imdn+xml\r\n\
a=path:{}\r\n\
a=setup:passive\r\n\
a={}\r\n",
            9, self.path, direction
        )
    }

    pub fn accept(&self, rt: &Runtime) -> MsrpConnection {
        let (stream, _) = rt
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), self.listener.accept()).await
            })
            .expect("the client to connect for MSRP")
            .unwrap();
        MsrpConnection {
            stream,
            buffer: Vec::new(),
        }
    }
}

pub struct MsrpConnection {
    stream: TcpStream,
    buffer: Vec<u8>,
}

/// An MSRP request or response as read: its first line, headers and body
pub struct MsrpFrame {
    pub first_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MsrpFrame {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn transaction_id(&self) -> &str {
        self.first_line.split(' ').nth(1).unwrap_or("")
    }
}

impl MsrpConnection {
    /// The next MSRP frame, within 5 s
    pub fn next(&mut self, rt: &Runtime) -> MsrpFrame {
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(frame) = self.take_frame() {
                        return frame;
                    }
                    let mut data = [0; 4096];
                    let size = self.stream.read(&mut data).await.unwrap();
                    assert!(size > 0, "the MSRP connection closed");
                    self.buffer.extend_from_slice(&data[..size]);
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "an MSRP frame, having read {:?}",
                    String::from_utf8_lossy(&self.buffer)
                )
            })
        })
    }

    /// The next SEND with something in it, the empty ones that bind the
    /// connection answered 200 on the way
    pub fn next_message(&mut self, rt: &Runtime) -> MsrpFrame {
        loop {
            let frame = self.next(rt);
            if frame.first_line.ends_with(" SEND") && frame.body.is_empty() {
                self.respond(rt, &frame, "200 OK");
                continue;
            }
            return frame;
        }
    }

    fn take_frame(&mut self) -> Option<MsrpFrame> {
        let text = String::from_utf8_lossy(&self.buffer).into_owned();
        let first_end = text.find("\r\n")?;
        let first_line = String::from(&text[..first_end]);
        let transaction_id = String::from(first_line.split(' ').nth(1)?);
        let end_line = format!("-------{}", transaction_id);
        let end = text.find(&end_line)?;
        let after_flag = end + end_line.len() + 1;
        let frame_end = text[after_flag..].find("\r\n")? + after_flag + 2;

        let head_and_body = &text[first_end + 2..end];
        let (head, body) = match head_and_body.find("\r\n\r\n") {
            Some(i) => (&head_and_body[..i], &head_and_body[i + 4..]),
            None => (head_and_body.trim_end_matches("\r\n"), ""),
        };
        let headers = head
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .map(|(n, v)| (String::from(n.trim()), String::from(v.trim())))
            .collect();
        let body = body
            .strip_suffix("\r\n")
            .unwrap_or(body)
            .as_bytes()
            .to_vec();

        self.buffer.drain(..frame_end);
        Some(MsrpFrame {
            first_line,
            headers,
            body,
        })
    }

    /// Answers `request` with `status`
    pub fn respond(&mut self, rt: &Runtime, request: &MsrpFrame, status: &str) {
        let data = format!(
            "MSRP {} {}\r\nTo-Path: {}\r\nFrom-Path: {}\r\n-------{}$\r\n",
            request.transaction_id(),
            status,
            request.header("From-Path").unwrap_or(""),
            request.header("To-Path").unwrap_or(""),
            request.transaction_id()
        );
        rt.block_on(self.stream.write_all(data.as_bytes())).unwrap();
    }

    /// Sends `content` in a CPIM message, as message `message_id`
    pub fn send_text(&mut self, rt: &Runtime, from_path: &str, to_path: &str, content: &str) {
        let cpim = cpim("Content-Type: text/plain;charset=UTF-8\r\n", content);
        self.send_cpim(rt, from_path, to_path, &cpim);
    }

    /// Sends the CPIM message `cpim`
    pub fn send_cpim(&mut self, rt: &Runtime, from_path: &str, to_path: &str, cpim: &str) {
        self.send_content(rt, from_path, to_path, "message/cpim", cpim);
    }

    /// Sends `content` of `content_type`
    pub fn send_content(
        &mut self,
        rt: &Runtime,
        from_path: &str,
        to_path: &str,
        content_type: &str,
        content: &str,
    ) {
        let data = format!(
            "MSRP peer-t1 SEND\r\n\
To-Path: {}\r\n\
From-Path: {}\r\n\
Message-ID: peer-m1\r\n\
Byte-Range: 1-{}/{}\r\n\
Content-Type: {}\r\n\
\r\n\
{}\r\n\
-------peer-t1$\r\n",
            to_path,
            from_path,
            content.len(),
            content.len(),
            content_type,
            content
        );
        rt.block_on(self.stream.write_all(data.as_bytes())).unwrap();
    }
}

/// The text a CPIM message carries, base64 encoded as the client sends it
pub fn cpim_text(cpim: &[u8]) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let cpim = String::from_utf8_lossy(cpim).into_owned();
    let content = cpim.rsplit("\r\n\r\n").next().unwrap_or("");
    match general_purpose::STANDARD.decode(content.trim()) {
        Ok(decoded) => String::from_utf8_lossy(&decoded).into_owned(),
        Err(_) => String::from(content),
    }
}

/// An INVITE from the peer to a 1-to-1 chat, offering `sdp`
pub fn chat_invite(call_id: &str, sdp: &str) -> String {
    format!(
        "INVITE sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: <{}>;tag=peer1\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:+15559876@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"\r\n\
Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"\r\n\
P-Asserted-Identity: <{}>\r\n\
Conversation-ID: conversation-1\r\n\
Contribution-ID: contribution-1\r\n\
Max-Forwards: 70\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        TRANSPORT_ADDRESS,
        call_id,
        PEER,
        IMPU,
        call_id,
        PEER,
        sdp.len(),
        sdp
    )
}

/// An ACK to the 2xx `response` of the client to the peer's INVITE
pub fn ack(response: &SipMessage, call_id: &str) -> String {
    format!(
        "ACK sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKack{}\r\n\
From: <{}>;tag=peer1\r\n\
To: <{}>;tag={}\r\n\
Call-ID: {}\r\n\
CSeq: 1 ACK\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n",
        TRANSPORT_ADDRESS,
        call_id,
        PEER,
        IMPU,
        to_tag(response),
        call_id
    )
}

#[test]
fn a_message_to_a_new_group_returns_and_invites_once() {
    let (client, mut peer) = start(true);

    // the first starts a session, the second waits for it
    let _first = client.send("sip:group1@conf.example.com", RecipientType::Group, "one");
    let _second = client.send("sip:group1@conf.example.com", RecipientType::Group, "two");

    peer.next_request("INVITE");
    peer.silence();
}

#[test]
fn an_invitation_over_a_connection_not_registered_is_refused() {
    let (client, mut peer) = start(false);
    let msrp = MsrpPeer::listen(&client.rt);

    peer.send(&chat_invite("unregistered", &msrp.sdp("sendrecv")));
    let response = peer.next_response();
    assert_eq!(status_code(&response), 480);
}

#[test]
fn a_message_sent_before_the_ack_waits_for_the_session() {
    let (client, mut peer) = start(true);
    let msrp = MsrpPeer::listen(&client.rt);

    peer.send(&chat_invite("early", &msrp.sdp("sendrecv")));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);

    // the session is set up, yet to start
    let result = client.send(PEER, RecipientType::Contact, "before the ACK");

    peer.send(&ack(&ok, "early"));

    let rt = Arc::clone(&client.rt);
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert!(send.first_line.ends_with(" SEND"), "{}", send.first_line);
    assert_eq!(cpim_text(&send.body), "before the ACK");
    connection.respond(&rt, &send, "200 OK");

    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
}

/// An INVITE from `from`, asserted as `asserted`, with `extra` headers
pub fn invite(
    call_id: &str,
    contact: &str,
    asserted: &str,
    accept_contact: &str,
    extra: &str,
    content_type: &str,
    body: &str,
) -> String {
    format!(
        "INVITE sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: <{}>;tag=peer1\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 INVITE\r\n\
Contact: {}\r\n\
Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.{}\"\r\n\
P-Asserted-Identity: <{}>\r\n\
Conversation-ID: conversation-1\r\n\
Contribution-ID: contribution-1\r\n\
{}Max-Forwards: 70\r\n\
Content-Type: {}\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        TRANSPORT_ADDRESS,
        call_id,
        asserted,
        IMPU,
        call_id,
        contact,
        accept_contact,
        asserted,
        extra,
        content_type,
        body.len(),
        body
    )
}

/// The value of `a=name:` in an SDP
fn sdp_attribute(sdp: &str, name: &str) -> Option<String> {
    let prefix = format!("a={}:", name);
    sdp.split("\r\n")
        .find_map(|line| line.strip_prefix(&prefix))
        .map(String::from)
}

/// A request from the peer in the dialog the client's `response` made,
/// the peer having sent the INVITE
fn in_dialog_request(method: &str, seq: u32, response: &SipMessage, call_id: &str) -> String {
    format!(
        "{} {} SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}{}\r\n\
From: <{}>;tag=peer1\r\n\
To: <{}>;tag={}\r\n\
Call-ID: {}\r\n\
CSeq: {} {}\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n",
        method,
        contact_uri(response),
        method.to_lowercase(),
        call_id,
        header_value_uri(response, "From"),
        IMPU,
        to_tag(response),
        call_id,
        seq,
        method
    )
}

/// The URI in a From or To
fn header_value_uri(message: &SipMessage, name: &str) -> String {
    let value = header_value(message, name);
    let start = value.find('<').map_or(0, |i| i + 1);
    let end = value.find('>').unwrap_or(value.len());
    String::from(&value[start..end])
}

/// The peer's answer to the client's `request`
fn answer(request: &SipMessage, status: &str, sdp: Option<&str>) -> String {
    answer_from(
        request,
        status,
        "<sip:+15559876@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        sdp,
    )
}

/// As answer(), from the Contact `contact`
fn answer_from(request: &SipMessage, status: &str, contact: &str, sdp: Option<&str>) -> String {
    let mut data = format!("SIP/2.0 {}\r\n", status);
    for name in ["Via", "From", "Call-ID", "CSeq"] {
        data += &format!("{}: {}\r\n", name, header_value(request, name));
    }
    data += &format!("To: {};tag=peer2\r\n", header_value(request, "To"));
    data += &format!("Contact: {}\r\n", contact);
    match sdp {
        Some(sdp) => {
            data += &format!(
                "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}",
                sdp.len(),
                sdp
            )
        }
        None => data += "Content-Length: 0\r\n\r\n",
    }
    data
}

impl MsrpConnection {
    /// The next MSRP response, the empty SENDs that bind the connection
    /// answered 200 on the way
    pub fn next_response(&mut self, rt: &Runtime) -> MsrpFrame {
        loop {
            let frame = self.next(rt);
            if frame.first_line.ends_with(" SEND") && frame.body.is_empty() {
                self.respond(rt, &frame, "200 OK");
                continue;
            }
            assert!(!frame.first_line.ends_with(" SEND"), "{}", frame.first_line);
            return frame;
        }
    }

    /// Checks that the client sends nothing for a while but the empty SENDs
    /// that bind the connection
    pub fn quiet(&mut self, rt: &Runtime) {
        let sent = rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(500), async {
                loop {
                    if let Some(frame) = self.take_frame() {
                        if !(frame.first_line.ends_with(" SEND") && frame.body.is_empty()) {
                            return frame;
                        }
                        continue;
                    }
                    let mut data = [0; 4096];
                    let size = self.stream.read(&mut data).await.unwrap();
                    assert!(size > 0, "the MSRP connection closed");
                    self.buffer.extend_from_slice(&data[..size]);
                }
            })
            .await
            .ok()
        });
        if let Some(frame) = sent {
            panic!("unexpected: {}", frame.first_line);
        }
    }

    /// Waits for the client to close the connection
    pub fn closed(&mut self, rt: &Runtime) {
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut data = [0; 4096];
                loop {
                    match self.stream.read(&mut data).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            })
            .await
            .expect("the MSRP connection to close")
        })
    }
}

/// A chat the peer started and the client accepted, its MSRP connection up
/// and bound, with the client's 200 and its a=path
fn incoming_chat(
    client: &Client,
    peer: &mut Peer,
    call_id: &str,
) -> (MsrpPeer, MsrpConnection, SipMessage, String) {
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);
    peer.send(&chat_invite(call_id, &msrp.sdp("sendrecv")));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    let our_path = sdp_attribute(&body(&ok), "path").expect("an a=path in the answer");

    peer.send(&ack(&ok, call_id));
    let mut connection = msrp.accept(&rt);

    // bound at once, before anything is sent
    let bind = connection.next(&rt);
    assert!(bind.first_line.ends_with(" SEND"), "{}", bind.first_line);
    assert!(bind.body.is_empty());
    assert_eq!(bind.header("To-Path"), Some(msrp.path.as_str()));
    connection.respond(&rt, &bind, "200 OK");

    (msrp, connection, ok, our_path)
}

#[test]
fn an_incoming_chat_is_answered_with_its_sdp_and_runs_both_ways() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (msrp, mut connection, ok, our_path) = incoming_chat(&client, &mut peer, "both-ways");

    assert_eq!(header_value(&ok, "Content-Type"), "application/sdp");
    let sdp = body(&ok);
    assert!(sdp.contains("m=message "), "{}", sdp);
    assert!(sdp.contains("a=sendrecv"), "{}", sdp);

    // the peer's message reaches the app
    connection.send_text(&rt, &msrp.path, &our_path, "hello");
    let response = connection.next(&rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
    let (contact, content_type, content) = client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("the message given to the app");
    assert_eq!(contact, PEER);
    assert!(content_type.starts_with("text/plain"), "{}", content_type);
    assert_eq!(content, "hello");

    // and the answer goes in the session
    let result = client.send(PEER, RecipientType::Contact, "hi back");
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "hi back");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    peer.silence();
}

#[test]
fn a_deferred_chat_is_answered_receive_only() {
    let (client, mut peer) = start(true);
    let msrp = MsrpPeer::listen(&client.rt);

    peer.send(&invite(
        "deferred",
        "<sip:rcse-standfw@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        "sip:rcse-standfw@example.com",
        "cpm.session",
        &format!("Referred-By: <{}>\r\n", PEER),
        "application/sdp",
        &msrp.sdp("sendonly"),
    ));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert!(body(&ok).contains("a=recvonly"), "{}", body(&ok));
}

#[test]
fn a_bye_ends_the_session_and_the_next_message_starts_another() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (_msrp, mut connection, ok, _) = incoming_chat(&client, &mut peer, "bye");

    peer.send(&in_dialog_request("BYE", 2, &ok, "bye"));
    let response = peer.next_response();
    assert_eq!(status_code(&response), 200);
    connection.closed(&rt);

    let _result = client.send(PEER, RecipientType::Contact, "after the end");
    peer.next_request("INVITE");
}

#[test]
fn a_session_whose_msrp_connection_drops_is_ended_with_a_bye() {
    let (client, mut peer) = start(true);
    let (_msrp, connection, _ok, _) = incoming_chat(&client, &mut peer, "dropped");

    drop(connection);
    let bye = peer.next_request("BYE");
    assert_eq!(header_value(&bye, "Call-ID"), "dropped");
}

#[test]
fn an_outgoing_chat_runs_in_the_session_it_starts() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);

    let first = client.send(PEER, RecipientType::Contact, "first");
    let invite = peer.next_request("INVITE");
    assert!(
        header_value(&invite, "Accept-Contact").contains("oma.cpm.session"),
        "{}",
        header_value(&invite, "Accept-Contact")
    );
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");

    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "first");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        first.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );

    // the next goes in the same session
    let second = client.send(PEER, RecipientType::Contact, "second");
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "second");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        second.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    peer.silence();
}

#[test]
fn a_refused_chat_fails_its_messages_and_the_next_starts_another() {
    let (client, mut peer) = start(true);

    let one = client.send(PEER, RecipientType::Contact, "one");
    let invite = peer.next_request("INVITE");
    let two = client.send(PEER, RecipientType::Contact, "two");
    std::thread::sleep(Duration::from_millis(200));

    peer.send(&answer(&invite, "486 Busy Here", None));
    for result in [one, two] {
        assert_eq!(
            result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
            Ok(486)
        );
    }

    let _three = client.send(PEER, RecipientType::Contact, "three");
    peer.next_request("ACK");
    peer.next_request("INVITE");
}

#[test]
fn a_group_invitation_reaches_the_group_handler() {
    let (client, mut peer) = start(true);
    let msrp = MsrpPeer::listen(&client.rt);

    peer.send(&invite(
        "group",
        "<sip:conf1@conf.example.com;transport=tcp>;isfocus;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        "sip:conf1@conf.example.com",
        "cpm.session",
        "Subject: Friends\r\nReferred-By: \"Alice\" <sip:+15550001@example.com>\r\n",
        "application/sdp",
        &msrp.sdp("sendrecv"),
    ));
    assert_eq!(
        client.group_invites.recv_timeout(Duration::from_secs(5)),
        Ok((String::from("Friends"), String::from("Alice")))
    );
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        next_group_event(&client),
        format!(
            "invited {} conversation-1 Friends sip:+15550001@example.com Alice accepted",
            GROUP
        )
    );
}

/// A CPIM message from the peer to the client, its content as given
fn cpim(content_headers: &str, content: &str) -> String {
    cpim_with("", content_headers, content)
}

/// As cpim(), with the CPIM headers `cpim_headers` too
fn cpim_with(cpim_headers: &str, content_headers: &str, content: &str) -> String {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-18T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: peer-message-1\r\n\
{}\
\r\n\
{}\r\n\
{}",
        PEER, IMPU, cpim_headers, content_headers, content
    )
}

#[test]
fn a_large_message_comes_in_its_session() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);

    let sip_cpim = cpim("Content-Type: text/plain\r\n", "");
    let sdp = msrp.sdp("sendonly");
    let multipart = format!(
        "--b1\r\nContent-Type: message/cpim\r\n\r\n{}\r\n--b1\r\nContent-Type: application/sdp\r\n\r\n{}\r\n--b1--\r\n",
        sip_cpim, sdp
    );
    peer.send(&invite(
        "large",
        "<sip:+15559876@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg\"",
        PEER,
        "cpm.largemsg",
        "",
        "multipart/mixed;boundary=b1",
        &multipart,
    ));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert!(
        header_value(&ok, "Contact").contains(IMPU),
        "{}",
        header_value(&ok, "Contact")
    );
    let answer_sdp = body(&ok);
    assert!(answer_sdp.contains("a=recvonly"), "{}", answer_sdp);
    let our_path = sdp_attribute(&answer_sdp, "path").expect("an a=path in the answer");

    peer.send(&ack(&ok, "large"));
    let mut connection = msrp.accept(&rt);
    let bind = connection.next(&rt);
    assert!(bind.body.is_empty(), "the connection bound first");
    connection.respond(&rt, &bind, "200 OK");

    connection.send_text(&rt, &msrp.path, &our_path, "a large message");
    let response = connection.next(&rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
    let (_, _, content) = client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("the message given to the app");
    assert_eq!(content, "a large message");

    // ended by the sender
    peer.send(&in_dialog_request("BYE", 2, &ok, "large"));
    assert_eq!(status_code(&peer.next_response()), 200);
    connection.closed(&rt);
}

#[test]
fn a_large_message_sent_is_reported_once_and_its_session_ended() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);

    let (result_tx, result) = mpsc::channel();
    client.standalone.send_large_mode_message(
        "text/plain",
        "a large message",
        "large-1",
        PEER,
        &RecipientType::Contact,
        PEER,
        move |status_code, _| {
            let _ = result_tx.send(status_code);
        },
        &client.core,
        &rt,
    );

    let invite = peer.next_request("INVITE");
    for name in ["Conversation-ID", "Contribution-ID"] {
        assert!(!header_value(&invite, name).is_empty(), "{}", name);
    }
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("recvonly"))));
    peer.next_request("ACK");

    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "a large message");
    // the message has the ID given, as the INVITE told
    let cpim = CPIMMessage::try_from(&Body::construct_message(&send.body).unwrap()).unwrap();
    assert_eq!(
        id_and_dispositions(&cpim),
        (String::from("large-1"), DELIVERY_AND_DISPLAY)
    );
    assert!(
        String::from_utf8_lossy(&body_data(&invite)).contains("imdn.Message-ID: large-1\r\n"),
        "{}",
        String::from_utf8_lossy(&body_data(&invite))
    );
    connection.respond(&rt, &send, "200 OK");

    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));
    peer.next_request("BYE");
    assert!(result.recv_timeout(Duration::from_millis(500)).is_err());
}

/// A pager-mode MESSAGE from the peer carrying `body`
fn pager_message(call_id: &str, content_type: &str, body: &str) -> String {
    pager_message_of(call_id, "cpm.msg", content_type, body)
}

/// A MESSAGE from the peer of the CPM service `service`, as cpm.msg,
/// carrying `body`
fn pager_message_of(call_id: &str, service: &str, content_type: &str, body: &str) -> String {
    format!(
        "MESSAGE sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: <{}>;tag=pager1\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 MESSAGE\r\n\
P-Asserted-Identity: <{}>\r\n\
Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.{}\"\r\n\
Max-Forwards: 70\r\n\
Content-Type: {}\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        TRANSPORT_ADDRESS,
        call_id,
        PEER,
        IMPU,
        call_id,
        PEER,
        service,
        content_type,
        body.len(),
        body
    )
}

#[test]
fn a_pager_message_is_read_in_a_multipart_body_and_in_base64_lines() {
    let (client, mut peer) = start(true);

    // the CPIM a part of a multipart body, as from an exploder
    let cpim_part = cpim("Content-Type: text/plain\r\n", "from a list");
    let multipart = format!(
        "--b1\r\nContent-Type: message/cpim\r\n\r\n{}\r\n--b1\r\nContent-Type: text/plain\r\n\r\nother\r\n--b1--\r\n",
        cpim_part
    );
    peer.send(&pager_message(
        "multipart",
        "multipart/mixed;boundary=b1",
        &multipart,
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("from a list"))
    );

    // base64 in lines, as MIME writes it
    let wrapped = "YSBtZXNzYWdlIGluIGJh\r\nc2U2NCBsaW5lcw==";
    peer.send(&pager_message(
        "wrapped",
        "message/cpim",
        &cpim(
            "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n",
            wrapped,
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("a message in base64 lines"))
    );

    // not base64 at all: refused, not given to the app
    peer.send(&pager_message(
        "not-base64",
        "message/cpim",
        &cpim(
            "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n",
            "!!! not base64 !!!",
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 400);
    assert!(client
        .received
        .recv_timeout(Duration::from_millis(500))
        .is_err());
}

/// A BYE from the peer in the dialog the client's `invite` made, the peer
/// having answered it with the To tag peer2
fn bye_to_our_invite(invite: &SipMessage) -> String {
    format!(
        "BYE {} SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKbye2\r\n\
From: {};tag=peer2\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: 1 BYE\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n",
        contact_uri(invite),
        header_value(invite, "To"),
        header_value(invite, "From"),
        header_value(invite, "Call-ID")
    )
}

#[test]
fn an_outgoing_chat_ended_by_a_bye_is_started_again() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);

    let first = client.send(PEER, RecipientType::Contact, "first");
    let invite = peer.next_request("INVITE");
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        first.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );

    peer.send(&bye_to_our_invite(&invite));
    assert_eq!(status_code(&peer.next_response()), 200);
    connection.closed(&rt);

    let _again = client.send(PEER, RecipientType::Contact, "again");
    let invite_again = peer.next_request("INVITE");
    assert_ne!(
        header_value(&invite_again, "Call-ID"),
        header_value(&invite, "Call-ID")
    );
}

/// The body of `message`, as sent
fn body_data(message: &SipMessage) -> Vec<u8> {
    use std::io::Read;

    let mut data = Vec::new();
    if let Some(body) = message.get_body() {
        body.reader().unwrap().read_to_end(&mut data).unwrap();
    }
    data
}

/// The CPIM message `message` carries
fn cpim_of(message: &SipMessage) -> CPIMMessage {
    CPIMMessage::try_from(&Body::construct_message(&body_data(message)).unwrap()).unwrap()
}

pub fn request_uri(message: &SipMessage) -> String {
    match message {
        SipMessage::Request(line, _, _) => String::from_utf8_lossy(&line.uri).into_owned(),
        _ => panic!("not a request"),
    }
}

/// The ID and dispositions asked for of the CPIM message `cpim`
fn id_and_dispositions(cpim: &CPIMMessage) -> (String, Dispositions) {
    let info = cpim.get_info().unwrap();
    (
        String::from_utf8_lossy(info.imdn_message_id).into_owned(),
        info.disposition_notification
            .map_or(Dispositions::default(), Dispositions::parse),
    )
}

const DELIVERY_AND_DISPLAY: Dispositions = Dispositions {
    positive_delivery: true,
    negative_delivery: false,
    display: true,
    processing: false,
};

#[test]
fn a_message_sent_has_the_id_given_and_asks_to_be_told_of_its_delivery_and_display() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);

    // in a chat
    let msrp = MsrpPeer::listen(&rt);
    let _result = client.send_with_id(PEER, RecipientType::Contact, "chat", "chat-message-1");
    let invite = peer.next_request("INVITE");
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    let cpim = CPIMMessage::try_from(&Body::construct_message(&send.body).unwrap()).unwrap();
    assert_eq!(
        id_and_dispositions(&cpim),
        (String::from("chat-message-1"), DELIVERY_AND_DISPLAY)
    );
    connection.respond(&rt, &send, "200 OK");

    // in pager mode, and an is-composing indication asking for nothing
    for (message_type, message_id, dispositions) in [
        ("text/plain", "pager-message-1", DELIVERY_AND_DISPLAY),
        (
            "application/im-iscomposing+xml",
            "composing-1",
            Dispositions::default(),
        ),
    ] {
        standalone_messaging::send_message(
            message_type,
            "<isComposing/>",
            message_id,
            PEER,
            &RecipientType::Contact,
            PEER,
            |_, _| {},
            Arc::clone(&client.core),
            &client.transport,
            IMPU,
            &rt,
        );
        let message = peer.next_request("MESSAGE");
        assert_eq!(
            id_and_dispositions(&cpim_of(&message)),
            (String::from(message_id), dispositions)
        );
        peer.send(&answer(&message, "200 OK", None));
    }
}

/// The notification the MESSAGE `receipt` from the client carries, it
/// having been sent to the peer by `service`
fn notification(receipt: &SipMessage, service: &str) -> Imdn {
    assert_eq!(request_uri(receipt), PEER);
    assert_eq!(header_value(receipt, "To"), format!("<{}>", PEER));
    assert_eq!(
        header_value(receipt, "Accept-Contact"),
        format!(
            "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.{}\"",
            service
        )
    );
    assert_eq!(
        header_value(receipt, "P-Preferred-Service"),
        format!("urn:urn-7:3gpp-service.ims.icsi.oma.{}", service)
    );
    assert_eq!(header_value(receipt, "Content-Type"), "message/cpim");

    let cpim = cpim_of(receipt);
    assert!(cpim.contains_imdn());
    let info = cpim.get_info().unwrap();
    assert_eq!(
        (info.from, info.to),
        (
            format!("<{}>", IMPU).as_bytes(),
            format!("<{}>", PEER).as_bytes()
        )
    );
    let (message_id, dispositions) = id_and_dispositions(&cpim);
    assert!(!message_id.is_empty() && message_id != "peer-message-1");
    assert_eq!(dispositions, Dispositions::default(), "it asks for nothing");

    let data = body_data(receipt);
    let data = String::from_utf8_lossy(&data);
    let xml = data.rsplit("\r\n\r\n").next().unwrap();
    Imdn::from_xml(xml.as_bytes()).expect("an IMDN document as it is")
}

const ASKING: &str = "imdn.Disposition-Notification: positive-delivery, display\r\n";

#[test]
fn a_standalone_message_asking_to_be_told_of_its_delivery_is() {
    let (client, mut peer) = start(true);

    peer.send(&pager_message(
        "asking",
        "message/cpim",
        &cpim_with(ASKING, "Content-Type: text/plain\r\n", "tell me"),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    let receipt = peer.next_request("MESSAGE");
    assert_eq!(
        notification(&receipt, "cpm.msg"),
        Imdn {
            message_id: String::from("peer-message-1"),
            datetime: String::from("2026-10-18T12:00:00.000Z"),
            recipient_uri: None,
            original_recipient_uri: None,
            notification: Notification::Delivery,
            status: Status::Delivered,
        }
    );
    peer.send(&answer(&receipt, "200 OK", None));

    // and of its display, by what was noted of it
    let notice = client
        .received_messages
        .displayed("peer-message-1")
        .unwrap();
    assert_eq!(notice.group, None, "standalone, not in a group");
    super::imdn::send_imdn(
        &notice.xml,
        &notice.sender_uri,
        notice.service,
        &client.core.get_transaction_manager(),
        &client.transport,
        IMPU,
        |_, _| {},
        &client.rt,
    );
    let receipt = peer.next_request("MESSAGE");
    let imdn = notification(&receipt, "cpm.msg");
    assert_eq!(
        (imdn.message_id.as_str(), imdn.notification, imdn.status),
        ("peer-message-1", Notification::Display, Status::Displayed)
    );

    // one not asking is not told of
    peer.send(&pager_message(
        "not-asking",
        "message/cpim",
        &cpim("Content-Type: text/plain\r\n", "say nothing"),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    peer.silence();
}

#[test]
fn a_chat_message_asking_to_be_told_of_its_delivery_is_by_the_chat_service() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (msrp, mut connection, _ok, our_path) = incoming_chat(&client, &mut peer, "asking");

    connection.send_cpim(
        &rt,
        &msrp.path,
        &our_path,
        &cpim_with(ASKING, "Content-Type: text/plain\r\n", "tell me"),
    );
    let response = connection.next(&rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );

    let receipt = peer.next_request("MESSAGE");
    let imdn = notification(&receipt, "cpm.session");
    assert_eq!(
        (imdn.message_id.as_str(), imdn.notification, imdn.status),
        ("peer-message-1", Notification::Delivery, Status::Delivered)
    );
}

#[test]
fn a_notification_sent_is_taken_as_one_and_not_told_of() {
    let (client, mut peer) = start(true);

    peer.send(&pager_message(
        "asking",
        "message/cpim",
        &cpim_with(ASKING, "Content-Type: text/plain\r\n", "tell me"),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    let _ = client.received.recv_timeout(Duration::from_secs(5));
    let receipt = peer.next_request("MESSAGE");
    peer.send(&answer(&receipt, "200 OK", None));

    // the client's receipt, sent back to it by the chat service, as a
    // notification of a chat message would come
    let receipt_cpim = String::from_utf8(body_data(&receipt)).unwrap();
    for service in ["cpm.msg", "cpm.session"] {
        peer.send(&pager_message_of(
            service,
            service,
            "message/cpim",
            &receipt_cpim,
        ));
        assert_eq!(status_code(&peer.next_response()), 200, "{}", service);
        let (_, content_type, content) = client
            .received
            .recv_timeout(Duration::from_secs(5))
            .expect("the notification given to the app");
        assert!(
            content_type.starts_with("message/imdn+xml"),
            "{}",
            content_type
        );
        assert!(Imdn::from_xml(content.as_bytes()).is_some(), "{}", content);
    }
    peer.silence();
}

#[test]
fn an_is_composing_indication_goes_as_it_is_in_a_one_to_one_chat() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (_msrp, mut connection, _ok, _) = incoming_chat(&client, &mut peer, "composing");

    for (active, state) in [
        (true, "<state>active</state>"),
        (false, "<state>idle</state>"),
    ] {
        let (result_tx, result) = mpsc::channel();
        let result_tx = std::sync::Mutex::new(result_tx);
        assert!(client.sessions.send_is_composing(
            PEER,
            &RecipientType::Contact,
            active,
            move |status_code, _| {
                let _ = result_tx.lock().unwrap().send(status_code);
            },
            &rt,
        ));
        let send = connection.next_message(&rt);
        assert_eq!(
            send.header("Content-Type"),
            Some("application/im-iscomposing+xml")
        );
        let body = String::from_utf8_lossy(&send.body);
        assert!(body.contains(state), "{}", body);
        assert!(
            body.contains("xmlns=\"urn:ietf:params:xml:ns:im-iscomposing\""),
            "{}",
            body
        );
        connection.respond(&rt, &send, "200 OK");
        assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));
    }
}

#[test]
fn no_session_is_started_for_an_is_composing_indication() {
    let (client, mut peer) = start(true);
    assert!(!client.sessions.send_is_composing(
        PEER,
        &RecipientType::Contact,
        true,
        |_, _| {},
        &client.rt
    ));
    peer.silence();
}

#[test]
fn an_is_composing_indication_received_is_given_to_the_app_and_not_acknowledged() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (msrp, mut connection, _ok, our_path) = incoming_chat(&client, &mut peer, "composed");

    let document = super::is_composing_document(true);
    connection.send_content(
        &rt,
        &msrp.path,
        &our_path,
        "application/im-iscomposing+xml",
        &document,
    );
    let response = connection.next(&rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
    assert_eq!(
        client.received.recv_timeout(Duration::from_secs(5)),
        Ok((
            String::from(PEER),
            String::from("application/im-iscomposing+xml"),
            document
        ))
    );
    peer.silence();
}

#[test]
fn a_chat_session_ended_on_request_is_ended_with_a_bye() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (_msrp, mut connection, _ok, _) = incoming_chat(&client, &mut peer, "ended");

    assert!(client.sessions.end_session(PEER));
    let bye = peer.next_request("BYE");
    assert_eq!(header_value(&bye, "Call-ID"), "ended");
    connection.closed(&rt);

    assert!(!client.sessions.end_session(PEER), "it ended already");
}

const FACTORY: &str = "sip:conference-factory@conf.example.com";
const GROUP: &str = "sip:conf1@conf.example.com";

/// A group chat the client started with two participants, its MSRP
/// connection up, with the INVITE and the SUBSCRIBE to its conference
/// events, answered
fn new_group(client: &Client, peer: &mut Peer) -> (MsrpConnection, SipMessage, SipMessage, String) {
    new_group_with(client, peer, "")
}

/// As new_group(), the focus answering with the headers `extra` too
fn new_group_with(
    client: &Client,
    peer: &mut Peer,
    extra: &str,
) -> (MsrpConnection, SipMessage, SipMessage, String) {
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);

    let (started_tx, started) = mpsc::channel();
    client.sessions.create_group_chat(
        FACTORY,
        &[
            String::from("sip:+15550001@example.com"),
            String::from("tel:+15550002"),
        ],
        Some("Friends"),
        move |status_code, _, conference_uri| {
            let _ = started_tx.send((status_code, conference_uri));
        },
        &client.core,
        &rt,
    );

    let invite = peer.next_request("INVITE");
    // the focus asserting an identity other than its URI
    let ok = answer_from(
        &invite,
        "200 OK",
        &format!(
            "<{}>;isfocus;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
            GROUP
        ),
        Some(&msrp.sdp("sendrecv")),
    )
    .replacen(
        "Contact:",
        &format!(
            "P-Asserted-Identity: <sip:focus@conf.example.com>\r\n{}Contact:",
            extra
        ),
        1,
    );
    peer.send(&ok);
    // the ACK, and the SUBSCRIBE once the session starts, in whatever order
    // the transport takes them
    let subscribe = next_requests(peer, &["ACK", "SUBSCRIBE"]).pop().unwrap();
    let connection = msrp.accept(&rt);

    assert_eq!(
        started.recv_timeout(Duration::from_secs(5)),
        Ok((200, Some(String::from(GROUP)))),
        "the group known by its focus"
    );

    peer.send(
        &answer_from(&subscribe, "200 OK", &format!("<{}>", GROUP), None).replacen(
            "Contact:",
            "Expires: 3600\r\nContact:",
            1,
        ),
    );

    (connection, invite, subscribe, msrp.path)
}

/// The requests `methods` from the client, in whatever order
fn next_requests(peer: &mut Peer, methods: &[&str]) -> Vec<SipMessage> {
    let mut requests: Vec<SipMessage> = (0..methods.len()).map(|_| peer.next()).collect();
    let mut sent: Vec<String> = requests.iter().map(first_line).collect();
    sent.sort();
    let mut expected: Vec<String> = methods.iter().map(|m| String::from(*m)).collect();
    expected.sort();
    assert_eq!(sent, expected);
    requests.sort_by_key(|r| methods.iter().position(|m| *m == first_line(r)));
    requests
}

/// A NOTIFY from the focus, in the subscription `subscribe` made, of the
/// conference-info `document`
fn conference_notify(subscribe: &SipMessage, seq: u32, document: &str) -> String {
    format!(
        "NOTIFY {} SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKnotify{}\r\n\
From: <{}>;tag=peer2\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {} NOTIFY\r\n\
Max-Forwards: 70\r\n\
Contact: <{}>\r\n\
Event: conference\r\n\
Subscription-State: active;expires=3600\r\n\
Content-Type: application/conference-info+xml\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        contact_uri(subscribe),
        seq,
        GROUP,
        header_value(subscribe, "From"),
        header_value(subscribe, "Call-ID"),
        seq,
        GROUP,
        document.len(),
        document
    )
}

/// The next event the app is told of a group chat
fn next_group_event(client: &Client) -> String {
    client
        .group_events
        .recv_timeout(Duration::from_secs(5))
        .expect("an event of the group chat")
}

#[test]
fn a_group_chat_is_started_through_the_factory_with_its_participants() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, invite, _subscribe, _) = new_group(&client, &mut peer);

    assert_eq!(request_uri(&invite), FACTORY);
    assert_eq!(header_value(&invite, "To"), format!("<{}>", FACTORY));
    assert_eq!(header_value(&invite, "Require"), "recipient-list-invite");
    assert_eq!(header_value(&invite, "Subject"), "Friends");
    assert!(header_value(&invite, "Content-Type").starts_with("multipart/mixed; boundary="));
    let body = String::from_utf8_lossy(&body_data(&invite)).into_owned();
    for part in [
        "Content-Type: application/sdp",
        "m=message ",
        "Content-Type: application/resource-lists+xml",
        "Content-Disposition: recipient-list",
        "<entry uri=\"sip:+15550001@example.com\" cp:copyControl=\"to\"/>",
        "<entry uri=\"tel:+15550002\" cp:copyControl=\"to\"/>",
    ] {
        assert!(body.contains(part), "{} in {}", part, body);
    }

    // a message to the group goes in its session
    let result = client.send(GROUP, RecipientType::Group, "hello all");
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "hello all");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );

    // and an is-composing indication, in a CPIM message for the focus to
    // know whose it is
    assert!(client
        .sessions
        .send_is_composing(GROUP, &RecipientType::Group, true, |_, _| {}, &rt));
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    let cpim = String::from_utf8_lossy(&send.body).into_owned();
    assert!(
        cpim.contains("Content-Type: application/im-iscomposing+xml"),
        "{}",
        cpim
    );
    assert!(!cpim.contains("Disposition-Notification"), "{}", cpim);
    connection.respond(&rt, &send, "200 OK");

    // the factory is not the group
    assert!(!client.sessions.has_session_with(FACTORY));

    // the session ended on request; the subscription, which no NOTIFY
    // started, has nothing to end
    let dialogs = || client.core.get_ongoing_dialogs().lock().unwrap().len();
    let before = dialogs();
    assert!(client.sessions.end_session(GROUP));
    peer.next_request("BYE");
    connection.closed(&rt);

    // and the dialog of the session goes once nothing holds it
    let gone = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        dialogs() == before - 1
    });
    assert!(gone, "the dialog of the session went");
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
    assert_eq!(next_group_event(&client), format!("left {}", GROUP));
}

#[test]
fn a_group_chat_the_factory_refuses_is_reported_and_not_known() {
    let (client, mut peer) = start(true);

    let (started_tx, started) = mpsc::channel();
    client.sessions.create_group_chat(
        FACTORY,
        &[String::from("sip:+15550001@example.com")],
        None,
        move |status_code, _, conference_uri| {
            let _ = started_tx.send((status_code, conference_uri));
        },
        &client.core,
        &client.rt,
    );
    let invite = peer.next_request("INVITE");
    assert_eq!(header_value(&invite, "Subject"), "", "no subject");
    peer.send(&answer(&invite, "403 Forbidden", None));
    assert_eq!(
        started.recv_timeout(Duration::from_secs(5)),
        Ok((403, None))
    );
    peer.next_request("ACK");

    // the factory is no one to send to in its session
    assert!(!client.sessions.has_session_with(FACTORY));
}

/// The encryption of group chats as the tests script it: the CPIM message it
/// prepares for each, if any, and what it is asked and given
#[derive(Default)]
struct ScriptedEncryption {
    cpim: Option<Vec<u8>>,
    /// Whether it joins the groups invited to
    joining: bool,
    /// The Conversation-ID, from, to and participants of each prepared
    prepared: std::sync::Mutex<Vec<(String, String, String, Vec<String>)>>,
    /// The Conversation-ID and server message of each group to join
    joined: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    /// The CPIM message it prepares for each addition, if any
    adding: Option<Vec<u8>>,
    /// The Conversation-ID, from, to and participants of each addition
    added: std::sync::Mutex<Vec<(String, String, String, Vec<String>)>>,
    /// The Conversation-ID of each Commit let go of, and whether a refusal
    /// of it was to follow
    discarded: std::sync::Mutex<Vec<(String, bool)>>,
    /// The CPIM message it prepares for each removal, if any
    removing: Option<Vec<u8>>,
    /// The Conversation-ID, from, to and participant of each removal
    removed: std::sync::Mutex<Vec<(String, String, String, String)>>,
    /// The CPIM message it prepares for leaving, if any
    leaving: Option<Vec<u8>>,
    /// What it waits for before preparing it, if anything
    leave_held: Option<Arc<tokio::sync::Notify>>,
    /// Whether what the focus sends carries Proposals
    proposing: bool,
    /// Whether what the focus sends moves its groups to unencrypted
    ending_by_focus: bool,
    /// The CPIM message it prepares for committing leaves, if any
    committing: Option<Vec<u8>>,
    /// The Conversation-ID, from and to of each commit of leaves
    committed: std::sync::Mutex<Vec<(String, String, String)>>,
    /// The CPIM message it prepares for a removal by the server, if any
    removing_for_server: Option<Vec<u8>>,
    /// The Conversation-ID, from, to and participant of each removal by the
    /// server
    removed_for_server: std::sync::Mutex<Vec<(String, String, String, String)>>,
    /// Whether its groups are to be self-healed, until one is
    out_of_step: std::sync::atomic::AtomicBool,
    /// What it asks the focus with each INFO when self-healing: its
    /// Info-Package and body
    pulling: Vec<(&'static [u8], Option<Vec<u8>>)>,
    /// The CPIM message it sends once healed, if any
    healing: Option<Vec<u8>>,
    /// The Conversation-ID, from and to of each self-healing, and the
    /// answers of the focus
    healed: Arc<std::sync::Mutex<Vec<(String, String, String, Vec<Option<(u16, Vec<u8>)>>)>>>,
    /// Whether a new Era of its groups is due, until one is prepared
    era_due: std::sync::atomic::AtomicBool,
    /// The CPIM message it prepares for a new Era, if any
    next_era: Option<Vec<u8>>,
    /// The Conversation-ID, from and to of each new Era prepared, and how
    /// the focus answered the GroupInfo pull
    eras: Arc<std::sync::Mutex<Vec<(String, String, String, Option<(u16, Vec<u8>)>)>>>,
    /// The Conversation-ID of each new Era the focus refused, and how
    refused_eras: std::sync::Mutex<Vec<(String, u16)>>,
    /// Whether what the focus sends moves its groups back to encrypted
    resuming_by_focus: bool,
    /// Whether its groups are to be moved back to encrypted, until one is
    upgrade_wanted: std::sync::atomic::AtomicBool,
    /// The CPIM message it prepares for moving a group back to encrypted,
    /// if any
    upgrading: Option<Vec<u8>>,
    /// Whether it does so with an Era for an INVITE restarting the group
    upgrading_by_restart: bool,
    /// Whether self-healing moves its groups to unencrypted, or back
    healing_flips: bool,
    /// Whether self-healing did
    flipped: Arc<std::sync::atomic::AtomicBool>,
    /// The Conversation-ID, from, to and participants of each move back to
    /// encrypted
    upgraded: std::sync::Mutex<Vec<(String, String, String, Vec<String>)>>,
    /// The Conversation-ID of each group whose membership changed
    memberships_changed: std::sync::Mutex<Vec<String>>,
    /// The Conversation-ID, from and to of each leave
    left: std::sync::Mutex<Vec<(String, String, String)>>,
    server_messages: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    /// Whether the IMDNs it is given refuse a control message of the client
    refusing: bool,
    /// Whether the IMDNs it is given tell a recipient cannot decrypt
    unavailable: bool,
    /// The CPIM message it prepares for moving to unencrypted, if any
    ending: Option<Vec<u8>>,
    /// The Conversation-ID, from, to and reason of each move to unencrypted
    ended: std::sync::Mutex<Vec<(String, String, String, EndReason)>>,
    /// Whether its groups were moved to unencrypted
    unencrypted: bool,
    /// Whether a key update is due in its groups
    keys_due: bool,
    /// The CPIM message it prepares for updating keys, if any
    updating: Option<Vec<u8>>,
    /// The Conversation-ID, from and to of each key update
    updated: std::sync::Mutex<Vec<(String, String, String)>>,
    /// The Conversation-ID and IMDN of each IMDN received in its groups
    imdns: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    abandoned: std::sync::Mutex<Vec<String>>,
    /// The groups it encrypts
    encrypting: Vec<String>,
    /// What it encrypts the messages of those as, if it can
    ciphertext: Option<String>,
    /// The Conversation-ID and CPIM message of each message to encrypt
    encrypted: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    /// The CPIM message it decrypts the encrypted messages to, if it can
    plaintext: Option<String>,
    /// What it signs the notifications of those as, if it can
    signature: Option<String>,
    /// The Conversation-ID and CPIM message of each notification to sign
    signed: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    /// Whether the notifications received in its groups are for the app
    verifying: bool,
    /// Whether they are not signed
    unsigned: bool,
    /// The Conversation-ID, CPIM From and IMDN of each notification to check
    verified: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
    /// The Conversation-ID, CPIM From and Message-ID, and content of each
    /// message to decrypt
    decrypted: std::sync::Mutex<Vec<(String, String, String, Vec<u8>)>>,
    /// The negative deliveries of messages not decrypted it gives, once
    failing_to_decrypt: std::sync::Mutex<Vec<FailedToDecrypt>>,
    /// The Conversation-ID each time it is asked for those
    asked_failed: std::sync::Mutex<Vec<String>>,
}

impl GroupEncryption for ScriptedEncryption {
    fn prepare(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.prepared
            .lock()
            .unwrap()
            .push((conversation_id, from, to, participants));
        let cpim = self.cpim.clone();
        Box::pin(async move { cpim })
    }

    fn prepare_add(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.added
            .lock()
            .unwrap()
            .push((conversation_id, from, to, participants));
        let cpim = self.adding.clone();
        Box::pin(async move { cpim })
    }

    fn prepare_remove(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.removed
            .lock()
            .unwrap()
            .push((conversation_id, from, to, participant));
        let cpim = self.removing.clone();
        Box::pin(async move { cpim })
    }

    fn prepare_leave(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.left.lock().unwrap().push((conversation_id, from, to));
        let cpim = self.leaving.clone();
        let held = self.leave_held.clone();
        Box::pin(async move {
            if let Some(held) = held {
                held.notified().await;
            }
            cpim
        })
    }

    fn commit_leaves(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.committed
            .lock()
            .unwrap()
            .push((conversation_id, from, to));
        let cpim = self.committing.clone();
        Box::pin(async move { cpim })
    }

    fn remove_for_server(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.removed_for_server
            .lock()
            .unwrap()
            .push((conversation_id, from, to, participant));
        let cpim = self.removing_for_server.clone();
        Box::pin(async move { cpim })
    }

    fn discard(&self, conversation_id: &str, refusal_follows: bool) {
        self.discarded
            .lock()
            .unwrap()
            .push((String::from(conversation_id), refusal_follows));
    }

    fn join(&self, conversation_id: &str, server_message: &[u8]) -> bool {
        self.joined
            .lock()
            .unwrap()
            .push((String::from(conversation_id), server_message.to_vec()));
        self.joining
    }

    fn on_server_message(&self, conversation_id: &str, body: &[u8]) -> Taken {
        self.server_messages
            .lock()
            .unwrap()
            .push((String::from(conversation_id), body.to_vec()));
        Taken {
            proposals: self.proposing,
            encryption_ended: self.ending_by_focus,
            encryption_resumed: self.resuming_by_focus,
        }
    }

    fn on_imdn(&self, conversation_id: &str, imdn: &[u8]) -> ImdnTold {
        self.imdns
            .lock()
            .unwrap()
            .push((String::from(conversation_id), imdn.to_vec()));
        if self.refusing {
            ImdnTold::Refusal
        } else if self.unavailable {
            ImdnTold::EncryptionNotAvailable
        } else {
            ImdnTold::Nothing
        }
    }

    fn end_encryption(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        reason: EndReason,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.ended
            .lock()
            .unwrap()
            .push((conversation_id, from, to, reason));
        let cpim = self.ending.clone();
        Box::pin(async move { cpim })
    }

    fn key_update_due(&self, _conversation_id: &str) -> bool {
        self.keys_due
    }

    fn update_keys(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.updated
            .lock()
            .unwrap()
            .push((conversation_id, from, to));
        let cpim = self.updating.clone();
        Box::pin(async move { cpim })
    }

    fn abandon(&self, conversation_id: &str) {
        self.abandoned
            .lock()
            .unwrap()
            .push(String::from(conversation_id));
    }

    fn needs_healing(&self, _conversation_id: &str) -> bool {
        self.out_of_step
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    fn heal(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        pull: GroupInfoPull,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        let pulling = self.pulling.clone();
        let cpim = self.healing.clone();
        let healed = Arc::clone(&self.healed);
        let flipping = self.healing_flips.then(|| Arc::clone(&self.flipped));
        Box::pin(async move {
            let mut answers = Vec::new();
            for (package, body) in pulling {
                answers.push(pull(package, body).await);
            }
            healed
                .lock()
                .unwrap()
                .push((conversation_id, from, to, answers));
            if let Some(flipped) = flipping {
                flipped.store(true, Ordering::SeqCst);
            }
            cpim
        })
    }

    fn new_era_due(&self, _conversation_id: &str) -> bool {
        self.era_due.load(Ordering::SeqCst)
    }

    fn prepare_next_era(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        pull: GroupInfoPull,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.era_due.store(false, Ordering::SeqCst);
        let cpim = self.next_era.clone();
        let eras = Arc::clone(&self.eras);
        Box::pin(async move {
            let answer = pull(b"MLS-Group-Info-Pull", None).await;
            eras.lock()
                .unwrap()
                .push((conversation_id, from, to, answer));
            cpim
        })
    }

    fn era_refused(&self, conversation_id: &str, status_code: u16) {
        self.refused_eras
            .lock()
            .unwrap()
            .push((String::from(conversation_id), status_code));
    }

    fn upgrade_due(&self, _: &str) -> bool {
        self.upgrade_wanted.load(Ordering::SeqCst)
    }

    fn membership_changed(&self, conversation_id: &str) {
        self.memberships_changed
            .lock()
            .unwrap()
            .push(String::from(conversation_id));
    }

    fn upgrade(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Upgrade>> {
        self.upgrade_wanted.store(false, Ordering::SeqCst);
        self.upgraded
            .lock()
            .unwrap()
            .push((conversation_id, from, to, participants));
        let upgrade = self
            .upgrading
            .clone()
            .map(|cpim| match self.upgrading_by_restart {
                true => Upgrade::Restart(cpim),
                false => Upgrade::InSession(cpim),
            });
        Box::pin(async move { upgrade })
    }

    fn encrypts(&self, conversation_id: &str) -> bool {
        self.encrypting.iter().any(|id| id == conversation_id)
    }

    fn encryption_ended(&self, _conversation_id: &str) -> bool {
        self.unencrypted != self.flipped.load(Ordering::SeqCst)
    }

    fn encrypt(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Sealed> {
        self.encrypted
            .lock()
            .unwrap()
            .push((String::from(conversation_id), cpim.to_vec()));
        let sealed = match &self.ciphertext {
            _ if self.unencrypted => Sealed::Unencrypted,
            Some(ciphertext) => Sealed::Encrypted(ciphertext.clone().into_bytes()),
            None => Sealed::Failed,
        };
        Box::pin(async move { sealed })
    }

    fn sign(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.signed
            .lock()
            .unwrap()
            .push((String::from(conversation_id), cpim.to_vec()));
        let signature = self.signature.clone().map(String::into_bytes);
        Box::pin(async move { signature })
    }

    fn verify(&self, conversation_id: &str, cpim_info: &CPIMInfo, imdn: &[u8]) -> Verified {
        self.verified.lock().unwrap().push((
            String::from(conversation_id),
            String::from_utf8_lossy(cpim_info.from).into_owned(),
            imdn.to_vec(),
        ));
        if self.unsigned {
            Verified::Unsigned
        } else if self.verifying {
            Verified::Signed
        } else {
            Verified::Forged
        }
    }

    fn decrypt(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        mls_message: &[u8],
    ) -> Option<Vec<u8>> {
        self.decrypted.lock().unwrap().push((
            String::from(conversation_id),
            String::from_utf8_lossy(cpim_info.from).into_owned(),
            String::from_utf8_lossy(cpim_info.imdn_message_id).into_owned(),
            mls_message.to_vec(),
        ));
        self.plaintext.clone().map(String::into_bytes)
    }

    fn failed_to_decrypt(&self, conversation_id: &str) -> Vec<FailedToDecrypt> {
        self.asked_failed
            .lock()
            .unwrap()
            .push(String::from(conversation_id));
        std::mem::take(&mut *self.failing_to_decrypt.lock().unwrap())
    }
}

/// The client with group chats encrypted as `cpim` makes them
fn encrypting(client: &Client, cpim: Option<&[u8]>) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: cpim.map(<[u8]>::to_vec),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// The content type and content of each part of the body of `message`
fn parts_of(message: &SipMessage) -> Vec<(String, Vec<u8>)> {
    use std::io::Read;

    let content_type = header_value(message, "Content-Type");
    let boundary = content_type
        .split_once("boundary=")
        .expect("a multipart body")
        .1;
    let Body::Multipart(multipart) =
        Body::construct_multipart(&body_data(message), boundary.as_bytes()).unwrap()
    else {
        panic!("not multipart");
    };
    multipart
        .parts
        .iter()
        .map(|part| match &**part {
            Body::Message(part) => {
                let content_type = header::search(&part.headers, b"Content-Type", true)
                    .map(|h| String::from_utf8_lossy(h.get_value()).into_owned())
                    .unwrap_or_default();
                let mut content = Vec::new();
                part.body
                    .reader()
                    .unwrap()
                    .read_to_end(&mut content)
                    .unwrap();
                (content_type, content)
            }
            _ => panic!("a part with no headers"),
        })
        .collect()
}

/// A CPIM message carrying an MLS message from the Conversation Focus,
/// MLS messages being binary
const MLS_GROUP_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x00\xff\x12\x80";

#[test]
fn an_encrypted_group_chat_is_invited_with_its_mls_group() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting(&client, Some(MLS_GROUP_CPIM));
    let (mut connection, invite, _subscribe, focus_path) = new_group(&client, &mut peer);

    // its MLS group made under its Conversation-ID
    let prepared = encryption.prepared.lock().unwrap().clone();
    assert_eq!(prepared.len(), 1);
    let (conversation_id, from, to, participants) = &prepared[0];
    assert_eq!(header_value(&invite, "Conversation-ID"), *conversation_id);
    assert_eq!(
        uuid::Uuid::parse_str(conversation_id).map(|id| id.get_version_num()),
        Ok(4)
    );
    assert_eq!((&from[..], &to[..]), (IMPU, FACTORY));
    assert_eq!(participants, &[ALICE, BOB]);

    // which the INVITE carries, along with the participants
    let parts = parts_of(&invite);
    let content_types: Vec<&str> = parts.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        content_types,
        [
            "application/sdp",
            "application/resource-lists+xml",
            "message/cpim"
        ]
    );
    assert_eq!(parts[2].1, MLS_GROUP_CPIM);
    let sdp = String::from_utf8_lossy(&parts[0].1).into_owned();
    assert_eq!(
        sdp_attribute(&sdp, "accept-wrapped-types").as_deref(),
        Some("multipart/mixed text/plain application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml message/imdn+xml message/mls message/mls-rcs-server")
    );
    let our_path = sdp_attribute(&sdp, "path").expect("an a=path in the offer");

    // what the focus sends of the MLS group goes to the encryption, and not
    // to the app
    let mls = general_purpose::STANDARD.encode(b"\x0a\x03abc\xff");
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &format!(
            "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-18T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: focus-message-1\r\n\
\r\n\
Content-Type: message/mls-rcs-server\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
{}",
            GROUP, IMPU, mls
        ),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &group_cpim(ALICE, "", "hi all"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|(_, content_type, content)| (content_type, content)),
        Ok((String::from("text/plain"), String::from("hi all")))
    );
    assert_eq!(
        *encryption.server_messages.lock().unwrap(),
        [(conversation_id.clone(), b"\x0a\x03abc\xff".to_vec())]
    );
    assert!(encryption.abandoned.lock().unwrap().is_empty());
}

#[test]
fn a_group_chat_that_cannot_be_encrypted_is_invited_as_one_that_is_not() {
    let (client, mut peer) = start(true);
    let encryption = encrypting(&client, None);
    let (_connection, invite, _subscribe, _) = new_group(&client, &mut peer);

    assert_eq!(encryption.prepared.lock().unwrap().len(), 1);
    let parts = parts_of(&invite);
    assert_eq!(parts.len(), 2);
    let sdp = String::from_utf8_lossy(&parts[0].1).into_owned();
    assert!(!sdp.contains("message/mls"), "{}", sdp);
}

/// The client starting a group chat with Alice, and a receiver of how it
/// started
fn starting_group(client: &Client) -> Receiver<(u16, Option<String>)> {
    let (started_tx, started) = mpsc::channel();
    client.sessions.create_group_chat(
        FACTORY,
        &[String::from(ALICE)],
        None,
        move |status_code, _, conference_uri| {
            let _ = started_tx.send((status_code, conference_uri));
        },
        &client.core,
        &client.rt,
    );
    started
}

#[test]
fn the_mls_group_of_a_group_chat_that_does_not_start_is_let_go_of() {
    for cpim in [Some(MLS_GROUP_CPIM), None] {
        let (client, mut peer) = start(true);
        let encryption = encrypting(&client, cpim);
        let started = starting_group(&client);
        let invite = peer.next_request("INVITE");
        peer.send(&answer(&invite, "403 Forbidden", None));
        assert_eq!(
            started.recv_timeout(Duration::from_secs(5)),
            Ok((403, None))
        );
        peer.next_request("ACK");

        let abandoned = encryption.abandoned.lock().unwrap().clone();
        match cpim {
            Some(_) => assert_eq!(abandoned, [header_value(&invite, "Conversation-ID")]),
            // there is none
            None => assert!(abandoned.is_empty()),
        }
    }
}

#[test]
fn a_group_chat_is_not_encrypted_by_a_client_not_registered() {
    let (client, mut peer) = start(false);
    let encryption = encrypting(&client, Some(MLS_GROUP_CPIM));
    let started = starting_group(&client);
    assert!(started.recv_timeout(Duration::from_secs(5)).is_ok());
    assert!(encryption.prepared.lock().unwrap().is_empty());
    peer.silence();
}

const ALICE: &str = "sip:+15550001@example.com";
const BOB: &str = "tel:+15550002";

/// The client joining the encrypted groups it is invited to, if `joining`
fn joining(client: &Client, joining: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        joining,
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// What the Conversation Focus sends of the MLS group an invited client is
/// to join
const WELCOME: &[u8] = b"\x12\x04welcome bundle";

/// An invitation of the focus to the group, its INVITE carrying the SDP
/// then `part`, with `part_headers`
fn multipart_group_invitation(
    client: &Client,
    peer: &mut Peer,
    call_id: &str,
    part_headers: &str,
    part: &str,
) -> MsrpPeer {
    let msrp = MsrpPeer::listen(&client.rt);
    let body = format!(
        "--part-1\r\nContent-Type: application/sdp\r\n\r\n{}\r\n--part-1\r\n{}\r\n{}\r\n--part-1--\r\n",
        msrp.sdp("sendrecv"),
        part_headers,
        part
    );
    peer.send(&invite(
        call_id,
        &focus_contact(),
        FOCUS,
        "cpm.session",
        "Subject: Friends\r\nReferred-By: \"Alice\" <sip:+15550001@example.com>\r\n",
        "multipart/mixed; boundary=part-1",
        &body,
    ));
    msrp
}

/// As multipart_group_invitation(), its MLS group `WELCOME`, base64
/// encoded in a CPIM message
fn encrypted_group_invitation(client: &Client, peer: &mut Peer, call_id: &str) -> MsrpPeer {
    let cpim = format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: welcome-1\r\n\
\r\n\
Content-Type: message/mls-rcs-server\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
{}",
        GROUP,
        IMPU,
        general_purpose::STANDARD.encode(WELCOME)
    );
    multipart_group_invitation(
        client,
        peer,
        call_id,
        "Content-Type: message/cpim\r\n",
        &cpim,
    )
}

#[test]
fn an_encrypted_group_invitation_is_joined_before_it_is_told_of() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = joining(&client, true);

    let msrp = encrypted_group_invitation(&client, &mut peer, "group-encrypted");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert_eq!(
        *encryption.joined.lock().unwrap(),
        [(String::from("conversation-1"), WELCOME.to_vec())]
    );
    assert_eq!(
        next_group_event(&client),
        format!(
            "invited {} conversation-1 Friends sip:+15550001@example.com Alice accepted encrypted",
            GROUP
        )
    );

    // its session taking what the focus sends of the MLS group
    assert_eq!(
        sdp_attribute(&body(&ok), "accept-wrapped-types").as_deref(),
        Some("multipart/mixed text/plain application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml message/imdn+xml application/im-iscomposing+xml message/mls message/mls-rcs-server")
    );
    peer.send(&ack(&ok, "group-encrypted"));
    peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
    let our_path = sdp_attribute(&body(&ok), "path").expect("an a=path in the answer");
    connection.send_content(
        &rt,
        &msrp.path,
        &our_path,
        "message/cpim",
        &format!(
            "From: <{}>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:01.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: focus-1\r\n\r\nContent-Type: message/mls-rcs-server\r\n\r\nfrom the focus",
            GROUP, IMPU
        ),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let taken = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.server_messages.lock().unwrap().is_empty()
    });
    assert!(taken);
    assert_eq!(
        *encryption.server_messages.lock().unwrap(),
        [(String::from("conversation-1"), b"from the focus".to_vec())]
    );
    assert!(encryption.abandoned.lock().unwrap().is_empty());
    // nothing to commit, as it carried no Proposals
    assert!(encryption.committed.lock().unwrap().is_empty());
}

#[test]
fn the_mls_group_of_an_invitation_may_come_in_a_part_of_its_own() {
    let (client, mut peer) = start(true);
    let encryption = joining(&client, true);
    let _msrp = multipart_group_invitation(
        &client,
        &mut peer,
        "group-bare",
        "Content-Type: message/mls-rcs-server\r\n",
        "the welcome",
    );
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        *encryption.joined.lock().unwrap(),
        [(String::from("conversation-1"), b"the welcome".to_vec())]
    );
    assert!(next_group_event(&client).ends_with(" accepted encrypted"));
    peer.silence();
}

#[test]
fn an_encrypted_group_that_cannot_be_joined_is_declined_without_asking() {
    for set in [true, false] {
        let (client, mut peer) = start(true);
        if set {
            joining(&client, false);
        }
        let _msrp = encrypted_group_invitation(&client, &mut peer, "group-not-joined");
        assert_eq!(status_code(&peer.next_response()), 488, "set {}", set);
        assert!(
            client.group_invites.try_recv().is_err(),
            "the user not asked"
        );
        assert!(
            client
                .group_events
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "nothing told"
        );
        peer.silence();
    }
}

#[test]
fn the_mls_group_of_an_invitation_not_accepted_is_let_go_of() {
    // declined by the user
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);
    let encryption = joining(&client, true);
    let _msrp = encrypted_group_invitation(&client, &mut peer, "group-declined");
    assert_eq!(status_code(&peer.next_response()), 180);
    assert!(next_group_event(&client).ends_with(" pending encrypted"));
    assert!(encryption.abandoned.lock().unwrap().is_empty());
    assert!(client.sessions.answer_invitation(GROUP, false, &client.rt));
    assert_eq!(status_code(&peer.next_response()), 603);
    assert_eq!(*encryption.abandoned.lock().unwrap(), ["conversation-1"]);
    peer.silence();

    // withdrawn by the focus
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);
    let encryption = joining(&client, true);
    let _msrp = encrypted_group_invitation(&client, &mut peer, "group-withdrawn");
    assert_eq!(status_code(&peer.next_response()), 180);
    peer.send(&cancel("group-withdrawn", FOCUS));
    let mut answers: Vec<u16> = (0..2).map(|_| status_code(&peer.next_response())).collect();
    answers.sort();
    assert_eq!(answers, [200, 487]);
    let let_go = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.abandoned.lock().unwrap().is_empty()
    });
    assert!(let_go);
    assert_eq!(*encryption.abandoned.lock().unwrap(), ["conversation-1"]);
    peer.silence();

    // refused by the app at once
    let (client, mut peer) = start(true);
    client.group_answer.store(486, Ordering::SeqCst);
    let encryption = joining(&client, true);
    let _msrp = encrypted_group_invitation(&client, &mut peer, "group-refused");
    let _ = peer.next_response();
    assert_eq!(*encryption.abandoned.lock().unwrap(), ["conversation-1"]);
    peer.silence();

    // and kept once accepted
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);
    let encryption = joining(&client, true);
    let _msrp = encrypted_group_invitation(&client, &mut peer, "group-accepted");
    assert_eq!(status_code(&peer.next_response()), 180);
    assert!(client.sessions.answer_invitation(GROUP, true, &client.rt));
    assert_eq!(status_code(&peer.next_response()), 200);
    assert!(encryption.abandoned.lock().unwrap().is_empty());
    peer.silence();
}

#[test]
fn an_invitation_whose_body_is_not_an_sdp_is_refused() {
    let (client, mut peer) = start(true);
    let msrp = MsrpPeer::listen(&client.rt);
    peer.send(&invite(
        "group-not-sdp",
        &focus_contact(),
        FOCUS,
        "cpm.session",
        "",
        "text/plain",
        &msrp.sdp("sendrecv"),
    ));
    assert_eq!(status_code(&peer.next_response()), 400);
    peer.silence();
}

#[test]
fn a_group_invitation_with_its_sdp_among_other_parts_is_taken() {
    let (client, mut peer) = start(true);
    let encryption = joining(&client, true);

    // nothing of an MLS group in a CPIM message of another kind
    let _msrp = multipart_group_invitation(
        &client,
        &mut peer,
        "group-other-part",
        "Content-Type: message/cpim\r\n",
        &cpim("Content-Type: text/plain\r\n", "not a welcome"),
    );
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert!(encryption.joined.lock().unwrap().is_empty());
    assert!(!body(&ok).contains("message/mls"), "{}", body(&ok));
    assert_eq!(
        next_group_event(&client),
        format!(
            "invited {} conversation-1 Friends sip:+15550001@example.com Alice accepted",
            GROUP
        )
    );
    peer.silence();
}

/// The client encrypting the messages of the group `conversation_id` as
/// `ciphertext`, and decrypting those it receives to `plaintext`
fn encrypting_messages(
    client: &Client,
    conversation_id: &str,
    ciphertext: Option<&str>,
    plaintext: Option<&str>,
) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from(conversation_id)],
        ciphertext: ciphertext.map(String::from),
        plaintext: plaintext.map(String::from),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// What the scripted encryption makes of a message
const CIPHERTEXT: &str = "From: <sip:+15551234@example.com>\r\nTo: <sip:conf1@conf.example.com>\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: encrypted-1\r\n\r\nContent-Type: message/mls\r\n\r\nciphertext";

#[test]
fn the_messages_of_an_encrypted_group_are_sent_encrypted() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    // the group made encrypted, whichever its Conversation-ID
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        ciphertext: Some(String::from(CIPHERTEXT)),
        ..ScriptedEncryption::default()
    });
    let encryption = {
        let prepared = Arc::clone(&encryption);
        client.sessions.set_group_encryption(
            Arc::new(EncryptingPrepared(prepared)) as Arc<dyn GroupEncryption>
        );
        encryption
    };
    let (mut connection, invite, _subscribe, _) = new_group(&client, &mut peer);
    let conversation_id = header_value(&invite, "Conversation-ID");

    // a message
    let result = client.send_with_id(GROUP, RecipientType::Group, "hello all", "encrypted-1");
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(String::from_utf8_lossy(&send.body), CIPHERTEXT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    let (encrypted_in, plaintext) = encryption.encrypted.lock().unwrap()[0].clone();
    assert_eq!(encrypted_in, conversation_id);
    assert_eq!(cpim_text(&plaintext), "hello all");
    let cpim = CPIMMessage::try_from(&Body::construct_message(&plaintext).unwrap()).unwrap();
    assert_eq!(
        id_and_dispositions(&cpim),
        (String::from("encrypted-1"), DELIVERY_AND_DISPLAY)
    );

    // and an is-composing indication
    assert!(client
        .sessions
        .send_is_composing(GROUP, &RecipientType::Group, true, |_, _| {}, &rt));
    let send = connection.next_message(&rt);
    assert_eq!(String::from_utf8_lossy(&send.body), CIPHERTEXT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(encryption.encrypted.lock().unwrap().len(), 2);
    assert!(
        String::from_utf8_lossy(&encryption.encrypted.lock().unwrap()[1].1)
            .contains("Content-Type: application/im-iscomposing+xml"),
    );
}

/// An encryption that encrypts the groups it prepares
struct EncryptingPrepared(Arc<ScriptedEncryption>);

impl GroupEncryption for EncryptingPrepared {
    fn prepare(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.prepare(conversation_id, from, to, participants)
    }

    fn prepare_add(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.prepare_add(conversation_id, from, to, participants)
    }

    fn prepare_remove(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0
            .prepare_remove(conversation_id, from, to, participant)
    }

    fn prepare_leave(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.prepare_leave(conversation_id, from, to)
    }

    fn commit_leaves(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.commit_leaves(conversation_id, from, to)
    }

    fn remove_for_server(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participant: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0
            .remove_for_server(conversation_id, from, to, participant)
    }

    fn discard(&self, conversation_id: &str, refusal_follows: bool) {
        self.0.discard(conversation_id, refusal_follows)
    }

    fn join(&self, conversation_id: &str, server_message: &[u8]) -> bool {
        self.0.join(conversation_id, server_message)
    }

    fn on_server_message(&self, conversation_id: &str, body: &[u8]) -> Taken {
        self.0.on_server_message(conversation_id, body)
    }

    fn on_imdn(&self, conversation_id: &str, imdn: &[u8]) -> ImdnTold {
        self.0.on_imdn(conversation_id, imdn)
    }

    fn end_encryption(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        reason: EndReason,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.end_encryption(conversation_id, from, to, reason)
    }

    fn key_update_due(&self, conversation_id: &str) -> bool {
        self.0.key_update_due(conversation_id)
    }

    fn update_keys(
        &self,
        conversation_id: String,
        from: String,
        to: String,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.update_keys(conversation_id, from, to)
    }

    fn abandon(&self, conversation_id: &str) {
        self.0.abandon(conversation_id)
    }

    fn needs_healing(&self, conversation_id: &str) -> bool {
        self.0.needs_healing(conversation_id)
    }

    fn heal(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        pull: GroupInfoPull,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.heal(conversation_id, from, to, pull)
    }

    fn new_era_due(&self, conversation_id: &str) -> bool {
        self.0.new_era_due(conversation_id)
    }

    fn prepare_next_era(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        pull: GroupInfoPull,
    ) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.prepare_next_era(conversation_id, from, to, pull)
    }

    fn era_refused(&self, conversation_id: &str, status_code: u16) {
        self.0.era_refused(conversation_id, status_code)
    }

    fn upgrade_due(&self, conversation_id: &str) -> bool {
        self.0.upgrade_due(conversation_id)
    }

    fn membership_changed(&self, conversation_id: &str) {
        self.0.membership_changed(conversation_id)
    }

    fn upgrade(
        &self,
        conversation_id: String,
        from: String,
        to: String,
        participants: Vec<String>,
    ) -> BoxFuture<'static, Option<Upgrade>> {
        self.0.upgrade(conversation_id, from, to, participants)
    }

    fn encrypts(&self, conversation_id: &str) -> bool {
        self.0
            .prepared
            .lock()
            .unwrap()
            .iter()
            .any(|(prepared, _, _, _)| prepared == conversation_id)
    }

    fn encryption_ended(&self, conversation_id: &str) -> bool {
        self.0.encryption_ended(conversation_id)
    }

    fn encrypt(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Sealed> {
        self.0.encrypt(conversation_id, cpim)
    }

    fn sign(&self, conversation_id: &str, cpim: &[u8]) -> BoxFuture<'static, Option<Vec<u8>>> {
        self.0.sign(conversation_id, cpim)
    }

    fn verify(&self, conversation_id: &str, cpim_info: &CPIMInfo, imdn: &[u8]) -> Verified {
        self.0.verify(conversation_id, cpim_info, imdn)
    }

    fn decrypt(
        &self,
        conversation_id: &str,
        cpim_info: &CPIMInfo,
        mls_message: &[u8],
    ) -> Option<Vec<u8>> {
        self.0.decrypt(conversation_id, cpim_info, mls_message)
    }

    fn failed_to_decrypt(&self, conversation_id: &str) -> Vec<FailedToDecrypt> {
        self.0.failed_to_decrypt(conversation_id)
    }
}

#[test]
fn a_message_that_cannot_be_encrypted_is_not_sent() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting_messages(&client, "conversation-1", None, None);
    let msrp = encrypted_group_invitation(&client, &mut peer, "group-not-encrypting");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-not-encrypting"));
    peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);

    let result = client.send(GROUP, RecipientType::Group, "secret");
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(500)
    );
    assert_eq!(encryption.encrypted.lock().unwrap().len(), 1);
    connection.quiet(&rt);
}

/// The group joined encrypted, its session up, with the MSRP connection,
/// the path of the focus and the client's
fn joined_encrypted_group(
    client: &Client,
    peer: &mut Peer,
    call_id: &str,
) -> (MsrpConnection, String, String) {
    let msrp = encrypted_group_invitation(client, peer, call_id);
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, call_id));
    peer.next_request("SUBSCRIBE");
    let connection = msrp.accept(&client.rt);
    let our_path = sdp_attribute(&body(&ok), "path").expect("an a=path in the answer");
    (connection, msrp.path, our_path)
}

/// An encrypted message from `from` through the focus, asking for
/// notifications as `cpim_headers` do
fn encrypted_group_cpim(from: &str, cpim_headers: &str, content: &str) -> String {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
NS: mls <http://www.gsma.com/rcs/mls>\r\n\
imdn.Message-ID: peer-message-1\r\n\
{}\
mls.Epoch-Authenticator: YXV0aA==\r\n\
mls.Era-ID: 0\r\n\
\r\n\
Content-Type: message/mls\r\n\
\r\n\
{}",
        from, GROUP, cpim_headers, content
    )
}

#[test]
fn an_encrypted_message_is_given_to_the_app_decrypted() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let plaintext = format!(
        "From: <tel:+15550002>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: peer-message-1\r\n{}\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        GROUP,
        ASKING,
        general_purpose::STANDARD.encode("decrypted hi")
    );
    let encryption = encrypting_messages(
        &client,
        "conversation-1",
        Some(CIPHERTEXT),
        Some(&plaintext),
    );
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-decrypting");

    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &encrypted_group_cpim(ALICE, ASKING, "ciphertext"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| (r.1, r.2)),
        Ok((String::from("text/plain"), String::from("decrypted hi")))
    );
    assert_eq!(
        *encryption.decrypted.lock().unwrap(),
        [(
            String::from("conversation-1"),
            format!("<{}>", ALICE),
            String::from("peer-message-1"),
            b"ciphertext".to_vec()
        )]
    );

    // its delivery told, as the plaintext says, unencrypted
    let send = connection.next_message(&rt);
    let (cpim, imdn) = group_notification(&send);
    assert_eq!(
        cpim.get_info().unwrap().to,
        b"<tel:+15550002>",
        "to the sender MLS tells of"
    );
    assert_eq!(imdn.message_id, "peer-message-1");
    connection.respond(&rt, &send, "200 OK");
    assert!(
        encryption.encrypted.lock().unwrap().is_empty(),
        "the notification not encrypted"
    );
    assert_eq!(
        encryption.signed.lock().unwrap().len(),
        1,
        "and sent unsigned, as it could not be signed"
    );
}

#[test]
fn an_encrypted_message_that_cannot_be_decrypted_is_not_given_to_the_app() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting_messages(&client, "conversation-1", Some(CIPHERTEXT), None);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-undecryptable");

    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &encrypted_group_cpim(ALICE, "", "garbage"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    // the next taken first
    connection.send_cpim(&rt, &focus_path, &our_path, &group_cpim(ALICE, "", "plain"));
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("plain"))
    );
    assert_eq!(encryption.decrypted.lock().unwrap().len(), 1);
}

#[test]
fn an_encrypted_message_in_a_group_not_encrypted_is_not_given_to_the_app() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting_messages(&client, "another", Some(CIPHERTEXT), Some("not used"));
    let (mut connection, invite, _subscribe, focus_path) = new_group(&client, &mut peer);
    let our_path = sdp_attribute(&String::from_utf8_lossy(&body_data(&invite)), "path").unwrap();

    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &encrypted_group_cpim(ALICE, "", "ciphertext"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    connection.send_cpim(&rt, &focus_path, &our_path, &group_cpim(ALICE, "", "plain"));
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("plain"))
    );
    assert!(encryption.decrypted.lock().unwrap().is_empty());
    assert!(encryption.encrypted.lock().unwrap().is_empty());
}

/// A delivery notification from the focus of the message `message_id`,
/// with `status`
fn group_imdn_cpim(message_id: &str, status: &str) -> String {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: focus-imdn-1\r\n\
\r\n\
Content-Type: message/imdn+xml\r\n\
Content-Disposition: notification\r\n\
\r\n\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\
<message-id>{}</message-id>\
<datetime>2026-10-25T11:59:59.000Z</datetime>\
<delivery-notification><status>{}</status></delivery-notification>\
</imdn>",
        GROUP, ALICE, message_id, status
    )
}

const REFUSED: &str =
    "<failed><mls-server-failure-reason><invalid-commit/></mls-server-failure-reason></failed>";

#[test]
fn a_refusal_of_a_control_message_of_the_client_is_not_given_to_the_app() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        refusing: true,
        // which the app would be given, were it not a refusal
        verifying: true,
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-refused");

    let refusal = group_imdn_cpim("control-1", REFUSED);
    connection.send_cpim(&rt, &focus_path, &our_path, &refusal);
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    // the next taken first
    connection.send_cpim(&rt, &focus_path, &our_path, &group_cpim(ALICE, "", "plain"));
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("plain"))
    );
    let imdns = encryption.imdns.lock().unwrap();
    assert_eq!(imdns.len(), 1);
    assert_eq!(imdns[0].0, "conversation-1");
    assert!(refusal.ends_with(&*String::from_utf8_lossy(&imdns[0].1)));
    assert!(encryption.verified.lock().unwrap().is_empty());
}

/// The client with the group `conversation-1` encrypted, the notifications
/// received in it taken as signed by whom they are from if `verifying`
fn verifying(client: &Client, verifying: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        verifying,
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

#[test]
fn a_notification_the_encryption_does_not_take_is_given_to_the_app() {
    // in an encrypted group, signed by whom it is from
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = verifying(&client, true);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-notified");
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &group_imdn_cpim("message-1", "<delivered/>"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let (_, content_type, content) = client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("the notification given to the app");
    assert!(content_type.starts_with("message/imdn+xml"));
    assert_eq!(
        Imdn::from_xml(content.as_bytes()).map(|imdn| imdn.message_id),
        Some(String::from("message-1"))
    );
    assert_eq!(encryption.imdns.lock().unwrap().len(), 1);
    let verified = encryption.verified.lock().unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(
        (verified[0].0.as_str(), verified[0].1.as_str()),
        ("conversation-1", &*format!("<{}>", GROUP))
    );
    assert_eq!(verified[0].2, encryption.imdns.lock().unwrap()[0].1);
    drop(verified);

    // and in one that is not, without the encryption
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = Arc::new(ScriptedEncryption {
        refusing: true,
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, invite, _subscribe, focus_path) = new_group(&client, &mut peer);
    let our_path = sdp_attribute(&String::from_utf8_lossy(&body_data(&invite)), "path").unwrap();
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &group_imdn_cpim("message-2", REFUSED),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let (_, content_type, _) = client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("the notification given to the app");
    assert!(content_type.starts_with("message/imdn+xml"));
    assert!(encryption.imdns.lock().unwrap().is_empty());
    assert!(encryption.verified.lock().unwrap().is_empty());

    // its own sent unsigned
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &group_cpim(ALICE, ASKING, "tell me"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let _ = client.received.recv_timeout(Duration::from_secs(5));
    let send = connection.next_message(&rt);
    let (_, imdn) = group_notification(&send);
    assert_eq!(imdn.message_id, "peer-message-1");
    connection.respond(&rt, &send, "200 OK");
    assert!(encryption.signed.lock().unwrap().is_empty());
}

#[test]
fn a_notification_not_signed_by_whom_it_is_from_is_not_given_to_the_app() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = verifying(&client, false);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-unverified");

    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &group_imdn_cpim("message-1", "<displayed/>"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    // the next taken first
    connection.send_cpim(&rt, &focus_path, &our_path, &group_cpim(ALICE, "", "plain"));
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("plain"))
    );
    assert_eq!(encryption.verified.lock().unwrap().len(), 1);
}

/// What the scripted encryption makes of a notification it signs
const SIGNED: &str = "From: <sip:+15551234@example.com>\r\nTo: <tel:+15550002>\r\nNS: mls <http://www.gsma.com/rcs/mls>\r\nmls.MLS-Derived-Content-Signature: c2lnbmVk\r\n\r\nContent-Type: message/imdn+xml\r\n\r\n<imdn/>";

#[test]
fn the_notifications_of_an_encrypted_group_are_sent_signed() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let plaintext = format!(
        "From: <tel:+15550002>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: peer-message-1\r\n{}\r\nContent-Type: text/plain\r\n\r\nhi",
        GROUP, ASKING
    );
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        ciphertext: Some(String::from(CIPHERTEXT)),
        plaintext: Some(plaintext),
        signature: Some(String::from(SIGNED)),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-signing");

    // its delivery
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &encrypted_group_cpim(ALICE, ASKING, "ciphertext"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let _ = client.received.recv_timeout(Duration::from_secs(5));
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(String::from_utf8_lossy(&send.body), SIGNED);
    connection.respond(&rt, &send, "200 OK");

    // and its display
    let notice = client
        .received_messages
        .displayed("peer-message-1")
        .unwrap();
    assert!(client.sessions.send_group_imdn(
        GROUP,
        &notice.xml,
        &notice.sender_uri,
        notice.original_message_id.as_deref(),
        |_, _| {},
        &rt
    ));
    let send = connection.next_message(&rt);
    assert_eq!(String::from_utf8_lossy(&send.body), SIGNED);
    connection.respond(&rt, &send, "200 OK");

    // signed as they would have been sent
    let signed = encryption.signed.lock().unwrap();
    let told: Vec<(&str, Notification, Status, String)> = signed
        .iter()
        .map(|(conversation_id, cpim)| {
            let cpim = CPIMMessage::try_from(&Body::construct_message(cpim).unwrap()).unwrap();
            let (content_type, xml, _) = cpim.get_message_body().unwrap();
            assert_eq!(content_type, Some(&b"message/imdn+xml"[..]));
            let imdn = Imdn::from_xml(xml).unwrap();
            (
                conversation_id.as_str(),
                imdn.notification,
                imdn.status,
                imdn.message_id,
            )
        })
        .collect();
    assert_eq!(
        told,
        [
            (
                "conversation-1",
                Notification::Delivery,
                Status::Delivered,
                String::from("peer-message-1")
            ),
            (
                "conversation-1",
                Notification::Display,
                Status::Displayed,
                String::from("peer-message-1")
            ),
        ]
    );
    assert!(
        encryption.encrypted.lock().unwrap().is_empty(),
        "nor encrypted"
    );
}

/// The CPIM messages signed by `encryption`, from the first `from` on: of
/// each, its CPIM To and Original-Message-ID, and the IMDN document
fn signed_from(
    encryption: &ScriptedEncryption,
    from: usize,
) -> Vec<(String, Option<String>, String)> {
    encryption.signed.lock().unwrap()[from..]
        .iter()
        .map(|(conversation_id, cpim)| {
            assert_eq!(conversation_id, "conversation-1");
            let cpim = CPIMMessage::try_from(&Body::construct_message(cpim).unwrap()).unwrap();
            let info = cpim.get_info().unwrap();
            let (content_type, xml, _) = cpim.get_message_body().unwrap();
            assert_eq!(content_type, Some(&b"message/imdn+xml"[..]));
            (
                String::from_utf8_lossy(info.to).into_owned(),
                info.mls_original_message_id
                    .map(|id| String::from_utf8_lossy(id).into_owned()),
                String::from_utf8_lossy(xml).into_owned(),
            )
        })
        .collect()
}

#[test]
fn the_senders_of_messages_not_decrypted_are_told_so_in_the_session() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        signature: Some(String::from(SIGNED)),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-not-decrypted");

    // as the encryption gives them once a message is not decrypted (RCC.16
    // section 10.2), of an Original Message and of a Re-Sent Message
    *encryption.failing_to_decrypt.lock().unwrap() = vec![
        FailedToDecrypt {
            imdn: String::from("<imdn>peer-message-1</imdn>"),
            sender_uri: String::from("tel:+15550002"),
            original_message_id: None,
        },
        FailedToDecrypt {
            imdn: String::from("<imdn>peer-message-5</imdn>"),
            sender_uri: String::from("tel:+15550003"),
            original_message_id: Some(String::from("peer-message-4")),
        },
    ];
    let asked = encryption.asked_failed.lock().unwrap().len();
    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &encrypted_group_cpim("tel:+15550002", "", "not to be decrypted"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    for _ in 0..2 {
        let send = connection.next_message(&rt);
        assert_eq!(send.header("Content-Type"), Some("message/cpim"));
        assert_eq!(String::from_utf8_lossy(&send.body), SIGNED);
        connection.respond(&rt, &send, "200 OK");
    }
    assert!(encryption.asked_failed.lock().unwrap().len() > asked);

    // sent signed to their senders, through the focus (sections 7.7.2.2,
    // 7.7.3)
    assert_eq!(
        signed_from(&encryption, 0),
        [
            (
                String::from("<tel:+15550002>"),
                None,
                String::from("<imdn>peer-message-1</imdn>")
            ),
            (
                String::from("<tel:+15550003>"),
                Some(String::from("peer-message-4")),
                String::from("<imdn>peer-message-5</imdn>")
            ),
        ]
    );
    connection.quiet(&rt);

    // asked for again once the focus sends a control message, which may
    // end self-healing
    *encryption.failing_to_decrypt.lock().unwrap() = vec![FailedToDecrypt {
        imdn: String::from("<imdn>peer-message-6</imdn>"),
        sender_uri: String::from("tel:+15550002"),
        original_message_id: None,
    }];
    connection.send_content(
        &rt,
        &focus_path,
        &our_path,
        "message/cpim",
        &from_the_focus("a commit"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let send = connection.next_message(&rt);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        signed_from(&encryption, 2),
        [(
            String::from("<tel:+15550002>"),
            None,
            String::from("<imdn>peer-message-6</imdn>")
        )]
    );
    connection.quiet(&rt);
}

#[test]
fn the_notifications_of_a_re_sent_message_tell_of_its_original_message() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    // as the encryption decrypts a Re-Sent Message (RCC.16 section 10.4)
    let plaintext = format!(
        "From: <tel:+15550002>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:05:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: peer-message-5\r\n{}NS: mls <http://www.gsma.com/rcs/mls>\r\nmls.Original-Message-ID: peer-message-1\r\n\r\nContent-Type: text/plain\r\n\r\nhi again",
        GROUP, ASKING
    );
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        plaintext: Some(plaintext),
        signature: Some(String::from(SIGNED)),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, focus_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-resent");

    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &encrypted_group_cpim("tel:+15550002", ASKING, "re-sent"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("hi again"))
    );
    let send = connection.next_message(&rt);
    connection.respond(&rt, &send, "200 OK");

    // its display asked for by the Message-ID of its Original Message,
    // which the app knows it by
    let notice = client
        .received_messages
        .displayed("peer-message-1")
        .unwrap();
    assert!(client.sessions.send_group_imdn(
        GROUP,
        &notice.xml,
        &notice.sender_uri,
        notice.original_message_id.as_deref(),
        |_, _| {},
        &rt
    ));
    let send = connection.next_message(&rt);
    connection.respond(&rt, &send, "200 OK");

    // both of the Re-Sent Message, with the Original-Message-ID (sections
    // 7.7.1, 7.7.3)
    let told: Vec<(Option<String>, Notification, String)> = signed_from(&encryption, 0)
        .into_iter()
        .map(|(to, original_message_id, xml)| {
            assert_eq!(to, "<tel:+15550002>");
            let imdn = Imdn::from_xml(xml.as_bytes()).unwrap();
            (original_message_id, imdn.notification, imdn.message_id)
        })
        .collect();
    assert_eq!(
        told,
        [
            (
                Some(String::from("peer-message-1")),
                Notification::Delivery,
                String::from("peer-message-5")
            ),
            (
                Some(String::from("peer-message-1")),
                Notification::Display,
                String::from("peer-message-5")
            ),
        ]
    );
}

#[test]
fn an_encrypted_group_restarted_is_encrypted_again() {
    // by the client
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting_messages(&client, "conversation-1", Some(CIPHERTEXT), None);
    let (mut connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-first");
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));

    let msrp = MsrpPeer::listen(&rt);
    let result = client.send(GROUP, RecipientType::Group, "again");
    let restart = peer.next_request("INVITE");
    assert_eq!(header_value(&restart, "Conversation-ID"), "conversation-1");
    let offer = String::from_utf8_lossy(&body_data(&restart)).into_owned();
    assert!(
        sdp_attribute(&offer, "accept-wrapped-types")
            .unwrap()
            .ends_with(" message/mls message/mls-rcs-server"),
        "{}",
        offer
    );
    peer.send(&answer_from(
        &restart,
        "200 OK",
        &focus_contact(),
        Some(&msrp.sdp("sendrecv")),
    ));
    next_requests(&mut peer, &["ACK", "SUBSCRIBE"]);
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(String::from_utf8_lossy(&send.body), CIPHERTEXT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    assert!(cpim_text(&encryption.encrypted.lock().unwrap()[0].1) == "again");

    // and by its focus
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));
    let msrp = group_invitation(&client, &mut peer, "group-again");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert!(sdp_attribute(&body(&ok), "accept-wrapped-types")
        .unwrap()
        .ends_with(" message/mls message/mls-rcs-server"));
    peer.send(&ack(&ok, "group-again"));
    peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);
    let _result = client.send(GROUP, RecipientType::Group, "once more");
    let send = connection.next_message(&rt);
    assert_eq!(String::from_utf8_lossy(&send.body), CIPHERTEXT);
    connection.respond(&rt, &send, "200 OK");
}

#[test]
fn the_participants_of_a_group_are_followed_while_its_session_lasts() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, _invite, subscribe, _) = new_group(&client, &mut peer);

    assert_eq!(request_uri(&subscribe), GROUP);
    assert_eq!(header_value(&subscribe, "To"), format!("<{}>", GROUP));
    assert_eq!(header_value(&subscribe, "Event"), "conference");
    assert_eq!(
        header_value(&subscribe, "Accept"),
        "application/conference-info+xml"
    );
    assert_eq!(header_value(&subscribe, "Expires"), "3600");
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));

    let user = |entity: &str, name: &str, status: &str, method: &str| {
        format!(
            "<user entity=\"{}\">{}<endpoint entity=\"{}\"><status>{}</status>{}</endpoint></user>",
            entity,
            if name.is_empty() {
                String::new()
            } else {
                format!("<display-text>{}</display-text>", name)
            },
            entity,
            status,
            if method.is_empty() {
                String::new()
            } else {
                format!("<disconnection-method>{}</disconnection-method>", method)
            }
        )
    };
    let document = |state: &str, version: u32, users: String| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" entity=\"{}\" \
state=\"{}\" version=\"{}\"><users>{}</users></conference-info>",
            GROUP, state, version, users
        )
    };

    peer.send(&conference_notify(
        &subscribe,
        1,
        &document(
            "full",
            1,
            user(ALICE, "Alice", "connected", "") + &user(BOB, "", "pending", ""),
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        next_group_event(&client),
        format!("participant {} {} Alice connected", GROUP, ALICE)
    );
    assert_eq!(
        next_group_event(&client),
        format!("participant {} {} - pending", GROUP, BOB)
    );

    peer.send(&conference_notify(
        &subscribe,
        2,
        &document("partial", 2, user(BOB, "", "disconnected", "departed")),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        next_group_event(&client),
        format!("participant {} {} - departed", GROUP, BOB)
    );

    // the session ended, the subscription ends with it
    assert!(client.sessions.end_session(GROUP));
    let requests = next_requests(&mut peer, &["BYE", "SUBSCRIBE"]);
    assert_eq!(header_value(&requests[1], "Expires"), "0");
    assert_eq!(
        header_value(&requests[1], "Call-ID"),
        header_value(&subscribe, "Call-ID")
    );
    assert_eq!(next_group_event(&client), format!("left {}", GROUP));
    connection.closed(&rt);
}

#[test]
fn participants_are_added_by_a_refer_in_the_session_of_the_group() {
    let (client, mut peer) = start(true);
    let (_connection, invite, _subscribe, _) = new_group(&client, &mut peer);

    let (result_tx, result) = mpsc::channel();
    assert!(client.sessions.add_participants(
        GROUP,
        &[
            String::from("sip:+15550003@example.com"),
            String::from("tel:+15550004")
        ],
        move |status_code, _| {
            let _ = result_tx.send(status_code);
        },
    ));

    let refer = peer.next_request("REFER");
    assert_eq!(request_uri(&refer), GROUP, "to the focus");
    assert_eq!(
        header_value(&refer, "Call-ID"),
        header_value(&invite, "Call-ID"),
        "in the session's dialog"
    );
    assert_eq!(header_value(&refer, "Require"), "multiple-refer");
    assert_eq!(header_value(&refer, "Refer-Sub"), "false");
    assert_eq!(
        header_value(&refer, "Content-Type"),
        "application/resource-lists+xml"
    );
    assert_eq!(
        header_value(&refer, "Content-Disposition"),
        "recipient-list"
    );
    let refer_to = header_value(&refer, "Refer-To");
    let content_id = header_value(&refer, "Content-ID");
    assert_eq!(
        refer_to.trim_start_matches("<cid:").trim_end_matches('>'),
        content_id.trim_start_matches('<').trim_end_matches('>'),
        "the list by its Content-ID"
    );
    let body = String::from_utf8_lossy(&body_data(&refer)).into_owned();
    for entry in [
        "<entry uri=\"sip:+15550003@example.com\" cp:copyControl=\"to\"/>",
        "<entry uri=\"tel:+15550004\" cp:copyControl=\"to\"/>",
    ] {
        assert!(body.contains(entry), "{} in {}", entry, body);
    }

    peer.send(&answer(&refer, "202 Accepted", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(202));

    // no group is not asked, nor a one-to-one chat
    assert!(!client.sessions.add_participants(
        "sip:conf9@conf.example.com",
        &[String::from(ALICE)],
        |_, _| {}
    ));
    let _one_to_one = incoming_chat(&client, &mut peer, "one-to-one");
    assert!(!client
        .sessions
        .add_participants(PEER, &[String::from(ALICE)], |_, _| {}));
}

#[test]
fn a_group_invitation_without_subject_or_inviter_name_is_taken() {
    let (client, mut peer) = start(true);
    let msrp = MsrpPeer::listen(&client.rt);

    peer.send(&invite(
        "group-plain",
        "<sip:conf1@conf.example.com;transport=tcp>;isfocus;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        "sip:conf1@conf.example.com",
        "cpm.session",
        "Referred-By: <sip:+15550001@example.com>\r\n",
        "application/sdp",
        &msrp.sdp("sendrecv"),
    ));
    assert_eq!(
        client.group_invites.recv_timeout(Duration::from_secs(5)),
        Ok((String::new(), String::new()))
    );

    // taken, and once started its participants followed
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert_eq!(
        next_group_event(&client),
        format!(
            "invited {} conversation-1 - sip:+15550001@example.com - accepted",
            GROUP
        )
    );
    peer.send(&ack(&ok, "group-plain"));
    let subscribe = peer.next_request("SUBSCRIBE");
    assert_eq!(request_uri(&subscribe), GROUP);
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
}

/// A CPIM message from the participant `from`, through the focus, asking for
/// notifications as `cpim_headers` do
fn group_cpim(from: &str, cpim_headers: &str, content: &str) -> String {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-18T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: peer-message-1\r\n\
{}\
\r\n\
Content-Type: text/plain\r\n\
\r\n\
{}",
        from, GROUP, cpim_headers, content
    )
}

/// The CPIM headers and IMDN document of a notification the client sent in
/// an MSRP SEND
fn group_notification(send: &MsrpFrame) -> (CPIMMessage, Imdn) {
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    let cpim = CPIMMessage::try_from(&Body::construct_message(&send.body).unwrap()).unwrap();
    assert!(
        cpim.contains_imdn(),
        "{}",
        String::from_utf8_lossy(&send.body)
    );
    let text = String::from_utf8_lossy(&send.body).into_owned();
    let xml = text.rsplit("\r\n\r\n").next().unwrap();
    let imdn = Imdn::from_xml(xml.as_bytes()).expect("an IMDN document as it is");
    (cpim, imdn)
}

#[test]
fn a_group_message_asking_to_be_told_of_is_answered_in_the_session_of_the_group() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, invite, _subscribe, focus_path) = new_group(&client, &mut peer);
    let our_path = sdp_attribute(&String::from_utf8_lossy(&body_data(&invite)), "path")
        .expect("an a=path in the offer");

    connection.send_cpim(
        &rt,
        &focus_path,
        &our_path,
        &group_cpim(ALICE, ASKING, "hi all"),
    );
    let response = connection.next_response(&rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| (r.0, r.2)),
        Ok((String::from(GROUP), String::from("hi all")))
    );

    // delivered, told the participant through the focus
    let send = connection.next_message(&rt);
    let (cpim, imdn) = group_notification(&send);
    let info = cpim.get_info().unwrap();
    assert_eq!(
        (info.from, info.to),
        (
            format!("<{}>", IMPU).as_bytes(),
            format!("<{}>", ALICE).as_bytes()
        )
    );
    assert!(
        info.disposition_notification.is_none(),
        "it asks for nothing"
    );
    assert_eq!(
        (imdn.message_id.as_str(), imdn.notification, imdn.status),
        ("peer-message-1", Notification::Delivery, Status::Delivered)
    );
    connection.respond(&rt, &send, "200 OK");

    // and displayed, the same way, by what was noted of it
    let notice = client
        .received_messages
        .displayed("peer-message-1")
        .unwrap();
    assert_eq!(
        (notice.group.as_deref(), notice.sender_uri.as_str()),
        (Some(GROUP), ALICE)
    );
    let (result_tx, result) = mpsc::channel();
    let result_tx = std::sync::Mutex::new(result_tx);
    assert!(client.sessions.send_group_imdn(
        GROUP,
        &notice.xml,
        &notice.sender_uri,
        notice.original_message_id.as_deref(),
        move |status_code, _| {
            let _ = result_tx.lock().unwrap().send(status_code);
        },
        &rt,
    ));
    let send = connection.next_message(&rt);
    let (_, imdn) = group_notification(&send);
    assert_eq!(
        (imdn.notification, imdn.status),
        (Notification::Display, Status::Displayed)
    );
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));

    // a message not asking is not answered
    connection.send_cpim(&rt, &focus_path, &our_path, &group_cpim(BOB, "", "quiet"));
    let response = connection.next_response(&rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
    connection.quiet(&rt);

    // nor is a group there is no session with, nor a one-to-one chat
    assert!(!client.sessions.send_group_imdn(
        "sip:conf9@conf.example.com",
        &notice.xml,
        ALICE,
        None,
        |_, _| {},
        &rt
    ));
    let _one_to_one = incoming_chat(&client, &mut peer, "one-to-one");
    assert!(!client
        .sessions
        .send_group_imdn(PEER, &notice.xml, ALICE, None, |_, _| {}, &rt));
}

/// The Reason of a BYE leaving a group for good
const LEAVING: &str = "SIP;cause=200;text=\"Call completed\"";

/// The Contact of the focus of the group
fn focus_contact() -> String {
    format!(
        "<{}>;isfocus;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        GROUP
    )
}

/// Leaves the group at `conference_uri`, returning a receiver of how it went
fn leave(client: &Client, conference_uri: &str) -> Receiver<u16> {
    let (result_tx, result) = mpsc::channel();
    client.sessions.leave_group_chat(
        conference_uri,
        move |status_code, _| {
            let _ = result_tx.send(status_code);
        },
        &client.core,
        &client.rt,
    );
    result
}

#[test]
fn a_group_is_left_for_good_with_a_bye_saying_so() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, invite, _subscribe, _) = new_group(&client, &mut peer);

    let result = leave(&client, GROUP);
    let bye = peer.next_request("BYE");
    assert_eq!(
        header_value(&bye, "Call-ID"),
        header_value(&invite, "Call-ID"),
        "in the session's dialog"
    );
    assert_eq!(header_value(&bye, "Reason"), LEAVING);
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));

    assert!(!client.sessions.has_session_with(GROUP));
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
    assert_eq!(next_group_event(&client), format!("left {}", GROUP));
}

#[test]
fn a_group_without_a_session_is_restarted_to_be_left() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, invite, _subscribe, _) = new_group(&client, &mut peer);

    // its session ended for the time being, as the focus does once it idles
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    assert_eq!(header_value(&bye, "Reason"), "", "not leaving the group");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));

    let msrp = MsrpPeer::listen(&rt);
    let result = leave(&client, GROUP);
    let restart = peer.next_request("INVITE");
    assert_eq!(request_uri(&restart), GROUP);
    assert_eq!(header_value(&restart, "To"), format!("<{}>", GROUP));
    assert_eq!(header_value(&restart, "Require"), "", "no one to invite");
    for id in ["Conversation-ID", "Contribution-ID"] {
        assert_eq!(
            header_value(&restart, id),
            header_value(&invite, id),
            "the group's {}",
            id
        );
    }

    // meanwhile, another request to leave waits for it
    assert_eq!(
        leave(&client, GROUP).recv_timeout(Duration::from_secs(5)),
        Ok(491)
    );

    // and once restarted, it is left
    peer.send(&answer_from(
        &restart,
        "200 OK",
        &focus_contact(),
        Some(&msrp.sdp("sendrecv")),
    ));
    let requests = next_requests(&mut peer, &["ACK", "SUBSCRIBE", "BYE"]);
    let bye = &requests[2];
    assert_eq!(
        header_value(bye, "Call-ID"),
        header_value(&restart, "Call-ID")
    );
    assert_eq!(header_value(bye, "Reason"), LEAVING);
    peer.send(&answer(bye, "200 OK", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));
    assert!(!client.sessions.has_session_with(GROUP));

    for event in ["joined", "left", "joined", "left"] {
        assert_eq!(next_group_event(&client), format!("{} {}", event, GROUP));
    }

    // a group the focus no longer has is told as it refuses the restart,
    // made with identifiers of its own
    let other = "sip:conf9@conf.example.com";
    let result = leave(&client, other);
    let restart = peer.next_request("INVITE");
    assert_eq!(request_uri(&restart), other);
    assert_ne!(
        header_value(&restart, "Conversation-ID"),
        header_value(&invite, "Conversation-ID")
    );
    peer.send(&answer(&restart, "404 Not Found", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(404));
    peer.next_request("ACK");
    peer.silence();
}

#[test]
fn a_group_joined_is_restarted_with_the_ids_it_was_joined_with() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let msrp = MsrpPeer::listen(&rt);

    peer.send(&invite(
        "group-joined",
        &focus_contact(),
        GROUP,
        "cpm.session",
        "Referred-By: <sip:+15550001@example.com>\r\n",
        "application/sdp",
        &msrp.sdp("sendrecv"),
    ));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-joined"));
    peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);

    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));

    // a message to the group restarts it as it was joined
    let _result = client.send(GROUP, RecipientType::Group, "back");
    let restart = peer.next_request("INVITE");
    assert_eq!(request_uri(&restart), GROUP);
    assert_eq!(header_value(&restart, "Conversation-ID"), "conversation-1");
    assert_eq!(header_value(&restart, "Contribution-ID"), "contribution-1");
}

/// The identity the focus asserts, other than the group's URI
const FOCUS: &str = "sip:focus@conf.example.com";

/// An invitation from the focus of the group, by Alice, its MSRP peer
/// listening
fn group_invitation(client: &Client, peer: &mut Peer, call_id: &str) -> MsrpPeer {
    let msrp = MsrpPeer::listen(&client.rt);
    peer.send(&invite(
        call_id,
        &focus_contact(),
        FOCUS,
        "cpm.session",
        "Subject: Friends\r\nReferred-By: \"Alice\" <sip:+15550001@example.com>\r\n",
        "application/sdp",
        &msrp.sdp("sendrecv"),
    ));
    msrp
}

/// The CANCEL of the INVITE invite() made with `call_id`, from `asserted`
fn cancel(call_id: &str, asserted: &str) -> String {
    format!(
        "CANCEL sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: <{}>;tag=peer1\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 CANCEL\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n",
        TRANSPORT_ADDRESS, call_id, asserted, IMPU, call_id
    )
}

/// Whether the dialogs the client has come to `count` within a second
fn dialogs_come_to(client: &Client, count: usize) -> bool {
    (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        client.core.get_ongoing_dialogs().lock().unwrap().len() == count
    })
}

#[test]
fn a_group_invitation_not_accepted_automatically_waits_for_the_user() {
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);

    let msrp = group_invitation(&client, &mut peer, "group-pending");
    assert_eq!(status_code(&peer.next_response()), 180);
    assert_eq!(
        next_group_event(&client),
        format!(
            "invited {} conversation-1 Friends sip:+15550001@example.com Alice pending",
            GROUP
        )
    );
    peer.silence();

    // accepted, it is taken part in
    assert!(client.sessions.answer_invitation(GROUP, true, &client.rt));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert_eq!(header_value(&ok, "Call-ID"), "group-pending");
    peer.send(&ack(&ok, "group-pending"));
    peer.next_request("SUBSCRIBE");
    let _connection = msrp.accept(&client.rt);
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));

    // once
    assert!(!client.sessions.answer_invitation(GROUP, true, &client.rt));
}

#[test]
fn a_group_invitation_declined_is_answered_603_and_let_go_of() {
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);

    let _msrp = group_invitation(&client, &mut peer, "group-declined");
    assert_eq!(status_code(&peer.next_response()), 180);
    assert!(next_group_event(&client).ends_with(" pending"));
    assert!(dialogs_come_to(&client, 1), "its early dialog");

    assert!(client.sessions.answer_invitation(GROUP, false, &client.rt));
    assert!(
        !client.sessions.answer_invitation(GROUP, true, &client.rt),
        "answered once"
    );
    assert_eq!(status_code(&peer.next_response()), 603);
    assert!(dialogs_come_to(&client, 0), "its early dialog went");
    peer.silence();
}

#[test]
fn a_group_restarted_by_its_focus_is_taken_part_in_again_at_once() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);

    let msrp = group_invitation(&client, &mut peer, "group-first");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-first"));
    peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);
    assert!(client
        .group_invites
        .recv_timeout(Duration::from_secs(5))
        .is_ok());

    // its session ended, as its focus does once it idles
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));
    assert!(next_group_event(&client).ends_with(" accepted"));
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
    assert_eq!(next_group_event(&client), format!("left {}", GROUP));

    // restarted by its focus, with the Conversation-ID known, it is taken
    // at once, though the user answers invitations
    client.group_answer.store(180, Ordering::SeqCst);
    let msrp = group_invitation(&client, &mut peer, "group-again");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert!(
        client.group_invites.try_recv().is_err(),
        "the user not asked"
    );
    peer.send(&ack(&ok, "group-again"));
    peer.next_request("SUBSCRIBE");
    let _connection = msrp.accept(&rt);
    assert_eq!(
        next_group_event(&client),
        format!("joined {}", GROUP),
        "not told of as an invitation"
    );
}

#[test]
fn a_group_invitation_cancelled_while_waiting_is_withdrawn_and_let_go_of() {
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);

    let _msrp = group_invitation(&client, &mut peer, "group-cancelled");
    assert_eq!(status_code(&peer.next_response()), 180);
    assert!(next_group_event(&client).ends_with(" pending"));
    assert!(dialogs_come_to(&client, 1), "its early dialog");

    // cancelled by the focus: the CANCEL answered, the INVITE ended
    peer.send(&cancel("group-cancelled", FOCUS));
    let mut answers: Vec<u16> = (0..2).map(|_| status_code(&peer.next_response())).collect();
    answers.sort();
    assert_eq!(answers, [200, 487]);

    // and the app told, the invitation no longer one to answer
    assert_eq!(next_group_event(&client), format!("withdrawn {}", GROUP));
    assert!(!client.sessions.answer_invitation(GROUP, true, &client.rt));
    assert!(dialogs_come_to(&client, 0), "its early dialog went");
    peer.silence();
}

#[test]
fn a_chat_invitation_cancelled_while_waiting_is_let_go_of_without_a_group_event() {
    let (client, mut peer) = start(true);
    client.chat_answer.store(180, Ordering::SeqCst);
    let msrp = MsrpPeer::listen(&client.rt);

    peer.send(&chat_invite("chat-cancelled", &msrp.sdp("sendrecv")));
    assert_eq!(status_code(&peer.next_response()), 180);
    assert!(dialogs_come_to(&client, 1), "its early dialog");

    peer.send(&cancel("chat-cancelled", PEER));
    let mut answers: Vec<u16> = (0..2).map(|_| status_code(&peer.next_response())).collect();
    answers.sort();
    assert_eq!(answers, [200, 487]);

    assert!(dialogs_come_to(&client, 0), "its early dialog went");
    assert!(!client.sessions.answer_invitation(PEER, true, &client.rt));
    assert!(
        client
            .group_events
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "nothing told of a group"
    );
}

#[test]
fn the_conversation_id_of_a_group_is_known_once_a_session_with_it_starts() {
    let (client, mut peer) = start(true);
    assert_eq!(client.sessions.group_conversation_id(GROUP), None);

    // one the client started, by the Conversation-ID it sent
    let (_connection, creating, _subscribe, _) = new_group(&client, &mut peer);
    assert_eq!(
        client.sessions.group_conversation_id(GROUP),
        Some(header_value(&creating, "Conversation-ID"))
    );

    // one it was invited to, by the invitation's
    let other = "sip:conf2@conf.example.com";
    let msrp = MsrpPeer::listen(&client.rt);
    peer.send(&invite(
        "group-other",
        &format!(
            "<{}>;isfocus;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
            other
        ),
        FOCUS,
        "cpm.session",
        "",
        "application/sdp",
        &msrp.sdp("sendrecv"),
    ));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-other"));
    peer.next_request("SUBSCRIBE");
    let _connection = msrp.accept(&client.rt);
    assert_eq!(
        client.sessions.group_conversation_id(other),
        Some(String::from("conversation-1"))
    );

    // and not a contact's
    let _one_to_one = incoming_chat(&client, &mut peer, "one-to-one");
    assert_eq!(client.sessions.group_conversation_id(PEER), None);
}

#[test]
fn the_ids_of_a_group_are_told_once_known_and_given_back_after_a_restart() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);

    // told once the group starts
    let (mut connection, creating, _subscribe, _) = new_group(&client, &mut peer);
    let ids = client
        .group_ids
        .recv_timeout(Duration::from_secs(5))
        .expect("the ids to keep");
    assert_eq!(
        ids,
        GroupIds {
            conference_uri: String::from(GROUP),
            conversation_id: header_value(&creating, "Conversation-ID"),
            contribution_id: header_value(&creating, "Contribution-ID"),
            mls_opaque_token: None,
        }
    );

    // and not again as it restarts with the same
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));
    let msrp = MsrpPeer::listen(&rt);
    let _sent = client.send(GROUP, RecipientType::Group, "again");
    let restart = peer.next_request("INVITE");
    peer.send(&answer_from(
        &restart,
        "200 OK",
        &focus_contact(),
        Some(&msrp.sdp("sendrecv")),
    ));
    next_requests(&mut peer, &["ACK", "SUBSCRIBE"]);
    let _connection = msrp.accept(&rt);
    assert!(
        client
            .group_ids
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "the same ids told again"
    );

    // a client made again, given them back, restarts the group with them
    let (again, mut peer) = start(true);
    again.sessions.remember_group_ids(ids.clone());
    let _sent = again.send(GROUP, RecipientType::Group, "back");
    let restart = peer.next_request("INVITE");
    assert_eq!(request_uri(&restart), GROUP);
    assert_eq!(
        header_value(&restart, "Conversation-ID"),
        ids.conversation_id
    );
    assert_eq!(
        header_value(&restart, "Contribution-ID"),
        ids.contribution_id
    );
    assert_eq!(
        again.sessions.group_conversation_id(GROUP),
        Some(ids.conversation_id)
    );
}

#[test]
fn a_group_given_back_is_known_when_its_focus_restarts_it() {
    let (client, mut peer) = start(true);
    client.group_answer.store(180, Ordering::SeqCst);
    client.sessions.remember_group_ids(GroupIds {
        conference_uri: String::from(GROUP),
        conversation_id: String::from("conversation-1"),
        contribution_id: String::from("contribution-1"),
        mls_opaque_token: None,
    });

    // taken at once, though the user answers invitations
    let msrp = group_invitation(&client, &mut peer, "group-known");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-known"));
    peer.next_request("SUBSCRIBE");
    let _connection = msrp.accept(&client.rt);
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
}

/// A token as RCC.16 section 7.2.4 has them, with each kind of character
const TOKEN: &str = "Focus.1!%*_+`'~z";

#[test]
fn the_mls_opaque_token_of_a_group_is_carried_by_its_requests_from_then_on() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, creating, subscribe, _) = new_group_with(
        &client,
        &mut peer,
        &format!("MLS-Opaque-Token: {}\r\n", TOKEN),
    );
    assert_eq!(header_value(&creating, "MLS-Opaque-Token"), "", "none yet");

    // kept by the app
    assert_eq!(
        client.group_ids.recv_timeout(Duration::from_secs(5)),
        Ok(GroupIds {
            conference_uri: String::from(GROUP),
            conversation_id: header_value(&creating, "Conversation-ID"),
            contribution_id: header_value(&creating, "Contribution-ID"),
            mls_opaque_token: Some(String::from(TOKEN)),
        })
    );

    // and carried by the requests of the conversation
    assert_eq!(header_value(&subscribe, "MLS-Opaque-Token"), TOKEN);
    assert!(client
        .sessions
        .add_participants(GROUP, &[String::from("tel:+15550004")], |_, _| {}));
    let refer = peer.next_request("REFER");
    assert_eq!(header_value(&refer, "MLS-Opaque-Token"), TOKEN);
    peer.send(&answer(&refer, "202 Accepted", None));
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    assert_eq!(header_value(&bye, "MLS-Opaque-Token"), TOKEN);
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));

    // in sessions to come too, the focus not giving it again
    let msrp = MsrpPeer::listen(&rt);
    let result = leave(&client, GROUP);
    let restart = peer.next_request("INVITE");
    assert_eq!(header_value(&restart, "MLS-Opaque-Token"), TOKEN);
    peer.send(&answer_from(
        &restart,
        "200 OK",
        &focus_contact(),
        Some(&msrp.sdp("sendrecv")),
    ));
    let requests = next_requests(&mut peer, &["ACK", "SUBSCRIBE", "BYE"]);
    assert_eq!(header_value(&requests[1], "MLS-Opaque-Token"), TOKEN);
    assert_eq!(header_value(&requests[2], "MLS-Opaque-Token"), TOKEN);
    peer.send(&answer(&requests[2], "200 OK", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));
    assert!(
        client
            .group_ids
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "the same ids told again"
    );
}

#[test]
fn a_new_mls_opaque_token_from_the_focus_replaces_the_one_kept() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    client.sessions.remember_group_ids(GroupIds {
        conference_uri: String::from(GROUP),
        conversation_id: String::from("conversation-1"),
        contribution_id: String::from("contribution-1"),
        mls_opaque_token: Some(String::from("first")),
    });

    // restarted by the focus, with a new one
    let msrp = MsrpPeer::listen(&rt);
    peer.send(&invite(
        "group-new-token",
        &focus_contact(),
        FOCUS,
        "cpm.session",
        "MLS-Opaque-Token: second\r\n",
        "application/sdp",
        &msrp.sdp("sendrecv"),
    ));
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-new-token"));
    let subscribe = peer.next_request("SUBSCRIBE");
    assert_eq!(header_value(&subscribe, "MLS-Opaque-Token"), "second");
    let _connection = msrp.accept(&rt);
    assert_eq!(
        client
            .group_ids
            .recv_timeout(Duration::from_secs(5))
            .map(|ids| ids.mls_opaque_token),
        Ok(Some(String::from("second")))
    );
}

#[test]
fn an_mls_opaque_token_given_back_is_carried_by_the_restart() {
    let (client, mut peer) = start(true);
    client.sessions.remember_group_ids(GroupIds {
        conference_uri: String::from(GROUP),
        conversation_id: String::from("conversation-1"),
        contribution_id: String::from("contribution-1"),
        mls_opaque_token: Some(String::from(TOKEN)),
    });
    let _sent = client.send(GROUP, RecipientType::Group, "back");
    let restart = peer.next_request("INVITE");
    assert_eq!(header_value(&restart, "Conversation-ID"), "conversation-1");
    assert_eq!(header_value(&restart, "MLS-Opaque-Token"), TOKEN);

    // nor one given back that is not one
    client.sessions.remember_group_ids(GroupIds {
        conference_uri: String::from("sip:conf8@conf.example.com"),
        conversation_id: String::from("conversation-8"),
        contribution_id: String::from("contribution-8"),
        mls_opaque_token: Some(String::from("token\r\nInjected: header")),
    });
    let _sent = client.send("sip:conf8@conf.example.com", RecipientType::Group, "back");
    let restart = peer.next_request("INVITE");
    assert_eq!(header_value(&restart, "Conversation-ID"), "conversation-8");
    assert_eq!(header_value(&restart, "MLS-Opaque-Token"), "");
    assert_eq!(header_value(&restart, "Injected"), "");

    // and not by the requests to other groups
    let other = "sip:conf9@conf.example.com";
    let _sent = client.send(other, RecipientType::Group, "hello");
    let invite = peer.next_request("INVITE");
    assert_eq!(request_uri(&invite), other);
    assert_eq!(header_value(&invite, "MLS-Opaque-Token"), "");
}

#[test]
fn the_mls_opaque_token_of_another_conversation_is_not_carried() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    client.sessions.remember_group_ids(GroupIds {
        conference_uri: String::from(GROUP),
        conversation_id: String::from("conversation-0"),
        contribution_id: String::from("contribution-0"),
        mls_opaque_token: Some(String::from(TOKEN)),
    });

    // the group at the same URI, in another conversation, with no token
    let msrp = group_invitation(&client, &mut peer, "group-other-conversation");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-other-conversation"));
    let subscribe = peer.next_request("SUBSCRIBE");
    assert_eq!(header_value(&subscribe, "MLS-Opaque-Token"), "");
    let _connection = msrp.accept(&rt);
    assert_eq!(
        client
            .group_ids
            .recv_timeout(Duration::from_secs(5))
            .map(|ids| (ids.conversation_id, ids.mls_opaque_token)),
        Ok((String::from("conversation-1"), None))
    );
}

#[test]
fn an_mls_opaque_token_not_one_is_not_taken() {
    for not_one in [
        "",
        "two words",
        "semi;colon",
        "quoted\"",
        "<angle>",
        "at@host",
    ] {
        let (client, mut peer) = start(true);
        let (_connection, _creating, subscribe, _) = new_group_with(
            &client,
            &mut peer,
            &format!("MLS-Opaque-Token: {}\r\n", not_one),
        );
        assert_eq!(
            header_value(&subscribe, "MLS-Opaque-Token"),
            "",
            "{}",
            not_one
        );
        assert_eq!(
            client
                .group_ids
                .recv_timeout(Duration::from_secs(5))
                .map(|ids| ids.mls_opaque_token),
            Ok(None),
            "{}",
            not_one
        );
    }
}

#[test]
fn a_restart_by_the_focus_of_a_group_being_left_is_declined() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, _creating, _subscribe, _) = new_group(&client, &mut peer);
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));

    // left with no session: restarted first
    let msrp = MsrpPeer::listen(&rt);
    let result = leave(&client, GROUP);
    let restart = peer.next_request("INVITE");

    // the focus restarting it meanwhile is declined
    let _focus_msrp = group_invitation(&client, &mut peer, "group-crossing");
    assert_eq!(status_code(&peer.next_response()), 603);

    // and the group left once restarted
    peer.send(&answer_from(
        &restart,
        "200 OK",
        &focus_contact(),
        Some(&msrp.sdp("sendrecv")),
    ));
    let requests = next_requests(&mut peer, &["ACK", "SUBSCRIBE", "BYE"]);
    assert_eq!(header_value(&requests[2], "Reason"), LEAVING);
    peer.send(&answer(&requests[2], "200 OK", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));

    // no longer being left, an invitation is answered as any other
    let _msrp = group_invitation(&client, &mut peer, "group-later");
    assert_eq!(status_code(&peer.next_response()), 200);
}

/// What the scripted encryption makes a REFER adding participants carry
const ADDING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x01\x02adding";

/// The client with the group `conversation-1` encrypted, participants added
/// to it with ADDING_CPIM if `adding`
fn adding_to(client: &Client, adding: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        adding: adding.then(|| ADDING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// Adds the participants Carol and Dave to the group, what the client is
/// told of how the focus answered given to `result`
fn add_carol_and_dave(client: &Client) -> mpsc::Receiver<u16> {
    let (result_tx, result) = mpsc::channel();
    let result_tx = std::sync::Mutex::new(result_tx);
    assert!(client.sessions.add_participants(
        GROUP,
        &[
            String::from("sip:+15550003@example.com"),
            String::from("tel:+15550004")
        ],
        move |status_code, _| {
            let _ = result_tx.lock().unwrap().send(status_code);
        },
    ));
    result
}

#[test]
fn participants_are_added_to_an_encrypted_group_with_the_commit_in_the_refer() {
    let (client, mut peer) = start(true);
    let encryption = adding_to(&client, true);
    let (_connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-adding");
    let result = add_carol_and_dave(&client);

    let refer = peer.next_request("REFER");
    assert_eq!(request_uri(&refer), GROUP);
    assert_eq!(header_value(&refer, "Require"), "multiple-refer");
    assert!(header_value(&refer, "Content-Type").starts_with("multipart/mixed; boundary="));

    // the list, then the control message (RCC.16 section 9.2)
    let parts = parts_of(&refer);
    let content_types: Vec<&str> = parts.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        content_types,
        ["application/resource-lists+xml", "message/cpim"]
    );
    let list = String::from_utf8_lossy(&parts[0].1).into_owned();
    for entry in [
        "<entry uri=\"sip:+15550003@example.com\" cp:copyControl=\"to\"/>",
        "<entry uri=\"tel:+15550004\" cp:copyControl=\"to\"/>",
    ] {
        assert!(list.contains(entry), "{} in {}", entry, list);
    }
    assert_eq!(parts[1].1, ADDING_CPIM);
    let refer_to = header_value(&refer, "Refer-To");
    let content_id = refer_to.trim_start_matches("<cid:").trim_end_matches('>');
    let body = String::from_utf8_lossy(&body_data(&refer)).into_owned();
    assert!(
        body.contains(&format!(
            "Content-Disposition: recipient-list\r\nContent-ID: <{}>",
            content_id
        )),
        "the list by its Content-ID in {}",
        body
    );

    // made for the participants, in the group's MLS group
    assert_eq!(
        *encryption.added.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP),
            vec![
                String::from("sip:+15550003@example.com"),
                String::from("tel:+15550004")
            ]
        )]
    );
    peer.send(&answer(&refer, "202 Accepted", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(202));
    assert!(encryption.discarded.lock().unwrap().is_empty());
}

#[test]
fn the_commit_of_a_refer_the_focus_answers_with_an_error_is_let_go_of() {
    let (client, mut peer) = start(true);
    let encryption = adding_to(&client, true);
    let (_connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-conflict");

    for (status, warning, refusal_follows) in [
        // a refusal saying why to follow (RCC.16 section 9.2)
        ("409 Conflict", None, true),
        // or another warning only
        (
            "400 Bad Request",
            Some("399 operator.com \"122 Function not allowed\""),
            true,
        ),
        // none (section 7.2.6)
        (
            "400 Bad Request",
            Some("399 operator.com \"451 Non-MLS error\", 399 google.com \"122 Function not allowed\""),
            false,
        ),
    ] {
        let result = add_carol_and_dave(&client);
        let refer = peer.next_request("REFER");
        let mut response = answer(&refer, status, None);
        if let Some(warning) = warning {
            response = response.replacen(
                "Content-Length: 0",
                &format!("Warning: {}\r\nContent-Length: 0", warning),
                1,
            );
        }
        peer.send(&response);
        let status_code: u16 = status[..3].parse().unwrap();
        assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(status_code));
        assert_eq!(
            encryption.discarded.lock().unwrap().last(),
            Some(&(String::from("conversation-1"), refusal_follows)),
            "{} {:?}",
            status,
            warning
        );
    }
    assert_eq!(encryption.discarded.lock().unwrap().len(), 3);
}

#[test]
fn participants_that_cannot_be_added_to_an_encrypted_group_are_not_referred() {
    let (client, mut peer) = start(true);
    let encryption = adding_to(&client, false);
    let (_connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-refusing");

    let result = add_carol_and_dave(&client);
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(488));
    assert_eq!(encryption.added.lock().unwrap().len(), 1);
    peer.silence();
    assert!(encryption.discarded.lock().unwrap().is_empty());
}

/// Removes the participant Carol from the group, what the client is told
/// of how the focus answered given to `result`
fn remove_carol(client: &Client) -> mpsc::Receiver<u16> {
    let (result_tx, result) = mpsc::channel();
    let result_tx = std::sync::Mutex::new(result_tx);
    assert!(client.sessions.remove_participant(
        GROUP,
        "sip:+15550003@example.com",
        move |status_code, _| {
            let _ = result_tx.lock().unwrap().send(status_code);
        },
    ));
    result
}

#[test]
fn a_participant_is_removed_by_a_refer_asking_the_focus_to_send_a_bye() {
    let (client, mut peer) = start(true);
    let (_connection, invite, _subscribe, _) = new_group(&client, &mut peer);
    let result = remove_carol(&client);

    let refer = peer.next_request("REFER");
    assert_eq!(request_uri(&refer), GROUP, "to the focus");
    assert_eq!(
        header_value(&refer, "Call-ID"),
        header_value(&invite, "Call-ID"),
        "in the session's dialog"
    );
    assert_eq!(
        header_value(&refer, "Refer-To"),
        "<sip:+15550003@example.com;method=BYE>"
    );
    assert_eq!(header_value(&refer, "Refer-Sub"), "false");
    assert_eq!(header_value(&refer, "Require"), "", "one participant");
    let lengths: Vec<_> = refer
        .headers()
        .unwrap()
        .iter()
        .filter(|header| header.get_name().eq_ignore_ascii_case(b"Content-Length"))
        .map(|header| header.get_value().to_vec())
        .collect();
    assert_eq!(lengths, [b"0".to_vec()], "one Content-Length");
    assert!(body_data(&refer).is_empty());
    peer.send(&answer(&refer, "202 Accepted", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(202));

    // no group is not asked, nor a one-to-one chat
    assert!(!client
        .sessions
        .remove_participant("sip:conf9@conf.example.com", ALICE, |_, _| {}));
    let _one_to_one = incoming_chat(&client, &mut peer, "one-to-one-removal");
    assert!(!client.sessions.remove_participant(PEER, ALICE, |_, _| {}));
}

/// What the scripted encryption makes a REFER removing a participant carry
const REMOVING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x03\x04removing";

/// The client with the group `conversation-1` encrypted, participants
/// removed from it with REMOVING_CPIM if `removing`
fn removing_from(client: &Client, removing: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        removing: removing.then(|| REMOVING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

#[test]
fn a_participant_is_removed_from_an_encrypted_group_with_the_commit_in_the_refer() {
    let (client, mut peer) = start(true);
    let encryption = removing_from(&client, true);
    let (_connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-removing");

    // a REFER the focus answers with an error, no refusal to follow
    let result = remove_carol(&client);
    let refer = peer.next_request("REFER");
    assert_eq!(
        header_value(&refer, "Refer-To"),
        "<sip:+15550003@example.com;method=BYE>"
    );
    assert_eq!(header_value(&refer, "Content-Type"), "message/cpim");
    assert_eq!(body_data(&refer), REMOVING_CPIM, "the control message");
    assert_eq!(
        *encryption.removed.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP),
            String::from("sip:+15550003@example.com")
        )]
    );
    peer.send(&answer(&refer, "400 Bad Request", None).replacen(
        "Content-Length: 0",
        "Warning: 399 operator.com \"451 Non-MLS error\"\r\nContent-Length: 0",
        1,
    ));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(400));
    assert_eq!(
        *encryption.discarded.lock().unwrap(),
        [(String::from("conversation-1"), false)]
    );

    // and one it accepts
    let result = remove_carol(&client);
    let refer = peer.next_request("REFER");
    peer.send(&answer(&refer, "202 Accepted", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(202));
    assert_eq!(encryption.discarded.lock().unwrap().len(), 1);
}

#[test]
fn a_participant_that_cannot_be_removed_from_an_encrypted_group_is_not_referred() {
    let (client, mut peer) = start(true);
    let encryption = removing_from(&client, false);
    let (_connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-not-removing");

    let result = remove_carol(&client);
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(488));
    assert_eq!(encryption.removed.lock().unwrap().len(), 1);
    peer.silence();
    assert!(encryption.discarded.lock().unwrap().is_empty());
}

/// What the scripted encryption makes the BYE leaving a group carry
const LEAVING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x05\x06leaving";

/// The client with the group `conversation-1` encrypted, left with
/// LEAVING_CPIM if `leaving`
fn leaving_from(client: &Client, leaving: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        leaving: leaving.then(|| LEAVING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

#[test]
fn an_encrypted_group_is_left_with_the_self_remove_in_the_bye() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = leaving_from(&client, true);
    let (mut connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-leaving");

    let result = leave(&client, GROUP);
    let bye = peer.next_request("BYE");
    assert_eq!(request_uri(&bye), GROUP, "to the focus");
    assert_eq!(header_value(&bye, "Reason"), LEAVING);
    assert_eq!(header_value(&bye, "Content-Type"), "message/cpim");
    assert_eq!(body_data(&bye), LEAVING_CPIM, "the control message");
    let lengths: Vec<_> = bye
        .headers()
        .unwrap()
        .iter()
        .filter(|header| header.get_name().eq_ignore_ascii_case(b"Content-Length"))
        .map(|header| header.get_value().to_vec())
        .collect();
    assert_eq!(lengths, [format!("{}", LEAVING_CPIM.len()).into_bytes()]);
    assert_eq!(
        *encryption.left.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP)
        )]
    );
    connection.closed(&rt);

    // the MLS group let go of once the focus agrees (RCC.16 section 9.4)
    std::thread::sleep(Duration::from_millis(100));
    assert!(encryption.abandoned.lock().unwrap().is_empty());
    peer.send(&answer(&bye, "200 OK", None));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));
    assert_eq!(*encryption.abandoned.lock().unwrap(), ["conversation-1"]);
    assert!(encryption.discarded.lock().unwrap().is_empty());
    assert!(!client.sessions.has_session_with(GROUP));
}

#[test]
fn the_self_remove_of_a_bye_the_focus_answers_with_an_error_is_let_go_of() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = leaving_from(&client, true);
    let (mut connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-not-left");

    let result = leave(&client, GROUP);
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "400 Bad Request", None).replacen(
        "Content-Length: 0",
        "Warning: 399 operator.com \"451 Non-MLS error\"\r\nContent-Length: 0",
        1,
    ));
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(400));
    assert_eq!(
        *encryption.discarded.lock().unwrap(),
        [(String::from("conversation-1"), false)]
    );
    assert!(encryption.abandoned.lock().unwrap().is_empty());
}

#[test]
fn an_encrypted_group_that_cannot_be_left_is_not_sent_a_bye() {
    let (client, mut peer) = start(true);
    let encryption = leaving_from(&client, false);
    let (_connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-staying");

    let result = leave(&client, GROUP);
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(488));
    assert_eq!(encryption.left.lock().unwrap().len(), 1);
    peer.silence();
    // the session going on as before
    assert!(client.sessions.has_session_with(GROUP));
    assert!(encryption.discarded.lock().unwrap().is_empty());
    assert!(encryption.abandoned.lock().unwrap().is_empty());
}

#[test]
fn a_leave_whose_session_ends_while_it_is_made_is_let_go_of() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let held = Arc::new(tokio::sync::Notify::new());
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        leaving: Some(LEAVING_CPIM.to_vec()),
        leave_held: Some(Arc::clone(&held)),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-ending");

    let result = leave(&client, GROUP);
    // the session ended meanwhile, for the time being only
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    assert_eq!(header_value(&bye, "Reason"), "", "not leaving the group");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));

    held.notify_one();
    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(481));
    assert_eq!(
        *encryption.discarded.lock().unwrap(),
        [(String::from("conversation-1"), false)]
    );
    assert!(encryption.abandoned.lock().unwrap().is_empty());
    peer.silence();
}

/// What the scripted encryption makes a Commit of the leaves of others, or
/// of a removal by the server, carry
const COMMITTING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x07\x08committing";

/// The client with the group `conversation-1` encrypted, what the focus
/// sends of it carrying Proposals, the leaves of others and removals by the
/// server committed with COMMITTING_CPIM
fn committing_in(client: &Client) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        proposing: true,
        committing: Some(COMMITTING_CPIM.to_vec()),
        removing_for_server: Some(COMMITTING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// A CPIM message of the focus carrying the `message/mls-rcs-server`
/// `content`
fn from_the_focus(content: &str) -> String {
    format!(
        "From: <{}>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:01.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: focus-1\r\n\r\nContent-Type: message/mls-rcs-server\r\n\r\n{}",
        GROUP, IMPU, content
    )
}

#[test]
fn a_leave_the_focus_forwards_is_committed_in_the_session() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = committing_in(&client);
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-committing");

    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &from_the_focus("a leave"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));

    // the Commit, as it is, for the focus (RCC.16 sections 9.4, 9.5.1)
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(send.body, COMMITTING_CPIM);
    assert_eq!(
        *encryption.committed.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP)
        )]
    );
    connection.respond(&rt, &send, "200 OK");
    std::thread::sleep(Duration::from_millis(100));
    assert!(encryption.discarded.lock().unwrap().is_empty());

    // one the focus does not take is let go of, no refusal to follow
    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &from_the_focus("another leave"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let send = connection.next_message(&rt);
    connection.respond(&rt, &send, "403 Forbidden");
    let discarded = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.discarded.lock().unwrap().is_empty()
    });
    assert!(discarded);
    assert_eq!(
        *encryption.discarded.lock().unwrap(),
        [(String::from("conversation-1"), false)]
    );
}

#[test]
fn a_participant_the_server_removed_is_committed_out_in_the_session() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = committing_in(&client);
    let msrp = encrypted_group_invitation(&client, &mut peer, "group-removed");
    let ok = peer.next_response();
    peer.send(&ack(&ok, "group-removed"));
    let subscribe = peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);

    let notify = |seq: u32, user: &str, reason: &str| {
        conference_notify(
            &subscribe,
            seq,
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" entity=\"{}\" \
state=\"partial\" version=\"{}\"><users><user entity=\"{}\"><endpoint entity=\"{}\">\
<status>disconnected</status><disconnection-method>booted</disconnection-method>\
<disconnection-info><reason>{}</reason></disconnection-info></endpoint></user></users>\
</conference-info>",
                GROUP, seq, user, user, reason
            ),
        )
    };

    // one removed by a participant, whose Commit came with the REFER
    peer.send(&notify(1, ALICE, "SIP;cause=410;text=&quot;Kicked&quot;"));
    assert_eq!(status_code(&peer.next_response()), 200);
    // one the Messaging Server removed (RCC.16 section 9.6)
    peer.send(&notify(
        2,
        BOB,
        "SIP;cause=410;text=&quot;Removed by server&quot;",
    ));
    assert_eq!(status_code(&peer.next_response()), 200);

    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(send.body, COMMITTING_CPIM);
    assert_eq!(
        *encryption.removed_for_server.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP),
            String::from(BOB)
        )]
    );
    connection.respond(&rt, &send, "200 OK");
    assert!(encryption.committed.lock().unwrap().is_empty());
}

#[test]
fn a_participant_the_server_removed_from_a_group_not_encrypted_is_not_committed_out() {
    let (client, mut peer) = start(true);
    let (_connection, _invite, subscribe, _) = new_group(&client, &mut peer);
    // set once the group is started without it
    let encryption = committing_in(&client);
    peer.send(&conference_notify(
        &subscribe,
        1,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" entity=\"{}\" \
state=\"partial\" version=\"1\"><users><user entity=\"{}\"><endpoint entity=\"{}\">\
<status>disconnected</status><disconnection-method>booted</disconnection-method>\
<disconnection-info><reason>SIP;cause=410;text=&quot;Removed by server&quot;</reason>\
</disconnection-info></endpoint></user></users></conference-info>",
            GROUP, BOB, BOB
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    std::thread::sleep(Duration::from_millis(200));
    assert!(encryption.removed_for_server.lock().unwrap().is_empty());
}

/// What the scripted encryption makes the External Commit of a self-healing
/// carry
const HEALING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x09\x0bhealing";

/// The client with the group `conversation-1` encrypted and out of step with
/// its focus: healed by asking for the enhanced GroupInfo, then for the
/// GroupInfo, and sending HEALING_CPIM
fn healing_in(client: &Client) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        out_of_step: std::sync::atomic::AtomicBool::new(true),
        pulling: vec![
            (
                &b"MLS-Enhanced-Group-Info-Pull"[..],
                Some(b"epoch 1".to_vec()),
            ),
            (&b"MLS-Group-Info-Pull"[..], None),
        ],
        healing: Some(HEALING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

#[test]
fn a_group_out_of_step_is_healed_with_info_requests_in_its_session() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = healing_in(&client);
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-healing");

    // a message the encryption cannot decrypt
    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &encrypted_group_cpim("tel:+15550002", "", "not to be decrypted"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));

    // the enhanced GroupInfo asked for in the session's dialog (RCC.16
    // sections 6.3.2, 7.10.2)
    let info = peer.next_request("INFO");
    assert_eq!(request_uri(&info), GROUP, "to the focus");
    assert_eq!(header_value(&info, "Call-ID"), "group-healing");
    assert_eq!(
        header_value(&info, "Info-Package"),
        "MLS-Enhanced-Group-Info-Pull"
    );
    assert_eq!(header_value(&info, "Content-Type"), "message/mls-rcs");
    assert_eq!(header_value(&info, "Content-Disposition"), "Info-Package");
    assert_eq!(body_data(&info), b"epoch 1");
    peer.send(
        &answer(&info, "200 OK", Some("a page"))
            .replace("application/sdp", "message/mls-rcs-server"),
    );

    // then the GroupInfo (section 6.3.1)
    let info = peer.next_request("INFO");
    assert_eq!(header_value(&info, "Info-Package"), "MLS-Group-Info-Pull");
    assert_eq!(header_value(&info, "Content-Type"), "");
    assert!(body_data(&info).is_empty());
    peer.send(&answer(&info, "469 Bad Info Package", None));

    // the External Commit sent to the focus, as it is (section 9.5.1)
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(send.body, HEALING_CPIM);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        *encryption.healed.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP),
            vec![Some((200, b"a page".to_vec())), Some((469, Vec::new()))]
        )]
    );
}

#[test]
fn what_the_focus_sends_of_a_group_out_of_step_has_it_healed() {
    for (call_id, cpim) in [
        (
            "group-healing-1",
            encrypted_group_cpim("tel:+15550002", "", "not to be decrypted"),
        ),
        // a refusal saying it is out of step
        ("group-healing-2", group_imdn_cpim("message-1", REFUSED)),
        // or a control message that cannot be applied
        ("group-healing-3", from_the_focus("not to be applied")),
    ] {
        let (client, mut peer) = start(true);
        let rt = Arc::clone(&client.rt);
        let encryption = healing_in(&client);
        let (mut connection, msrp_path, our_path) =
            joined_encrypted_group(&client, &mut peer, call_id);
        connection.send_content(&rt, &msrp_path, &our_path, "message/cpim", &cpim);
        assert!(connection.next_response(&rt).first_line.contains(" 200"));

        let info = peer.next_request("INFO");
        assert_eq!(
            header_value(&info, "Info-Package"),
            "MLS-Enhanced-Group-Info-Pull",
            "{}",
            call_id
        );
        peer.send(&answer(&info, "469 Bad Info Package", None));
        let info = peer.next_request("INFO");
        peer.send(&answer(&info, "469 Bad Info Package", None));
        let send = connection.next_message(&rt);
        connection.respond(&rt, &send, "200 OK");
        assert_eq!(encryption.healed.lock().unwrap().len(), 1, "{}", call_id);
    }
}

#[test]
fn a_group_in_step_is_not_healed() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = healing_in(&client);
    encryption
        .out_of_step
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-in-step");
    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &from_the_focus("a control message"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    peer.silence();
    assert!(encryption.healed.lock().unwrap().is_empty());
}

#[test]
fn the_info_requests_of_a_self_healing_carry_the_mls_opaque_token() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        out_of_step: std::sync::atomic::AtomicBool::new(true),
        pulling: vec![(
            &b"MLS-Enhanced-Group-Info-Pull"[..],
            Some(b"epoch 1".to_vec()),
        )],
        ..ScriptedEncryption::default()
    });
    client.sessions.set_group_encryption(
        Arc::new(EncryptingPrepared(Arc::clone(&encryption))) as Arc<dyn GroupEncryption>
    );
    let (mut connection, invite, _subscribe, msrp_path) = new_group_with(
        &client,
        &mut peer,
        &format!("MLS-Opaque-Token: {}\r\n", TOKEN),
    );
    let sdp = String::from_utf8_lossy(&parts_of(&invite)[0].1).into_owned();
    let our_path = sdp_attribute(&sdp, "path").expect("an a=path in the offer");

    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &encrypted_group_cpim("tel:+15550002", "", "not to be decrypted"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let info = peer.next_request("INFO");
    assert_eq!(header_value(&info, "MLS-Opaque-Token"), TOKEN);
    peer.send(&answer(&info, "469 Bad Info Package", None));
    let healed = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.healed.lock().unwrap().is_empty()
    });
    assert!(healed);
}

/// What the scripted encryption makes a Commit moving a group to unencrypted
/// carry
const ENDING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x0b\x0cending";

/// The client with the group `conversation-1` encrypted, its notifications
/// signed and moved to unencrypted with ENDING_CPIM, the encryption otherwise
/// as `scripted`
fn ending_in(client: &Client, scripted: ScriptedEncryption) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        verifying: true,
        ending: Some(ENDING_CPIM.to_vec()),
        ..scripted
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

#[test]
fn what_a_client_not_encrypting_sends_moves_the_group_to_unencrypted() {
    for (call_id, scripted, cpim, reason) in [
        // a message
        (
            "group-ending-1",
            ScriptedEncryption::default(),
            group_cpim(ALICE, "", "plain"),
            EndReason::ClientFailureEncryptionNotAvailable,
        ),
        (
            "group-ending-2",
            ScriptedEncryption::default(),
            group_cpim(ALICE, "", "<file/>")
                .replace("text/plain", "application/vnd.gsma.rcs-ft-http+xml"),
            EndReason::ClientFailureEncryptionNotAvailable,
        ),
        // a notification not signed
        (
            "group-ending-3",
            ScriptedEncryption {
                unsigned: true,
                ..ScriptedEncryption::default()
            },
            group_imdn_cpim("message-1", "<delivered/>"),
            EndReason::ClientFailureEncryptionNotAvailable,
        ),
        // the focus telling a recipient cannot decrypt
        (
            "group-ending-4",
            ScriptedEncryption {
                unavailable: true,
                ..ScriptedEncryption::default()
            },
            group_imdn_cpim(
                "message-1",
                "<failed><mls-server-failure-reason><encryption-not-available/></mls-server-failure-reason></failed>",
            ),
            EndReason::ServerFailureEncryptionNotAvailable,
        ),
    ] {
        let (client, mut peer) = start(true);
        let rt = Arc::clone(&client.rt);
        let encryption = ending_in(&client, scripted);
        let (mut connection, msrp_path, our_path) =
            joined_encrypted_group(&client, &mut peer, call_id);
        connection.send_content(&rt, &msrp_path, &our_path, "message/cpim", &cpim);
        assert!(connection.next_response(&rt).first_line.contains(" 200"));

        // given to the app all the same
        assert!(
            client.received.recv_timeout(Duration::from_secs(5)).is_ok(),
            "{}",
            call_id
        );
        // the Commit, as it is, for the focus (RCC.16 sections 9.5.1, 11.2)
        let send = connection.next_message(&rt);
        assert_eq!(send.header("Content-Type"), Some("message/cpim"));
        assert_eq!(send.body, ENDING_CPIM, "{}", call_id);
        connection.respond(&rt, &send, "200 OK");
        assert_eq!(
            *encryption.ended.lock().unwrap(),
            [(
                String::from("conversation-1"),
                String::from(IMPU),
                String::from(GROUP),
                reason
            )],
            "{}",
            call_id
        );
    }
}

#[test]
fn what_is_not_an_rcs_message_does_not_move_the_group_to_unencrypted() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = ending_in(&client, ScriptedEncryption::default());
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-not-ending");

    // an is-composing, a notification signed, nor what the focus sends
    for (content_type, content) in [
        (
            "application/im-iscomposing+xml",
            super::is_composing_document(true),
        ),
        ("message/cpim", group_imdn_cpim("message-1", "<delivered/>")),
        ("message/cpim", from_the_focus("a control message")),
    ] {
        connection.send_content(&rt, &msrp_path, &our_path, content_type, &content);
        assert!(connection.next_response(&rt).first_line.contains(" 200"));
    }
    for _ in 0..2 {
        assert!(client.received.recv_timeout(Duration::from_secs(5)).is_ok());
    }

    // only a message the next does
    connection.send_cpim(&rt, &msrp_path, &our_path, &group_cpim(ALICE, "", "plain"));
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("plain"))
    );
    let send = connection.next_message(&rt);
    assert_eq!(send.body, ENDING_CPIM);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(encryption.ended.lock().unwrap().len(), 1);
    // nor did the app hear of it moving to unencrypted
    assert!(client
        .group_events
        .try_iter()
        .all(|event| !event.starts_with("unencrypted")));
}

#[test]
fn the_messages_of_a_group_moved_to_unencrypted_are_sent_as_they_are() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = ending_in(
        &client,
        ScriptedEncryption {
            unencrypted: true,
            ciphertext: Some(String::from(CIPHERTEXT)),
            ..ScriptedEncryption::default()
        },
    );
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-unencrypted");

    let result = client.send_with_id(GROUP, RecipientType::Group, "hello all", "plain-1");
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    let cpim = CPIMMessage::try_from(&Body::construct_message(&send.body).unwrap()).unwrap();
    assert_eq!(
        id_and_dispositions(&cpim),
        (String::from("plain-1"), DELIVERY_AND_DISPLAY)
    );
    assert_eq!(cpim_text(&send.body), "hello all");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    assert_eq!(encryption.encrypted.lock().unwrap().len(), 1);

    // nor is it moved to unencrypted again by what others send so
    connection.send_cpim(&rt, &msrp_path, &our_path, &group_cpim(ALICE, "", "plain"));
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    assert_eq!(
        client
            .received
            .recv_timeout(Duration::from_secs(5))
            .map(|r| r.2),
        Ok(String::from("plain"))
    );
    assert!(encryption.ended.lock().unwrap().is_empty());
    connection.quiet(&rt);
}

#[test]
fn a_group_moved_to_unencrypted_is_told_to_the_app() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = ending_in(
        &client,
        ScriptedEncryption {
            ending_by_focus: true,
            ..ScriptedEncryption::default()
        },
    );
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-ended");

    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &from_the_focus("an end_mls Commit"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let unencrypted = format!("unencrypted {}", GROUP);
    let told = std::iter::from_fn(|| {
        client
            .group_events
            .recv_timeout(Duration::from_secs(5))
            .ok()
    })
    .any(|event| event == unencrypted);
    assert!(told);
    assert_eq!(encryption.server_messages.lock().unwrap().len(), 1);
    // nothing sent of it
    assert!(encryption.ended.lock().unwrap().is_empty());
    connection.quiet(&rt);
}

/// What the scripted encryption makes a key update carry
const UPDATING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x0d\x0eupdating";

/// The client with the group `conversation-1` encrypted as CIPHERTEXT, its
/// keys updated with UPDATING_CPIM, a key update due if `due`
fn updating_in(client: &Client, due: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        ciphertext: Some(String::from(CIPHERTEXT)),
        keys_due: due,
        updating: Some(UPDATING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

#[test]
fn the_keys_of_an_encrypted_group_are_updated_as_its_session_starts() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = updating_in(&client, false);
    let (mut connection, _, _) = joined_encrypted_group(&client, &mut peer, "group-updating");

    // the Commit, as it is, for the focus (RCC.16 sections 9.5.1, 9.5.2)
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(send.body, UPDATING_CPIM);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        *encryption.updated.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP)
        )]
    );
    connection.quiet(&rt);
}

#[test]
fn the_keys_are_updated_after_a_message_once_due() {
    for due in [true, false] {
        let (client, mut peer) = start(true);
        let rt = Arc::clone(&client.rt);
        let encryption = updating_in(&client, due);
        let (mut connection, _, _) =
            joined_encrypted_group(&client, &mut peer, "group-updating-later");
        let send = connection.next_message(&rt);
        assert_eq!(send.body, UPDATING_CPIM);
        connection.respond(&rt, &send, "200 OK");

        // the message and, once due, the Commit, which each go out in a task
        // of their own, the Commit maybe first
        let result = client.send(GROUP, RecipientType::Group, "hello all");
        let mut sent = Vec::new();
        for _ in 0..if due { 2 } else { 1 } {
            let send = connection.next_message(&rt);
            sent.push(send.body.clone());
            connection.respond(&rt, &send, "200 OK");
        }
        assert_eq!(
            result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
            Ok(200)
        );
        sent.sort();
        let mut expected = vec![CIPHERTEXT.as_bytes().to_vec()];
        if due {
            expected.push(UPDATING_CPIM.to_vec());
        }
        expected.sort();
        assert_eq!(sent, expected, "due {}", due);
        connection.quiet(&rt);
        assert_eq!(
            encryption.updated.lock().unwrap().len(),
            if due { 2 } else { 1 },
            "due {}",
            due
        );
    }
}

#[test]
fn the_keys_are_updated_after_a_message_received_once_due() {
    for due in [true, false] {
        let (client, mut peer) = start(true);
        let rt = Arc::clone(&client.rt);
        let encryption = Arc::new(ScriptedEncryption {
            cpim: Some(MLS_GROUP_CPIM.to_vec()),
            joining: true,
            encrypting: vec![String::from("conversation-1")],
            plaintext: Some(encrypted_group_cpim(ALICE, "", "unused").replace(
                "Content-Type: message/mls\r\n\r\nunused",
                "Content-Type: text/plain\r\n\r\nhello",
            )),
            keys_due: due,
            updating: Some(UPDATING_CPIM.to_vec()),
            ..ScriptedEncryption::default()
        });
        client
            .sessions
            .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
        let (mut connection, msrp_path, our_path) =
            joined_encrypted_group(&client, &mut peer, "group-updating-on-receipt");
        let send = connection.next_message(&rt);
        assert_eq!(send.body, UPDATING_CPIM);
        connection.respond(&rt, &send, "200 OK");

        connection.send_content(
            &rt,
            &msrp_path,
            &our_path,
            "message/cpim",
            &encrypted_group_cpim(ALICE, "", "ciphertext"),
        );
        assert!(connection.next_response(&rt).first_line.contains(" 200"));
        assert_eq!(
            client
                .received
                .recv_timeout(Duration::from_secs(5))
                .map(|r| r.2),
            Ok(String::from("hello"))
        );
        if due {
            let send = connection.next_message(&rt);
            assert_eq!(send.body, UPDATING_CPIM);
            connection.respond(&rt, &send, "200 OK");
        }
        connection.quiet(&rt);
        assert_eq!(
            encryption.updated.lock().unwrap().len(),
            if due { 2 } else { 1 },
            "due {}",
            due
        );
    }
}

/// The group the client joined with `invitation`, accepted, its session
/// ended since
fn group_left_for_now(
    client: &Client,
    peer: &mut Peer,
    invitation: fn(&Client, &mut Peer, &str) -> MsrpPeer,
) {
    let rt = Arc::clone(&client.rt);
    let msrp = invitation(client, peer, "group-first");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    peer.send(&ack(&ok, "group-first"));
    peer.next_request("SUBSCRIBE");
    let mut connection = msrp.accept(&rt);
    assert!(client
        .group_invites
        .recv_timeout(Duration::from_secs(5))
        .is_ok());
    assert!(next_group_event(client).contains(" accepted"));
    assert_eq!(next_group_event(client), format!("joined {}", GROUP));
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));
    assert_eq!(next_group_event(client), format!("left {}", GROUP));
}

#[test]
fn a_group_its_focus_restarts_with_a_new_era_joins_it_at_once() {
    let (client, mut peer) = start(true);
    let encryption = joining(&client, true);
    group_left_for_now(&client, &mut peer, encrypted_group_invitation);

    // restarted by its focus with a new Era of its MLS group (RCC.16
    // section 8.3), taken at once, though the user answers invitations
    client.group_answer.store(180, Ordering::SeqCst);
    let msrp = encrypted_group_invitation(&client, &mut peer, "group-new-era");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert!(
        client.group_invites.try_recv().is_err(),
        "the user not asked"
    );
    assert_eq!(
        *encryption.joined.lock().unwrap(),
        [
            (String::from("conversation-1"), WELCOME.to_vec()),
            (String::from("conversation-1"), WELCOME.to_vec())
        ]
    );
    // its session taking what the focus sends of the MLS group
    assert!(sdp_attribute(&body(&ok), "accept-wrapped-types")
        .unwrap()
        .ends_with(" message/mls message/mls-rcs-server"));
    peer.send(&ack(&ok, "group-new-era"));
    peer.next_request("SUBSCRIBE");
    let _connection = msrp.accept(&client.rt);
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
}

#[test]
fn a_group_restarted_with_an_mls_group_it_cannot_join_is_taken_part_in_still() {
    let (client, mut peer) = start(true);
    let encryption = joining(&client, false);
    group_left_for_now(&client, &mut peer, group_invitation);

    let msrp = encrypted_group_invitation(&client, &mut peer, "group-new-era");
    let ok = peer.next_response();
    assert_eq!(status_code(&ok), 200);
    assert_eq!(
        *encryption.joined.lock().unwrap(),
        [(String::from("conversation-1"), WELCOME.to_vec())]
    );
    // unencrypted
    assert!(!sdp_attribute(&body(&ok), "accept-wrapped-types")
        .unwrap()
        .contains("message/mls"));
    peer.send(&ack(&ok, "group-new-era"));
    peer.next_request("SUBSCRIBE");
    let _connection = msrp.accept(&client.rt);
    assert_eq!(next_group_event(&client), format!("joined {}", GROUP));
}

/// What the scripted encryption makes the INVITE of a new Era carry
const NEXT_ERA_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x0a\x08next era";

/// The client with the group `conversation-1` encrypted, a new Era of it
/// due as self-healing it failed, which is made as NEXT_ERA_CPIM if
/// `made`; the session with the group, its MSRP connection, once a message
/// it cannot decrypt came, and the INFO asking the focus for the GroupInfo
/// in its dialog, unanswered
fn new_era_asked_for(
    client: &Client,
    peer: &mut Peer,
    made: bool,
) -> (Arc<ScriptedEncryption>, MsrpConnection, SipMessage) {
    let rt = Arc::clone(&client.rt);
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        era_due: std::sync::atomic::AtomicBool::new(true),
        next_era: made.then(|| NEXT_ERA_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(client, peer, "group-old-era");
    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &encrypted_group_cpim("tel:+15550002", "", "not to be decrypted"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));

    // the GroupInfo asked for in the session's dialog (RCC.16 section 6.3.1)
    let info = peer.next_request("INFO");
    assert_eq!(header_value(&info, "Call-ID"), "group-old-era");
    assert_eq!(header_value(&info, "Info-Package"), "MLS-Group-Info-Pull");
    (encryption, connection, info)
}

/// The GroupInfo the focus gives for `info`
fn group_info_given(peer: &mut Peer, info: &SipMessage) {
    peer.send(
        &answer(info, "200 OK", Some("the group info"))
            .replace("application/sdp", "message/mls-rcs-server"),
    );
}

/// As new_era_asked_for(), the GroupInfo given
fn new_era_due(
    client: &Client,
    peer: &mut Peer,
    made: bool,
) -> (Arc<ScriptedEncryption>, MsrpConnection) {
    let (encryption, connection, info) = new_era_asked_for(client, peer, made);
    group_info_given(peer, &info);
    (encryption, connection)
}

/// The INVITE restarting the group, once its session ended, answered with
/// `status`
fn restart_in_new_era(
    client: &Client,
    peer: &mut Peer,
    mut connection: MsrpConnection,
    status: &str,
) -> SipMessage {
    let rt = Arc::clone(&client.rt);
    let bye = peer.next_request("BYE");
    assert_eq!(header_value(&bye, "Call-ID"), "group-old-era");
    connection.closed(&rt);
    // nothing restarted before the session ended
    assert!(peer.next_within(Duration::from_millis(200)).is_none());
    peer.send(&answer(&bye, "200 OK", None));

    let restart = peer.next_request("INVITE");
    assert_eq!(request_uri(&restart), GROUP);
    assert_eq!(header_value(&restart, "Conversation-ID"), "conversation-1");
    match status {
        "200 OK" => {
            let msrp = MsrpPeer::listen(&rt);
            peer.send(&answer_from(
                &restart,
                status,
                &focus_contact(),
                Some(&msrp.sdp("sendrecv")),
            ));
            next_requests(peer, &["ACK", "SUBSCRIBE"]);
            let _connection = msrp.accept(&rt);
        }
        _ => {
            peer.send(&answer(&restart, status, None));
            peer.next_request("ACK");
        }
    }
    restart
}

#[test]
fn a_group_whose_healing_failed_is_restarted_in_a_new_era() {
    let (client, mut peer) = start(true);
    let (encryption, connection) = new_era_due(&client, &mut peer, true);
    let restart = restart_in_new_era(&client, &mut peer, connection, "200 OK");

    // the INVITE carries the SDP and the new Era of its MLS group (RCC.16
    // sections 8.1, 8.3.1)
    let parts = parts_of(&restart);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].0, "application/sdp");
    assert_eq!(
        parts[1],
        (String::from("message/cpim"), NEXT_ERA_CPIM.to_vec())
    );
    assert_eq!(
        *encryption.eras.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP),
            Some((200, b"the group info".to_vec()))
        )]
    );
    assert!(encryption.discarded.lock().unwrap().is_empty());
}

#[test]
fn a_new_era_the_focus_refuses_is_told_how_it_was() {
    for (status, status_code) in [("409 Conflict", 409), ("403 Forbidden", 403)] {
        let (client, mut peer) = start(true);
        let (encryption, connection) = new_era_due(&client, &mut peer, true);
        restart_in_new_era(&client, &mut peer, connection, status);
        let refused = (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(20));
            !encryption.refused_eras.lock().unwrap().is_empty()
        });
        assert!(refused);
        // for its Commit to be discarded, and another Era made (RCC.16
        // sections 8.3.1, 10.1)
        assert_eq!(
            *encryption.refused_eras.lock().unwrap(),
            [(String::from("conversation-1"), status_code)]
        );
        assert!(encryption.discarded.lock().unwrap().is_empty());
    }
}

#[test]
fn a_session_whose_new_era_is_not_made_goes_on() {
    let (client, mut peer) = start(true);
    let (encryption, _connection) = new_era_due(&client, &mut peer, false);
    let made = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.eras.lock().unwrap().is_empty()
    });
    assert!(made);

    // the session not ended, nor the group restarted
    peer.silence();
    assert!(client.sessions.has_session_with(GROUP));
}

#[test]
fn a_new_era_made_once_the_session_ended_otherwise_is_discarded() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (encryption, mut connection, info) = new_era_asked_for(&client, &mut peer, true);

    // the session ended meanwhile, as when the user leaves
    assert!(client.sessions.end_session(GROUP));
    let bye = peer.next_request("BYE");
    connection.closed(&rt);
    peer.send(&answer(&bye, "200 OK", None));
    group_info_given(&mut peer, &info);

    let discarded = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.discarded.lock().unwrap().is_empty()
    });
    assert!(discarded);
    assert_eq!(
        *encryption.discarded.lock().unwrap(),
        [(String::from("conversation-1"), false)]
    );
    // the group not restarted
    peer.silence();
}

/// What the scripted encryption makes the Commit moving a group back to
/// encrypted carry
const UPGRADING_CPIM: &[u8] = b"From: <sip:+15551234@example.com>\r\n\r\nContent-Type: message/mls-rcs-client\r\n\r\n\x0a\x09upgrading";

/// The client with the group `conversation-1` encrypted, and moved to
/// unencrypted, to be moved back if `due`, which UPGRADING_CPIM does
fn upgrading_in(client: &Client, due: bool) -> Arc<ScriptedEncryption> {
    let encryption = Arc::new(ScriptedEncryption {
        cpim: Some(MLS_GROUP_CPIM.to_vec()),
        joining: true,
        encrypting: vec![String::from("conversation-1")],
        upgrade_wanted: std::sync::atomic::AtomicBool::new(due),
        upgrading: Some(UPGRADING_CPIM.to_vec()),
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// A conference-info document of `version`, `state` full or partial, with
/// each user and its endpoint status, and disconnection method if any
fn conference_info(version: u32, state: &str, users: &[(&str, &str, &str)]) -> String {
    let users: String = users
        .iter()
        .map(|(entity, status, method)| {
            format!(
                "<user entity=\"{}\"><endpoint entity=\"{}\"><status>{}</status>{}</endpoint></user>",
                entity,
                entity,
                status,
                if method.is_empty() {
                    String::new()
                } else {
                    format!("<disconnection-method>{}</disconnection-method>", method)
                }
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" entity=\"{}\" \
state=\"{}\" version=\"{}\"><users>{}</users></conference-info>",
        GROUP, state, version, users
    )
}

/// The session with the encrypted group `call_id` started, its MSRP
/// connection, and the SUBSCRIBE to its conference events
fn subscribed_to_encrypted_group(
    client: &Client,
    peer: &mut Peer,
    call_id: &str,
) -> (MsrpConnection, SipMessage) {
    let msrp = encrypted_group_invitation(client, peer, call_id);
    let ok = peer.next_response();
    peer.send(&ack(&ok, call_id));
    let subscribe = peer.next_request("SUBSCRIBE");
    let connection = msrp.accept(&client.rt);
    (connection, subscribe)
}

const CAROL: &str = "tel:+15550003";

#[test]
fn a_group_moved_to_unencrypted_is_moved_back_once_its_participants_are_told() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = upgrading_in(&client, true);
    let (mut connection, subscribe) =
        subscribed_to_encrypted_group(&client, &mut peer, "group-upgrading");

    // those taking part, connected or invited, the user among them, and not
    // one who departed (RCC.16 section 11.1)
    peer.send(&conference_notify(
        &subscribe,
        1,
        &conference_info(
            1,
            "full",
            &[
                (IMPU, "connected", ""),
                (ALICE, "connected", ""),
                (BOB, "pending", ""),
                (CAROL, "disconnected", "departed"),
            ],
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    let send = connection.next_message(&rt);
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    assert_eq!(send.body, UPGRADING_CPIM);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(
        *encryption.upgraded.lock().unwrap(),
        [(
            String::from("conversation-1"),
            String::from(IMPU),
            String::from(GROUP),
            vec![String::from(IMPU), String::from(ALICE), String::from(BOB)]
        )]
    );
    // first told, its membership did not change
    assert!(encryption.memberships_changed.lock().unwrap().is_empty());

    // a status changing is no change of membership
    peer.send(&conference_notify(
        &subscribe,
        2,
        &conference_info(2, "partial", &[(BOB, "connected", "")]),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    std::thread::sleep(Duration::from_millis(200));
    assert!(encryption.memberships_changed.lock().unwrap().is_empty());

    // one joining or leaving is
    for (version, user) in [
        (3, (CAROL, "connected", "")),
        (4, (ALICE, "disconnected", "booted")),
    ] {
        peer.send(&conference_notify(
            &subscribe,
            version,
            &conference_info(version, "partial", &[user]),
        ));
        assert_eq!(status_code(&peer.next_response()), 200);
    }
    let changed = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        encryption.memberships_changed.lock().unwrap().len() == 2
    });
    assert!(changed);
    assert_eq!(
        *encryption.memberships_changed.lock().unwrap(),
        [
            String::from("conversation-1"),
            String::from("conversation-1")
        ]
    );
    // not moved back again, as it is not due
    assert_eq!(encryption.upgraded.lock().unwrap().len(), 1);
    connection.quiet(&rt);
}

#[test]
fn a_group_not_due_to_move_back_to_encrypted_is_left_as_it_is() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = upgrading_in(&client, false);
    let (mut connection, subscribe) =
        subscribed_to_encrypted_group(&client, &mut peer, "group-not-upgrading");

    peer.send(&conference_notify(
        &subscribe,
        1,
        &conference_info(
            1,
            "full",
            &[(IMPU, "connected", ""), (BOB, "connected", "")],
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    std::thread::sleep(Duration::from_millis(200));
    assert!(encryption.upgraded.lock().unwrap().is_empty());
    connection.quiet(&rt);
}

#[test]
fn a_group_never_encrypted_is_restarted_with_its_first_era() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let (mut connection, invite, subscribe, _) = new_group(&client, &mut peer);
    let conversation_id = header_value(&invite, "Conversation-ID");
    // set once the group is started without it: the session has none, the
    // service has (RCC.16 section 11.1)
    let encryption = Arc::new(ScriptedEncryption {
        upgrade_wanted: std::sync::atomic::AtomicBool::new(true),
        upgrading: Some(NEXT_ERA_CPIM.to_vec()),
        upgrading_by_restart: true,
        ..ScriptedEncryption::default()
    });
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    peer.send(&conference_notify(
        &subscribe,
        1,
        &conference_info(
            1,
            "full",
            &[(IMPU, "connected", ""), (BOB, "connected", "")],
        ),
    ));
    assert_eq!(status_code(&peer.next_response()), 200);

    // the session ended, then the group restarted with the INVITE carrying
    // the Era (sections 8.1, 8.3.1)
    // the BYE, and the end of the subscription to the conference events,
    // in whatever order the transport takes them
    let ended = next_requests(&mut peer, &["BYE", "SUBSCRIBE"]);
    let (bye, unsubscribe) = (&ended[0], &ended[1]);
    assert_eq!(
        header_value(bye, "Call-ID"),
        header_value(&invite, "Call-ID")
    );
    assert_eq!(header_value(unsubscribe, "Expires"), "0");
    connection.closed(&rt);
    assert!(peer.next_within(Duration::from_millis(200)).is_none());
    peer.send(&answer(bye, "200 OK", None));
    let restart = peer.next_request("INVITE");
    assert_eq!(request_uri(&restart), GROUP);
    assert_eq!(header_value(&restart, "Conversation-ID"), conversation_id);
    let parts = parts_of(&restart);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].0, "application/sdp");
    assert_eq!(
        parts[1],
        (String::from("message/cpim"), NEXT_ERA_CPIM.to_vec())
    );
    assert_eq!(
        *encryption.upgraded.lock().unwrap(),
        [(
            conversation_id.clone(),
            String::from(IMPU),
            String::from(GROUP),
            vec![String::from(IMPU), String::from(BOB)]
        )]
    );

    // the Focus refusing it, it is told so
    peer.send(&answer(&restart, "403 Forbidden", None));
    peer.next_request("ACK");
    let refused = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        !encryption.refused_eras.lock().unwrap().is_empty()
    });
    assert!(refused);
    assert_eq!(
        *encryption.refused_eras.lock().unwrap(),
        [(conversation_id, 403)]
    );
}

#[test]
fn self_healing_moving_the_group_to_unencrypted_or_back_is_told_to_the_app() {
    for (unencrypted, flips, told) in [
        (false, true, Some("unencrypted")),
        (true, true, Some("encrypted")),
        (false, false, None),
    ] {
        let (client, mut peer) = start(true);
        let rt = Arc::clone(&client.rt);
        let encryption = Arc::new(ScriptedEncryption {
            cpim: Some(MLS_GROUP_CPIM.to_vec()),
            joining: true,
            encrypting: vec![String::from("conversation-1")],
            unencrypted,
            out_of_step: std::sync::atomic::AtomicBool::new(true),
            healing_flips: flips,
            ..ScriptedEncryption::default()
        });
        client
            .sessions
            .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
        let (mut connection, msrp_path, our_path) =
            joined_encrypted_group(&client, &mut peer, "group-healing-told");

        // a message not decrypted sets self-healing off, which moves the
        // group to unencrypted, or back to encrypted (RCC.16 sections 10.1,
        // 11.1.2)
        connection.send_content(
            &rt,
            &msrp_path,
            &our_path,
            "message/cpim",
            &encrypted_group_cpim("tel:+15550002", "", "not to be decrypted"),
        );
        assert!(connection.next_response(&rt).first_line.contains(" 200"));
        let events: Vec<String> = std::iter::from_fn(|| {
            client
                .group_events
                .recv_timeout(Duration::from_millis(500))
                .ok()
        })
        .collect();
        // once, or not at all if it did not
        let encryption_events: Vec<&String> = events
            .iter()
            .filter(|event| event.ends_with(&format!("encrypted {}", GROUP)))
            .collect();
        match told {
            Some(told) => assert_eq!(
                encryption_events,
                [&format!("{} {}", told, GROUP)],
                "{:?}",
                events
            ),
            None => assert!(encryption_events.is_empty(), "{:?}", events),
        }
        assert_eq!(encryption.healed.lock().unwrap().len(), 1);
    }
}

#[test]
fn a_group_moved_back_to_encrypted_is_told_to_the_app() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = ending_in(
        &client,
        ScriptedEncryption {
            resuming_by_focus: true,
            ..ScriptedEncryption::default()
        },
    );
    let (mut connection, msrp_path, our_path) =
        joined_encrypted_group(&client, &mut peer, "group-resumed");

    connection.send_content(
        &rt,
        &msrp_path,
        &our_path,
        "message/cpim",
        &from_the_focus("a Commit removing end_mls"),
    );
    assert!(connection.next_response(&rt).first_line.contains(" 200"));
    let events: Vec<String> = std::iter::from_fn(|| {
        client
            .group_events
            .recv_timeout(Duration::from_millis(500))
            .ok()
    })
    .collect();
    assert!(events.contains(&format!("encrypted {}", GROUP)));
    assert!(!events.contains(&format!("unencrypted {}", GROUP)));
    assert_eq!(encryption.server_messages.lock().unwrap().len(), 1);
    connection.quiet(&rt);
}
