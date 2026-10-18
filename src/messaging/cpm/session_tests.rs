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
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::runtime::Runtime;

use rust_rcs_core::internet::header;
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

use super::session::{CPMSessionService, CPMSessionServiceWrapper};
use super::standalone_messaging::{StandaloneMessagingService, StandaloneMessagingServiceWrapper};

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
        let (result_tx, result_rx) = mpsc::channel();
        let (returned_tx, returned_rx) = mpsc::channel();

        let sessions = Arc::clone(&self.sessions);
        let core = Arc::clone(&self.core);
        let rt = Arc::clone(&self.rt);
        let recipient = String::from(recipient);
        let content = String::from(content);
        std::thread::spawn(move || {
            sessions.send_message(
                "text/plain",
                &content,
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

    let sessions = Arc::new(CPMSessionService::new(
        move |_session, contact, _cpim_info, content_type, content| {
            let _ = received_tx.lock().unwrap().send((
                String::from_utf8_lossy(contact).into_owned(),
                String::from_utf8_lossy(content_type).into_owned(),
                String::from_utf8_lossy(content).into_owned(),
            ));
        },
        |_msrp_info| allocate_msrp_socket(),
        |sock, raddr, rport, _tls| connect_msrp_socket(sock, raddr, rport),
        |_, _, _, _, _| 200,
        move |_, _, _, subject, referred_by_name, _, _| {
            let _ = group_invites_tx
                .lock()
                .unwrap()
                .send((String::from(subject), String::from(referred_by_name)));
            200
        },
        |_| {},
    ));

    let standalone = Arc::new(StandaloneMessagingService::new(
        move |contact, _cpim_info, content_type, content| {
            let _ = received_tx_.lock().unwrap().send((
                String::from_utf8_lossy(contact).into_owned(),
                String::from_utf8_lossy(content_type).into_owned(),
                String::from_utf8_lossy(content).into_owned(),
            ));
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
        let cpim = format!(
            "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-18T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: peer-message-1\r\n\
\r\n\
Content-Type: text/plain;charset=UTF-8\r\n\
\r\n\
{}",
            PEER, IMPU, content
        );
        let data = format!(
            "MSRP peer-t1 SEND\r\n\
To-Path: {}\r\n\
From-Path: {}\r\n\
Message-ID: peer-m1\r\n\
Byte-Range: 1-{}/{}\r\n\
Content-Type: message/cpim\r\n\
\r\n\
{}\r\n\
-------peer-t1$\r\n",
            to_path,
            from_path,
            cpim.len(),
            cpim.len(),
            cpim
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
    let mut data = format!("SIP/2.0 {}\r\n", status);
    for name in ["Via", "From", "Call-ID", "CSeq"] {
        data += &format!("{}: {}\r\n", name, header_value(request, name));
    }
    data += &format!("To: {};tag=peer2\r\n", header_value(request, "To"));
    data += "Contact: <sip:+15559876@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"\r\n";
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
}

/// A CPIM message from the peer to the client, its content as given
fn cpim(content_headers: &str, content: &str) -> String {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-18T12:00:00.000Z\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: peer-message-1\r\n\
\r\n\
{}\r\n\
{}",
        PEER, IMPU, content_headers, content
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
    connection.respond(&rt, &send, "200 OK");

    assert_eq!(result.recv_timeout(Duration::from_secs(5)), Ok(200));
    peer.next_request("BYE");
    assert!(result.recv_timeout(Duration::from_millis(500)).is_err());
}

/// A pager-mode MESSAGE from the peer carrying `body`
fn pager_message(call_id: &str, content_type: &str, body: &str) -> String {
    format!(
        "MESSAGE sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: <{}>;tag=pager1\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 MESSAGE\r\n\
P-Asserted-Identity: <{}>\r\n\
Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg\"\r\n\
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
