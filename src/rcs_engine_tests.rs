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

//! How the engine sends messages and files, run against a peer the test
//! scripts, as the chat sessions' tests run: what goes standalone or in a
//! chat, and in which chat with E2EE

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rust_rcs_core::cpim::CPIMInfo;

use tokio::runtime::Runtime;
use tokio::sync::Notify;

use crate::messaging::config::MessagingConfigs;
use crate::messaging::cpm::encryption::GroupEncryption;
use crate::messaging::cpm::session_tests::{
    answer, body_data, cpim_text, header_value, new_group, request_uri, start, status_code,
    ChatScript, Client, MsrpPeer, Peer, ScriptedEncryption, CHAT_BUNDLE, GROUP, IMPU, PEER, TOKEN,
    TRANSPORT_ADDRESS,
};
use crate::messaging::ffi::RecipientType;

use super::{
    cpim_from, joined_feature_tags, report_video_chat_event, route_message, sealing_of,
    send_group_video_chat_message, send_to_contact, send_video_chat_message, taken_by_video_chat,
    Content, MessageRoute, PendingMessage, PreparingChats, RcsEngineConnectionState,
    RcsEngineRegistrationState, UploadFor,
};
use crate::video_chat::{
    VideoChatConfig, VideoChatEvent, VideoChatLink, VideoChatService, CONTENT_TYPE,
};

/// The type of file transfer messages (RCC.07 section 3.2.5)
const FILE_TRANSFER: &str = "application/vnd.gsma.rcs-ft-http+xml";

/// A file transfer message, its XML as the app sends it
const FILE_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><file><file-info type=\"file\"><file-size>4</file-size><file-name>a.txt</file-name><content-type>text/plain</content-type><data url=\"https://ftcs.example.com/f/1\" until=\"2026-11-04T00:00:00Z\"/></file-info></file>";

/// What the engine sends messages with, over the services of a test client
struct Engine {
    route: MessageRoute,
    preparing: PreparingChats,
    rt: Arc<Runtime>,
}

impl Engine {
    /// The engine sending over `client`, registered on its transport as
    /// IMPU, configured as `messaging`
    fn over(client: &Client, messaging: MessagingConfigs) -> Engine {
        Engine {
            route: MessageRoute {
                state: Arc::new(Mutex::new((
                    RcsEngineConnectionState::CONNECTED(
                        Arc::clone(&client.transport),
                        String::new(),
                    ),
                    RcsEngineRegistrationState::MAINTAINED(String::from(IMPU)),
                ))),
                messaging_config: Arc::new(Mutex::new(messaging)),
                cpm_session_service: Arc::clone(&client.sessions),
                standalone_messaging_service: Arc::clone(&client.standalone),
                core: Arc::clone(&client.core),
            },
            preparing: Arc::new(Mutex::new(HashMap::new())),
            rt: Arc::clone(&client.rt),
        }
    }

    /// Configures it as `messaging` from then on
    fn configure(&self, messaging: MessagingConfigs) {
        *self.route.messaging_config.lock().unwrap() = messaging;
    }

    /// Has it no longer registered
    fn unregister(&self) {
        *self.route.state.lock().unwrap() = (
            RcsEngineConnectionState::IDLE,
            RcsEngineRegistrationState::NONE,
        );
    }

    /// Sends `content` of `message_type` to PEER as send_message() does
    /// without E2EE, returning when route_message() does, within 5 s, and a
    /// receiver of its result
    fn route(
        &self,
        message_type: &str,
        content: &str,
        message_id: &str,
    ) -> Receiver<(u16, String)> {
        let route = self.route.clone();
        let rt = Arc::clone(&self.rt);
        let (message_type, content, message_id) = (
            String::from(message_type),
            String::from(content),
            String::from(message_id),
        );
        returning(move |told| {
            route_message(
                &route,
                &message_type,
                &content,
                &message_id,
                PEER,
                RecipientType::Contact,
                told,
                &rt,
            )
        })
    }

    /// As route(), as send_message() does with `encryption`: in an
    /// encrypted 1-to-1 chat if it can
    fn send(
        &self,
        encryption: &Arc<ScriptedEncryption>,
        message_type: &str,
        content: &str,
        message_id: &str,
    ) -> Receiver<(u16, String)> {
        let route = self.route.clone();
        let preparing = Arc::clone(&self.preparing);
        let encryption = Arc::clone(encryption) as Arc<dyn GroupEncryption>;
        let rt = Arc::clone(&self.rt);
        let message = (
            String::from(message_type),
            String::from(content),
            String::from(message_id),
        );
        returning(move |told| {
            let (message_type, message_content, message_id) = message;
            let message = PendingMessage {
                message_type,
                content: Content::App(message_content),
                message_id,
                recipient: String::from(PEER),
                callback: Box::new(told),
            };
            send_to_contact(&route, &preparing, encryption, message, &rt)
        })
    }
}

impl Engine {
    /// Sends the VideoChatMessage `message` to PEER as RCS Video Chat does,
    /// returning as send_video_chat_message() does, and a receiver of its
    /// result
    fn video_chat(&self, message: &[u8]) -> Receiver<(u16, String)> {
        let route = self.route.clone();
        let preparing = Arc::clone(&self.preparing);
        let rt = Arc::clone(&self.rt);
        let message = message.to_vec();
        returning(move |told| {
            send_video_chat_message(
                &route,
                &preparing,
                PEER,
                message,
                Box::new(move |status_code| told(status_code, String::new())),
                &rt,
            )
        })
    }
}

impl Engine {
    /// Sends the ClientGroupVideoMessage `message` to GROUP as Group RCS
    /// Video Chat does, returning as send_group_video_chat_message() does,
    /// and a receiver of its result
    fn group_video_chat(&self, message: &[u8]) -> Receiver<(u16, String)> {
        let route = self.route.clone();
        let rt = Arc::clone(&self.rt);
        let message = message.to_vec();
        returning(move |told| {
            send_group_video_chat_message(
                &route,
                GROUP,
                message,
                Box::new(move |status_code| told(status_code, String::new())),
                &rt,
            )
        })
    }
}

/// The configuration with chats and group chats
fn configured_for_groups() -> MessagingConfigs {
    let mut messaging = configured(true, true);
    messaging.group_chat_auth = 1;
    messaging
}

/// A VideoChatMessage as RCS Video Chat sends it, encoded: not text
const VIDEO_CHAT: &[u8] = b"\x0a\x04call\xaa\x06\x02\x0a\x00\xff";

/// The content of the CPIM message `cpim`, base64 decoded
fn cpim_content(cpim: &[u8]) -> Vec<u8> {
    use base64::{engine::general_purpose, Engine as _};

    let cpim = String::from_utf8_lossy(cpim).into_owned();
    let content = cpim.rsplit("\r\n\r\n").next().unwrap_or("");
    general_purpose::STANDARD.decode(content.trim()).unwrap()
}

/// Runs `send` on a thread of its own, with what tells its result, waiting
/// for it to return, within 5 s; and a receiver of that result
fn returning(
    send: impl FnOnce(Box<dyn FnOnce(u16, String) + Send + Sync>) + Send + 'static,
) -> Receiver<(u16, String)> {
    let (result_tx, result_rx) = mpsc::channel();
    let (returned_tx, returned_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result_tx = Mutex::new(result_tx);
        send(Box::new(move |status_code, reason_phrase| {
            let _ = result_tx.lock().unwrap().send((status_code, reason_phrase));
        }));
        let _ = returned_tx.send(());
    });
    returned_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the engine to return");
    result_rx
}

/// The configuration with chats if `chat`, and standalone messages if
/// `standalone`
fn configured(chat: bool, standalone: bool) -> MessagingConfigs {
    let mut messaging = MessagingConfigs::new();
    messaging.chat_auth = i32::from(chat);
    messaging.standalone_msg_auth = i32::from(standalone);
    messaging
}

/// The encryption of `client`'s chats as `script` has it
fn encrypting(client: &Client, script: ChatScript) -> Arc<ScriptedEncryption> {
    let encryption = ScriptedEncryption::of_chats(script);
    client
        .sessions
        .set_group_encryption(Arc::clone(&encryption) as Arc<dyn GroupEncryption>);
    encryption
}

/// The status code `result` gives, within 5 s
fn told(result: &Receiver<(u16, String)>) -> u16 {
    result
        .recv_timeout(Duration::from_secs(5))
        .expect("the result")
        .0
}

/// The imdn.Message-ID of the CPIM message `cpim`
fn message_id_of(cpim: &[u8]) -> String {
    String::from_utf8_lossy(cpim)
        .lines()
        .find_map(|line| line.strip_prefix("imdn.Message-ID: "))
        .map(String::from)
        .expect("an imdn.Message-ID")
}

/// Takes the standalone MESSAGE the client sends next, checking it goes to
/// PEER, answering it `status`, and giving the CPIM message it carries
fn standalone_message(peer: &mut Peer, status: &str) -> String {
    let message = peer.next_request("MESSAGE");
    assert_eq!(request_uri(&message), PEER);
    peer.send(&answer(&message, status, None));
    String::from_utf8_lossy(&body_data(&message)).into_owned()
}

#[test]
fn a_message_to_a_contact_goes_standalone_or_in_a_chat_as_configured() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let engine = Engine::over(&client, configured(true, true));

    // standalone, with no chat there is with the contact
    let first = engine.route("text/plain", "first", "m1");
    let cpim = standalone_message(&mut peer, "200 OK");
    assert_eq!(cpim_text(cpim.as_bytes()), "first");
    assert_eq!(told(&first), 200);

    // in a new chat, when it cannot go standalone
    engine.configure(configured(true, false));
    let msrp = MsrpPeer::listen(&rt);
    let second = engine.route("text/plain", "second", "m2");
    let invite = peer.next_request("INVITE");
    assert_eq!(request_uri(&invite), PEER);
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "second");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&second), 200);

    // in the chat there is, though it could go standalone
    engine.configure(configured(true, true));
    let third = engine.route("text/plain", "third", "m3");
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "third");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&third), 200);

    // standalone with chats off, whatever chat there is
    engine.configure(configured(false, true));
    let fourth = engine.route("text/plain", "fourth", "m4");
    let cpim = standalone_message(&mut peer, "200 OK");
    assert_eq!(cpim_text(cpim.as_bytes()), "fourth");
    assert_eq!(told(&fourth), 200);

    // neither: refused, as when not registered
    engine.configure(configured(false, false));
    assert_eq!(told(&engine.route("text/plain", "fifth", "m5")), 403);
    engine.configure(configured(true, true));
    engine.unregister();
    assert_eq!(told(&engine.route("text/plain", "sixth", "m6")), 403);
    connection.quiet(&rt);
    peer.silence();
}

#[test]
fn a_message_to_a_contact_goes_in_the_encrypted_chat_kept_with_it() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting(
        &client,
        ChatScript {
            kept: vec![(
                String::from(PEER),
                String::from("chat-1"),
                Some(String::from(TOKEN)),
            )],
            chatting: Some((String::from("chat-2"), CHAT_BUNDLE.to_vec())),
            encrypting: vec![String::from("chat-1")],
            ciphertext: Some(String::from("ciphertext")),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    // a new session of it, with its token (RCC.16 sections 6.1.3, 8.1.1),
    // and no new MLS group
    let sent = engine.send(&encryption, "text/plain", "again", "m1");
    let invite = peer.next_request("INVITE");
    assert_eq!(header_value(&invite, "Content-Type"), "application/sdp");
    assert_eq!(header_value(&invite, "MLS-Opaque-Token"), TOKEN);
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(send.body, b"ciphertext");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);

    let encrypted = encryption.encrypted();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].0, "chat-1");
    assert_eq!(cpim_text(&encrypted[0].1), "again");
    assert!(encryption.chats_prepared().is_empty());
    assert!(encryption.chat_eras_prepared().is_empty());

    // the next in that session
    let next = engine.send(&encryption, "text/plain", "next", "m2");
    let send = connection.next_message(&rt);
    assert_eq!(send.body, b"ciphertext");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&next), 200);
    assert_eq!(encryption.encrypted().len(), 2);
    assert!(encryption.chats_prepared().is_empty());
    peer.silence();
}

#[test]
fn messages_to_a_contact_wait_for_the_new_encrypted_chat_they_start() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let held = Arc::new(Notify::new());
    let encryption = encrypting(
        &client,
        ChatScript {
            chatting: Some((String::from("chat-1"), CHAT_BUNDLE.to_vec())),
            held: Some(Arc::clone(&held)),
            encrypting: vec![String::from("chat-1")],
            ciphertext: Some(String::from("ciphertext")),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    // nothing sent while its MLS group is made, asked for once, from the
    // public identity registered (RCC.16 section 8.1.1)
    let first = engine.send(&encryption, "text/plain", "first", "m1");
    let second = engine.send(&encryption, "text/plain", "second", "m2");
    let third = engine.send(&encryption, FILE_TRANSFER, FILE_XML, "m3");
    peer.silence();
    assert_eq!(
        encryption.chats_prepared(),
        [(String::from(PEER), String::from(IMPU))]
    );
    assert!(first.try_recv().is_err());

    // then the first starting the chat, with the MLS group its INVITE
    // carries
    held.notify_one();
    let invite = peer.next_request("INVITE");
    assert!(header_value(&invite, "Content-Type").starts_with("multipart/mixed; boundary="));
    let body = body_data(&invite);
    assert!(body.windows(CHAT_BUNDLE.len()).any(|w| w == CHAT_BUNDLE));

    // and the others after it in its session, all encrypted with that MLS
    // group, in the order sent
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    for _ in 0..3 {
        let send = connection.next_message(&rt);
        assert_eq!(send.body, b"ciphertext");
        connection.respond(&rt, &send, "200 OK");
    }
    for result in [&first, &second, &third] {
        assert_eq!(told(result), 200);
    }
    let encrypted: Vec<_> = encryption
        .encrypted()
        .iter()
        .map(|(group_id, cpim)| (group_id.clone(), message_id_of(cpim)))
        .collect();
    assert_eq!(
        encrypted,
        ["m1", "m2", "m3"].map(|id| (String::from("chat-1"), String::from(id)))
    );
    assert_eq!(encryption.chats_prepared().len(), 1);
    peer.silence();
}

#[test]
fn messages_to_a_contact_not_taking_an_encrypted_chat_go_as_without_e2ee() {
    let (client, mut peer) = start(true);
    let held = Arc::new(Notify::new());
    let encryption = encrypting(
        &client,
        ChatScript {
            held: Some(Arc::clone(&held)),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));

    // asked for, then each standalone, a file not sealed for the chat too
    let text = engine.send(&encryption, "text/plain", "hello", "m1");
    let file = engine.send(&encryption, FILE_TRANSFER, FILE_XML, "m2");
    peer.silence();
    held.notify_one();
    let mut sent: Vec<_> = (0..2)
        .map(|_| standalone_message(&mut peer, "200 OK"))
        .collect();
    sent.sort_by_key(|cpim| message_id_of(cpim.as_bytes()));
    assert_eq!(message_id_of(sent[0].as_bytes()), "m1");
    assert_eq!(cpim_text(sent[0].as_bytes()), "hello");
    assert_eq!(message_id_of(sent[1].as_bytes()), "m2");
    assert!(sent[1].contains(FILE_TRANSFER), "{}", sent[1]);
    assert_eq!(told(&text), 200);
    assert_eq!(told(&file), 200);
    assert_eq!(
        encryption.chats_prepared(),
        [(String::from(PEER), String::from(IMPU))]
    );
    assert!(encryption.encrypted().is_empty());

    // asked for again with the next, none waiting any longer
    held.notify_one();
    let again = engine.send(&encryption, "text/plain", "again", "m3");
    standalone_message(&mut peer, "200 OK");
    assert_eq!(told(&again), 200);
    assert_eq!(encryption.chats_prepared().len(), 2);
    peer.silence();
}

#[test]
fn a_file_sealed_for_a_chat_that_does_not_start_is_refused() {
    let (client, mut peer) = start(true);
    let encryption = encrypting(
        &client,
        ChatScript {
            sealed_for_chats: true,
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));

    // not sent unencrypted, as the contact could not open it (RCC.16
    // section 9.1.2.1)
    let file = engine.send(&encryption, FILE_TRANSFER, FILE_XML, "m1");
    assert_eq!(told(&file), 488);
    peer.silence();

    // a text all the same
    let text = engine.send(&encryption, "text/plain", "hello", "m2");
    let cpim = standalone_message(&mut peer, "200 OK");
    assert_eq!(cpim_text(cpim.as_bytes()), "hello");
    assert_eq!(told(&text), 200);
    peer.silence();
}

#[test]
fn a_chat_unused_for_long_starts_again_in_a_new_era() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting(
        &client,
        ChatScript {
            kept: vec![(
                String::from(PEER),
                String::from("chat-1"),
                Some(String::from(TOKEN)),
            )],
            chatting: Some((String::from("chat-2"), CHAT_BUNDLE.to_vec())),
            eras_due: vec![String::from(PEER)],
            encrypting: vec![String::from("chat-1"), String::from("chat-2")],
            ciphertext: Some(String::from("ciphertext")),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    // the next Era of its MLS group, not a new chat, carried by the INVITE
    // with the chat's token (RCC.16 section 8.3)
    let sent = engine.send(&encryption, "text/plain", "again", "m1");
    let invite = peer.next_request("INVITE");
    assert!(header_value(&invite, "Content-Type").starts_with("multipart/mixed; boundary="));
    assert_eq!(header_value(&invite, "MLS-Opaque-Token"), TOKEN);
    let body = body_data(&invite);
    assert!(body.windows(CHAT_BUNDLE.len()).any(|w| w == CHAT_BUNDLE));
    assert_eq!(
        encryption.chat_eras_prepared(),
        [(String::from(PEER), String::from(IMPU))]
    );
    assert!(encryption.chats_prepared().is_empty());

    // the message encrypted in it
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(send.body, b"ciphertext");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);
    assert_eq!(encryption.encrypted()[0].0, "chat-2");
    assert!(encryption.abandoned().is_empty());
    peer.silence();
}

#[test]
fn a_chat_whose_new_era_is_not_made_starts_again_as_it_is() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting(
        &client,
        ChatScript {
            kept: vec![(
                String::from(PEER),
                String::from("chat-1"),
                Some(String::from(TOKEN)),
            )],
            eras_due: vec![String::from(PEER)],
            encrypting: vec![String::from("chat-1")],
            ciphertext: Some(String::from("ciphertext")),
            sealed_for_chats: true,
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    // in a new session of the chat kept, encrypted with its MLS group, a
    // file sealed for it too
    let file = engine.send(&encryption, FILE_TRANSFER, FILE_XML, "m1");
    let invite = peer.next_request("INVITE");
    assert_eq!(header_value(&invite, "Content-Type"), "application/sdp");
    assert_eq!(header_value(&invite, "MLS-Opaque-Token"), TOKEN);
    assert_eq!(
        encryption.chat_eras_prepared(),
        [(String::from(PEER), String::from(IMPU))]
    );
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(send.body, b"ciphertext");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&file), 200);
    assert_eq!(encryption.encrypted()[0].0, "chat-1");
    assert!(encryption.chats_prepared().is_empty());
    peer.silence();
}

#[test]
fn a_message_to_a_contact_goes_in_the_chat_there_is_with_it() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let engine = Engine::over(&client, configured(true, false));
    let msrp = MsrpPeer::listen(&rt);

    // a chat not encrypted started before
    let first = engine.route("text/plain", "first", "m1");
    let invite = peer.next_request("INVITE");
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&first), 200);

    // the next in it, no new chat made for it, though one could be
    let encryption = encrypting(
        &client,
        ChatScript {
            chatting: Some((String::from("chat-2"), CHAT_BUNDLE.to_vec())),
            ..ChatScript::default()
        },
    );
    let second = engine.send(&encryption, "text/plain", "second", "m2");
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "second");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&second), 200);
    assert!(encryption.chats_prepared().is_empty());

    // nor a new Era of the chat kept, though it would be due
    let encryption = encrypting(
        &client,
        ChatScript {
            kept: vec![(String::from(PEER), String::from("chat-1"), None)],
            chatting: Some((String::from("chat-2"), CHAT_BUNDLE.to_vec())),
            eras_due: vec![String::from(PEER)],
            ..ChatScript::default()
        },
    );
    let third = engine.send(&encryption, "text/plain", "third", "m3");
    let send = connection.next_message(&rt);
    assert_eq!(cpim_text(&send.body), "third");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&third), 200);
    assert!(encryption.chats_prepared().is_empty());
    assert!(encryption.chat_eras_prepared().is_empty());
    peer.silence();
}

#[test]
fn nothing_goes_to_a_contact_while_not_registered() {
    let (client, mut peer) = start(true);
    let encryption = encrypting(
        &client,
        ChatScript {
            chatting: Some((String::from("chat-1"), CHAT_BUNDLE.to_vec())),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    engine.unregister();

    let sent = engine.send(&encryption, "text/plain", "hello", "m1");
    assert_eq!(told(&sent), 403);
    assert!(encryption.chats_prepared().is_empty());
    assert!(engine.preparing.lock().unwrap().is_empty());
    peer.silence();
}

#[test]
fn a_file_is_sealed_for_what_it_is_uploaded_for_while_that_is_encrypted() {
    let rt = Runtime::new().unwrap();
    let sealing = |script: ChatScript, upload_for: UploadFor| {
        let encryption = ScriptedEncryption::of_chats(script);
        let sealing = rt.block_on(sealing_of(
            &upload_for,
            Some(Arc::clone(&encryption) as Arc<dyn GroupEncryption>),
        ));
        sealing.map(|(sealed_for, by)| {
            // with that encryption
            assert!(std::ptr::eq(
                Arc::as_ptr(&by) as *const u8,
                Arc::as_ptr(&encryption) as *const u8
            ));
            sealed_for
        })
    };
    let group = || ChatScript {
        encrypting: vec![String::from("conversation-1")],
        ..ChatScript::default()
    };
    let chat = |sealing_chat_files| ChatScript {
        sealing_chat_files,
        ..ChatScript::default()
    };

    // for anyone: never (RCC.16 section 9.1.2.1)
    assert_eq!(sealing(group(), UploadFor::Anyone), None);
    assert_eq!(sealing(chat(true), UploadFor::Anyone), None);

    // for a group chat: while it is encrypted
    let conversation = UploadFor::Group(String::from("conversation-1"));
    assert_eq!(sealing(group(), conversation.clone()), Some(conversation));
    let other = UploadFor::Group(String::from("conversation-2"));
    assert_eq!(sealing(group(), other), None);

    // for a contact: if the message sending it goes encrypted (section
    // 8.1.1)
    let contact = UploadFor::Chat(String::from(PEER));
    assert_eq!(sealing(chat(true), contact.clone()), Some(contact.clone()));
    assert_eq!(sealing(chat(false), contact.clone()), None);
    assert_eq!(sealing(group(), contact.clone()), None);

    // never without E2EE
    for upload_for in [
        UploadFor::Anyone,
        UploadFor::Group(String::from("conversation-1")),
        contact,
    ] {
        assert!(rt.block_on(sealing_of(&upload_for, None)).is_none());
    }
}

#[test]
fn a_standalone_message_carries_the_user_alias_in_its_from() {
    let (client, mut peer) = start(true);
    let engine = Engine::over(&client, configured(true, true));

    // as its display name (RCC.07 section 2.5.3.3); standalone messages are
    // not encrypted
    client
        .standalone
        .set_user_alias(Some(String::from("Alice")));
    let sent = engine.route("text/plain", "hello", "m1");
    let message = peer.next_request("MESSAGE");
    let from = header_value(&message, "From");
    assert!(
        from.starts_with(&format!("\"Alice\" <{}>;tag=", IMPU)),
        "{}",
        from
    );
    peer.send(&answer(&message, "200 OK", None));
    assert_eq!(told(&sent), 200);

    // none once let go of
    client.standalone.set_user_alias(Some(String::from("  ")));
    let sent = engine.route("text/plain", "again", "m2");
    let message = peer.next_request("MESSAGE");
    let from = header_value(&message, "From");
    assert!(from.starts_with(&format!("<{}>;tag=", IMPU)), "{}", from);
    peer.send(&answer(&message, "200 OK", None));
    assert_eq!(told(&sent), 200);
    peer.silence();
}

#[test]
fn the_alias_of_the_sender_of_a_standalone_message_is_told() {
    let (client, mut peer) = start(true);
    // as the display name of its From (RCC.07 section 2.5.3.3)
    peer.send(&standalone_message_from(
        "alias-message",
        "\"Bob\" <sip:+15559876@example.com>;tag=peer1",
    ));
    assert_eq!(status_code(&peer.next_response()), 200);
    assert_eq!(
        client.aliases.recv_timeout(Duration::from_secs(5)),
        Ok((String::from(PEER), String::from("Bob"), false))
    );
}

/// A pager MESSAGE from PEER, its From `from`
fn standalone_message_from(call_id: &str, from: &str) -> String {
    let cpim = format!(
        "From: <{}>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: standalone-1\r\n\r\nContent-Type: text/plain\r\n\r\nhello",
        PEER, IMPU
    );
    format!(
        "MESSAGE sip:+15551234@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: {}\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 MESSAGE\r\n\
Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg\"\r\n\
P-Asserted-Identity: <{}>\r\n\
Max-Forwards: 70\r\n\
Content-Type: message/cpim\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        TRANSPORT_ADDRESS,
        call_id,
        from,
        IMPU,
        call_id,
        PEER,
        cpim.len(),
        cpim
    )
}

#[test]
fn a_video_chat_message_goes_in_a_chat_never_standalone() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    // in a new chat, where a message of the app would go standalone (RCC.07
    // v18.0 section 3.7.5.2.2)
    let sent = engine.video_chat(VIDEO_CHAT);
    let invite = peer.next_request("INVITE");
    assert_eq!(request_uri(&invite), PEER);
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    let cpim = String::from_utf8_lossy(&send.body).into_owned();
    // of its own content type (section 3.7.5.2.3.1.1), asking for no
    // notification, as AckInvitation tells of its delivery
    assert!(
        cpim.contains("Content-Type: rcs/video-chat+proto"),
        "{}",
        cpim
    );
    assert!(!cpim.contains("Disposition-Notification"), "{}", cpim);
    assert_eq!(cpim_content(&send.body), VIDEO_CHAT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);

    // the next in it
    let next = engine.video_chat(VIDEO_CHAT);
    let send = connection.next_message(&rt);
    assert_eq!(cpim_content(&send.body), VIDEO_CHAT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&next), 200);

    // not without chats, though it could go standalone
    engine.configure(configured(false, true));
    assert_eq!(told(&engine.video_chat(VIDEO_CHAT)), 403);
    connection.quiet(&rt);
    peer.silence();
}

#[test]
fn a_video_chat_message_goes_in_the_encrypted_chat_kept_with_the_contact() {
    // RCC.16 section 9.8.1
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let encryption = encrypting(
        &client,
        ChatScript {
            kept: vec![(
                String::from(PEER),
                String::from("chat-1"),
                Some(String::from(TOKEN)),
            )],
            encrypting: vec![String::from("chat-1")],
            ciphertext: Some(String::from("ciphertext")),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    let sent = engine.video_chat(VIDEO_CHAT);
    let invite = peer.next_request("INVITE");
    assert_eq!(header_value(&invite, "MLS-Opaque-Token"), TOKEN);
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(send.body, b"ciphertext");
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);
    let encrypted = encryption.encrypted();
    assert_eq!(encrypted.len(), 1);
    assert_eq!(encrypted[0].0, "chat-1");
    assert_eq!(cpim_content(&encrypted[0].1), VIDEO_CHAT);
    peer.silence();
}

#[test]
fn a_video_chat_message_to_a_contact_not_taking_an_encrypted_chat_goes_in_one_not_encrypted() {
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let held = Arc::new(Notify::new());
    let encryption = encrypting(
        &client,
        ChatScript {
            held: Some(Arc::clone(&held)),
            ..ChatScript::default()
        },
    );
    let engine = Engine::over(&client, configured(true, true));
    let msrp = MsrpPeer::listen(&rt);

    // an encrypted chat asked for, then a chat not encrypted, not
    // standalone as a message of the app would go
    let sent = engine.video_chat(VIDEO_CHAT);
    held.notify_one();
    let invite = peer.next_request("INVITE");
    assert_eq!(request_uri(&invite), PEER);
    peer.send(&answer(&invite, "200 OK", Some(&msrp.sdp("sendrecv"))));
    peer.next_request("ACK");
    let mut connection = msrp.accept(&rt);
    let send = connection.next_message(&rt);
    assert_eq!(cpim_content(&send.body), VIDEO_CHAT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);
    assert_eq!(
        encryption.chats_prepared(),
        [(String::from(PEER), String::from(IMPU))]
    );
    assert!(encryption.encrypted().is_empty());
    peer.silence();
}

/// Takes nothing, a link for a service to take signals with; the group
/// messages it sends noted
struct Unlinked {
    group_sent: Mutex<Vec<String>>,
}

impl VideoChatLink for Unlinked {
    fn send(&self, _: &str, _: Vec<u8>, sent: Box<dyn FnOnce(u16) + Send + Sync>) {
        sent(200);
    }

    fn report(&self, _: &str, _: Vec<u8>) {}

    fn registered_uri(&self) -> Option<String> {
        None
    }

    fn send_to_group(
        &self,
        conference_uri: &str,
        _: Vec<u8>,
        sent: Box<dyn FnOnce(u16) + Send + Sync>,
    ) {
        self.group_sent
            .lock()
            .unwrap()
            .push(String::from(conference_uri));
        sent(200);
    }

    fn group_conversation_id(&self, _: &str) -> Option<String> {
        None
    }
}

#[test]
fn video_chat_messages_go_to_the_video_chats_not_to_the_app() {
    use crate::video_chat::proto::{
        video_chat_message, CallInvitation, ServerGroupVideoMessage, VideoChatMessage,
    };

    let rt = Runtime::new().unwrap();
    let link = Arc::new(Unlinked {
        group_sent: Mutex::new(Vec::new()),
    });
    let service = VideoChatService::new(
        Arc::clone(&link) as Arc<dyn VideoChatLink>,
        rt.handle().clone(),
    );
    service.set_config(VideoChatConfig {
        technology: 3,
        ..VideoChatConfig::default()
    });
    let told = Arc::new(Mutex::new(Vec::new()));
    let telling = Arc::clone(&told);
    service.set_listener(Arc::new(move |call_id, contact, event| {
        telling
            .lock()
            .unwrap()
            .push((String::from(call_id), String::from(contact), event));
    }));
    let video_chat = OnceLock::new();
    let _ = video_chat.set(Arc::downgrade(&service));

    let invitation = |call_id: &str, sdp_offer: &str| VideoChatMessage {
        call_id: String::from(call_id),
        event: Some(video_chat_message::Event::CallInvitation(CallInvitation {
            sdp_offer: String::from(sdp_offer),
        })),
    };
    let body = prost::Message::encode_to_vec(&invitation("bob-call", "offer"));
    let date = chrono::Utc::now().to_rfc3339();
    let cpim_info = CPIMInfo {
        imdn_message_id: b"m1",
        from: b"<tel:+15550002>",
        to: b"<tel:+15550001>",
        date: date.as_bytes(),
        from_uri: None,
        to_uri: None,
        payload_type: None,
        disposition_notification: None,
        mls_derived_content_signature: None,
        mls_original_message_id: None,
    };

    // not a video chat message: the app's
    assert!(!taken_by_video_chat(
        &video_chat,
        || None,
        PEER.as_bytes(),
        &cpim_info,
        b"text/plain",
        b"hi"
    ));
    // of an encrypted group: taken, though not yet by the video chats, as
    // RCC.16 section 9.8.2 has it signed
    let group = ServerGroupVideoMessage {
        video_chat_message: prost::Message::encode_to_vec(&invitation("carol-call", "")),
        sdp: String::from("sfu offer"),
        ..ServerGroupVideoMessage::default()
    };
    let group = prost::Message::encode_to_vec(&group);
    assert!(taken_by_video_chat(
        &video_chat,
        || Some(true),
        b"sip:group@conf.example.com",
        &cpim_info,
        CONTENT_TYPE.as_bytes(),
        &group
    ));
    assert!(told.lock().unwrap().is_empty());
    // of a 1-to-1 chat, with parameters too
    assert!(taken_by_video_chat(
        &video_chat,
        || None,
        PEER.as_bytes(),
        &cpim_info,
        b"rcs/video-chat+proto; charset=binary",
        &body
    ));
    assert_eq!(
        std::mem::take(&mut *told.lock().unwrap()),
        [(
            String::from("bob-call"),
            String::from(PEER),
            VideoChatEvent::Incoming {
                sdp_offer: String::from("offer"),
                ongoing: false,
            }
        )]
    );
    service.hang_up("bob-call");
    // of a group not encrypted, from the participant of its CPIM From
    assert!(taken_by_video_chat(
        &video_chat,
        || Some(false),
        b"sip:group@conf.example.com",
        &cpim_info,
        CONTENT_TYPE.as_bytes(),
        &group
    ));
    assert_eq!(
        *told.lock().unwrap(),
        [(
            String::from("carol-call"),
            String::from("sip:group@conf.example.com"),
            VideoChatEvent::Incoming {
                sdp_offer: String::from("sfu offer"),
                ongoing: false,
            }
        )]
    );
    assert_eq!(
        *link.group_sent.lock().unwrap(),
        ["sip:group@conf.example.com"]
    );
    // the video chats gone, not the app's all the same
    drop(service);
    assert!(taken_by_video_chat(
        &video_chat,
        || None,
        PEER.as_bytes(),
        &cpim_info,
        CONTENT_TYPE.as_bytes(),
        &body
    ));
}

#[test]
fn the_cpim_from_of_a_group_message_gives_its_participant() {
    let cpim_info = |from: &'static [u8]| CPIMInfo {
        imdn_message_id: b"m1",
        from,
        to: b"<sip:group@conf.example.com>",
        date: b"2026-11-13T00:00:00Z",
        from_uri: None,
        to_uri: None,
        payload_type: None,
        disposition_notification: None,
        mls_derived_content_signature: None,
        mls_original_message_id: None,
    };
    assert_eq!(
        cpim_from(&cpim_info(b"Bob <tel:+15550002>")),
        "tel:+15550002"
    );
    assert_eq!(cpim_from(&cpim_info(b" tel:+15550002 ")), "tel:+15550002");
}

#[test]
fn joining_or_leaving_a_video_chat_is_reported_in_a_sip_message() {
    // RCC.07 v18.0 section 3.7.5.2.5
    let (client, mut peer) = start(true);
    let engine = Engine::over(&client, configured(true, true));
    let tm = client.core.get_transaction_manager();
    report_video_chat_event(
        &engine.route,
        &tm,
        "sip:mivc@example.com",
        VIDEO_CHAT.to_vec(),
        &client.rt,
    );
    let message = peer.next_request("MESSAGE");
    assert_eq!(request_uri(&message), "sip:mivc@example.com");
    assert_eq!(header_value(&message, "Content-Type"), CONTENT_TYPE);
    assert!(header_value(&message, "From").starts_with(&format!("<{}>;tag=", IMPU)));
    assert_eq!(header_value(&message, "P-Preferred-Identity"), IMPU);
    assert_eq!(body_data(&message), VIDEO_CHAT);
    peer.send(&answer(&message, "200 OK", None));

    // nothing while not registered
    engine.unregister();
    report_video_chat_event(
        &engine.route,
        &tm,
        "sip:mivc@example.com",
        VIDEO_CHAT.to_vec(),
        &client.rt,
    );
    peer.silence();
}

#[test]
fn the_feature_tag_of_video_chat_is_told_besides_those_of_e2ee() {
    let e2ee = || Some(String::from("+g.gsma.rcs.msg.e2ee=\"1\""));
    assert_eq!(
        joined_feature_tags(e2ee(), Some("+g.gsma.rcs.videochat")).as_deref(),
        Some("+g.gsma.rcs.msg.e2ee=\"1\";+g.gsma.rcs.videochat")
    );
    assert_eq!(
        joined_feature_tags(None, Some("+g.gsma.rcs.videochat")).as_deref(),
        Some("+g.gsma.rcs.videochat")
    );
    assert_eq!(joined_feature_tags(e2ee(), None), e2ee());
    assert_eq!(joined_feature_tags(Some(String::new()), None), None);
    assert_eq!(joined_feature_tags(None, None), None);
}

#[test]
fn a_group_video_chat_message_goes_in_the_group_chat() {
    // RCC.07 v18.0 section 3.7.5.5
    let (client, mut peer) = start(true);
    let rt = Arc::clone(&client.rt);
    let engine = Engine::over(&client, configured_for_groups());
    let (mut connection, _, _, _) = new_group(&client, &mut peer);

    let sent = engine.group_video_chat(VIDEO_CHAT);
    let send = connection.next_message(&rt);
    let cpim = String::from_utf8_lossy(&send.body).into_owned();
    assert!(cpim.contains(&format!("To: <{}>", GROUP)), "{}", cpim);
    assert!(
        cpim.contains("Content-Type: rcs/video-chat+proto"),
        "{}",
        cpim
    );
    assert!(!cpim.contains("Disposition-Notification"), "{}", cpim);
    assert_eq!(cpim_content(&send.body), VIDEO_CHAT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);

    // not without group chats
    let mut messaging = configured_for_groups();
    messaging.group_chat_auth = 0;
    engine.configure(messaging);
    assert_eq!(told(&engine.group_video_chat(VIDEO_CHAT)), 403);

    // nor yet in a group encrypted end to end, where it is to be signed
    // (RCC.16 section 9.8.2)
    engine.configure(configured_for_groups());
    let conversation_id = client.sessions.group_conversation_id(GROUP).unwrap();
    encrypting(
        &client,
        ChatScript {
            encrypting: vec![conversation_id.clone()],
            ..ChatScript::default()
        },
    );
    assert_eq!(told(&engine.group_video_chat(VIDEO_CHAT)), 488);

    // but as in one not encrypted once it moved to unencrypted (RCC.16
    // section 11.2)
    client
        .sessions
        .set_group_encryption(
            ScriptedEncryption::moved_to_unencrypted(vec![conversation_id])
                as Arc<dyn GroupEncryption>,
        );
    let sent = engine.group_video_chat(VIDEO_CHAT);
    let send = connection.next_message(&rt);
    assert_eq!(cpim_content(&send.body), VIDEO_CHAT);
    connection.respond(&rt, &send, "200 OK");
    assert_eq!(told(&sent), 200);
    connection.quiet(&rt);
    peer.silence();
}
