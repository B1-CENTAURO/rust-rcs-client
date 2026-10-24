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

extern crate rust_rcs_core;
extern crate rust_strict_sdp;

use std::io::Read;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

use futures::Future;

use rust_rcs_core::cpim::{CPIMInfo, CPIMMessage};
use rust_rcs_core::internet::body::message_body::MessageBody;
use rust_rcs_core::internet::body::multipart_body::MultipartBody;
use rust_rcs_core::internet::body::VectorReader;
use rust_rcs_core::internet::header::search;
use rust_rcs_core::internet::header_field::AsHeaderField;
use rust_rcs_core::internet::Body;
use rust_rcs_core::internet::{header, Header};

use rust_rcs_core::internet::headers::{AsContentType, Supported};

use rust_rcs_core::internet::name_addr::AsNameAddr;
use rust_rcs_core::io::network::stream::{ClientSocket, ClientStream};
use rust_rcs_core::io::{DynamicChain, Serializable};
use rust_rcs_core::msrp::info::msrp_info_reader::AsMsrpInfo;
use rust_rcs_core::msrp::info::{MsrpDirection, MsrpInfo, MsrpInterfaceType, MsrpSetupMethod};
use rust_rcs_core::msrp::msrp_channel::MsrpChannel;
use rust_rcs_core::msrp::msrp_chunk::MsrpChunk;
use rust_rcs_core::msrp::msrp_demuxer::MsrpDemuxer;
use rust_rcs_core::msrp::msrp_muxer::{MsrpDataWriter, MsrpMessageReceiver, MsrpMuxer};
use rust_rcs_core::msrp::msrp_transport::msrp_transport_start;
// use rust_rcs_core::msrp::msrp_transport::MsrpTransportWrapper;
use rust_rcs_core::sip::sip_core::SipDialogCache;
use rust_rcs_core::sip::sip_session::{
    choose_timeout_for_server_transaction_response,
    choose_timeout_on_client_transaction_completion, Refresher, SipSession, SipSessionEvent,
    SipSessionEventReceiver,
};
use rust_rcs_core::sip::sip_transaction::client_transaction::ClientTransactionNilCallbacks;
use rust_rcs_core::sip::sip_transaction::server_transaction;

use rust_rcs_core::sip::SipDialog;
use rust_rcs_core::sip::{ClientTransactionCallbacks, SipTransactionManager};
use rust_rcs_core::sip::{ServerTransaction, SipDialogEventCallbacks};
use rust_rcs_core::sip::{ServerTransactionEvent, UPDATE};
use rust_rcs_core::sip::{SipCore, SipTransport};

use rust_rcs_core::sip::SipMessage;
use rust_rcs_core::sip::TransactionHandler;

use rust_rcs_core::sip::INVITE;

use rust_rcs_core::sip::sip_headers::AsFromTo;

use rust_rcs_core::util::rand::create_raw_alpha_numeric_string;

use rust_strict_sdp::AsSDP;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::contact::ContactKnownIdentities;
use crate::messaging::ffi::RecipientType;

use super::encryption::{GroupEncryption, CONTENT_TYPE_MLS_RCS_SERVER};
use super::group_chat::{refer_participants, GroupChats, GroupIds, GroupInvitation, Participant};
use super::imdn::send_group_imdn;
use super::session_invitation::{
    decline_hanging_invitation, end_cancelled_invitation, try_accept_hanging_invitation,
    try_accept_invitation, CPMSessionInvitation, CPMSessionInvitationResponse,
};
use super::sip::cpm_accept_contact::CPMAcceptContact;
use super::sip::cpm_contact::{AsCPMContact, CPMContact, CPMServiceType};
use super::standalone_messaging::OutgoingPagerModeContext;
use super::{
    decode_base64, is_composing_document, is_media_type, make_cpim_message_content_body,
    new_message_id, understands_cpim_requirements, CPMMessageParam, IS_COMPOSING,
};

// to-do: use enum
pub struct CPMSessionInfo {
    pub cpm_contact: CPMContact,
    pub asserted_contact_uri: String,
    pub conversation_id: Option<String>,
    pub contribution_id: Option<String>,
    pub subject: Option<String>,
    pub referred_by: Option<String>,
    pub is_deferred_session: bool,
    pub contact_alias: Option<String>,
    pub conversation_supports_anonymization: bool,
    pub conversation_is_using_anonymization_token: bool,
}

impl CPMSessionInfo {
    /// Whom the messages of the session are from, as the app knows it: a
    /// group by its focus's URI, which it sends to, else the identity
    /// asserted
    pub fn contact_uri(&self) -> String {
        match self.cpm_contact.service_type {
            CPMServiceType::Group => {
                String::from_utf8_lossy(&self.cpm_contact.service_uri).into_owned()
            }
            _ => self.asserted_contact_uri.clone(),
        }
    }

    pub fn get_contact_known_identities(&self) -> ContactKnownIdentities {
        let mut known_identities = ContactKnownIdentities::new();
        known_identities.add_identity(self.asserted_contact_uri.clone());
        // a group by its focus, which messages to it are sent to (RFC 4579)
        match self.cpm_contact.service_type {
            CPMServiceType::OneToOne | CPMServiceType::Chatbot | CPMServiceType::Group => {
                if let Ok(service_uri) = std::str::from_utf8(&self.cpm_contact.service_uri) {
                    known_identities.add_identity(String::from(service_uri));
                }
            }
            _ => {}
        }
        if let Some(contact_alias) = &self.contact_alias {
            known_identities.add_identity(String::from(contact_alias));
        }
        known_identities
    }
}

/// Whether `uri` is the store and forward server's, which delivers deferred
/// messages on behalf of their sender (GSMA RCC.07 section 3.3.4.1.5)
fn is_store_and_forward_server(uri: &[u8]) -> bool {
    let user_part = match uri.iter().position(|c| *c == b':') {
        Some(idx) => &uri[idx + 1..],
        None => uri,
    };
    user_part.len() >= 13 && user_part[..13].eq_ignore_ascii_case(b"rcse-standfw@")
}

pub fn get_cpm_session_info_from_message(
    message: &SipMessage,
    is_outgoing: bool,
) -> Option<CPMSessionInfo> {
    if let Some(headers) = message.headers() {
        let mut contact_header = None;
        let mut asserted_identity_header = None;
        let mut subject_header = None;
        let mut referred_by_header = None;

        let mut from_header = None;
        let mut to_header = None;

        let mut conversation_id: Option<&[u8]> = None;
        let mut contribution_id: Option<&[u8]> = None;

        for header in headers {
            if header.get_name().eq_ignore_ascii_case(b"Contact") {
                contact_header = Some(header);
            } else if header
                .get_name()
                .eq_ignore_ascii_case(b"P-Asserted-Identity")
            {
                asserted_identity_header = Some(header);
            } else if header.get_name().eq_ignore_ascii_case(b"Conversation-ID") {
                conversation_id = Some(header.get_value());
            } else if header.get_name().eq_ignore_ascii_case(b"Contribution-ID") {
                contribution_id = Some(header.get_value());
            } else if header.get_name().eq_ignore_ascii_case(b"Subject") {
                subject_header = Some(header);
            } else if header.get_name().eq_ignore_ascii_case(b"Referred-By") {
                referred_by_header = Some(header);
            } else if header.get_name().eq_ignore_ascii_case(b"From") {
                from_header = Some(header);
            } else if header.get_name().eq_ignore_ascii_case(b"To") {
                to_header = Some(header);
            }
        }

        if let Some(contact_header) = contact_header {
            if let Some(cpm_contact) = contact_header
                .get_value()
                .as_header_field()
                .as_cpm_contact()
            {
                let mut asserted_contact_uri = None;
                let mut is_deferred_session = false;
                let mut conversation_supports_anonymization = false;
                let mut conversation_is_using_anonymization_token = false;

                match cpm_contact.service_type {
                    CPMServiceType::OneToOne | CPMServiceType::Chatbot => {
                        if let Some(asserted_identity_header) = asserted_identity_header {
                            if let Some(name_addr) = asserted_identity_header
                                .get_value()
                                .as_name_addresses()
                                .first()
                            {
                                if let Some(uri_part) = &name_addr.uri_part {
                                    if is_store_and_forward_server(uri_part.uri) {
                                        is_deferred_session = true;
                                        if let Some(referred_by_header) = referred_by_header {
                                            if let Some(referred_by) = referred_by_header
                                                .get_value()
                                                .as_name_addresses()
                                                .first()
                                            {
                                                if let Some(uri_part) = &referred_by.uri_part {
                                                    asserted_contact_uri = Some(uri_part.uri);
                                                    for p in referred_by_header
                                                        .get_value()
                                                        .as_header_field()
                                                        .get_parameter_iterator()
                                                    {
                                                        if p.name == b"tk" {
                                                            match p.value {
                                                                Some(b"on") => {
                                                                    conversation_supports_anonymization = true;
                                                                    conversation_is_using_anonymization_token = true;
                                                                }
                                                                Some(b"off") => {
                                                                    conversation_supports_anonymization = true;
                                                                }
                                                                _ => {}
                                                            }
                                                            break;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if !is_deferred_session {
                                        asserted_contact_uri = Some(uri_part.uri);
                                        for p in uri_part.get_parameter_iterator() {
                                            if p.name == b"tk" {
                                                match p.value {
                                                    Some(b"on") => {
                                                        conversation_supports_anonymization = true;
                                                        conversation_is_using_anonymization_token =
                                                            true;
                                                    }
                                                    Some(b"off") => {
                                                        conversation_supports_anonymization = true;
                                                    }
                                                    _ => {}
                                                }
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    _ => {
                        if let Some(asserted_identity_header) = asserted_identity_header {
                            if let Some(name_addr) = asserted_identity_header
                                .get_value()
                                .as_name_addresses()
                                .first()
                            {
                                if let Some(uri_part) = &name_addr.uri_part {
                                    asserted_contact_uri = Some(uri_part.uri);
                                }
                            }
                        }
                    }
                }

                if asserted_contact_uri.is_none() {
                    asserted_contact_uri = Some(&cpm_contact.service_uri);
                }

                if let Some(asserted_contact_uri) = asserted_contact_uri {
                    if let Ok(asserted_contact_uri) = std::str::from_utf8(asserted_contact_uri) {
                        let asserted_contact_uri = String::from(asserted_contact_uri);

                        let mut contact_alias = None;
                        if is_outgoing {
                            if let Some(to_header) = to_header {
                                if let Some(name_addr) = to_header
                                    .get_value()
                                    .as_header_field()
                                    .as_from_to()
                                    .addresses
                                    .first()
                                {
                                    if let Some(display_name) = name_addr.display_name {
                                        if let Ok(display_name) = std::str::from_utf8(display_name)
                                        {
                                            contact_alias = Some(String::from(display_name));
                                        }
                                    }
                                }
                            }
                        } else {
                            if let Some(from_header) = from_header {
                                if let Some(name_addr) = from_header
                                    .get_value()
                                    .as_header_field()
                                    .as_from_to()
                                    .addresses
                                    .first()
                                {
                                    if let Some(display_name) = name_addr.display_name {
                                        if let Ok(display_name) = std::str::from_utf8(display_name)
                                        {
                                            contact_alias = Some(String::from(display_name));
                                        }
                                    }
                                }
                            }
                        }

                        return Some(CPMSessionInfo {
                            cpm_contact,
                            asserted_contact_uri,
                            conversation_id: match conversation_id {
                                Some(conversation_id) => match std::str::from_utf8(conversation_id)
                                {
                                    Ok(conversation_id) => Some(String::from(conversation_id)),
                                    Err(_) => None,
                                },
                                None => None,
                            },
                            contribution_id: match contribution_id {
                                Some(contribution_id) => match std::str::from_utf8(contribution_id)
                                {
                                    Ok(contribution_id) => Some(String::from(contribution_id)),
                                    Err(_) => None,
                                },
                                None => None,
                            },
                            subject: match subject_header {
                                Some(subject_header) => {
                                    if let Ok(subject) =
                                        std::str::from_utf8(subject_header.get_value())
                                    {
                                        Some(String::from(subject))
                                    } else {
                                        None
                                    }
                                }
                                None => None,
                            },
                            referred_by: match referred_by_header {
                                Some(referred_by_header) => {
                                    if let Ok(referred_by) =
                                        std::str::from_utf8(referred_by_header.get_value())
                                    {
                                        Some(String::from(referred_by))
                                    } else {
                                        None
                                    }
                                }
                                None => None,
                            },
                            is_deferred_session,
                            contact_alias,
                            conversation_supports_anonymization,
                            conversation_is_using_anonymization_token,
                        });
                    }
                }
            }
        }
    }

    None
}

enum CPMSessionNegotiationState {
    NoneSet,
    LocalSet(Arc<Body>, Option<ClientSocket>, bool, String, u16, Vec<u8>),
    RemoteSet(Arc<Body>, String, u16, Vec<u8>),
}

enum CPMSessionState {
    Negotiating(CPMSessionNegotiationState),
    Negotiated(
        Arc<Body>,
        Arc<Body>,
        Option<ClientSocket>,
        bool,
        String,
        u16,
        Vec<u8>,
        String,
        u16,
        Vec<u8>,
    ),
    Starting(
        Arc<Body>,
        Arc<Body>,
        String,
        u16,
        String,
        u16,
        // Arc<MsrpChannel>,
        mpsc::Sender<CPMMessageParam>,
    ),
    /// Ended by either side, its MSRP connection closing as the sender of
    /// the messages, kept by Starting, is dropped
    Ended,
    // Started(
    //     Arc<Body>,
    //     Arc<Body>,
    //     String,
    //     u16,
    //     String,
    //     u16,
    //     Arc<MsrpTransport>,
    // ),
    // also
    //  there is no Re-negotiating for CPM Session
}

pub struct CPMSession {
    session_info: CPMSessionInfo,
    session_state: Arc<Mutex<CPMSessionState>>,
    /// The messages sent before the session started, taken under the state
    /// lock
    pending_messages: Mutex<Vec<CPMMessageParam>>,
    /// Told when the session ends
    ended: Arc<Notify>,
    /// The writer of the MSRP connection, once up, taken under the state
    /// lock
    msrp_writer: Arc<Mutex<Option<mpsc::Sender<Option<Vec<u8>>>>>>,
    /// What ending the session takes, once its dialog is confirmed, taken
    /// when it ends
    session_end: Mutex<Option<SessionEnd>>,
    /// Set when the session ends, for any number to watch
    ended_watch: watch::Sender<bool>,
}

impl CPMSession {
    pub fn new(session_info: CPMSessionInfo) -> CPMSession {
        CPMSession {
            session_info,
            session_state: Arc::new(Mutex::new(CPMSessionState::Negotiating(
                CPMSessionNegotiationState::NoneSet,
            ))),
            pending_messages: Mutex::new(Vec::new()),
            ended: Arc::new(Notify::new()),
            msrp_writer: Arc::new(Mutex::new(None)),
            session_end: Mutex::new(None),
            ended_watch: watch::channel(false).0,
        }
    }

    /// Whether the session ended, as it changes: true once it has
    pub fn when_ended(&self) -> watch::Receiver<bool> {
        self.ended_watch.subscribe()
    }

    /// Keeps what ending the session takes, for it to be ended on request
    pub(crate) fn keep_session_end(&self, session_end: SessionEnd) {
        self.session_end.lock().unwrap().replace(session_end);
    }

    /// Told once when the session ends, to whoever waits first
    pub fn ended(&self) -> Arc<Notify> {
        Arc::clone(&self.ended)
    }

    pub fn get_session_info(&self) -> &CPMSessionInfo {
        &self.session_info
    }

    pub fn set_local_sdp(
        &self,
        l_sdp: Arc<Body>,
        cs: ClientSocket,
        tls: bool,
        laddr: String,
        lport: u16,
        lpath: Vec<u8>,
    ) -> Result<(), &'static str> {
        let mut guard = self.session_state.lock().unwrap();
        match &mut *guard {
            CPMSessionState::Negotiating(ref mut negotiation_state) => match negotiation_state {
                CPMSessionNegotiationState::NoneSet => {
                    *guard = CPMSessionState::Negotiating(CPMSessionNegotiationState::LocalSet(
                        l_sdp,
                        Some(cs),
                        tls,
                        laddr,
                        lport,
                        lpath,
                    ));
                    Ok(())
                }
                CPMSessionNegotiationState::LocalSet(_, _, _, _, _, _) => Err("local already set"),
                CPMSessionNegotiationState::RemoteSet(
                    ref r_sdp,
                    ref raddr,
                    ref rport,
                    ref mut rpath,
                ) => {
                    let mut path = Vec::new();
                    path.append(rpath);
                    *guard = CPMSessionState::Negotiated(
                        l_sdp,
                        Arc::clone(r_sdp),
                        Some(cs),
                        tls,
                        laddr,
                        lport,
                        lpath,
                        String::from(raddr),
                        *rport,
                        path,
                    );
                    Ok(())
                }
            },

            _ => Err("already negotiated"),
        }
    }

    pub fn set_remote_sdp(
        &self,
        r_sdp: Arc<Body>,
        raddr: String,
        rport: u16,
        rpath: Vec<u8>,
    ) -> Result<(), &'static str> {
        let mut guard = self.session_state.lock().unwrap();
        match &mut *guard {
            CPMSessionState::Negotiating(ref mut negotiation_state) => match negotiation_state {
                CPMSessionNegotiationState::NoneSet => {
                    *guard = CPMSessionState::Negotiating(CPMSessionNegotiationState::RemoteSet(
                        r_sdp, raddr, rport, rpath,
                    ));
                    Ok(())
                }
                CPMSessionNegotiationState::LocalSet(
                    ref l_sdp,
                    ref mut sock,
                    ref tls,
                    ref laddr,
                    ref lport,
                    ref mut lpath,
                ) => {
                    let mut path = Vec::new();
                    path.append(lpath);
                    *guard = CPMSessionState::Negotiated(
                        Arc::clone(l_sdp),
                        r_sdp,
                        sock.take(),
                        *tls,
                        String::from(laddr),
                        *lport,
                        path,
                        raddr,
                        rport,
                        rpath,
                    );
                    Ok(())
                }
                CPMSessionNegotiationState::RemoteSet(_, _, _, _) => Err("remote already set"),
            },

            _ => Err("already negotiated"),
        }
    }

    pub fn start<MRL, F>(
        &self,
        public_user_identity: &str,
        message_receive_listener: MRL,
        connect_function: &Arc<
            dyn Fn(
                    ClientSocket,
                    &String,
                    u16,
                    bool,
                ) -> Pin<
                    Box<dyn Future<Output = Result<ClientStream, (u16, &'static str)>> + Send>,
                > + Send
                + Sync
                + 'static,
        >,
        session_end_function: F,
        rt: &Arc<Runtime>,
    ) -> Result<mpsc::Sender<CPMMessageParam>, ()>
    where
        MRL: Fn(&CPIMInfo, &[u8], &[u8]) + Send + Sync + 'static,
        F: Fn() + Send + Sync + 'static,
    {
        let mut guard = self.session_state.lock().unwrap();
        match &mut *guard {
            CPMSessionState::Negotiated(
                ref l_sdp,
                ref r_sdp,
                ref mut sock,
                ref tls,
                ref laddr,
                ref lport,
                ref mut lpath,
                ref raddr,
                ref rport,
                ref mut rpath,
            ) => {
                if let Some(sock) = sock.take() {
                    let mut from_path = Vec::with_capacity(lpath.len());
                    from_path.append(lpath);
                    let mut to_path = Vec::with_capacity(rpath.len());
                    to_path.append(rpath);
                    let from_path_ = from_path.clone();
                    let to_path_ = to_path.clone();
                    let demuxer = MsrpDemuxer::new(from_path_, to_path_);
                    let demuxer = Arc::new(demuxer);
                    let demuxer_ = Arc::clone(&demuxer);
                    let message_receive_listener = Arc::new(message_receive_listener);
                    let muxer = MsrpMuxer::new(CPMSessionMessageReceiver {
                        callback: Arc::new(move |cpim_info, content_type, content_body| {
                            message_receive_listener(cpim_info, content_type, content_body)
                        }),
                    });

                    let from_path_ = from_path.clone();
                    let to_path_ = to_path.clone();

                    let mut session_channel =
                        MsrpChannel::new(from_path_, to_path_, demuxer, muxer);
                    // let session_channel = Arc::new(session_channel);
                    // let session_channel_ = Arc::clone(&session_channel);

                    let addr = String::from(raddr);
                    let port = *rport;
                    let tls = *tls;

                    let l_sdp = Arc::clone(l_sdp);
                    // let l_sdp_ = Arc::clone(&l_sdp);
                    let r_sdp = Arc::clone(r_sdp);
                    // let r_sdp_ = Arc::clone(&r_sdp);

                    let laddr = String::from(laddr);
                    // let laddr_ = String::from(&laddr);
                    let lport = *lport;
                    let raddr = String::from(raddr);
                    // let raddr_ = String::from(&raddr);
                    let rport = *rport;

                    let (message_tx, mut message_rx) = mpsc::channel::<CPMMessageParam>(8);
                    let message_tx_ = message_tx.clone();

                    // the messages sent while the session was set up go first
                    let pending_messages =
                        std::mem::take(&mut *self.pending_messages.lock().unwrap());
                    if !pending_messages.is_empty() {
                        let message_tx = message_tx.clone();
                        rt.spawn(async move {
                            for message in pending_messages {
                                if let Err(e) = message_tx.send(message).await {
                                    (e.0.message_result_callback)(
                                        500,
                                        String::from("Internal Error"),
                                    );
                                }
                            }
                        });
                    }

                    *guard = CPMSessionState::Starting(
                        l_sdp, r_sdp, laddr, lport, raddr, rport,
                        // session_channel,
                        message_tx,
                    );

                    let t_id = String::from(public_user_identity);
                    let public_user_identity = String::from(public_user_identity);

                    let rt_ = Arc::clone(rt);

                    // let session_state = Arc::clone(&self.session_state);

                    let future = connect_function(sock, &addr, port, tls);

                    let session_state = Arc::clone(&self.session_state);
                    let msrp_writer = Arc::clone(&self.msrp_writer);
                    let session_end_function = Arc::new(session_end_function);
                    let session_end_function_ = Arc::clone(&session_end_function);

                    rt.spawn(async move {
                        let cs = match future.await {
                            Ok(cs) => cs,
                            Err(_) => {
                                // no connection, no session
                                session_end_function_();
                                return;
                            }
                        };
                        {
                            // let transport = MsrpTransportWrapper::new(
                            //     cs,
                            //     t_id,
                            //     move |message_chunk| session_channel.on_message(message_chunk),
                            //     move |transport| session_end_function(),
                            //     &rt_,
                            // );

                            // let t = transport.get_transport();

                            // let mut guard = session_state.lock().unwrap();

                            // *guard = CPMSessionState::Started(l_sdp_, r_sdp_, laddr_, lport, raddr_, rport, t);

                            let (data_tx, data_rx) = mpsc::channel(8);
                            let data_tx_ = data_tx.clone();

                            // the writer, which the session closes the
                            // connection with when it ends, unless it has
                            if let CPMSessionState::Ended = *session_state.lock().unwrap() {
                                return;
                            } else {
                                *msrp_writer.lock().unwrap() = Some(data_tx.clone());
                            }

                            msrp_transport_start(
                                cs,
                                t_id,
                                data_tx_,
                                data_rx,
                                move |message_chunk| session_channel.on_message(message_chunk),
                                move || session_end_function(),
                                &rt_,
                            );

                            let data_tx_ = data_tx.clone();

                            let (chunk_tx, mut chunk_rx) = mpsc::channel::<MsrpChunk>(16);

                            rt_.spawn(async move {
                                while let Some(chunk) = chunk_rx.recv().await {
                                    let size = chunk.estimated_size();
                                    let mut data = Vec::with_capacity(size);

                                    {
                                        let mut readers = Vec::new();
                                        chunk.get_readers(&mut readers);
                                        match DynamicChain::new(readers).read_to_end(&mut data) {
                                            Ok(_) => {}
                                            Err(_) => {} // to-do: early failure
                                        }
                                    }

                                    match data_tx_.send(Some(data)).await {
                                        Ok(()) => {}
                                        Err(e) => {}
                                    }
                                }
                            });

                            // the side that connects binds the connection to
                            // the session at once, with a SEND that may be
                            // empty (RFC 4975 section 5.4)
                            demuxer_.start(
                                from_path.clone(),
                                to_path.clone(),
                                None,
                                0,
                                std::io::empty(),
                                |_, _| {},
                                chunk_tx.clone(),
                                &rt_,
                            );

                            while let Some(message) = message_rx.recv().await {
                                let (content_type, data) = if message.raw {
                                    (
                                        message.message_type.as_bytes().to_vec(),
                                        message.message_content.as_bytes().to_vec(),
                                    )
                                } else {
                                    let body = make_cpim_message_content_body(
                                        &message.message_type,
                                        &message.message_content,
                                        &message.recipient_type,
                                        &message.recipient_uri,
                                        &message.message_id,
                                        &public_user_identity,
                                    );

                                    let mut data = Vec::with_capacity(body.estimated_size());
                                    match body.reader() {
                                        Ok(mut reader) => {
                                            match reader.read_to_end(&mut data) {
                                                Ok(_) => {}
                                                Err(_) => {} // to-do: early failure
                                            }
                                        }
                                        Err(_) => {} // to-do: early failure
                                    }

                                    (b"message/cpim".to_vec(), data)
                                };
                                let content_type = Some(content_type);
                                let size = data.len();

                                let from_path_ = from_path.clone();
                                let to_path_ = to_path.clone();

                                let chunk_tx = chunk_tx.clone();

                                demuxer_.start(
                                    from_path_,
                                    to_path_,
                                    content_type,
                                    size,
                                    VectorReader::new(data),
                                    move |status_code, reason_phrase| {
                                        (message.message_result_callback)(
                                            status_code,
                                            reason_phrase,
                                        );
                                    },
                                    chunk_tx,
                                    &rt_,
                                );
                            }
                        }
                    });

                    return Ok(message_tx_);
                }
            }
            _ => {}
        }

        Err(())
    }

    pub fn send_message(&self, message: CPMMessageParam, rt: &Arc<Runtime>) {
        let guard = self.session_state.lock().unwrap();
        match &*guard {
            // until the session starts, as an incoming one does on the ACK
            CPMSessionState::Negotiating(_) | CPMSessionState::Negotiated(..) => {
                self.pending_messages.lock().unwrap().push(message);
            }
            CPMSessionState::Starting(_, _, _, _, _, _, message_tx) => {
                let message_tx = message_tx.clone();
                rt.spawn(async move {
                    match message_tx.send(message).await {
                        Ok(()) => {}
                        Err(e) => {
                            (e.0.message_result_callback)(500, String::from("Internal Error"))
                        }
                    }
                });
            }
            CPMSessionState::Ended => {
                drop(guard);
                (message.message_result_callback)(480, String::from("Temporarily Unavailable"));
            }
        }
    }

    /// Ends the session, closing its MSRP connection, and failing the
    /// messages waiting for it to start; whether it had not ended already
    pub fn end(&self, rt: &Arc<Runtime>) -> bool {
        let (pending_messages, msrp_writer) = {
            let mut guard = self.session_state.lock().unwrap();
            if let CPMSessionState::Ended = *guard {
                return false;
            }
            *guard = CPMSessionState::Ended;
            (
                std::mem::take(&mut *self.pending_messages.lock().unwrap()),
                self.msrp_writer.lock().unwrap().take(),
            )
        };

        // the connection is closed, which its transport, holding a sender of
        // its own, would not be on its senders being dropped
        if let Some(msrp_writer) = msrp_writer {
            rt.spawn(async move {
                let _ = msrp_writer.send(None).await;
            });
        }

        self.ended.notify_one();
        self.ended_watch.send_replace(true);

        for message in pending_messages {
            (message.message_result_callback)(480, String::from("Temporarily Unavailable"));
        }

        true
    }
}

/// The Reason of the BYE leaving a group chat for good, as RCC.07 gives it;
/// one of another cause leaves it only until the session is restarted
const LEAVING_REASON: &[u8] = b"SIP;cause=200;text=\"Call completed\"";

/// What ending a chat session takes
#[derive(Clone)]
pub(crate) struct SessionEnd {
    pub(crate) sip_session: Arc<SipSession<CPMSession>>,
    pub(crate) ongoing_sessions:
        Arc<Mutex<Vec<(ContactKnownIdentities, Arc<SipSession<CPMSession>>)>>>,
    pub(crate) dialog: Arc<SipDialog>,
    pub(crate) tm: Arc<SipTransactionManager>,
    pub(crate) registered_public_identity: Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>,
    pub(crate) rt: Arc<Runtime>,
}

impl SessionEnd {
    /// Ends the session, unless it ended already: a message sent from now on
    /// starts another, its MSRP connection closes, and its dialog goes,
    /// ended with a BYE if `send_bye`, as when its MSRP connection is lost
    pub(crate) fn end(&self, send_bye: bool) {
        if !self.close() {
            return;
        }

        if send_bye {
            if let Ok(message) = self.dialog.make_request(b"BYE", None) {
                self.send(message, ClientTransactionNilCallbacks {});
            }
        }

        self.hang_up();
    }

    /// Leaves the group the session is with for good, where end() leaves it
    /// only until the next session: with a BYE whose Reason is SIP cause 200
    /// (RCC.07 section 3.2.4.11, by RCC.11), `callback` told how it was
    /// answered, or else why it was not sent
    pub(crate) fn leave<F>(&self, callback: F)
    where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        if !self.close() {
            callback(481, String::from("Call/Transaction Does Not Exist"));
            return;
        }

        let (client_transaction_tx, mut client_transaction_rx) = mpsc::channel(1);
        self.rt.spawn(async move {
            match client_transaction_rx.recv().await {
                Some((status_code, reason_phrase)) => callback(status_code, reason_phrase),
                None => callback(500, String::from("Internal Error")),
            }
        });

        if let Ok(mut message) = self.dialog.make_request(b"BYE", None) {
            message.add_header(Header::new(b"Reason", LEAVING_REASON));
            self.send(
                message,
                OutgoingPagerModeContext {
                    client_transaction_tx,
                    rt: Arc::clone(&self.rt),
                },
            );
        }

        self.hang_up();
    }

    /// Takes the session out of those ongoing and ends it; false if it ended
    /// already
    fn close(&self) -> bool {
        // which the session holds, and holds it
        self.sip_session
            .get_inner()
            .session_end
            .lock()
            .unwrap()
            .take();

        {
            let mut guard = self.ongoing_sessions.lock().unwrap();
            if let Some(idx) = guard
                .iter()
                .position(|(_, sip_session)| Arc::ptr_eq(sip_session, &self.sip_session))
            {
                guard.swap_remove(idx);
            }
        }

        self.sip_session.get_inner().end(&self.rt)
    }

    /// Sends `message` over the registered transport, if there is one
    fn send<C>(&self, message: SipMessage, callbacks: C)
    where
        C: ClientTransactionCallbacks + Send + Sync + 'static,
    {
        let transport = match &*self.registered_public_identity.lock().unwrap() {
            Some((transport, _, _)) => Some(Arc::clone(transport)),
            None => None,
        };
        if let Some(transport) = transport {
            self.tm
                .send_request(message, &transport, callbacks, &self.rt);
        }
    }

    /// Lets go of the session's dialog, not from within the dialog, which
    /// may be calling us
    fn hang_up(&self) {
        let sip_session = Arc::clone(&self.sip_session);
        self.rt.spawn(async move {
            sip_session.hang_up();
        });
    }
}

type OutgoingInvitation = Arc<(ContactKnownIdentities, mpsc::Sender<CPMMessageParam>)>;

fn remove_invitation(
    invitations: &Arc<Mutex<Vec<OutgoingInvitation>>>,
    invitation: &OutgoingInvitation,
) {
    let mut guard = invitations.lock().unwrap();
    if let Some(idx) = guard.iter().position(|i| Arc::ptr_eq(i, invitation)) {
        guard.swap_remove(idx);
    }
}

/// Ends an invitation that failed, so that a message sent from now on
/// starts another, and fails those waiting for it as it failed
fn fail_invitation(
    invitations: &Arc<Mutex<Vec<OutgoingInvitation>>>,
    invitation: OutgoingInvitation,
    message_rx: &mut mpsc::Receiver<CPMMessageParam>,
    status_code: u16,
    reason_phrase: &str,
) {
    remove_invitation(invitations, &invitation);
    drop(invitation);
    message_rx.close();
    while let Ok(message) = message_rx.try_recv() {
        (message.message_result_callback)(status_code, String::from(reason_phrase));
    }
}

impl Drop for CPMSession {
    /// The messages that waited for a session that never started fail
    fn drop(&mut self) {
        let pending_messages = std::mem::take(&mut *self.pending_messages.lock().unwrap());
        for message in pending_messages {
            (message.message_result_callback)(480, String::from("Temporarily Unavailable"));
        }
    }
}

struct CPMSessionCPIMMessageWriter {
    message_id: Vec<u8>,
    message_buf: Vec<u8>,
    message_callback: Arc<dyn Fn(&CPIMInfo, &[u8], &[u8]) + Send + Sync>,
}

impl MsrpDataWriter for CPMSessionCPIMMessageWriter {
    fn write(&mut self, data: &[u8]) -> Result<usize, (u16, &'static str)> {
        self.message_buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn complete(&mut self) -> Result<(), (u16, &'static str)> {
        match Body::construct_message(&self.message_buf) {
            Ok(body) => match CPIMMessage::try_from(&body) {
                Ok(cpim_message) if !understands_cpim_requirements(&cpim_message) => {
                    Err((400, "required CPIM header not understood"))
                }

                Ok(cpim_message) => match cpim_message.get_info() {
                    Ok(cpim_message_info) => {
                        if let Some((content_type, content_body, base64_encoded)) =
                            cpim_message.get_message_body()
                        {
                            let content_type: &[u8] = match content_type {
                                Some(content_type) => content_type,
                                None => b"text/plain",
                            };

                            if base64_encoded {
                                if let Ok(decoded_content_body) = decode_base64(content_body) {
                                    (self.message_callback)(
                                        &cpim_message_info,
                                        content_type,
                                        &decoded_content_body,
                                    );
                                    return Ok(());
                                }
                            } else {
                                (self.message_callback)(
                                    &cpim_message_info,
                                    content_type,
                                    content_body,
                                );
                                return Ok(());
                            }
                        }

                        Err((400, "failed to get content body"))
                    }

                    Err(e) => Err((400, e)),
                },

                Err(e) => Err((400, e)),
            },

            Err(e) => Err((400, e)),
        }
    }
}

struct CPMSessionMessageReceiver {
    callback: Arc<dyn Fn(&CPIMInfo, &[u8], &[u8]) + Send + Sync>,
}

impl MsrpMessageReceiver for CPMSessionMessageReceiver {
    fn on_message(
        &mut self,
        message_id: &[u8],
        content_type: &[u8],
    ) -> Result<Box<dyn MsrpDataWriter + Send + Sync>, (u16, &'static str)> {
        if content_type.eq_ignore_ascii_case(b"message/cpim") {
            // to-do: should check accept-types
            let cb = Arc::clone(&self.callback);
            Ok(Box::new(CPMSessionCPIMMessageWriter {
                message_id: message_id.to_vec(),
                message_buf: Vec::with_capacity(1024),
                message_callback: cb,
            }))
        } else if is_media_type(content_type, IS_COMPOSING) {
            // as it is, from the other end of the session (RFC 3994)
            Ok(Box::new(IsComposingWriter {
                content_type: content_type.to_vec(),
                data: Vec::new(),
                callback: Arc::clone(&self.callback),
            }))
        } else {
            Err((415, "Unsupported Media Type"))
        }
    }
}

/// An is-composing indication sent as it is, given to the app as a message of
/// no CPIM headers
struct IsComposingWriter {
    content_type: Vec<u8>,
    data: Vec<u8>,
    callback: Arc<dyn Fn(&CPIMInfo, &[u8], &[u8]) + Send + Sync>,
}

impl MsrpDataWriter for IsComposingWriter {
    fn write(&mut self, data: &[u8]) -> Result<usize, (u16, &'static str)> {
        self.data.extend_from_slice(data);
        Ok(data.len())
    }

    fn complete(&mut self) -> Result<(), (u16, &'static str)> {
        let info = CPIMInfo {
            imdn_message_id: b"",
            from: b"",
            to: b"",
            date: b"",
            from_uri: None,
            to_uri: None,
            payload_type: None,
            disposition_notification: None,
        };
        (self.callback)(&info, &self.content_type, &self.data);
        Ok(())
    }
}

pub enum CPMGroupEvent {
    /// Invited to a group not known before
    Invited(GroupInvitation),
    /// The invitation to the group at the URI, which waited for the user's
    /// answer, cancelled by whoever sent it
    InvitationWithdrawn(String),
    /// The identifiers of a group, once known or changed, for the app to keep
    Ids(GroupIds),
    /// The session with the group at the URI started
    Joined(String),
    /// What the focus of the group at the URI tells of a participant
    Participant(String, Participant),
    /// The session with the group at the URI ended
    Left(String),
}

pub struct CPMSessionService {
    ongoing_sessions: Arc<Mutex<Vec<(ContactKnownIdentities, Arc<SipSession<CPMSession>>)>>>,
    ongoing_incoming_invitations: Arc<
        Mutex<
            Vec<
                Arc<(
                    ContactKnownIdentities,
                    mpsc::Sender<CPMSessionInvitationResponse>,
                )>,
            >,
        >,
    >,
    ongoing_outgoing_invitations:
        Arc<Mutex<Vec<Arc<(ContactKnownIdentities, mpsc::Sender<CPMMessageParam>)>>>>,

    registered_public_identity: Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>,

    message_receive_listener:
        Arc<dyn Fn(&Arc<SipSession<CPMSession>>, &[u8], &CPIMInfo, &[u8], &[u8]) + Send + Sync>,

    msrp_socket_allocator_function: Arc<
        dyn Fn(
                Option<&MsrpInfo>,
            )
                -> Result<(ClientSocket, String, u16, bool, bool, bool), (u16, &'static str)>
            + Send
            + Sync
            + 'static,
    >,

    msrp_socket_connect_function: Arc<
        dyn Fn(
                ClientSocket,
                &String,
                u16,
                bool,
            )
                -> Pin<Box<dyn Future<Output = Result<ClientStream, (u16, &'static str)>> + Send>>
            + Send
            + Sync
            + 'static,
    >,

    conversation_invite_handler_function:
        Box<dyn Fn(bool, &str, &str, &str, oneshot::Receiver<()>) -> u16 + Send + Sync + 'static>,

    group_invite_handler_function: Box<
        dyn Fn(&str, &str, &str, &str, &str, &str, oneshot::Receiver<()>) -> u16
            + Send
            + Sync
            + 'static,
    >,
    /// The group chats taken part in, told of through the group event
    /// listener
    group_chats: Arc<GroupChats>,
    /// The end-to-end encryption of the group chats created, if the client
    /// has it
    group_encryption: Arc<Mutex<Option<Arc<dyn GroupEncryption>>>>,
}

impl CPMSessionService {
    pub fn new<MRL, MAF, MCF, CF, GF, GL>(
        message_receive_listener: MRL,
        msrp_socket_allocator_function: MAF,
        msrp_socket_connect_function: MCF,
        conversation_invite_handler_function: CF,
        group_invite_handler_function: GF,
        group_invite_event_listener_function: GL,
    ) -> CPMSessionService
    where
        MRL: Fn(&Arc<SipSession<CPMSession>>, &[u8], &CPIMInfo, &[u8], &[u8])
            + Send
            + Sync
            + 'static,
        MAF: Fn(
                Option<&MsrpInfo>,
            )
                -> Result<(ClientSocket, String, u16, bool, bool, bool), (u16, &'static str)>
            + Send
            + Sync
            + 'static,
        MCF: Fn(
                ClientSocket,
                &String,
                u16,
                bool,
            )
                -> Pin<Box<dyn Future<Output = Result<ClientStream, (u16, &'static str)>> + Send>>
            + Send
            + Sync
            + 'static,
        CF: Fn(bool, &str, &str, &str, oneshot::Receiver<()>) -> u16 + Send + Sync + 'static,
        GF: Fn(&str, &str, &str, &str, &str, &str, oneshot::Receiver<()>) -> u16
            + Send
            + Sync
            + 'static,
        GL: Fn(CPMGroupEvent) + Send + Sync + 'static,
    {
        let registered_public_identity = Arc::new(Mutex::new(None));
        let group_chats = Arc::new(GroupChats::new(
            Arc::clone(&registered_public_identity),
            Arc::new(group_invite_event_listener_function),
        ));

        // what the Conversation Focus sends of the MLS group of a session
        // goes to the encryption, not to the app
        let group_encryption: Arc<Mutex<Option<Arc<dyn GroupEncryption>>>> =
            Arc::new(Mutex::new(None));
        let encryption = Arc::clone(&group_encryption);
        let message_receive_listener =
            move |session: &Arc<SipSession<CPMSession>>,
                  contact: &[u8],
                  cpim_info: &CPIMInfo,
                  content_type: &[u8],
                  content_body: &[u8]| {
                if !content_type.eq_ignore_ascii_case(CONTENT_TYPE_MLS_RCS_SERVER) {
                    message_receive_listener(
                        session,
                        contact,
                        cpim_info,
                        content_type,
                        content_body,
                    );
                    return;
                }
                let encryption = encryption.lock().unwrap().clone();
                let conversation_id = session
                    .get_inner()
                    .get_session_info()
                    .conversation_id
                    .clone();
                if let (Some(encryption), Some(conversation_id)) = (encryption, conversation_id) {
                    encryption.on_server_message(&conversation_id, content_body);
                }
            };

        CPMSessionService {
            ongoing_sessions: Arc::new(Mutex::new(Vec::new())),
            ongoing_incoming_invitations: Arc::new(Mutex::new(Vec::new())),
            ongoing_outgoing_invitations: Arc::new(Mutex::new(Vec::new())),
            registered_public_identity,
            message_receive_listener: Arc::new(message_receive_listener),
            msrp_socket_allocator_function: Arc::new(msrp_socket_allocator_function),
            msrp_socket_connect_function: Arc::new(msrp_socket_connect_function),
            conversation_invite_handler_function: Box::new(conversation_invite_handler_function),
            group_invite_handler_function: Box::new(group_invite_handler_function),
            group_chats,
            group_encryption,
        }
    }

    /// Has the group chats created from now on encrypted end to end by
    /// `encryption` when they can be
    pub fn set_group_encryption(&self, encryption: Arc<dyn GroupEncryption>) {
        *self.group_encryption.lock().unwrap() = Some(encryption);
    }

    /// Takes note of the identifiers of a group the app kept from before, for
    /// the group to be restarted with them, and known when its focus
    /// restarts it (RCC.07 section 3.2.4.10)
    pub fn remember_group_ids(&self, ids: GroupIds) {
        self.group_chats.remember(ids);
    }

    /// The Conversation-ID of the group at `conference_uri`, as its last
    /// session had it, if there was one
    pub fn group_conversation_id(&self, conference_uri: &str) -> Option<String> {
        self.group_chats
            .ids_of(conference_uri)
            .map(|(conversation_id, _)| conversation_id)
    }

    /// The core the conference events of groups are subscribed to with
    pub fn attach_core(&self, core: &Arc<SipCore>) {
        self.group_chats.attach_core(core);
    }

    /// Asks the focus of the group at `conference_uri`, in the session there
    /// is with it, to invite `participants` (RFC 5368), `callback` told how
    /// it answered; false, and nothing asked, if there is no such session
    pub fn add_participants<F>(
        &self,
        conference_uri: &str,
        participants: &[String],
        callback: F,
    ) -> bool
    where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let session_end = group_session_end(&self.ongoing_sessions.lock().unwrap(), conference_uri);
        match session_end {
            Some(session_end) => refer_participants(&session_end, participants, callback),
            None => false,
        }
    }

    pub fn set_registered_public_identity(
        &self,
        registered_public_identity: String,
        sip_instance_id: String,
        transport: Arc<SipTransport>,
    ) {
        (*self.registered_public_identity.lock().unwrap()).replace((
            transport,
            registered_public_identity,
            sip_instance_id,
        ));
    }

    pub fn accept_and_open_session(&self, recipient: &str, rt: &Arc<Runtime>) {
        self.answer_invitation(recipient, true, rt);
    }

    /// Accepts the invitation from `recipient`, a contact or a group, that
    /// waits for the user's answer, or declines it; false if there is none
    pub fn answer_invitation(&self, recipient: &str, accept: bool, rt: &Arc<Runtime>) -> bool {
        let invitation = {
            let mut guard = self.ongoing_incoming_invitations.lock().unwrap();
            guard
                .iter()
                .position(|invitation| {
                    let (known_identities, _) = invitation.as_ref();
                    known_identities == recipient
                })
                .map(|idx| guard.swap_remove(idx))
        };
        match invitation {
            Some(invitation) => {
                let (_, tx) = invitation.as_ref();
                let tx = tx.clone();
                let response = if accept {
                    CPMSessionInvitationResponse::Accept
                } else {
                    CPMSessionInvitationResponse::Decline
                };
                rt.spawn(async move {
                    let _ = tx.send(response).await;
                });
                true
            }
            None => false,
        }
    }

    /// Whether there is a session with `recipient`, or one being set up
    /// Tells `recipient`, in the chat session there is with it, that the user
    /// is composing a message, or no longer is (RFC 3994). As an indication
    /// starts no session, false, and nothing sent, if there is none. It goes
    /// as it is in a one-to-one chat, and in a CPIM message in a group's, for
    /// the sender to be known.
    pub fn send_is_composing<F>(
        &self,
        recipient: &str,
        recipient_type: &RecipientType,
        active: bool,
        result_callback: F,
        rt: &Arc<Runtime>,
    ) -> bool
    where
        F: Fn(u16, String) + Send + Sync + 'static,
    {
        let cpm_session = {
            let sessions = self.ongoing_sessions.lock().unwrap();
            match sessions
                .iter()
                .find(|(known_identities, _)| known_identities == recipient)
            {
                Some((_, sip_session)) => sip_session.get_inner(),
                None => return false,
            }
        };

        let message = CPMMessageParam::new(
            String::from(IS_COMPOSING),
            is_composing_document(active),
            new_message_id(),
            recipient,
            recipient_type,
            recipient,
            result_callback,
        );
        let message = match recipient_type {
            RecipientType::Group => message,
            _ => message.raw(),
        };

        cpm_session.send_message(message, rt);
        true
    }

    /// Sends the IMDN document `imdn_xml` in the session with the group at
    /// `conference_uri`, for its focus to send on to the participant
    /// `recipient_uri`; false, and nothing sent, if there is no such session
    pub fn send_group_imdn<F>(
        &self,
        conference_uri: &str,
        imdn_xml: &str,
        recipient_uri: &str,
        callback: F,
        rt: &Arc<Runtime>,
    ) -> bool
    where
        F: Fn(u16, String) + Send + Sync + 'static,
    {
        let public_user_identity = match &*self.registered_public_identity.lock().unwrap() {
            Some((_, public_user_identity, _)) => public_user_identity.clone(),
            None => return false,
        };
        let session = group_session(&self.ongoing_sessions.lock().unwrap(), conference_uri)
            .map(|sip_session| sip_session.get_inner());
        match session {
            Some(session) => {
                send_group_imdn(
                    &session,
                    imdn_xml,
                    recipient_uri,
                    &public_user_identity,
                    callback,
                    rt,
                );
                true
            }
            None => false,
        }
    }

    /// Ends the chat session with `recipient`, with a BYE; whether there was
    /// one. A message sent to `recipient` from now on starts another.
    pub fn end_session(&self, recipient: &str) -> bool {
        let session_end = {
            let sessions = self.ongoing_sessions.lock().unwrap();
            sessions
                .iter()
                .find(|(known_identities, _)| known_identities == recipient)
                .and_then(|(_, sip_session)| {
                    sip_session.get_inner().session_end.lock().unwrap().clone()
                })
        };
        match session_end {
            Some(session_end) => {
                session_end.end(true);
                true
            }
            None => false,
        }
    }

    /// Leaves the group chat at `conference_uri` for good, where ending its
    /// session leaves it only until the next: in its session, which is
    /// started first if there is none. `callback` is told how the focus
    /// answered, or why the group could not be left.
    pub fn leave_group_chat<F>(
        &self,
        conference_uri: &str,
        callback: F,
        core: &Arc<SipCore>,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let sessions = self.ongoing_sessions.lock().unwrap();
        if let Some(session_end) = group_session_end(&sessions, conference_uri) {
            drop(sessions);
            session_end.leave(callback);
            return;
        }

        let invitations = self.ongoing_outgoing_invitations.lock().unwrap();
        if invitations.iter().any(|invitation| {
            let (known_identities, _) = invitation.as_ref();
            known_identities == conference_uri
        }) {
            // a session with the group on its way, for a request made once
            // it starts to leave in
            drop(invitations);
            drop(sessions);
            callback(491, String::from("Request Pending"));
            return;
        }

        // a restart of the group by its focus meanwhile declined
        self.group_chats.set_leaving(conference_uri, true);
        let group_chats = Arc::clone(&self.group_chats);
        let ongoing_sessions = Arc::clone(&self.ongoing_sessions);
        let group = String::from(conference_uri);
        self.invite(
            sessions,
            invitations,
            Invitee {
                uri: conference_uri,
                to_uri: conference_uri,
                recipient_type: &RecipientType::Group,
                known_as: Some(conference_uri),
                new_group: None,
            },
            None,
            Some(Box::new(move |status_code, reason_phrase, _| {
                group_chats.set_leaving(&group, false);
                if status_code != 200 {
                    callback(status_code, reason_phrase);
                    return;
                }
                let session_end = group_session_end(&ongoing_sessions.lock().unwrap(), &group);
                match session_end {
                    Some(session_end) => session_end.leave(callback),
                    None => callback(481, String::from("Call/Transaction Does Not Exist")),
                }
            })),
            core,
            rt,
        );
    }

    pub fn has_session_with(&self, recipient: &str) -> bool {
        for (known_identities, _) in &*self.ongoing_sessions.lock().unwrap() {
            if known_identities == recipient {
                return true;
            }
        }
        for invitation in &*self.ongoing_outgoing_invitations.lock().unwrap() {
            let (known_identities, _) = invitation.as_ref();
            if known_identities == recipient {
                return true;
            }
        }
        false
    }

    pub fn send_message<F>(
        &self,
        message_type: &str,
        message_content: &str,
        message_id: &str,
        recipient: &str,
        recipient_type: &RecipientType,
        recipient_uri: &str,
        message_result_callback: F,
        core: &Arc<SipCore>,
        // ctrl_itf: SipTransactionManagerControlInterface,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let sessions = self.ongoing_sessions.lock().unwrap();

        for (known_identities, sip_session) in &*sessions {
            if known_identities == recipient {
                sip_session.mark_session_active();

                let cpm_session = sip_session.get_inner();

                let message_result_callback = Arc::new(Mutex::new(Some(message_result_callback)));
                let message_result_callback = move |status_code, reason_phrase| {
                    let mut guard = message_result_callback.lock().unwrap();
                    if let Some(message_result_callback) = guard.take() {
                        message_result_callback(status_code, reason_phrase);
                    }
                };

                let message = CPMMessageParam::new(
                    String::from(message_type),
                    String::from(message_content),
                    String::from(message_id),
                    recipient,
                    recipient_type,
                    recipient_uri,
                    message_result_callback,
                );

                cpm_session.send_message(message, rt);

                return;
            }
        }

        let invitations = self.ongoing_outgoing_invitations.lock().unwrap();

        for invitation in &*invitations {
            let (known_identities, message_tx) = invitation.as_ref();
            if known_identities == recipient {
                let message_result_callback = Arc::new(Mutex::new(Some(message_result_callback)));
                let message_result_callback = move |status_code, reason_phrase| {
                    let mut guard = message_result_callback.lock().unwrap();
                    if let Some(message_result_callback) = guard.take() {
                        message_result_callback(status_code, reason_phrase);
                    }
                };

                let message = CPMMessageParam::new(
                    String::from(message_type),
                    String::from(message_content),
                    String::from(message_id),
                    recipient,
                    recipient_type,
                    recipient_uri,
                    message_result_callback,
                );
                let message_tx = message_tx.clone();
                rt.spawn(async move {
                    match message_tx.send(message).await {
                        Ok(()) => {}
                        Err(e) => {
                            (e.0.message_result_callback)(403, String::from("Forbidden"));
                        }
                    }
                });
                return;
            }
        }

        let message_result_callback = Arc::new(Mutex::new(Some(message_result_callback)));
        let message_result_callback = move |status_code, reason_phrase| {
            let mut guard = message_result_callback.lock().unwrap();
            if let Some(message_result_callback) = guard.take() {
                message_result_callback(status_code, reason_phrase);
            }
        };

        let message = CPMMessageParam::new(
            String::from(message_type),
            String::from(message_content),
            String::from(message_id),
            recipient,
            recipient_type,
            recipient_uri,
            message_result_callback,
        );

        self.invite(
            sessions,
            invitations,
            Invitee {
                uri: recipient,
                to_uri: recipient_uri,
                recipient_type,
                known_as: Some(recipient),
                new_group: None,
            },
            Some(message),
            None,
            core,
            rt,
        );
    }

    /// Starts a new group chat with `participants`, about `subject`, through
    /// the conference factory at `factory_uri` (RFC 5366). `callback` is told
    /// the URI of the group once its session starts, a message to which goes
    /// in the session, or else why it did not start.
    ///
    /// The group is encrypted end to end if the encryption set can make its
    /// MLS group (RCC.16 section 8.1), which is let go of if the group does
    /// not start.
    pub fn create_group_chat<F>(
        self: &Arc<Self>,
        factory_uri: &str,
        participants: &[String],
        subject: Option<&str>,
        callback: F,
        core: &Arc<SipCore>,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String, Option<String>) + Send + Sync + 'static,
    {
        let encryption = self.group_encryption.lock().unwrap().clone();
        let identity = self
            .registered_public_identity
            .lock()
            .unwrap()
            .as_ref()
            .map(|(_, public_user_identity, _)| public_user_identity.clone());
        let (Some(encryption), Some(public_user_identity)) = (encryption, identity) else {
            self.invite_new_group(
                factory_uri,
                participants,
                subject,
                None,
                Box::new(callback),
                core,
                rt,
            );
            return;
        };

        let conversation_id = String::from(
            Uuid::new_v4()
                .as_hyphenated()
                .encode_lower(&mut Uuid::encode_buffer()),
        );
        let preparing = encryption.prepare(
            conversation_id.clone(),
            public_user_identity,
            String::from(factory_uri),
            participants.to_vec(),
        );
        let service = Arc::clone(self);
        let factory_uri = String::from(factory_uri);
        let participants = participants.to_vec();
        let subject = subject.map(String::from);
        let core = Arc::clone(core);
        let rt_ = Arc::clone(rt);
        rt.spawn(async move {
            let bundle = preparing.await;
            let started: Started = match &bundle {
                Some(_) => {
                    let conversation_id = conversation_id.clone();
                    Box::new(move |status_code, reason_phrase, conference_uri| {
                        if status_code != 200 {
                            encryption.abandon(&conversation_id);
                        }
                        callback(status_code, reason_phrase, conference_uri);
                    })
                }
                None => Box::new(callback),
            };
            let encrypted = bundle
                .as_ref()
                .map(|bundle| (&conversation_id[..], &bundle[..]));
            service.invite_new_group(
                &factory_uri,
                &participants,
                subject.as_deref(),
                encrypted,
                started,
                &core,
                &rt_,
            );
        });
    }

    fn invite_new_group(
        &self,
        factory_uri: &str,
        participants: &[String],
        subject: Option<&str>,
        encrypted: Option<(&str, &[u8])>,
        started: Started,
        core: &Arc<SipCore>,
        rt: &Arc<Runtime>,
    ) {
        let sessions = self.ongoing_sessions.lock().unwrap();
        let invitations = self.ongoing_outgoing_invitations.lock().unwrap();

        self.invite(
            sessions,
            invitations,
            Invitee {
                uri: factory_uri,
                to_uri: factory_uri,
                recipient_type: &RecipientType::Group,
                // the group is known by its own URI once it starts, not by
                // the factory's
                known_as: None,
                new_group: Some(NewGroup {
                    participants,
                    subject,
                    encrypted,
                }),
            },
            None,
            Some(started),
            core,
            rt,
        );
    }

    /// Starts a session with `invitee`, `message` sent in it once it starts,
    /// as the messages sent to the invitation meanwhile are, and `started`
    /// told how it went. The invitation is made known through `invitations`;
    /// the guards are let go of before anyone is called back.
    fn invite(
        &self,
        sessions: MutexGuard<'_, Vec<(ContactKnownIdentities, Arc<SipSession<CPMSession>>)>>,
        mut invitations: MutexGuard<'_, Vec<OutgoingInvitation>>,
        invitee: Invitee<'_>,
        message: Option<CPMMessageParam>,
        started: Option<Started>,
        core: &Arc<SipCore>,
        rt: &Arc<Runtime>,
    ) {
        let recipient = invitee.uri;
        let recipient_uri = invitee.to_uri;
        let recipient_type = invitee.recipient_type;
        let encrypted = invitee
            .new_group
            .as_ref()
            .is_some_and(|new_group| new_group.encrypted.is_some());

        if let Ok((sock, host, port, tls, active_setup, ipv6)) =
            (self.msrp_socket_allocator_function)(None)
        {
            let path_random = create_raw_alpha_numeric_string(16);
            let path_random = std::str::from_utf8(&path_random).unwrap();
            let path = if tls {
                format!("msrps://{}:{}/{};tcp", &host, port, path_random)
            } else {
                format!("msrp://{}:{}/{};tcp", &host, port, path_random)
            };

            // to-do: accepted types for Group message and others

            let path = path.into_bytes();

            let msrp_info: MsrpInfo = MsrpInfo {
                protocol: if tls { b"TCP/TLS/MSRP" } else { b"TCP/MSRP" },
                address: host.as_bytes(),
                interface_type: if ipv6 {
                    MsrpInterfaceType::IPv6
                } else {
                    MsrpInterfaceType::IPv4
                },
                port,
                path: &path,
                inactive: false,
                direction: MsrpDirection::SendReceive,
                accept_types: if let RecipientType::Chatbot = recipient_type {
                    b"message/cpim"
                } else {
                    b"message/cpim application/im-iscomposing+xml"
                },
                setup_method: if active_setup {
                    MsrpSetupMethod::Active
                } else {
                    MsrpSetupMethod::Passive
                },
                accept_wrapped_types: if let RecipientType::Chatbot = recipient_type {
                    Some(b"multipart/mixed text/plain application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml message/imdn+xml application/vnd.gsma.botmessage.v1.0+json application/vnd.gsma.botsuggestion.v1.0+json application/commontemplate+xml")
                } else if encrypted {
                    // and what the Conversation Focus sends of the MLS group
                    // (RCC.16 sections 7.5.6, 7.9)
                    Some(b"multipart/mixed text/plain application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml message/imdn+xml message/mls message/mls-rcs-server")
                } else {
                    Some(b"multipart/mixed text/plain application/vnd.gsma.rcs-ft-http+xml application/vnd.gsma.rcspushlocation+xml message/imdn+xml")
                },
                cema: false,
                file_info: None,
            };

            let sdp = String::from(msrp_info);
            let sdp = sdp.into_bytes();
            let sdp = Body::Raw(sdp);
            let sdp = Arc::new(sdp);

            let guard = self.registered_public_identity.lock().unwrap();

            if let Some((transport, contact_identity, instance_id)) = &*guard {
                let mut invite_message = SipMessage::new_request(INVITE, recipient.as_bytes());

                let call_id = String::from(
                    Uuid::new_v4()
                        .as_hyphenated()
                        .encode_lower(&mut Uuid::encode_buffer()),
                );
                invite_message.add_header(Header::new(b"Call-ID", call_id));

                invite_message.add_header(Header::new(b"CSeq", b"1 INVITE"));

                let tag = create_raw_alpha_numeric_string(8);
                let tag = String::from_utf8_lossy(&tag);

                invite_message.add_header(Header::new(
                    b"From",
                    format!("<{}>;tag={}", contact_identity, tag),
                ));

                invite_message.add_header(Header::new(b"To", format!("<{}>", recipient_uri)));

                invite_message.add_header(Header::new(
                    b"Contact",
                    if let RecipientType::Chatbot = recipient_type {
                        format!("<{}>;+sip.instance=\"{}\";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot\";+g.gsma.rcs.botversion=\"#=1,#=2\"", contact_identity, instance_id)
                    } else {
                        format!("<{}>;+sip.instance=\"{}\";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"", contact_identity, instance_id)
                    },
                ));

                // the service of the session, which the Contact also gives
                invite_message.add_header(Header::new(
                    b"Accept-Contact",
                    "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
                ));

                if let RecipientType::Chatbot = recipient_type {
                    invite_message.add_header(Header::new(b"Accept-Contact", "*;+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot\";+g.gsma.rcs.botversion=\"#=1,#=2\";require;explicit"));
                }

                // a group restarted with those it was started or joined with
                // (RCC.07 section 3.2.4.10)
                let stored_ids = match (recipient_type, &invitee.new_group) {
                    (RecipientType::Group, None) => self.group_chats.ids_of(recipient),
                    _ => None,
                };
                let (conversation_id, contribution_id) = stored_ids.unwrap_or_else(|| {
                    let new_id = || {
                        String::from(
                            Uuid::new_v4()
                                .as_hyphenated()
                                .encode_lower(&mut Uuid::encode_buffer()),
                        )
                    };
                    // the MLS group of an encrypted one is made under it
                    let conversation_id = invitee
                        .new_group
                        .as_ref()
                        .and_then(|new_group| new_group.encrypted)
                        .map_or_else(new_id, |(conversation_id, _)| String::from(conversation_id));
                    (conversation_id, new_id())
                });
                invite_message.add_header(Header::new(b"Conversation-ID", conversation_id.clone()));
                invite_message.add_header(Header::new(b"Contribution-ID", contribution_id.clone()));

                invite_message.add_header(Header::new(
                    b"Allow",
                    b"NOTIFY, OPTIONS, INVITE, UPDATE, CANCEL, BYE, ACK, MESSAGE",
                ));

                invite_message.add_header(Header::new(b"Supported", b"timer"));

                /*
                 * to-do: 3gpp TS 24.229 5.1.3.1
                 *
                 * If the UE supports the Session Timer extension, the UE shall include the option-tag "timer" in the Supported header field and should either insert a Session-Expires header field with the header field value set to the configured session timer interval value, or should not include the Session-Expires header field in the initial INVITE request. The header field value of the Session-Expires header field may be configured using local configuration or using the Session_Timer_Initial_Interval node specified in 3GPP 24.167 [8G]. If the UE is configured with both the local configuration and the Session_Timer_Initial_Interval node specified in 3GPP 24.167 [8G], then the local configuration shall take precedence.
                 * If the UE inserts the Session-Expires header field in the initial INVITE request, the UE may also include the "refresher" parameter with the "refresher" parameter value set to "uac".
                 */
                invite_message.add_header(Header::new(b"Session-Expires", b"1800"));

                invite_message.add_header(Header::new(
                    b"P-Preferred-Service",
                    b"urn:urn-7:3gpp-service.ims.icsi.oma.cpm.session",
                ));

                invite_message.add_header(Header::new(
                    b"P-Preferred-Identity",
                    String::from(contact_identity),
                ));

                let l_sdp_body = Arc::clone(&sdp);

                match invitee.new_group {
                    // the participants for the focus to invite (RFC 5366)
                    Some(NewGroup {
                        participants,
                        subject,
                        encrypted,
                    }) => {
                        invite_message
                            .add_header(Header::new(b"Require", b"recipient-list-invite"));

                        if let Some(subject) = subject {
                            let subject: String =
                                subject.chars().filter(|c| !c.is_control()).collect();
                            invite_message.add_header(Header::new(b"Subject", subject));
                        }

                        let (boundary, body) = group_invitation_body(
                            &sdp,
                            participants,
                            encrypted.map(|(_, bundle)| bundle),
                        );
                        invite_message.add_header(Header::new(
                            b"Content-Type",
                            format!("multipart/mixed; boundary={}", boundary),
                        ));
                        invite_message.add_header(Header::new(
                            b"Content-Length",
                            format!("{}", body.estimated_size()),
                        ));
                        invite_message.set_body(Arc::new(body));
                    }

                    None => {
                        invite_message.add_header(Header::new(b"Content-Type", "application/sdp"));
                        invite_message.add_header(Header::new(
                            b"Content-Length",
                            format!("{}", sdp.estimated_size()),
                        ));
                        invite_message.set_body(sdp);
                    }
                }

                let req_headers = invite_message.copy_headers();

                let public_user_identity = String::from(contact_identity);

                // let (client_transaction_tx, client_transaction_rx) = mpsc::channel::<mpsc::Sender<CPMMessageParam>>(1);
                let (client_transaction_tx, mut client_transaction_rx) = mpsc::channel::<
                    Result<(SipMessage, CPMSessionInfo, Arc<Body>), (u16, String)>,
                >(1);
                let (message_tx, mut message_rx) = mpsc::channel::<CPMMessageParam>(8);
                let message_receive_listener = Arc::clone(&self.message_receive_listener);
                let message_receive_listener_ = Arc::clone(&message_receive_listener);

                let connect_function = Arc::clone(&self.msrp_socket_connect_function);

                let ongoing_dialogs = core.get_ongoing_dialogs();

                let mut known_identities = ContactKnownIdentities::new();
                if let Some(known_as) = invitee.known_as {
                    known_identities.add_identity(String::from(known_as));
                }
                let outgoing_invitation = Arc::new((known_identities, message_tx));
                let known_as = invitee.known_as.map(String::from);
                let outgoing_invitation_ = Arc::clone(&outgoing_invitation);

                let ongoing_outgoing_invitations = Arc::clone(&self.ongoing_outgoing_invitations);
                let ongoing_sessions = Arc::clone(&self.ongoing_sessions);
                let group_chats = Arc::clone(&self.group_chats);

                let registered_public_identity = Arc::clone(&self.registered_public_identity);

                let tm = core.get_transaction_manager();
                let tm_ = Arc::clone(&tm);

                let rt_ = Arc::clone(rt);

                rt.spawn(async move {
                    // if let Some(message_tx) = client_transaction_rx.recv().await {
                    //     match message_tx.send(message).await {
                    //         Ok(()) => {},
                    //         Err(e) => {
                    //             (e.0.message_result_callback)(403);
                    //         },
                    //     }

                    //     while let Some(message) = message_rx.recv().await {
                    //         match message_tx.send(message).await {
                    //             Ok(()) => {},
                    //             Err(e) => {
                    //                 (e.0.message_result_callback)(403);
                    //             },
                    //         }
                    //     }
                    // }

                    if let Some(res) = client_transaction_rx.recv().await {
                        match res {
                            Ok((resp_message, mut session_info, r_sdp_body)) => {
                                // those sent, unless the answer tells others
                                session_info.conversation_id.get_or_insert(conversation_id);
                                session_info.contribution_id.get_or_insert(contribution_id);

                                if let Some(l_sdp) = match l_sdp_body.as_ref() {
                                    Body::Raw(raw) => {
                                        raw.as_sdp()
                                    }
                                    _ => None,
                                } {
                                    if let Some(r_sdp) = match r_sdp_body.as_ref() {
                                        Body::Raw(raw) => {
                                            raw.as_sdp()
                                        }
                                        _ => None,
                                    } {
                                        if let Some(r_msrp_info) = r_sdp.as_msrp_info() {
                                            // where the first URI of a=path points
                                            // (RFC 4975 section 8.1)
                                            let connection_address = r_msrp_info.connection_address(false);
                                            if let Some(Ok(raddr)) = connection_address.map(|(a, _)| std::str::from_utf8(a)) {
                                                let raddr = String::from(raddr);
                                                let rport = connection_address.map_or(r_msrp_info.port, |(_, p)| p);
                                                let rpath = r_msrp_info.path.to_vec();

                                                let asserted_contact_uri = session_info.contact_uri();
                                                let service_uri = String::from_utf8_lossy(&session_info.cpm_contact.service_uri).into_owned();
                                                let asserted_contact_uri_ = asserted_contact_uri.clone();
                                                // known also by the address the
                                                // messages were sent to
                                                let mut known_identities = session_info.get_contact_known_identities();
                                                if let Some(known_as) = &known_as {
                                                    known_identities.add_identity(known_as.clone());
                                                }
                                                let cpm_session = CPMSession::new(session_info);

                                                if let Ok(_) = cpm_session.set_local_sdp(l_sdp_body, sock, tls, host, port, path) {
                                                    if let Ok(_) = cpm_session.set_remote_sdp(r_sdp_body, raddr, rport, rpath) {
                                                        let cpm_session = Arc::new(cpm_session);

                                                        let (d_tx, mut d_rx) = mpsc::channel(1);

                                                        let ongoing_dialogs_ = Arc::clone(&ongoing_dialogs);

                                                        rt_.spawn(async move {
                                                            if let Some(dialog) = d_rx.recv().await {
                                                                ongoing_dialogs_.remove_dialog(&dialog);
                                                            }
                                                        });

                                                        if let Ok(dialog) = SipDialog::try_new_as_uac(&req_headers, &resp_message, move |d| {
                                                            match d_tx.try_send(d) {
                                                                Ok(()) => {},
                                                                Err(e) => {},
                                                            }
                                                        }) {
                                                            let dialog = Arc::new(dialog);

                                                            ongoing_dialogs.add_dialog(&dialog);

                                                            let (sess_tx, mut sess_rx) = mpsc::channel::<SipSessionEvent>(8);

                                                            let sip_session = SipSession::new(&cpm_session, SipSessionEventReceiver {
                                                                tx: sess_tx,
                                                                rt: Arc::clone(&rt_),
                                                            });

                                                            let sip_session = Arc::new(sip_session);
                                                            let sip_session_ = Arc::clone(&sip_session);

                                                            let public_user_identity_ = public_user_identity.clone();

                                                            let session_end = SessionEnd {
                                                                sip_session: Arc::clone(&sip_session),
                                                                ongoing_sessions: Arc::clone(&ongoing_sessions),
                                                                dialog: Arc::clone(&dialog),
                                                                tm: Arc::clone(&tm_),
                                                                registered_public_identity: Arc::clone(&registered_public_identity),
                                                                rt: Arc::clone(&rt_),
                                                            };
                                                            cpm_session.keep_session_end(session_end.clone());

                                                            sip_session.setup_confirmed_dialog(&dialog, CPMSessionDialogEventReceiver {
                                                                public_user_identity: public_user_identity_,
                                                                sip_session: Arc::clone(&sip_session),
                                                                session_end: session_end.clone(),
                                                                message_receive_listener: Arc::new(move |cpim_info, content_type, content_body| {
                                                                    message_receive_listener_(&sip_session_, asserted_contact_uri_.as_bytes(), cpim_info, content_type, content_body)
                                                                }),
                                                                msrp_socket_connect_function: Arc::clone(
                                                                    &connect_function,
                                                                ),
                                                                // started once it is answered
                                                                group_chats: None,
                                                                rt: Arc::clone(&rt_),
                                                            });

                                                            if let Some((timeout, refresher)) =
                                                            choose_timeout_on_client_transaction_completion(None, &resp_message)
                                                            {
                                                                match refresher {
                                                                    Refresher::UAC => sip_session.schedule_refresh(timeout, true, &rt_),

                                                                    Refresher::UAS => sip_session.schedule_refresh(timeout, false, &rt_),
                                                                }
                                                            }

                                                            let sip_session_1 = Arc::clone(&sip_session);
                                                            let sip_session_2 = Arc::clone(&sip_session);

                                                            let registered_public_identity_ = Arc::clone(&registered_public_identity);

                                                            let tm = Arc::clone(&tm_);
                                                            let rt = Arc::clone(&rt_);

                                                            let session_end_ = session_end.clone();

                                                            rt_.spawn(async move {
                                                                // until the session ends, its timers
                                                                // with it
                                                                let ended = session_end_.sip_session.get_inner().ended();
                                                                while let Some(ev) = tokio::select! {
                                                                    ev = sess_rx.recv() => ev,
                                                                    _ = ended.notified() => None,
                                                                } {
                                                                    match ev {
                                                                        SipSessionEvent::ShouldRefresh(dialog) => {
                                                                            if let Ok(mut message) =
                                                                                dialog.make_request(b"UPDATE", None)
                                                                            {
                                                                                message.add_header(Header::new(
                                                                                    b"Supported",
                                                                                    b"timer",
                                                                                ));

                                                                                let guard =
                                                                                registered_public_identity_.lock().unwrap();

                                                                                if let Some((transport, _, _)) = &*guard {
                                                                                    tm.send_request(
                                                                                        message,
                                                                                        transport,
                                                                                        UpdateMessageCallbacks {
                                                                                            // session_expires: None,
                                                                                            dialog,
                                                                                            sip_session: Arc::clone(&sip_session_1),
                                                                                            rt: Arc::clone(&rt),
                                                                                        },
                                                                                        &rt,
                                                                                    );
                                                                                }
                                                                            }
                                                                        }

                                                                        SipSessionEvent::Expired(_) => {
                                                                            session_end_.end(true);
                                                                        }

                                                                        _ => {}
                                                                    }
                                                                }
                                                            });

                                                            if let Ok(ack_message) = dialog.make_request(b"ACK", Some(1)) {

                                                                let rt = Arc::clone(&rt_);

                                                                if let Some(transport) = {
                                                                    let i;
                                                                    {
                                                                        let guard = registered_public_identity.lock().unwrap();

                                                                        if let Some((transport, _, _)) = &*guard {
                                                                            i = Some(Arc::clone(transport))
                                                                        } else {
                                                                            i = None
                                                                        }
                                                                    }
                                                                    i
                                                                } {
                                                                    tm_.send_request(
                                                                        ack_message,
                                                                        &transport,
                                                                        ClientTransactionNilCallbacks {},
                                                                        &rt_,
                                                                    );

                                                                    if let Ok(message_tx) = cpm_session.start(&public_user_identity, move |cpim_info, content_type, mesage_buf| {
                                                                        message_receive_listener(&sip_session_2, asserted_contact_uri.as_bytes(), cpim_info, content_type, mesage_buf)
                                                                    }, &connect_function, move || {
                                                                        // the MSRP connection lost, the
                                                                        // session is ended
                                                                        session_end.end(true)
                                                                    }, &rt) {

                                                                        // the session takes the messages
                                                                        // from now on, the invitation those
                                                                        // sent to it until no one holds it
                                                                        let joined = Arc::clone(&sip_session);
                                                                        ongoing_sessions.lock().unwrap().push((known_identities, sip_session));
                                                                        group_chats.started(&joined, &rt_);
                                                                        remove_invitation(&ongoing_outgoing_invitations, &outgoing_invitation_);
                                                                        drop(outgoing_invitation_);

                                                                        if let Some(started) = started {
                                                                            started(200, String::from("Ok"), Some(service_uri));
                                                                        }

                                                                        if let Some(message) = message {
                                                                            match message_tx.send(message).await {
                                                                                Ok(()) => {},
                                                                                Err(e) => {
                                                                                    (e.0.message_result_callback)(403, String::from("Forbidden"));
                                                                                },
                                                                            }
                                                                        }

                                                                        while let Some(message) = message_rx.recv().await {
                                                                            match message_tx.send(message).await {
                                                                                Ok(()) => {},
                                                                                Err(e) => {
                                                                                    (e.0.message_result_callback)(403, String::from("Forbidden"));
                                                                                },
                                                                            }
                                                                        }

                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            Err((error_code, error_reason)) => {
                                fail_invitation(
                                    &ongoing_outgoing_invitations,
                                    outgoing_invitation_,
                                    &mut message_rx,
                                    error_code,
                                    &error_reason,
                                );
                                if let Some(message) = message {
                                    (message.message_result_callback)(error_code, error_reason.clone());
                                }
                                if let Some(started) = started {
                                    started(error_code, error_reason, None);
                                }
                                return;
                            }
                        }
                    }

                    fail_invitation(
                        &ongoing_outgoing_invitations,
                        outgoing_invitation_,
                        &mut message_rx,
                        500,
                        "Internal Error",
                    );
                    if let Some(message) = message {
                        (message.message_result_callback)(500, String::from("Internal Error"));
                    }
                    if let Some(started) = started {
                        started(500, String::from("Internal Error"), None);
                    }
                });

                tm.send_request(
                    invite_message,
                    transport,
                    CPMSessionInviteCallbacks {
                        // l_sdp,
                        recipient_type: RecipientType::from(recipient_type),
                        client_transaction_tx,
                        // message_result_callback: Box::new(message_result_callback),
                        // message_receive_listener: Arc::clone(&self.message_receive_listener),
                        rt: Arc::clone(rt),
                    },
                    rt,
                );

                // through the guard held, the lock not being reentrant
                invitations.push(outgoing_invitation);
                return;
            }
        }

        drop(invitations);
        drop(sessions);

        if let Some(message) = message {
            (message.message_result_callback)(500, String::from("Internal Error"));
        }
        if let Some(started) = started {
            started(500, String::from("Internal Error"), None);
        }
    }
}

/// The session with the group at `conference_uri` among `sessions`
fn group_session<'s>(
    sessions: &'s [(ContactKnownIdentities, Arc<SipSession<CPMSession>>)],
    conference_uri: &str,
) -> Option<&'s Arc<SipSession<CPMSession>>> {
    sessions
        .iter()
        .find(|(known_identities, sip_session)| {
            known_identities == conference_uri
                && matches!(
                    sip_session
                        .get_inner()
                        .get_session_info()
                        .cpm_contact
                        .service_type,
                    CPMServiceType::Group
                )
        })
        .map(|(_, sip_session)| sip_session)
}

/// What ending the session with the group at `conference_uri` takes, if
/// there is such a session and it has not ended
fn group_session_end(
    sessions: &[(ContactKnownIdentities, Arc<SipSession<CPMSession>>)],
    conference_uri: &str,
) -> Option<SessionEnd> {
    group_session(sessions, conference_uri)
        .and_then(|sip_session| sip_session.get_inner().session_end.lock().unwrap().clone())
}

/// Whom an outgoing session is with
struct Invitee<'a> {
    /// The Request-URI of the INVITE
    uri: &'a str,
    /// The URI of its To
    to_uri: &'a str,
    recipient_type: &'a RecipientType,
    /// What the messages sent before the session starts are sent to, if known
    known_as: Option<&'a str>,
    new_group: Option<NewGroup<'a>>,
}

/// A group to start
struct NewGroup<'a> {
    participants: &'a [String],
    subject: Option<&'a str>,
    /// Its Conversation-ID, and the CPIM message of its MLS group, if it is
    /// encrypted (RCC.16 section 8.1.2)
    encrypted: Option<(&'a str, &'a [u8])>,
}

/// Told how a session started: 200 and the URI it is known by, or why it did
/// not
type Started = Box<dyn FnOnce(u16, String, Option<String>) + Send + Sync>;

/// The body of an INVITE starting a group, with its boundary: its SDP, the
/// participants the focus is to invite (RFC 5366 section 4), and the CPIM
/// message of its MLS group if it is encrypted (RCC.16 section 8.1.2)
fn group_invitation_body(
    sdp: &Arc<Body>,
    participants: &[String],
    encrypted: Option<&[u8]>,
) -> (String, Body) {
    let boundary = create_raw_alpha_numeric_string(16);
    let boundary_ = String::from_utf8_lossy(&boundary).into_owned();

    let mut list = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<resource-lists xmlns=\"urn:ietf:params:xml:ns:resource-lists\" \
xmlns:cp=\"urn:ietf:params:xml:ns:copycontrol\"><list>",
    );
    for participant in participants {
        list += &format!(
            "<entry uri=\"{}\" cp:copyControl=\"to\"/>",
            quick_xml::escape::escape(participant)
        );
    }
    list += "</list></resource-lists>";
    let list = list.into_bytes();

    let mut parts = vec![
        Arc::new(Body::Message(MessageBody {
            headers: vec![
                Header::new(b"Content-Type", b"application/sdp"),
                Header::new(b"Content-Length", format!("{}", sdp.estimated_size())),
            ],
            body: Arc::clone(sdp),
        })),
        Arc::new(Body::Message(MessageBody {
            headers: vec![
                Header::new(b"Content-Type", b"application/resource-lists+xml"),
                Header::new(b"Content-Disposition", b"recipient-list"),
                Header::new(b"Content-Length", format!("{}", list.len())),
            ],
            body: Arc::new(Body::Raw(list)),
        })),
    ];
    if let Some(cpim) = encrypted {
        parts.push(Arc::new(Body::Message(MessageBody {
            headers: vec![
                Header::new(b"Content-Type", b"message/cpim"),
                Header::new(b"Content-Length", format!("{}", cpim.len())),
            ],
            body: Arc::new(Body::Raw(cpim.to_vec())),
        })));
    }

    (
        boundary_,
        Body::Multipart(MultipartBody { boundary, parts }),
    )
}

struct CPMSessionInviteCallbacks {
    // l_sdp: Arc<Body>,
    recipient_type: RecipientType,
    client_transaction_tx:
        mpsc::Sender<Result<(SipMessage, CPMSessionInfo, Arc<Body>), (u16, String)>>,
    // client_transaction_tx: mpsc::Sender<mpsc::Sender<CPMMessageParam>>,
    // message_result_callback: Box<dyn Fn(u16) + Send + Sync>,
    // message_receive_listener: Arc<dyn Fn(&[u8], &[u8], &[u8]) + Send + Sync>,
    rt: Arc<Runtime>,
}

impl ClientTransactionCallbacks for CPMSessionInviteCallbacks {
    fn on_provisional_response(&self, message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        if let SipMessage::Response(l, _, _) = &message {
            let mut status_code = 500;
            let mut reason_phrase = String::from("Internal Error");
            if l.status_code >= 200 && l.status_code < 300 {
                if let Some(session_info) = get_cpm_session_info_from_message(&message, true) {
                    loop {
                        let accepting_chatbot_session_is_forbidden =
                            if let RecipientType::Chatbot = self.recipient_type {
                                match session_info.cpm_contact.service_type {
                                    CPMServiceType::Chatbot => false,
                                    _ => true,
                                }
                            } else {
                                false
                            };

                        if accepting_chatbot_session_is_forbidden {
                            status_code = 606;
                            reason_phrase = String::from("Not Acceptable");
                            break;
                        }

                        if let Some(resp_body) = message.get_body() {
                            // let mut sdp: Option<Sdp> = None;

                            if let Some(headers) = message.headers() {
                                if let Some(header) = header::search(headers, b"Content-Type", true)
                                {
                                    if let Some(content_type) =
                                        header.get_value().as_header_field().as_content_type()
                                    {
                                        if content_type
                                            .major_type
                                            .eq_ignore_ascii_case(b"application")
                                            && content_type.sub_type.eq_ignore_ascii_case(b"sdp")
                                        {
                                            // match resp_body.as_ref() {
                                            //     Body::Raw(raw) => {
                                            //         sdp = raw.as_sdp();
                                            //     }
                                            //     _ => {}
                                            // }
                                            let client_transaction_tx =
                                                self.client_transaction_tx.clone();
                                            let sdp_body = Arc::clone(&resp_body);
                                            self.rt.spawn(async move {
                                                match client_transaction_tx
                                                    .send(Ok((message, session_info, sdp_body)))
                                                    .await
                                                {
                                                    Ok(()) => {}
                                                    Err(e) => {}
                                                }
                                            });

                                            return;
                                        }
                                    }
                                }
                            }

                            // let l_sdp_body = Arc::clone(&self.l_sdp);
                            // let r_sdp_body = resp_body;

                            // if let Some(sdp) = sdp {
                            //     if let Some(msrp_info) = sdp.as_msrp_info() {
                            //         if let Some(l_sdp) = match l_sdp_body.as_ref() {
                            //             Body::Raw(raw) => {
                            //                 raw.as_sdp()
                            //             }
                            //             _ => None,
                            //         } {
                            //             if let Some(l_msrp_info) = l_sdp.as_msrp_info() {
                            //                 let message_receive_listener = Arc::clone(&self.message_receive_listener);
                            //                 let cpm_session = CPMSession::new(session_info, move |content_type, mesage_buf| {
                            //                     message_receive_listener("", content_type, mesage_buf)
                            //                 });

                            //                 if let Ok(_) = cpm_session.set_local_sdp(l_sdp_body, sock, tls, laddr, lport, lpath) {
                            //                     if let Ok(_) = cpm_session.set_remote_sdp(r_sdp_body, raddr, rport, rpath) {

                            //                         if let Ok(message_tx) = cpm_session.start(connect_function, session_end_function, &self.rt) {
                            //                             let client_transaction_tx = self.client_transaction_tx.clone();

                            //                             self.rt.spawn(async move {
                            //                                 client_transaction_tx.send(message_tx).await;
                            //                             });

                            //                             return;
                            //                         }
                            //                     }
                            //                 }
                            //             }
                            //         }
                            //     }
                            // }
                        }
                        break;
                    }
                }
            } else {
                status_code = l.status_code;
                reason_phrase = String::from_utf8_lossy(&l.reason_phrase).to_string();
            }

            let client_transaction_tx = self.client_transaction_tx.clone();
            self.rt.spawn(async move {
                match client_transaction_tx
                    .send(Err((status_code, reason_phrase)))
                    .await
                {
                    Ok(()) => {}
                    Err(e) => {}
                }
            });
        }
    }

    fn on_transport_error(&self) {
        let client_transaction_tx = self.client_transaction_tx.clone();
        self.rt.spawn(async move {
            let _ = client_transaction_tx
                .send(Err((408, String::from("Request Timeout"))))
                .await;
        });
    }
}

pub(crate) struct UpdateMessageCallbacks<T> {
    // session_expires: Option<Header>,
    pub(crate) dialog: Arc<SipDialog>,
    pub(crate) sip_session: Arc<SipSession<T>>,
    pub(crate) rt: Arc<Runtime>,
}

impl<T> ClientTransactionCallbacks for UpdateMessageCallbacks<T> {
    fn on_provisional_response(&self, message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        if let SipMessage::Response(l, _, _) = &message {
            if l.status_code >= 200 && l.status_code < 300 {
                if let Some((timeout, refresher)) =
                    choose_timeout_on_client_transaction_completion(None, &message)
                {
                    match refresher {
                        Refresher::UAC => {
                            self.sip_session.schedule_refresh(timeout, true, &self.rt)
                        }

                        Refresher::UAS => {
                            self.sip_session.schedule_refresh(timeout, false, &self.rt)
                        }
                    }
                }
            } else {
                if l.status_code == 404
                    || l.status_code == 410
                    || l.status_code == 416
                    || (l.status_code >= 482 && l.status_code <= 485)
                    || l.status_code == 489
                    || l.status_code == 604
                {
                    self.dialog.on_terminating_response(&message, &self.rt);
                }
            }
        }
    }

    fn on_transport_error(&self) {}
}

pub(crate) struct CPMSessionDialogEventReceiver {
    pub(crate) sip_session: Arc<SipSession<CPMSession>>,
    pub(crate) session_end: SessionEnd,
    pub(crate) public_user_identity: String,
    pub(crate) message_receive_listener: Arc<dyn Fn(&CPIMInfo, &[u8], &[u8]) + Send + Sync>,
    pub(crate) msrp_socket_connect_function: Arc<
        dyn Fn(
                ClientSocket,
                &String,
                u16,
                bool,
            )
                -> Pin<Box<dyn Future<Output = Result<ClientStream, (u16, &'static str)>> + Send>>
            + Send
            + Sync,
    >,
    /// Told the session started, on the ACK, if one the client accepted
    pub(crate) group_chats: Option<Arc<GroupChats>>,
    pub(crate) rt: Arc<Runtime>,
}

impl SipDialogEventCallbacks for CPMSessionDialogEventReceiver {
    fn on_ack(&self, _transaction: &Arc<ServerTransaction>) {
        if let Some(group_chats) = &self.group_chats {
            group_chats.started(&self.sip_session, &self.rt);
        }

        let session_end = self.session_end.clone();
        let session = self.sip_session.get_inner();
        let message_receive_listener = Arc::clone(&self.message_receive_listener);
        match session.start(
            &self.public_user_identity,
            move |cpim_info, content_type, content_body| {
                message_receive_listener(cpim_info, content_type, content_body)
            },
            &self.msrp_socket_connect_function,
            // the MSRP connection lost, the session is ended
            move || session_end.end(true),
            &self.rt,
        ) {
            Ok(_) => {}
            Err(()) => {}
        };
    }

    fn on_new_request(
        &self,
        transaction: Arc<ServerTransaction>,
        tx: mpsc::Sender<ServerTransactionEvent>,
        // timer: &Timer,
        rt: &Arc<Runtime>,
    ) -> Option<(u16, bool)> {
        let message = transaction.message();

        if let SipMessage::Request(l, req_headers, req_body) = message {
            if l.method == UPDATE {
                if let Some(headers) = req_headers {
                    if let Some(h) = search(headers, b"Supported", true) {
                        if h.supports(b"timer") {
                            if let Ok(Some((timeout, refresher))) =
                                choose_timeout_for_server_transaction_response(
                                    &transaction,
                                    true,
                                    Refresher::UAC,
                                )
                            {
                                // to-do: not always UAC ?
                                if let Some(mut resp_message) = server_transaction::make_response(
                                    message,
                                    transaction.to_tag(),
                                    200,
                                    b"Ok",
                                ) {
                                    match refresher {
                                        Refresher::UAC => {
                                            resp_message.add_header(Header::new(
                                                b"Session-Expires",
                                                format!("{};refresher=uac", timeout),
                                            ));

                                            self.sip_session.schedule_refresh(timeout, false, rt);
                                        }
                                        Refresher::UAS => {
                                            resp_message.add_header(Header::new(
                                                b"Session-Expires",
                                                format!("{};refresher=uas", timeout),
                                            ));

                                            self.sip_session.schedule_refresh(timeout, true, rt);
                                        }
                                    }

                                    server_transaction::send_response(
                                        transaction,
                                        resp_message,
                                        tx,
                                        rt,
                                    );
                                }

                                return Some((200, false));
                            }
                        }
                    }

                    if let Some(resp_message) =
                        server_transaction::make_response(message, transaction.to_tag(), 200, b"Ok")
                    {
                        server_transaction::send_response(transaction, resp_message, tx, rt);
                    }
                }

                return Some((200, false));
            }
        }

        None
    }

    fn on_terminating_request(&self, _message: &SipMessage) {
        // a BYE, answered by the dialog
        self.session_end.end(false);
    }

    fn on_terminating_response(&self, message: &SipMessage) {}
}

pub struct CPMSessionServiceWrapper {
    pub service: Arc<CPMSessionService>,
    pub tm: Arc<SipTransactionManager>,
}

impl TransactionHandler for CPMSessionServiceWrapper {
    fn handle_transaction(
        &self,
        transaction: &Arc<ServerTransaction>,
        ongoing_dialogs: &Arc<Mutex<Vec<Arc<SipDialog>>>>,
        channels: &mut Option<(
            mpsc::Sender<ServerTransactionEvent>,
            mpsc::Receiver<ServerTransactionEvent>,
        )>,
        rt: &Arc<Runtime>,
    ) -> bool {
        let message = transaction.message();
        if let SipMessage::Request(req_line, Some(req_headers), Some(req_body)) = message {
            if req_line.method == INVITE {
                let mut is_cpm_session_invitation = false;

                for header in req_headers {
                    if header.get_name().eq_ignore_ascii_case(b"Accept-Contact") {
                        if header.get_value().as_header_field().contains_icsi_ref(
                            b"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session",
                        ) {
                            is_cpm_session_invitation = true;
                            break;
                        }
                    }
                }

                if is_cpm_session_invitation {
                    let mut sdp = None;

                    for header in req_headers {
                        if header.get_name().eq_ignore_ascii_case(b"Content-Type") {
                            if let Some(content_type) =
                                header.get_value().as_header_field().as_content_type()
                            {
                                if content_type.major_type.eq_ignore_ascii_case(b"application")
                                    && content_type.sub_type.eq_ignore_ascii_case(b"sdp")
                                {
                                    match req_body.as_ref() {
                                        Body::Raw(raw) => {
                                            sdp = raw.as_sdp();
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }

                    if let Some(sdp) = sdp {
                        if let Some(msrp_info) = sdp.as_msrp_info() {
                            if let Some(session_info) =
                                get_cpm_session_info_from_message(message, false)
                            {
                                let auto_accept_response_code: u16;
                                // told once answered or waiting for an answer
                                let mut invited: Option<GroupInvitation> = None;

                                let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

                                match session_info.cpm_contact.service_type {
                                    CPMServiceType::Group => loop {
                                        // the subject, and who invited, as
                                        // far as the invitation tells: a
                                        // focus inviting again may tell
                                        // neither
                                        if let (Some(conversation_id), Some(contribution_id)) = (
                                            &session_info.conversation_id,
                                            &session_info.contribution_id,
                                        ) {
                                            // a restart of a group being left
                                            // declined, as the user asked to
                                            // leave it (RCC.07 sections
                                            // 3.2.4.10 and 3.2.4.11)
                                            if self
                                                .service
                                                .group_chats
                                                .is_leaving(&session_info.contact_uri())
                                            {
                                                if let Some(resp_message) =
                                                    server_transaction::make_response(
                                                        message,
                                                        transaction.to_tag(),
                                                        603,
                                                        b"Decline",
                                                    )
                                                {
                                                    if let Some((tx, _)) = channels.take() {
                                                        server_transaction::send_response(
                                                            Arc::clone(transaction),
                                                            resp_message,
                                                            tx,
                                                            rt,
                                                        );
                                                    }
                                                }
                                                return true;
                                            }

                                            // a group taken part in, which its
                                            // focus restarts, is taken part in
                                            // again at once (RCC.07 section
                                            // 3.2.4.10)
                                            if let MsrpDirection::SendReceive = msrp_info.direction
                                            {
                                                if self.service.group_chats.knows(conversation_id) {
                                                    auto_accept_response_code = 200;
                                                    break;
                                                }
                                            }

                                            let subject = session_info
                                                .subject
                                                .as_deref()
                                                .and_then(|subject| {
                                                    urlencoding::decode(subject).ok()
                                                })
                                                .map(|subject| subject.into_owned())
                                                .unwrap_or_default();
                                            let referred_by = session_info.referred_by.as_deref();
                                            let referred_by = referred_by.and_then(|referred_by| {
                                                referred_by
                                                    .as_bytes()
                                                    .as_name_addresses()
                                                    .first()
                                                    .map(|name_addr| {
                                                        (
                                                            name_addr
                                                                .display_name
                                                                .map(|n| {
                                                                    String::from_utf8_lossy(n)
                                                                        .into_owned()
                                                                })
                                                                .unwrap_or_default(),
                                                            name_addr
                                                                .uri_part
                                                                .as_ref()
                                                                .map(|u| {
                                                                    String::from_utf8_lossy(u.uri)
                                                                        .into_owned()
                                                                })
                                                                .unwrap_or_default(),
                                                        )
                                                    })
                                            });
                                            let (referred_by_name, referred_by_uri) =
                                                referred_by.unwrap_or_default();

                                            match msrp_info.direction {
                                                MsrpDirection::SendReceive => {
                                                    auto_accept_response_code = (self
                                                        .service
                                                        .group_invite_handler_function)(
                                                        &session_info.asserted_contact_uri,
                                                        conversation_id,
                                                        contribution_id,
                                                        &subject,
                                                        &referred_by_name,
                                                        &referred_by_uri,
                                                        cancel_rx,
                                                    );
                                                    let told = |s: String| {
                                                        Some(s).filter(|s| !s.is_empty())
                                                    };
                                                    invited = Some(GroupInvitation {
                                                        conference_uri: session_info.contact_uri(),
                                                        conversation_id: conversation_id.clone(),
                                                        subject: told(subject),
                                                        inviter_uri: told(referred_by_uri),
                                                        inviter_name: told(referred_by_name),
                                                        pending: (100..200)
                                                            .contains(&auto_accept_response_code),
                                                    });
                                                    break;
                                                }

                                                _ => return false,
                                            }
                                        }

                                        return false;
                                    },

                                    _ => {
                                        let mut is_chatbot_session = false;

                                        for header in req_headers {
                                            if header
                                                .get_name()
                                                .eq_ignore_ascii_case(b"Accept-Contact")
                                            {
                                                if header.get_value().as_header_field().contains_iari_ref(b"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot") {
                                                    is_chatbot_session = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if is_chatbot_session {
                                            match session_info.cpm_contact.service_type {
                                                CPMServiceType::Chatbot => {}
                                                _ => {
                                                    if let Some(resp_message) =
                                                        server_transaction::make_response(
                                                            message,
                                                            transaction.to_tag(),
                                                            606,
                                                            b"Not Acceptable",
                                                        )
                                                    {
                                                        if let Some((tx, _)) = channels.take() {
                                                            server_transaction::send_response(
                                                                Arc::clone(transaction),
                                                                resp_message,
                                                                tx,
                                                                // &timer,
                                                                rt,
                                                            );
                                                        }
                                                    }

                                                    return true;
                                                }
                                            }

                                            // to-do: check privacy settings and return 606 if appropriate
                                        }

                                        loop {
                                            if let (Some(conversation_id), Some(contribution_id)) = (
                                                &session_info.conversation_id,
                                                &session_info.contribution_id,
                                            ) {
                                                match msrp_info.direction {
                                                    MsrpDirection::SendOnly => {
                                                        if session_info.is_deferred_session {
                                                            auto_accept_response_code = (self.service.conversation_invite_handler_function)(true, &session_info.asserted_contact_uri, contribution_id, conversation_id, cancel_rx);
                                                            break;
                                                        }
                                                    }

                                                    MsrpDirection::SendReceive => {
                                                        auto_accept_response_code = (self
                                                            .service
                                                            .conversation_invite_handler_function)(
                                                            false,
                                                            &session_info.asserted_contact_uri,
                                                            &contribution_id,
                                                            &conversation_id,
                                                            cancel_rx,
                                                        );
                                                        break;
                                                    }

                                                    _ => {}
                                                }
                                            }

                                            return false;
                                        }
                                    }
                                }

                                if auto_accept_response_code >= 200
                                    && auto_accept_response_code < 300
                                {
                                    if let Some((tx, rx)) = channels.take() {
                                        try_accept_invitation(
                                            session_info,
                                            tx,
                                            rx,
                                            None,
                                            req_body,
                                            msrp_info,
                                            &self.service.msrp_socket_allocator_function,
                                            &self.service.msrp_socket_connect_function,
                                            &self.service.message_receive_listener,
                                            transaction,
                                            message,
                                            &self.service.registered_public_identity,
                                            ongoing_dialogs,
                                            &self.service.ongoing_sessions,
                                            &self.service.group_chats,
                                            &self.tm,
                                            rt,
                                        );

                                        if let Some(invited) = invited {
                                            (self.service.group_chats.listener)(
                                                CPMGroupEvent::Invited(invited),
                                            );
                                        }
                                    } else {
                                        // 500
                                    }

                                    return true;
                                } else if auto_accept_response_code >= 100
                                    && auto_accept_response_code < 200
                                {
                                    if let Some((tx, mut rx)) = channels.take() {
                                        if let Some(mut resp_message) =
                                            server_transaction::make_response(
                                                message,
                                                transaction.to_tag(),
                                                180,
                                                b"Ringing",
                                            )
                                        {
                                            resp_message.add_header(Header::new(b"Allow", b"NOTIFY, OPTIONS, INVITE, UPDATE, CANCEL, BYE, ACK, MESSAGE"));

                                            {
                                                let guard = self
                                                    .service
                                                    .registered_public_identity
                                                    .lock()
                                                    .unwrap();

                                                if let Some((
                                                    transport,
                                                    contact_identity,
                                                    instance_id,
                                                )) = &*guard
                                                {
                                                    let transport_ = transaction.transport();
                                                    if Arc::ptr_eq(transport, transport_) {
                                                        resp_message.add_header(Header::new(
                                                            b"Contact",
                                                            format!(
                                                                "<{}>;+sip.instance=\"{}\"",
                                                                contact_identity, instance_id
                                                            ),
                                                        ));
                                                    } // to-do: treat as error if transport has changed somehow
                                                }
                                            }

                                            let (d_tx, mut d_rx) = mpsc::channel(1);

                                            let ongoing_dialogs_ = Arc::clone(ongoing_dialogs);

                                            rt.spawn(async move {
                                                if let Some(dialog) = d_rx.recv().await {
                                                    ongoing_dialogs_.remove_dialog(&dialog);
                                                }
                                            });

                                            if let Ok(dialog) = SipDialog::try_new_as_uas(
                                                message,
                                                &resp_message,
                                                move |d| match d_tx.try_send(d) {
                                                    Ok(()) => {}
                                                    Err(e) => {}
                                                },
                                            ) {
                                                let dialog = Arc::new(dialog);

                                                ongoing_dialogs.add_dialog(&dialog);

                                                // dialog.register_transaction(Arc::clone(transaction));

                                                let (tx_, rx_) =
                                                    mpsc::channel::<ServerTransactionEvent>(8);

                                                let known_identities =
                                                    session_info.get_contact_known_identities();

                                                let invitation = CPMSessionInvitation::new(
                                                    session_info,
                                                    Arc::clone(&req_body),
                                                    Arc::clone(&transaction),
                                                    tx.clone(),
                                                    rx_,
                                                    dialog,
                                                );

                                                let (iv_tx, mut iv_rx) =
                                                    mpsc::channel::<CPMSessionInvitationResponse>(
                                                        1,
                                                    );
                                                let iv_tx_ = iv_tx.clone();
                                                let iv = Arc::new((known_identities, iv_tx_));
                                                let iv_ = Arc::clone(&iv);

                                                let message_receive_listener = Arc::clone(
                                                    &self.service.message_receive_listener,
                                                );
                                                let msrp_socket_allocator_function = Arc::clone(
                                                    &self.service.msrp_socket_allocator_function,
                                                );
                                                let msrp_socket_connect_function = Arc::clone(
                                                    &self.service.msrp_socket_connect_function,
                                                );
                                                let registered_public_identity = Arc::clone(
                                                    &self.service.registered_public_identity,
                                                );
                                                let ongoing_dialogs = Arc::clone(ongoing_dialogs);
                                                let ongoing_sessions =
                                                    Arc::clone(&self.service.ongoing_sessions);
                                                let group_chats =
                                                    Arc::clone(&self.service.group_chats);

                                                let ongoing_incoming_invitations_ = Arc::clone(
                                                    &self.service.ongoing_incoming_invitations,
                                                );

                                                let tm_ = Arc::clone(&self.tm);
                                                let rt_ = Arc::clone(rt);

                                                rt.spawn(async move {
                                                    let response = iv_rx.recv().await;

                                                    // no longer one to answer,
                                                    // before the app is told
                                                    {
                                                        let mut guard =
                                                            ongoing_incoming_invitations_
                                                                .lock()
                                                                .unwrap();
                                                        if let Some(idx) = guard
                                                            .iter()
                                                            .position(|iv| Arc::ptr_eq(iv, &iv_))
                                                        {
                                                            guard.swap_remove(idx);
                                                        }
                                                    }

                                                    match response {
                                                        Some(
                                                            CPMSessionInvitationResponse::Accept,
                                                        ) => {
                                                            try_accept_hanging_invitation(
                                                                invitation,
                                                                &msrp_socket_allocator_function,
                                                                &msrp_socket_connect_function,
                                                                &message_receive_listener,
                                                                &registered_public_identity,
                                                                &ongoing_dialogs,
                                                                &ongoing_sessions,
                                                                &group_chats,
                                                                &tm_,
                                                                &rt_,
                                                            );
                                                        }
                                                        Some(
                                                            CPMSessionInvitationResponse::Decline,
                                                        ) => decline_hanging_invitation(
                                                            invitation,
                                                            &ongoing_dialogs,
                                                            &rt_,
                                                        ),
                                                        Some(
                                                            CPMSessionInvitationResponse::Dispose,
                                                        ) => {
                                                            let _ = cancel_tx.send(());
                                                            if let Some(conference_uri) =
                                                                end_cancelled_invitation(
                                                                    invitation,
                                                                    &ongoing_dialogs,
                                                                )
                                                            {
                                                                (group_chats.listener)(
                                                                    CPMGroupEvent::InvitationWithdrawn(
                                                                        conference_uri,
                                                                    ),
                                                                );
                                                            }
                                                        }
                                                        None => {}
                                                    }
                                                });

                                                {
                                                    self.service
                                                        .ongoing_incoming_invitations
                                                        .lock()
                                                        .unwrap()
                                                        .push(iv);
                                                }

                                                rt.spawn(async move {
                                                    while let Some(ev) = rx.recv().await {
                                                        match ev {
                                                            ServerTransactionEvent::Cancelled => {
                                                                match iv_tx.send(CPMSessionInvitationResponse::Dispose).await {
                                                                    Ok(()) => {},
                                                                    Err(e) => {},
                                                                }
                                                            }
                                                            _ => {}
                                                        }

                                                        match tx_.send(ev).await {
                                                            Ok(()) => {}
                                                            Err(e) => {}
                                                        }
                                                    }
                                                });

                                                server_transaction::send_response(
                                                    Arc::clone(transaction),
                                                    resp_message,
                                                    tx,
                                                    // &timer,
                                                    rt,
                                                );

                                                // once ringing, for the app to
                                                // answer as it is told
                                                if let Some(invited) = invited {
                                                    (self.service.group_chats.listener)(
                                                        CPMGroupEvent::Invited(invited),
                                                    );
                                                }

                                                return true;
                                            }
                                        }
                                    }

                                    return true;
                                }
                            }

                            return false;
                        }
                    }

                    if let Some(resp_message) = server_transaction::make_response(
                        message,
                        transaction.to_tag(),
                        400,
                        b"Bad Request",
                    ) {
                        if let Some((tx, _)) = channels.take() {
                            server_transaction::send_response(
                                Arc::clone(transaction),
                                resp_message,
                                tx,
                                // &timer,
                                rt,
                            );
                        }
                    }

                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use rust_rcs_core::sip::sip_parser::SipParser;
    use rust_rcs_core::sip::ClientTransactionCallbacks;
    use tokio::runtime::Runtime;

    use super::super::CPMMessageParam;
    use super::{get_cpm_session_info_from_message, CPMSession, CPMSessionInviteCallbacks};
    use crate::messaging::ffi::RecipientType;

    #[test]
    fn an_invite_that_times_out_fails_its_messages() {
        let rt = Arc::new(Runtime::new().unwrap());
        let (client_transaction_tx, mut client_transaction_rx) = tokio::sync::mpsc::channel(1);
        let callbacks = CPMSessionInviteCallbacks {
            recipient_type: RecipientType::Group,
            client_transaction_tx,
            rt: Arc::clone(&rt),
        };

        callbacks.on_transport_error();

        let result = rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), client_transaction_rx.recv()).await
        });
        match result {
            Ok(Some(Err((status_code, _)))) => assert_eq!(status_code, 408),
            _ => panic!("no failure reported"),
        }
    }

    #[test]
    fn messages_waiting_for_a_session_that_never_starts_fail() {
        let mut parser = SipParser::new();
        parser.feed(
            b"INVITE sip:+15551234@192.0.2.10:5060;transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKnever\r\n\
From: <sip:+15559876@example.com>;tag=peer1\r\n\
To: <sip:+15551234@example.com>\r\n\
Call-ID: never\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:+15559876@192.0.2.1:5060;transport=tcp>\r\n\
P-Asserted-Identity: <sip:+15559876@example.com>\r\n\
Conversation-ID: conversation-1\r\n\
Contribution-ID: contribution-1\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let invite = parser.produce().unwrap().unwrap();
        let session_info = get_cpm_session_info_from_message(&invite, false).unwrap();

        let rt = Arc::new(Runtime::new().unwrap());
        let (result_tx, result_rx) = mpsc::channel();
        let result_tx = std::sync::Mutex::new(result_tx);

        let session = CPMSession::new(session_info);
        session.send_message(
            CPMMessageParam::new(
                String::from("text/plain"),
                String::from("never sent"),
                String::from("never-sent-1"),
                "sip:+15559876@example.com",
                &RecipientType::Contact,
                "sip:+15559876@example.com",
                move |status_code, _| {
                    let _ = result_tx.lock().unwrap().send(status_code);
                },
            ),
            &rt,
        );
        assert!(result_rx.try_recv().is_err(), "it waits for the session");

        drop(session);
        assert_eq!(result_rx.recv_timeout(Duration::from_secs(1)), Ok(480));
    }
}
