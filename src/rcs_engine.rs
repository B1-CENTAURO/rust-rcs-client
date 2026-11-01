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

extern crate libc;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
use std::net::{SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::time::Duration;

use futures::StreamExt;

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
use libc::{AF_INET, AF_INET6};
use rust_rcs_core::dns::DnsConfig;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::http::HttpClient;
#[cfg(all(feature = "android", target_os = "android"))]
use rust_rcs_core::io::network::android_socket::AndroidTcpStream;
#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
use rust_rcs_core::io::network::ohos_socket::OhosTcpStream;
use rust_rcs_core::io::network::stream::ClientSocket;
use rust_rcs_core::io::network::stream::ClientStream;

use rust_rcs_core::msrp::info::MsrpInfo;
use rust_rcs_core::msrp::info::MsrpInterfaceType;
use rust_rcs_core::msrp::info::MsrpSetupMethod;
use rust_rcs_core::security::gba::GbaContext;
use rust_rcs_core::security::SecurityContext;
use rust_rcs_core::sip::SipCore;
use rust_rcs_core::sip::SipTransactionManager;

use rust_rcs_core::sip::sip_subscription::SubscriptionManager;
use rust_rcs_core::sip::sip_transport::setup_sip_transport;
use rust_rcs_core::sip::SipTransport;
use rust_rcs_core::sip::TransactionHandler;
use rust_rcs_core::sip::ACK;
use rust_rcs_core::sip::BYE;
use rust_rcs_core::sip::CANCEL;
use rust_rcs_core::sip::INVITE;
use rust_rcs_core::sip::MESSAGE;
use rust_rcs_core::sip::NOTIFY;
use rust_rcs_core::sip::OPTIONS;
use rust_rcs_core::sip::UPDATE;

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
use tokio::net::TcpSocket;
use tokio::runtime::Runtime;

use url::Url;
use uuid::Uuid;

use crate::capability::{
    Capabilities, CapabilityQuery, CapabilityService, CapabilityServiceWrapper,
};
use crate::chat_bot;
use crate::chat_bot::chatbot_config::ChatbotConfig;
use crate::chat_bot::chatbot_sip_uri::AsChatbotSipUri;
use crate::chat_bot::RetrieveChatbotInfoSuccess;
use crate::chat_bot::RetrieveSpecificChatbotsSuccess;
use crate::conference::ffi::MultiConferenceEventListener;
use crate::conference::ffi::MultiConferenceEventListenerContextWrapper;
use crate::conference::MultiConferenceServiceV1;
use crate::conference::MultiConferenceServiceV1Wrapper;
use crate::conference::MultiConferenceV1;
use crate::conference::MultiConferenceV1InviteResponseReceiver;
use crate::connection::msrp_connection_config::MsrpConnectionConfig;
use crate::connection::p_cscf_connection_config::PCscfConnectionConfig;
use crate::connection::p_cscf_connection_config::ServiceType;
use crate::connectivity::authentication_type::AuthenticationType;
use crate::connectivity::flow::FlowEvent;
use crate::connectivity::registration::deregister;
use crate::connectivity::registration::start_register;
use crate::connectivity::registration::RegistrationEvent;
use crate::connectivity::retry::backoff;
use crate::connectivity::retry::Reconnect;
use crate::connectivity::{flow::FlowManager, registration::Registration};
use crate::context::Context;
use crate::messaging::config::MessagingConfigs;
use crate::messaging::cpm::encryption::{GroupEncryption, MetadataChange, UploadedIcon};
use crate::messaging::cpm::group_chat::{GroupIds, GroupInvitation};
use crate::messaging::cpm::imdn::{
    acknowledge_delivery, acknowledge_group_delivery, app_message_id, send_imdn, ImdnService,
    ReceivedMessages, Refusal,
};
use crate::messaging::cpm::new_message_id;
use crate::messaging::cpm::session::CPMSessionServiceWrapper;
use crate::messaging::cpm::session::{CPMGroupEvent, CPMSessionService};
use crate::messaging::cpm::sip::cpm_contact::CPMServiceType;
use crate::messaging::cpm::standalone_messaging::StandaloneMessagingServiceWrapper;
use crate::messaging::cpm::standalone_messaging::{self, StandaloneMessagingService};
use crate::messaging::cpm::MessagingSessionHandle;
use crate::messaging::ffi::RecipientType;
use crate::messaging::ft_http::config::FileTransferOverHTTPConfigs;
use crate::messaging::ft_http::download_file;
use crate::messaging::ft_http::download_sealed_file;
use crate::messaging::ft_http::upload_file;
use crate::messaging::ft_http::upload_sealed_file;
use crate::messaging::ft_http::FileInfo;
use crate::messaging::ft_http::FileTransferOverHTTPService;
use crate::messaging::ft_http::{ContentServer, Credentials};

use super::provisioning::characteristic::Characteristic;
use super::provisioning::ims_application::ImsApplication;
use super::provisioning::rcs_application::RcsApplication;

const LOG_TAG: &str = "librust_rcs_client";

type GroupChatListener = Arc<dyn Fn(CPMGroupEvent) + Send + Sync>;
type GroupChatInvitationListener = Arc<dyn Fn(GroupInvitation) + Send + Sync>;
type GroupChatIdsListener = Arc<dyn Fn(GroupIds) + Send + Sync>;

pub enum RcsEngineConnectionState {
    IDLE,
    CONNECTING,
    CONNECTED(Arc<SipTransport>, String),
}

pub enum RcsEngineRegistrationState {
    NONE,
    AUTHENTICATED(String),
    MAINTAINED(String),
}

pub struct RcsEngine {
    state: Arc<Mutex<(RcsEngineConnectionState, RcsEngineRegistrationState)>>,

    connector: Arc<Connector>,

    standalone_messaging_service: Arc<StandaloneMessagingService>,

    cpm_session_service: Arc<CPMSessionService>,

    ft_http_service: Arc<FileTransferOverHTTPService>,

    chatbot_config: ChatbotConfig,

    msrp_connection_config: Arc<Mutex<MsrpConnectionConfig>>,

    messaging_config: Arc<Mutex<MessagingConfigs>>,

    ft_http_configs: FileTransferOverHTTPConfigs,

    conference_service_v1: Arc<MultiConferenceServiceV1>,

    /// Telling and asking capabilities over SIP OPTIONS
    capability_service: Arc<CapabilityService>,

    /// The messages last taken, and the notifications each asks for
    received_messages: Arc<ReceivedMessages>,

    /// Told of the group chats taken part in, if the app set one
    group_chat_listener: Arc<Mutex<Option<GroupChatListener>>>,

    /// Told of the invitations to group chats, if the app set one
    group_chat_invitation_listener: Arc<Mutex<Option<GroupChatInvitationListener>>>,

    /// Told of the identifiers of group chats to keep, if the app set one
    group_chat_ids_listener: Arc<Mutex<Option<GroupChatIdsListener>>>,

    // msrp_channels: Arc<MsrpChannelManager>,
    core: Arc<SipCore>,
}

impl RcsEngine {
    pub fn new<SCF, MCF, MCIHF>(
        subscription_id: i32,
        rt: Arc<Runtime>,
        context: Arc<Context>,
        state_callback: SCF,
        message_callback: MCF,
        multi_conference_v1_invite_handler_function: MCIHF,
    ) -> RcsEngine
    where
        SCF: Fn(RcsEngineRegistrationState) + Send + Sync + 'static,
        MCF: Fn(i32, Option<MessagingSessionHandle>, &str, &str, &str, &str, &str, Option<&str>)
            + Send
            + Sync
            + 'static,
        MCIHF: Fn(MultiConferenceV1, String, MultiConferenceV1InviteResponseReceiver)
            + Send
            + Sync
            + 'static,
    {
        let state = Arc::new(Mutex::new((
            RcsEngineConnectionState::IDLE,
            RcsEngineRegistrationState::NONE,
        )));

        let state_callback: Arc<Box<dyn Fn(RcsEngineRegistrationState) + Send + Sync + 'static>> =
            Arc::new(Box::new(state_callback));

        let sm = SubscriptionManager::new(500);
        // let (tm, tm_control_itf, tm_event_itf) = SipTransactionManager::new(rt);
        let (tm, tm_event_itf) = SipTransactionManager::new(&rt);
        let tm = Arc::new(tm);

        let received_messages = Arc::new(ReceivedMessages::new());

        let group_chat_listener: Arc<Mutex<Option<GroupChatListener>>> = Arc::new(Mutex::new(None));
        let group_chat_listener_ = Arc::clone(&group_chat_listener);
        let group_chat_invitation_listener: Arc<Mutex<Option<GroupChatInvitationListener>>> =
            Arc::new(Mutex::new(None));
        let group_chat_invitation_listener_ = Arc::clone(&group_chat_invitation_listener);
        let group_chat_ids_listener: Arc<Mutex<Option<GroupChatIdsListener>>> =
            Arc::new(Mutex::new(None));
        let group_chat_ids_listener_ = Arc::clone(&group_chat_ids_listener);

        #[cfg(not(all(feature = "android", target_os = "android")))]
        let tls_client_config = context.get_tls_client_config();

        let msrp_connection_config = MsrpConnectionConfig::new();
        let msrp_connection_config = Arc::new(Mutex::new(msrp_connection_config));
        let msrp_connection_config_ = Arc::clone(&msrp_connection_config);

        let messaging_config = Arc::new(Mutex::new(MessagingConfigs::new()));

        let messaging_config_1 = Arc::clone(&messaging_config);
        let messaging_config_2 = Arc::clone(&messaging_config);

        let msrp_socket_allocator_function_impl = move |msrp_info: Option<&MsrpInfo>| {
            if let Some((dns_config, mut tls)) = msrp_connection_config_
                .lock()
                .unwrap()
                .get_transport_config()
            {
                match msrp_info {
                    Some(msrp_info) => {
                        if tls && msrp_info.protocol.eq_ignore_ascii_case(b"TCP/MSRP") {
                            return Err((480, "Temporarily Unavailable"));
                        }

                        if msrp_info.protocol.eq_ignore_ascii_case(b"TCP/TLS/MSRP") {
                            tls = true; // it is okay to use tls transport under cellular IMHO
                        }

                        match msrp_info.setup_method {
                            MsrpSetupMethod::Passive => match msrp_info.interface_type {
                                MsrpInterfaceType::IPv4 => {
                                    #[cfg(all(feature = "android", target_os = "android"))]
                                    if let Ok(sock) = AndroidTcpStream::create() {
                                        // to-do: the socket
                                        if let Ok(_) =
                                            sock.bind(&Ipv4Addr::UNSPECIFIED.to_string(), 0)
                                        {
                                            if let Ok((ip, port)) = sock.get_local_addr() {
                                                return Ok((
                                                    ClientSocket(sock),
                                                    ip,
                                                    port,
                                                    tls,
                                                    true,
                                                    false,
                                                ));
                                            }
                                        }
                                    }

                                    #[cfg(all(
                                        feature = "ohos",
                                        all(target_os = "linux", target_env = "ohos")
                                    ))]
                                    if let Ok(sock) = OhosTcpStream::create() {
                                        if let Ok(_) = sock.bind(
                                            AF_INET,
                                            &Ipv4Addr::UNSPECIFIED.to_string(),
                                            0,
                                        ) {
                                            if let Ok((ip, port)) = sock.get_local_addr() {
                                                return Ok((
                                                    ClientSocket(sock),
                                                    ip,
                                                    port,
                                                    tls,
                                                    true,
                                                    false,
                                                ));
                                            }
                                        }
                                    }

                                    #[cfg(not(any(
                                        all(feature = "android", target_os = "android"),
                                        all(
                                            feature = "ohos",
                                            all(target_os = "linux", target_env = "ohos")
                                        )
                                    )))]
                                    if let Ok(sock) = TcpSocket::new_v4() {
                                        if let Ok(()) = sock.bind(std::net::SocketAddr::V4(
                                            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                                        )) {
                                            if let Ok(addr) = sock.local_addr() {
                                                let ip = match addr.ip() {
                                                    std::net::IpAddr::V4(v4) => format!("{}", v4),
                                                    std::net::IpAddr::V6(v6) => format!("{}", v6),
                                                };
                                                return Ok((
                                                    ClientSocket(sock),
                                                    ip,
                                                    addr.port(),
                                                    tls,
                                                    true,
                                                    false,
                                                ));
                                            }
                                        }
                                    }
                                }

                                MsrpInterfaceType::IPv6 => {
                                    #[cfg(all(feature = "android", target_os = "android"))]
                                    if let Ok(sock) = AndroidTcpStream::create() {
                                        if let Ok(_) =
                                            sock.bind(&Ipv6Addr::UNSPECIFIED.to_string(), 0)
                                        {
                                            if let Ok((ip, port)) = sock.get_local_addr() {
                                                return Ok((
                                                    ClientSocket(sock),
                                                    ip,
                                                    port,
                                                    tls,
                                                    true,
                                                    false,
                                                ));
                                            }
                                        }
                                    }

                                    #[cfg(all(
                                        feature = "ohos",
                                        all(target_os = "linux", target_env = "ohos")
                                    ))]
                                    if let Ok(sock) = OhosTcpStream::create() {
                                        if let Ok(_) = sock.bind(
                                            AF_INET6,
                                            &Ipv6Addr::UNSPECIFIED.to_string(),
                                            0,
                                        ) {
                                            if let Ok((ip, port)) = sock.get_local_addr() {
                                                return Ok((
                                                    ClientSocket(sock),
                                                    ip,
                                                    port,
                                                    tls,
                                                    true,
                                                    false,
                                                ));
                                            }
                                        }
                                    }

                                    #[cfg(not(any(
                                        all(feature = "android", target_os = "android"),
                                        all(
                                            feature = "ohos",
                                            all(target_os = "linux", target_env = "ohos")
                                        )
                                    )))]
                                    if let Ok(sock) = TcpSocket::new_v6() {
                                        if let Ok(()) = sock.bind(std::net::SocketAddr::V6(
                                            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0),
                                        )) {
                                            if let Ok(addr) = sock.local_addr() {
                                                let ip = match addr.ip() {
                                                    std::net::IpAddr::V4(v4) => format!("{}", v4),
                                                    std::net::IpAddr::V6(v6) => format!("{}", v6),
                                                };
                                                return Ok((
                                                    ClientSocket(sock),
                                                    ip,
                                                    addr.port(),
                                                    tls,
                                                    true,
                                                    false,
                                                ));
                                            }
                                        }
                                    }
                                }
                            },

                            MsrpSetupMethod::Active => {
                                // not supported yet
                            }
                        }
                    }

                    None => {
                        #[cfg(all(feature = "android", target_os = "android"))]
                        if let Ok(sock) = AndroidTcpStream::create() {
                            if let Ok(_) = sock.bind(&Ipv4Addr::UNSPECIFIED.to_string(), 0) {
                                if let Ok((ip, port)) = sock.get_local_addr() {
                                    return Ok((ClientSocket(sock), ip, port, tls, true, false));
                                }
                            }
                        }

                        #[cfg(all(
                            feature = "ohos",
                            all(target_os = "linux", target_env = "ohos")
                        ))]
                        if let Ok(sock) = OhosTcpStream::create() {
                            if let Ok(_) = sock.bind(AF_INET, &Ipv4Addr::UNSPECIFIED.to_string(), 0)
                            {
                                if let Ok((ip, port)) = sock.get_local_addr() {
                                    return Ok((ClientSocket(sock), ip, port, tls, true, false));
                                }
                            }
                        }

                        #[cfg(not(any(
                            all(feature = "android", target_os = "android"),
                            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
                        )))]
                        if let Ok(sock) = TcpSocket::new_v4() {
                            if let Ok(()) = sock.bind(std::net::SocketAddr::V4(SocketAddrV4::new(
                                Ipv4Addr::UNSPECIFIED,
                                0,
                            ))) {
                                if let Ok(addr) = sock.local_addr() {
                                    let ip = match addr.ip() {
                                        std::net::IpAddr::V4(v4) => format!("{}", v4),
                                        std::net::IpAddr::V6(v6) => format!("{}", v6),
                                    };
                                    return Ok((
                                        ClientSocket(sock),
                                        ip,
                                        addr.port(),
                                        tls,
                                        true,
                                        false,
                                    ));
                                }
                            }
                        }

                        // to-do: could use ipv6 sometimes
                    }
                }
            }

            return Err((480, "Temporarily Unavailable"));
        };

        let msrp_socket_allocator_function_impl_1 = Arc::new(msrp_socket_allocator_function_impl);
        let msrp_socket_allocator_function_impl_2 =
            Arc::clone(&msrp_socket_allocator_function_impl_1);

        let msrp_socket_connect_function_impl =
            move |sock: ClientSocket, raddr: String, rport: u16, tls: bool| {
                #[cfg(not(all(feature = "android", target_os = "android")))]
                let tls_client_config_ = Arc::clone(&tls_client_config);
                return Box::pin(async move {
                    #[cfg(all(feature = "android", target_os = "android"))]
                    if let Ok(ip) = raddr.parse() {
                        if tls {
                            match sock.configure_tls(&raddr) {
                                Ok(sock) => {
                                    if let Ok(cs) = sock.connect(ip, rport).await {
                                        return Ok(cs);
                                    }
                                }
                                Err(_) => return Err((500, "")),
                            }
                        } else {
                            if let Ok(cs) = sock.connect(ip, rport).await {
                                return Ok(cs);
                            }
                        }
                    }

                    #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
                    if let Ok(ip) = raddr.parse() {
                        if tls {
                            match sock.configure_tls(tls_client_config_, &raddr) {
                                Ok(cc) => {
                                    if let Ok(cs) = sock.connect(ip, rport, Some(cc)).await {
                                        return Ok(cs);
                                    }
                                }
                                Err(_) => return Err((500, "")),
                            }
                        } else {
                            if let Ok(cs) = sock.connect(ip, rport, None).await {
                                return Ok(cs);
                            }
                        }
                    }

                    #[cfg(not(any(
                        all(feature = "android", target_os = "android"),
                        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
                    )))]
                    if let Ok(ip) = raddr.parse() {
                        if tls {
                            match sock.configure_tls(tls_client_config_, &raddr) {
                                Ok(cc) => {
                                    if let Ok(cs) = sock.connect(ip, rport, Some(cc)).await {
                                        return Ok(cs);
                                    }
                                }
                                Err(_) => return Err((500, "")),
                            }
                        } else {
                            if let Ok(cs) = sock.connect(ip, rport, None).await {
                                return Ok(cs);
                            }
                        }
                    }

                    Err((500, "Server Internal Error"))
                });
            };

        let message_callback_impl_1 = Arc::new(message_callback);
        let message_callback_impl_2 = Arc::clone(&message_callback_impl_1);

        let msrp_socket_connect_function_impl_1 = Arc::new(msrp_socket_connect_function_impl);
        let msrp_socket_connect_function_impl_2 = Arc::clone(&msrp_socket_connect_function_impl_1);

        let (state_1, tm_1, received_messages_1, rt_1) = (
            Arc::clone(&state),
            Arc::clone(&tm),
            Arc::clone(&received_messages),
            Arc::clone(&rt),
        );
        let standalone_messaging_service = StandaloneMessagingService::new(
            move |contact_uri, cpim_info, content_type, message_body| {
                if let (Ok(contact_uri), Ok(content_type), Ok(message_body)) = (
                    std::str::from_utf8(contact_uri),
                    std::str::from_utf8(content_type),
                    std::str::from_utf8(message_body),
                ) {
                    if let (Ok(imdn_message_id), Ok(cpim_date)) = (
                        std::str::from_utf8(cpim_info.imdn_message_id),
                        std::str::from_utf8(cpim_info.date),
                    ) {
                        let cpim_from = if let Some(uri) = &cpim_info.from_uri {
                            let uri = uri.string_representation_without_query_and_fragment();
                            if let Ok(uri) = String::from_utf8(uri) {
                                Some(uri)
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        message_callback_impl_1(
                            1,
                            None,
                            contact_uri,
                            content_type,
                            message_body,
                            imdn_message_id,
                            cpim_date,
                            cpim_from.as_deref(),
                        );
                        acknowledge_delivery(
                            &received_messages_1,
                            ImdnService::Standalone,
                            contact_uri,
                            cpim_info,
                            content_type.as_bytes(),
                            || registered_identity(&state_1),
                            &tm_1,
                            &rt_1,
                        );
                    } else {
                        platform_log(LOG_TAG, "failed to decode cpim info as utf-8 string");
                    }
                } else {
                    platform_log(LOG_TAG, "failed to decode message data as utf-8 string");
                }
            },
            move |msrp_info| msrp_socket_allocator_function_impl_1(msrp_info),
            move |sock, raddr, rport, tls| {
                let raddr = String::from(raddr);
                msrp_socket_connect_function_impl_1(sock, raddr, rport, tls)
            },
        );
        let standalone_messaging_service = Arc::new(standalone_messaging_service);
        let (state_2, tm_2, received_messages_2, rt_2) = (
            Arc::clone(&state),
            Arc::clone(&tm),
            Arc::clone(&received_messages),
            Arc::clone(&rt),
        );
        let cpm_session_service = CPMSessionService::new(
            move |session, contact_uri, cpim_info, content_type, message_body| {
                if let (Ok(contact_uri), Ok(content_type), Ok(message_body)) = (
                    std::str::from_utf8(contact_uri),
                    std::str::from_utf8(content_type),
                    std::str::from_utf8(message_body),
                ) {
                    // a Re-Sent Message known by the Message-ID of its
                    // Original Message (RCC.16 section 10.4)
                    if let (Ok(imdn_message_id), Ok(cpim_date)) = (
                        std::str::from_utf8(app_message_id(cpim_info, content_type.as_bytes())),
                        std::str::from_utf8(cpim_info.date),
                    ) {
                        let cpim_from = if let Some(uri) = &cpim_info.from_uri {
                            let uri = uri.string_representation_without_query_and_fragment();
                            if let Ok(uri) = String::from_utf8(uri) {
                                Some(uri)
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        message_callback_impl_2(
                            0,
                            Some(MessagingSessionHandle {
                                // to-do: it might be deferred session
                                inner: Arc::clone(session),
                            }),
                            contact_uri,
                            content_type,
                            message_body,
                            imdn_message_id,
                            cpim_date,
                            cpim_from.as_deref(),
                        );
                        let cpm_session = session.get_inner();
                        let service_type = &cpm_session.get_session_info().cpm_contact.service_type;
                        if let Some(service) = ImdnService::of_chat(service_type) {
                            acknowledge_delivery(
                                &received_messages_2,
                                service,
                                contact_uri,
                                cpim_info,
                                content_type.as_bytes(),
                                || registered_identity(&state_2),
                                &tm_2,
                                &rt_2,
                            );
                        } else if let CPMServiceType::Group = *service_type {
                            // the contact is the group's focus
                            acknowledge_group_delivery(
                                &received_messages_2,
                                session,
                                contact_uri,
                                cpim_info,
                                content_type.as_bytes(),
                                || registered_identity(&state_2).map(|(_, impu)| impu),
                                &rt_2,
                            );
                        }
                    } else {
                        platform_log(LOG_TAG, "failed to decode cpim info as utf-8 string");
                    }
                } else {
                    platform_log(LOG_TAG, "failed to decode message data as utf-8 string");
                }
            },
            move |msrp_info| msrp_socket_allocator_function_impl_2(msrp_info),
            move |sock, raddr, rport, tls| {
                let raddr = String::from(raddr);
                msrp_socket_connect_function_impl_2(sock, raddr, rport, tls)
            },
            move |is_deferred_session, contact_uri, conversation_id, contribution_id, rx| {
                let messaging_config = &*messaging_config_1.lock().unwrap();
                if messaging_config.chat_auth == 1 {
                    if is_deferred_session {
                        return 200;
                    }
                    if messaging_config.im_session_auto_accept == 1 {
                        return 200;
                    }
                }
                180
            },
            move |contact_uri,
                  conversation_id,
                  contribution_id,
                  subject,
                  referred_by_name,
                  referred_by_uri,
                  rx| {
                let messaging_config = &*messaging_config_2.lock().unwrap();
                if messaging_config.group_chat_auth == 1 {
                    if messaging_config.im_session_auto_accept_group_chat == 1 {
                        return 200;
                    }
                }
                180
            },
            move |event| {
                // not called under the lock, for the app may set another
                match event {
                    CPMGroupEvent::Invited(invitation) => {
                        let listener = group_chat_invitation_listener_.lock().unwrap().clone();
                        if let Some(listener) = listener {
                            listener(invitation);
                        }
                    }
                    CPMGroupEvent::Ids(ids) => {
                        let listener = group_chat_ids_listener_.lock().unwrap().clone();
                        if let Some(listener) = listener {
                            listener(ids);
                        }
                    }
                    event => {
                        let listener = group_chat_listener_.lock().unwrap().clone();
                        if let Some(listener) = listener {
                            listener(event);
                        }
                    }
                }
            },
        );
        let cpm_session_service = Arc::new(cpm_session_service);
        let multi_conference_service_v1 =
            MultiConferenceServiceV1::new(multi_conference_v1_invite_handler_function);
        let multi_conference_service_v1 = Arc::new(multi_conference_service_v1);
        let sm = Arc::new(sm);
        let allowed_methods: Vec<&'static [u8]> =
            [ACK, BYE, CANCEL, INVITE, MESSAGE, NOTIFY, OPTIONS, UPDATE].to_vec();

        let capability_service = Arc::new(CapabilityService::new());

        let mut transaction_handlers: Vec<Box<dyn TransactionHandler + Send + Sync>> = Vec::new();
        transaction_handlers.push(Box::new(CapabilityServiceWrapper {
            service: Arc::clone(&capability_service),
        }));
        transaction_handlers.push(Box::new(StandaloneMessagingServiceWrapper {
            service: Arc::clone(&standalone_messaging_service),
            tm: Arc::clone(&tm),
        }));
        transaction_handlers.push(Box::new(CPMSessionServiceWrapper {
            service: Arc::clone(&cpm_session_service),
            tm: Arc::clone(&tm),
        }));
        transaction_handlers.push(Box::new(MultiConferenceServiceV1Wrapper {
            service: Arc::clone(&multi_conference_service_v1),
            tm: Arc::clone(&tm),
        }));

        let core = Arc::new(SipCore::new(
            &sm,
            &tm,
            tm_event_itf,
            allowed_methods,
            transaction_handlers,
            &rt,
        ));

        cpm_session_service.attach_core(&core, &rt);

        let connector = Arc::new_cyclic(|connector: &Weak<Connector>| {
            let connector = Weak::clone(connector);

            Connector {
                state: Arc::clone(&state),

                state_callback,

                tm: Arc::clone(&tm),

                core: Arc::clone(&core),

                context,

                flow_manager: Arc::new(FlowManager::new(
                    &sm,
                    &tm,
                    move |event, transport, registration| {
                        if let Some(connector) = connector.upgrade() {
                            connector.on_flow_event(event, &transport, &registration);
                        }
                    },
                )),

                cpm_session_service: Arc::clone(&cpm_session_service),

                standalone_messaging_service: Arc::clone(&standalone_messaging_service),

                conference_service_v1: Arc::clone(&multi_conference_service_v1),

                capability_service: Arc::clone(&capability_service),

                subscription_id,

                settings: Mutex::new(ConnectSettings {
                    impi: None,
                    impu: None,
                    home_domain: None,
                    authentication_type: None,
                    sip_instance_id: Uuid::new_v4(),
                    p_cscf_connection_config: PCscfConnectionConfig::new(),
                    registration_id_counter: 0,
                }),

                retry: Mutex::new(Retry {
                    wanted: false,
                    failures: 0,
                    generation: 0,
                }),

                rt: Arc::clone(&rt),
            }
        });

        RcsEngine {
            state,

            connector,

            standalone_messaging_service,

            cpm_session_service,

            ft_http_service: Arc::new(FileTransferOverHTTPService::new()),

            chatbot_config: ChatbotConfig::new(),

            msrp_connection_config,

            messaging_config,

            ft_http_configs: FileTransferOverHTTPConfigs::new(),

            conference_service_v1: multi_conference_service_v1,

            capability_service,

            received_messages,

            group_chat_listener,

            group_chat_invitation_listener,

            group_chat_ids_listener,

            // msrp_channels,
            core,
            // gba_context: None,
        }
    }

    pub fn configure(&mut self, ims_config: String, rcs_config: String) {
        if let (Ok(ims_app), Ok(rcs_app)) = (
            ims_config.parse::<Characteristic>(),
            rcs_config.parse::<Characteristic>(),
        ) {
            let ims_app = ImsApplication::new(&ims_app);
            let rcs_app = RcsApplication::new(&rcs_app);

            {
                let mut guard = self.connector.settings.lock().unwrap();
                let settings = &mut *guard;

                settings.impi.take();

                if let Some(pvui) = ims_app.get_private_user_identity() {
                    settings.impi.replace(String::from(pvui));
                }

                settings.impu.take();

                let mut pbui_priority = 0;

                for pbui in ims_app.get_public_user_identity_list() {
                    if pbui.starts_with("sip:") {
                        if pbui.starts_with("sip:+") {
                            if pbui_priority < 3 {
                                pbui_priority = 3;
                                settings.impu = Some(String::from(pbui));
                            }
                        } else {
                            if pbui_priority < 2 {
                                pbui_priority = 2;
                                settings.impu = Some(String::from(pbui));
                            }
                        }
                    } else if pbui.starts_with("tel:") {
                        if pbui_priority < 1 {
                            pbui_priority = 1;
                            settings.impu = Some(String::from(pbui));
                        }
                    } else {
                        if settings.impu.is_none() {
                            settings.impu.replace(String::from(pbui));
                        }
                    }
                }

                platform_log(
                    LOG_TAG,
                    format!(
                        "rcs engine configured with IMPI: {:?}, IMPU: {:?}",
                        &settings.impi, &settings.impu
                    ),
                );

                settings.home_domain = None;

                if let Some(home_domain) = ims_app.get_home_domain() {
                    settings.home_domain = Some(String::from(home_domain));
                }

                settings.authentication_type = None;

                if let Some(gsma_ext) = ims_app.get_ims_gsma_extension() {
                    let ext_info = gsma_ext.get_info();

                    if let Some(auth_type) = ext_info.auth_type {
                        if auth_type.eq_ignore_ascii_case("AKA") {
                            if let (Some(realm), Some(username)) =
                                (&settings.home_domain, &settings.impi)
                            {
                                settings.authentication_type = Some(AuthenticationType::Aka(
                                    String::from("AKAv1-MD5"),
                                    realm.clone(),
                                    username.clone(),
                                ));
                            }
                        } else if auth_type.eq_ignore_ascii_case("Digest") {
                            if let (Some(realm), Some(username), Some(password)) =
                                (ext_info.realm, ext_info.user_name, ext_info.user_password)
                            {
                                settings.authentication_type = Some(AuthenticationType::Digest(
                                    String::from("SHA-256"),
                                    String::from(realm),
                                    String::from(username),
                                    String::from(password),
                                ))
                            }
                        }
                    }

                    if let Some(uuid_value) = ext_info.uuid_value {
                        if let Ok(uuid) = Uuid::parse_str(uuid_value) {
                            settings.sip_instance_id = uuid;
                        }
                    }
                }

                settings
                    .p_cscf_connection_config
                    .update_configuration(&ims_app);
            }

            self.chatbot_config.update_configuration(&rcs_app);

            self.msrp_connection_config
                .lock()
                .unwrap()
                .update_configuration(&ims_app);

            self.messaging_config
                .lock()
                .unwrap()
                .update_configuration(&rcs_app);

            self.ft_http_configs.update_configuration(&rcs_app)
        }
    }

    /// Connects and registers, on the runtime the engine was made with, and
    /// connects again whenever the connection is lost, until disconnect()
    pub fn connect(&mut self, _rt: Arc<Runtime>) {
        platform_log(LOG_TAG, "calling engine->connect()");

        let attempt = {
            let mut retry = self.connector.retry.lock().unwrap();
            retry.wanted = true;
            retry.failures = 0;
            retry.generation += 1;
            retry.generation
        };

        self.connector.connect(attempt);
    }

    pub fn disconnect(&self, rt: Arc<Runtime>) {
        {
            let mut retry = self.connector.retry.lock().unwrap();
            retry.wanted = false;
            retry.generation += 1;
        }

        let transport = {
            let mut guard = self.state.lock().unwrap();
            let transport = match &guard.0 {
                RcsEngineConnectionState::CONNECTED(transport, _) => Some(Arc::clone(transport)),
                _ => None,
            };
            guard.0 = RcsEngineConnectionState::IDLE;
            guard.1 = RcsEngineRegistrationState::NONE;
            transport
        };

        (self.connector.state_callback)(RcsEngineRegistrationState::NONE);

        if let Some(transport) = transport {
            let registration = self.connector.flow_manager.stop_observation(&transport);
            self.connector
                .release(&transport, registration.as_ref(), &rt);
        }
    }
    /// Sends a message, with the imdn.Message-ID `message_id`, or a new one,
    /// which notifications of it give
    pub fn send_message<F>(
        &self,
        message_type: &str,
        message_content: &str,
        message_id: Option<&str>,
        recipient: &str,
        recipient_type: RecipientType,
        message_result_callback: F,
        /* engine_itf: RcsEngineInterface, */ rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let core = Arc::clone(&self.core);

        let message_id = match message_id {
            Some(message_id) => String::from(message_id),
            None => new_message_id(),
        };

        // what to send with, decided under the engine's locks, which are not
        // held while sending or calling back, so that the application may
        // call into the engine from the callback
        let (transport, public_user_identity) = match registered_identity(&self.state) {
            Some(registered) => registered,
            None => {
                message_result_callback(403, String::from("Forbidden"));
                return;
            }
        };

        let mut send_through_one_to_one_chat_service = false;
        let mut send_through_group_chat_service = false;
        let mut send_through_standalone_message_service = false;

        // bool contact_is_chatbot = (options & rcs_send_message_option_contact_is_chatbot) != 0;

        // a chat with the recipient, which an answer goes in; without one,
        // whether the recipient takes chats is not known, as capabilities
        // are not exchanged
        let has_session = self.cpm_session_service.has_session_with(recipient);

        // bool contact_supports_standalone = (options & rcs_send_message_option_contact_supports_standalone) != 0;
        let recipient_supports_standalone = true;

        // bool contact_is_group = (options & rcs_send_message_option_send_to_group) != 0;
        // let recipient_is_group = false;

        let mut recipient_uri = String::from(recipient);

        let (standalone_msg_max_size, standalone_msg_switch_over_size) = {
            let messaging_config = &*self.messaging_config.lock().unwrap();

            if let RecipientType::Chatbot = recipient_type {
                // chatbots by chat only, or by either (GSMA RCC.07 chatbot
                // messaging technology)
                if messaging_config.chatbot_msg_tech == 1 && messaging_config.chat_auth == 1 {
                    send_through_one_to_one_chat_service = true;
                } else if messaging_config.chatbot_msg_tech == 2 {
                    if messaging_config.chat_auth == 1 && has_session {
                        send_through_one_to_one_chat_service = true;
                    }

                    if messaging_config.standalone_msg_auth == 1 && recipient_supports_standalone {
                        send_through_standalone_message_service = true;
                    }
                } else if messaging_config.chatbot_msg_tech == 3
                    && messaging_config.standalone_msg_auth == 1
                    && recipient_supports_standalone
                {
                    send_through_standalone_message_service = true;
                }
            } else if let RecipientType::Group = recipient_type {
                if messaging_config.group_chat_auth == 1 {
                    send_through_group_chat_service = true;
                }
            } else if let RecipientType::ResourceList = recipient_type {
                // to-do: check max_one_to_many_recipients for limit
                // through the exploder the network gives, which has no
                // address to fall back on
                if let (1, Some(exploder_uri)) = (
                    messaging_config.standalone_msg_auth,
                    &messaging_config.exploder_uri,
                ) {
                    recipient_uri = String::from(exploder_uri);
                    send_through_standalone_message_service = true;
                }
            } else {
                // in the chat there is, or in a new one when the message
                // cannot go standalone
                if messaging_config.chat_auth == 1
                    && (has_session || messaging_config.standalone_msg_auth != 1)
                {
                    send_through_one_to_one_chat_service = true;
                }

                if messaging_config.standalone_msg_auth == 1 && recipient_supports_standalone {
                    send_through_standalone_message_service = true;
                }
            }

            (
                messaging_config.standalone_msg_max_size,
                messaging_config.standalone_msg_switch_over_size,
            )
        };

        if send_through_one_to_one_chat_service || send_through_group_chat_service {
            self.cpm_session_service.send_message(
                message_type,
                message_content,
                &message_id,
                recipient,
                &recipient_type,
                &recipient_uri,
                message_result_callback,
                &core,
                rt,
            );
        } else if send_through_standalone_message_service
            && standalone_msg_max_size >= message_content.len()
        {
            if standalone_msg_switch_over_size < message_content.len() {
                self.standalone_messaging_service.send_large_mode_message(
                    message_type,
                    message_content,
                    &message_id,
                    recipient,
                    &recipient_type,
                    &recipient_uri,
                    message_result_callback,
                    &core,
                    rt,
                );
            } else {
                standalone_messaging::send_message(
                    message_type,
                    message_content,
                    &message_id,
                    recipient,
                    &recipient_type,
                    &recipient_uri,
                    message_result_callback,
                    core,
                    &transport,
                    &public_user_identity,
                    &rt,
                );
            }
        } else {
            message_result_callback(403, String::from("Forbidden"))
        }
    }

    /// Starts a new group chat with `participants`, about `subject`, through
    /// the provisioned conference factory. `callback` is told the URI of the
    /// group once its session starts, which messages to it are sent to, as to
    /// a recipient of the group type, or else why it did not start.
    pub fn create_group_chat<F>(
        &self,
        participants: Vec<String>,
        subject: Option<&str>,
        callback: F,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String, Option<String>) + Send + Sync + 'static,
    {
        let factory_uri = {
            let messaging_config = &*self.messaging_config.lock().unwrap();
            let too_many = messaging_config.max_ad_hoc_group_size > 0
                && participants.len() + 1 > messaging_config.max_ad_hoc_group_size;
            match (
                messaging_config.group_chat_auth,
                &messaging_config.conf_fcty_uri,
            ) {
                (1, Some(factory_uri)) if !participants.is_empty() && !too_many => {
                    Some(factory_uri.clone())
                }
                _ => None,
            }
        };

        match (factory_uri, registered_identity(&self.state)) {
            (Some(factory_uri), Some(_)) => self.cpm_session_service.create_group_chat(
                &factory_uri,
                &participants,
                subject,
                callback,
                &self.core,
                rt,
            ),
            _ => callback(403, String::from("Forbidden"), None),
        }
    }

    /// Sets what is told of the group chats taken part in: joined, a
    /// participant's status, left, and of an invitation that waited for the
    /// user's answer being withdrawn
    pub fn set_group_chat_listener<L>(&self, listener: L)
    where
        L: Fn(CPMGroupEvent) + Send + Sync + 'static,
    {
        self.group_chat_listener
            .lock()
            .unwrap()
            .replace(Arc::new(listener));
    }

    /// Sets what is told of the invitations to group chats not known before,
    /// as they are being accepted or wait for the user's answer
    pub fn set_group_chat_invitation_listener<L>(&self, listener: L)
    where
        L: Fn(GroupInvitation) + Send + Sync + 'static,
    {
        self.group_chat_invitation_listener
            .lock()
            .unwrap()
            .replace(Arc::new(listener));
    }

    /// Sets what is told of the identifiers of group chats, once known or
    /// changed, for the app to keep and give back once the engine is made
    /// again
    pub fn set_group_chat_ids_listener<L>(&self, listener: L)
    where
        L: Fn(GroupIds) + Send + Sync + 'static,
    {
        self.group_chat_ids_listener
            .lock()
            .unwrap()
            .replace(Arc::new(listener));
    }

    /// Gives back the identifiers of a group chat the app kept, for it to be
    /// restarted with them (RCC.07 section 3.2.4.10)
    pub fn remember_group_chat_ids(&self, ids: GroupIds) {
        self.cpm_session_service.remember_group_ids(ids);
    }

    /// Accepts the invitation to the group chat at `conference_uri` that
    /// waits for the user's answer, or declines it: 404 if there is none
    pub fn answer_group_chat_invitation<F>(
        &self,
        conference_uri: &str,
        accept: bool,
        callback: F,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        if self
            .cpm_session_service
            .answer_invitation(conference_uri, accept, rt)
        {
            callback(200, String::from("Ok"));
        } else {
            callback(404, String::from("Not Found"));
        }
    }

    /// Asks the focus of the group at `conference_uri` to invite
    /// `participants`, in the session there is with it: 404 if there is
    /// none
    pub fn add_group_chat_participants<F>(
        &self,
        conference_uri: &str,
        participants: &[String],
        result_callback: F,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        if participants.is_empty() {
            result_callback(400, String::from("Bad Request"));
            return;
        }
        let result_callback = Arc::new(Mutex::new(Some(result_callback)));
        let result_callback_ = Arc::clone(&result_callback);
        let asked = self.cpm_session_service.add_participants(
            conference_uri,
            participants,
            move |status_code, reason_phrase| {
                let result_callback = result_callback_.lock().unwrap().take();
                if let Some(result_callback) = result_callback {
                    result_callback(status_code, reason_phrase);
                }
            },
        );
        if !asked {
            let result_callback = result_callback.lock().unwrap().take();
            if let Some(result_callback) = result_callback {
                result_callback(404, String::from("Not Found"));
            }
        }
    }

    /// Asks the focus of the group at `conference_uri` to remove
    /// `participant`, in the session there is with it: 404 if there is none
    pub fn remove_group_chat_participant<F>(
        &self,
        conference_uri: &str,
        participant: &str,
        result_callback: F,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        if participant.is_empty() {
            result_callback(400, String::from("Bad Request"));
            return;
        }
        let result_callback = Arc::new(Mutex::new(Some(result_callback)));
        let result_callback_ = Arc::clone(&result_callback);
        let asked = self.cpm_session_service.remove_participant(
            conference_uri,
            participant,
            move |status_code, reason_phrase| {
                let result_callback = result_callback_.lock().unwrap().take();
                if let Some(result_callback) = result_callback {
                    result_callback(status_code, reason_phrase);
                }
            },
        );
        if !asked {
            let result_callback = result_callback.lock().unwrap().take();
            if let Some(result_callback) = result_callback {
                result_callback(404, String::from("Not Found"));
            }
        }
    }

    /// Sets the encrypted subject of the group chat at `conference_uri`, or
    /// deletes it if None, in the session there is with it (RCC.16 sections
    /// 9.7.1.5, 9.7.1.7): 404 if there is none, 488 if the group is not
    /// encrypted end to end, or if the change cannot be made; else how its
    /// focus answered, see `CPMSessionService::change_group_metadata()`
    pub fn set_group_subject<F>(&self, conference_uri: &str, subject: Option<&str>, callback: F)
    where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        change_group_metadata(
            &self.cpm_session_service,
            conference_uri,
            MetadataChange::Subject(subject.map(String::from)),
            callback,
        );
    }

    /// Sets the encrypted icon of the group chat at `conference_uri` to the
    /// file at `icon_path`, of `content_type`, or deletes it if None, in the
    /// session there is with it (RCC.16 sections 9.7.1.4, 9.7.1.6), as
    /// set_group_subject() does
    ///
    /// The icon is encrypted with a key of its own and uploaded to the
    /// content server first, as `ft_http::upload_sealed_file()` uploads a
    /// file, then the Commit to its key sent with its URL. An upload that
    /// fails is told as upload_file() tells it; 403 if there is no content
    /// server to upload it to.
    pub fn set_group_icon<F>(
        &self,
        conference_uri: &str,
        icon: Option<(&str, &str)>,
        msisdn: Option<&str>,
        http_client: Arc<HttpClient>,
        gba_context: Arc<GbaContext>,
        security_context: Arc<SecurityContext>,
        rt: &Arc<Runtime>,
        callback: F,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let Some((icon_path, content_type)) = icon else {
            change_group_metadata(
                &self.cpm_session_service,
                conference_uri,
                MetadataChange::Icon(None),
                callback,
            );
            return;
        };
        // not uploaded unless it is to be set
        let encryption = match self
            .cpm_session_service
            .group_session_encryption(conference_uri)
        {
            None => return callback(404, String::from("Not Found")),
            Some(encrypted) => encrypted
                .filter(|(encryption, conversation_id)| encryption.encrypts_files(conversation_id)),
        };
        let Some((encryption, _)) = encryption else {
            return callback(488, String::from("Not Acceptable Here"));
        };
        let ft_http_cs_uri = match (
            self.ft_http_configs.ft_auth,
            &self.ft_http_configs.ft_http_cs_uri,
        ) {
            (1, Some(ft_http_cs_uri)) => ft_http_cs_uri.clone(),
            _ => return callback(403, String::from("Forbidden")),
        };

        let ft_http_service = Arc::clone(&self.ft_http_service);
        let cpm_session_service = Arc::clone(&self.cpm_session_service);
        let credentials = self.ft_http_cs_credentials();
        let msisdn = msisdn.map(String::from);
        let conference_uri = String::from(conference_uri);
        let icon_path = String::from(icon_path);
        let content_type = String::from(content_type);
        rt.spawn(async move {
            let server = ContentServer {
                http_client: &http_client,
                gba_context: &gba_context,
                security_context: &security_context,
                credentials: credentials
                    .as_ref()
                    .map(|(host, user, password)| Credentials {
                        host,
                        user,
                        password,
                    }),
                msisdn: msisdn.as_deref(),
            };
            let icon = FileInfo {
                path: &icon_path,
                name: "",
                mime: &content_type,
                hash: None,
            };
            let progress_callback: Arc<Box<dyn Fn(u32, i32) + Send + Sync>> =
                Arc::new(Box::new(|_, _| {}));
            let seal = |content: &[u8], _: &str, mime: &str| encryption.seal_icon(content, mime);
            let uploaded = upload_sealed_file(
                &ft_http_service,
                &ft_http_cs_uri,
                Uuid::new_v4(),
                icon,
                None,
                &server,
                &progress_callback,
                &seal,
            )
            .await;
            match uploaded {
                Ok((xml, metadata, _)) => change_group_metadata(
                    &cpm_session_service,
                    &conference_uri,
                    MetadataChange::Icon(Some(UploadedIcon {
                        xml: xml.into_bytes(),
                        metadata,
                    })),
                    callback,
                ),
                Err(e) => callback(e.error_code(), e.error_string()),
            }
        });
    }

    /// Leaves the group chat at `conference_uri` for good, its session
    /// restarted first if there is none (RCC.07 section 3.2.4.11). `callback`
    /// is told how the focus answered; a restart refused with 404 or 403
    /// means the user already takes no part in the group (section 3.2.4.10).
    pub fn leave_group_chat<F>(&self, conference_uri: &str, callback: F, rt: &Arc<Runtime>)
    where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        match registered_identity(&self.state) {
            Some(_) => {
                self.cpm_session_service
                    .leave_group_chat(conference_uri, callback, &self.core, rt)
            }
            None => callback(403, String::from("Forbidden")),
        }
    }

    /// Tells `recipient`, in the chat session there is with it, that the user
    /// is composing a message, or no longer is. No session is started for it:
    /// 404 if there is none.
    /// Asks `contact_uri` for its capabilities over SIP OPTIONS (RCC.07
    /// section 2.6.1.1); `callback` is told what it answered
    pub fn query_capabilities<F>(&self, contact_uri: &str, callback: F, rt: &Arc<Runtime>)
    where
        F: FnOnce(Capabilities) + Send + 'static,
    {
        self.capability_service.query(
            contact_uri,
            callback,
            &self.core.get_transaction_manager(),
            rt,
        );
    }

    /// Asks contacts for their capabilities, as query_capabilities() does
    pub fn capability_query(&self) -> CapabilityQuery {
        let service = Arc::clone(&self.capability_service);
        let tm = self.core.get_transaction_manager();
        let rt = Arc::clone(&self.connector.rt);
        Arc::new(move |contact_uri| {
            let (tx, rx) = futures::channel::oneshot::channel();
            service.query(
                &contact_uri,
                move |capabilities| {
                    let _ = tx.send(capabilities);
                },
                &tm,
                &rt,
            );
            Box::pin(async move {
                rx.await.unwrap_or(Capabilities {
                    status_code: 0,
                    feature_tags: String::new(),
                })
            })
        })
    }

    /// Has the group chats created from now on encrypted end to end by
    /// `encryption` when they can be (RCC.16 section 8.1)
    pub fn set_group_encryption(&self, encryption: Arc<dyn GroupEncryption>) {
        self.cpm_session_service.set_group_encryption(encryption);
    }

    /// Has the feature tags `extra` gives, when it gives any, told in OPTIONS
    /// exchanges besides those of the services of this client
    pub fn set_extra_feature_tags(
        &self,
        extra: impl Fn() -> Option<String> + Send + Sync + 'static,
    ) {
        self.capability_service.set_extra_feature_tags(extra);
    }

    /// The feature tags told in OPTIONS exchanges as they apply now
    #[cfg(all(test, feature = "e2ee"))]
    pub(crate) fn feature_tags(&self) -> String {
        self.capability_service.feature_tags()
    }

    pub fn send_is_composing<F>(
        &self,
        recipient: &str,
        recipient_type: RecipientType,
        active: bool,
        result_callback: F,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let result_callback = Arc::new(Mutex::new(Some(result_callback)));
        let result_callback_ = Arc::clone(&result_callback);
        let sent = self.cpm_session_service.send_is_composing(
            recipient,
            &recipient_type,
            active,
            move |status_code, reason_phrase| {
                if let Some(result_callback) = result_callback_.lock().unwrap().take() {
                    result_callback(status_code, reason_phrase);
                }
            },
            rt,
        );
        if !sent {
            let result_callback = result_callback.lock().unwrap().take();
            if let Some(result_callback) = result_callback {
                result_callback(404, String::from("Not Found"));
            }
        }
    }

    /// Ends the chat session with `recipient`, a contact or a group: 404 if
    /// there is none. A message sent to it from now on starts another.
    pub fn end_chat_session<F>(&self, recipient: &str, result_callback: F)
    where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        if self.cpm_session_service.end_session(recipient) {
            result_callback(200, String::from("Ok"));
        } else {
            result_callback(404, String::from("Not Found"));
        }
    }

    /// Sends the IMDN document `imdn_content` to `sender_uri`, by the service
    /// the message told of came by: a chat (0) or standalone messaging (1)
    pub fn send_imdn_report<F>(
        &self,
        imdn_content: &str,
        sender_uri: &str,
        sender_service_type: i32,
        _sender_session_handle: *mut MessagingSessionHandle,
        rt: Arc<Runtime>,
        send_imdn_report_result_callback: F,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let service = match sender_service_type {
            0 => ImdnService::Chat,
            1 => ImdnService::Standalone,
            _ => {
                send_imdn_report_result_callback(403, String::from("Forbidden"));
                return;
            }
        };

        // as send_message(), no engine lock held while sending or calling back
        match registered_identity(&self.state) {
            Some((transport, public_user_identity)) => send_imdn(
                imdn_content,
                sender_uri,
                service,
                &self.core.get_transaction_manager(),
                &transport,
                &public_user_identity,
                send_imdn_report_result_callback,
                &rt,
            ),

            None => send_imdn_report_result_callback(403, String::from("Forbidden")),
        }
    }

    /// Tells the sender of the message `message_id` that it was displayed, if
    /// it asked to be told: in the session with the group if the message was
    /// taken in one, else by the service it came by. A message not among
    /// those last taken is answered with 404, one that did not ask with 403,
    /// and one of a group there is no session with any longer with 480.
    pub fn send_display_notification<F>(
        &self,
        message_id: &str,
        rt: Arc<Runtime>,
        result_callback: F,
    ) where
        F: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let notice = match self.received_messages.displayed(message_id) {
            Ok(notification) => notification,
            Err(Refusal::Unknown) => {
                result_callback(404, String::from("Not Found"));
                return;
            }
            Err(Refusal::NotAskedFor) => {
                result_callback(403, String::from("Forbidden"));
                return;
            }
        };

        if let Some(group) = &notice.group {
            let result_callback = Arc::new(Mutex::new(Some(result_callback)));
            let result_callback_ = Arc::clone(&result_callback);
            let sent = self.cpm_session_service.send_group_imdn(
                group,
                &notice.xml,
                &notice.sender_uri,
                notice.original_message_id.as_deref(),
                move |status_code, reason_phrase| {
                    let result_callback = result_callback_.lock().unwrap().take();
                    if let Some(result_callback) = result_callback {
                        result_callback(status_code, reason_phrase);
                    }
                },
                &rt,
            );
            if !sent {
                let result_callback = result_callback.lock().unwrap().take();
                if let Some(result_callback) = result_callback {
                    result_callback(480, String::from("Temporarily Unavailable"));
                }
            }
            return;
        }

        match registered_identity(&self.state) {
            Some((transport, public_user_identity)) => send_imdn(
                &notice.xml,
                &notice.sender_uri,
                notice.service,
                &self.core.get_transaction_manager(),
                &transport,
                &public_user_identity,
                result_callback,
                &rt,
            ),

            None => result_callback(403, String::from("Forbidden")),
        }
    }

    /// The host of ftHTTPCSURI, with ftHTTPCSUser and ftHTTPCSPwd, if all are
    /// provisioned
    fn ft_http_cs_credentials(&self) -> Option<(String, String, String)> {
        let configs = &self.ft_http_configs;
        let url = Url::parse(configs.ft_http_cs_uri.as_deref()?).ok()?;
        Some((
            String::from(url.host_str()?),
            configs.ft_http_cs_user.clone()?,
            configs.ft_http_cs_pwd.clone()?,
        ))
    }

    /// Uploads the file at `file_path`, with the thumbnail at
    /// `thumbnail_path` if any, as `tid`, resuming the upload if `tid` was
    /// uploaded before: the result callback is given the XML of the content
    /// server telling where they are
    ///
    /// For the group chat of Conversation-ID `conversation_id` while it is
    /// encrypted, they are encrypted first, their keys kept for the message
    /// sending them to carry (RCC.16 section 9.1.2.1), see
    /// `ft_http::upload_sealed_file()`.
    pub fn upload_file<PF, RF>(
        &self,
        tid: &str,
        conversation_id: Option<&str>,
        file_path: &str,
        file_name: &str,
        file_mime: &str,
        file_hash: Option<&str>,
        thumbnail_path: Option<&str>,
        thumbnail_name: Option<&str>,
        thumbnail_mime: Option<&str>,
        thumbnail_hash: Option<&str>,
        msisdn: Option<&str>,
        http_client: Arc<HttpClient>,
        gba_context: Arc<GbaContext>,
        security_context: Arc<SecurityContext>,
        rt: Arc<Runtime>,
        upload_file_progress_callback: PF,
        upload_file_result_callback: RF,
    ) where
        PF: Fn(u32, i32) + Send + Sync + 'static,
        RF: FnOnce(u16, String, Option<String>) + Send + Sync + 'static,
    {
        match Uuid::parse_str(tid) {
            Ok(tid) => {
                let ft_auth = self.ft_http_configs.ft_auth;

                if ft_auth == 1 {
                    if let Some(ft_http_cs_uri) = &self.ft_http_configs.ft_http_cs_uri {
                        let ft_http_service = Arc::clone(&self.ft_http_service);
                        // that of an encrypted group chat, sealed
                        let sealing = conversation_id.and_then(|conversation_id| {
                            self.cpm_session_service
                                .group_encryption()
                                .filter(|encryption| encryption.encrypts_files(conversation_id))
                                .map(|encryption| (String::from(conversation_id), encryption))
                        });

                        let ft_http_cs_uri = String::from(ft_http_cs_uri);
                        let credentials = self.ft_http_cs_credentials();
                        let msisdn = match msisdn {
                            Some(msisdn) => Some(String::from(msisdn)),
                            None => None,
                        };

                        let file_path = String::from(file_path);
                        let file_name = String::from(file_name);
                        let file_mime = String::from(file_mime);
                        let file_hash = match file_hash {
                            Some(file_hash) => Some(String::from(file_hash)),
                            None => None,
                        };

                        let thumbnail_path = match thumbnail_path {
                            Some(thumbnail_path) => Some(String::from(thumbnail_path)),
                            None => None,
                        };

                        let thumbnail_name = match thumbnail_name {
                            Some(thumbnail_name) => Some(String::from(thumbnail_name)),
                            None => None,
                        };

                        let thumbnail_mime = match thumbnail_mime {
                            Some(thumbnail_mime) => Some(String::from(thumbnail_mime)),
                            None => None,
                        };

                        let thumbnail_hash = match thumbnail_hash {
                            Some(thumbnail_hash) => Some(String::from(thumbnail_hash)),
                            None => None,
                        };

                        rt.spawn(async move {
                            let file: FileInfo<'_> = FileInfo {
                                path: &file_path,
                                name: &file_name,
                                mime: &file_mime,
                                hash: file_hash.as_deref(),
                            };

                            let thumbnail = match (
                                thumbnail_path.as_deref(),
                                thumbnail_name.as_deref(),
                                thumbnail_mime.as_deref(),
                            ) {
                                (
                                    Some(thumbnail_path),
                                    Some(thumbnail_name),
                                    Some(thumbnail_mime),
                                ) => Some(FileInfo {
                                    path: thumbnail_path,
                                    name: thumbnail_name,
                                    mime: thumbnail_mime,
                                    hash: thumbnail_hash.as_deref(),
                                }),
                                _ => None,
                            };

                            let progress_callback: Box<dyn Fn(u32, i32) + Send + Sync> =
                                Box::new(upload_file_progress_callback);
                            let progress_callback = Arc::new(progress_callback);

                            let server = ContentServer {
                                http_client: &http_client,
                                gba_context: &gba_context,
                                security_context: &security_context,
                                credentials: credentials.as_ref().map(|(host, user, password)| {
                                    Credentials {
                                        host,
                                        user,
                                        password,
                                    }
                                }),
                                msisdn: msisdn.as_deref(),
                            };

                            let uploaded = match &sealing {
                                Some((conversation_id, encryption)) => {
                                    let seal = |content: &[u8], name: &str, mime: &str| {
                                        encryption.seal_file(content, name, mime)
                                    };
                                    upload_sealed_file(
                                        &ft_http_service,
                                        &ft_http_cs_uri,
                                        tid,
                                        file,
                                        thumbnail,
                                        &server,
                                        &progress_callback,
                                        &seal,
                                    )
                                    .await
                                    .map(
                                        |(xml, file, thumbnail)| {
                                            if !encryption.uploaded(
                                                conversation_id,
                                                xml.as_bytes(),
                                                &file,
                                                thumbnail.as_deref(),
                                            ) {
                                                platform_log(
                                                    LOG_TAG,
                                                    "the keys of the file uploaded not kept",
                                                );
                                            }
                                            xml
                                        },
                                    )
                                }
                                None => {
                                    upload_file(
                                        &ft_http_service,
                                        &ft_http_cs_uri,
                                        tid,
                                        file,
                                        thumbnail,
                                        &server,
                                        &progress_callback,
                                    )
                                    .await
                                }
                            };
                            match uploaded {
                                Ok(result_xml) => {
                                    upload_file_result_callback(
                                        200,
                                        String::from("Ok"),
                                        Some(result_xml),
                                    );
                                }

                                Err(e) => {
                                    let status_code = e.error_code();
                                    let reason_phrase = e.error_string();
                                    upload_file_result_callback(status_code, reason_phrase, None);
                                }
                            }
                        });

                        return;
                    }
                }

                upload_file_result_callback(403, String::from("Forbidden"), None);
            }

            Err(e) => upload_file_result_callback(400, format!("{}", e), None),
        }
    }

    /// Downloads the file at `file_uri` to `download_path`, from `start` of
    /// its `total` size if known, through the download proxy if one is
    /// provisioned, told what `origin` tells of the message that brought it
    ///
    /// One received encrypted in a group chat is downloaded encrypted next to
    /// `download_path`, going on from what is there of it rather than from
    /// `start`, then opened into `download_path` with its key, which is
    /// forgotten then (RCC.16 section 9.1.2.2), see
    /// `ft_http::download_sealed_file()`.
    pub fn download_file<PF, RF>(
        &self,
        file_uri: &str,
        download_path: &str,
        start: usize,
        total: Option<usize>,
        origin: DownloadOrigin<'_>,
        msisdn: Option<&str>,
        http_client: Arc<HttpClient>,
        gba_context: Arc<GbaContext>,
        security_context: Arc<SecurityContext>,
        rt: Arc<Runtime>,
        download_file_progress_callback: PF,
        download_file_result_callback: RF,
    ) where
        PF: Fn(u32, i32) + Send + Sync + 'static,
        RF: FnOnce(u16, String) + Send + Sync + 'static,
    {
        let ft_auth = self.ft_http_configs.ft_auth;

        if ft_auth == 1 {
            // one received encrypted, opened once downloaded (RCC.16 section
            // 9.1.2.2)
            let opening = self
                .cpm_session_service
                .group_encryption()
                .filter(|encryption| encryption.opens_file(file_uri))
                .map(|encryption| (String::from(file_uri), encryption));
            let file_uri = download_uri(
                self.ft_http_configs.ft_http_dl_uri.as_deref(),
                file_uri,
                &origin,
                |other_party| self.cpm_session_service.group_conversation_id(other_party),
            );

            let credentials = self.ft_http_cs_credentials();

            let download_path = String::from(download_path);

            let msisdn = match msisdn {
                Some(msisdn) => Some(String::from(msisdn)),
                None => None,
            };

            rt.spawn(async move {
                let server = ContentServer {
                    http_client: &http_client,
                    gba_context: &gba_context,
                    security_context: &security_context,
                    credentials: credentials
                        .as_ref()
                        .map(|(host, user, password)| Credentials {
                            host,
                            user,
                            password,
                        }),
                    msisdn: msisdn.as_deref(),
                };

                let downloaded = match &opening {
                    Some((url, encryption)) => {
                        let open = |ciphertext: &[u8]| encryption.open_file(url, ciphertext);
                        download_sealed_file(
                            &file_uri,
                            &download_path,
                            total,
                            &server,
                            download_file_progress_callback,
                            &open,
                        )
                        .await
                    }
                    None => {
                        download_file(
                            &file_uri,
                            &download_path,
                            start,
                            total,
                            &server,
                            download_file_progress_callback,
                        )
                        .await
                    }
                };
                match downloaded {
                    Ok(()) => {
                        download_file_result_callback(200, String::from("Ok"));
                    }

                    Err(e) => {
                        let status_code = e.error_code();
                        let reason_phrase = e.error_string();
                        download_file_result_callback(status_code, reason_phrase);
                    }
                }
            });

            return;
        }

        download_file_result_callback(403, String::from("Forbidden"));
    }

    pub fn create_conference_v1<F>(
        &self,
        recipients: &str,
        offer_sdp: &str,
        event_cb: Option<MultiConferenceEventListener>,
        event_cb_context: MultiConferenceEventListenerContextWrapper,
        rt: &Arc<Runtime>,
        callback: F,
    ) where
        F: FnOnce(Option<(MultiConferenceV1, String)>) + Send + Sync + 'static,
    {
        let core = Arc::clone(&self.core);

        // to-do: check RcsEngineRegistrationState

        self.conference_service_v1.create_conference(
            recipients,
            offer_sdp,
            event_cb,
            event_cb_context,
            &core,
            rt,
            callback,
        )
    }

    pub fn retrieve_specific_chatbots<F>(
        &self,
        local_etag: Option<&str>,
        msisdn: Option<&str>,
        http_client: Arc<HttpClient>,
        gba_context: Arc<GbaContext>,
        security_context: Arc<SecurityContext>,
        rt: Arc<Runtime>,
        retrieve_specific_chatbots_result_callback: F,
    ) where
        F: FnOnce(u16, String, Option<String>, Option<String>, u32) + Send + Sync + 'static,
    {
        platform_log(LOG_TAG, "calling retrieve_specific_chatbots()");

        if let Some(specific_chatbots_lists_url) = &self.chatbot_config.specific_chatbots_lists {
            let specific_chatbots_lists_url = String::from(specific_chatbots_lists_url);

            let local_etag: Option<String> = match local_etag {
                Some(local_etag) => Some(String::from(local_etag)),
                None => None,
            };

            let msisdn = match msisdn {
                Some(msisdn) => Some(String::from(msisdn)),
                None => None,
            };

            rt.spawn(async move {
                match chat_bot::retrieve_specific_chatbots(
                    &specific_chatbots_lists_url,
                    local_etag.as_deref(),
                    msisdn.as_deref(),
                    &http_client,
                    &gba_context,
                    &security_context,
                    None,
                )
                .await
                {
                    Ok(result) => match result {
                        RetrieveSpecificChatbotsSuccess::Ok(
                            specific_chatbots,
                            response_etag,
                            expiry,
                        ) => {
                            retrieve_specific_chatbots_result_callback(
                                200,
                                String::from("Ok"),
                                Some(specific_chatbots),
                                response_etag,
                                expiry,
                            );
                        }
                        RetrieveSpecificChatbotsSuccess::NotModified(response_etag, expiry) => {
                            retrieve_specific_chatbots_result_callback(
                                304,
                                String::from("Not Modified"),
                                None,
                                response_etag,
                                expiry,
                            );
                        }
                    },
                    Err(e) => {
                        platform_log(
                            LOG_TAG,
                            format!("retrieve_specific_chatbots error: {:?}", &e),
                        );
                        let status_code = e.error_code();
                        let reason_phrase = e.error_string();
                        retrieve_specific_chatbots_result_callback(
                            status_code,
                            reason_phrase,
                            None,
                            None,
                            0,
                        );
                    }
                }
            });
        } else {
            retrieve_specific_chatbots_result_callback(
                404,
                String::from("Not Found"),
                None,
                None,
                0,
            );
        }
    }

    pub fn search_chatbot<F>(
        &self,
        query: &str,
        start: u32,
        num: u32,
        home_operator: &str,
        msisdn: Option<&str>,
        http_client: Arc<HttpClient>,
        gba_context: Arc<GbaContext>,
        security_context: Arc<SecurityContext>,
        rt: Arc<Runtime>,
        chatbot_search_result_callback: F,
    ) where
        F: FnOnce(u16, String, Option<String>) + Send + Sync + 'static,
    {
        platform_log(LOG_TAG, "calling search_chatbot()");

        if let Some(chatbot_directory) = &self.chatbot_config.chatbot_directory {
            let chatbot_directory = String::from(chatbot_directory);
            let query = String::from(query);
            let home_operator = String::from(home_operator);
            let msisdn = match msisdn {
                Some(msisdn) => Some(String::from(msisdn)),
                None => None,
            };

            rt.spawn(async move {
                match chat_bot::search_chatbot_directory(
                    &chatbot_directory,
                    &query,
                    start,
                    num,
                    &home_operator,
                    msisdn.as_deref(),
                    &http_client,
                    &gba_context,
                    &security_context,
                    None,
                )
                .await
                {
                    Ok(json) => {
                        chatbot_search_result_callback(200, String::from("Ok"), Some(json));
                    }
                    Err(e) => {
                        platform_log(LOG_TAG, format!("search_chatbot_directory error: {:?}", &e));
                        let status_code = e.error_code();
                        let reason_phrase = e.error_string();
                        chatbot_search_result_callback(status_code, reason_phrase, None);
                    }
                }
            });

            return;
        }

        chatbot_search_result_callback(403, String::from("Forbidden"), None);
    }

    pub fn retrieve_chatbot_info<F>(
        &self,
        chatbot_sip_uri: &str,
        local_etag: Option<&str>,
        home_operator: &str,
        home_language: &str,
        msisdn: Option<&str>,
        http_client: Arc<HttpClient>,
        gba_context: Arc<GbaContext>,
        security_context: Arc<SecurityContext>,
        rt: Arc<Runtime>,
        retrieve_chatbot_info_result_callback: F,
    ) where
        F: FnOnce(u16, String, Option<String>, Option<String>, u32) + Send + Sync + 'static,
    {
        platform_log(LOG_TAG, "calling retrieve_chatbot_info()");

        let host = match &self.chatbot_config.bot_info_fqdn {
            Some(bot_info_fqdn) => String::from(bot_info_fqdn),

            None => {
                if let Some(chatbot_sip_uri) = chatbot_sip_uri.as_chatbot_sip_uri() {
                    format!(
                        "{}.{}",
                        chatbot_sip_uri.bot_platform, chatbot_sip_uri.bot_platform_domain
                    )
                } else {
                    retrieve_chatbot_info_result_callback(
                        403,
                        String::from("Forbidden"),
                        None,
                        None,
                        0,
                    );
                    return;
                }
            }
        };

        let chatbot_sip_uri = String::from(chatbot_sip_uri);

        let local_etag: Option<String> = match local_etag {
            Some(local_etag) => Some(String::from(local_etag)),
            None => None,
        };

        let home_operator = String::from(home_operator);
        let home_language = String::from(home_language);

        let msisdn = match msisdn {
            Some(msisdn) => Some(String::from(msisdn)),
            None => None,
        };

        rt.spawn(async move {
            match chat_bot::retrieve_chatbot_info(
                &host,
                &chatbot_sip_uri,
                local_etag.as_deref(),
                &home_operator,
                &home_language,
                msisdn.as_deref(),
                &http_client,
                &gba_context,
                &security_context,
                None,
            )
            .await
            {
                Ok(result) => match result {
                    RetrieveChatbotInfoSuccess::Ok(chatbot_info, response_etag, expiry) => {
                        retrieve_chatbot_info_result_callback(
                            200,
                            String::from("Ok"),
                            Some(chatbot_info),
                            response_etag,
                            expiry,
                        );
                    }
                    RetrieveChatbotInfoSuccess::NotModified(response_etag, expiry) => {
                        retrieve_chatbot_info_result_callback(
                            304,
                            String::from("Not Modified"),
                            None,
                            response_etag,
                            expiry,
                        );
                    }
                },
                Err(e) => {
                    platform_log(LOG_TAG, format!("retrieve_chatbot_info error: {:?}", &e));
                    let status_code = e.error_code();
                    let reason_phrase = e.error_string();
                    retrieve_chatbot_info_result_callback(
                        status_code,
                        reason_phrase,
                        None,
                        None,
                        0,
                    );
                }
            }
        });
    }
}

/// What connecting takes from the configuration
struct ConnectSettings {
    impi: Option<String>,
    impu: Option<String>,

    home_domain: Option<String>,

    authentication_type: Option<AuthenticationType>,

    sip_instance_id: Uuid,

    p_cscf_connection_config: PCscfConnectionConfig,

    registration_id_counter: u32,
}

/// Whether to stay connected, and how to try again
struct Retry {
    /// Whether connect() was called last, rather than disconnect()
    wanted: bool,
    /// The attempts in a row that have failed to register
    failures: u32,
    /// Counts the attempts to connect, so that only the latest goes on
    generation: u64,
}

/// Connects to a P-CSCF and registers, and does so again whenever the
/// connection or the registration is lost. The retry lock is never taken with
/// the state lock held
struct Connector {
    state: Arc<Mutex<(RcsEngineConnectionState, RcsEngineRegistrationState)>>,

    state_callback: Arc<Box<dyn Fn(RcsEngineRegistrationState) + Send + Sync + 'static>>,

    tm: Arc<SipTransactionManager>,

    core: Arc<SipCore>,

    context: Arc<Context>,

    flow_manager: Arc<FlowManager>,

    cpm_session_service: Arc<CPMSessionService>,

    standalone_messaging_service: Arc<StandaloneMessagingService>,

    conference_service_v1: Arc<MultiConferenceServiceV1>,

    capability_service: Arc<CapabilityService>,

    subscription_id: i32,

    settings: Mutex<ConnectSettings>,

    retry: Mutex<Retry>,

    rt: Arc<Runtime>,
}

impl Connector {
    /// Connects and registers, unless `attempt` is not the latest attempt or
    /// there is a connection already
    fn connect(self: &Arc<Self>, attempt: u64) {
        {
            let retry = self.retry.lock().unwrap();
            if !retry.wanted || retry.generation != attempt {
                return;
            }

            let mut guard = self.state.lock().unwrap();
            match &guard.0 {
                RcsEngineConnectionState::IDLE => {
                    guard.0 = RcsEngineConnectionState::CONNECTING;
                }

                _ => return,
            }
        }

        let configured = {
            let mut guard = self.settings.lock().unwrap();
            let settings = &mut *guard;
            match (
                settings.impi.clone(),
                settings.impu.clone(),
                settings.home_domain.clone(),
                settings.authentication_type.clone(),
            ) {
                (Some(impi), Some(impu), Some(home_domain), Some(authentication_type)) => {
                    settings.registration_id_counter += 1;
                    Some((
                        impi,
                        impu,
                        home_domain,
                        authentication_type,
                        settings.sip_instance_id,
                        settings.registration_id_counter,
                        settings.p_cscf_connection_config.get_next(),
                    ))
                }

                _ => None,
            }
        };

        let (
            impi,
            impu,
            home_domain,
            authentication_type,
            sip_instance_id,
            registration_id,
            p_cscf,
        ) = match configured {
            Some(configured) => configured,
            None => {
                platform_log(LOG_TAG, "connect(): not configured");
                self.end_attempt(attempt, Reconnect::Never);
                return;
            }
        };

        let (dns_config, service_type, address, known_host, known_ip, known_port) = match p_cscf {
            Some(p_cscf) => p_cscf,
            None => {
                platform_log(LOG_TAG, "connect(): no P-CSCF to connect to");
                self.end_attempt(attempt, Reconnect::Backoff);
                return;
            }
        };

        platform_log(
            LOG_TAG,
            format!(
                "connect(): configured with: {}, known as {:?}, {:?}:{:?}",
                &address, &known_host, &known_ip, &known_port
            ),
        );

        let connector = Arc::clone(self);

        self.rt.spawn(async move {
            let cs = match connect_to_p_cscf(
                &connector.context,
                dns_config,
                &service_type,
                known_host,
                known_ip,
                known_port,
            )
            .await
            {
                Some(cs) => cs,
                None => {
                    connector.end_attempt(attempt, Reconnect::Backoff);
                    return;
                }
            };

            let transport_address = cs.get_local_transport_address();

            let transport = Arc::new(SipTransport::new::<ClientStream>(
                transport_address.clone(),
                cs.get_sip_transport_type(),
            ));

            let connector_ec = Arc::downgrade(&connector);
            let transport_ec = Arc::clone(&transport);
            let transport_tx = setup_sip_transport(
                &transport,
                cs,
                connector.tm.get_ctrl_itf(),
                Arc::clone(&connector.rt),
                move || {
                    platform_log(LOG_TAG, "on sip transport exit");

                    if let Some(connector) = connector_ec.upgrade() {
                        connector.on_lost(&transport_ec, Reconnect::Backoff);
                    }
                },
            );

            {
                let retry = connector.retry.lock().unwrap();
                let mut guard = connector.state.lock().unwrap();

                match guard.0 {
                    RcsEngineConnectionState::CONNECTING if retry.generation == attempt => {
                        guard.0 = RcsEngineConnectionState::CONNECTED(
                            Arc::clone(&transport),
                            transport_address.clone(),
                        );

                        connector
                            .tm
                            .register_sip_transport(Arc::clone(&transport), transport_tx);
                    }

                    _ => return, // dropping transport_tx closes the connection
                }
            }

            let registration = Arc::new(Registration::new(
                connector.subscription_id,
                impi,
                impu,
                home_domain,
                authentication_type,
                Arc::clone(&transport),
                transport_address.clone(),
                registration_id,
                sip_instance_id,
            ));

            connector.flow_manager.observe_registration(
                &transport,
                transport_address,
                &registration,
                &connector.core,
                &connector.rt,
            );

            let connector_ = Arc::downgrade(&connector);
            let transport_ = Arc::clone(&transport);
            start_register(
                &registration,
                &connector.flow_manager,
                &connector.core,
                &connector.rt,
                move |ev| {
                    if let Some(connector) = connector_.upgrade() {
                        connector.on_registration_event(ev, &transport_, sip_instance_id);
                    }
                },
            );
        });
    }

    /// Ends `attempt` to connect, unless another attempt overtook it, and
    /// connects again as `reconnect` says
    fn end_attempt(self: &Arc<Self>, attempt: u64, reconnect: Reconnect) {
        {
            let retry = self.retry.lock().unwrap();
            if retry.generation != attempt {
                return;
            }

            let mut guard = self.state.lock().unwrap();
            match &guard.0 {
                RcsEngineConnectionState::CONNECTING => {
                    guard.0 = RcsEngineConnectionState::IDLE;
                }

                _ => return,
            }
        }

        self.schedule_reconnect(reconnect);
    }

    /// Ends the connection over `transport`, unless it ended already, and
    /// connects again as `reconnect` says
    fn on_lost(self: &Arc<Self>, transport: &Arc<SipTransport>, reconnect: Reconnect) {
        {
            let mut guard = self.state.lock().unwrap();
            match &guard.0 {
                RcsEngineConnectionState::CONNECTED(current, _)
                    if Arc::ptr_eq(current, transport) => {}

                _ => return,
            }

            guard.0 = RcsEngineConnectionState::IDLE;
            guard.1 = RcsEngineRegistrationState::NONE;
        }

        (self.state_callback)(RcsEngineRegistrationState::NONE);

        let _ = self.flow_manager.stop_observation(transport);
        self.tm.unregister_sip_transport(transport, &self.rt);

        self.schedule_reconnect(reconnect);
    }

    /// Connects again after the time `reconnect` says, if still wanted, the
    /// backoff growing with each attempt in a row that fails
    fn schedule_reconnect(self: &Arc<Self>, reconnect: Reconnect) {
        let (delay, attempt) = {
            let mut retry = self.retry.lock().unwrap();
            if !retry.wanted {
                return;
            }

            let delay = match reconnect_delay(reconnect, retry.failures) {
                Some(delay) => delay,
                None => return,
            };

            retry.failures += 1;
            retry.generation += 1;

            (delay, retry.generation)
        };

        platform_log(LOG_TAG, format!("connecting again in {:?}", delay));

        let connector = Arc::downgrade(self);

        self.rt.spawn(async move {
            tokio::time::sleep(delay).await;

            if let Some(connector) = connector.upgrade() {
                connector.connect(attempt);
            }
        });
    }

    fn on_registration_event(
        self: &Arc<Self>,
        event: RegistrationEvent,
        transport: &Arc<SipTransport>,
        sip_instance_id: Uuid,
    ) {
        match event {
            RegistrationEvent::Registered(unbarred_impu) => {
                platform_log(LOG_TAG, "on RegistrationEvent::Registered");

                {
                    let mut guard = self.state.lock().unwrap();
                    match &guard.0 {
                        RcsEngineConnectionState::CONNECTED(current, _)
                            if Arc::ptr_eq(current, transport) => {}

                        _ => return,
                    }

                    guard.1 = RcsEngineRegistrationState::AUTHENTICATED(unbarred_impu.clone());
                    // to-do: we need to append transport address anyway, why not here?
                }

                let sip_instance_id = format!(
                    "<urn:uuid:{}>",
                    sip_instance_id
                        .as_hyphenated()
                        .encode_lower(&mut Uuid::encode_buffer())
                );

                self.core.set_default_public_identity(
                    unbarred_impu.clone(),
                    sip_instance_id.clone(),
                    Arc::clone(transport),
                ); // fix-me: contact identities should not be visible for sip core, best we can do is to provide a map between transport and registered impu to each message consumer

                self.cpm_session_service.set_registered_public_identity(
                    unbarred_impu.clone(),
                    sip_instance_id.clone(),
                    Arc::clone(transport),
                );

                self.conference_service_v1.set_registered_public_identity(
                    unbarred_impu.clone(),
                    sip_instance_id.clone(),
                    Arc::clone(transport),
                );

                // the Contact of its answers to large-mode messages
                self.standalone_messaging_service
                    .set_registered_public_identity(
                        unbarred_impu.clone(),
                        sip_instance_id.clone(),
                        Arc::clone(transport),
                    );

                self.capability_service.set_registered_public_identity(
                    unbarred_impu.clone(),
                    sip_instance_id.clone(),
                    Arc::clone(transport),
                );

                self.retry.lock().unwrap().failures = 0;

                (self.state_callback)(RcsEngineRegistrationState::AUTHENTICATED(unbarred_impu));
            }

            RegistrationEvent::Refreshed => {
                platform_log(LOG_TAG, "on RegistrationEvent::Refreshed");
            }

            RegistrationEvent::Released(reconnect) => {
                platform_log(
                    LOG_TAG,
                    format!("on RegistrationEvent::Released, {:?}", reconnect),
                );

                self.on_lost(transport, reconnect);
            }
        }
    }

    fn on_flow_event(
        self: &Arc<Self>,
        event: FlowEvent,
        transport: &Arc<SipTransport>,
        registration: &Arc<Registration>,
    ) {
        match event {
            FlowEvent::Registered(public_user_id) => {
                platform_log(
                    LOG_TAG,
                    format!("flow_manager: registered as {}", &public_user_id),
                );

                let current = {
                    let mut guard = self.state.lock().unwrap();
                    match &guard.0 {
                        RcsEngineConnectionState::CONNECTED(current, _)
                            if Arc::ptr_eq(current, transport) =>
                        {
                            guard.1 =
                                RcsEngineRegistrationState::MAINTAINED(public_user_id.clone());
                            true
                        }

                        _ => false,
                    }
                };

                if !current {
                    platform_log(LOG_TAG, "registered on a connection given up");
                    self.release(transport, Some(registration), &self.rt);
                    return;
                }

                (self.state_callback)(RcsEngineRegistrationState::MAINTAINED(public_user_id));
            }

            FlowEvent::Lost(reconnect) => {
                platform_log(LOG_TAG, format!("flow_manager: lost, {:?}", reconnect));

                self.on_lost(transport, reconnect);
            }
        }
    }

    /// Leaves the connection over `transport`, de-registering `registration`
    /// first if registered
    fn release(
        &self,
        transport: &Arc<SipTransport>,
        registration: Option<&Arc<Registration>>,
        rt: &Arc<Runtime>,
    ) {
        let deregistering = match registration {
            Some(registration) => deregister(registration, &self.core, rt),
            None => false,
        };

        // the connection is left once the de-registration is answered
        if !deregistering {
            self.tm.unregister_sip_transport(transport, rt);
        }
    }
}

/// What the message that brought the URL of a file tells, for the download
/// proxy to be told (RCC.07 section 4.2.3)
#[derive(Default)]
pub struct DownloadOrigin<'a> {
    /// The imdn.Message-ID of the message
    pub message_id: Option<&'a str>,
    /// The other party of the message: a contact, or a group by its URI
    pub other_party: Option<&'a str>,
    /// The Conversation-ID of the group chat the message came in
    pub conversation_id: Option<&'a str>,
}

/// The URI `file_uri` is downloaded from: the download proxy at
/// `ft_http_dl_uri` if there is one, its query given the file's URL and what
/// `origin` tells (RCC.07 section 4.2.3, Table 99), with the Conversation-ID
/// `conversation_id_of` knows of the other party, a group, if not given; else
/// the file's URL as it is
fn download_uri<C>(
    ft_http_dl_uri: Option<&str>,
    file_uri: &str,
    origin: &DownloadOrigin<'_>,
    conversation_id_of: C,
) -> String
where
    C: Fn(&str) -> Option<String>,
{
    let mut url = match ft_http_dl_uri.map(Url::parse) {
        Some(Ok(url)) => url,
        _ => return String::from(file_uri),
    };

    let conversation_id = origin
        .conversation_id
        .map(String::from)
        .or_else(|| origin.other_party.and_then(&conversation_id_of));

    {
        let mut query = url.query_pairs_mut();
        query.append_pair("url", file_uri);
        if let Some(message_id) = origin.message_id {
            query.append_pair("id", message_id);
        }
        if let Some(other_party) = origin.other_party {
            query.append_pair("op", other_party);
        }
        if let Some(conversation_id) = &conversation_id {
            query.append_pair("ci", conversation_id);
        }
    }

    url.to_string()
}

/// The transport and public identity the engine is registered with, if it is
fn registered_identity(
    state: &Mutex<(RcsEngineConnectionState, RcsEngineRegistrationState)>,
) -> Option<(Arc<SipTransport>, String)> {
    match &*state.lock().unwrap() {
        (
            RcsEngineConnectionState::CONNECTED(transport, _),
            RcsEngineRegistrationState::MAINTAINED(public_user_identity),
        ) => Some((Arc::clone(transport), public_user_identity.clone())),
        _ => None,
    }
}

/// How long to wait before connecting again as `reconnect` says, after
/// `failures` attempts in a row have failed, if at all
fn reconnect_delay(reconnect: Reconnect, failures: u32) -> Option<Duration> {
    match reconnect {
        Reconnect::Now if failures == 0 => Some(Duration::ZERO),
        Reconnect::Now | Reconnect::Backoff => Some(backoff(failures)),
        Reconnect::After(after) => Some(after.max(backoff(failures))),
        Reconnect::Never => None,
    }
}

/// A connection to the P-CSCF known by `host` or `ip`, at `port` or the
/// ports DNS gives (RFC 3263), the addresses of each tried in turn, IPv4
/// first
async fn connect_to_p_cscf(
    context: &Arc<Context>,
    dns_config: DnsConfig,
    service_type: &ServiceType,
    host: Option<String>,
    ip: Option<IpAddr>,
    port: Option<u16>,
) -> Option<ClientStream> {
    let dns_client = context.get_dns_client();

    let name = match (&host, ip) {
        (Some(host), _) => host.clone(),
        (None, Some(ip)) => ip.to_string(),
        (None, None) => return None,
    };

    let mut targets = Vec::new();
    match port {
        Some(port) => targets.push((name.clone(), port)),
        None => {
            if let Ok(mut stream) = dns_client
                .resolve_service(
                    dns_config.clone(),
                    name.clone(),
                    service_type.get_string_repr(),
                )
                .await
            {
                while let Some(target) = stream.next().await {
                    targets.push(target);
                }
            }
        }
    }

    for (target, port) in targets {
        platform_log(
            LOG_TAG,
            format!("connect(): sip service resolved with {}:{}", &target, port),
        );

        let mut addrs = Vec::new();
        match ip {
            Some(ip) => addrs.push(ip),
            None => {
                if let Ok(mut stream) = dns_client.resolve(dns_config.clone(), target.clone()).await
                {
                    while let Some(addr) = stream.next().await {
                        addrs.push(addr);
                    }
                }
            }
        }

        // IPv6 only where IPv4 fails, as many carrier networks do not take
        // SIP over IPv6 yet
        addrs.sort_by_key(|addr| addr.is_ipv6());

        // the server is known by the domain asked for, not the one DNS gave
        // (RFC 5922 section 4)
        let server_name = host.as_deref().unwrap_or(&name);

        for addr in addrs {
            if let Some(cs) = open_stream(context, service_type, addr, port, server_name).await {
                return Some(cs);
            }
        }
    }

    None
}

async fn open_stream(
    context: &Arc<Context>,
    service_type: &ServiceType,
    addr: IpAddr,
    port: u16,
    server_name: &str,
) -> Option<ClientStream> {
    match service_type {
        ServiceType::SipD2T => {
            #[cfg(all(feature = "android", target_os = "android"))]
            let r = ClientStream::new_android(addr, port).await;

            #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
            let r = ClientStream::new_ohos(addr, port).await;

            #[cfg(not(any(
                all(feature = "android", target_os = "android"),
                all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
            )))]
            let r = ClientStream::new_tokio(addr, port).await;

            match r {
                Ok(cs) => Some(cs),
                Err(e) => {
                    platform_log(LOG_TAG, format!("error creating client stream: {:?}", e));
                    None
                }
            }
        }

        ServiceType::SipsD2T => {
            #[cfg(all(feature = "android", target_os = "android"))]
            let r = ClientStream::new_android_ssl(addr, port, server_name).await;

            #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
            let r = ClientStream::new_ohos_ssl(
                context.get_tls_client_config(),
                addr,
                port,
                server_name,
            )
            .await;

            #[cfg(not(any(
                all(feature = "android", target_os = "android"),
                all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
            )))]
            let r = ClientStream::new_tokio_ssl(
                context.get_tls_client_config(),
                addr,
                port,
                server_name,
            )
            .await;

            match r {
                Ok(cs) => match cs.do_handshake().await {
                    Ok((cs, _)) => {
                        platform_log(LOG_TAG, format!("ssl do_handshake success"));
                        Some(cs)
                    }
                    Err(e) => {
                        platform_log(
                            LOG_TAG,
                            format!("ssl do_handshake failed with error {:?}", e),
                        );
                        None
                    }
                },
                Err(e) => {
                    platform_log(
                        LOG_TAG,
                        format!("error creating ssl client stream: {:?}", e),
                    );
                    None
                }
            }
        }

        ServiceType::SipD2U => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{download_uri, reconnect_delay, DownloadOrigin};
    use crate::connectivity::retry::Reconnect;

    fn no_group(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn a_download_through_the_proxy_carries_the_file_url_encoded() {
        assert_eq!(
            download_uri(
                Some("https://dl.example.com/dl?op=x"),
                "https://ftcs.example.com/f/1?a=1&b=2",
                &DownloadOrigin::default(),
                no_group,
            ),
            "https://dl.example.com/dl?op=x&url=https%3A%2F%2Fftcs.example.com%2Ff%2F1%3Fa%3D1%26b%3D2"
        );
        // a query given to a proxy without one
        assert_eq!(
            download_uri(
                Some("https://dl.example.com/dl"),
                "https://ftcs.example.com/f/1",
                &DownloadOrigin::default(),
                no_group,
            ),
            "https://dl.example.com/dl?url=https%3A%2F%2Fftcs.example.com%2Ff%2F1"
        );
        assert_eq!(
            download_uri(
                Some("not a url"),
                "https://ftcs.example.com/f/1",
                &DownloadOrigin::default(),
                no_group,
            ),
            "https://ftcs.example.com/f/1"
        );
    }

    #[test]
    fn a_download_with_no_proxy_is_from_the_file_url_as_it_is() {
        let origin = DownloadOrigin {
            message_id: Some("123456789"),
            other_party: Some("sip:+491711234567@example.com"),
            conversation_id: Some("conversation-1"),
        };
        assert_eq!(
            download_uri(None, "https://ftcs.example.com/f/1", &origin, no_group),
            "https://ftcs.example.com/f/1"
        );
    }

    #[test]
    fn the_proxy_is_told_the_message_as_rcc07_shows() {
        // the example of RCC.07 section 4.2.3
        let origin = DownloadOrigin {
            message_id: Some("123456789"),
            other_party: Some("sip:+491711234567@ims.mnc001.mcc262.3gppnetwork.org;user=phone"),
            conversation_id: None,
        };
        assert_eq!(
            download_uri(
                Some("https://dl.operator.com/path?parm=foo"),
                "https://ftcontentserver.rcs.mnc001.mcc262.pub.3gppnetwork.org/dl?uid=1234",
                &origin,
                no_group,
            ),
            "https://dl.operator.com/path?parm=foo\
&url=https%3A%2F%2Fftcontentserver.rcs.mnc001.mcc262.pub.3gppnetwork.org%2Fdl%3Fuid%3D1234\
&id=123456789\
&op=sip%3A%2B491711234567%40ims.mnc001.mcc262.3gppnetwork.org%3Buser%3Dphone"
        );
    }

    #[test]
    fn the_proxy_is_told_the_conversation_of_a_group() {
        const GROUP: &str = "sip:conf1@conf.example.com";
        let known = |other_party: &str| {
            if other_party == GROUP {
                Some(String::from("known-1"))
            } else {
                None
            }
        };
        let proxy = Some("https://dl.example.com/dl");
        let file = "https://ftcs.example.com/f/1";
        let url = "url=https%3A%2F%2Fftcs.example.com%2Ff%2F1";

        // as given
        let given = DownloadOrigin {
            message_id: None,
            other_party: Some(GROUP),
            conversation_id: Some("given-1"),
        };
        assert_eq!(
            download_uri(proxy, file, &given, known),
            format!(
                "https://dl.example.com/dl?{}&op=sip%3Aconf1%40conf.example.com&ci=given-1",
                url
            )
        );

        // else as known of the group
        let group = DownloadOrigin {
            message_id: None,
            other_party: Some(GROUP),
            conversation_id: None,
        };
        assert_eq!(
            download_uri(proxy, file, &group, known),
            format!(
                "https://dl.example.com/dl?{}&op=sip%3Aconf1%40conf.example.com&ci=known-1",
                url
            )
        );

        // and none of a contact
        let contact = DownloadOrigin {
            message_id: None,
            other_party: Some("tel:+15550001"),
            conversation_id: None,
        };
        assert_eq!(
            download_uri(proxy, file, &contact, known),
            format!("https://dl.example.com/dl?{}&op=tel%3A%2B15550001", url)
        );
    }

    #[test]
    fn a_lost_registration_is_made_again_at_once_only_after_a_success() {
        assert_eq!(reconnect_delay(Reconnect::Now, 0), Some(Duration::ZERO));

        // lost again before registering: the backoff
        let delay = reconnect_delay(Reconnect::Now, 1).unwrap();
        assert!(delay >= Duration::from_secs(30) && delay <= Duration::from_secs(60));

        let delay = reconnect_delay(Reconnect::Backoff, 0).unwrap();
        assert!(delay >= Duration::from_secs(15) && delay <= Duration::from_secs(30));

        // the time the network asks for, or the backoff if longer
        assert_eq!(
            reconnect_delay(Reconnect::After(Duration::from_secs(600)), 0),
            Some(Duration::from_secs(600))
        );
        let delay = reconnect_delay(Reconnect::After(Duration::from_secs(1)), 2).unwrap();
        assert!(delay >= Duration::from_secs(60) && delay <= Duration::from_secs(120));

        assert_eq!(reconnect_delay(Reconnect::Never, 0), None);
    }
}

/// Changes the encrypted subject or icon of the group chat at
/// `conference_uri` as `change` does, in the session there is with it,
/// `callback` told how its focus answered; 404 if there is no session
fn change_group_metadata<F>(
    cpm_session_service: &CPMSessionService,
    conference_uri: &str,
    change: MetadataChange,
    callback: F,
) where
    F: FnOnce(u16, String) + Send + Sync + 'static,
{
    let callback = Arc::new(Mutex::new(Some(callback)));
    let callback_ = Arc::clone(&callback);
    let asked = cpm_session_service.change_group_metadata(
        conference_uri,
        change,
        move |status_code, reason_phrase| {
            if let Some(callback) = callback_.lock().unwrap().take() {
                callback(status_code, reason_phrase);
            }
        },
    );
    if !asked {
        if let Some(callback) = callback.lock().unwrap().take() {
            callback(404, String::from("Not Found"));
        }
    }
}
