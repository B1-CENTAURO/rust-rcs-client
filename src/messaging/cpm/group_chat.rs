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

//! Group chats: who takes part, as the focus tells by the conference event
//! package (RFC 4575) while the session with the group lasts, and adding
//! participants to one (RFC 5368)

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::internet::body::message_body::MessageBody;
use rust_rcs_core::internet::body::multipart_body::MultipartBody;
use rust_rcs_core::internet::parameter::ParameterParser;
use rust_rcs_core::internet::syntax;
use rust_rcs_core::internet::{Body, Header};
use rust_rcs_core::io::Serializable;
use rust_rcs_core::sip::sip_session::SipSession;
use rust_rcs_core::sip::sip_subscription::subscribe_request::SubscribeRequest;
use rust_rcs_core::sip::sip_subscription::subscriber::{Subscriber, SubscriberEvent};
use rust_rcs_core::sip::sip_subscription::InitialSubscribeContext;
use rust_rcs_core::sip::{
    ClientTransactionCallbacks, SipCore, SipDialog, SipMessage, SipTransport, SUBSCRIBE,
};
use rust_rcs_core::util::rand::create_raw_alpha_numeric_string;
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::encryption::{says_no_refusal_follows, GroupInfoPull, CONTENT_TYPE_MLS_RCS};
use super::session::{
    add_mls_opaque_token, mls_opaque_token_value, CPMGroupEvent, CPMSession, SessionEnd,
};
use super::sip::cpm_contact::CPMServiceType;
use super::{is_media_type, LOG_TAG};

/// A participant of a group chat, as its focus tells
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Participant {
    pub uri: String,
    pub display_name: Option<String>,
    /// The status of its endpoint (RFC 4575 section 5.7.4): connected,
    /// pending and so on, or how it was disconnected (section 5.7.5):
    /// departed, booted, failed or busy, or disconnected if not told
    pub status: String,
    /// Why its endpoint was disconnected, if the focus tells in
    /// `<disconnection-info>` (section 5.7.6): a SIP Reason, such as
    /// `SIP;cause=410;text="Removed by server"` (RCC.16 sections 9.3, 9.4,
    /// 9.6)
    pub disconnection_reason: Option<String>,
}

impl Participant {
    /// Whether the Messaging Server removed it from the group, as it does a
    /// user who lost RCS, saying so with cause 410 and the text "Removed by
    /// server" (RCC.16 section 9.6)
    pub fn removed_by_server(&self) -> bool {
        let Some(reason) = &self.disconnection_reason else {
            return false;
        };
        let mut parameters = ParameterParser::new(reason.as_bytes(), b';', true);
        if !parameters
            .next()
            .is_some_and(|protocol| protocol.name.eq_ignore_ascii_case(b"SIP"))
        {
            return false;
        }
        let (mut cause, mut text) = (None, None);
        for parameter in parameters {
            if parameter.name.eq_ignore_ascii_case(b"cause") {
                cause = parameter.value;
            } else if parameter.name.eq_ignore_ascii_case(b"text") {
                text = parameter.value.map(syntax::unquote);
            }
        }
        cause == Some(b"410")
            && text.is_some_and(|text| text.eq_ignore_ascii_case(b"Removed by server"))
    }
}

/// An invitation to a group chat not known before (RCC.07 section 3.2.4.4)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInvitation {
    /// The URI of the group, as its focus tells
    pub conference_uri: String,
    pub conversation_id: String,
    /// What the invitation tells, if it does: the subject of the group, and
    /// the URI and display name of whoever invited
    pub subject: Option<String>,
    pub inviter_uri: Option<String>,
    pub inviter_name: Option<String>,
    /// Whether it waits for the user to accept or decline it, as group chats
    /// are not accepted automatically (AutAcceptGroupChat 0); else it is
    /// being accepted
    pub pending: bool,
    /// Whether the group is encrypted end to end, its MLS group joined
    /// (RCC.16 section 8.1)
    pub encrypted: bool,
}

/// The identifiers a group chat is restarted with (RCC.07 section 3.2.4.10),
/// for the app to keep and give back once the client starts again
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupIds {
    pub conference_uri: String,
    pub conversation_id: String,
    pub contribution_id: String,
    /// The MLS-Opaque-Token its focus gave, which the requests of the
    /// conversation carry (RCC.16 section 6.1.3)
    pub mls_opaque_token: Option<String>,
}

/// A user of a conference-info document
#[derive(Debug, Default)]
struct User {
    entity: String,
    deleted: bool,
    display_text: Option<String>,
    status: Option<String>,
    disconnection_reason: Option<String>,
}

/// A conference-info document (RFC 4575 section 5), as far as its users go
#[derive(Debug)]
struct ConferenceInfo {
    partial: bool,
    version: Option<u32>,
    users: Vec<User>,
}

/// The status an endpoint of `status` and `disconnection_method` gives, the
/// most connected of a user's endpoints counting
fn endpoint_status(status: Option<String>, disconnection_method: Option<String>) -> String {
    match status.as_deref() {
        Some("disconnected") | None => {
            disconnection_method.unwrap_or_else(|| String::from("disconnected"))
        }
        Some(status) => String::from(status),
    }
}

fn parse_conference_info(xml: &[u8]) -> Option<ConferenceInfo> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();

    let mut info: Option<ConferenceInfo> = None;
    let mut user: Option<User> = None;
    // the status, disconnection method and disconnection reason of the
    // endpoint being read
    let mut endpoint: Option<(Option<String>, Option<String>, Option<String>)> = None;
    // the elements open, by local name
    let mut path: Vec<Vec<u8>> = Vec::new();

    loop {
        let event = reader.read_event_into(&mut buf).ok()?;
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(event, Event::Empty(_));
                let name = e.local_name().as_ref().to_vec();
                let attribute = |key: &[u8]| {
                    e.attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == key)
                        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
                };

                match &name[..] {
                    b"conference-info" if path.is_empty() => {
                        info = Some(ConferenceInfo {
                            partial: attribute(b"state").as_deref() == Some("partial"),
                            version: attribute(b"version").and_then(|v| v.parse().ok()),
                            users: Vec::new(),
                        });
                    }
                    b"user" if path.last().map(|p| &p[..]) == Some(b"users") => {
                        user = Some(User {
                            entity: attribute(b"entity").unwrap_or_default(),
                            deleted: attribute(b"state").as_deref() == Some("deleted"),
                            ..User::default()
                        });
                    }
                    b"endpoint" if user.is_some() => {
                        endpoint = Some((None, None, None));
                    }
                    _ => {}
                }

                if !empty {
                    path.push(name);
                } else {
                    // an empty element ends where it starts
                    match &name[..] {
                        b"endpoint" => endpoint = None,
                        b"user" => {
                            if let (Some(info), Some(user)) = (&mut info, user.take()) {
                                if !user.entity.is_empty() {
                                    info.users.push(user);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            Event::Text(ref e) => {
                let text = e.unescape().ok()?.trim().to_string();
                let parent = path.last().map(|p| &p[..]);
                let grandparent = path.len().checked_sub(2).map(|i| &path[i][..]);
                match (grandparent, parent) {
                    (Some(b"user"), Some(b"display-text")) => {
                        if let Some(user) = &mut user {
                            user.display_text = Some(text);
                        }
                    }
                    (Some(b"endpoint"), Some(b"status")) => {
                        if let Some(endpoint) = &mut endpoint {
                            endpoint.0 = Some(text);
                        }
                    }
                    (Some(b"endpoint"), Some(b"disconnection-method")) => {
                        if let Some(endpoint) = &mut endpoint {
                            endpoint.1 = Some(text);
                        }
                    }
                    (Some(b"disconnection-info"), Some(b"reason")) => {
                        if let Some(endpoint) = &mut endpoint {
                            endpoint.2 = Some(text);
                        }
                    }
                    _ => {}
                }
            }

            Event::End(ref e) => {
                path.pop();
                match e.local_name().as_ref() {
                    b"endpoint" => {
                        if let (Some(user), Some((status, method, reason))) =
                            (&mut user, endpoint.take())
                        {
                            let status = endpoint_status(status, method);
                            // a connected endpoint makes the user so
                            if user.status.as_deref() != Some("connected") {
                                user.status = Some(status);
                                user.disconnection_reason = reason;
                            }
                        }
                    }
                    b"user" => {
                        if let (Some(info), Some(user)) = (&mut info, user.take()) {
                            if !user.entity.is_empty() {
                                info.users.push(user);
                            }
                        }
                    }
                    _ => {}
                }
            }

            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    info
}

/// Who takes part in a group chat, as told so far
#[derive(Default)]
pub struct Roster {
    version: Option<u32>,
    participants: Vec<Participant>,
}

impl Roster {
    /// Takes in the conference-info document `xml`, giving the participants
    /// it changes. A document older than the last one taken changes nothing
    /// (RFC 4575 section 4.1).
    pub fn take_in(&mut self, xml: &[u8]) -> Vec<Participant> {
        let info = match parse_conference_info(xml) {
            Some(info) => info,
            None => {
                platform_log(LOG_TAG, "conference-info not read");
                return Vec::new();
            }
        };

        if let (Some(current), Some(version)) = (self.version, info.version) {
            if version <= current {
                return Vec::new();
            }
        }
        if info.version.is_some() {
            self.version = info.version;
        }

        let mut changed = Vec::new();

        // in a full document, those it leaves out are no longer there
        if !info.partial {
            for participant in &mut self.participants {
                let listed = info.users.iter().any(|u| u.entity == participant.uri);
                if !listed && participant.status != "disconnected" {
                    participant.status = String::from("disconnected");
                    changed.push(participant.clone());
                }
            }
            self.participants
                .retain(|participant| participant.status != "disconnected");
        }

        for user in info.users {
            let known = self.participants.iter().position(|p| p.uri == user.entity);
            let previous = known.map(|i| self.participants[i].clone());

            let (status, disconnection_reason) = match (user.deleted, user.status) {
                (true, _) => (String::from("disconnected"), user.disconnection_reason),
                (false, Some(status)) => (status, user.disconnection_reason),
                (false, None) => previous
                    .as_ref()
                    .map_or((String::from("connected"), None), |p| {
                        (p.status.clone(), p.disconnection_reason.clone())
                    }),
            };
            let participant = Participant {
                display_name: user
                    .display_text
                    .or_else(|| previous.as_ref().and_then(|p| p.display_name.clone())),
                uri: user.entity,
                status,
                disconnection_reason,
            };

            if previous.as_ref() != Some(&participant) {
                changed.push(participant.clone());
            }

            match known {
                Some(i) => self.participants[i] = participant,
                None => self.participants.push(participant),
            }
        }

        self.participants
            .retain(|participant| participant.status != "disconnected");

        changed
    }
}

/// The group chats the client takes part in, followed while their sessions
/// last
pub struct GroupChats {
    core: Mutex<Option<Weak<SipCore>>>,
    /// The identifiers of each group by its URI, as its last session had
    /// them, for it to be restarted with (RCC.07 section 3.2.4.10)
    ids: Mutex<HashMap<String, GroupIds>>,
    /// The groups by their URIs being left, through a session started to
    /// leave in
    leaving: Mutex<HashSet<String>>,
    registered_public_identity: Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>,
    pub(crate) listener: Arc<dyn Fn(CPMGroupEvent) + Send + Sync>,
}

impl GroupChats {
    pub(crate) fn new(
        registered_public_identity: Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>,
        listener: Arc<dyn Fn(CPMGroupEvent) + Send + Sync>,
    ) -> GroupChats {
        GroupChats {
            core: Mutex::new(None),
            ids: Mutex::new(HashMap::new()),
            leaving: Mutex::new(HashSet::new()),
            registered_public_identity,
            listener,
        }
    }

    /// The core subscriptions to the groups' conference events are made with
    pub(crate) fn attach_core(&self, core: &Arc<SipCore>) {
        self.core.lock().unwrap().replace(Arc::downgrade(core));
    }

    /// The identifiers the group at `conference_uri` had in its last
    /// session, if there was one
    pub(crate) fn ids_of(&self, conference_uri: &str) -> Option<GroupIds> {
        self.ids.lock().unwrap().get(conference_uri).cloned()
    }

    /// Takes note of the identifiers of a group the app kept, to restart it
    /// with as if a session with it had been had
    pub(crate) fn remember(&self, mut ids: GroupIds) {
        // a token not one is not sent
        ids.mls_opaque_token = ids
            .mls_opaque_token
            .and_then(|token| mls_opaque_token_value(token.as_bytes()));
        self.ids
            .lock()
            .unwrap()
            .insert(ids.conference_uri.clone(), ids);
    }

    /// Takes note of the group at `conference_uri` being left, or no longer
    pub(crate) fn set_leaving(&self, conference_uri: &str, leaving: bool) {
        let mut guard = self.leaving.lock().unwrap();
        if leaving {
            guard.insert(String::from(conference_uri));
        } else {
            guard.remove(conference_uri);
        }
    }

    /// Whether the group at `conference_uri` is being left
    pub(crate) fn is_leaving(&self, conference_uri: &str) -> bool {
        self.leaving.lock().unwrap().contains(conference_uri)
    }

    /// Whether `conversation_id` is that of a group a session was had with
    pub(crate) fn knows(&self, conversation_id: &str) -> bool {
        self.ids
            .lock()
            .unwrap()
            .values()
            .any(|ids| ids.conversation_id == conversation_id)
    }

    /// Takes note of `sip_session` starting, which if with a group is
    /// followed until it ends: the app told it joined the group, then of its
    /// participants as the focus tells, and that it left once the session
    /// ends
    pub(crate) fn started(&self, sip_session: &Arc<SipSession<CPMSession>>, rt: &Arc<Runtime>) {
        let session = sip_session.get_inner();
        let session_info = session.get_session_info();
        if !matches!(session_info.cpm_contact.service_type, CPMServiceType::Group) {
            return;
        }
        let conference_uri =
            String::from_utf8_lossy(&session_info.cpm_contact.service_uri).into_owned();

        if let (Some(conversation_id), Some(contribution_id)) =
            (&session_info.conversation_id, &session_info.contribution_id)
        {
            let changed = {
                let mut known = self.ids.lock().unwrap();
                let previous = known.get(&conference_uri);
                // the token given last, until another is (RCC.16 section
                // 6.1.3), for the conversation it was given in
                let mls_opaque_token = session_info.mls_opaque_token.clone().or_else(|| {
                    previous
                        .filter(|previous| previous.conversation_id == *conversation_id)
                        .and_then(|previous| previous.mls_opaque_token.clone())
                });
                *session.mls_opaque_token().lock().unwrap() = mls_opaque_token.clone();
                let ids = GroupIds {
                    conference_uri: conference_uri.clone(),
                    conversation_id: conversation_id.clone(),
                    contribution_id: contribution_id.clone(),
                    mls_opaque_token,
                };
                let changed = previous != Some(&ids);
                known.insert(conference_uri.clone(), ids.clone());
                changed.then_some(ids)
            };
            // the app told those it is to keep, once known or changed
            if let Some(ids) = changed {
                (self.listener)(CPMGroupEvent::Ids(ids));
            }
        }

        (self.listener)(CPMGroupEvent::Joined(conference_uri.clone()));

        // a participant the Messaging Server removed is committed out of
        // the MLS group by the members (RCC.16 section 9.6)
        let removing = Arc::downgrade(sip_session);
        let removed_by_server = move |participant: &str| {
            let session_end = removing
                .upgrade()
                .and_then(|sip_session| sip_session.get_inner().session_end());
            if let Some(session_end) = session_end {
                let participant = String::from(participant);
                session_end.commit(move |encryption, conversation_id, from, to| {
                    encryption.remove_for_server(conversation_id, from, to, participant)
                });
            }
        };

        let core = self.core.lock().unwrap().as_ref().and_then(Weak::upgrade);
        let registered = self.registered_public_identity.lock().unwrap().clone();
        let subscriber = match (core, registered) {
            (Some(core), Some((transport, impu, instance_id))) => subscribe(
                &conference_uri,
                &core,
                &transport,
                &impu,
                &instance_id,
                session.mls_opaque_token(),
                &self.listener,
                removed_by_server,
                rt,
            )
            .map(|subscriber| (subscriber, core, transport)),
            _ => None,
        };

        // the subscription ends with the session
        let mut ended = session.when_ended();
        let listener = Arc::clone(&self.listener);
        let rt_ = Arc::clone(rt);
        rt.spawn(async move {
            while !*ended.borrow_and_update() {
                if ended.changed().await.is_err() {
                    break;
                }
            }
            if let Some((subscriber, core, transport)) = subscriber {
                subscriber.stop_subscribing(
                    &core.get_subscription_manager(),
                    &core.get_transaction_manager(),
                    &transport,
                    &rt_,
                );
            }
            listener(CPMGroupEvent::Left(conference_uri));
        });
    }
}

/// Subscribes to the conference events of the group at `conference_uri`,
/// telling `listener` of each participant that changes, and
/// `removed_by_server` of each the Messaging Server removed
fn subscribe(
    conference_uri: &str,
    core: &Arc<SipCore>,
    transport: &Arc<SipTransport>,
    impu: &str,
    instance_id: &str,
    mls_opaque_token: Arc<Mutex<Option<String>>>,
    listener: &Arc<dyn Fn(CPMGroupEvent) + Send + Sync>,
    removed_by_server: impl Fn(&str) + Send + Sync + 'static,
    rt: &Arc<Runtime>,
) -> Option<Arc<Subscriber>> {
    let roster = Mutex::new(Roster::default());
    let listener = Arc::clone(listener);
    let conference_uri_ = String::from(conference_uri);
    let conference_uri = String::from(conference_uri);
    let impu = String::from(impu);
    let instance_id = String::from(instance_id);

    let subscriber = Arc::new(Subscriber::new(
        "Group chat",
        move |event| match event {
            SubscriberEvent::ReceivedNotify(_, content_type, body) => {
                if !is_media_type(&content_type, "application/conference-info+xml") {
                    return;
                }
                if let Body::Raw(xml) = body.as_ref() {
                    let changed = roster.lock().unwrap().take_in(xml);
                    for participant in changed {
                        if participant.removed_by_server() {
                            removed_by_server(&participant.uri);
                        }
                        listener(CPMGroupEvent::Participant(
                            conference_uri_.clone(),
                            participant,
                        ));
                    }
                }
            }
            SubscriberEvent::Terminated(_, _, _) => {
                platform_log(LOG_TAG, "conference event subscription terminated");
            }
            SubscriberEvent::SubscribeFailed(status_code) => {
                platform_log(
                    LOG_TAG,
                    format!("conference event subscription failed: {}", status_code),
                );
            }
            SubscriberEvent::NearExpiration(_) => {}
        },
        move |dialog, expiration| {
            let mut message =
                build_subscribe(dialog, expiration, &conference_uri, &impu, &instance_id)?;
            add_mls_opaque_token(&mut message, mls_opaque_token.lock().unwrap().clone());
            Ok(message)
        },
    ));

    let request = subscriber.build_request(None, 3600).ok()?;
    let subscribe_request =
        Arc::new(SubscribeRequest::new(&request, Arc::clone(&subscriber)).ok()?);

    core.get_subscription_manager()
        .register_request(Arc::clone(&subscribe_request), rt);

    core.get_transaction_manager().send_request(
        request,
        transport,
        InitialSubscribeContext::new(subscribe_request, Arc::clone(core), Arc::clone(rt)),
        rt,
    );

    Some(subscriber)
}

/// A SUBSCRIBE to the conference events of the group at `conference_uri`,
/// in `dialog` if the subscription has one (RFC 4575 section 3)
fn build_subscribe(
    dialog: Option<Arc<SipDialog>>,
    expiration: u32,
    conference_uri: &str,
    impu: &str,
    instance_id: &str,
) -> Result<SipMessage, ()> {
    let mut message = match dialog {
        Some(dialog) => dialog.make_request(SUBSCRIBE, None).map_err(|_| ())?,
        None => {
            let mut message = SipMessage::new_request(SUBSCRIBE, conference_uri.as_bytes());

            message.add_header(Header::new(
                b"Call-ID",
                String::from(
                    Uuid::new_v4()
                        .as_hyphenated()
                        .encode_lower(&mut Uuid::encode_buffer()),
                ),
            ));
            message.add_header(Header::new(b"CSeq", b"1 SUBSCRIBE"));

            let tag = create_raw_alpha_numeric_string(8);
            message.add_header(Header::new(
                b"From",
                format!("<{}>;tag={}", impu, String::from_utf8_lossy(&tag)),
            ));
            message.add_header(Header::new(b"To", format!("<{}>", conference_uri)));
            message.add_header(Header::new(
                b"Contact",
                format!("<{}>;+sip.instance=\"{}\"", impu, instance_id),
            ));
            message.add_header(Header::new(b"P-Preferred-Identity", String::from(impu)));

            message
        }
    };

    message.add_header(Header::new(b"Event", b"conference"));
    message.add_header(Header::new(b"Accept", b"application/conference-info+xml"));
    message.add_header(Header::new(b"Expires", expiration.to_string()));

    Ok(message)
}

/// The participants as a resource list (RFC 4826), each a To of the group
/// (RFC 5364)
pub(crate) fn resource_list(participants: &[String]) -> Vec<u8> {
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
    list.into_bytes()
}

/// Asks the focus of the session `session_end` ends to invite
/// `participants` (RFC 5368), with the CPIM message `control_message` of
/// the Commit adding them to its MLS group if it is encrypted (RCC.16
/// section 9.2), `callback` told how it answered and whether an MLS refusal
/// may follow (section 7.2.6); `callback` given back, and nothing asked, if
/// the session is not up to it
pub(crate) fn refer_participants<F>(
    session_end: &SessionEnd,
    participants: &[String],
    control_message: Option<&[u8]>,
    callback: F,
) -> Result<(), F>
where
    F: FnOnce(u16, String, bool) + Send + Sync + 'static,
{
    let Some((mut message, transport)) = new_request(session_end, b"REFER") else {
        return Err(callback);
    };

    let content_id = format!(
        "{}@rcs",
        String::from_utf8_lossy(&create_raw_alpha_numeric_string(16))
    );
    let list = resource_list(participants);

    message.add_header(Header::new(b"Refer-To", format!("<cid:{}>", content_id)));
    message.add_header(Header::new(b"Refer-Sub", b"false"));
    message.add_header(Header::new(b"Require", b"multiple-refer"));
    match control_message {
        // the list, then the control message (RCC.16 section 9.2)
        Some(cpim) => {
            let boundary = create_raw_alpha_numeric_string(16);
            let parts = vec![
                Arc::new(Body::Message(MessageBody {
                    headers: vec![
                        Header::new(b"Content-Type", b"application/resource-lists+xml"),
                        Header::new(b"Content-Disposition", b"recipient-list"),
                        Header::new(b"Content-ID", format!("<{}>", content_id)),
                        Header::new(b"Content-Length", format!("{}", list.len())),
                    ],
                    body: Arc::new(Body::Raw(list)),
                })),
                Arc::new(Body::Message(MessageBody {
                    headers: vec![
                        Header::new(b"Content-Type", b"message/cpim"),
                        Header::new(b"Content-Length", format!("{}", cpim.len())),
                    ],
                    body: Arc::new(Body::Raw(cpim.to_vec())),
                })),
            ];
            message.add_header(Header::new(
                b"Content-Type",
                format!(
                    "multipart/mixed; boundary={}",
                    String::from_utf8_lossy(&boundary)
                ),
            ));
            let body = Body::Multipart(MultipartBody { boundary, parts });
            message.add_header(Header::new(
                b"Content-Length",
                format!("{}", body.estimated_size()),
            ));
            message.set_body(Arc::new(body));
        }
        None => {
            message.add_header(Header::new(
                b"Content-Type",
                b"application/resource-lists+xml",
            ));
            message.add_header(Header::new(b"Content-Disposition", b"recipient-list"));
            message.add_header(Header::new(b"Content-ID", format!("<{}>", content_id)));
            message.add_header(Header::new(b"Content-Length", format!("{}", list.len())));
            message.set_body(Arc::new(Body::Raw(list)));
        }
    }

    send_refer(session_end, message, &transport, callback);
    Ok(())
}

/// Asks the focus of the session `session_end` ends to remove `participant`
/// from the group, by sending it a BYE (RFC 4579, RCC.07 section 3.2.4.12),
/// with the CPIM message `control_message` of the Commit removing its
/// Clients from the MLS group if it is encrypted (RCC.16 section 9.3);
/// otherwise as refer_participants()
pub(crate) fn refer_removal<F>(
    session_end: &SessionEnd,
    participant: &str,
    control_message: Option<&[u8]>,
    callback: F,
) -> Result<(), F>
where
    F: FnOnce(u16, String, bool) + Send + Sync + 'static,
{
    let Some((mut message, transport)) = new_request(session_end, b"REFER") else {
        return Err(callback);
    };

    message.add_header(Header::new(
        b"Refer-To",
        format!("<{};method=BYE>", participant),
    ));
    message.add_header(Header::new(b"Refer-Sub", b"false"));
    // without, the transaction gives it its Content-Length
    if let Some(cpim) = control_message {
        message.add_header(Header::new(b"Content-Type", b"message/cpim"));
        message.add_header(Header::new(b"Content-Length", format!("{}", cpim.len())));
        message.set_body(Arc::new(Body::Raw(cpim.to_vec())));
    }

    send_refer(session_end, message, &transport, callback);
    Ok(())
}

/// A `method` request in the dialog of the session `session_end` ends, with
/// the MLS-Opaque-Token of its group, and the transport it goes by; None if
/// the session is not up to it
fn new_request(session_end: &SessionEnd, method: &[u8]) -> Option<(SipMessage, Arc<SipTransport>)> {
    let transport = match &*session_end.registered_public_identity.lock().unwrap() {
        Some((transport, _, _)) => Arc::clone(transport),
        None => return None,
    };
    let mut message = session_end.dialog.make_request(method, None).ok()?;
    let mls_opaque_token = session_end.sip_session.get_inner().mls_opaque_token();
    add_mls_opaque_token(&mut message, mls_opaque_token.lock().unwrap().clone());
    Some((message, transport))
}

/// Sends the REFER `message` over `transport`, `callback` told how it was
/// answered
fn send_refer<F>(
    session_end: &SessionEnd,
    message: SipMessage,
    transport: &Arc<SipTransport>,
    callback: F,
) where
    F: FnOnce(u16, String, bool) + Send + Sync + 'static,
{
    session_end.tm.send_request(
        message,
        transport,
        focus_answer(&session_end.rt, callback),
        &session_end.rt,
    );
}

/// What tells `callback` how the focus answered a request of a session, as
/// FocusAnswer does; 500 if the request was not sent
pub(crate) fn focus_answer<F>(rt: &Arc<Runtime>, callback: F) -> FocusAnswer
where
    F: FnOnce(u16, String, bool) + Send + Sync + 'static,
{
    let (client_transaction_tx, mut client_transaction_rx) = mpsc::channel(1);
    rt.spawn(async move {
        match client_transaction_rx.recv().await {
            Some((status_code, reason_phrase, refusal_follows)) => {
                callback(status_code, reason_phrase, refusal_follows)
            }
            None => callback(500, String::from("Internal Error"), false),
        }
    });

    FocusAnswer {
        client_transaction_tx,
        rt: Arc::clone(rt),
    }
}

/// Tells how the focus answered a request, such as a REFER or a BYE: its
/// status code and reason phrase, and whether an MLS refusal of what it
/// carried may follow (RCC.16 section 7.2.6), as none does when it did not
/// reach the focus
pub(crate) struct FocusAnswer {
    client_transaction_tx: mpsc::Sender<(u16, String, bool)>,
    rt: Arc<Runtime>,
}

impl ClientTransactionCallbacks for FocusAnswer {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        let refusal_follows = !says_no_refusal_follows(&message);
        if let SipMessage::Response(l, _, _) = message {
            let answer = (
                l.status_code,
                String::from_utf8_lossy(&l.reason_phrase).into_owned(),
                refusal_follows,
            );
            let tx = self.client_transaction_tx.clone();
            self.rt.spawn(async move {
                let _ = tx.send(answer).await;
            });
        }
    }

    fn on_transport_error(&self) {
        let tx = self.client_transaction_tx.clone();
        self.rt.spawn(async move {
            let _ = tx.send((0, String::from("Transport Error"), false)).await;
        });
    }
}

/// Asks the focus of the session `session_end` ends for the GroupInfo of its
/// MLS group, with INFO requests in the session's dialog, as GroupInfoPull
/// does (RCC.16 sections 6.3.1, 6.3.2, 7.10)
pub(crate) fn group_info_pull(session_end: &SessionEnd) -> GroupInfoPull {
    let session_end = session_end.clone();
    Arc::new(move |package, body| {
        let (tx, rx) = oneshot::channel();
        if let Some((mut message, transport)) = new_request(&session_end, b"INFO") {
            message.add_header(Header::new(b"Info-Package", package));
            // without, the transaction gives it its Content-Length
            if let Some(body) = body {
                message.add_header(Header::new(b"Content-Type", CONTENT_TYPE_MLS_RCS));
                message.add_header(Header::new(b"Content-Disposition", b"Info-Package"));
                message.add_header(Header::new(b"Content-Length", format!("{}", body.len())));
                message.set_body(Arc::new(Body::Raw(body)));
            }
            session_end.tm.send_request(
                message,
                &transport,
                InfoAnswer(Mutex::new(Some(tx))),
                &session_end.rt,
            );
        }
        Box::pin(async move { rx.await.ok().flatten() })
    })
}

/// Tells the status code and body of the final response to an INFO request,
/// or None if none came
struct InfoAnswer(Mutex<Option<oneshot::Sender<Option<(u16, Vec<u8>)>>>>);

impl InfoAnswer {
    fn tell(&self, answer: Option<(u16, Vec<u8>)>) {
        if let Some(tx) = self.0.lock().unwrap().take() {
            let _ = tx.send(answer);
        }
    }
}

impl ClientTransactionCallbacks for InfoAnswer {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        let body = match message.get_body().as_deref() {
            Some(Body::Raw(data)) => data.clone(),
            _ => Vec::new(),
        };
        if let SipMessage::Response(l, _, _) = message {
            self.tell(Some((l.status_code, body)));
        }
    }

    fn on_transport_error(&self) {
        self.tell(None);
    }
}

#[cfg(test)]
mod tests {
    use super::{Participant, Roster};

    fn document(state: &str, version: u32, users: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" \
entity=\"sip:conf1@conf.example.com\" state=\"{}\" version=\"{}\">\
<conference-description><display-text>the group</display-text></conference-description>\
<users>{}</users></conference-info>",
            state, version, users
        )
        .into_bytes()
    }

    fn user(entity: &str, display_text: Option<&str>, endpoint: &str) -> String {
        format!(
            "<user entity=\"{}\">{}{}</user>",
            entity,
            display_text.map_or(String::new(), |d| format!(
                "<display-text>{}</display-text>",
                d
            )),
            endpoint
        )
    }

    fn endpoint(status: &str, method: Option<&str>) -> String {
        format!(
            "<endpoint entity=\"sip:x@example.com\"><display-text>a phone</display-text>\
<status>{}</status>{}</endpoint>",
            status,
            method.map_or(String::new(), |m| format!(
                "<disconnection-method>{}</disconnection-method>",
                m
            ))
        )
    }

    fn participant(uri: &str, display_name: Option<&str>, status: &str) -> Participant {
        Participant {
            uri: String::from(uri),
            display_name: display_name.map(String::from),
            status: String::from(status),
            disconnection_reason: None,
        }
    }

    const A: &str = "sip:+15550001@example.com";
    const B: &str = "tel:+15550002";

    #[test]
    fn a_full_document_tells_who_takes_part_and_who_no_longer_does() {
        let mut roster = Roster::default();
        assert_eq!(
            roster.take_in(&document(
                "full",
                1,
                &(user(A, Some("Alice"), &endpoint("connected", None))
                    + &user(B, None, &endpoint("pending", None)))
            )),
            vec![
                participant(A, Some("Alice"), "connected"),
                participant(B, None, "pending"),
            ]
        );

        // the same again changes nothing; B left out has gone
        assert_eq!(
            roster.take_in(&document(
                "full",
                2,
                &user(A, Some("Alice"), &endpoint("connected", None))
            )),
            vec![participant(B, None, "disconnected")]
        );
    }

    #[test]
    fn a_partial_document_changes_only_those_it_lists() {
        let mut roster = Roster::default();
        roster.take_in(&document(
            "full",
            1,
            &(user(A, Some("Alice"), &endpoint("connected", None))
                + &user(B, None, &endpoint("connected", None))),
        ));

        // B departed, A named again with no endpoint keeps its status
        assert_eq!(
            roster.take_in(&document(
                "partial",
                2,
                &(user(B, None, &endpoint("disconnected", Some("departed")))
                    + &user(A, Some("Alice B."), ""))
            )),
            vec![
                participant(B, None, "departed"),
                participant(A, Some("Alice B."), "connected"),
            ]
        );

        // a user deleted
        assert_eq!(
            roster.take_in(&document(
                "partial",
                3,
                &format!("<user entity=\"{}\" state=\"deleted\"/>", A)
            )),
            vec![participant(A, Some("Alice B."), "disconnected")]
        );
    }

    #[test]
    fn an_older_document_changes_nothing() {
        let mut roster = Roster::default();
        roster.take_in(&document(
            "full",
            5,
            &user(A, None, &endpoint("connected", None)),
        ));
        // older, or the same again
        for version in [4, 5] {
            assert!(roster
                .take_in(&document(
                    "partial",
                    version,
                    &user(A, None, &endpoint("disconnected", Some("booted")))
                ))
                .is_empty());
        }
        assert!(roster.take_in(b"not xml at all <").is_empty());
    }

    #[test]
    fn a_user_is_connected_if_any_endpoint_is() {
        let mut roster = Roster::default();
        assert_eq!(
            roster.take_in(&document(
                "full",
                1,
                &user(
                    A,
                    None,
                    &(endpoint("connected", None) + &endpoint("disconnected", Some("failed")))
                )
            )),
            vec![participant(A, None, "connected")]
        );
    }

    /// An endpoint disconnected by `method`, the focus telling why as
    /// `reason`, a SIP Reason
    fn disconnected(method: &str, reason: &str) -> String {
        format!(
            "<endpoint entity=\"sip:x@example.com\"><status>disconnected</status>\
<disconnection-method>{}</disconnection-method>\
<disconnection-info><when>2026-10-25T12:00:00Z</when><reason>{}</reason>\
<by>sip:conf1@conf.example.com</by></disconnection-info></endpoint>",
            method, reason
        )
    }

    #[test]
    fn why_a_participant_was_disconnected_is_told() {
        let mut roster = Roster::default();
        roster.take_in(&document(
            "full",
            1,
            &(user(A, Some("Alice"), &endpoint("connected", None))
                + &user(B, None, &endpoint("connected", None))),
        ));

        // removed by the Messaging Server (RCC.16 section 9.6)
        let changed = roster.take_in(&document(
            "partial",
            2,
            &user(
                B,
                None,
                &disconnected("booted", "SIP;cause=410;text=&quot;Removed by server&quot;"),
            ),
        ));
        assert_eq!(
            changed,
            vec![Participant {
                disconnection_reason: Some(String::from(
                    "SIP;cause=410;text=\"Removed by server\""
                )),
                ..participant(B, None, "booted")
            }]
        );
        assert!(changed[0].removed_by_server());

        // kept while nothing tells otherwise
        let changed = roster.take_in(&document("partial", 3, &user(B, Some("Bob"), "")));
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].status, "booted");
        assert!(changed[0].removed_by_server());

        // a connected endpoint tells no reason, whatever another tells
        let changed = roster.take_in(&document(
            "partial",
            4,
            &user(
                A,
                None,
                &(disconnected("departed", "SIP;cause=200;text=&quot;Call completed&quot;")
                    + &endpoint("connected", None)),
            ),
        ));
        assert!(changed.is_empty(), "{:?}", changed);
    }

    #[test]
    fn only_the_server_removing_a_participant_is_a_removal_by_the_server() {
        let removed = |reason: Option<&str>| Participant {
            disconnection_reason: reason.map(String::from),
            ..participant(B, None, "booted")
        };
        for reason in [
            "SIP;cause=410;text=\"Removed by server\"",
            "sip ; Cause=410 ; TEXT=\"removed by server\"",
        ] {
            assert!(removed(Some(reason)).removed_by_server(), "{}", reason);
        }
        for reason in [
            // removed by a participant (section 9.3), or left (section 9.4)
            "SIP;cause=410;text=\"Kicked\"",
            "SIP;cause=200;text=\"Call completed\"",
            "SIP;cause=480;text=\"Removed by server\"",
            "Q.850;cause=410;text=\"Removed by server\"",
            "SIP;cause=410",
            "",
        ] {
            assert!(!removed(Some(reason)).removed_by_server(), "{}", reason);
        }
        assert!(!removed(None).removed_by_server());
    }
}
