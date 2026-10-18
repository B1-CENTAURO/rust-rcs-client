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

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    runtime::Runtime,
    select,
    sync::oneshot,
    time::{interval, sleep},
};

use rust_rcs_core::{
    ffi::log::platform_log,
    internet::{Body, Header},
    sip::{
        sip_subscription::{
            subscribe_request::SubscribeRequest,
            subscriber::{Subscriber, SubscriberEvent},
            InitialSubscribeContext, SubscriptionManager,
        },
        SipCore, SipMessage, SipTransactionManager, SipTransport, SUBSCRIBE,
    },
    util::{rand, raw_string::StrEq},
};

use uuid::Uuid;

use super::{
    reg_info_xml::{parse_xml, RegInfoXml},
    registration::{contact_uri, Registration},
    retry::Reconnect,
};

const LOG_TAG: &str = "librust_rcs_client";

/// What the network says of a registration
pub enum FlowEvent {
    /// The network holds the registration, for the IMPU given
    Registered(String),
    /// The registration is gone, and when to register again
    Lost(Reconnect),
}

type ObservedRegistration = (
    Arc<SipTransport>,
    String,
    Arc<Registration>,
    oneshot::Sender<()>,
);

pub struct FlowManager {
    managed_flow: Arc<
        Mutex<(
            Option<ObservedRegistration>,
            Option<(String, Arc<Subscriber>)>,
        )>,
    >,

    sm: Arc<SubscriptionManager>,
    tm: Arc<SipTransactionManager>,

    state_callback: Box<dyn Fn(FlowEvent, Arc<SipTransport>, Arc<Registration>) + Send + Sync>,
}

impl FlowManager {
    pub fn new<CB>(
        sm: &Arc<SubscriptionManager>,
        tm: &Arc<SipTransactionManager>,
        state_callback: CB,
    ) -> FlowManager
    where
        CB: Fn(FlowEvent, Arc<SipTransport>, Arc<Registration>) + Send + Sync + 'static,
    {
        FlowManager {
            managed_flow: Arc::new(Mutex::new((None, None))),

            sm: Arc::clone(sm),
            tm: Arc::clone(tm),

            state_callback: Box::new(state_callback),
        }
    }

    pub fn observe_registration(
        &self,
        transport: &Arc<SipTransport>,
        transport_address: String,
        registration: &Arc<Registration>,
        core: &Arc<SipCore>,
        rt: &Arc<Runtime>,
    ) {
        let (tx, mut rx) = oneshot::channel();

        let subscriber = {
            let mut guard = self.managed_flow.lock().unwrap();

            guard.0 = Some((
                Arc::clone(transport),
                transport_address,
                Arc::clone(registration),
                tx,
            ));

            guard.1.take()
        };

        if let Some((_, subscriber)) = subscriber {
            subscriber.stop_subscribing(&self.sm, &self.tm, transport, rt);
        }

        let transport_ = Arc::clone(transport);

        let core_ = Arc::clone(core);
        let rt_ = Arc::clone(rt);

        rt.spawn(async move {
            let mut interval = interval(Duration::from_secs(120)); // to-do: make it adjustable
            let mut ticks = 0;

            loop {
                select! {
                    _ = &mut rx => {
                        break
                    },

                    _ = interval.tick() => {
                        if ticks > 0 {
                            let tm = core_.get_transaction_manager();
                            tm.send_heartbeat(&transport_, &rt_);
                        }
                        ticks += 1;
                    },
                };
            }
        });
    }

    pub fn schedule_next_subscribe_directly(
        &self,
        transport: &Arc<SipTransport>,
        core: &Arc<SipCore>,
        rt: &Arc<Runtime>,
    ) {
        let sm = core.get_subscription_manager();
        let tm = core.get_transaction_manager();

        let subscriber = match &self.managed_flow.lock().unwrap().1 {
            Some((_, subscriber)) => Arc::clone(subscriber),
            None => return,
        };

        subscriber.extend_all_subscriptions(3600, &sm, &tm, transport, rt);
    }

    pub fn stop_observation(&self, transport: &Arc<SipTransport>) -> Option<Arc<Registration>> {
        let mut guard = self.managed_flow.lock().unwrap();
        if let Some((transport_, transport_address, registration, tx)) = guard.0.take() {
            if Arc::ptr_eq(transport, &transport_) {
                let _ = tx.send(()); // stop heart-beat

                guard.1.take();

                return Some(registration);
            } else {
                guard
                    .0
                    .replace((transport_, transport_address, registration, tx));
            }
        }

        None
    }

    /// Whether `registration` is the one observed
    fn observes(&self, registration: &Arc<Registration>) -> bool {
        match &self.managed_flow.lock().unwrap().0 {
            Some((_, _, observed, _)) => Arc::ptr_eq(observed, registration),
            None => false,
        }
    }

    fn report(&self, event: FlowEvent, registration: &Arc<Registration>) {
        let transport = match &self.managed_flow.lock().unwrap().0 {
            Some((transport, _, observed, _)) if Arc::ptr_eq(observed, registration) => {
                Arc::clone(transport)
            }
            _ => return,
        };

        (self.state_callback)(event, transport, Arc::clone(registration));
    }
}

pub enum SubscriptionEvent {
    /// The network shortened the registration to the seconds given, to have
    /// it authenticated again (TS 24.229 section 5.1.1.6)
    Shortened(u32),
}

/// What a reginfo document says of a contact
#[derive(Debug, PartialEq)]
pub enum RegNews {
    /// The contact is registered; the seconds left if the network shortened
    /// its registration
    Registered(Option<u32>),
    /// The contact's registration is gone, and when to register again
    Lost(Reconnect),
    /// Nothing about the contact
    Nothing,
}

/// What `reg_info` says of the contact `contact_uri` (RFC 3680, and TS
/// 24.229 sections 5.1.1.6 and 5.1.1.7)
pub fn reg_news(reg_info: &RegInfoXml, contact_uri: &str) -> RegNews {
    for registration_node in &reg_info.registration_nodes {
        for contact_node in &registration_node.contact_nodes {
            if !same_uri(&contact_node.uri, contact_uri) {
                continue;
            }

            let expires = contact_node
                .expires
                .as_ref()
                .and_then(|e| e.parse::<u32>().ok());

            return if contact_node.state == "active" {
                if contact_node.event == "shortened" {
                    RegNews::Registered(Some(expires.unwrap_or(0)))
                } else {
                    RegNews::Registered(None)
                }
            } else {
                match &contact_node.event[..] {
                    // not to be registered again unasked
                    "rejected" => RegNews::Lost(Reconnect::Never),
                    // to be registered again once the time given is over
                    "probation" => RegNews::Lost(
                        match contact_node
                            .retry_after
                            .as_ref()
                            .and_then(|r| r.parse::<u64>().ok())
                        {
                            Some(retry_after) => Reconnect::After(Duration::from_secs(retry_after)),
                            None => Reconnect::Backoff,
                        },
                    ),
                    // deactivated, expired, unregistered
                    _ => RegNews::Lost(Reconnect::Now),
                }
            };
        }
    }

    // a full state without the contact has it unregistered
    if reg_info.state == "full" {
        RegNews::Lost(Reconnect::Now)
    } else {
        RegNews::Nothing
    }
}

/// Whether two SIP URIs, perhaps in angle brackets and with parameters, name
/// the same user at the same address
fn same_uri(a: &str, b: &str) -> bool {
    let bare = |uri: &str| -> String {
        let uri = uri.trim().trim_start_matches('<');
        let uri = uri.split(|c| c == '>' || c == ';').next().unwrap_or(uri);
        uri.to_ascii_lowercase()
    };
    bare(a) == bare(b)
}

/// Subscribes to the registration state of `impu` (TS 24.229 section
/// 5.1.1.3), once `registration` is authenticated
pub fn on_registration_authenticated<CB>(
    flow_manager: &Arc<FlowManager>,
    impu: String,
    transport: &Arc<SipTransport>,
    transport_address: String, // use this in Contact Header ?
    registration: &Arc<Registration>,
    sip_instance_id: Uuid,
    core: &Arc<SipCore>,
    rt: &Arc<Runtime>,
    state_callback: CB,
) where
    CB: Fn(SubscriptionEvent) + Send + Sync + 'static,
{
    platform_log(LOG_TAG, "on_registration_authenticated()");

    let subscription = Arc::new(RegEventSubscription {
        flow_manager: Arc::clone(flow_manager),
        impu,
        transport: Arc::clone(transport),
        transport_address,
        registration: Arc::clone(registration),
        sip_instance_id,
        core: Arc::clone(core),
        rt: Arc::clone(rt),
        state_callback: Box::new(state_callback),
    });

    subscription.subscribe();
}

struct RegEventSubscription {
    flow_manager: Arc<FlowManager>,
    impu: String,
    transport: Arc<SipTransport>,
    transport_address: String,
    registration: Arc<Registration>,
    sip_instance_id: Uuid,
    core: Arc<SipCore>,
    rt: Arc<Runtime>,
    state_callback: Box<dyn Fn(SubscriptionEvent) + Send + Sync>,
}

impl RegEventSubscription {
    fn subscribe(self: &Arc<Self>) {
        if !self.flow_manager.observes(&self.registration) {
            return;
        }

        let this = Arc::clone(self);
        let this_ = Arc::clone(self);

        let subscriber = Subscriber::new(
            "Registrar",
            // only single source dialog allowed for reg-info subscription
            move |event| this.on_event(event),
            move |dialog, expiration| this_.build_request(dialog, expiration),
        );

        let subscriber = Arc::new(subscriber);

        {
            let mut guard = self.flow_manager.managed_flow.lock().unwrap();
            match &guard.0 {
                Some((_, _, observed, _)) if Arc::ptr_eq(observed, &self.registration) => {}
                _ => return,
            }
            guard.1 = Some((self.impu.clone(), Arc::clone(&subscriber)));
        }

        if let Ok(request_message) = subscriber.build_request(None, 3600) {
            if let Ok(subscribe_request) = SubscribeRequest::new(&request_message, subscriber) {
                let subscribe_request = Arc::new(subscribe_request);

                self.core
                    .get_subscription_manager()
                    .register_request(Arc::clone(&subscribe_request), &self.rt);

                self.core.get_transaction_manager().send_request(
                    request_message,
                    &self.transport,
                    InitialSubscribeContext::new(
                        subscribe_request,
                        Arc::clone(&self.core),
                        Arc::clone(&self.rt),
                    ),
                    &self.rt,
                )
            }
        }
    }

    fn on_event(self: &Arc<Self>, event: SubscriberEvent) {
        match event {
            SubscriberEvent::ReceivedNotify(_, content_type, body) => {
                platform_log(LOG_TAG, "on NOTIFY content");

                if !content_type.equals_bytes(b"application/reginfo+xml", true) {
                    return;
                }

                let reg_info = match body.as_ref() {
                    Body::Raw(r) => parse_xml(r),
                    _ => None,
                };

                let reg_info = match reg_info {
                    Some(reg_info) => reg_info,
                    None => {
                        // the registration stands as the REGISTER made it
                        platform_log(LOG_TAG, "reginfo+xml not read");
                        return;
                    }
                };

                let contact_uri = contact_uri(&self.impu, &self.transport_address);

                match reg_news(&reg_info, &contact_uri) {
                    RegNews::Registered(shortened) => {
                        platform_log(
                            LOG_TAG,
                            format!("registration is bound at {}", &contact_uri),
                        );

                        self.flow_manager
                            .report(FlowEvent::Registered(self.impu.clone()), &self.registration);

                        if let Some(remaining) = shortened {
                            (self.state_callback)(SubscriptionEvent::Shortened(remaining));
                        }
                    }

                    RegNews::Lost(reconnect) => {
                        platform_log(LOG_TAG, format!("registration is lost: {:?}", reconnect));

                        self.flow_manager.managed_flow.lock().unwrap().1.take();

                        self.flow_manager
                            .report(FlowEvent::Lost(reconnect), &self.registration);
                    }

                    RegNews::Nothing => {}
                }
            }

            SubscriberEvent::NearExpiration(_) => {
                platform_log(LOG_TAG, "on NearExpiration event");
            }

            SubscriberEvent::Terminated(_, can_resubscribe, retry_after) => {
                platform_log(
                    LOG_TAG,
                    format!("on Terminated event: {}, {}", can_resubscribe, retry_after),
                );

                // the registration stands; the subscription is made again
                // when the network allows (RFC 6665 section 4.1.3)
                self.flow_manager.managed_flow.lock().unwrap().1.take();

                if can_resubscribe {
                    let this = Arc::clone(self);
                    self.rt.spawn(async move {
                        sleep(Duration::from_secs(retry_after as u64)).await;
                        if this.flow_manager.managed_flow.lock().unwrap().1.is_none() {
                            this.subscribe();
                        }
                    });
                }
            }

            SubscriberEvent::SubscribeFailed(code) => {
                // without the registration state, the registration stands
                // as the REGISTER made it
                platform_log(LOG_TAG, format!("on SubscribeFailed event: {}", code));

                self.flow_manager
                    .report(FlowEvent::Registered(self.impu.clone()), &self.registration);
            }
        }
    }

    fn build_request(
        &self,
        dialog: Option<Arc<rust_rcs_core::sip::SipDialog>>,
        expiration: u32,
    ) -> Result<SipMessage, ()> {
        match dialog {
            Some(dialog) => match dialog.make_request(SUBSCRIBE, None) {
                Ok(message) => Ok(message),
                Err(e) => {
                    platform_log(LOG_TAG, format!("sip in-dialog message build error {}", e));
                    Err(())
                }
            },

            None => {
                let mut message = SipMessage::new_request(SUBSCRIBE, self.impu.as_bytes());

                message.add_header(Header::new(
                    b"Call-ID",
                    String::from(
                        Uuid::new_v4()
                            .as_hyphenated()
                            .encode_lower(&mut Uuid::encode_buffer()),
                    ),
                ));

                message.add_header(Header::new(b"CSeq", b"1 SUBSCRIBE"));

                let tag = rand::create_raw_alpha_numeric_string(8);
                let tag = String::from_utf8_lossy(&tag);

                message.add_header(Header::new(b"From", format!("<{}>;tag={}", self.impu, tag)));

                message.add_header(Header::new(b"To", format!("<{}>", self.impu)));

                message.add_header(Header::new(
                    b"Contact",
                    format!(
                        "<{};transport={}>;+sip.instance=\"<urn:uuid:{}>\"",
                        contact_uri(&self.impu, &self.transport_address),
                        self.transport.get_contact_transport_type(),
                        self.sip_instance_id
                            .hyphenated()
                            .encode_lower(&mut Uuid::encode_buffer())
                    ),
                )); // to-do: is transport_address neccessary? also check NOTIFY 200 Ok

                message.add_header(Header::new(b"Expires", expiration.to_string()));

                message.add_header(Header::new(b"Event", b"reg"));

                message.add_header(Header::new(b"Accept-Contact", b"*"));

                message.add_header(Header::new(b"Accept", b"application/reginfo+xml"));

                Ok(message)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::reg_info_xml::parse_xml;
    use super::super::retry::Reconnect;
    use super::{reg_news, RegNews};

    const OURS: &str = "sip:+15551234@192.0.2.10:5060";

    fn news(state: &str, contacts: &[(&str, &str, &str, &str)]) -> RegNews {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\
<reginfo xmlns=\"urn:ietf:params:xml:ns:reginfo\" version=\"1\" state=\"{}\">\
<registration aor=\"sip:+15551234@example.com\" id=\"a7\" state=\"active\">",
            state
        );
        for (i, (uri, state, event, extra)) in contacts.iter().enumerate() {
            xml += &format!(
                "<contact id=\"{}\" state=\"{}\" event=\"{}\" {}><uri>{}</uri></contact>",
                i, state, event, extra, uri
            );
        }
        xml += "</registration></reginfo>";
        reg_news(&parse_xml(xml.as_bytes()).unwrap(), OURS)
    }

    #[test]
    fn our_contact_is_told_apart_from_others() {
        let other = "sip:+15551234@198.51.100.7:5060";

        // another device registers, or loses its registration
        assert_eq!(
            news("partial", &[(other, "active", "registered", "")]),
            RegNews::Nothing
        );
        assert_eq!(
            news("partial", &[(other, "terminated", "deactivated", "")]),
            RegNews::Nothing
        );

        // ours, as the registrar may write it
        for uri in [OURS, "SIP:+15551234@192.0.2.10:5060;transport=tcp"] {
            assert_eq!(
                news(
                    "full",
                    &[
                        (other, "active", "registered", ""),
                        (uri, "active", "registered", "")
                    ]
                ),
                RegNews::Registered(None),
                "{}",
                uri
            );
        }

        // a full state without ours
        assert_eq!(
            news("full", &[(other, "active", "registered", "")]),
            RegNews::Lost(Reconnect::Now)
        );
    }

    #[test]
    fn each_event_of_our_contact_has_its_meaning() {
        for (state, event, extra, expected) in [
            ("active", "created", "", RegNews::Registered(None)),
            ("active", "refreshed", "", RegNews::Registered(None)),
            (
                "active",
                "shortened",
                "expires=\"40\"",
                RegNews::Registered(Some(40)),
            ),
            (
                "terminated",
                "deactivated",
                "",
                RegNews::Lost(Reconnect::Now),
            ),
            ("terminated", "expired", "", RegNews::Lost(Reconnect::Now)),
            (
                "terminated",
                "unregistered",
                "",
                RegNews::Lost(Reconnect::Now),
            ),
            (
                "terminated",
                "probation",
                "retry-after=\"300\"",
                RegNews::Lost(Reconnect::After(Duration::from_secs(300))),
            ),
            (
                "terminated",
                "probation",
                "",
                RegNews::Lost(Reconnect::Backoff),
            ),
            (
                "terminated",
                "rejected",
                "",
                RegNews::Lost(Reconnect::Never),
            ),
        ] {
            assert_eq!(
                news("partial", &[(OURS, state, event, extra)]),
                expected,
                "{} {}",
                state,
                event
            );
        }
    }
}
