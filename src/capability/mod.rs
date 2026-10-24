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

//! Capability discovery by SIP OPTIONS (RCC.07 section 2.6.1.1): telling
//! others what this client supports, and asking them what they do

#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};

use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::internet::header::{self, HeaderSearch};
use rust_rcs_core::internet::header_field::AsHeaderField;
use rust_rcs_core::internet::Header;
use rust_rcs_core::sip::sip_transaction::server_transaction;
use rust_rcs_core::sip::{
    ClientTransactionCallbacks, ServerTransaction, ServerTransactionEvent, SipDialog, SipMessage,
    SipTransactionManager, SipTransport, TransactionHandler, OPTIONS,
};
use rust_rcs_core::util::rand;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use uuid::Uuid;

const LOG_TAG: &str = "capability";

/// The feature tags of the services of this client, which it registers with
/// (RCC.07 section 2.4.4) and tells in OPTIONS exchanges (section 2.6.1.1)
pub const FEATURE_TAGS: &str = "+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session.group,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.largemsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.systemmsg,urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.filetransfer\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftthumb,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.fthttp,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.ftsms,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.chatbot.sa,urn%3Aurn-7%3A3gpp-application.ims.iari.rcse.im,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geopush,urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.geosm\";+g.gsma.rcs.cpm.pager-large;+g.gsma.rcs.botversion=\"#=1,#=2\"";

/// What a contact answered an OPTIONS with, to be taken as RCC.07 table 6
/// says
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// The final status code, 0 if none came; 403 if this client was not
    /// registered to ask
    pub status_code: u16,
    /// The feature tags of the Contact of a 200, as given, `;` separated
    pub feature_tags: String,
}

/// Feature tags told besides FEATURE_TAGS while they apply, `;` separated
type ExtraFeatureTags = Box<dyn Fn() -> Option<String> + Send + Sync>;

pub struct CapabilityService {
    /// The public identity, the sip.instance and the transport registered
    registered: Mutex<Option<(String, String, Arc<SipTransport>)>>,
    extra_feature_tags: Mutex<Option<ExtraFeatureTags>>,
}

impl CapabilityService {
    pub fn new() -> CapabilityService {
        CapabilityService {
            registered: Mutex::new(None),
            extra_feature_tags: Mutex::new(None),
        }
    }

    pub fn set_registered_public_identity(
        &self,
        public_user_identity: String,
        sip_instance_id: String,
        transport: Arc<SipTransport>,
    ) {
        *self.registered.lock().unwrap() = Some((public_user_identity, sip_instance_id, transport));
    }

    /// Has the feature tags `extra` gives, when it gives any, told besides
    /// those of the services of this client
    pub fn set_extra_feature_tags(
        &self,
        extra: impl Fn() -> Option<String> + Send + Sync + 'static,
    ) {
        *self.extra_feature_tags.lock().unwrap() = Some(Box::new(extra));
    }

    /// The feature tags of this client as they apply now, `;` separated
    pub fn feature_tags(&self) -> String {
        let extra = self
            .extra_feature_tags
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|extra| extra())
            .filter(|extra| !extra.is_empty());
        match extra {
            Some(extra) => format!("{};{}", FEATURE_TAGS, extra),
            None => String::from(FEATURE_TAGS),
        }
    }

    /// The Contact of this client as registered, with its feature tags
    fn contact(&self, public_user_identity: &str, sip_instance_id: &str) -> String {
        format!(
            "<{}>;+sip.instance=\"{}\";{}",
            public_user_identity,
            sip_instance_id,
            self.feature_tags()
        )
    }

    /// Asks `contact_uri` for its capabilities, telling it those of this
    /// client (RCC.07 section 2.6.1.1)
    pub fn query<F>(
        &self,
        contact_uri: &str,
        callback: F,
        tm: &Arc<SipTransactionManager>,
        rt: &Arc<Runtime>,
    ) where
        F: FnOnce(Capabilities) + Send + 'static,
    {
        let registered = self.registered.lock().unwrap().clone();
        let Some((public_user_identity, sip_instance_id, transport)) = registered else {
            callback(Capabilities {
                status_code: 403,
                feature_tags: String::new(),
            });
            return;
        };

        let mut req_message = SipMessage::new_request(OPTIONS, contact_uri.as_bytes());
        req_message.add_header(Header::new(
            b"Call-ID",
            String::from(
                Uuid::new_v4()
                    .as_hyphenated()
                    .encode_lower(&mut Uuid::encode_buffer()),
            ),
        ));
        req_message.add_header(Header::new(b"CSeq", b"1 OPTIONS"));
        let tag = rand::create_raw_alpha_numeric_string(8);
        req_message.add_header(Header::new(
            b"From",
            format!(
                "<{}>;tag={}",
                public_user_identity,
                String::from_utf8_lossy(&tag)
            ),
        ));
        req_message.add_header(Header::new(b"To", format!("<{}>", contact_uri)));
        req_message.add_header(Header::new(
            b"Contact",
            self.contact(&public_user_identity, &sip_instance_id),
        ));
        req_message.add_header(Header::new(
            b"P-Preferred-Identity",
            public_user_identity.clone(),
        ));
        // no SDP (RCC.07 section 2.6.1.1)
        req_message.add_header(Header::new(b"Content-Length", b"0"));

        tm.send_request(
            req_message,
            &transport,
            OptionsQuery {
                callback: Mutex::new(Some(Box::new(callback))),
            },
            rt,
        );
    }

    /// Answers an OPTIONS with the capabilities of this client, or as not
    /// available while it is not registered
    fn answer(
        &self,
        transaction: &Arc<ServerTransaction>,
        tx: mpsc::Sender<ServerTransactionEvent>,
        rt: &Arc<Runtime>,
    ) {
        let message = transaction.message();
        let registered = self.registered.lock().unwrap().clone();
        let response = match registered {
            Some((public_user_identity, sip_instance_id, _)) => {
                server_transaction::make_response(message, transaction.to_tag(), 200, b"OK").map(
                    |mut response| {
                        response.add_header(Header::new(
                            b"Contact",
                            self.contact(&public_user_identity, &sip_instance_id),
                        ));
                        response.add_header(Header::new(
                            b"Allow",
                            b"NOTIFY, OPTIONS, INVITE, UPDATE, CANCEL, BYE, ACK, MESSAGE",
                        ));
                        response
                    },
                )
            }
            None => server_transaction::make_response(
                message,
                transaction.to_tag(),
                480,
                b"Temporarily Unavailable",
            ),
        };
        if let Some(response) = response {
            server_transaction::send_response(Arc::clone(transaction), response, tx, rt);
        }
    }
}

/// The feature tags of the first Contact of `message`
fn feature_tags(message: &SipMessage) -> String {
    message
        .headers()
        .and_then(|headers| HeaderSearch::new(headers, b"Contact", true).next())
        .map(|contact| {
            contact
                .get_value()
                .as_header_field()
                .get_parameter_iterator()
                .map(|parameter| match parameter.value {
                    Some(value) => format!(
                        "{}={}",
                        String::from_utf8_lossy(parameter.name),
                        String::from_utf8_lossy(value)
                    ),
                    None => String::from_utf8_lossy(parameter.name).into_owned(),
                })
                .collect::<Vec<String>>()
                .join(";")
        })
        .unwrap_or_default()
}

/// An OPTIONS sent, whose answer is told once
struct OptionsQuery {
    callback: Mutex<Option<Box<dyn FnOnce(Capabilities) + Send>>>,
}

impl OptionsQuery {
    fn tell(&self, capabilities: Capabilities) {
        if let Some(callback) = self.callback.lock().unwrap().take() {
            callback(capabilities);
        }
    }
}

impl ClientTransactionCallbacks for OptionsQuery {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        if let SipMessage::Response(line, _, _) = &message {
            let status_code = line.status_code;
            platform_log(LOG_TAG, format!("OPTIONS answered with {}", status_code));
            let feature_tags = if status_code == 200 {
                feature_tags(&message)
            } else {
                String::new()
            };
            self.tell(Capabilities {
                status_code,
                feature_tags,
            });
        }
    }

    fn on_transport_error(&self) {
        self.tell(Capabilities {
            status_code: 0,
            feature_tags: String::new(),
        });
    }
}

pub struct CapabilityServiceWrapper {
    pub service: Arc<CapabilityService>,
}

impl TransactionHandler for CapabilityServiceWrapper {
    fn handle_transaction(
        &self,
        transaction: &Arc<ServerTransaction>,
        _ongoing_dialogs: &Arc<Mutex<Vec<Arc<SipDialog>>>>,
        channels: &mut Option<(
            mpsc::Sender<ServerTransactionEvent>,
            mpsc::Receiver<ServerTransactionEvent>,
        )>,
        rt: &Arc<Runtime>,
    ) -> bool {
        let SipMessage::Request(line, Some(headers), _) = transaction.message() else {
            return false;
        };
        if line.method != OPTIONS || header::search(headers, b"Call-ID", true).is_none() {
            return false;
        }
        if let Some((tx, _)) = channels.take() {
            self.service.answer(transaction, tx, rt);
        }
        true
    }
}
