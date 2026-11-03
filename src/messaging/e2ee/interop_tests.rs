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

//! Two devices of the client, Alice's and Bob's, in conversations with each
//! other: what one makes, the other takes, through a Conversation Focus and
//! a Home KDS of the tests, as RCC.16 has them pass it on
//!
//! Each device is as the client sets it up: an `E2eeDevice` enrolled with
//! its certificate, and the `DeviceGroups` the session service is given,
//! which asks the other for its capabilities as an OPTIONS would. The Focus
//! does what the tests need of one: it forwards what a member sends to the
//! others as RCC.16 gives it (sections 6.2.4, 7.9.3, 8.2.1), and tells the
//! sender it accepted it; it doesn't validate it.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose, Engine as _};
use futures::executor::block_on;
use rust_rcs_core::cpim::CPIMMessage;
use rust_rcs_core::imdn::notification::{Imdn, Notification, Status};
use rust_rcs_core::io::Serializable;
use rust_rcs_core::mls::rcs::proto::{
    self, client_mls_rcs_message, server_mls_rcs_message, AcceptedMlsRcsMessage,
    ClientMlsRcsMessage, CommitBundle, EpochIdentifier, MlsGroupInfo, ServerCommitBundle,
    ServerMlsRcsMessage, WelcomeCommitBundle,
};
use rust_rcs_core::mls::rcs::same_tel_uri;
use rust_rcs_core::mls::rcs::INFO_PACKAGE_MLS_GROUP_INFO_PULL;
use rust_rcs_core::mls::Ciphersuite;

use crate::capability::{Capabilities, CapabilityQuery, FEATURE_TAGS};
use crate::messaging::cpm::encryption::{
    EncryptedMetadata, EndReason, FtdAnswer, GroupEncryption, GroupInfoPull, GroupMetadata,
    MetadataChange, Sealed, Taken, UploadedIcon, Verified,
};
use crate::messaging::cpm::make_cpim_imdn_body;

use rust_rcs_core::internet::body::multipart_body::MultipartBody;
use rust_rcs_core::internet::{header, Body};
use rust_rcs_core::sip::SipMessage;
use tokio::runtime::Runtime;

use crate::messaging::cpm::session_tests::{
    ack, answer, answer_from, body_data, header_value, invite as invite_from, next_group_event,
    next_requests, sdp_attribute, start_as, status_code, Client, MsrpConnection, MsrpFrame,
    MsrpPeer, Peer, TRANSPORT_ADDRESS,
};
use crate::messaging::ffi::RecipientType;

use super::chat::contact_tel_uri;
use super::device::{E2eeDevice, Enrolled};
use super::device_tests::provision;
use super::group::DeviceGroups;
use super::group_tests::{bundle_of, cpim_message, forwarded_of, metadata_parts, xml_value};
use super::kds::{Enrolment, Fetched, KdsFuture, KeyDistribution, Recipient};
use super::kds_tests::certificates::*;
use super::kds_tests::{bytes, signer, validator, ALICE_TEL, BOB_TEL, HOME_KDS, TODAY};

const ALICE_IMPU: &str = "sip:+491701234567@ims.example.com";
const BOB_IMPU: &str = "sip:+491707654321@ims.example.com";
const CONVERSATION: &str = "7b2c4e1a-9d3f-4a6b-8c5e-1f2a3b4c5d6e";
const GROUP_URI: &str = "sip:conf7@conf.example.com";
const TOKEN: &str = "focus-token-1";
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The KeyPackages the Participants uploaded, by tel URI, handed out one per
/// Client and fetch, each once, as a Home KDS does (RCC.16 sections 5.1,
/// 5.3)
#[derive(Default)]
struct Directory(Mutex<HashMap<String, VecDeque<Vec<u8>>>>);

/// The Home KDS as the device of the Participant `tel_uri` reaches it,
/// issuing it `chain` (section 4.2)
struct HomeKds {
    directory: Arc<Directory>,
    tel_uri: &'static str,
    chain: Vec<Vec<u8>>,
}

impl KeyDistribution for HomeKds {
    fn enrol(&self, enrolment: Enrolment) -> KdsFuture<Vec<Vec<u8>>> {
        assert_eq!(enrolment.tel_uri, self.tel_uri);
        let chain = self.chain.clone();
        Box::pin(async move { Ok(chain) })
    }

    fn upload(&self, key_packages: Vec<Vec<u8>>) -> KdsFuture<()> {
        self.directory
            .0
            .lock()
            .unwrap()
            .entry(String::from(self.tel_uri))
            .or_default()
            .extend(key_packages);
        Box::pin(async { Ok(()) })
    }

    fn fetch(
        &self,
        _ciphersuites: Vec<Ciphersuite>,
        recipients: Vec<Recipient>,
    ) -> KdsFuture<Vec<(String, Fetched)>> {
        let mut uploaded = self.directory.0.lock().unwrap();
        let fetched = recipients
            .into_iter()
            .map(|recipient| {
                let key_package = uploaded
                    .iter_mut()
                    .find(|(tel_uri, _)| same_tel_uri(tel_uri, &recipient.tel_uri))
                    .and_then(|(_, key_packages)| key_packages.pop_front());
                let fetched = match key_package {
                    Some(key_package) => Fetched::KeyPackages(vec![key_package]),
                    None => Fetched::NotFound,
                };
                (recipient.tel_uri, fetched)
            })
            .collect();
        Box::pin(async move { Ok(fetched) })
    }
}

/// The devices answering OPTIONS, by the tel URI of their user
type Network = Arc<Mutex<Vec<(String, Weak<E2eeDevice>)>>>;

/// What `contact` answers an OPTIONS with: the feature tags of the client,
/// with the E2EE capability of its device while it tells it (RCC.16 section
/// 5.2); 404 if it is none of `network`
fn options(network: &Network) -> CapabilityQuery {
    let network = Arc::clone(network);
    Arc::new(move |contact: String| {
        let device = contact_tel_uri(&contact).and_then(|tel_uri| {
            network
                .lock()
                .unwrap()
                .iter()
                .find(|(of, _)| same_tel_uri(of, &tel_uri))
                .and_then(|(_, device)| device.upgrade())
        });
        let answer = match device {
            Some(device) => Capabilities {
                status_code: 200,
                feature_tags: match device.mls_feature_tags() {
                    Some(mls) => format!("{};{}", FEATURE_TAGS, mls),
                    None => String::from(FEATURE_TAGS),
                },
            },
            None => Capabilities {
                status_code: 404,
                feature_tags: String::new(),
            },
        };
        Box::pin(async move { answer })
    })
}

/// The time both devices tell, which the tests move on
#[derive(Clone)]
struct Clock(Arc<Mutex<SystemTime>>);

impl Clock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

/// The device of a Participant, with the groups of its session service
struct Party {
    device: Arc<E2eeDevice>,
    groups: Arc<DeviceGroups>,
    impu: &'static str,
}

/// Alice and Bob, enrolled with the Home KDS of both, telling the time of
/// the clock given
fn alice_and_bob() -> (Party, Party, Clock) {
    let network: Network = Arc::default();
    let directory: Arc<Directory> = Arc::default();
    let clock = Clock(Arc::new(Mutex::new(SystemTime::now())));
    let party = |impu, tel_uri, certificate, key, public_key| {
        let kds = HomeKds {
            directory: Arc::clone(&directory),
            tel_uri,
            chain: vec![bytes(certificate), bytes(CA)],
        };
        let clock = clock.clone();
        let device = E2eeDevice::new(
            validator(TODAY),
            HOME_KDS,
            Arc::new(kds),
            Box::new(|_| true),
            None,
        )
        .unwrap()
        .with_signer(move || Some(signer(key, public_key)))
        .with_clock(move || clock.now());
        provision(&device, &[impu], None);
        assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now), "{}", impu);
        let device = Arc::new(device);
        network
            .lock()
            .unwrap()
            .push((String::from(tel_uri), Arc::downgrade(&device)));
        let groups = Arc::new(DeviceGroups::new(&device, options(&network)));
        Party {
            device,
            groups,
            impu,
        }
    };
    let alice = party(ALICE_IMPU, ALICE_TEL, ALICE, ALICE_KEY, ALICE_PUBLIC_KEY);
    let bob = party(BOB_IMPU, BOB_TEL, BOB, BOB_KEY, BOB_PUBLIC_KEY);
    (alice, bob, clock)
}

/// The epoch `party` is in, in the MLS group `group_id`, which the Focus
/// tells of when it accepts what was sent in it (RCC.16 section 6.2.4)
fn epoch_of(party: &Party, group_id: &str) -> EpochIdentifier {
    party
        .device
        .store()
        .peek_conversation(group_id.as_bytes(), |conversation, _| {
            conversation.epoch_identifier()
        })
        .unwrap()
}

/// What the Focus sends the sender of what was sent in the epoch `previous`
/// once it accepts it (RCC.16 section 6.2.4)
fn accepted(previous: EpochIdentifier) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::AcceptedMlsRcsMessage(
            AcceptedMlsRcsMessage {
                message_id: String::from("accepted"),
                previous_epoch_identifier: Some(previous),
            },
        )),
    })
}

/// What the Focus sends those the initial Commit `bundle` adds: the Commit,
/// the Welcome and the ratchet tree (RCC.16 sections 7.9.3, 8.2.1)
fn welcomed(bundle: &WelcomeCommitBundle) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: bundle.commit_list.clone(),
                welcome: bundle.welcome.clone(),
                ratchet_tree: bundle.ratchet_tree.clone(),
                ..ServerCommitBundle::default()
            },
        )),
    })
}

/// A message `from` sends `to`, as the client sends one, asking to be told
/// of its delivery and display
fn message(from: &str, to: &str, message_id: &str, text: &str) -> Vec<u8> {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: {}\r\n\
imdn.Disposition-Notification: positive-delivery, display\r\n\
NS: cpm <http://www.openmobilealliance.org/cpm/>\r\n\
cpm.Payload-Type: text/plain\r\n\
\r\n\
Content-Type: text/plain\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        from,
        to,
        message_id,
        text.len(),
        text
    )
    .into_bytes()
}

/// The body of the CPIM message `cpim`, decoded if Base64
fn body_of(cpim: &CPIMMessage) -> Vec<u8> {
    let (_, content, base64) = cpim.get_message_body().unwrap();
    match base64 {
        true => general_purpose::STANDARD.decode(content).unwrap(),
        false => content.to_vec(),
    }
}

/// What `to` takes of `cpim`, which `from` sends encrypted in the MLS group
/// `group_id`, as the Focus forwards it as it is (RCC.16 sections 7.5.6,
/// 9.1.1)
fn passed(from: &Party, to: &Party, group_id: &str, cpim: &[u8]) -> Vec<u8> {
    let outer = match block_on(from.groups.encrypt(group_id, cpim)) {
        Sealed::Encrypted(outer) => outer,
        other => panic!("not encrypted: {:?}", other),
    };
    let message = cpim_message(&outer);
    let (content_type, _, _) = message.get_message_body().unwrap();
    assert_eq!(content_type, Some(&b"message/mls"[..]));
    to.groups
        .decrypt(group_id, &message.get_info().unwrap(), &body_of(&message))
        .expect("decrypted")
}

/// What `from` says to `to` in the MLS group `group_id`, as `to` takes it:
/// from whom, the Message-ID and the text
fn said(from: &Party, to: &Party, group_id: &str, to_uri: &str, message_id: &str, text: &str) {
    let taken = passed(
        from,
        to,
        group_id,
        &message(from.impu, to_uri, message_id, text),
    );
    let taken = cpim_message(&taken);
    let info = taken.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", from.impu).as_bytes());
    assert_eq!(info.imdn_message_id, message_id.as_bytes());
    assert_eq!(body_of(&taken), text.as_bytes());
}

/// Whether `to` takes as signed by `from` the notification of `status` of
/// the message `message_id` that `from` signs in the MLS group `group_id`,
/// as the session sends it (RCC.16 sections 7.6, 9.1.3, 9.1.4); and that
/// one changed on the way, as forged
fn notified(from: &Party, to: &Party, group_id: &str, message_id: &str, status: Status) {
    let notification = match status {
        Status::Displayed => Notification::Display,
        _ => Notification::Delivery,
    };
    let xml = Imdn {
        message_id: String::from(message_id),
        datetime: String::from("2026-10-25T12:00:01.000+00:00"),
        recipient_uri: None,
        original_recipient_uri: None,
        notification,
        status,
    }
    .to_xml()
    .unwrap();
    let body = make_cpim_imdn_body(&xml, to.impu, None, from.impu);
    let mut cpim = Vec::with_capacity(body.estimated_size());
    body.reader().unwrap().read_to_end(&mut cpim).unwrap();

    let signed = block_on(from.groups.sign(group_id, &cpim)).expect("signed");
    let message = cpim_message(&signed);
    let info = message.get_info().unwrap();
    let content = body_of(&message);
    assert_eq!(content, xml.as_bytes());
    assert_eq!(
        to.groups.verify(group_id, &info, &content),
        Verified::Signed
    );

    let changed = String::from_utf8(content)
        .unwrap()
        .replace(message_id, "another-message");
    assert_eq!(
        to.groups.verify(group_id, &info, changed.as_bytes()),
        Verified::Forged
    );
}

/// Alice makes the group chat of the two, which Bob joins with what the
/// Focus sends him of it (RCC.16 sections 7.9.2, 8.1, 8.2.1)
fn group_of_the_two(alice: &Party, bob: &Party) {
    let cpim = block_on(alice.groups.prepare(
        String::from(CONVERSATION),
        String::from(alice.impu),
        String::from(GROUP_URI),
        vec![String::from(bob.impu)],
    ))
    .expect("an encrypted group");
    let bundle = bundle_of(&cpim);
    let previous = epoch_of(alice, CONVERSATION);
    assert!(bob.groups.join(CONVERSATION, &welcomed(&bundle)));
    assert_eq!(
        alice
            .groups
            .on_server_message(CONVERSATION, &accepted(previous)),
        Taken::default()
    );
}

#[test]
fn a_group_one_device_makes_the_other_joins_and_both_talk_in() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // both in the same epoch of the same Era (RCC.16 section 6.1.1)
    let epoch = epoch_of(&alice, CONVERSATION);
    assert_eq!((epoch.era_id, epoch.epoch_id), (0, 1));
    assert_eq!(epoch_of(&bob, CONVERSATION), epoch);

    // each taking what the other says (section 9.1.1)
    said(
        &alice,
        &bob,
        CONVERSATION,
        GROUP_URI,
        "alice-1",
        "hello Bob",
    );
    said(
        &bob,
        &alice,
        CONVERSATION,
        GROUP_URI,
        "bob-1",
        "hello Alice",
    );
    said(
        &alice,
        &bob,
        CONVERSATION,
        GROUP_URI,
        "alice-2",
        "how are you?",
    );

    // and the notifications the other signs (sections 9.1.3, 9.1.4)
    notified(&bob, &alice, CONVERSATION, "alice-1", Status::Delivered);
    notified(&bob, &alice, CONVERSATION, "alice-1", Status::Displayed);
    notified(&alice, &bob, CONVERSATION, "bob-1", Status::Delivered);

    // shown the same identity verification code (section 5.5)
    let code = alice
        .device
        .identity_verification_code(bob.impu, Some(CONVERSATION))
        .expect("Alice's code");
    assert_eq!(code.len(), 80);
    assert_eq!(
        bob.device
            .identity_verification_code(alice.impu, Some(CONVERSATION)),
        Ok(code)
    );
}

#[test]
fn a_file_one_device_sends_in_a_group_the_other_opens() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // sealed with a key of its own, uploaded, its key carried in the
    // message sending it (RCC.16 sections 7.8, 9.1.2.1)
    let url = "https://ftcs.example.com/f/7";
    let file = alice
        .groups
        .seal_file(b"the picture", "picture.jpg", "image/jpeg")
        .unwrap();
    let xml = super::file::upload_xml(url);
    assert!(alice
        .groups
        .uploaded(CONVERSATION, xml.as_bytes(), &file.metadata, None));
    let cpim = format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: alice-ft-1\r\n\
imdn.Disposition-Notification: positive-delivery, display\r\n\
\r\n\
Content-Type: application/vnd.gsma.rcs-ft-http+xml\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        alice.impu,
        GROUP_URI,
        xml.len(),
        xml
    );
    let outer = match block_on(alice.groups.encrypt(CONVERSATION, cpim.as_bytes())) {
        Sealed::Encrypted(outer) => outer,
        other => panic!("not encrypted: {:?}", other),
    };

    // Bob given the XML of the file, as it was named, and opening it once
    // downloaded (section 9.1.2.2)
    let message = cpim_message(&outer);
    let (content_type, xml, _) = message.get_message_body().unwrap();
    assert_eq!(
        content_type,
        Some(&b"application/vnd.gsma.rcs-ft-http+xml"[..])
    );
    let opened = bob
        .groups
        .decrypt_file_transfer(CONVERSATION, &message.get_info().unwrap(), xml)
        .expect("the file transfer message decrypted");
    let opened = String::from_utf8_lossy(&body_of(&cpim_message(&opened))).into_owned();
    assert!(
        opened.contains("<file-name>picture.jpg</file-name>"),
        "{}",
        opened
    );
    assert!(!opened.contains("mls-file"), "{}", opened);
    assert!(bob.groups.opens_file(url));
    assert_eq!(
        bob.groups.open_file(url, &file.ciphertext).as_deref(),
        Some(&b"the picture"[..])
    );
}

#[test]
fn the_subject_one_device_sets_in_a_group_the_other_opens() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // the Commit bringing its key, which the Focus forwards, and the request
    // it takes the encrypted subject from (RCC.16 sections 7.13.1, 9.7.1.5)
    let cpim = block_on(alice.groups.change_metadata(
        String::from(CONVERSATION),
        String::from(alice.impu),
        String::from(GROUP_URI),
        MetadataChange::Subject(Some(String::from("Team <7>"))),
    ))
    .expect("the subject set");
    let (_, bundle, request) = metadata_parts(&cpim);
    let subject = xml_value(&request, "encrypted-subject").expect("the encrypted subject");
    let previous = epoch_of(&alice, CONVERSATION);
    bob.groups
        .on_server_message(CONVERSATION, &forwarded_of(&bundle));
    alice
        .groups
        .on_server_message(CONVERSATION, &accepted(previous));
    assert_eq!(epoch_of(&bob, CONVERSATION), epoch_of(&alice, CONVERSATION));

    // which both open, as the Focus tells of it (section 7.13.2)
    let told = || {
        Some(EncryptedMetadata {
            value: subject.clone(),
            participant: Some(String::from(alice.impu)),
        })
    };
    let opened = GroupMetadata::Subject {
        subject: Some(String::from("Team <7>")),
        participant: Some(String::from(alice.impu)),
    };
    assert_eq!(
        bob.groups.take_metadata(CONVERSATION, told(), None),
        [opened.clone()]
    );
    assert_eq!(
        alice.groups.take_metadata(CONVERSATION, told(), None),
        [opened]
    );
}

#[test]
fn an_encrypted_chat_one_device_starts_the_other_joins_and_both_talk_in() {
    let (alice, bob, clock) = alice_and_bob();

    // a new MLS group of a random GUID, joined by Bob with what the Focus
    // fans out of the INVITE (RCC.16 sections 6.1.1, 8.1.1, 8.2.1)
    let (group_id, cpim) = block_on(
        alice
            .groups
            .prepare_chat(String::from(bob.impu), String::from(alice.impu)),
    )
    .expect("an encrypted chat");
    let bundle = bundle_of(&cpim);
    let previous = epoch_of(&alice, &group_id);
    assert_eq!(
        bob.groups
            .join_chat(alice.impu, &welcomed(&bundle), Some(String::from(TOKEN))),
        Some(group_id.clone())
    );
    alice
        .groups
        .keep_chat(bob.impu, &group_id, Some(String::from(TOKEN)));
    alice
        .groups
        .on_server_message(&group_id, &accepted(previous));
    assert_eq!(
        alice.groups.chat_group(bob.impu),
        Some((group_id.clone(), Some(String::from(TOKEN))))
    );
    assert_eq!(
        bob.groups.chat_group(alice.impu),
        Some((group_id.clone(), Some(String::from(TOKEN))))
    );
    assert_eq!(epoch_of(&bob, &group_id), epoch_of(&alice, &group_id));

    // each taking what the other says, and the notifications the other signs
    // (sections 9.1.1, 9.1.3, 9.1.4)
    said(&alice, &bob, &group_id, bob.impu, "alice-1", "hi Bob");
    said(&bob, &alice, &group_id, alice.impu, "bob-1", "hi Alice");
    notified(&bob, &alice, &group_id, "alice-1", Status::Displayed);
    notified(&alice, &bob, &group_id, "bob-1", Status::Delivered);

    // shown the same identity verification code, from the chat alone
    // (section 5.5)
    let code = alice
        .device
        .identity_verification_code(bob.impu, None)
        .expect("Alice's code");
    assert_eq!(
        bob.device.identity_verification_code(alice.impu, None),
        Ok(code)
    );

    // 30 days unused, it starts again in its next Era, which Bob joins in
    // place of the one he has (sections 6.1.2, 8.3)
    assert!(!alice.groups.chat_era_due(bob.impu));
    clock.advance(31 * DAY);
    assert!(alice.groups.chat_era_due(bob.impu));
    let (era_group, cpim) = block_on(
        alice
            .groups
            .prepare_chat_era(String::from(bob.impu), String::from(alice.impu)),
    )
    .expect("the next Era");
    assert_eq!(era_group, group_id);
    let bundle = bundle_of(&cpim);
    let previous = epoch_of(&alice, &group_id);
    assert_eq!(
        bob.groups.join_chat(
            alice.impu,
            &welcomed(&bundle),
            Some(String::from("focus-token-2"))
        ),
        Some(group_id.clone())
    );
    alice
        .groups
        .keep_chat(bob.impu, &group_id, Some(String::from("focus-token-2")));
    alice
        .groups
        .on_server_message(&group_id, &accepted(previous));
    let epoch = epoch_of(&alice, &group_id);
    assert_eq!((epoch.era_id, epoch.epoch_id), (1, 1));
    assert_eq!(epoch_of(&bob, &group_id), epoch);
    assert!(!alice.groups.chat_era_due(bob.impu));

    // in which both talk on
    said(&bob, &alice, &group_id, alice.impu, "bob-2", "back again");
    said(&alice, &bob, &group_id, bob.impu, "alice-2", "welcome back");
    notified(&bob, &alice, &group_id, "alice-2", Status::Delivered);
}

#[test]
fn a_file_one_device_sends_in_a_new_chat_the_other_opens() {
    let (alice, bob, _) = alice_and_bob();

    // sealed before any chat with Bob, as he advertises E2EE, and uploaded
    // (RCC.16 sections 8.1.1, 9.1.2.1)
    assert!(block_on(alice.groups.seals_chat_files(bob.impu)));
    let url = "https://ftcs.example.com/f/8";
    let file = alice
        .groups
        .seal_file(b"the picture", "picture.jpg", "image/jpeg")
        .unwrap();
    let xml = super::file::upload_xml(url);
    assert!(alice
        .groups
        .uploaded_for_chat(bob.impu, xml.as_bytes(), &file.metadata, None));

    // the chat its message starts, which Bob joins
    let (group_id, cpim) = block_on(
        alice
            .groups
            .prepare_chat(String::from(bob.impu), String::from(alice.impu)),
    )
    .expect("an encrypted chat");
    let previous = epoch_of(&alice, &group_id);
    assert_eq!(
        bob.groups
            .join_chat(alice.impu, &welcomed(&bundle_of(&cpim)), None),
        Some(group_id.clone())
    );
    alice.groups.keep_chat(bob.impu, &group_id, None);
    alice
        .groups
        .on_server_message(&group_id, &accepted(previous));

    // the message carrying its key (section 7.8.2)
    let cpim = format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: alice-ft-2\r\n\
imdn.Disposition-Notification: positive-delivery, display\r\n\
\r\n\
Content-Type: application/vnd.gsma.rcs-ft-http+xml\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        alice.impu,
        bob.impu,
        xml.len(),
        xml
    );
    let outer = match block_on(alice.groups.encrypt(&group_id, cpim.as_bytes())) {
        Sealed::Encrypted(outer) => outer,
        other => panic!("not encrypted: {:?}", other),
    };

    // Bob given the XML of the file, as it was named, and opening it once
    // downloaded (section 9.1.2.2)
    let message = cpim_message(&outer);
    let (_, xml, _) = message.get_message_body().unwrap();
    let opened = bob
        .groups
        .decrypt_file_transfer(&group_id, &message.get_info().unwrap(), xml)
        .expect("the file transfer message decrypted");
    let opened = String::from_utf8_lossy(&body_of(&cpim_message(&opened))).into_owned();
    assert!(
        opened.contains("<file-name>picture.jpg</file-name>"),
        "{}",
        opened
    );
    assert!(bob.groups.opens_file(url));
    assert_eq!(
        bob.groups.open_file(url, &file.ciphertext).as_deref(),
        Some(&b"the picture"[..])
    );
}

/// The `message/mls-rcs-client` the control message `cpim` carries, alone
/// or first of its parts (RCC.16 sections 7.9.1, 7.13.1)
fn client_message(cpim: &[u8]) -> ClientMlsRcsMessage {
    let message = cpim_message(cpim);
    let (content_type, _, _) = message.get_message_body().unwrap();
    let multipart =
        content_type.is_some_and(|content_type| content_type.starts_with(b"multipart/"));
    if multipart {
        let (_, bundle, _) = metadata_parts(cpim);
        return ClientMlsRcsMessage {
            payload: Some(client_mls_rcs_message::Payload::CommitBundle(bundle)),
        };
    }
    proto::decode(&body_of(&message)).expect("a message/mls-rcs-client")
}

/// The CommitBundle the control message `cpim` carries
fn commit_bundle(cpim: &[u8]) -> CommitBundle {
    match client_message(cpim).payload {
        Some(client_mls_rcs_message::Payload::CommitBundle(bundle)) => bundle,
        other => panic!("not a CommitBundle: {:?}", other.is_some()),
    }
}

/// What `from` makes with `commit`, a Commit of the MLS group `group_id`
/// in a control message, as the Focus takes it: forwarded to `to`, `from`
/// told it accepted it (RCC.16 sections 6.2.4, 7.9.3); what `to`, then
/// `from`, take of it, and the GroupInfo of the epoch it leads to, with the
/// ratchet tree, as the Focus keeps it to give (section 6.3.1)
fn committed(
    from: &Party,
    to: Option<&Party>,
    group_id: &str,
    commit: impl FnOnce(&Party) -> Option<Vec<u8>>,
) -> (Taken, Taken, MlsGroupInfo) {
    let cpim = commit(from).expect("a Commit");
    let bundle = commit_bundle(&cpim);
    let previous = epoch_of(from, group_id);
    let taken = to.map_or(Taken::default(), |to| {
        to.groups
            .on_server_message(group_id, &forwarded_of(&bundle))
    });
    let own = from.groups.on_server_message(group_id, &accepted(previous));
    let group_info = MlsGroupInfo {
        group_info: bundle.group_info,
        ratchet_tree: ratchet_tree_of(from, group_id),
        pending_proposals: Vec::new(),
    };
    (taken, own, group_info)
}

/// The ratchet tree of the MLS group `group_id` as `party` has it, which the
/// Focus keeps of the latest epoch to give with Welcomes and GroupInfos
/// (RCC.16 sections 6.3.1, 8.2.1)
fn ratchet_tree_of(party: &Party, group_id: &str) -> Vec<u8> {
    party
        .device
        .store()
        .peek_conversation(group_id.as_bytes(), |conversation, _| {
            conversation.ratchet_tree()
        })
        .unwrap()
        .unwrap()
}

/// The Focus answering INFO requests with `group_info`, the GroupInfo it
/// keeps, to an MLS-Group-Info-Pull; the enhanced one not supported
/// (RCC.16 sections 6.3.1, 6.3.2)
fn giving(group_info: MlsGroupInfo) -> GroupInfoPull {
    Arc::new(move |package: &'static [u8], _| {
        let answer = match package == INFO_PACKAGE_MLS_GROUP_INFO_PULL {
            true => Some((
                200,
                proto::encode(&ServerMlsRcsMessage {
                    payload: Some(server_mls_rcs_message::Payload::MlsGroupInfo(
                        group_info.clone(),
                    )),
                }),
            )),
            false => Some((501, Vec::new())),
        };
        Box::pin(async move { answer })
    })
}

/// `party` setting the subject of the group chat, a Commit (RCC.16 section
/// 9.7.1.5)
fn subject_set(party: &Party) -> Option<Vec<u8>> {
    block_on(party.groups.change_metadata(
        String::from(CONVERSATION),
        String::from(party.impu),
        String::from(GROUP_URI),
        MetadataChange::Subject(Some(String::from("Team"))),
    ))
}

/// `party` sending `count` messages in the group chat `conversation_id`,
/// which the others need not take
fn chatted(party: &Party, conversation_id: &str, count: usize) {
    for n in 0..count {
        let cpim = message(party.impu, GROUP_URI, &format!("chat-{}", n), "chat");
        assert!(matches!(
            block_on(party.groups.encrypt(conversation_id, &cpim)),
            Sealed::Encrypted(_)
        ));
    }
}

/// What `to` decrypts of `cpim`, which `from` sends encrypted in the MLS
/// group `group_id`; None if it cannot
fn decrypted_by(from: &Party, to: &Party, group_id: &str, cpim: &[u8]) -> Option<Vec<u8>> {
    let outer = match block_on(from.groups.encrypt(group_id, cpim)) {
        Sealed::Encrypted(outer) => outer,
        other => panic!("not encrypted: {:?}", other),
    };
    let message = cpim_message(&outer);
    to.groups
        .decrypt(group_id, &message.get_info().unwrap(), &body_of(&message))
}

#[test]
fn a_device_leaving_is_committed_out_by_the_other_and_can_be_added_again() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // Bob's self_remove Proposal, which the Focus forwards (RCC.16 sections
    // 7.9.4, 9.4)
    let cpim = block_on(bob.groups.prepare_leave(
        String::from(CONVERSATION),
        String::from(bob.impu),
        String::from(GROUP_URI),
    ))
    .expect("the leave");
    let proposals = match client_message(&cpim).payload {
        Some(client_mls_rcs_message::Payload::ProposalList(proposals)) => proposals,
        _ => panic!("not a ProposalList"),
    };
    let forwarded = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(proposals)),
    });
    assert!(
        alice
            .groups
            .on_server_message(CONVERSATION, &forwarded)
            .proposals
    );

    // committed by Alice, Bob's group let go of once he left (section 9.5.1)
    committed(&alice, None, CONVERSATION, |alice| {
        block_on(alice.groups.commit_leaves(
            String::from(CONVERSATION),
            String::from(alice.impu),
            String::from(GROUP_URI),
        ))
    });
    bob.groups.abandon(CONVERSATION);
    let members = alice
        .device
        .store()
        .peek_conversation(CONVERSATION.as_bytes(), |conversation, _| {
            conversation.members().len()
        });
    assert_eq!(members, Ok(1));
    assert!(!bob.groups.encrypts(CONVERSATION));

    // added again, with a KeyPackage of his the Home KDS has (sections 5.3,
    // 9.2)
    let cpim = block_on(alice.groups.prepare_add(
        String::from(CONVERSATION),
        String::from(alice.impu),
        String::from(GROUP_URI),
        vec![String::from(bob.impu)],
    ))
    .expect("Bob added");
    let mut bundle = bundle_of(&cpim);
    let previous = epoch_of(&alice, CONVERSATION);
    alice
        .groups
        .on_server_message(CONVERSATION, &accepted(previous));
    // the ratchet tree from the Focus, if the Commit doesn't bring it
    if bundle.ratchet_tree.is_empty() {
        bundle.ratchet_tree = ratchet_tree_of(&alice, CONVERSATION);
    }
    assert!(bob.groups.join(CONVERSATION, &welcomed(&bundle)));
    assert_eq!(epoch_of(&bob, CONVERSATION), epoch_of(&alice, CONVERSATION));
    said(
        &alice,
        &bob,
        CONVERSATION,
        GROUP_URI,
        "alice-3",
        "welcome back",
    );
    said(&bob, &alice, CONVERSATION, GROUP_URI, "bob-3", "thanks");
}

#[test]
fn a_device_removed_takes_nothing_more_while_the_other_talks_on() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // the Commit removing Bob, which the Focus forwards to him too (RCC.16
    // section 9.3)
    let _ = committed(&alice, Some(&bob), CONVERSATION, |alice| {
        block_on(alice.groups.prepare_remove(
            String::from(CONVERSATION),
            String::from(alice.impu),
            String::from(GROUP_URI),
            String::from(bob.impu),
        ))
    });
    let members = alice
        .device
        .store()
        .peek_conversation(CONVERSATION.as_bytes(), |conversation, _| {
            conversation.members().len()
        });
    assert_eq!(members, Ok(1));

    // what Alice says next not his to decrypt
    assert_eq!(
        decrypted_by(
            &alice,
            &bob,
            CONVERSATION,
            &message(alice.impu, GROUP_URI, "alice-2", "Bob is gone")
        ),
        None
    );
}

#[test]
fn the_keys_one_device_updates_the_other_follows_and_both_talk_on() {
    let (alice, bob, clock) = alice_and_bob();
    group_of_the_two(&alice, &bob);
    let before = epoch_of(&alice, CONVERSATION);
    // due once 50 messages are sent, a week on at the earliest
    clock.advance(8 * DAY);

    // each in turn, by a Commit the Focus forwards (RCC.16 section 9.5.2)
    for (from, to) in [(&alice, &bob), (&bob, &alice)] {
        chatted(from, CONVERSATION, 50);
        committed(from, Some(to), CONVERSATION, |from| {
            block_on(from.groups.update_keys(
                String::from(CONVERSATION),
                String::from(from.impu),
                String::from(GROUP_URI),
            ))
        });
        assert_eq!(epoch_of(to, CONVERSATION), epoch_of(from, CONVERSATION));
    }
    assert_eq!(epoch_of(&alice, CONVERSATION).epoch_id, before.epoch_id + 2);
    said(&alice, &bob, CONVERSATION, GROUP_URI, "alice-2", "new keys");
    said(&bob, &alice, CONVERSATION, GROUP_URI, "bob-2", "mine too");
}

#[test]
fn a_device_that_missed_a_commit_heals_and_has_what_it_could_not_decrypt_re_sent() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // Alice's Commit setting the subject, which Bob misses, then a message
    // of hers he can't decrypt (RCC.16 section 10.1)
    let (_, _, group_info) = committed(&alice, None, CONVERSATION, subject_set);
    let missed = message(alice.impu, GROUP_URI, "alice-2", "did you get this?");
    assert_eq!(decrypted_by(&alice, &bob, CONVERSATION, &missed), None);
    assert!(bob.groups.needs_healing(CONVERSATION));

    // healed with an External Commit from the GroupInfo the Focus gives,
    // which it forwards to Alice (sections 6.3.1, 10.1.1)
    let _ = committed(&bob, Some(&alice), CONVERSATION, |bob| {
        block_on(bob.groups.heal(
            String::from(CONVERSATION),
            String::from(bob.impu),
            String::from(GROUP_URI),
            giving(group_info),
        ))
    });
    assert!(!bob.groups.needs_healing(CONVERSATION));
    assert_eq!(epoch_of(&bob, CONVERSATION), epoch_of(&alice, CONVERSATION));
    said(
        &bob,
        &alice,
        CONVERSATION,
        GROUP_URI,
        "bob-2",
        "back in step",
    );

    // Alice told, by the negative delivery Bob signs, of what he could not
    // decrypt, which she re-sends to him alone (sections 10.2 to 10.4)
    let failed = bob.groups.failed_to_decrypt(CONVERSATION);
    assert_eq!(failed.len(), 1);
    let failed = &failed[0];
    let body = make_cpim_imdn_body(
        &failed.imdn,
        &failed.sender_uri,
        failed.original_message_id.as_deref(),
        bob.impu,
    );
    let mut cpim = Vec::with_capacity(body.estimated_size());
    body.reader().unwrap().read_to_end(&mut cpim).unwrap();
    let signed = block_on(bob.groups.sign(CONVERSATION, &cpim)).expect("signed");
    let signed = cpim_message(&signed);
    let resent = match alice.groups.answer_failed_to_decrypt(
        CONVERSATION,
        &signed.get_info().unwrap(),
        &body_of(&signed),
    ) {
        FtdAnswer::Resend(resent) => resent,
        _ => panic!("not re-sent"),
    };
    let resent = cpim_message(&resent);
    let taken = bob
        .groups
        .decrypt(CONVERSATION, &resent.get_info().unwrap(), &body_of(&resent))
        .expect("the Re-Sent Message decrypted");
    let taken = cpim_message(&taken);
    let info = taken.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", alice.impu).as_bytes());
    assert_eq!(info.mls_original_message_id, Some(&b"alice-2"[..]));
    assert_eq!(body_of(&taken), b"did you get this?");
}

#[test]
fn the_icon_one_device_sets_in_a_group_the_other_opens() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // sealed with a key of its own, uploaded, the Commit bringing its key
    // forwarded, its URL told by the Focus (RCC.16 sections 7.13, 9.7.1.4)
    let url = "https://ftcs.example.com/i/7";
    let sealed = alice.groups.seal_icon(b"the icon", "image/png").unwrap();
    let uploaded = UploadedIcon {
        xml: super::file::upload_xml(url).into_bytes(),
        metadata: sealed.metadata.clone(),
    };
    let cpim = block_on(alice.groups.change_metadata(
        String::from(CONVERSATION),
        String::from(alice.impu),
        String::from(GROUP_URI),
        MetadataChange::Icon(Some(uploaded)),
    ))
    .expect("the icon set");
    let (_, bundle, request) = metadata_parts(&cpim);
    assert_eq!(xml_value(&request, "encrypted-icon").as_deref(), Some(url));
    let previous = epoch_of(&alice, CONVERSATION);
    bob.groups
        .on_server_message(CONVERSATION, &forwarded_of(&bundle));
    alice
        .groups
        .on_server_message(CONVERSATION, &accepted(previous));

    // which Bob opens once downloaded
    let told = bob.groups.take_metadata(
        CONVERSATION,
        None,
        Some(EncryptedMetadata {
            value: String::from(url),
            participant: Some(String::from(alice.impu)),
        }),
    );
    assert!(
        matches!(&told[..], [GroupMetadata::Icon { url: Some(told), .. }] if told == url),
        "{:?}",
        told
    );
    assert_eq!(
        bob.groups.open_file(url, &sealed.ciphertext).as_deref(),
        Some(&b"the icon"[..])
    );
}

#[test]
fn a_group_one_device_moves_to_unencrypted_is_unencrypted_for_the_other() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // by a Commit adding end_mls (RCC.16 sections 7.11.2, 11.2)
    let (taken, own, _) = committed(&alice, Some(&bob), CONVERSATION, |alice| {
        block_on(alice.groups.end_encryption(
            String::from(CONVERSATION),
            String::from(alice.impu),
            String::from(GROUP_URI),
            EndReason::ClientFailureEncryptionNotAvailable,
        ))
    });
    assert!(taken.encryption_ended && own.encryption_ended);
    for party in [&alice, &bob] {
        assert!(party.groups.encryption_ended(CONVERSATION));
        assert_eq!(
            block_on(party.groups.encrypt(
                CONVERSATION,
                &message(party.impu, GROUP_URI, "plain-1", "in the clear")
            )),
            Sealed::Unencrypted
        );
    }
}

#[test]
fn the_next_era_of_a_group_one_device_makes_the_other_joins() {
    let (alice, bob, _) = alice_and_bob();
    group_of_the_two(&alice, &bob);
    let (_, _, group_info) = committed(&alice, Some(&bob), CONVERSATION, subject_set);

    // made after the GroupInfo the Focus gives, with Bob's Clients as the
    // Home KDS gives them, and joined by him in place of the Era he has
    // (RCC.16 sections 8.3.1, 10.1)
    alice.device.heals().want_new_era(CONVERSATION);
    assert!(alice.groups.new_era_due(CONVERSATION));
    let cpim = block_on(alice.groups.prepare_next_era(
        String::from(CONVERSATION),
        String::from(alice.impu),
        String::from(GROUP_URI),
        giving(group_info),
    ))
    .expect("the next Era");
    let bundle = bundle_of(&cpim);
    let previous = epoch_of(&alice, CONVERSATION);
    assert!(bob.groups.join(CONVERSATION, &welcomed(&bundle)));
    alice
        .groups
        .on_server_message(CONVERSATION, &accepted(previous));
    let epoch = epoch_of(&alice, CONVERSATION);
    assert_eq!((epoch.era_id, epoch.epoch_id), (1, 1));
    assert_eq!(epoch_of(&bob, CONVERSATION), epoch);
    said(
        &alice,
        &bob,
        CONVERSATION,
        GROUP_URI,
        "alice-2",
        "a new Era",
    );
    said(&bob, &alice, CONVERSATION, GROUP_URI, "bob-2", "so it is");
}

#[test]
fn a_device_whose_keys_went_stale_is_replaced_by_the_other_and_rejoins() {
    let (alice, bob, clock) = alice_and_bob();
    group_of_the_two(&alice, &bob);

    // Bob's leaf not updated for over 30 days, Alice replaces his Client
    // with a KeyPackage of his the Home KDS has, updating her keys as well
    // (RCC.16 section 9.5.4)
    clock.advance(31 * DAY);
    assert!(alice.groups.key_update_due(CONVERSATION));
    let cpim = block_on(alice.groups.update_keys(
        String::from(CONVERSATION),
        String::from(alice.impu),
        String::from(GROUP_URI),
    ))
    .expect("the KeyPackage Update");
    let mut bundle = bundle_of(&cpim);
    let previous = epoch_of(&alice, CONVERSATION);
    alice
        .groups
        .on_server_message(CONVERSATION, &accepted(previous));
    if bundle.ratchet_tree.is_empty() {
        bundle.ratchet_tree = ratchet_tree_of(&alice, CONVERSATION);
    }

    // the Commit forwarded to Bob's old Client, a member still, with the
    // Welcome along, which he joins anew with once his leaf is gone
    bob.groups
        .on_server_message(CONVERSATION, &welcomed(&bundle));
    assert!(bob.groups.encrypts(CONVERSATION));
    assert_eq!(epoch_of(&bob, CONVERSATION), epoch_of(&alice, CONVERSATION));
    said(
        &alice,
        &bob,
        CONVERSATION,
        GROUP_URI,
        "alice-2",
        "still there?",
    );
    said(&bob, &alice, CONVERSATION, GROUP_URI, "bob-2", "anew");
}

/// The parts of the multipart body of `message`, each its Content-Type and
/// content
fn parts_of(message: &SipMessage) -> Vec<(String, Vec<u8>)> {
    let content_type = header_value(message, "Content-Type");
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .expect("a multipart body")
        .trim_matches('"');
    let body = body_data(message);
    MultipartBody::construct(&body, boundary.as_bytes())
        .unwrap()
        .parts
        .iter()
        .map(|part| match part.as_ref() {
            Body::Message(part) => {
                let content_type = header::search(&part.headers, b"Content-Type", true)
                    .map(|header| String::from_utf8_lossy(header.get_value()).into_owned())
                    .unwrap_or_default();
                let mut content = Vec::new();
                part.body
                    .reader()
                    .unwrap()
                    .read_to_end(&mut content)
                    .unwrap();
                (content_type, content)
            }
            _ => panic!("a part not a message"),
        })
        .collect()
}

/// A CPIM message from the Focus carrying the `message/mls-rcs-server`
/// `server_message` (RCC.16 sections 7.9.1, 7.9.3)
fn from_the_focus(to: &str, server_message: &[u8]) -> Vec<u8> {
    let mut cpim = format!(
        "From: <{}>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:01.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: focus-1\r\n\r\nContent-Type: message/mls-rcs-server\r\n\r\n",
        FOCUS_URI, to
    )
    .into_bytes();
    cpim.extend_from_slice(server_message);
    cpim
}

const FOCUS_URI: &str = "sip:focus@conf.example.com";

/// What a session service takes, through the Focus relaying `send`, an
/// MSRP SEND of the other's session, over `connection` from `focus_path`
/// to `path`: answered, and given to the app as `received` tells
fn relayed(
    connection: &mut MsrpConnection,
    rt: &Runtime,
    focus_path: &str,
    path: &str,
    send: &MsrpFrame,
) {
    connection.send_data(
        rt,
        focus_path,
        path,
        send.header("Content-Type").unwrap_or("message/cpim"),
        &send.body,
    );
    let response = connection.next_response(rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
}

#[test]
fn an_encrypted_chat_runs_between_two_session_services_through_the_focus() {
    let (alice, bob, _) = alice_and_bob();
    let (alice_client, mut alice_sip) = start_as(true, ALICE_IMPU);
    let (bob_client, mut bob_sip) = start_as(true, BOB_IMPU);
    let (alice_rt, bob_rt) = (Arc::clone(&alice_client.rt), Arc::clone(&bob_client.rt));
    alice_client
        .sessions
        .set_group_encryption(Arc::clone(&alice.groups) as Arc<dyn GroupEncryption>);
    bob_client
        .sessions
        .set_group_encryption(Arc::clone(&bob.groups) as Arc<dyn GroupEncryption>);

    // Alice's session service starts the chat with the INVITE carrying its
    // MLS group, as the engine has it do (RCC.16 sections 8.1, 8.1.1)
    let (group_id, bundle) = block_on(
        alice
            .groups
            .prepare_chat(String::from(BOB_IMPU), String::from(ALICE_IMPU)),
    )
    .expect("an encrypted chat");
    let sent = alice_client.send_starting_chat(BOB_IMPU, "hi Bob", &group_id, &bundle, false);
    let invite = alice_sip.next_request("INVITE");
    let parts = parts_of(&invite);
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].0, "application/sdp");
    let alice_path =
        sdp_attribute(&String::from_utf8_lossy(&parts[0].1), "path").expect("Alice's a=path");
    let welcome_bundle = bundle_of(&parts[1].1);

    // the Focus answers it, then fans it out to Bob, the Welcome in a
    // message/mls-rcs-server (section 8.2.1)
    let alice_msrp = MsrpPeer::listen(&alice_rt);
    let ok = answer(&invite, "200 OK", Some(&alice_msrp.sdp("sendrecv"))).replacen(
        "Contact:",
        &format!("MLS-Opaque-Token: {}\r\nContact:", TOKEN),
        1,
    );
    alice_sip.send(&ok);
    alice_sip.next_request("ACK");
    let mut to_alice = alice_msrp.accept(&alice_rt);

    let bob_msrp = MsrpPeer::listen(&bob_rt);
    let welcome = format!(
        "From: <{}>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: welcome-1\r\n\r\nContent-Type: message/mls-rcs-server\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        ALICE_IMPU,
        BOB_IMPU,
        general_purpose::STANDARD.encode(welcomed(&welcome_bundle))
    );
    let body = format!(
        "--part-1\r\nContent-Type: application/sdp\r\n\r\n{}\r\n--part-1\r\nContent-Type: message/cpim\r\n\r\n{}\r\n--part-1--\r\n",
        bob_msrp.sdp("sendrecv"),
        welcome
    );
    bob_sip.send(&invite_from(
        "chat-to-bob",
        "<sip:+491701234567@192.0.2.1:5060;transport=tcp>;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        ALICE_IMPU,
        "cpm.session",
        &format!("MLS-Opaque-Token: {}\r\n", TOKEN),
        "multipart/mixed; boundary=part-1",
        &body,
    ));
    let bobs_ok = bob_sip.next_response();
    assert_eq!(status_code(&bobs_ok), 200);
    bob_sip.send(&ack(&bobs_ok, "chat-to-bob"));
    let bob_path = sdp_attribute(&super::super::cpm::session_tests::body(&bobs_ok), "path")
        .expect("Bob's a=path");
    let mut to_bob = bob_msrp.accept(&bob_rt);
    assert_eq!(
        bob.groups.chat_group(ALICE_IMPU).map(|(id, _)| id),
        Some(group_id.clone())
    );

    // Alice's message waits for the Focus to accept her Commit, then goes
    // encrypted, which Bob's session service gives his app decrypted
    // (sections 6.2.4, 9.1.1)
    let previous = epoch_of(&alice, &group_id);
    to_alice.send_data(
        &alice_rt,
        &alice_msrp.path,
        &alice_path,
        "message/cpim",
        &from_the_focus(ALICE_IMPU, &accepted(previous)),
    );
    let response = to_alice.next_response(&alice_rt);
    assert!(
        response.first_line.contains(" 200"),
        "{}",
        response.first_line
    );
    let send = to_alice.next_message(&alice_rt);
    to_alice.respond(&alice_rt, &send, "200 OK");
    assert_eq!(
        sent.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    relayed(&mut to_bob, &bob_rt, &bob_msrp.path, &bob_path, &send);
    let (contact, content_type, content) = bob_client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("Alice's message given to Bob's app");
    assert_eq!(
        (contact.as_str(), content_type.as_str(), content.as_str()),
        (ALICE_IMPU, "text/plain", "hi Bob")
    );

    // its delivery, signed in Bob's session, verified by Alice's (sections
    // 9.1.3, 7.6.2)
    let delivery = to_bob.next_message(&bob_rt);
    to_bob.respond(&bob_rt, &delivery, "200 OK");
    relayed(
        &mut to_alice,
        &alice_rt,
        &alice_msrp.path,
        &alice_path,
        &delivery,
    );
    // from the Focus's Contact, as the session tells of its contact
    let (_, content_type, content) = alice_client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("the delivery given to Alice's app");
    assert!(
        content_type.starts_with("message/imdn+xml"),
        "{}",
        content_type
    );
    assert!(content.contains("<delivered/>"), "{}", content);

    // and the same the other way
    let reply = bob_client.send(ALICE_IMPU, RecipientType::Contact, "hi Alice");
    let send = to_bob.next_message(&bob_rt);
    to_bob.respond(&bob_rt, &send, "200 OK");
    assert_eq!(
        reply.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
        Ok(200)
    );
    relayed(
        &mut to_alice,
        &alice_rt,
        &alice_msrp.path,
        &alice_path,
        &send,
    );
    let (_, content_type, content) = alice_client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("Bob's message given to Alice's app");
    assert_eq!(
        (content_type.as_str(), content.as_str()),
        ("text/plain", "hi Alice")
    );
    let delivery = to_alice.next_message(&alice_rt);
    to_alice.respond(&alice_rt, &delivery, "200 OK");
    relayed(&mut to_bob, &bob_rt, &bob_msrp.path, &bob_path, &delivery);
    let (_, content_type, content) = bob_client
        .received
        .recv_timeout(Duration::from_secs(5))
        .expect("the delivery given to Bob's app");
    assert!(
        content_type.starts_with("message/imdn+xml"),
        "{}",
        content_type
    );
    assert!(content.contains("<delivered/>"), "{}", content);
}

const FACTORY_URI: &str = "sip:conference-factory@conf.example.com";

/// The Contact of the Focus of the group chat at GROUP_URI (RCC.07 section
/// 3.4.4.1)
fn focus_contact() -> String {
    format!(
        "<{}>;isfocus;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
        GROUP_URI
    )
}

/// The INVITE the Focus sends `to` to the group chat of `conversation_id`,
/// offering `sdp` and carrying `server_message`, the Welcome of its MLS
/// group in a `message/mls-rcs-server` (RCC.07 section 3.4.4.1.2, RCC.16
/// section 8.2.1)
fn focus_invite(
    call_id: &str,
    to: &str,
    conversation_id: &str,
    sdp: &str,
    server_message: &[u8],
) -> String {
    let welcome = format!(
        "From: <{}>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:00.000Z\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: welcome-1\r\n\r\nContent-Type: message/mls-rcs-server\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        GROUP_URI,
        to,
        general_purpose::STANDARD.encode(server_message)
    );
    let body = format!(
        "--part-1\r\nContent-Type: application/sdp\r\n\r\n{}\r\n--part-1\r\nContent-Type: message/cpim\r\n\r\n{}\r\n--part-1--\r\n",
        sdp, welcome
    );
    let user = to
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    format!(
        "INVITE sip:{}@{};transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK{}\r\n\
From: <{}>;tag=peer1\r\n\
To: <{}>\r\n\
Call-ID: {}\r\n\
CSeq: 1 INVITE\r\n\
Contact: {}\r\n\
Accept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"\r\n\
P-Asserted-Identity: <{}>\r\n\
Conversation-ID: {}\r\n\
Contribution-ID: contribution-1\r\n\
Referred-By: <{}>\r\n\
MLS-Opaque-Token: {}\r\n\
Max-Forwards: 70\r\n\
Content-Type: multipart/mixed; boundary=part-1\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        user,
        TRANSPORT_ADDRESS,
        call_id,
        FOCUS_URI,
        to,
        call_id,
        focus_contact(),
        FOCUS_URI,
        conversation_id,
        ALICE_IMPU,
        TOKEN,
        body.len(),
        body
    )
}

/// A session service of a Participant's client in a group chat, with the
/// Focus at the other end of its SIP connection, and of its session's MSRP
/// connection, from `focus_path` to `path`
struct Member {
    party: Party,
    client: Client,
    sip: Peer,
    connection: MsrpConnection,
    focus_path: String,
    path: String,
}

impl Member {
    fn rt(&self) -> Arc<Runtime> {
        Arc::clone(&self.client.rt)
    }

    /// Sends what the Focus sends in the session: the CPIM message `cpim`,
    /// which the session takes
    fn focus_sends(&mut self, cpim: &[u8]) {
        let rt = self.rt();
        self.connection
            .send_data(&rt, &self.focus_path, &self.path, "message/cpim", cpim);
        let response = self.connection.next_response(&rt);
        assert!(
            response.first_line.contains(" 200"),
            "{}",
            response.first_line
        );
    }

    /// The next message the session sends, answered 200
    fn sent(&mut self) -> MsrpFrame {
        let rt = self.rt();
        let send = self.connection.next_message(&rt);
        self.connection.respond(&rt, &send, "200 OK");
        send
    }

    /// What the app is given next: in which conversation, of what type, and
    /// what
    fn given(&self) -> (String, String, String) {
        self.client
            .received
            .recv_timeout(Duration::from_secs(5))
            .expect("a message given to the app")
    }

    /// Sends `text` in the group chat, returning once it is answered 200
    fn says(&mut self, text: &str) -> MsrpFrame {
        let result = self.client.send(GROUP_URI, RecipientType::Group, text);
        let send = self.sent();
        assert_eq!(
            result.recv_timeout(Duration::from_secs(5)).map(|r| r.0),
            Ok(200)
        );
        send
    }

    /// The Focus relaying `send`, what another member sent in the group, to
    /// this one
    fn relayed(&mut self, send: &MsrpFrame) {
        let rt = self.rt();
        relayed(
            &mut self.connection,
            &rt,
            &self.focus_path,
            &self.path,
            send,
        );
    }
}

/// Alice's and Bob's session services in the encrypted group chat Alice's
/// starts, which Bob's joins as the Focus invites it, its Conversation-ID,
/// and the clock of both devices (RCC.16 sections 7.9.2, 8.1, 8.2.1)
fn group_through_the_focus() -> (Member, Member, String, Clock) {
    let (alice, bob, clock) = alice_and_bob();
    let (alice_client, mut alice_sip) = start_as(true, ALICE_IMPU);
    let (bob_client, mut bob_sip) = start_as(true, BOB_IMPU);
    let (alice_rt, bob_rt) = (Arc::clone(&alice_client.rt), Arc::clone(&bob_client.rt));
    alice_client
        .sessions
        .set_group_encryption(Arc::clone(&alice.groups) as Arc<dyn GroupEncryption>);
    bob_client
        .sessions
        .set_group_encryption(Arc::clone(&bob.groups) as Arc<dyn GroupEncryption>);

    // Alice's INVITE to the conference factory, carrying the MLS group
    // made for Bob with a KeyPackage of his from the Home KDS
    let (started_tx, started) = std::sync::mpsc::channel();
    alice_client.sessions.create_group_chat(
        FACTORY_URI,
        &[String::from(BOB_IMPU)],
        None,
        move |status_code, _, conference_uri| {
            let _ = started_tx.send((status_code, conference_uri));
        },
        &alice_client.core,
        &alice_rt,
    );
    let invite = alice_sip.next_request("INVITE");
    let conversation_id = header_value(&invite, "Conversation-ID");
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
    let alice_path =
        sdp_attribute(&String::from_utf8_lossy(&parts[0].1), "path").expect("Alice's a=path");
    let bundle = bundle_of(&parts[2].1);

    // the Focus answering, the group known by its URI, and Alice's
    // subscription to its conference events taken
    let alice_msrp = MsrpPeer::listen(&alice_rt);
    let ok = answer_from(
        &invite,
        "200 OK",
        &focus_contact(),
        Some(&alice_msrp.sdp("sendrecv")),
    )
    .replacen(
        "Contact:",
        &format!("MLS-Opaque-Token: {}\r\nContact:", TOKEN),
        1,
    );
    alice_sip.send(&ok);
    let subscribe = next_requests(&mut alice_sip, &["ACK", "SUBSCRIBE"])
        .pop()
        .unwrap();
    alice_sip.send(
        &answer_from(&subscribe, "200 OK", &format!("<{}>", GROUP_URI), None).replacen(
            "Contact:",
            "Expires: 3600\r\nContact:",
            1,
        ),
    );
    let to_alice = alice_msrp.accept(&alice_rt);
    assert_eq!(
        started.recv_timeout(Duration::from_secs(5)),
        Ok((200, Some(String::from(GROUP_URI))))
    );

    // the Focus accepting Alice's Commit (RCC.16 section 6.2.4)
    let previous = epoch_of(&alice, &conversation_id);
    let mut alice = Member {
        party: alice,
        client: alice_client,
        sip: alice_sip,
        connection: to_alice,
        focus_path: alice_msrp.path.clone(),
        path: alice_path,
    };
    alice.focus_sends(&from_the_focus(ALICE_IMPU, &accepted(previous)));

    // then inviting Bob with the Welcome, which his session service joins
    // before telling his app of the group
    let bob_msrp = MsrpPeer::listen(&bob_rt);
    bob_sip.send(&focus_invite(
        "group-to-bob",
        BOB_IMPU,
        &conversation_id,
        &bob_msrp.sdp("sendrecv"),
        &welcomed(&bundle),
    ));
    let bobs_ok = bob_sip.next_response();
    assert_eq!(status_code(&bobs_ok), 200);
    assert_eq!(
        epoch_of(&bob, &conversation_id),
        epoch_of(&alice.party, &conversation_id)
    );
    let invited = next_group_event(&bob_client);
    assert!(
        invited.starts_with(&format!("invited {} {} ", GROUP_URI, conversation_id))
            && invited.ends_with(" accepted encrypted"),
        "{}",
        invited
    );
    bob_sip.send(&ack(&bobs_ok, "group-to-bob"));
    let subscribe = bob_sip.next_request("SUBSCRIBE");
    bob_sip.send(
        &answer_from(&subscribe, "200 OK", &format!("<{}>", GROUP_URI), None).replacen(
            "Contact:",
            "Expires: 3600\r\nContact:",
            1,
        ),
    );
    let bob_path = sdp_attribute(&super::super::cpm::session_tests::body(&bobs_ok), "path")
        .expect("Bob's a=path");
    let to_bob = bob_msrp.accept(&bob_rt);
    assert_eq!(
        next_group_event(&bob_client),
        format!("joined {}", GROUP_URI)
    );
    let bob = Member {
        party: bob,
        client: bob_client,
        sip: bob_sip,
        connection: to_bob,
        focus_path: bob_msrp.path.clone(),
        path: bob_path,
    };
    (alice, bob, conversation_id, clock)
}

#[test]
fn an_encrypted_group_runs_between_two_session_services_through_the_focus() {
    let (mut alice, mut bob, conversation_id, _) = group_through_the_focus();
    assert!(alice.party.groups.encrypts(&conversation_id));
    assert!(bob.party.groups.encrypts(&conversation_id));

    // Alice's message goes encrypted, which Bob's session service gives his
    // app decrypted (RCC.16 section 9.1.1)
    let send = alice.says("hi Bob");
    assert!(
        !String::from_utf8_lossy(&send.body).contains("hi Bob"),
        "sent in the clear"
    );
    bob.relayed(&send);
    let (contact, content_type, content) = bob.given();
    assert_eq!(
        (contact.as_str(), content_type.as_str(), content.as_str()),
        (GROUP_URI, "text/plain", "hi Bob")
    );

    // its delivery, signed in Bob's session, verified by Alice's (sections
    // 7.6.2, 9.1.3)
    let delivery = bob.sent();
    alice.relayed(&delivery);
    let (_, content_type, content) = alice.given();
    assert!(
        content_type.starts_with("message/imdn+xml"),
        "{}",
        content_type
    );
    assert!(content.contains("<delivered/>"), "{}", content);

    // and the same the other way
    let send = bob.says("hi Alice");
    alice.relayed(&send);
    let (contact, content_type, content) = alice.given();
    assert_eq!(
        (contact.as_str(), content_type.as_str(), content.as_str()),
        (GROUP_URI, "text/plain", "hi Alice")
    );
    let delivery = alice.sent();
    bob.relayed(&delivery);
    let (_, content_type, content) = bob.given();
    assert!(
        content_type.starts_with("message/imdn+xml"),
        "{}",
        content_type
    );
    assert!(content.contains("<delivered/>"), "{}", content);
    alice.sip.silence();
    bob.sip.silence();
}

#[test]
fn a_device_leaving_a_group_through_its_session_is_committed_out_by_the_other() {
    let (mut alice, mut bob, conversation_id, _) = group_through_the_focus();

    // Bob's session service leaves with the BYE carrying his self_remove
    // Proposal, his MLS group let go of once the Focus agrees (RCC.16
    // sections 7.9.4, 9.4)
    let (left_tx, left) = std::sync::mpsc::channel();
    bob.client.sessions.leave_group_chat(
        GROUP_URI,
        move |status_code, _| {
            let _ = left_tx.send(status_code);
        },
        &bob.client.core,
        &bob.client.rt,
    );
    let bye = bob.sip.next_request("BYE");
    assert_eq!(header_value(&bye, "Content-Type"), "message/cpim");
    let proposals = match client_message(&body_data(&bye)).payload {
        Some(client_mls_rcs_message::Payload::ProposalList(proposals)) => proposals,
        _ => panic!("not a ProposalList"),
    };
    bob.sip.send(&answer(&bye, "200 OK", None));
    assert_eq!(left.recv_timeout(Duration::from_secs(5)), Ok(200));
    assert!(!bob.party.groups.encrypts(&conversation_id));

    // the Focus forwards it in Alice's session, which commits Bob out in it
    // (sections 7.9.3, 9.5.1)
    let forwarded = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(proposals)),
    });
    alice.focus_sends(&from_the_focus(ALICE_IMPU, &forwarded));
    let send = alice.sent();
    assert_eq!(send.header("Content-Type"), Some("message/cpim"));
    commit_bundle(&send.body);
    let members = |party: &Party| {
        party
            .device
            .store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                conversation.members().len()
            })
            .unwrap()
    };
    assert_eq!(members(&alice.party), 2, "until the Focus accepts it");

    // once the Focus accepts it, Alice is alone in the group, and talks on
    // in its next epoch (section 6.2.4)
    let previous = epoch_of(&alice.party, &conversation_id);
    alice.focus_sends(&from_the_focus(ALICE_IMPU, &accepted(previous.clone())));
    let merged = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        members(&alice.party) == 1
    });
    assert!(merged, "Bob committed out");
    assert_eq!(
        epoch_of(&alice.party, &conversation_id).epoch_id,
        previous.epoch_id + 1
    );
    let send = alice.says("anyone?");
    assert!(
        !String::from_utf8_lossy(&send.body).contains("anyone?"),
        "sent in the clear"
    );
    alice.sip.silence();
    bob.sip.silence();
}

#[test]
fn a_commit_one_device_makes_in_its_session_the_other_takes_in_its() {
    let (mut alice, mut bob, conversation_id, clock) = group_through_the_focus();
    let before = epoch_of(&alice.party, &conversation_id);

    // Alice's keys due, a week on and 50 messages sent (RCC.16 section
    // 9.5.2): the next message her session sends is followed by the Commit
    // updating them
    clock.advance(8 * DAY);
    chatted(&alice.party, &conversation_id, 50);
    let message = alice.says("new keys");
    let commit = alice.sent();
    assert_eq!(commit.header("Content-Type"), Some("message/cpim"));
    let bundle = commit_bundle(&commit.body);

    // the Focus relaying the message to Bob, which his session takes in the
    // epoch it was sent in
    bob.relayed(&message);
    let (_, content_type, content) = bob.given();
    assert_eq!(
        (content_type.as_str(), content.as_str()),
        ("text/plain", "new keys")
    );
    let delivery = bob.sent();
    alice.relayed(&delivery);
    let (_, content_type, _) = alice.given();
    assert!(
        content_type.starts_with("message/imdn+xml"),
        "{}",
        content_type
    );

    // then forwarding the Commit to Bob's session, and accepting it for
    // Alice's: both in the next epoch (sections 6.2.4, 7.9.3)
    bob.focus_sends(&from_the_focus(BOB_IMPU, &forwarded_of(&bundle)));
    let previous = epoch_of(&alice.party, &conversation_id);
    assert_eq!(previous, before, "until the Focus accepts it");
    alice.focus_sends(&from_the_focus(ALICE_IMPU, &accepted(previous)));
    let in_step = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        let alice_epoch = epoch_of(&alice.party, &conversation_id);
        alice_epoch.epoch_id == before.epoch_id + 1
            && epoch_of(&bob.party, &conversation_id) == alice_epoch
    });
    assert!(in_step, "both in the next epoch");

    // in which both talk on
    let send = bob.says("mine still fine");
    alice.relayed(&send);
    let (_, content_type, content) = alice.given();
    assert_eq!(
        (content_type.as_str(), content.as_str()),
        ("text/plain", "mine still fine")
    );
    let delivery = alice.sent();
    bob.relayed(&delivery);
    let (_, content_type, _) = bob.given();
    assert!(
        content_type.starts_with("message/imdn+xml"),
        "{}",
        content_type
    );
    alice.sip.silence();
    bob.sip.silence();
}
