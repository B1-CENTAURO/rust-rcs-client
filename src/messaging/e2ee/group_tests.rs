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

use std::io::Read;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose, Engine as _};
use futures::executor::block_on;
use rust_rcs_core::cpim::{CPIMHeaders, CPIMMessage};
use rust_rcs_core::internet::Body;
use rust_rcs_core::mls::rcs::certificate::CertificateError;
use rust_rcs_core::mls::rcs::proto::{
    self, client_mls_rcs_message, server_mls_rcs_message, AcceptedMlsRcsMessage,
    ClientMlsRcsMessage, CommitBundle, EpochControlMessages, EpochIdentifier, MlsEnhancedGroupInfo,
    MlsGroupInfo, ServerCommitBundle, ServerMlsRcsMessage, WelcomeCommitBundle,
};
use rust_rcs_core::mls::rcs::wire::{
    self, encode_message_list, AuthenticatedData, DeliveryNotificationStatus,
    DisplayNotificationStatus, VerifiableDeliveryImdn, VerifiableDerivedContent,
    VerifiableDisplayImdn,
};
use rust_rcs_core::mls::rcs::{
    is_unencrypted_cpim_header, ClientFailureReason, ServerFailureReason,
    CONTENT_TYPE_MLS_RCS_CLIENT, INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL,
    INFO_PACKAGE_MLS_GROUP_INFO_PULL,
};
use rust_rcs_core::mls::{ErrorKind, IncomingMessage, MlsClient, MlsConfig, MlsConversation};

use crate::capability::{Capabilities, CapabilityQuery};
use crate::messaging::cpm::encryption::{GroupEncryption, GroupInfoPull};
use crate::messaging::cpm::make_cpim_imdn_body;

use super::device::{E2eeDevice, Enrolled, CIPHERSUITE};
use super::device_tests::{alice, provision};
use super::group::{recipients, DeviceGroups, GroupError};
use super::kds::{Fetched, KdsError, KeyDistribution, Recipient};
use super::kds_tests::certificates::*;
use super::kds_tests::{
    bob, credential, signer, validator, App, Kds, ALICE_TEL, BOB_TEL, HOME_KDS, TODAY,
};
use super::message::MessageError;
use super::store::StoreError;

const CONVERSATION: &str = "4f0e8b9c-3a71-4d2e-9b6a-2c5d8e1f7a30";
const IMPU: &str = "sip:+491701234567@ims.example.com";
const FACTORY: &str = "sip:conference-factory@conf.example.com";
/// A Participant the Home KDS has no Client of
const CAROL_TEL: &str = "tel:+491700000001";

/// The feature tags of a contact with E2EE v1 and the Home KDS `home_kds`
fn mls(home_kds: &str) -> Capabilities {
    Capabilities {
        status_code: 200,
        feature_tags: format!(
            "+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\";+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"{}\"",
            home_kds
        ),
    }
}

fn answered(status_code: u16, feature_tags: &str) -> Capabilities {
    Capabilities {
        status_code,
        feature_tags: String::from(feature_tags),
    }
}

/// Contacts answering as `answers` say, 404 if not among them, and those
/// asked
fn answering(answers: &[(&str, Capabilities)]) -> (CapabilityQuery, Arc<Mutex<Vec<String>>>) {
    let answers: Vec<(String, Capabilities)> = answers
        .iter()
        .map(|(contact, capabilities)| (String::from(*contact), capabilities.clone()))
        .collect();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asking = Arc::clone(&asked);
    let query: CapabilityQuery = Arc::new(move |contact: String| {
        asking.lock().unwrap().push(contact.clone());
        let answer = answers
            .iter()
            .find(|(of, _)| *of == contact)
            .map_or(answered(404, ""), |(_, capabilities)| capabilities.clone());
        Box::pin(async move { answer })
    });
    (query, asked)
}

fn recipient(tel_uri: &str) -> Recipient {
    Recipient {
        tel_uri: String::from(tel_uri),
        home_kds: String::from("42"),
    }
}

/// Alice's device enrolled with a Home KDS having `directory` for the
/// Participants asked for, if it has one
fn enrolled(directory: Option<Vec<(&str, Fetched)>>) -> (Arc<E2eeDevice>, Arc<Kds>) {
    let (device, kds, _) = enrolled_with_app(directory);
    (device, kds)
}

/// As enrolled(), with the app keeping its state
fn enrolled_with_app(
    directory: Option<Vec<(&str, Fetched)>>,
) -> (Arc<E2eeDevice>, Arc<Kds>, Arc<App>) {
    let app = Arc::new(App::default());
    let kds = Kds::issuing(&[ALICE, CA], &app);
    let kds = Arc::new(match directory {
        Some(directory) => kds.knowing_too(directory),
        None => kds,
    });
    let device = alice(&app, &kds, TODAY, None);
    provision(&device, &[ALICE_TEL], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    (Arc::new(device), kds, app)
}

/// Bob, and a KeyPackage of his
fn bob_with_key_package() -> (MlsClient, Vec<u8>) {
    let bob = bob();
    let key_package = bob.generate_key_package(false).unwrap();
    (bob, key_package)
}

/// The epoch of the group `conversation_id` of `device`, and whether a
/// Commit of it is pending
fn epoch(device: &E2eeDevice, conversation_id: &str) -> Result<(u64, bool), StoreError> {
    device
        .store()
        .with_conversation(conversation_id.as_bytes(), |conversation, _| {
            Ok((conversation.epoch(), conversation.has_pending_commit()))
        })
}

/// The bundle the CPIM message `cpim` carries
fn bundle_of(cpim: &[u8]) -> WelcomeCommitBundle {
    let message = CPIMMessage::try_from(&Body::construct_message(cpim).unwrap()).unwrap();
    let (content_type, content, base64) = message.get_message_body().unwrap();
    assert_eq!(content_type, Some(CONTENT_TYPE_MLS_RCS_CLIENT));
    assert!(!base64);
    match proto::decode::<ClientMlsRcsMessage>(content)
        .unwrap()
        .payload
    {
        Some(client_mls_rcs_message::Payload::WelcomeCommitBundle(bundle)) => bundle,
        _ => panic!("not a WelcomeCommitBundle"),
    }
}

/// The group Bob joins with `bundle`
fn joined(bob: &MlsClient, bundle: &WelcomeCommitBundle) -> MlsConversation {
    bob.join_conversation(&bundle.welcome, &bundle.ratchet_tree)
        .unwrap()
}

/// What the Conversation Focus sends once it accepts what was sent in the
/// epoch `previous`
fn accepted(previous: EpochIdentifier) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::AcceptedMlsRcsMessage(
            AcceptedMlsRcsMessage {
                message_id: String::from("accepted-1"),
                previous_epoch_identifier: Some(previous),
            },
        )),
    })
}

fn epoch_identifier(device: &E2eeDevice, conversation_id: &str) -> EpochIdentifier {
    device
        .store()
        .with_conversation(conversation_id.as_bytes(), |conversation, _| {
            Ok(conversation.epoch_identifier())
        })
        .unwrap()
}

#[test]
fn participants_are_asked_for_by_tel_uri_at_the_home_kds_they_advertise() {
    let participants = [
        String::from(BOB_TEL),
        String::from("sip:+491700000002@ims.example.com;user=phone"),
    ];
    let (query, asked) = answering(&[
        (BOB_TEL, mls("42")),
        ("sip:+491700000002@ims.example.com;user=phone", mls("7")),
    ]);
    assert_eq!(
        block_on(recipients(&participants, &query)),
        Some(vec![
            recipient(BOB_TEL),
            Recipient {
                tel_uri: String::from("tel:+491700000002"),
                home_kds: String::from("7"),
            },
        ])
    );
    assert_eq!(*asked.lock().unwrap(), participants.to_vec());

    assert_eq!(block_on(recipients(&[], &query)), Some(Vec::new()));
}

#[test]
fn a_group_is_not_encrypted_unless_each_participant_advertises_e2ee_v1() {
    let others = [
        ("not registered", answered(480, "")),
        (
            "not available, whatever it tells",
            Capabilities {
                status_code: 480,
                ..mls("42")
            },
        ),
        (
            "without E2EE",
            answered(
                200,
                "+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.session\"",
            ),
        ),
        (
            "of another version",
            answered(
                200,
                "+g.gsma.rcs.mls.mls-version=\"v2\";+g.gsma.rcs.mls.mls-kds=\"42\"",
            ),
        ),
        (
            "without a Home KDS",
            answered(200, "+g.gsma.rcs.mls.mls-version=\"v1\""),
        ),
        (
            "with a Home KDS not a Vendor ID",
            answered(
                200,
                "+g.gsma.rcs.mls.mls-version=\"v1\";+g.gsma.rcs.mls.mls-kds=\"kds\"",
            ),
        ),
    ];
    for (case, capabilities) in others {
        let (query, _) = answering(&[(BOB_TEL, mls("42")), (CAROL_TEL, capabilities)]);
        let participants = [String::from(BOB_TEL), String::from(CAROL_TEL)];
        assert_eq!(
            block_on(recipients(&participants, &query)),
            None,
            "{}",
            case
        );
    }

    // nor one known by no number
    let (query, _) = answering(&[("sip:carol@example.com", mls("42"))]);
    assert_eq!(
        block_on(recipients(&[String::from("sip:carol@example.com")], &query)),
        None
    );
}

#[test]
fn a_group_is_made_for_the_focus_to_accept_with_the_clients_of_each_participant() {
    let (bob, bobs) = bob_with_key_package();
    let (device, kds) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));

    let cpim = block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)]))
        .unwrap();
    assert_eq!(
        *kds.queries.lock().unwrap(),
        vec![(vec![CIPHERSUITE], vec![recipient(BOB_TEL)])]
    );

    // only the headers left unencrypted, asking to be told if it is refused
    let message = CPIMMessage::try_from(&Body::construct_message(&cpim).unwrap()).unwrap();
    let CPIMHeaders::Inflated(headers) = &message.headers else {
        panic!("headers not inflated");
    };
    let names: Vec<String> = headers
        .iter()
        .map(|header| String::from_utf8_lossy(header.get_name()).into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "From",
            "To",
            "DateTime",
            "<urn:ietf:params:imdn>.Message-ID",
            "<urn:ietf:params:imdn>.Disposition-Notification",
        ]
    );
    assert!(headers
        .iter()
        .all(|header| is_unencrypted_cpim_header(header.get_name())));
    let info = message.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", FACTORY).as_bytes());
    assert_eq!(
        info.disposition_notification,
        Some(&b"negative-delivery"[..])
    );
    assert_eq!(info.imdn_message_id.len(), 36);
    let text = String::from_utf8_lossy(&cpim).into_owned();
    let namespaces: Vec<&str> = text.lines().filter(|l| l.starts_with("NS:")).collect();
    assert_eq!(namespaces, ["NS: imdn <urn:ietf:params:imdn>"]);

    // with what Bob joins by, in the group of the conversation, in Era 0
    let bundle = bundle_of(&cpim);
    assert!(!bundle.commit_list.is_empty());
    assert!(!bundle.group_info.is_empty());
    let mut bobs_group = joined(&bob, &bundle);
    assert_eq!(bobs_group.group_id(), CONVERSATION.as_bytes());
    assert_eq!(bobs_group.era(), Some(0));
    assert_eq!(bobs_group.epoch(), 1);
    assert_eq!(bundle.epoch_authenticator, bobs_group.epoch_authenticator());
    // with the continuity token of the group, 256 bits (section 8.3.1.1)
    let continuity_token = device
        .store()
        .with_client(|client| client.group_metadata(CONVERSATION.as_bytes()))
        .unwrap()
        .continuity_token;
    assert_eq!(continuity_token.len(), 32);
    assert_eq!(
        bob.group_metadata(CONVERSATION.as_bytes())
            .unwrap()
            .continuity_token,
        continuity_token
    );

    // Alice's applied once the focus accepts it
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
    let previous = epoch_identifier(&device, CONVERSATION);
    match device
        .on_server_message(CONVERSATION, &accepted(previous))
        .as_deref()
    {
        Ok([IncomingMessage::Commit { added, .. }]) => {
            assert_eq!(added, &vec![credential(&[BOB, CA])])
        }
        other => panic!("{:?}", other.map(|_| ())),
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    let sent = device
        .store()
        .with_conversation(CONVERSATION.as_bytes(), |conversation, client| {
            conversation.encrypt(client, b"hello Bob")
        })
        .unwrap();
    match bobs_group.process(&bob, &sent) {
        Ok(IncomingMessage::Application { data, .. }) => assert_eq!(data, b"hello Bob"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

#[test]
fn only_what_the_focus_accepted_of_the_epoch_is_applied() {
    let (_, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])).unwrap();
    let previous = epoch_identifier(&device, CONVERSATION);

    let mut other_epoch = previous.clone();
    other_epoch.epoch_authenticator[0] ^= 1;
    assert_eq!(
        device
            .on_server_message(CONVERSATION, &accepted(other_epoch))
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::UnexpectedMessage))
    );

    // the GroupInfo, which only answers a request for it, and what is no
    // message
    let group_info = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::MlsGroupInfo(
            MlsGroupInfo::default(),
        )),
    });
    assert_eq!(
        device
            .on_server_message(CONVERSATION, &group_info)
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::UnexpectedMessage))
    );
    assert_eq!(
        device
            .on_server_message(
                CONVERSATION,
                &proto::encode(&ServerMlsRcsMessage::default())
            )
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::UnexpectedMessage))
    );
    assert_eq!(
        device
            .on_server_message(CONVERSATION, b"\x0a\xff")
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::BadFormat))
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));

    // nor of a group there is not
    assert_eq!(
        device
            .on_server_message("another", &accepted(previous))
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
}

#[test]
fn a_group_is_not_made_unless_each_participant_can_be_added() {
    let (_, bobs) = bob_with_key_package();
    let directory = || {
        vec![
            (BOB_TEL, Fetched::KeyPackages(vec![bobs.clone()])),
            (CAROL_TEL, Fetched::NotFound),
            // Bob's, for another
            (
                "tel:+491700000003",
                Fetched::KeyPackages(vec![bobs.clone()]),
            ),
        ]
    };
    let (device, _) = enrolled(Some(directory()));
    for (asked, refused) in [
        (CAROL_TEL, Fetched::NotFound),
        (
            "tel:+491700000003",
            Fetched::Refused(CertificateError::Identity),
        ),
        // nothing returned for it
        ("tel:+491700000004", Fetched::NotFound),
    ] {
        assert_eq!(
            block_on(device.create_group(
                CONVERSATION,
                IMPU,
                FACTORY,
                vec![recipient(BOB_TEL), recipient(asked)]
            )),
            Err(GroupError::NotEncryptable(String::from(asked), refused))
        );
        assert_eq!(
            epoch(&device, CONVERSATION),
            Err(StoreError::Mls(ErrorKind::UnknownGroup))
        );
    }

    // nor when the Home KDS cannot be reached
    let (device, _) = enrolled(None);
    assert_eq!(
        block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])),
        Err(GroupError::Kds(KdsError::Unavailable))
    );
}

#[test]
fn a_group_mls_fails_to_make_is_not_kept() {
    // a KeyPackage with the signature key of the device itself
    let alices = MlsClient::with_credential(
        credential(&[ALICE, CA]),
        signer(ALICE_KEY, ALICE_PUBLIC_KEY),
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(validator(TODAY)),
    )
    .unwrap()
    .generate_key_package(false)
    .unwrap();
    let (device, _) = enrolled(Some(vec![(ALICE_TEL, Fetched::KeyPackages(vec![alices]))]));
    let made =
        block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(ALICE_TEL)]));
    assert!(
        matches!(made, Err(GroupError::Store(StoreError::Mls(_)))),
        "{:?}",
        made.map(|_| ())
    );
    assert_eq!(
        epoch(&device, CONVERSATION),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

#[test]
fn a_group_abandoned_is_let_go_of() {
    let (_, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])).unwrap();

    assert_eq!(device.abandon(CONVERSATION), Ok(()));
    assert_eq!(
        epoch(&device, CONVERSATION),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
    assert_eq!(
        device.abandon(CONVERSATION),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

/// What DeviceGroups prepares for a group with Bob
fn prepared(groups: &DeviceGroups) -> Option<Vec<u8>> {
    block_on(groups.prepare(
        String::from(CONVERSATION),
        String::from(IMPU),
        String::from(FACTORY),
        vec![String::from(BOB_TEL)],
    ))
}

#[test]
fn the_groups_of_the_device_are_encrypted_while_it_can_be_added_to_them() {
    let (bob, bobs) = bob_with_key_package();
    let (device, kds) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let (query, asked) = answering(&[(BOB_TEL, mls("42"))]);
    let groups = DeviceGroups::new(&device, query);

    let cpim = prepared(&groups).expect("a group encrypted");
    assert_eq!(*asked.lock().unwrap(), [BOB_TEL]);
    assert_eq!(
        kds.queries.lock().unwrap()[0].1,
        vec![recipient(BOB_TEL)],
        "asked for at the Home KDS Bob advertises"
    );
    let bobs_group = joined(&bob, &bundle_of(&cpim));
    assert_eq!(bobs_group.group_id(), CONVERSATION.as_bytes());

    // what the focus sends goes to the group
    let previous = epoch_identifier(&device, CONVERSATION);
    groups.on_server_message(CONVERSATION, b"\x0a\xff");
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
    groups.on_server_message(CONVERSATION, &accepted(previous));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    groups.abandon(CONVERSATION);
    assert_eq!(
        epoch(&device, CONVERSATION),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );

    // nothing once the device is let go of
    drop(device);
    assert_eq!(prepared(&groups), None);
    groups.on_server_message(CONVERSATION, b"\x0a\xff");
    groups.abandon(CONVERSATION);
}

#[test]
fn the_groups_of_the_device_are_not_encrypted_when_they_cannot_be() {
    // the device not enrolled; no one is asked
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app));
    let device = Arc::new(alice(&app, &kds, TODAY, None));
    let (query, asked) = answering(&[(BOB_TEL, mls("42"))]);
    assert_eq!(prepared(&DeviceGroups::new(&device, query)), None);
    assert!(asked.lock().unwrap().is_empty());

    // Bob not advertising E2EE; the Home KDS is not asked
    let (_, bobs) = bob_with_key_package();
    let (device, kds) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let (query, _) = answering(&[(BOB_TEL, answered(480, ""))]);
    assert_eq!(prepared(&DeviceGroups::new(&device, query)), None);
    assert!(kds.queries.lock().unwrap().is_empty());

    // the Home KDS not having Bob
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::NotFound)]));
    let (query, _) = answering(&[(BOB_TEL, mls("42"))]);
    assert_eq!(prepared(&DeviceGroups::new(&device, query)), None);
    assert_eq!(
        epoch(&device, CONVERSATION),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

/// A KeyPackage of the device that the Home KDS holds, the `n`th uploaded
fn uploaded_key_package(kds: &Kds, n: usize) -> Vec<u8> {
    kds.uploads()[0].0[n].clone()
}

/// Bob's group `group_id`, to which he adds the device with `key_package`,
/// and what its Conversation Focus sends the device of it, with
/// `private_message` bundled
fn focus_welcome(
    bob: &MlsClient,
    group_id: &str,
    key_package: &[u8],
    private_message: impl FnOnce(&mut MlsConversation) -> Vec<u8>,
) -> (MlsConversation, Vec<u8>) {
    let mut conversation = bob
        .create_conversation(Some(group_id.as_bytes()), 0)
        .unwrap();
    let output = conversation.add_members(bob, &[key_package]).unwrap();
    conversation.merge_pending_commit(bob).unwrap();
    let private_message = private_message(&mut conversation);
    let server_message = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: encode_message_list(&[&output.commit]).unwrap(),
                welcome: output.welcome.unwrap(),
                private_message,
                ratchet_tree: output.ratchet_tree.unwrap(),
            },
        )),
    });
    (conversation, server_message)
}

#[test]
fn a_group_is_joined_with_the_welcome_its_focus_sends() {
    let (device, kds) = enrolled(None);
    let bob = bob();
    let (mut bobs_group, server_message) =
        focus_welcome(&bob, CONVERSATION, &uploaded_key_package(&kds, 0), |_| {
            Vec::new()
        });

    assert_eq!(device.join_group(CONVERSATION, &server_message), Ok(()));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    // in the group with Bob, both ways
    let sent = bobs_group.encrypt(&bob, b"hello Alice").unwrap();
    let received = device
        .store()
        .with_conversation(CONVERSATION.as_bytes(), |conversation, client| {
            conversation.process(client, &sent)
        });
    match received {
        Ok(IncomingMessage::Application { data, .. }) => assert_eq!(data, b"hello Alice"),
        other => panic!("{:?}", other.map(|_| ())),
    }
    let sent = device
        .store()
        .with_conversation(CONVERSATION.as_bytes(), |conversation, client| {
            conversation.encrypt(client, b"hello Bob")
        })
        .unwrap();
    match bobs_group.process(&bob, &sent) {
        Ok(IncomingMessage::Application { data, .. }) => assert_eq!(data, b"hello Bob"),
        other => panic!("{:?}", other.map(|_| ())),
    }

    // with the continuity token of the group
    assert_eq!(
        device
            .store()
            .with_client(|client| client.group_metadata(CONVERSATION.as_bytes()))
            .map(|keys| keys.continuity_token),
        bob.group_metadata(CONVERSATION.as_bytes())
            .map(|keys| keys.continuity_token)
            .map_err(StoreError::Mls)
    );
}

#[test]
fn a_message_bundled_with_the_welcome_is_one_the_group_decrypts() {
    let (device, kds) = enrolled(None);
    let bob = bob();
    let (_, server_message) = focus_welcome(
        &bob,
        CONVERSATION,
        &uploaded_key_package(&kds, 0),
        |group| group.encrypt(&bob, b"bundled").unwrap(),
    );
    assert_eq!(device.join_group(CONVERSATION, &server_message), Ok(()));

    // one that is not, the group not kept
    let (_, server_message) =
        focus_welcome(&bob, "group-2", &uploaded_key_package(&kds, 1), |_| {
            b"not a message".to_vec()
        });
    assert!(device.join_group("group-2", &server_message).is_err());
    assert_eq!(
        epoch(&device, "group-2"),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

#[test]
fn a_welcome_to_another_group_than_the_conversation_is_not_joined() {
    let (device, kds) = enrolled(None);
    let (_, server_message) = focus_welcome(
        &bob(),
        "another-group",
        &uploaded_key_package(&kds, 0),
        |_| Vec::new(),
    );
    assert_eq!(
        device.join_group(CONVERSATION, &server_message),
        Err(StoreError::Mls(ErrorKind::Rejected))
    );
    for group_id in [CONVERSATION, "another-group"] {
        assert_eq!(
            epoch(&device, group_id),
            Err(StoreError::Mls(ErrorKind::UnknownGroup)),
            "{}",
            group_id
        );
    }
}

#[test]
fn what_is_not_a_welcome_for_the_device_is_not_joined() {
    let (device, _) = enrolled(None);

    // one for another client of the user
    let other_client = MlsClient::with_credential(
        credential(&[ALICE, CA]),
        signer(ALICE_KEY, ALICE_PUBLIC_KEY),
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(validator(TODAY)),
    )
    .unwrap();
    let (_, server_message) = focus_welcome(
        &bob(),
        CONVERSATION,
        &other_client.generate_key_package(false).unwrap(),
        |_| Vec::new(),
    );
    assert!(device.join_group(CONVERSATION, &server_message).is_err());

    // what has none
    let without = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle::default(),
        )),
    });
    assert_eq!(
        device.join_group(CONVERSATION, &without),
        Err(StoreError::Mls(ErrorKind::UnexpectedMessage))
    );
    let previous = EpochIdentifier::default();
    assert_eq!(
        device.join_group(CONVERSATION, &accepted(previous)),
        Err(StoreError::Mls(ErrorKind::UnexpectedMessage))
    );
    assert_eq!(
        device.join_group(CONVERSATION, b"\x0a\xff"),
        Err(StoreError::Mls(ErrorKind::BadFormat))
    );
    assert_eq!(
        epoch(&device, CONVERSATION),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

#[test]
fn the_groups_of_the_device_are_joined_while_it_is_kept() {
    let (device, kds) = enrolled(None);
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    let (_, server_message) =
        focus_welcome(&bob(), CONVERSATION, &uploaded_key_package(&kds, 0), |_| {
            Vec::new()
        });
    assert!(!groups.join("another-group", &server_message));
    let (_, server_message) =
        focus_welcome(&bob(), CONVERSATION, &uploaded_key_package(&kds, 1), |_| {
            Vec::new()
        });
    assert!(groups.join(CONVERSATION, &server_message));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    let (_, server_message) =
        focus_welcome(&bob(), "group-2", &uploaded_key_package(&kds, 2), |_| {
            Vec::new()
        });
    drop(device);
    assert!(!groups.join("group-2", &server_message));
}

/// Alice's device and Bob in the group of the conversation, the Commit
/// making it accepted, both in epoch 1
fn alice_and_bob() -> (Arc<E2eeDevice>, MlsClient, MlsConversation) {
    let (bob, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let cpim = block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)]))
        .unwrap();
    let bobs_group = joined(&bob, &bundle_of(&cpim));
    let previous = epoch_identifier(&device, CONVERSATION);
    device
        .on_server_message(CONVERSATION, &accepted(previous))
        .unwrap();
    (device, bob, bobs_group)
}

const GROUP_URI: &str = "sip:conf1@conf.example.com";

/// A CPIM message from Alice to the group as the client sends one, asking
/// to be told of `disposition`
fn plaintext(message_id: &str, disposition: Option<&str>) -> Vec<u8> {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:00.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: {}\r\n\
{}\
NS: cpm <http://www.openmobilealliance.org/cpm/>\r\n\
cpm.Payload-Type: text/plain\r\n\
NS: rcs <http://www.gsma.com/rcs>\r\n\
rcs.advised-action: none\r\n\
\r\n\
Content-Type: text/plain\r\n\
Content-Length: 9\r\n\
\r\n\
hello Bob",
        IMPU,
        GROUP_URI,
        message_id,
        disposition
            .map(|d| format!("imdn.Disposition-Notification: {}\r\n", d))
            .unwrap_or_default()
    )
    .into_bytes()
}

fn header_names(message: &CPIMMessage) -> Vec<String> {
    let CPIMHeaders::Inflated(headers) = &message.headers else {
        panic!("headers not inflated");
    };
    headers
        .iter()
        .map(|header| String::from_utf8_lossy(header.get_name()).into_owned())
        .collect()
}

fn cpim_message(data: &[u8]) -> CPIMMessage {
    CPIMMessage::try_from(&Body::construct_message(data).unwrap()).unwrap()
}

#[test]
fn a_message_is_sent_encrypted_with_only_the_headers_left_unencrypted() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let outer = device
        .encrypt_message(
            CONVERSATION,
            &plaintext("message-1", Some("positive-delivery, display")),
        )
        .unwrap();

    let message = cpim_message(&outer);
    assert_eq!(
        header_names(&message),
        [
            "From",
            "To",
            "DateTime",
            "<urn:ietf:params:imdn>.Message-ID",
            "<http://www.gsma.com/rcs>.advised-action",
            "<urn:ietf:params:imdn>.Disposition-Notification",
            "<http://www.gsma.com/rcs/mls>.Epoch-Authenticator",
            "<http://www.gsma.com/rcs/mls>.Era-ID",
        ]
    );
    let info = message.get_info().unwrap();
    assert_eq!(info.imdn_message_id, b"message-1");
    assert_eq!(
        info.disposition_notification,
        Some(&b"positive-delivery, display, negative-delivery"[..])
    );
    let value = |name: &str| {
        message
            .get_values(name.as_bytes())
            .first()
            .map(|value| String::from_utf8_lossy(value.value).into_owned())
    };
    assert_eq!(
        value("<http://www.gsma.com/rcs/mls>.Epoch-Authenticator"),
        Some(general_purpose::STANDARD.encode(bobs_group.epoch_authenticator()))
    );
    assert_eq!(
        value("<http://www.gsma.com/rcs/mls>.Era-ID"),
        Some(String::from("0"))
    );
    let text = String::from_utf8_lossy(&outer).into_owned();
    let namespaces: Vec<&str> = text.lines().filter(|l| l.starts_with("NS:")).collect();
    assert_eq!(
        namespaces,
        [
            "NS: imdn <urn:ietf:params:imdn>",
            "NS: rcs <http://www.gsma.com/rcs>",
            "NS: mls <http://www.gsma.com/rcs/mls>",
        ]
    );

    // what Bob decrypts the rest of
    let (content_type, mls_message, base64) = message.get_message_body().unwrap();
    assert_eq!(content_type, Some(&b"message/mls"[..]));
    assert!(!base64);
    let decrypted = bobs_group.decrypt(&bob, mls_message, b"message-1").unwrap();
    assert_eq!(decrypted.sender, credential(&[ALICE, CA]));
    assert_eq!(
        String::from_utf8_lossy(&decrypted.payload.unwrap()),
        "NS: cpm <http://www.openmobilealliance.org/cpm/>\r\n\
cpm.Payload-Type: text/plain\r\n\
\r\n\
Content-Type: text/plain\r\n\
Content-Length: 9\r\n\
\r\n\
hello Bob"
    );
}

#[test]
fn a_message_asks_to_be_told_of_a_negative_delivery_once() {
    let (device, _, _) = alice_and_bob();
    for (asked, told) in [
        (None, "negative-delivery"),
        (Some("negative-delivery"), "negative-delivery"),
        (
            Some("display, Negative-Delivery"),
            "display, Negative-Delivery",
        ),
        (
            Some("positive-delivery"),
            "positive-delivery, negative-delivery",
        ),
    ] {
        let outer = device
            .encrypt_message(CONVERSATION, &plaintext("message-2", asked))
            .unwrap();
        assert_eq!(
            cpim_message(&outer)
                .get_info()
                .unwrap()
                .disposition_notification,
            Some(told.as_bytes()),
            "{:?}",
            asked
        );
    }
}

#[test]
fn a_message_is_not_encrypted_unless_it_can_be() {
    // the Commit of the group not yet accepted
    let (_, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])).unwrap();
    assert_eq!(
        device.encrypt_message(CONVERSATION, &plaintext("message-3", None)),
        Err(MessageError::Pending)
    );

    // in no group, or not a CPIM message with an ID
    let (device, _, _) = alice_and_bob();
    assert_eq!(
        device.encrypt_message("another", &plaintext("message-4", None)),
        Err(MessageError::Store(StoreError::Mls(
            ErrorKind::UnknownGroup
        )))
    );
    assert_eq!(
        device.encrypt_message(CONVERSATION, b"not a CPIM message"),
        Err(MessageError::NotCpim)
    );
    let without_id = String::from_utf8(plaintext("message-5", None))
        .unwrap()
        .replace("imdn.Message-ID: message-5\r\n", "");
    assert_eq!(
        device.encrypt_message(CONVERSATION, without_id.as_bytes()),
        Err(MessageError::NotCpim)
    );
}

/// What Bob sends the group as the client of Alice receives it, from
/// `from`: the CPIM message carrying it and the encrypted message
fn from_bob(
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
    from: &str,
    message_id: &str,
) -> (Vec<u8>, Vec<u8>) {
    let mls_message = bobs_group
        .encrypt_cpim(
            bob,
            b"NS: cpm <http://www.openmobilealliance.org/cpm/>\r\ncpm.Payload-Type: text/plain\r\n\r\nContent-Type: text/plain\r\n\r\nhi Alice",
            b"bob-1",
            b"",
        )
        .unwrap();
    let mut outer = format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:01.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: {}\r\n\
imdn.Disposition-Notification: positive-delivery, negative-delivery\r\n\
\r\n\
Content-Type: message/mls\r\n\
\r\n",
        from, GROUP_URI, message_id
    )
    .into_bytes();
    outer.extend_from_slice(&mls_message);
    (outer, mls_message)
}

#[test]
fn a_message_received_is_decrypted_with_the_headers_it_came_with() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (outer, mls_message) = from_bob(
        &bob,
        &mut bobs_group,
        "sip:+491707654321@ims.example.com",
        "bob-1",
    );
    let outer = cpim_message(&outer);
    let plaintext = device
        .decrypt_message(CONVERSATION, &outer.get_info().unwrap(), &mls_message)
        .unwrap();

    let message = cpim_message(&plaintext);
    let info = message.get_info().unwrap();
    assert_eq!(info.from, b"<sip:+491707654321@ims.example.com>");
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());
    assert_eq!(info.date, b"2026-10-25T12:00:01.000+00:00");
    assert_eq!(info.imdn_message_id, b"bob-1");
    assert_eq!(
        info.disposition_notification,
        Some(&b"positive-delivery, negative-delivery"[..])
    );
    assert_eq!(info.payload_type, Some(&b"text/plain"[..]));
    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"text/plain"[..]), &b"hi Alice"[..], false))
    );
}

#[test]
fn a_message_from_another_than_its_mls_sender_is_from_the_mls_sender() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    for told in ["sip:+491700000009@ims.example.com", "sip:bob@example.com"] {
        let (outer, mls_message) = from_bob(&bob, &mut bobs_group, told, "bob-1");
        let plaintext = device
            .decrypt_message(
                CONVERSATION,
                &cpim_message(&outer).get_info().unwrap(),
                &mls_message,
            )
            .unwrap();
        assert_eq!(
            cpim_message(&plaintext).get_info().unwrap().from,
            b"<tel:+491707654321>",
            "{}",
            told
        );
    }
}

#[test]
fn a_message_not_for_the_group_as_it_came_is_not_decrypted() {
    let (device, bob, mut bobs_group) = alice_and_bob();

    // bound to another Message-ID
    let (outer, mls_message) = from_bob(&bob, &mut bobs_group, "tel:+491707654321", "another-id");
    assert_eq!(
        device.decrypt_message(
            CONVERSATION,
            &cpim_message(&outer).get_info().unwrap(),
            &mls_message
        ),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::Rejected)))
    );

    // of another group, or none
    let (outer, mls_message) = from_bob(&bob, &mut bobs_group, "tel:+491707654321", "bob-1");
    let info = cpim_message(&outer);
    assert_eq!(
        device.decrypt_message("another", &info.get_info().unwrap(), &mls_message),
        Err(MessageError::Store(StoreError::Mls(
            ErrorKind::UnknownGroup
        )))
    );
    assert!(device
        .decrypt_message(CONVERSATION, &info.get_info().unwrap(), b"not MLS")
        .is_err());

    // its own coming back
    let own = device
        .encrypt_message(CONVERSATION, &plaintext("message-6", None))
        .unwrap();
    let own = cpim_message(&own);
    let (_, mls_message, _) = own.get_message_body().unwrap();
    assert!(device
        .decrypt_message(CONVERSATION, &own.get_info().unwrap(), mls_message)
        .is_err());
}

#[test]
fn messages_wait_for_the_focus_to_accept_the_commit_of_the_group() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])).unwrap();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    assert!(groups.encrypts(CONVERSATION));
    assert!(!groups.encrypts("another"));

    let waiting = rt.spawn(groups.encrypt(CONVERSATION, &plaintext("message-7", None)));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        !waiting.is_finished(),
        "waits for the Commit to be accepted"
    );
    // what is not the acceptance leaves it waiting
    groups.on_server_message(CONVERSATION, b"\x0a\xff");
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!waiting.is_finished());

    groups.on_server_message(
        CONVERSATION,
        &accepted(epoch_identifier(&device, CONVERSATION)),
    );
    let encrypted = rt.block_on(waiting).unwrap().expect("sent once accepted");
    assert_eq!(
        cpim_message(&encrypted).get_info().unwrap().imdn_message_id,
        b"message-7"
    );
}

#[test]
fn messages_are_not_sent_in_a_group_whose_commit_is_not_accepted() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])).unwrap();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query)
        .with_acceptance_wait(std::time::Duration::from_millis(300));
    assert_eq!(
        rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                groups.encrypt(CONVERSATION, &plaintext("message-8", None)),
            )
            .await
        }),
        Ok(None),
        "given up after the wait"
    );

    // nor what cannot be, nor once the device is let go of
    assert_eq!(rt.block_on(groups.encrypt(CONVERSATION, b"not CPIM")), None);
    drop(device);
    assert!(!groups.encrypts(CONVERSATION));
    assert_eq!(
        rt.block_on(groups.encrypt(CONVERSATION, &plaintext("message-9", None))),
        None
    );
}

#[test]
fn the_messages_of_the_groups_of_the_device_are_decrypted_while_it_is_kept() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    let (outer, mls_message) = from_bob(&bob, &mut bobs_group, "tel:+491707654321", "bob-1");
    let info = cpim_message(&outer);
    let plaintext = groups
        .decrypt(CONVERSATION, &info.get_info().unwrap(), &mls_message)
        .expect("decrypted");
    assert_eq!(
        cpim_message(&plaintext)
            .get_message_body()
            .map(|b| b.1.to_vec()),
        Some(b"hi Alice".to_vec())
    );
    let (outer, mls_message) = from_bob(&bob, &mut bobs_group, "tel:+491707654321", "bob-2");
    let info = cpim_message(&outer);
    assert_eq!(
        groups.decrypt("another", &info.get_info().unwrap(), &mls_message),
        None
    );
    drop(device);
    assert_eq!(
        groups.decrypt(CONVERSATION, &info.get_info().unwrap(), &mls_message),
        None
    );
}

#[test]
fn a_message_with_no_rcs_header_declares_no_rcs_namespace() {
    let (device, _, _) = alice_and_bob();
    let without = String::from_utf8(plaintext("message-10", None))
        .unwrap()
        .replace(
            "NS: rcs <http://www.gsma.com/rcs>\r\nrcs.advised-action: none\r\n",
            "",
        );
    let outer = device
        .encrypt_message(CONVERSATION, without.as_bytes())
        .unwrap();
    let text = String::from_utf8_lossy(&outer).into_owned();
    let namespaces: Vec<&str> = text.lines().filter(|l| l.starts_with("NS:")).collect();
    assert_eq!(
        namespaces,
        [
            "NS: imdn <urn:ietf:params:imdn>",
            "NS: mls <http://www.gsma.com/rcs/mls>",
        ]
    );
}

#[test]
fn a_message_re_sent_is_not_taken_yet() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let resent = bobs_group
        .encrypt_resent(
            &bob,
            b"\r\nContent-Type: text/plain\r\n\r\nagain",
            &credential(&[ALICE, CA]),
            b"bob-2",
            b"bob-1",
        )
        .unwrap();
    let mut outer = format!(
        "From: <tel:+491707654321>\r\nTo: <{}>\r\nDateTime: 2026-10-25T12:00:02.000+00:00\r\nNS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: bob-2\r\n\r\nContent-Type: message/mls\r\n\r\n",
        GROUP_URI
    )
    .into_bytes();
    outer.extend_from_slice(&resent);
    assert_eq!(
        device.decrypt_message(
            CONVERSATION,
            &cpim_message(&outer).get_info().unwrap(),
            &resent
        ),
        Err(MessageError::Store(StoreError::Mls(
            ErrorKind::UnexpectedMessage
        )))
    );
}

#[test]
fn the_groups_of_a_device_restored_are_encrypted() {
    let (bob, bobs) = bob_with_key_package();
    let (device, kds, app) =
        enrolled_with_app(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let cpim = block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)]))
        .unwrap();
    let mut bobs_group = joined(&bob, &bundle_of(&cpim));
    let previous = epoch_identifier(&device, CONVERSATION);
    device
        .on_server_message(CONVERSATION, &accepted(previous))
        .unwrap();

    let restored = Arc::new(alice(&app, &kds, TODAY, Some(&app.last().unwrap())));
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&restored, query);
    assert!(groups.encrypts(CONVERSATION));
    assert!(!groups.encrypts("another"));

    // and its messages decrypted
    let (outer, mls_message) = from_bob(&bob, &mut bobs_group, "tel:+491707654321", "bob-1");
    assert!(groups
        .decrypt(
            CONVERSATION,
            &cpim_message(&outer).get_info().unwrap(),
            &mls_message
        )
        .is_some());
}

/// What the Conversation Focus forwards of the Commit `commit` it accepted
/// (RCC.16 section 7.9.3)
fn focus_commit(commit_list: &[&[u8]]) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: encode_message_list(commit_list).unwrap(),
                ..ServerCommitBundle::default()
            },
        )),
    })
}

/// What the client of Alice receives of what Bob sends the group, decrypted
fn received_from_bob(
    device: &E2eeDevice,
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
) -> Result<Vec<u8>, MessageError> {
    let (outer, mls_message) = from_bob(bob, bobs_group, "tel:+491707654321", "bob-1");
    device
        .decrypt_message(
            CONVERSATION,
            &cpim_message(&outer).get_info().unwrap(),
            &mls_message,
        )
        .map(|plaintext| {
            cpim_message(&plaintext)
                .get_message_body()
                .unwrap()
                .1
                .to_vec()
        })
}

/// What Bob decrypts of the message `outer` the client of Alice sends
fn received_by_bob(bob: &MlsClient, bobs_group: &mut MlsConversation, outer: &[u8]) -> Vec<u8> {
    let outer = cpim_message(outer);
    let (_, mls_message, _) = outer.get_message_body().unwrap();
    bobs_group
        .decrypt(bob, mls_message, outer.get_info().unwrap().imdn_message_id)
        .unwrap()
        .payload
        .unwrap()
}

#[test]
fn a_commit_of_another_member_is_applied_as_the_focus_forwards_it() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let output = bobs_group.update_keys(&bob).unwrap();

    match device
        .on_server_message(CONVERSATION, &focus_commit(&[&output.commit]))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit {
            sender,
            added,
            removed,
            self_removed: false,
        }] => {
            assert_eq!(sender, bob.credential());
            assert!(added.is_empty() && removed.is_empty());
        }
        other => panic!("{} messages", other.len()),
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));

    // the epoch both are in
    bobs_group.merge_pending_commit(&bob).unwrap();
    assert_eq!(
        received_from_bob(&device, &bob, &mut bobs_group),
        Ok(b"hi Alice".to_vec())
    );
    let sent = device
        .encrypt_message(CONVERSATION, &plaintext("message-11", None))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&received_by_bob(&bob, &mut bobs_group, &sent))
            .ends_with("hello Bob")
    );
}

#[test]
fn a_bundle_of_commits_is_applied_whole_or_not_at_all() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (outer, mls_message) = from_bob(&bob, &mut bobs_group, "tel:+491707654321", "bob-1");
    let output = bobs_group.update_keys(&bob).unwrap();

    // with a Commit of another group after it
    let mut others = bob.create_conversation(Some(b"other"), 0).unwrap();
    let other = others.update_keys(&bob).unwrap();
    assert_eq!(
        device
            .on_server_message(
                CONVERSATION,
                &focus_commit(&[&output.commit, &other.commit])
            )
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::UnexpectedMessage))
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
    // still in the epoch the message is of
    assert!(device
        .decrypt_message(
            CONVERSATION,
            &cpim_message(&outer).get_info().unwrap(),
            &mls_message
        )
        .is_ok());

    assert_eq!(
        device
            .on_server_message(CONVERSATION, &focus_commit(&[&output.commit]))
            .map(|messages| messages.len()),
        Ok(1)
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));
}

#[test]
fn a_proposal_the_focus_forwards_is_kept_for_a_commit() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let proposal = bobs_group.leave(&bob).unwrap();
    let proposal_list = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(
            encode_message_list(&[&proposal]).unwrap(),
        )),
    });

    match device
        .on_server_message(CONVERSATION, &proposal_list)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Proposal { sender }] => assert_eq!(sender, bob.credential()),
        other => panic!("{} messages", other.len()),
    }
    let pending = device
        .store()
        .with_conversation(CONVERSATION.as_bytes(), |conversation, _| {
            Ok(conversation.mls_group().pending_proposals().count())
        });
    assert_eq!(pending, Ok(1));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
}

#[test]
fn the_commit_of_the_device_forwarded_back_is_applied() {
    let (bob, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let cpim = block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)]))
        .unwrap();
    let bundle = bundle_of(&cpim);
    let mut bobs_group = joined(&bob, &bundle);

    // as the Focus forwards it to all members, before it accepts it
    let forwarded = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: bundle.commit_list.clone(),
                welcome: bundle.welcome.clone(),
                private_message: Vec::new(),
                ratchet_tree: bundle.ratchet_tree.clone(),
            },
        )),
    });
    let previous = epoch_identifier(&device, CONVERSATION);
    assert!(matches!(
        device
            .on_server_message(CONVERSATION, &forwarded)
            .unwrap()
            .as_slice(),
        [IncomingMessage::Commit { .. }]
    ));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
    assert!(device
        .on_server_message(CONVERSATION, &accepted(previous))
        .is_ok());
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    let sent = device
        .encrypt_message(CONVERSATION, &plaintext("message-12", None))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&received_by_bob(&bob, &mut bobs_group, &sent))
            .ends_with("hello Bob")
    );

    // a refusal of what was applied is not taken
    let message_id = String::from_utf8(
        cpim_message(&cpim)
            .get_info()
            .unwrap()
            .imdn_message_id
            .to_vec(),
    )
    .unwrap();
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&message_id, "transient-error")),
        Ok(None)
    );
}

#[test]
fn a_commit_of_another_applied_first_voids_the_one_of_the_device() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, bob, mut bobs_group) = alice_and_bob();
    device
        .store()
        .with_conversation(CONVERSATION.as_bytes(), |conversation, client| {
            conversation.update_keys(client).map(|_| ())
        })
        .unwrap();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let waiting = rt.spawn(groups.encrypt(CONVERSATION, &plaintext("message-13", None)));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!waiting.is_finished(), "waits for the Commit");

    let output = bobs_group.update_keys(&bob).unwrap();
    bobs_group.merge_pending_commit(&bob).unwrap();
    groups.on_server_message(CONVERSATION, &focus_commit(&[&output.commit]));
    let sent = rt
        .block_on(waiting)
        .unwrap()
        .expect("sent in the epoch of the other Commit");
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));
    assert!(
        String::from_utf8_lossy(&received_by_bob(&bob, &mut bobs_group, &sent))
            .ends_with("hello Bob")
    );
}

/// The IMDN of the Conversation Focus refusing the message `message_id`
/// for `reason` (RCC.16 sections 6.2.5, 7.7.2.3)
fn refusal(message_id: &str, reason: &str) -> Vec<u8> {
    imdn(
        message_id,
        &format!(
            "<failed><mls-server-failure-reason><{}/></mls-server-failure-reason></failed>",
            reason
        ),
    )
}

fn imdn(message_id: &str, status: &str) -> Vec<u8> {
    imdn_with(message_id, status, "")
}

/// An IMDN with `extension` in its delivery notification, after the status
fn imdn_with(message_id: &str, status: &str, extension: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\
<message-id>{}</message-id>\
<datetime>2026-10-25T12:00:03.000+00:00</datetime>\
<delivery-notification><status>{}</status>{}</delivery-notification>\
</imdn>",
        message_id, status, extension
    )
    .into_bytes()
}

const INVALID_COMMIT: &str =
    "<mls-server-failure-reason><invalid-commit/></mls-server-failure-reason>";

/// The device with a group it made, and the Message-ID of the control
/// message of its Commit
fn group_made() -> (Arc<E2eeDevice>, String) {
    let (_, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let cpim = block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)]))
        .unwrap();
    let message_id = cpim_message(&cpim)
        .get_info()
        .unwrap()
        .imdn_message_id
        .to_vec();
    (device, String::from_utf8(message_id).unwrap())
}

#[test]
fn a_commit_the_focus_refuses_is_discarded() {
    let (device, message_id) = group_made();

    // what is not its refusal
    for (conversation_id, imdn) in [
        (CONVERSATION, refusal("another", "transient-error")),
        ("another", refusal(&message_id, "transient-error")),
        (CONVERSATION, imdn(&message_id, "<delivered/>")),
        (CONVERSATION, imdn(&message_id, "<failed/>")),
        (
            CONVERSATION,
            imdn(
                &message_id,
                "<failed><mls-client-failure-reason><invalid-commit/></mls-client-failure-reason></failed>",
            ),
        ),
        (
            CONVERSATION,
            imdn_with(&message_id, "<delivered/>", INVALID_COMMIT),
        ),
        (CONVERSATION, b"not an IMDN".to_vec()),
    ] {
        assert_eq!(
            device.on_imdn(conversation_id, &imdn),
            Ok(None),
            "{}",
            String::from_utf8_lossy(&imdn)
        );
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
    // nor is what the Focus sends that leaves it pending
    assert!(device.on_server_message(CONVERSATION, b"\x0a\xff").is_err());

    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&message_id, "transient-error")),
        Ok(Some(ServerFailureReason::TransientError))
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, false)));
    // the group is of the device alone
    assert_eq!(
        device.encrypt_message(CONVERSATION, &plaintext("message-14", None)),
        Err(MessageError::NotCreated)
    );
    // and refused once
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&message_id, "transient-error")),
        Ok(None)
    );
}

#[test]
fn a_group_abandoned_takes_no_refusal() {
    let (device, message_id) = group_made();
    device.abandon(CONVERSATION).unwrap();
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&message_id, "invalid-commit")),
        Ok(None)
    );
}

#[test]
fn messages_waiting_for_a_commit_the_focus_refuses_are_not_sent() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, message_id) = group_made();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let waiting = rt.spawn(groups.encrypt(CONVERSATION, &plaintext("message-15", None)));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!waiting.is_finished(), "waits for the Commit");

    assert!(!groups.on_imdn(CONVERSATION, &refusal("another", "invalid-commit")));
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!waiting.is_finished());

    // the reason where section 6.2.5 places it
    assert!(groups.on_imdn(
        CONVERSATION,
        &imdn_with(&message_id, "<failed/>", INVALID_COMMIT)
    ));
    assert_eq!(
        rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), waiting).await
        })
        .map(|sent| sent.unwrap()),
        Ok(None),
        "not sent, at once"
    );

    drop(device);
    assert!(!groups.on_imdn(CONVERSATION, &refusal(&message_id, "invalid-commit")));
}

/// An IMDN document of `message_id`, its notification `notification` with
/// `status`
fn notification_xml(message_id: &str, notification: &str, status: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<imdn xmlns=\"urn:ietf:params:xml:ns:imdn\">\
<message-id>{}</message-id>\
<datetime>2026-10-25T12:00:00.000Z</datetime>\
<{2}><status>{}</status></{2}>\
</imdn>",
        message_id, status, notification
    )
}

/// The CPIM message of Message-ID `cpim_id` carrying the notification `xml`,
/// from `from`, as the client sends one, with `extra` headers
fn notification_cpim(from: &str, cpim_id: &str, extra: &str, xml: &str) -> Vec<u8> {
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-10-25T12:00:04.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: {}\r\n\
{}\
\r\n\
Content-Type: message/imdn+xml\r\n\
Content-Disposition: notification\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        from,
        BOB_TEL,
        cpim_id,
        extra,
        xml.len(),
        xml
    )
    .into_bytes()
}

/// What the signature of a notification of the CPIM message `cpim_id` in
/// Era 0 covers, as Bob derives it
fn derived(cpim_id: &str, content: VerifiableDerivedContent) -> Vec<u8> {
    wire::encode(&AuthenticatedData::new(cpim_id.as_bytes(), b"", 0, content)).unwrap()
}

#[test]
fn a_notification_is_signed_over_what_it_tells_of() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let alice = credential(&[ALICE, CA]);

    for (xml, content) in [
        (
            notification_xml("bob-1", "delivery-notification", "<delivered/>"),
            VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
                DeliveryNotificationStatus::Delivered,
                b"bob-1",
                b"",
                ClientFailureReason::Unset,
            )),
        ),
        (
            notification_xml("bob-1", "display-notification", "<displayed/>"),
            VerifiableDerivedContent::DisplayImdn(VerifiableDisplayImdn::new(
                DisplayNotificationStatus::Displayed,
                b"bob-1",
                b"",
            )),
        ),
        // a negative delivery with the reason of the client
        (
            notification_xml(
                "bob-1",
                "delivery-notification",
                "<failed><mls-client-failure-reason><failed-to-decrypt/></mls-client-failure-reason></failed>",
            ),
            VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
                DeliveryNotificationStatus::Failed,
                b"bob-1",
                b"",
                ClientFailureReason::FailureToDecrypt,
            )),
        ),
    ] {
        let cpim = notification_cpim(IMPU, "imdn-1", "", &xml);
        let signed = device.sign_notification(CONVERSATION, &cpim).unwrap();

        // the headers added after those it had, the notification as it was
        let message = cpim_message(&signed);
        assert_eq!(
            header_names(&message),
            [
                "From",
                "To",
                "DateTime",
                "<urn:ietf:params:imdn>.Message-ID",
                "<http://www.gsma.com/rcs/mls>.MLS-Derived-Content-Signature",
                "<http://www.gsma.com/rcs/mls>.Era-ID",
            ]
        );
        assert_eq!(
            message.get_message_body(),
            Some((Some(&b"message/imdn+xml"[..]), xml.as_bytes(), false))
        );
        let text = String::from_utf8_lossy(&signed).into_owned();
        assert!(text.contains("\r\nmls.Era-ID: 0\r\n\r\n"), "{}", text);

        let signature = message
            .get_info()
            .unwrap()
            .mls_derived_content_signature
            .unwrap();
        let signature = general_purpose::STANDARD.decode(signature).unwrap();
        assert_eq!(
            bobs_group
                .verify_signature(&bob, &signature, &derived("imdn-1", content))
                .unwrap(),
            alice,
            "{}",
            xml
        );
    }
}

#[test]
fn a_notification_is_not_signed_unless_it_can_be() {
    let xml = notification_xml("bob-1", "delivery-notification", "<delivered/>");
    let cpim = notification_cpim(IMPU, "imdn-2", "", &xml);

    // while the Commit of the group waits, or once it is refused
    let (device, message_id) = group_made();
    assert_eq!(
        device.sign_notification(CONVERSATION, &cpim),
        Err(MessageError::Pending)
    );
    device
        .on_imdn(CONVERSATION, &refusal(&message_id, "invalid-commit"))
        .unwrap();
    assert_eq!(
        device.sign_notification(CONVERSATION, &cpim),
        Err(MessageError::NotCreated)
    );

    // what is no delivery or display notification, or no CPIM message, or
    // of no group
    let (device, _, _) = alice_and_bob();
    let processed = notification_cpim(
        IMPU,
        "imdn-3",
        "",
        &notification_xml("bob-1", "processing-notification", "<processed/>"),
    );
    for cpim in [
        processed,
        notification_cpim(IMPU, "imdn-4", "", "<not-an-imdn/>"),
        b"not a CPIM message".to_vec(),
    ] {
        assert_eq!(
            device.sign_notification(CONVERSATION, &cpim),
            Err(MessageError::NotCpim)
        );
    }
    assert_eq!(
        device.sign_notification("another", &cpim),
        Err(MessageError::Store(StoreError::Mls(
            ErrorKind::UnknownGroup
        )))
    );
}

/// Bob's notification of `xml`, in the CPIM message `cpim_id` from `from`,
/// signed over `content`
fn signed_by_bob(
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
    from: &str,
    cpim_id: &str,
    xml: &str,
    content: VerifiableDerivedContent,
) -> Vec<u8> {
    let signature = bobs_group.sign(bob, &derived(cpim_id, content)).unwrap();
    let extra = format!(
        "NS: mls <http://www.gsma.com/rcs/mls>\r\nmls.MLS-Derived-Content-Signature: {}\r\nmls.Era-ID: 0\r\n",
        general_purpose::STANDARD.encode(signature)
    );
    notification_cpim(from, cpim_id, &extra, xml)
}

#[test]
fn a_notification_received_is_taken_if_signed_by_whom_it_is_from() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let xml = notification_xml("message-1", "display-notification", "<displayed/>");
    let displayed = || {
        VerifiableDerivedContent::DisplayImdn(VerifiableDisplayImdn::new(
            DisplayNotificationStatus::Displayed,
            b"message-1",
            b"",
        ))
    };
    let verified = |cpim: &[u8], xml: &str| {
        device.verify_notification(
            CONVERSATION,
            &cpim_message(cpim).get_info().unwrap(),
            xml.as_bytes(),
        )
    };

    // by him, from him, in a SIP URI or a tel URI
    for from in ["sip:+491707654321@ims.example.com", BOB_TEL] {
        let cpim = signed_by_bob(&bob, &mut bobs_group, from, "imdn-5", &xml, displayed());
        assert_eq!(verified(&cpim, &xml), Ok(()), "{}", from);
    }

    // from another
    let cpim = signed_by_bob(
        &bob,
        &mut bobs_group,
        "sip:+491700000009@ims.example.com",
        "imdn-6",
        &xml,
        displayed(),
    );
    assert_eq!(verified(&cpim, &xml), Err(MessageError::NotFromSigner));

    // not over what it tells of: another notification, or another CPIM
    // message
    let cpim = signed_by_bob(&bob, &mut bobs_group, BOB_TEL, "imdn-7", &xml, displayed());
    let delivered = notification_xml("message-1", "delivery-notification", "<delivered/>");
    assert_eq!(
        verified(&cpim, &delivered),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::Rejected)))
    );
    let moved = String::from_utf8(cpim)
        .unwrap()
        .replace("imdn.Message-ID: imdn-7", "imdn.Message-ID: imdn-8");
    assert_eq!(
        verified(moved.as_bytes(), &xml),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::Rejected)))
    );

    // a signature that is none
    let cpim = notification_cpim(
        BOB_TEL,
        "imdn-9",
        "NS: mls <http://www.gsma.com/rcs/mls>\r\nmls.MLS-Derived-Content-Signature: %%%\r\n",
        &xml,
    );
    assert_eq!(
        verified(&cpim, &xml),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::BadFormat)))
    );

    // unsigned, only a negative delivery
    let cpim = notification_cpim(BOB_TEL, "imdn-10", "", &xml);
    assert_eq!(verified(&cpim, &xml), Err(MessageError::NotSigned));
    let failed = refusal("message-1", "transient-error");
    let failed = String::from_utf8(failed).unwrap();
    let cpim = notification_cpim(BOB_TEL, "imdn-11", "", &failed);
    assert_eq!(verified(&cpim, &failed), Ok(()));
}

#[test]
fn the_notifications_of_the_groups_of_the_device_are_signed_once_its_commit_is_accepted() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (bob, bobs) = bob_with_key_package();
    let (device, _) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    let cpim = block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)]))
        .unwrap();
    let mut bobs_group = joined(&bob, &bundle_of(&cpim));
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    let xml = notification_xml("bob-1", "delivery-notification", "<delivered/>");
    let waiting =
        rt.spawn(groups.sign(CONVERSATION, &notification_cpim(IMPU, "imdn-12", "", &xml)));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!waiting.is_finished(), "waits for the Commit");
    groups.on_server_message(
        CONVERSATION,
        &accepted(epoch_identifier(&device, CONVERSATION)),
    );
    let signed = rt.block_on(waiting).unwrap().expect("signed once accepted");
    let signature = cpim_message(&signed)
        .get_info()
        .unwrap()
        .mls_derived_content_signature
        .map(|signature| general_purpose::STANDARD.decode(signature).unwrap())
        .unwrap();
    let content = VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
        DeliveryNotificationStatus::Delivered,
        b"bob-1",
        b"",
        ClientFailureReason::Unset,
    ));
    assert!(bobs_group
        .verify_signature(&bob, &signature, &derived("imdn-12", content))
        .is_ok());

    // and those received checked
    let mine = notification_xml("message-1", "delivery-notification", "<delivered/>");
    let content = VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
        DeliveryNotificationStatus::Delivered,
        b"message-1",
        b"",
        ClientFailureReason::Unset,
    ));
    let cpim = signed_by_bob(&bob, &mut bobs_group, BOB_TEL, "imdn-13", &mine, content);
    let info = cpim_message(&cpim);
    assert!(groups.verify(CONVERSATION, &info.get_info().unwrap(), mine.as_bytes()));
    let unsigned = cpim_message(&notification_cpim(BOB_TEL, "imdn-14", "", &mine));
    assert!(!groups.verify(CONVERSATION, &unsigned.get_info().unwrap(), mine.as_bytes()));

    // nor what cannot be, nor once the device is let go of
    assert_eq!(rt.block_on(groups.sign(CONVERSATION, b"not CPIM")), None);
    drop(device);
    assert!(!groups.verify(CONVERSATION, &info.get_info().unwrap(), mine.as_bytes()));
    assert_eq!(
        rt.block_on(groups.sign(CONVERSATION, &notification_cpim(IMPU, "imdn-15", "", &xml))),
        None
    );
}

#[test]
fn a_notification_as_the_client_makes_one_is_signed() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let xml = notification_xml("bob-1", "delivery-notification", "<delivered/>");
    let body = make_cpim_imdn_body(&xml, BOB_TEL, IMPU);
    let mut cpim = Vec::new();
    body.reader().unwrap().read_to_end(&mut cpim).unwrap();

    let signed = device.sign_notification(CONVERSATION, &cpim).unwrap();
    let message = cpim_message(&signed);
    assert_eq!(
        message.get_message_body(),
        Some((Some(&b"message/imdn+xml"[..]), xml.as_bytes(), false))
    );
    let info = message.get_info().unwrap();
    let signature = general_purpose::STANDARD
        .decode(info.mls_derived_content_signature.unwrap())
        .unwrap();
    let content = VerifiableDerivedContent::DeliveryImdn(VerifiableDeliveryImdn::new(
        DeliveryNotificationStatus::Delivered,
        b"bob-1",
        b"",
        ClientFailureReason::Unset,
    ));
    let cpim_id = String::from_utf8(info.imdn_message_id.to_vec()).unwrap();
    assert!(bobs_group
        .verify_signature(&bob, &signature, &derived(&cpim_id, content))
        .is_ok());
}

/// A day both of the phones of the user and Bob have certificates for
const LATER: &str = "2026-10-01";

/// A client of `certificate` and its keys, checking certificates as of
/// LATER
fn client_later(certificate: &str, key: &str, public_key: &str) -> MlsClient {
    MlsClient::with_credential(
        credential(&[certificate, CA]),
        signer(key, public_key),
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(validator(LATER)),
    )
    .unwrap()
}

/// The device as of LATER, in the group of the conversation with the other
/// phone of the user, its Commit accepted, both in epoch 1: the device, the
/// other phone and its group, and Bob, of whom the Home KDS has a KeyPackage
fn group_to_add_bob_to() -> (Arc<E2eeDevice>, MlsClient, MlsConversation, MlsClient) {
    let phone = client_later(ALICE_RENEWED, ALICE_RENEWED_KEY, ALICE_RENEWED_PUBLIC_KEY);
    let bob = client_later(BOB, BOB_KEY, BOB_PUBLIC_KEY);
    let phones = phone.generate_key_package(false).unwrap();
    let bobs = bob.generate_key_package(false).unwrap();

    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app).knowing_too(vec![
        (ALICE_TEL, Fetched::KeyPackages(vec![phones])),
        (BOB_TEL, Fetched::KeyPackages(vec![bobs])),
    ]));
    let device = alice(&app, &kds, LATER, None);
    provision(&device, &[ALICE_TEL], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    let device = Arc::new(device);

    let cpim =
        block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(ALICE_TEL)]))
            .unwrap();
    let phones_group = joined(&phone, &bundle_of(&cpim));
    let previous = epoch_identifier(&device, CONVERSATION);
    device
        .on_server_message(CONVERSATION, &accepted(previous))
        .unwrap();
    (device, phone, phones_group, bob)
}

/// What the Conversation Focus forwards of a Commit it accepted, its
/// CommitList as the device sent it
fn forwarded(bundle: &WelcomeCommitBundle) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: bundle.commit_list.clone(),
                ..ServerCommitBundle::default()
            },
        )),
    })
}

#[test]
fn participants_are_added_with_a_commit_the_focus_forwards_back() {
    let (device, phone, mut phones_group, bob) = group_to_add_bob_to();
    let cpim =
        block_on(device.add_to_group(CONVERSATION, IMPU, GROUP_URI, vec![recipient(BOB_TEL)]))
            .unwrap();

    // the Commit, a Welcome for Bob, the GroupInfo and Epoch Authenticator,
    // without the tree the Focus keeps (RCC.16 section 7.9.2)
    let info = cpim_message(&cpim);
    let info = info.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());
    assert_eq!(
        info.disposition_notification,
        Some(&b"negative-delivery"[..])
    );
    let bundle = bundle_of(&cpim);
    assert!(!bundle.welcome.is_empty());
    assert!(!bundle.group_info.is_empty());
    assert!(!bundle.epoch_authenticator.is_empty());
    assert!(bundle.ratchet_tree.is_empty());
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, true)));

    // applied once forwarded back
    match device
        .on_server_message(CONVERSATION, &forwarded(&bundle))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { added, .. }] => {
            assert_eq!(added, &vec![credential(&[BOB, CA])])
        }
        other => panic!("{} messages", other.len()),
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));

    // Bob in the group, with the tree the Focus gives him, and the other
    // phone in the epoch too
    let tree = device
        .store()
        .with_conversation(CONVERSATION.as_bytes(), |conversation, _| {
            conversation.ratchet_tree()
        })
        .unwrap();
    let mut bobs_group = bob.join_conversation(&bundle.welcome, &tree).unwrap();
    assert!(phones_group
        .process_commit_bundle(
            &phone,
            &ServerCommitBundle {
                commit_list: bundle.commit_list.clone(),
                ..ServerCommitBundle::default()
            }
        )
        .is_ok());
    let sent = device
        .encrypt_message(CONVERSATION, &plaintext("message-16", None))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&received_by_bob(&bob, &mut bobs_group, &sent))
            .ends_with("hello Bob")
    );
    assert!(
        String::from_utf8_lossy(&received_by_bob(&phone, &mut phones_group, &sent))
            .ends_with("hello Bob")
    );
}

#[test]
fn participants_are_not_added_unless_each_can_be() {
    let (device, _, _, _) = group_to_add_bob_to();

    // one the Home KDS has no Client of
    assert_eq!(
        block_on(device.add_to_group(
            CONVERSATION,
            IMPU,
            GROUP_URI,
            vec![recipient(BOB_TEL), recipient(CAROL_TEL)]
        )),
        Err(GroupError::NotEncryptable(
            String::from(CAROL_TEL),
            Fetched::NotFound
        ))
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    // nor to a group there is not
    assert_eq!(
        block_on(device.add_to_group("another", IMPU, GROUP_URI, vec![recipient(BOB_TEL)])),
        Err(GroupError::Store(StoreError::Mls(ErrorKind::UnknownGroup)))
    );

    // nor while a Commit of the device waits, no KeyPackage taken for it
    let (_, bobs) = bob_with_key_package();
    let (device, kds) = enrolled(Some(vec![(BOB_TEL, Fetched::KeyPackages(vec![bobs]))]));
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(BOB_TEL)])).unwrap();
    assert_eq!(kds.queries.lock().unwrap().len(), 1);
    assert_eq!(
        block_on(device.add_to_group(CONVERSATION, IMPU, GROUP_URI, vec![recipient(BOB_TEL)])),
        Err(GroupError::Pending)
    );
    assert_eq!(kds.queries.lock().unwrap().len(), 1);
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
}

#[test]
fn a_commit_whose_request_the_focus_answers_with_an_error_is_discarded() {
    let (device, phone, mut phones_group, _) = group_to_add_bob_to();
    let control_id = |cpim: &[u8]| {
        String::from_utf8(
            cpim_message(cpim)
                .get_info()
                .unwrap()
                .imdn_message_id
                .to_vec(),
        )
        .unwrap()
    };

    // a refusal to follow, which is then taken
    let cpim =
        block_on(device.add_to_group(CONVERSATION, IMPU, GROUP_URI, vec![recipient(BOB_TEL)]))
            .unwrap();
    assert_eq!(device.discard_pending(CONVERSATION, true), Ok(()));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
    assert_eq!(
        device.on_imdn(
            CONVERSATION,
            &refusal(&control_id(&cpim), "incorrect-epoch")
        ),
        Ok(Some(ServerFailureReason::IncorrectEpoch))
    );

    // none to follow
    let cpim =
        block_on(device.add_to_group(CONVERSATION, IMPU, GROUP_URI, vec![recipient(BOB_TEL)]))
            .unwrap();
    assert_eq!(device.discard_pending(CONVERSATION, false), Ok(()));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&control_id(&cpim), "invalid-commit")),
        Ok(None)
    );

    // messages sent in the epoch the others are in
    let sent = device
        .encrypt_message(CONVERSATION, &plaintext("message-17", None))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&received_by_bob(&phone, &mut phones_group, &sent))
            .ends_with("hello Bob")
    );
}

#[test]
fn the_groups_of_the_device_are_added_to_once_its_commit_is_accepted() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let phone = client_later(ALICE_RENEWED, ALICE_RENEWED_KEY, ALICE_RENEWED_PUBLIC_KEY);
    let bob = client_later(BOB, BOB_KEY, BOB_PUBLIC_KEY);
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[ALICE, CA], &app).knowing_too(vec![
        (
            ALICE_TEL,
            Fetched::KeyPackages(vec![phone.generate_key_package(false).unwrap()]),
        ),
        (
            BOB_TEL,
            Fetched::KeyPackages(vec![bob.generate_key_package(false).unwrap()]),
        ),
    ]));
    let device = alice(&app, &kds, LATER, None);
    provision(&device, &[ALICE_TEL], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    let device = Arc::new(device);
    block_on(device.create_group(CONVERSATION, IMPU, FACTORY, vec![recipient(ALICE_TEL)])).unwrap();
    let (query, asked) = answering(&[(BOB_TEL, mls("42"))]);
    let groups = DeviceGroups::new(&device, query);

    // Bob added once the Commit making the group is accepted
    let adding = rt.spawn(groups.prepare_add(
        String::from(CONVERSATION),
        String::from(IMPU),
        String::from(GROUP_URI),
        vec![String::from(BOB_TEL)],
    ));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!adding.is_finished(), "waits for the Commit");
    groups.on_server_message(
        CONVERSATION,
        &accepted(epoch_identifier(&device, CONVERSATION)),
    );
    let cpim = rt.block_on(adding).unwrap().expect("added once accepted");
    assert!(!bundle_of(&cpim).welcome.is_empty());
    assert_eq!(*asked.lock().unwrap(), [BOB_TEL]);
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, true)));

    // a message waiting for that Commit sent once it is let go of
    let waiting = rt.spawn(groups.encrypt(CONVERSATION, &plaintext("message-18", None)));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!waiting.is_finished(), "waits for the Commit");
    groups.discard(CONVERSATION, false);
    assert!(rt.block_on(waiting).unwrap().is_some(), "sent in epoch 1");
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    // none who cannot encrypt, nor once the device is let go of
    assert_eq!(
        rt.block_on(groups.prepare_add(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            vec![String::from(CAROL_TEL)],
        )),
        None
    );
    drop(device);
    assert_eq!(
        rt.block_on(groups.prepare_add(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            vec![String::from(BOB_TEL)],
        )),
        None
    );
}

/// The bundle of a Commit without Welcome the CPIM message `cpim` carries
fn commit_bundle_of(cpim: &[u8]) -> CommitBundle {
    let message = cpim_message(cpim);
    let (content_type, content, _) = message.get_message_body().unwrap();
    assert_eq!(content_type, Some(CONTENT_TYPE_MLS_RCS_CLIENT));
    match proto::decode::<ClientMlsRcsMessage>(content)
        .unwrap()
        .payload
    {
        Some(client_mls_rcs_message::Payload::CommitBundle(bundle)) => bundle,
        _ => panic!("not a CommitBundle"),
    }
}

#[test]
fn a_participant_is_removed_with_all_of_its_clients() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let cpim = device
        .remove_from_group(CONVERSATION, IMPU, GROUP_URI, BOB_TEL)
        .unwrap();

    // the Commit, the GroupInfo and the Epoch Authenticator (RCC.16 section
    // 7.9.2), in a control message from the user to the group
    let info = cpim_message(&cpim);
    let info = info.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());
    assert_eq!(
        info.disposition_notification,
        Some(&b"negative-delivery"[..])
    );
    let bundle = commit_bundle_of(&cpim);
    assert!(!bundle.group_info.is_empty());
    assert!(!bundle.epoch_authenticator.is_empty());
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, true)));

    // applied once forwarded back, Bob out of the group
    let forwarded = ServerCommitBundle {
        commit_list: bundle.commit_list.clone(),
        ..ServerCommitBundle::default()
    };
    match device
        .on_server_message(
            CONVERSATION,
            &proto::encode(&ServerMlsRcsMessage {
                payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
                    forwarded.clone(),
                )),
            }),
        )
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { removed, .. }] => {
            assert_eq!(removed, &vec![credential(&[BOB, CA])])
        }
        other => panic!("{} messages", other.len()),
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));
    assert!(matches!(
        bobs_group
            .process_commit_bundle(&bob, &forwarded)
            .unwrap()
            .as_slice(),
        [IncomingMessage::Commit {
            self_removed: true,
            ..
        }]
    ));

    // reading nothing sent after
    let sent = device
        .encrypt_message(CONVERSATION, &plaintext("message-19", None))
        .unwrap();
    let sent = cpim_message(&sent);
    let (_, mls_message, _) = sent.get_message_body().unwrap();
    assert!(bobs_group
        .decrypt(&bob, mls_message, sent.get_info().unwrap().imdn_message_id)
        .is_err());
}

#[test]
fn a_participant_is_not_removed_unless_it_can_be() {
    let (device, _, _) = alice_and_bob();
    // none of whose Clients is a member, or the user, who leaves instead
    for tel_uri in [CAROL_TEL, ALICE_TEL] {
        assert_eq!(
            device.remove_from_group(CONVERSATION, IMPU, GROUP_URI, tel_uri),
            Err(GroupError::NotMember(String::from(tel_uri)))
        );
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
    assert_eq!(
        device.remove_from_group("another", IMPU, GROUP_URI, BOB_TEL),
        Err(GroupError::Store(StoreError::Mls(ErrorKind::UnknownGroup)))
    );

    // nor while a Commit of the device waits
    let (device, _) = group_made();
    assert_eq!(
        device.remove_from_group(CONVERSATION, IMPU, GROUP_URI, BOB_TEL),
        Err(GroupError::Pending)
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
}

#[test]
fn the_participants_of_the_groups_of_the_device_are_removed_once_its_commit_is_accepted() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, message_id) = group_made();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    // Bob, by the SIP URI of his number
    let removing = rt.spawn(groups.prepare_remove(
        String::from(CONVERSATION),
        String::from(IMPU),
        String::from(GROUP_URI),
        String::from("sip:+491707654321@ims.example.com"),
    ));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!removing.is_finished(), "waits for the Commit");
    groups.on_server_message(
        CONVERSATION,
        &accepted(epoch_identifier(&device, CONVERSATION)),
    );
    let cpim = rt
        .block_on(removing)
        .unwrap()
        .expect("removed once accepted");
    assert!(!commit_bundle_of(&cpim).commit_list.is_empty());
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, true)));
    // its control message the one now known
    assert!(!groups.on_imdn(CONVERSATION, &refusal(&message_id, "invalid-commit")));
    let removal_id = String::from_utf8(
        cpim_message(&cpim)
            .get_info()
            .unwrap()
            .imdn_message_id
            .to_vec(),
    )
    .unwrap();
    assert!(groups.on_imdn(CONVERSATION, &refusal(&removal_id, "invalid-commit")));
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    // nor one who is no member, nor by a URI of no number, nor once the
    // device is let go of
    for participant in ["sip:+491700000001@ims.example.com", "sip:bob@example.com"] {
        assert_eq!(
            rt.block_on(groups.prepare_remove(
                String::from(CONVERSATION),
                String::from(IMPU),
                String::from(GROUP_URI),
                String::from(participant),
            )),
            None,
            "{}",
            participant
        );
    }
    drop(device);
    assert_eq!(
        rt.block_on(groups.prepare_remove(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            String::from(BOB_TEL),
        )),
        None
    );
}

/// The Message-ID of the control message `cpim`
fn control_id(cpim: &[u8]) -> String {
    String::from_utf8(
        cpim_message(cpim)
            .get_info()
            .unwrap()
            .imdn_message_id
            .to_vec(),
    )
    .unwrap()
}

#[test]
fn the_user_leaves_with_a_self_remove_of_the_device_another_member_commits() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let cpim = device.leave_group(CONVERSATION, IMPU, GROUP_URI).unwrap();

    // a ProposalList (RCC.16 section 7.9.4), in a control message from the
    // user to the group
    let message = cpim_message(&cpim);
    let info = message.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());
    assert_eq!(
        info.disposition_notification,
        Some(&b"negative-delivery"[..])
    );
    let (content_type, content, _) = message.get_message_body().unwrap();
    assert_eq!(content_type, Some(CONTENT_TYPE_MLS_RCS_CLIENT));
    let list = match proto::decode::<ClientMlsRcsMessage>(content)
        .unwrap()
        .payload
    {
        Some(client_mls_rcs_message::Payload::ProposalList(list)) => list,
        _ => panic!("not a ProposalList"),
    };
    assert_eq!(wire::decode_message_list(&list).unwrap().len(), 1);
    // the group kept until the Focus agrees to the leave
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    // Bob, the Focus forwarding it to him, commits it
    let forwarded = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(list)),
    });
    match bobs_group
        .process_server_message(&bob, &forwarded)
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Proposal { sender }] => assert_eq!(sender, &credential(&[ALICE, CA])),
        other => panic!("{} messages", other.len()),
    }
    let output = bobs_group.commit_pending_proposals(&bob).unwrap();
    bobs_group.merge_pending_commit(&bob).unwrap();
    assert_eq!(bobs_group.members(), [credential(&[BOB, CA])]);
    match device
        .on_server_message(CONVERSATION, &focus_commit(&[&output.commit]))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { self_removed, .. }] => assert!(*self_removed),
        other => panic!("{} messages", other.len()),
    }
}

#[test]
fn a_leave_is_not_made_unless_it_can_be() {
    let (device, _, _) = alice_and_bob();
    assert_eq!(
        device.leave_group("another", IMPU, GROUP_URI),
        Err(GroupError::Store(StoreError::Mls(ErrorKind::UnknownGroup)))
    );

    // nor while a Commit of the device waits
    let (device, message_id) = group_made();
    assert_eq!(
        device.leave_group(CONVERSATION, IMPU, GROUP_URI),
        Err(GroupError::Pending)
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((0, true)));
    // its control message still the one known
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&message_id, "invalid-commit")),
        Ok(Some(ServerFailureReason::InvalidCommit))
    );
}

#[test]
fn a_leave_the_focus_refuses_is_withdrawn() {
    let (device, _, _) = alice_and_bob();

    // refused by an IMDN alone
    let cpim = device.leave_group(CONVERSATION, IMPU, GROUP_URI).unwrap();
    assert_eq!(
        device.on_imdn(
            CONVERSATION,
            &refusal(&control_id(&cpim), "transient-error")
        ),
        Ok(Some(ServerFailureReason::TransientError))
    );

    // answered with an error, a refusal to follow, which is then taken
    let cpim = device.leave_group(CONVERSATION, IMPU, GROUP_URI).unwrap();
    assert_eq!(device.discard_pending(CONVERSATION, true), Ok(()));
    assert_eq!(
        device.on_imdn(
            CONVERSATION,
            &refusal(&control_id(&cpim), "incorrect-epoch")
        ),
        Ok(Some(ServerFailureReason::IncorrectEpoch))
    );

    // none to follow
    let cpim = device.leave_group(CONVERSATION, IMPU, GROUP_URI).unwrap();
    assert_eq!(device.discard_pending(CONVERSATION, false), Ok(()));
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&control_id(&cpim), "invalid-commit")),
        Ok(None)
    );

    // the device commits as before, its self_remove gone
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
    assert!(device
        .remove_from_group(CONVERSATION, IMPU, GROUP_URI, BOB_TEL)
        .is_ok());
}

#[test]
fn the_groups_of_the_device_are_left_once_its_commit_is_accepted() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, message_id) = group_made();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    let leaving = rt.spawn(groups.prepare_leave(
        String::from(CONVERSATION),
        String::from(IMPU),
        String::from(GROUP_URI),
    ));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!leaving.is_finished(), "waits for the Commit");
    groups.on_server_message(
        CONVERSATION,
        &accepted(epoch_identifier(&device, CONVERSATION)),
    );
    let cpim = rt.block_on(leaving).unwrap().expect("left once accepted");
    // its control message the one now known
    assert!(!groups.on_imdn(CONVERSATION, &refusal(&message_id, "invalid-commit")));
    assert!(groups.on_imdn(CONVERSATION, &refusal(&control_id(&cpim), "invalid-commit")));

    // let go of once the Focus agrees
    groups.abandon(CONVERSATION);
    assert!(!groups.encrypts(CONVERSATION));

    // nor a group not kept, nor once the device is let go of
    assert_eq!(
        rt.block_on(groups.prepare_leave(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
        )),
        None
    );
    let (device, _, _) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    drop(device);
    assert_eq!(
        rt.block_on(groups.prepare_leave(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
        )),
        None
    );
}

/// What the Conversation Focus forwards of a leave: the ProposalList of the
/// self_remove `proposal` (RCC.16 section 9.4)
fn forwarded_leave(proposal: &[u8]) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(
            encode_message_list(&[proposal]).unwrap(),
        )),
    })
}

/// What the Conversation Focus forwards of the Commit the control message
/// `cpim` carries, without Welcome
fn forwarded_commit(cpim: &[u8]) -> Vec<u8> {
    proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: commit_bundle_of(cpim).commit_list,
                ..ServerCommitBundle::default()
            },
        )),
    })
}

const BOB_IMPU: &str = "sip:+491707654321@ims.example.com";

/// Bob's device as of LATER, in the group of the conversation with both
/// phones of Alice, its Commit accepted: the device, and each phone of Alice
/// with its group
fn bob_with_both_phones_of_alice() -> (
    Arc<E2eeDevice>,
    (MlsClient, MlsConversation),
    (MlsClient, MlsConversation),
) {
    let phone = client_later(ALICE, ALICE_KEY, ALICE_PUBLIC_KEY);
    let other_phone = client_later(ALICE_RENEWED, ALICE_RENEWED_KEY, ALICE_RENEWED_PUBLIC_KEY);
    let app = Arc::new(App::default());
    let kds = Arc::new(Kds::issuing(&[BOB, CA], &app).knowing_too(vec![(
        ALICE_TEL,
        Fetched::KeyPackages(vec![
            phone.generate_key_package(false).unwrap(),
            other_phone.generate_key_package(false).unwrap(),
        ]),
    )]));
    let device = E2eeDevice::new(
        validator(LATER),
        HOME_KDS,
        kds as Arc<dyn KeyDistribution>,
        Box::new(|_| true),
        None,
    )
    .unwrap()
    .with_signer(|| Some(signer(BOB_KEY, BOB_PUBLIC_KEY)));
    provision(&device, &[BOB_TEL], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    let device = Arc::new(device);

    let cpim =
        block_on(device.create_group(CONVERSATION, BOB_IMPU, FACTORY, vec![recipient(ALICE_TEL)]))
            .unwrap();
    let phones_group = joined(&phone, &bundle_of(&cpim));
    let other_phones_group = joined(&other_phone, &bundle_of(&cpim));
    let previous = epoch_identifier(&device, CONVERSATION);
    device
        .on_server_message(CONVERSATION, &accepted(previous))
        .unwrap();
    (
        device,
        (phone, phones_group),
        (other_phone, other_phones_group),
    )
}

#[test]
fn a_leave_the_focus_forwards_is_committed_with_the_other_clients_of_the_leaver() {
    let (device, (phone, mut phones_group), (other_phone, mut other_phones_group)) =
        bob_with_both_phones_of_alice();
    assert_eq!(
        device.commit_leaves(CONVERSATION, BOB_IMPU, GROUP_URI),
        Ok(None),
        "no one leaving"
    );

    // Alice leaves from one phone
    let proposal = phones_group.leave(&phone).unwrap();
    let forwarded = forwarded_leave(&proposal);
    assert!(matches!(
        device
            .on_server_message(CONVERSATION, &forwarded)
            .unwrap()
            .as_slice(),
        [IncomingMessage::Proposal { .. }]
    ));
    other_phones_group
        .process_server_message(&other_phone, &forwarded)
        .unwrap();
    let cpim = device
        .commit_leaves(CONVERSATION, BOB_IMPU, GROUP_URI)
        .unwrap()
        .expect("a Commit of the leave");

    // in a control message from Bob to the group (RCC.16 section 9.5.1)
    let info = cpim_message(&cpim);
    let info = info.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", BOB_IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());
    assert_eq!(
        info.disposition_notification,
        Some(&b"negative-delivery"[..])
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, true)));

    // removing both phones once forwarded back
    match device
        .on_server_message(CONVERSATION, &forwarded_commit(&cpim))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { removed, .. }] => {
            assert_eq!(removed.len(), 2);
            for phone in [&phone, &other_phone] {
                assert!(removed.contains(phone.credential()));
            }
        }
        other => panic!("{} messages", other.len()),
    }
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));
    for (client, group) in [
        (&phone, &mut phones_group),
        (&other_phone, &mut other_phones_group),
    ] {
        assert!(matches!(
            group
                .process_server_message(client, &forwarded_commit(&cpim))
                .unwrap()
                .as_slice(),
            [IncomingMessage::Commit {
                self_removed: true,
                ..
            }]
        ));
    }

    // its control message the one known
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&control_id(&cpim), "invalid-commit")),
        Ok(None),
        "applied already"
    );
}

#[test]
fn the_leave_of_the_user_from_another_client_is_left_for_others_to_commit() {
    let (device, phone, mut phones_group, _) = group_to_add_bob_to();
    let proposal = phones_group.leave(&phone).unwrap();
    device
        .on_server_message(CONVERSATION, &forwarded_leave(&proposal))
        .unwrap();
    assert_eq!(
        device.commit_leaves(CONVERSATION, IMPU, GROUP_URI),
        Ok(None)
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));
}

#[test]
fn a_leave_is_committed_once_the_commit_of_the_device_is_settled() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    // a Commit of the device made before Bob's leave came
    let removal = device
        .remove_from_group(CONVERSATION, IMPU, GROUP_URI, BOB_TEL)
        .unwrap();
    let proposal = bobs_group.leave(&bob).unwrap();
    assert!(groups.on_server_message(CONVERSATION, &forwarded_leave(&proposal)));
    assert_eq!(
        device.commit_leaves(CONVERSATION, IMPU, GROUP_URI),
        Err(GroupError::Pending)
    );

    // which the Focus refuses for leaving the leave out
    let committing = rt.spawn(groups.commit_leaves(
        String::from(CONVERSATION),
        String::from(IMPU),
        String::from(GROUP_URI),
    ));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!committing.is_finished(), "waits for the Commit");
    assert!(groups.on_imdn(
        CONVERSATION,
        &refusal(&control_id(&removal), "incorrect-epoch")
    ));
    let cpim = rt
        .block_on(committing)
        .unwrap()
        .expect("committed once refused");
    match device
        .on_server_message(CONVERSATION, &forwarded_commit(&cpim))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { removed, .. }] => {
            assert_eq!(removed, &vec![credential(&[BOB, CA])])
        }
        other => panic!("{} messages", other.len()),
    }

    // what is not a Proposal leaves nothing to commit, nor once the device
    // is let go of
    assert!(!groups.on_server_message(CONVERSATION, b"\x0a\xff"));
    drop(device);
    assert!(!groups.on_server_message(CONVERSATION, &forwarded_leave(&proposal)));
    assert_eq!(
        rt.block_on(groups.commit_leaves(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
        )),
        None
    );
}

#[test]
fn a_participant_the_server_removed_is_committed_out_with_server_remove() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let cpim = device
        .remove_for_server(CONVERSATION, IMPU, GROUP_URI, BOB_TEL)
        .unwrap();
    let info = cpim_message(&cpim);
    let info = info.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());

    // a server_remove Proposal (RCC.16 section 7.11.9) in the Commit
    let commit_list = commit_bundle_of(&cpim).commit_list;
    assert!(commit_list.windows(3).any(|w| w == [1, 0xF0, 0x04]));
    match device
        .on_server_message(CONVERSATION, &forwarded_commit(&cpim))
        .unwrap()
        .as_slice()
    {
        [IncomingMessage::Commit { removed, .. }] => {
            assert_eq!(removed, &vec![credential(&[BOB, CA])])
        }
        other => panic!("{} messages", other.len()),
    }
    assert!(matches!(
        bobs_group
            .process_server_message(&bob, &forwarded_commit(&cpim))
            .unwrap()
            .as_slice(),
        [IncomingMessage::Commit {
            self_removed: true,
            ..
        }]
    ));

    // none left once removed, as when another member's Commit came first
    assert_eq!(
        device.remove_for_server(CONVERSATION, IMPU, GROUP_URI, BOB_TEL),
        Err(GroupError::NotMember(String::from(BOB_TEL)))
    );
    // nor is the user
    assert_eq!(
        device.remove_for_server(CONVERSATION, IMPU, GROUP_URI, ALICE_TEL),
        Err(GroupError::NotMember(String::from(ALICE_TEL)))
    );
}

#[test]
fn the_participants_the_server_removed_from_groups_of_the_device_are_committed_out() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, _) = group_made();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    // Bob, by the SIP URI of his number, once the Commit making the group is
    // accepted
    let removing = rt.spawn(groups.remove_for_server(
        String::from(CONVERSATION),
        String::from(IMPU),
        String::from(GROUP_URI),
        String::from("sip:+491707654321@ims.example.com"),
    ));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!removing.is_finished(), "waits for the Commit");
    // which carries no Proposals
    assert!(!groups.on_server_message(
        CONVERSATION,
        &accepted(epoch_identifier(&device, CONVERSATION)),
    ));
    let cpim = rt
        .block_on(removing)
        .unwrap()
        .expect("removed once accepted");
    assert!(!commit_bundle_of(&cpim).commit_list.is_empty());
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, true)));
    groups.discard(CONVERSATION, false);

    // nor one who is no member, nor by a URI of no number, at once
    for participant in ["sip:+491700000001@ims.example.com", "sip:bob@example.com"] {
        assert_eq!(
            rt.block_on(groups.remove_for_server(
                String::from(CONVERSATION),
                String::from(IMPU),
                String::from(GROUP_URI),
                String::from(participant),
            )),
            None,
            "{}",
            participant
        );
    }
}

/// A Conversation Focus answering the INFO requests asking for GroupInfo
/// with `answers` in turn, keeping each request: its Info-Package and body
fn focus_answering(
    answers: Vec<Option<(u16, Vec<u8>)>>,
) -> (GroupInfoPull, Arc<Mutex<Vec<(Vec<u8>, Option<Vec<u8>>)>>>) {
    let answers = Arc::new(Mutex::new(answers.into_iter()));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asked_ = Arc::clone(&asked);
    let pull: GroupInfoPull = Arc::new(move |package, body| {
        asked_.lock().unwrap().push((package.to_vec(), body));
        let answer = answers.lock().unwrap().next().flatten();
        Box::pin(async move { answer })
    });
    (pull, asked)
}

/// Bob's Commit of a key update, which the Focus accepted and the device
/// missed, and the GroupInfo the Focus keeps since
fn missed_by_the_device(
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
) -> (Vec<u8>, MlsGroupInfo) {
    let output = bobs_group.update_keys(bob).unwrap();
    bobs_group.merge_pending_commit(bob).unwrap();
    let group_info = MlsGroupInfo {
        group_info: output.group_info.clone(),
        ratchet_tree: bobs_group.ratchet_tree().unwrap(),
        pending_proposals: Vec::new(),
    };
    (output.commit, group_info)
}

#[test]
fn a_group_that_missed_a_commit_is_healed_with_the_control_messages_the_focus_kept() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let device_epoch = epoch_identifier(&device, CONVERSATION);
    let (commit, group_info) = missed_by_the_device(&bob, &mut bobs_group);

    // not to be healed until something fails
    assert!(!groups.needs_healing(CONVERSATION));
    // Bob's message of the epoch the device missed
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_err());
    assert!(groups.needs_healing(CONVERSATION));

    // the Focus giving the Commit since the epoch the device asked from
    // (RCC.16 sections 7.10.3, 10.1.2)
    let latest = bobs_group.epoch_identifier();
    let enhanced = proto::encode(&MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(latest.clone()),
        mls_group_info: Some(group_info),
        committed_control_messages: vec![EpochControlMessages {
            rcs_message_id: String::from("focus-commit-1"),
            server_mls_rcs_message: Some(ServerMlsRcsMessage {
                payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
                    ServerCommitBundle {
                        commit_list: encode_message_list(&[&commit]).unwrap(),
                        ..ServerCommitBundle::default()
                    },
                )),
            }),
        }],
        paginated_epoch_identifier: Some(latest),
    });
    let (pull, asked) = focus_answering(vec![Some((200, enhanced))]);
    assert_eq!(
        rt.block_on(groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        )),
        None,
        "no External Commit"
    );
    assert_eq!(
        *asked.lock().unwrap(),
        [(
            INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL.to_vec(),
            Some(proto::encode(&device_epoch))
        )]
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));
    assert!(!groups.needs_healing(CONVERSATION));
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_ok());
}

#[test]
fn a_group_the_focus_cannot_catch_up_is_rejoined_with_an_external_commit() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let (_, group_info) = missed_by_the_device(&bob, &mut bobs_group);
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_err());

    // the epoch of the device unknown to the Focus: only its GroupInfo given
    let enhanced = proto::encode(&MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(bobs_group.epoch_identifier()),
        mls_group_info: Some(group_info),
        ..MlsEnhancedGroupInfo::default()
    });
    let (pull, asked) = focus_answering(vec![Some((200, enhanced))]);
    let cpim = rt
        .block_on(groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        ))
        .expect("an External Commit");
    assert_eq!(asked.lock().unwrap().len(), 1);

    // in a control message from the user to the group, applied already
    let info = cpim_message(&cpim);
    let info = info.get_info().unwrap();
    assert_eq!(info.from, format!("<{}>", IMPU).as_bytes());
    assert_eq!(info.to, format!("<{}>", GROUP_URI).as_bytes());
    assert_eq!(epoch(&device, CONVERSATION), Ok((3, false)));

    // which Bob takes, the device then back in step with him
    bobs_group
        .process_server_message(&bob, &forwarded_commit(&cpim))
        .unwrap();
    assert_eq!(bobs_group.members().len(), 2);
    let sent = device
        .encrypt_message(CONVERSATION, &plaintext("message-21", None))
        .unwrap();
    assert!(
        String::from_utf8_lossy(&received_by_bob(&bob, &mut bobs_group, &sent))
            .ends_with("hello Bob")
    );
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_ok());
    // forwarded back, it is the device's own
    assert!(device
        .on_server_message(CONVERSATION, &forwarded_commit(&cpim))
        .is_ok());
    assert_eq!(epoch(&device, CONVERSATION), Ok((3, false)));
}

#[test]
fn the_group_info_is_pulled_when_the_enhanced_one_is_not_given() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, bob, mut bobs_group) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let (_, group_info) = missed_by_the_device(&bob, &mut bobs_group);

    // pages that bring nothing new are not asked for again
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_err());
    let stuck = proto::encode(&MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(bobs_group.epoch_identifier()),
        paginated_epoch_identifier: Some(epoch_identifier(&device, CONVERSATION)),
        ..MlsEnhancedGroupInfo::default()
    });
    let (pull, asked) = focus_answering(vec![
        Some((200, stuck)),
        Some((469, Vec::new())),
        Some((469, Vec::new())),
    ]);
    assert_eq!(
        rt.block_on(groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        )),
        None
    );
    let packages: Vec<_> = asked
        .lock()
        .unwrap()
        .iter()
        .map(|(package, _)| package.clone())
        .collect();
    assert_eq!(
        packages,
        [
            INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL.to_vec(),
            INFO_PACKAGE_MLS_GROUP_INFO_PULL.to_vec()
        ]
    );

    // no MLS group with the Focus: nothing comes of it (RCC.16 section 6.3.1)
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_err());
    let (pull, asked) = focus_answering(vec![Some((469, Vec::new())), Some((469, Vec::new()))]);
    assert_eq!(
        rt.block_on(groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        )),
        None
    );
    let packages: Vec<_> = asked
        .lock()
        .unwrap()
        .iter()
        .map(|(package, body)| (package.clone(), body.is_some()))
        .collect();
    assert_eq!(
        packages,
        [
            (INFO_PACKAGE_MLS_ENHANCED_GROUP_INFO_PULL.to_vec(), true),
            (INFO_PACKAGE_MLS_GROUP_INFO_PULL.to_vec(), false)
        ]
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((1, false)));

    // the GroupInfo given, the group is rejoined from it
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_err());
    let pulled = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::MlsGroupInfo(group_info)),
    });
    let (pull, _) = focus_answering(vec![None, Some((200, pulled))]);
    let cpim = rt
        .block_on(groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        ))
        .expect("an External Commit");
    bobs_group
        .process_server_message(&bob, &forwarded_commit(&cpim))
        .unwrap();
    assert!(received_from_bob(&device, &bob, &mut bobs_group).is_ok());
}

#[test]
fn a_group_is_self_healed_once_at_a_time_and_not_too_often() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, _, _) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let up_to_date = || {
        proto::encode(&MlsEnhancedGroupInfo {
            latest_epoch_identifier: Some(epoch_identifier(&device, CONVERSATION)),
            ..MlsEnhancedGroupInfo::default()
        })
    };
    let heal = |pull: GroupInfoPull| {
        groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        )
    };

    // not unless it is to be
    let (pull, asked) = focus_answering(vec![Some((200, up_to_date()))]);
    assert_eq!(rt.block_on(heal(pull)), None);
    assert!(asked.lock().unwrap().is_empty());

    // while it is, messages wait, and it is not healed again
    let released = Arc::new(tokio::sync::Notify::new());
    let released_ = Arc::clone(&released);
    let answer = up_to_date();
    let held: GroupInfoPull = Arc::new(move |_, _| {
        let released = Arc::clone(&released_);
        let answer = answer.clone();
        Box::pin(async move {
            released.notified().await;
            Some((200, answer))
        })
    });
    device.heals().want(CONVERSATION);
    let healing = rt.spawn(heal(held));
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!groups.needs_healing(CONVERSATION));
    // what fails meanwhile is not healed again
    device.heals().want(CONVERSATION);
    let (pull, asked) = focus_answering(vec![Some((200, up_to_date()))]);
    assert_eq!(rt.block_on(heal(pull)), None);
    assert!(asked.lock().unwrap().is_empty());
    let waiting = rt.spawn(groups.encrypt(CONVERSATION, &plaintext("message-22", None)));
    let xml = notification_xml("bob-1", "delivery-notification", "<delivered/>");
    let signing =
        rt.spawn(groups.sign(CONVERSATION, &notification_cpim(IMPU, "imdn-22", "", &xml)));
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(!waiting.is_finished(), "waits for the group to be healed");
    assert!(!signing.is_finished(), "waits for the group to be healed");
    released.notify_one();
    assert_eq!(rt.block_on(healing).unwrap(), None);
    assert!(rt.block_on(waiting).unwrap().is_some(), "sent once healed");
    assert!(
        rt.block_on(signing).unwrap().is_some(),
        "signed once healed"
    );
    assert!(!groups.needs_healing(CONVERSATION));

    // four more times in a day, and no more (RCC.16 section 10.1)
    for _ in 0..4 {
        device.heals().want(CONVERSATION);
        let (pull, asked) = focus_answering(vec![Some((200, up_to_date()))]);
        rt.block_on(heal(pull));
        assert_eq!(asked.lock().unwrap().len(), 1);
    }
    device.heals().want(CONVERSATION);
    let (pull, asked) = focus_answering(vec![Some((200, up_to_date()))]);
    assert_eq!(rt.block_on(heal(pull)), None);
    assert!(asked.lock().unwrap().is_empty());
}

#[test]
fn a_group_is_to_be_healed_once_out_of_step_with_its_focus() {
    let (device, _, _) = alice_and_bob();

    // a refusal saying so, of a message or a control message (RCC.16
    // section 6.2.5)
    for reason in [
        "incorrect-epoch-authenticator",
        "mismatched-confirmation-tag",
    ] {
        let (device, _, _) = alice_and_bob();
        assert_eq!(
            device.on_imdn(CONVERSATION, &refusal("message-23", reason)),
            Ok(None)
        );
        assert!(device.needs_healing(CONVERSATION), "{}", reason);
    }
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal("message-23", "transient-error")),
        Ok(None)
    );
    assert!(!device.needs_healing(CONVERSATION));

    // what is not even an MLS message is not
    let garbage = cpim_message(&plaintext("message-24", None));
    assert!(device
        .decrypt_message(CONVERSATION, &garbage.get_info().unwrap(), b"not MLS")
        .is_err());
    assert!(!device.needs_healing(CONVERSATION));

    // a control message of the Focus that cannot be applied (section 6.2.6)
    assert!(device.on_server_message(CONVERSATION, b"\x0a\xff").is_err());
    assert!(device.needs_healing(CONVERSATION));
}

#[test]
fn a_commit_of_the_device_the_focus_kept_is_applied_by_healing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, _, _) = alice_and_bob();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);
    let cpim = device
        .remove_from_group(CONVERSATION, IMPU, GROUP_URI, BOB_TEL)
        .unwrap();

    // the Focus accepted it, which the device was not told
    let bundle = commit_bundle_of(&cpim);
    let latest = EpochIdentifier {
        epoch_id: 2,
        epoch_authenticator: bundle.epoch_authenticator.clone(),
        ..epoch_identifier(&device, CONVERSATION)
    };
    let enhanced = proto::encode(&MlsEnhancedGroupInfo {
        latest_epoch_identifier: Some(latest.clone()),
        committed_control_messages: vec![EpochControlMessages {
            rcs_message_id: control_id(&cpim),
            server_mls_rcs_message: Some(ServerMlsRcsMessage {
                payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
                    ServerCommitBundle {
                        commit_list: bundle.commit_list,
                        ..ServerCommitBundle::default()
                    },
                )),
            }),
        }],
        paginated_epoch_identifier: Some(latest),
        ..MlsEnhancedGroupInfo::default()
    });
    device.heals().want(CONVERSATION);
    let (pull, _) = focus_answering(vec![Some((200, enhanced))]);
    assert_eq!(
        rt.block_on(groups.heal(
            String::from(CONVERSATION),
            String::from(IMPU),
            String::from(GROUP_URI),
            pull,
        )),
        None
    );
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));
    // its control message no longer waits for a refusal
    assert_eq!(
        device.on_imdn(CONVERSATION, &refusal(&control_id(&cpim), "invalid-commit")),
        Ok(None)
    );
}
