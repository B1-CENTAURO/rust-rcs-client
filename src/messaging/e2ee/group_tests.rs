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

use std::sync::{Arc, Mutex};

use futures::executor::block_on;
use rust_rcs_core::cpim::{CPIMHeaders, CPIMMessage};
use rust_rcs_core::internet::Body;
use rust_rcs_core::mls::rcs::certificate::CertificateError;
use rust_rcs_core::mls::rcs::proto::{
    self, client_mls_rcs_message, server_mls_rcs_message, AcceptedMlsRcsMessage,
    ClientMlsRcsMessage, EpochIdentifier, ServerCommitBundle, ServerMlsRcsMessage,
    WelcomeCommitBundle,
};
use rust_rcs_core::mls::rcs::wire::encode_message_list;
use rust_rcs_core::mls::rcs::{is_unencrypted_cpim_header, CONTENT_TYPE_MLS_RCS_CLIENT};
use rust_rcs_core::mls::{ErrorKind, IncomingMessage, MlsClient, MlsConfig, MlsConversation};

use crate::capability::{Capabilities, CapabilityQuery};
use crate::messaging::cpm::encryption::GroupEncryption;

use super::device::{E2eeDevice, Enrolled, CIPHERSUITE};
use super::device_tests::{alice, provision};
use super::group::{recipients, DeviceGroups, GroupError};
use super::kds::{Fetched, KdsError, Recipient};
use super::kds_tests::certificates::*;
use super::kds_tests::{bob, credential, signer, validator, App, Kds, ALICE_TEL, BOB_TEL, TODAY};
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
    let app = Arc::new(App::default());
    let kds = Kds::issuing(&[ALICE, CA], &app);
    let kds = Arc::new(match directory {
        Some(directory) => kds.knowing_too(directory),
        None => kds,
    });
    let device = alice(&app, &kds, TODAY, None);
    provision(&device, &[ALICE_TEL], None);
    assert_eq!(block_on(device.enrol()), Ok(Enrolled::Now));
    (Arc::new(device), kds)
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
    match device.on_server_message(CONVERSATION, &accepted(previous)) {
        Ok(IncomingMessage::Commit { added, .. }) => {
            assert_eq!(added, vec![credential(&[BOB, CA])])
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

    // what is for members, and what is no message
    let group_info = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ProposalList(vec![0])),
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
