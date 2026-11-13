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

//! The signalling and the media of the Group RCS Video Chats of encrypted
//! groups (RCC.16 section 9.8.2)

use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose, Engine as _};
use prost::Message;
use rust_rcs_core::mls::rcs::sframe::{SframeSession, DEFAULT_LAYOUT};
use rust_rcs_core::mls::rcs::wire::{self, VerifiableVideoChatMessage};
use rust_rcs_core::mls::{ErrorKind, MlsClient, MlsConversation};

use crate::video_chat::proto::{
    video_chat_message, AckInvitation, ClientGroupVideoMessage, VideoChatMessage,
};

use super::device::E2eeDevice;
use super::group::DeviceGroups;
use super::group_tests::{
    accepted, alice_and_bob, alice_and_bob_in_time, alice_and_bob_in_time_with_kds, answering,
    bundle_of, commit_bundle_of, cpim_message, epoch, epoch_identifier, focus_commit, header_names,
    joined, missed_by_the_device, notification_cpim, notification_xml, recipient,
    uploaded_key_package, Clock, CONVERSATION, DAY, FACTORY, GROUP_URI, IMPU,
};
use super::kds_tests::certificates::*;
use super::kds_tests::{credential, BOB_TEL};
use super::message::MessageError;
use super::store::StoreError;
use super::video::{
    same_participant, FrameError, ASKED_KEPT, COMMITTER_WAIT, FRAME_OVERHEAD, RECEIPTS_WAIT, SUITE,
};
use crate::messaging::cpm::encryption::{GroupEncryption, Verified};

/// A VideoChatMessage of the call `call_id`, encoded
fn video_chat_message(call_id: &str) -> Vec<u8> {
    VideoChatMessage {
        call_id: String::from(call_id),
        event: Some(video_chat_message::Event::AckInvitation(AckInvitation {})),
    }
    .encode_to_vec()
}

/// The CPIM message of Message-ID `cpim_id` from `from` to the group,
/// carrying `message`, Base64 encoded as the client sends it, with the CPIM
/// headers `extra`
fn video_chat_cpim(from: &str, cpim_id: &str, extra: &str, message: &[u8]) -> Vec<u8> {
    let encoded = general_purpose::STANDARD.encode(message);
    format!(
        "From: <{}>\r\n\
To: <{}>\r\n\
DateTime: 2026-11-13T12:00:00.000+00:00\r\n\
NS: imdn <urn:ietf:params:imdn>\r\n\
imdn.Message-ID: {}\r\n\
{}\
\r\n\
Content-Type: rcs/video-chat+proto\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        from,
        GROUP_URI,
        cpim_id,
        extra,
        encoded.len(),
        encoded
    )
    .into_bytes()
}

/// The ClientGroupVideoMessage carrying `video_chat_message`, encoded
fn client_message(video_chat_message: &[u8]) -> Vec<u8> {
    ClientGroupVideoMessage {
        video_chat_message: video_chat_message.to_vec(),
        sdp: String::from("v=0"),
        event: None,
    }
    .encode_to_vec()
}

/// What the signature of `video_chat_message` sent in the CPIM message of
/// Message-ID `cpim_id` covers (RCC.16 section 7.6.3.4)
fn derived(cpim_id: &str, video_chat_message: &[u8]) -> Vec<u8> {
    wire::encode(&VerifiableVideoChatMessage::new(
        video_chat_message,
        cpim_id.as_bytes(),
    ))
    .unwrap()
}

#[test]
fn the_signalling_of_a_group_video_chat_is_signed_over_its_video_chat_message() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let alice = credential(&[ALICE, CA]);
    let message = video_chat_message("call-1");
    let cpim = video_chat_cpim(IMPU, "video-1", "", &client_message(&message));

    // as sign() signs it, with the headers after those it had, and not the
    // Era-ID, which the VerifiableVideoChatMessage does not cover
    let signed = device.sign_message(CONVERSATION, &cpim).unwrap();
    let signed_message = cpim_message(&signed);
    assert_eq!(
        header_names(&signed_message),
        [
            "From",
            "To",
            "DateTime",
            "<urn:ietf:params:imdn>.Message-ID",
            "<http://www.gsma.com/rcs/mls>.MLS-Derived-Content-Signature",
        ]
    );
    let (content_type, content, base64_encoded) = signed_message.get_message_body().unwrap();
    assert_eq!(content_type, Some(&b"rcs/video-chat+proto"[..]));
    assert!(base64_encoded);
    assert_eq!(
        general_purpose::STANDARD.decode(content).unwrap(),
        client_message(&message)
    );

    // over the VideoChatMessage it carries end to end, and the Message-ID,
    // not the SDP for the SFU
    let signature = signed_message
        .get_info()
        .unwrap()
        .mls_derived_content_signature
        .unwrap();
    let signature = general_purpose::STANDARD.decode(signature).unwrap();
    assert_eq!(
        bobs_group
            .verify_signature(&bob, &signature, &derived("video-1", &message))
            .unwrap(),
        alice
    );
    assert_eq!(
        bobs_group.verify_signature(&bob, &signature, &derived("video-2", &message)),
        Err(ErrorKind::Rejected)
    );

    // what is no ClientGroupVideoMessage is not
    let not_one = video_chat_cpim(IMPU, "video-3", "", b"\xff\xff");
    assert_eq!(
        device.sign_video_chat(CONVERSATION, &not_one),
        Err(MessageError::NotCpim)
    );
    // and a notification is signed as one, with the Era-ID
    let xml = notification_xml("bob-1", "delivery-notification", "<delivered/>");
    let notification = notification_cpim(IMPU, "imdn-1", "", &xml);
    let signed = device.sign_message(CONVERSATION, &notification).unwrap();
    assert!(header_names(&cpim_message(&signed))
        .contains(&String::from("<http://www.gsma.com/rcs/mls>.Era-ID")));
}

#[test]
fn the_signalling_of_a_group_video_chat_is_not_signed_unless_it_can_be() {
    let (device, _, _, clock) = alice_and_bob_in_time();
    let cpim = video_chat_cpim(
        IMPU,
        "video-4",
        "",
        &client_message(&video_chat_message("call-1")),
    );
    assert_eq!(
        device.sign_video_chat("another", &cpim),
        Err(MessageError::Store(StoreError::Mls(
            ErrorKind::UnknownGroup
        )))
    );
    // while a Commit of the device waits for the Focus
    clock.advance(31 * DAY);
    device
        .update_keys(CONVERSATION, IMPU, GROUP_URI)
        .unwrap()
        .expect("a control message");
    assert_eq!(
        device.sign_video_chat(CONVERSATION, &cpim),
        Err(MessageError::Pending)
    );
}

/// Bob's signal `message` in the CPIM message `cpim_id` from `from`, signed
/// over `signed_over` in the CPIM message `signed_id`
fn signed_by_bob(
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
    from: &str,
    cpim_id: &str,
    signed_id: &str,
    signed_over: &[u8],
) -> Vec<u8> {
    let signature = bobs_group
        .sign(bob, &derived(signed_id, signed_over))
        .unwrap();
    let extra = format!(
        "NS: mls <http://www.gsma.com/rcs/mls>\r\nmls.MLS-Derived-Content-Signature: {}\r\n",
        general_purpose::STANDARD.encode(signature)
    );
    video_chat_cpim(from, cpim_id, &extra, b"relayed")
}

#[test]
fn a_video_chat_message_relayed_is_taken_signed_by_its_participant() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let message = video_chat_message("call-1");
    let verified = |cpim: &[u8], message: &[u8]| {
        device.verify_video_chat(
            CONVERSATION,
            &cpim_message(cpim).get_info().unwrap(),
            message,
        )
    };

    // by him, from him, in a SIP URI or a tel URI
    for from in ["sip:+491707654321@ims.example.com", BOB_TEL] {
        let cpim = signed_by_bob(&bob, &mut bobs_group, from, "video-5", "video-5", &message);
        assert_eq!(verified(&cpim, &message), Ok(()), "{}", from);
    }

    // from another
    let cpim = signed_by_bob(
        &bob,
        &mut bobs_group,
        "tel:+491700000009",
        "video-6",
        "video-6",
        &message,
    );
    assert_eq!(verified(&cpim, &message), Err(MessageError::NotFromSigner));

    // not over what it relays, or not in the CPIM message it was sent in
    let cpim = signed_by_bob(
        &bob,
        &mut bobs_group,
        BOB_TEL,
        "video-7",
        "video-7",
        &message,
    );
    assert_eq!(
        verified(&cpim, &video_chat_message("call-2")),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::Rejected)))
    );
    let cpim = signed_by_bob(
        &bob,
        &mut bobs_group,
        BOB_TEL,
        "video-8",
        "video-9",
        &message,
    );
    assert_eq!(
        verified(&cpim, &message),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::Rejected)))
    );

    // a signature that is none, or no signature
    let cpim = video_chat_cpim(
        BOB_TEL,
        "video-10",
        "NS: mls <http://www.gsma.com/rcs/mls>\r\nmls.MLS-Derived-Content-Signature: %%%\r\n",
        b"relayed",
    );
    assert_eq!(
        verified(&cpim, &message),
        Err(MessageError::Store(StoreError::Mls(ErrorKind::BadFormat)))
    );
    let cpim = video_chat_cpim(BOB_TEL, "video-11", "", b"relayed");
    assert_eq!(verified(&cpim, &message), Err(MessageError::NotSigned));
}

/// The keys of the call `call_id` Bob has in `bobs_group`
pub(super) fn keys_of_bob(bob: &MlsClient, bobs_group: &MlsConversation) -> SframeSession {
    SframeSession::of(bobs_group, bob, SUITE, DEFAULT_LAYOUT, 7).unwrap()
}

/// Has the device tell what the keys of its calls switched to
fn switches(device: &E2eeDevice) -> Arc<Mutex<Vec<(String, u64)>>> {
    let switched = Arc::new(Mutex::new(Vec::new()));
    let told = Arc::clone(&switched);
    device.set_call_keys_listener(Arc::new(move |call_id, epoch| {
        told.lock().unwrap().push((String::from(call_id), epoch));
    }));
    switched
}

/// The epoch of the frame `encrypted` Bob decrypts, and the frame
fn bob_decrypts(bobs_keys: &mut SframeSession, encrypted: &[u8]) -> (u64, Vec<u8>) {
    let frame = bobs_keys.decrypt(b"meta", encrypted).unwrap();
    (frame.epoch, frame.frame)
}

#[test]
fn the_media_of_a_group_call_is_encrypted_with_the_keys_of_its_mls_group() {
    let (device, bob, bobs_group) = alice_and_bob();
    // of a group chat encrypted end to end alone
    assert_eq!(device.start_call_keys("call-1", "another"), Ok(false));
    assert!(!device.encrypts_call("call-1"));
    assert_eq!(
        device.encrypt_call_frame("call-1", b"meta", b"frame"),
        Err(FrameError::NoKeys)
    );
    assert_eq!(device.start_call_keys("call-1", CONVERSATION), Ok(true));
    assert!(device.encrypts_call("call-1"));

    // both ways, each frame once
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert!(encrypted.len() <= b"frame 1".len() + FRAME_OVERHEAD);
    assert_eq!(
        bob_decrypts(&mut bobs_keys, &encrypted),
        (1, b"frame 1".to_vec())
    );
    let from_bob = bobs_keys.encrypt(b"meta", b"frame 2").unwrap();
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Ok(b"frame 2".to_vec())
    );
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Err(FrameError::Replayed)
    );
    // not with other metadata
    let from_bob = bobs_keys.encrypt(b"meta", b"frame 3").unwrap();
    assert_eq!(
        device.decrypt_call_frame("call-1", b"other", &from_bob),
        Err(FrameError::Rejected)
    );
    // nor once the call ended
    device.end_call_keys("call-1");
    assert!(!device.encrypts_call("call-1"));
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Err(FrameError::NoKeys)
    );
}

/// The Commit of a key update of the device, its control message and
/// Message-ID, accepted by the Focus, the group in epoch 2
pub(super) fn device_commits(device: &E2eeDevice, clock: &Clock) -> (Vec<u8>, String) {
    clock.advance(31 * DAY);
    let cpim = device
        .update_keys(CONVERSATION, IMPU, GROUP_URI)
        .unwrap()
        .expect("a control message");
    let message_id =
        String::from_utf8_lossy(cpim_message(&cpim).get_info().unwrap().imdn_message_id)
            .into_owned();
    let previous = epoch_identifier(device, CONVERSATION);
    device
        .on_server_message(CONVERSATION, &accepted(previous))
        .unwrap();
    assert_eq!(epoch(device, CONVERSATION), Ok((2, false)));
    (cpim, message_id)
}

/// Bob takes the Commit the control message `cpim` of the device carries,
/// and the keys of his call those of the new epoch, sent in by the device
fn bob_takes(
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
    bobs_keys: &mut SframeSession,
    cpim: &[u8],
) {
    bobs_group
        .process_commit_bundle(
            bob,
            &rust_rcs_core::mls::rcs::proto::ServerCommitBundle {
                commit_list: commit_bundle_of(cpim).commit_list,
                ..Default::default()
            },
        )
        .unwrap();
    let alice = bobs_group.leaf_index_of(&credential(&[ALICE, CA])).unwrap();
    bobs_keys.advance_with(bobs_group, bob, alice).unwrap();
}

/// The delivery notification of `message_id` from Bob
fn delivered_by_bob(device: &E2eeDevice, message_id: &str, status: &str) -> bool {
    let xml = notification_xml(message_id, "delivery-notification", status);
    let cpim = notification_cpim(BOB_TEL, "imdn-20", "", &xml);
    device.commit_delivered(
        CONVERSATION,
        &cpim_message(&cpim).get_info().unwrap(),
        xml.as_bytes(),
    )
}

#[test]
fn the_committer_sends_in_the_new_epoch_once_the_others_in_the_call_delivered_its_commit() {
    let (device, bob, mut bobs_group, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);

    // its Commit asking to be told of its delivery during the call
    let (cpim, message_id) = device_commits(&device, &clock);
    assert_eq!(
        cpim_message(&cpim)
            .get_info()
            .unwrap()
            .disposition_notification,
        Some(&b"positive-delivery, negative-delivery"[..])
    );

    // sending in the epoch before until Bob delivers it
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 1);
    bob_takes(&bob, &mut bobs_group, &mut bobs_keys, &cpim);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 2")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 1);
    // but taking frames of the new epoch at once
    let mut ahead = keys_of_bob_in(&bob, &bobs_group);
    let from_bob = ahead.encrypt(b"meta", b"frame 3").unwrap();
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Ok(b"frame 3".to_vec())
    );
    assert!(switched.lock().unwrap().is_empty());

    // a notification of another message, or not of its delivery, is for the
    // app
    assert!(!delivered_by_bob(&device, "message-1", "<delivered/>"));
    let display = notification_xml(&message_id, "display-notification", "<displayed/>");
    let cpim_info = notification_cpim(BOB_TEL, "imdn-21", "", &display);
    assert!(!device.commit_delivered(
        CONVERSATION,
        &cpim_message(&cpim_info).get_info().unwrap(),
        display.as_bytes()
    ));
    assert!(switched.lock().unwrap().is_empty());

    // Bob delivering it, the keys switch, the app told to send a frame
    assert!(delivered_by_bob(&device, &message_id, "<delivered/>"));
    assert_eq!(*switched.lock().unwrap(), [(String::from("call-1"), 2)]);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 4")
        .unwrap();
    assert_eq!(
        bob_decrypts(&mut bobs_keys, &encrypted),
        (2, b"frame 4".to_vec())
    );
    // and Bob switching with it
    assert_eq!(bobs_keys.sending_epoch(), 2);

    // a receipt again is not for the app, and switches nothing more
    assert!(delivered_by_bob(&device, &message_id, "<delivered/>"));
    assert_eq!(switched.lock().unwrap().len(), 1);
}

/// Keys of Bob's sending in the epoch his group is in
fn keys_of_bob_in(bob: &MlsClient, bobs_group: &MlsConversation) -> SframeSession {
    SframeSession::of(bobs_group, bob, SUITE, DEFAULT_LAYOUT, 9).unwrap()
}

#[test]
fn the_committer_waits_only_for_the_participants_in_the_call() {
    let (device, _, _, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants(
        "call-1",
        vec![String::from(BOB_TEL), String::from("tel:+491700000009")],
    );
    let (_, message_id) = device_commits(&device, &clock);

    // Bob delivering it, the other still to
    assert!(delivered_by_bob(&device, &message_id, "<delivered/>"));
    assert!(switched.lock().unwrap().is_empty());
    // the other leaving the call
    device.call_participants(
        "call-1",
        vec![String::from("sip:+491707654321@ims.example.com")],
    );
    assert_eq!(*switched.lock().unwrap(), [(String::from("call-1"), 2)]);
}

#[test]
fn the_committer_alone_in_the_call_switches_at_once() {
    let (device, _, _, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device_commits(&device, &clock);
    assert_eq!(*switched.lock().unwrap(), [(String::from("call-1"), 2)]);
}

#[test]
fn the_committer_switches_all_the_same_once_its_wait_runs_out() {
    let (device, bob, mut bobs_group, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);
    let (cpim, _) = device_commits(&device, &clock);
    bob_takes(&bob, &mut bobs_group, &mut bobs_keys, &cpim);

    clock.advance(RECEIPTS_WAIT - std::time::Duration::from_millis(1));
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 1);
    clock.advance(std::time::Duration::from_millis(1));
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 2")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 2);
    assert_eq!(*switched.lock().unwrap(), [(String::from("call-1"), 2)]);

    // as it does on a frame received too
    let (device, bob, bobs_group, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);
    device_commits(&device, &clock);
    clock.advance(RECEIPTS_WAIT);
    let from_bob = bobs_keys.encrypt(b"meta", b"frame 3").unwrap();
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Ok(b"frame 3".to_vec())
    );
    assert_eq!(*switched.lock().unwrap(), [(String::from("call-1"), 2)]);
}

/// The Commit of a key update of Bob, applied by the device and Bob, the
/// keys of Bob's call sending in its epoch
fn bob_commits(
    device: &E2eeDevice,
    bob: &MlsClient,
    bobs_group: &mut MlsConversation,
    bobs_keys: &mut SframeSession,
) {
    let output = bobs_group.update_keys(bob).unwrap();
    device
        .on_server_message(CONVERSATION, &focus_commit(&[&output.commit]))
        .unwrap();
    bobs_group.merge_pending_commit(bob).unwrap();
    let own = bobs_group.own_leaf_index();
    bobs_keys.advance_with(bobs_group, bob, own).unwrap();
    bobs_keys.switch_to_new_epoch();
}

#[test]
fn the_others_send_in_the_new_epoch_once_the_committer_does() {
    let (device, bob, mut bobs_group, _) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);
    bob_commits(&device, &bob, &mut bobs_group, &mut bobs_keys);

    // in the epoch before until a frame of Bob in the new one comes
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 1);
    let from_bob = bobs_keys.encrypt(b"meta", b"frame 2").unwrap();
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Ok(b"frame 2".to_vec())
    );
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 3")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 2);
    // the app not told: it is not the committer
    assert!(switched.lock().unwrap().is_empty());
}

#[test]
fn the_others_switch_all_the_same_once_their_wait_runs_out() {
    let (device, bob, mut bobs_group, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);
    bob_commits(&device, &bob, &mut bobs_group, &mut bobs_keys);

    clock.advance(COMMITTER_WAIT - std::time::Duration::from_millis(1));
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 1);
    clock.advance(std::time::Duration::from_millis(1));
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 2")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 2);
    assert!(switched.lock().unwrap().is_empty());
}

#[test]
fn a_commit_asks_to_be_told_of_its_delivery_only_during_a_call_of_its_group() {
    let (device, _, _, clock) = alice_and_bob_in_time();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.end_call_keys("call-1");
    clock.advance(31 * DAY);
    let cpim = device
        .update_keys(CONVERSATION, IMPU, GROUP_URI)
        .unwrap()
        .expect("a control message");
    let info = cpim_message(&cpim);
    let info = info.get_info().unwrap();
    assert_eq!(
        info.disposition_notification,
        Some(&b"negative-delivery"[..])
    );
    // nor are notifications of it taken
    let message_id = String::from_utf8_lossy(info.imdn_message_id).into_owned();
    assert!(!delivered_by_bob(&device, &message_id, "<delivered/>"));
}

#[test]
fn the_keys_of_a_call_take_the_epochs_its_group_is_healed_into() {
    use rust_rcs_core::mls::rcs::proto::{
        self, server_mls_rcs_message, EpochControlMessages, MlsEnhancedGroupInfo,
        ServerCommitBundle, ServerMlsRcsMessage,
    };
    use rust_rcs_core::mls::rcs::wire::encode_message_list;

    let (device, bob, mut bobs_group) = alice_and_bob();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let (commit, group_info) = missed_by_the_device(&bob, &mut bobs_group);

    // the Commit the device missed, the Focus kept (RCC.16 section 10.1.2)
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
    device
        .process_enhanced_group_info(CONVERSATION, &enhanced)
        .unwrap();
    assert_eq!(epoch(&device, CONVERSATION), Ok((2, false)));

    // its keys taken, Bob the committer
    let mut bobs_keys = keys_of_bob_in(&bob, &bobs_group);
    let from_bob = bobs_keys.encrypt(b"meta", b"frame 1").unwrap();
    assert_eq!(
        device.decrypt_call_frame("call-1", b"meta", &from_bob),
        Ok(b"frame 1".to_vec())
    );
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 2")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).0, 2);
}

#[test]
fn the_keys_of_a_call_are_made_anew_as_the_device_rejoins_its_group() {
    let (device, bob, mut bobs_group) = alice_and_bob();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let (_, group_info) = missed_by_the_device(&bob, &mut bobs_group);

    // with an External Commit, at another leaf (RCC.16 section 10.1.1)
    let cpim = device
        .rejoin_group(CONVERSATION, IMPU, GROUP_URI, &group_info, None)
        .unwrap();
    bobs_group
        .process_commit_bundle(
            &bob,
            &rust_rcs_core::mls::rcs::proto::ServerCommitBundle {
                commit_list: commit_bundle_of(&cpim).commit_list,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(bobs_group.epoch(), 3);

    // sending in the epoch it rejoined in at once, its participants kept
    let mut bobs_keys = keys_of_bob_in(&bob, &bobs_group);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(
        bob_decrypts(&mut bobs_keys, &encrypted),
        (3, b"frame 1".to_vec())
    );
    assert!(switched.lock().unwrap().is_empty());
    assert!(device.encrypts_call("call-1"));
}

#[test]
fn the_keys_of_a_call_are_made_anew_as_the_device_joins_a_new_era_of_its_group() {
    use rust_rcs_core::mls::rcs::era::EraBase;
    use rust_rcs_core::mls::rcs::proto::{
        self, server_mls_rcs_message, ServerCommitBundle, ServerMlsRcsMessage,
    };
    use rust_rcs_core::mls::rcs::wire::encode_message_list;

    let (device, kds, bob, bobs_group, _) = alice_and_bob_in_time_with_kds();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);

    // Bob's new Era, in place of the group (RCC.16 section 8.3)
    let mut next = bob
        .create_next_era(&EraBase::of_conversation(&bobs_group), false)
        .unwrap();
    let output = next
        .add_members(&bob, &[&uploaded_key_package(&kds, 0)])
        .unwrap();
    next.merge_pending_commit(&bob).unwrap();
    let server_message = proto::encode(&ServerMlsRcsMessage {
        payload: Some(server_mls_rcs_message::Payload::ServerCommitBundle(
            ServerCommitBundle {
                commit_list: encode_message_list(&[&output.commit]).unwrap(),
                welcome: output.welcome.unwrap(),
                private_message: Vec::new(),
                ratchet_tree: output.ratchet_tree.unwrap(),
            },
        )),
    });
    device.join_group(CONVERSATION, &server_message).unwrap();

    // frames in it at once
    let mut bobs_keys = keys_of_bob_in(&bob, &next);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(
        bob_decrypts(&mut bobs_keys, &encrypted),
        (next.epoch(), b"frame 1".to_vec())
    );
}

/// The device making a new Era of its group with Bob, the control message
/// carrying it, and the new Era Bob joins
fn device_makes_a_new_era(
    device: &E2eeDevice,
    kds: &super::kds_tests::Kds,
    bob: &MlsClient,
) -> (Vec<u8>, MlsConversation) {
    use super::kds::Fetched;
    kds.now_knowing(vec![(
        BOB_TEL,
        Fetched::KeyPackages(vec![bob.generate_key_package(false).unwrap()]),
    )]);
    let cpim = futures::executor::block_on(device.create_next_era(
        CONVERSATION,
        IMPU,
        GROUP_URI,
        vec![recipient(BOB_TEL)],
        None,
    ))
    .unwrap();
    let next = joined(bob, &bundle_of(&cpim));
    (cpim, next)
}

#[test]
fn the_keys_of_a_call_are_made_anew_as_a_new_era_of_the_device_is_accepted() {
    // as the Focus answers the INVITE carrying it (RCC.16 section 8.3.2)
    let (device, kds, bob, _, _) = alice_and_bob_in_time_with_kds();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    let (_, next) = device_makes_a_new_era(&device, &kds, &bob);
    device.first_commit_accepted(CONVERSATION).unwrap();
    let mut bobs_keys = keys_of_bob_in(&bob, &next);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).1, b"frame 1");

    // or in the session (section 6.2.4)
    let (device, kds, bob, _, _) = alice_and_bob_in_time_with_kds();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    let (_, next) = device_makes_a_new_era(&device, &kds, &bob);
    let previous = epoch_identifier(&device, CONVERSATION);
    device
        .on_server_message(CONVERSATION, &accepted(previous))
        .unwrap();
    let mut bobs_keys = keys_of_bob_in(&bob, &next);
    let encrypted = device
        .encrypt_call_frame("call-1", b"meta", b"frame 2")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &encrypted).1, b"frame 2");
}

#[test]
fn participants_are_the_same_by_their_number_or_their_uri() {
    assert!(same_participant(
        BOB_TEL,
        "sip:+491707654321@ims.example.com"
    ));
    assert!(same_participant("tel:+491707654321", BOB_TEL));
    assert!(!same_participant(BOB_TEL, "tel:+491700000009"));
    // without a number, by the URI
    assert!(same_participant(
        "sip:bob@example.com",
        "SIP:bob@example.com"
    ));
    assert!(!same_participant(
        "sip:bob@example.com",
        "sip:carol@example.com"
    ));
    assert!(!same_participant("sip:bob@example.com", BOB_TEL));
}

#[test]
fn the_group_encryption_of_the_device_signs_checks_and_keys_group_calls() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (device, bob, mut bobs_group, clock) = alice_and_bob_in_time();
    let (query, _) = answering(&[]);
    let groups = DeviceGroups::new(&device, query);

    // signed as a video chat message, without the Era-ID
    let message = video_chat_message("call-1");
    let cpim = video_chat_cpim(IMPU, "video-20", "", &client_message(&message));
    let signed = rt.block_on(groups.sign(CONVERSATION, &cpim)).unwrap();
    assert!(!header_names(&cpim_message(&signed))
        .contains(&String::from("<http://www.gsma.com/rcs/mls>.Era-ID")));
    // Bob's checked
    let checked = |cpim: &[u8]| {
        groups.verify_video_chat(
            CONVERSATION,
            &cpim_message(cpim).get_info().unwrap(),
            &message,
        )
    };
    let by_bob = signed_by_bob(
        &bob,
        &mut bobs_group,
        BOB_TEL,
        "video-21",
        "video-21",
        &message,
    );
    assert_eq!(checked(&by_bob), Verified::Signed);
    assert_eq!(
        checked(&video_chat_cpim(BOB_TEL, "video-22", "", b"relayed")),
        Verified::Unsigned
    );
    let forged = signed_by_bob(
        &bob,
        &mut bobs_group,
        BOB_TEL,
        "video-23",
        "video-24",
        &message,
    );
    assert_eq!(checked(&forged), Verified::Forged);

    // the keys of a call made, told its participants, and let go of
    assert_eq!(groups.start_call_keys(CONVERSATION, "call-1"), Some(true));
    assert_eq!(groups.start_call_keys("another", "call-2"), Some(false));
    assert!(device.encrypts_call("call-1"));
    groups.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let switched = switches(&device);
    let (_, message_id) = device_commits(&device, &clock);
    let xml = notification_xml(&message_id, "delivery-notification", "<delivered/>");
    let receipt = notification_cpim(BOB_TEL, "imdn-30", "", &xml);
    assert!(groups.commit_delivered(
        CONVERSATION,
        &cpim_message(&receipt).get_info().unwrap(),
        xml.as_bytes()
    ));
    assert_eq!(*switched.lock().unwrap(), [(String::from("call-1"), 2)]);
    groups.end_call_keys("call-1");
    assert!(!device.encrypts_call("call-1"));
}

#[test]
fn a_commit_not_delivered_is_not_given_to_the_app_but_switches_nothing() {
    let (device, _, _, clock) = alice_and_bob_in_time();
    let switched = switches(&device);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let (_, message_id) = device_commits(&device, &clock);
    assert!(delivered_by_bob(
        &device,
        &message_id,
        "<failed><mls-client-failure-reason><invalid-commit/></mls-client-failure-reason></failed>"
    ));
    assert!(switched.lock().unwrap().is_empty());
}

#[test]
fn a_commit_asks_to_be_told_of_its_delivery_only_during_a_call_of_its_own_group() {
    let (device, kds, bob, _, clock) = alice_and_bob_in_time_with_kds();
    // a call of another group of the device
    kds.now_knowing(vec![(
        BOB_TEL,
        super::kds::Fetched::KeyPackages(vec![bob.generate_key_package(false).unwrap()]),
    )]);
    futures::executor::block_on(device.create_group(
        "conversation-2",
        IMPU,
        FACTORY,
        vec![recipient(BOB_TEL)],
    ))
    .unwrap();
    let previous = epoch_identifier(&device, "conversation-2");
    device
        .on_server_message("conversation-2", &accepted(previous))
        .unwrap();
    assert_eq!(device.start_call_keys("call-2", "conversation-2"), Ok(true));

    clock.advance(31 * DAY);
    let cpim = device
        .update_keys(CONVERSATION, IMPU, GROUP_URI)
        .unwrap()
        .expect("a control message");
    assert_eq!(
        cpim_message(&cpim)
            .get_info()
            .unwrap()
            .disposition_notification,
        Some(&b"negative-delivery"[..])
    );
}

#[test]
fn the_keys_of_a_call_made_again_in_the_same_epoch_send_under_other_key_ids() {
    // their counters starting again, as a counter is never to be used twice
    // with the same key (RFC 9605 section 9.1)
    let (device, bob, bobs_group) = alice_and_bob();
    let mut bobs_keys = keys_of_bob(&bob, &bobs_group);
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    let first = device
        .encrypt_call_frame("call-1", b"meta", b"frame 1")
        .unwrap();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    let second = device
        .encrypt_call_frame("call-1", b"meta", b"frame 2")
        .unwrap();
    assert_eq!(bob_decrypts(&mut bobs_keys, &first).1, b"frame 1");
    assert_eq!(bob_decrypts(&mut bobs_keys, &second).1, b"frame 2");
}

#[test]
fn the_receipts_of_the_latest_commits_asked_for_are_known_alone() {
    let (device, _, _, clock) = alice_and_bob_in_time();
    device.start_call_keys("call-1", CONVERSATION).unwrap();
    device.call_participants("call-1", vec![String::from(BOB_TEL)]);
    let (_, first) = device_commits(&device, &clock);
    let mut last = first.clone();
    for _ in 0..ASKED_KEPT {
        let (cpim, message_id) = {
            clock.advance(31 * DAY);
            let cpim = device
                .update_keys(CONVERSATION, IMPU, GROUP_URI)
                .unwrap()
                .expect("a control message");
            let message_id =
                String::from_utf8_lossy(cpim_message(&cpim).get_info().unwrap().imdn_message_id)
                    .into_owned();
            (cpim, message_id)
        };
        let _ = cpim;
        let previous = epoch_identifier(&device, CONVERSATION);
        device
            .on_server_message(CONVERSATION, &accepted(previous))
            .unwrap();
        last = message_id;
    }
    // the first one's for the app then
    assert!(!delivered_by_bob(&device, &first, "<delivered/>"));
    assert!(delivered_by_bob(&device, &last, "<delivered/>"));
}
