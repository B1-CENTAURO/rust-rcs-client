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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rust_rcs_core::mls::{
    Ciphersuite, Credential, CredentialValidator, ErrorKind, IncomingMessage, MlsClient, MlsConfig,
    MlsConversation,
};

use super::store::{MlsStore, StoreError};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

struct AllowAll;

impl CredentialValidator for AllowAll {
    fn validate(&self, _credential: &Credential, _signature_key: &[u8]) -> bool {
        true
    }
}

/// What the app keeps of the state, as it is given it
#[derive(Default)]
struct App {
    kept: Mutex<Vec<Vec<u8>>>,
    refusing: AtomicBool,
}

impl App {
    fn kept(&self) -> usize {
        self.kept.lock().unwrap().len()
    }

    fn last(&self) -> Vec<u8> {
        self.kept.lock().unwrap().last().unwrap().clone()
    }

    fn refuse(&self, refusing: bool) {
        self.refusing.store(refusing, Ordering::SeqCst);
    }
}

/// A store keeping the state with `app`
fn store(app: &Arc<App>) -> MlsStore {
    let app = Arc::clone(app);
    MlsStore::new(
        MlsConfig::default(),
        Arc::new(AllowAll),
        Box::new(move |state| {
            if app.refusing.load(Ordering::SeqCst) {
                return false;
            }
            app.kept.lock().unwrap().push(state.to_vec());
            true
        }),
    )
}

/// A store with a client of its own, `identity`
fn device(app: &Arc<App>, identity: &'static str) -> MlsStore {
    let store = store(app);
    store
        .create(|config, validator| {
            MlsClient::new(identity.as_bytes(), CIPHERSUITE, config, validator)
        })
        .unwrap();
    store
}

/// Another member, as a client of its own
fn member(identity: &str) -> MlsClient {
    MlsClient::new(
        identity.as_bytes(),
        CIPHERSUITE,
        MlsConfig::default(),
        Box::new(AllowAll),
    )
    .unwrap()
}

/// A group the device creates with `other`, who joins it; its ID and the
/// group as `other` has it
fn group_with(device: &MlsStore, other: &MlsClient) -> (Vec<u8>, MlsConversation) {
    let key_package = other.generate_key_package(false).unwrap();
    let (group_id, (welcome, ratchet_tree)) = device
        .add_conversation(|client| {
            let mut conversation = client.create_conversation(None, 0)?;
            let output = conversation.add_members(client, &[&key_package])?;
            conversation.merge_pending_commit(client)?;
            Ok((
                conversation,
                (output.welcome.unwrap(), output.ratchet_tree.unwrap()),
            ))
        })
        .unwrap();
    let joined = other.join_conversation(&welcome, &ratchet_tree).unwrap();
    (group_id, joined)
}

fn encrypt(device: &MlsStore, group_id: &[u8], text: &str) -> Result<Vec<u8>, StoreError> {
    device.with_conversation(group_id, |conversation, client| {
        conversation.encrypt(client, text.as_bytes())
    })
}

fn decrypt(other: &MlsClient, conversation: &mut MlsConversation, message: &[u8]) -> String {
    match conversation.process(other, message).unwrap() {
        IncomingMessage::Application { data, .. } => String::from_utf8(data).unwrap(),
        _ => panic!("not an application message"),
    }
}

#[test]
fn every_change_is_kept_before_what_it_made_is_given_out() {
    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    assert_eq!(app.kept(), 1, "the client made");

    let bob = member("bob");
    let (group_id, mut bobs) = group_with(&device, &bob);
    assert_eq!(app.kept(), 2, "the group created");

    let message = encrypt(&device, &group_id, "one").unwrap();
    assert_eq!(app.kept(), 3, "the message encrypted");
    assert_eq!(decrypt(&bob, &mut bobs, &message), "one");

    // the state kept goes on where the device left off: a message encrypted
    // from an older state would reuse the keys of the first
    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert_eq!(again.credential(), device.credential());
    let message = encrypt(&again, &group_id, "two").unwrap();
    assert_eq!(decrypt(&bob, &mut bobs, &message), "two");
}

#[test]
fn a_change_that_cannot_be_kept_is_undone_and_not_given_out() {
    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    let bob = member("bob");
    let (group_id, mut bobs) = group_with(&device, &bob);
    let epoch = |device: &MlsStore| {
        device
            .with_conversation(&group_id, |conversation, _| Ok(conversation.epoch()))
            .unwrap()
    };
    let before = epoch(&device);

    // a Commit applied, the state it leaves not kept
    app.refuse(true);
    let kept = app.kept();
    let committed = device.with_conversation(&group_id, |conversation, client| {
        let output = conversation.update_keys(client)?;
        conversation.merge_pending_commit(client)?;
        Ok(output.commit)
    });
    assert_eq!(committed, Err(StoreError::NotSaved));
    assert_eq!(
        device.with_client(|client| client.generate_key_package(false)),
        Err(StoreError::NotSaved)
    );
    assert_eq!(app.kept(), kept);

    // undone, as kept
    app.refuse(false);
    assert_eq!(epoch(&device), before);
    let message = encrypt(&device, &group_id, "after").unwrap();
    assert_eq!(decrypt(&bob, &mut bobs, &message), "after");
}

#[test]
fn a_client_that_cannot_be_kept_is_not_taken_on() {
    let app = Arc::new(App::default());
    let device = store(&app);
    app.refuse(true);
    assert_eq!(
        device.create(|config, validator| {
            MlsClient::new(b"alice", CIPHERSUITE, config, validator)
        }),
        Err(StoreError::NotSaved)
    );
    assert_eq!(device.credential(), None);
}

#[test]
fn nothing_is_done_without_a_client() {
    let app = Arc::new(App::default());
    let device = store(&app);
    assert_eq!(
        device.with_client(|client| client.generate_key_package(false)),
        Err(StoreError::NoClient)
    );
    assert_eq!(
        device.with_conversation(b"group", |conversation, _| Ok(conversation.epoch())),
        Err(StoreError::NoClient)
    );
    assert_eq!(device.credential(), None);
    assert_eq!(app.kept(), 0);
}

#[test]
fn a_state_that_is_not_one_is_refused() {
    let app = Arc::new(App::default());
    let device = store(&app);
    assert_eq!(
        device.restore(b"not a state"),
        Err(StoreError::Mls(ErrorKind::BadFormat))
    );
    assert_eq!(device.credential(), None);
}

#[test]
fn what_mls_refuses_is_told_once_the_state_is_kept() {
    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    let (group_id, _bobs) = group_with(&device, &member("bob"));

    let kept = app.kept();
    assert_eq!(
        device
            .with_conversation(&group_id, |conversation, client| {
                conversation.process(client, b"not an MLS message")
            })
            .map(|_| ()),
        Err(StoreError::Mls(ErrorKind::BadFormat))
    );
    assert_eq!(app.kept(), kept + 1);

    assert_eq!(
        device.with_conversation(b"unknown", |conversation, _| Ok(conversation.epoch())),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

#[test]
fn a_group_deleted_is_gone_from_the_state_kept() {
    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    let (group_id, _bobs) = group_with(&device, &member("bob"));

    device.delete_conversation(&group_id).unwrap();
    assert_eq!(
        device.with_conversation(&group_id, |conversation, _| Ok(conversation.epoch())),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );

    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert_eq!(
        again.with_conversation(&group_id, |conversation, _| Ok(conversation.epoch())),
        Err(StoreError::Mls(ErrorKind::UnknownGroup))
    );
}

#[test]
fn a_store_is_shared_between_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<MlsStore>();
}

#[test]
fn the_participant_key_is_made_once_and_kept_with_the_state() {
    let app = Arc::new(App::default());
    let device = store(&app);
    let participant_key = device.participant_public_key().unwrap();
    assert_eq!(app.kept(), 1, "the Participant Key made");
    assert_eq!(device.participant_public_key(), Ok(participant_key.clone()));
    assert_eq!(app.kept(), 1);

    // kept along with the client, and its changes
    device
        .create(|config, validator| MlsClient::new(b"alice", CIPHERSUITE, config, validator))
        .unwrap();
    let made = store(&app);
    made.restore(&app.last()).unwrap();
    assert_eq!(made.participant_public_key(), Ok(participant_key.clone()));
    assert_eq!(app.kept(), 2, "the client made");
    let bob = member("bob");
    let (group_id, _bobs) = group_with(&device, &bob);
    encrypt(&device, &group_id, "one").unwrap();

    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert_eq!(again.participant_public_key(), Ok(participant_key.clone()));
    assert_eq!(again.credential(), device.credential());

    // and through a change undone
    app.refuse(true);
    assert_eq!(
        encrypt(&device, &group_id, "two"),
        Err(StoreError::NotSaved)
    );
    app.refuse(false);
    assert_eq!(device.participant_public_key(), Ok(participant_key));
}

#[test]
fn a_participant_key_that_cannot_be_kept_is_not_taken_on() {
    let app = Arc::new(App::default());
    let device = store(&app);
    app.refuse(true);
    assert_eq!(device.participant_public_key(), Err(StoreError::NotSaved));
    app.refuse(false);
    let participant_key = device.participant_public_key().unwrap();

    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert_eq!(again.participant_public_key(), Ok(participant_key));
    assert_eq!(app.kept(), 1);
}

#[test]
fn a_client_is_kept_without_a_participant_key_until_one_is_asked_for() {
    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert_eq!(again.credential(), device.credential());

    // made for the client restored, and kept with it
    let participant_key = again.participant_public_key().unwrap();
    let once_more = store(&app);
    once_more.restore(&app.last()).unwrap();
    assert_eq!(once_more.credential(), device.credential());
    assert_eq!(once_more.participant_public_key(), Ok(participant_key));
}

#[test]
fn a_state_with_a_participant_key_that_is_not_one_is_refused() {
    let app = Arc::new(App::default());
    let device = store(&app);
    device.participant_public_key().unwrap();
    let kept = app.last();
    let key_length = b"RCS-E2EE2".len();

    let mut short = kept.clone();
    short[key_length] = 200;
    let mut not_a_key = kept.clone();
    for byte in &mut not_a_key[key_length + 1..key_length + 33] {
        *byte = 0xff;
    }
    for state in [short, not_a_key] {
        assert_eq!(
            store(&app).restore(&state),
            Err(StoreError::Mls(ErrorKind::BadFormat))
        );
    }
}

#[test]
fn whether_key_packages_were_uploaded_is_kept_with_the_client() {
    let app = Arc::new(App::default());
    let device = store(&app);
    assert_eq!(
        device.set_key_packages_uploaded(),
        Err(StoreError::NoClient)
    );
    device
        .create(|config, validator| MlsClient::new(b"alice", CIPHERSUITE, config, validator))
        .unwrap();
    assert!(!device.key_packages_uploaded());

    // not kept, not taken on
    app.refuse(true);
    assert_eq!(
        device.set_key_packages_uploaded(),
        Err(StoreError::NotSaved)
    );
    assert!(!device.key_packages_uploaded());
    app.refuse(false);

    let kept = app.kept();
    device.set_key_packages_uploaded().unwrap();
    assert!(device.key_packages_uploaded());
    device.set_key_packages_uploaded().unwrap();
    assert_eq!(app.kept(), kept + 1, "kept once");

    // along with the changes that follow
    let (group_id, _bobs) = group_with(&device, &member("bob"));
    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert!(again.key_packages_uploaded());

    // and through a change undone
    app.refuse(true);
    assert_eq!(
        encrypt(&device, &group_id, "one"),
        Err(StoreError::NotSaved)
    );
    app.refuse(false);
    assert!(device.key_packages_uploaded());

    // none of a new client's
    device
        .create(|config, validator| MlsClient::new(b"alice", CIPHERSUITE, config, validator))
        .unwrap();
    assert!(!device.key_packages_uploaded());
    let again = store(&app);
    again.restore(&app.last()).unwrap();
    assert!(!again.key_packages_uploaded());
}

#[test]
fn a_state_of_another_layout_is_refused() {
    let app = Arc::new(App::default());
    let device = store(&app);
    device.participant_public_key().unwrap();
    let kept = app.last();
    let uploaded_at = b"RCS-E2EE2".len() + 1 + 32;

    let mut not_a_flag = kept.clone();
    not_a_flag[uploaded_at] = 2;
    let mut older = kept.clone();
    older[..9].copy_from_slice(b"RCS-E2EE1");
    let cut = kept[..uploaded_at].to_vec();
    for state in [not_a_flag, older, cut] {
        assert_eq!(
            store(&app).restore(&state),
            Err(StoreError::Mls(ErrorKind::BadFormat))
        );
    }
    assert!(store(&app).restore(&kept).is_ok());
}

#[test]
fn every_client_the_store_takes_on_tells_the_time_of_its_clock() {
    use std::time::{Duration, SystemTime};

    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    let now = Arc::new(Mutex::new(SystemTime::now()));
    let clock: rust_rcs_core::mls::Clock = {
        let now = Arc::clone(&now);
        Arc::new(move || *now.lock().unwrap())
    };
    device.set_clock(Arc::clone(&clock));
    let bob = member("bob");
    let (group_id, _) = group_with(&device, &bob);
    let due = |device: &MlsStore| {
        device
            .peek_conversation(&group_id, |conversation, client| {
                conversation.key_update_due(client).unwrap()
            })
            .unwrap()
    };
    assert!(!due(&device));
    *now.lock().unwrap() += Duration::from_secs(31 * 24 * 60 * 60);
    assert!(due(&device));

    // the client taken again from the state kept, as a change is undone
    app.refuse(true);
    assert_eq!(
        encrypt(&device, &group_id, "not kept"),
        Err(StoreError::NotSaved)
    );
    app.refuse(false);
    assert!(due(&device));

    // or as a state is restored
    let restored = store(&app);
    restored.set_clock(clock);
    restored.restore(&app.last()).unwrap();
    assert!(due(&restored));
}

#[test]
fn a_renewal_is_kept_at_once_or_undone() {
    use rust_rcs_core::mls::SignatureKeyPair;

    let app = Arc::new(App::default());
    let device = device(&app, "alice");
    // a basic credential, as one of another client
    let renewed = |name: &str| -> Credential { member(name).credential().clone() };
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    let public_key = signer.public().to_vec();
    device.renew(renewed("alice 2"), signer).unwrap();
    let restored = store(&app);
    restored.restore(&app.last()).unwrap();
    assert_eq!(restored.credential(), Some(renewed("alice 2")));
    assert_eq!(restored.signature_key(), Some(public_key.clone()));

    app.refuse(true);
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
    assert_eq!(
        device.renew(renewed("alice 3"), signer),
        Err(StoreError::NotSaved)
    );
    app.refuse(false);
    assert_eq!(device.credential(), Some(renewed("alice 2")));
    assert_eq!(device.signature_key(), Some(public_key));
}
