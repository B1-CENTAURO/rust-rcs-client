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

//! The encrypted subject and icon of the group chats of the device, as their
//! Conversation Focus tells of them (RCC.16 sections 7.13.2, 9.7.1)
//!
//! The subject is decrypted with the key of the subject the device keeps. The
//! NOTIFY telling of it may come before the Commit bringing its key: a
//! subject that does not open is tried again once the device took what the
//! Focus sent. The icon is told by its URL, kept with the MLS state, for the
//! app to download it: the download is opened with the key of the icon then.
//!
//! What does not open has the Group Metadata keys of the group checked, once
//! nothing of the device waits for the Focus (section 10.5.1, item 3).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::{engine::general_purpose, Engine as _};
use rust_rcs_core::ffi::log::platform_log;
use rust_rcs_core::mls::rcs::file::decrypt_file;
use rust_rcs_core::mls::rcs::metadata::{TARGET_ENCRYPTED_ICON, TARGET_ENCRYPTED_SUBJECT};
use rust_rcs_core::mls::rcs::proto::{self, FileInfo, FileMetadata};
use rust_rcs_core::mls::rcs::GROUP_ICON_FILE_NAME;
use rust_rcs_core::mls::ErrorKind;
use rust_rcs_core::util::rand::create_raw_alpha_numeric_string;

use crate::messaging::cpm::encryption::{
    EncryptedMetadata, GroupMetadata, MetadataChange, SealedFile,
};

use super::device::E2eeDevice;
use super::file::{file_urls, seal_file};
use super::group::GroupError;
use super::notes::{put, NotesData, Reader as NotesReader};
use super::store::StoreError;

const LOG_TAG: &str = "e2ee";

/// Content-Type of the CPM Group Session Data Management requests (RCC.16
/// section 7.13.1)
pub const CONTENT_TYPE_GROUP_DATA: &[u8] = b"application/vnd.oma.cpm-groupdata+xml";

/// The encrypted icon of a group chat, as kept in the notes of the device
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Icon {
    pub(super) conversation_id: String,
    pub(super) url: String,
    /// The URI of the participant who set it, if told
    pub(super) participant: Option<String>,
}

/// What of the subject and icon of a group did not open yet
#[derive(Default)]
struct Unopened {
    /// The encrypted subject, and who set it, if told
    subject: Option<(Vec<u8>, Option<String>)>,
    /// The tag of the key of the icon its download did not open with, empty
    /// if no key was kept
    icon: Option<Vec<u8>>,
}

/// What did not open of the subjects and icons of the groups, by
/// Conversation-ID, for as long as the device runs
#[derive(Default)]
pub(super) struct Descriptions(Mutex<HashMap<String, Unopened>>);

impl Descriptions {
    /// Lets go of the group `conversation_id`
    pub(super) fn forget(&self, conversation_id: &str) {
        self.0.lock().unwrap().remove(conversation_id);
    }
}

/// The key of the subject or of the icon, of the keys kept
type KeyOf = fn(&FileInfo) -> Option<&FileMetadata>;

impl E2eeDevice {
    /// Takes what the Conversation Focus of the group chat `conversation_id`
    /// tells of its encrypted `subject` and `icon`, if it does: what the app
    /// is to be told of them now (RCC.16 sections 7.13.2, 9.7.1.4 to 9.7.1.7)
    ///
    /// The subject is told decrypted, once it is; one that does not open is
    /// kept for metadata_opened(), the keys of the group checked. The icon is
    /// told by its URL, which open_file() opens once downloaded, and the
    /// Content-Type its key kept tells. Either is told as None once deleted.
    pub fn take_metadata(
        &self,
        conversation_id: &str,
        subject: Option<EncryptedMetadata>,
        icon: Option<EncryptedMetadata>,
    ) -> Vec<GroupMetadata> {
        let mut told = Vec::new();
        if let Some(subject) = subject {
            told.extend(self.take_subject(conversation_id, subject));
        }
        if let Some(icon) = icon {
            told.extend(self.take_icon(conversation_id, icon));
        }
        told
    }

    fn take_subject(
        &self,
        conversation_id: &str,
        subject: EncryptedMetadata,
    ) -> Option<GroupMetadata> {
        let EncryptedMetadata { value, participant } = subject;
        self.forget_unopened(conversation_id, |unopened| unopened.subject = None);
        if value.is_empty() {
            return Some(GroupMetadata::Subject {
                subject: None,
                participant,
            });
        }

        let mut text = value.into_bytes();
        text.retain(|b| !b.is_ascii_whitespace());
        let Ok(ciphertext) = general_purpose::STANDARD.decode(text) else {
            platform_log(LOG_TAG, "encrypted subject not base64, passed over");
            return None;
        };
        match self.open_subject(conversation_id, &ciphertext) {
            Some(subject) => Some(GroupMetadata::Subject {
                subject: Some(subject),
                participant,
            }),
            None => {
                self.descriptions()
                    .0
                    .lock()
                    .unwrap()
                    .entry(String::from(conversation_id))
                    .or_default()
                    .subject = Some((ciphertext, participant));
                self.recoveries().check(conversation_id, false);
                None
            }
        }
    }

    fn take_icon(&self, conversation_id: &str, icon: EncryptedMetadata) -> Option<GroupMetadata> {
        let EncryptedMetadata { value, participant } = icon;
        let url = value.trim();
        let kept = (!url.is_empty()).then(|| Icon {
            conversation_id: String::from(conversation_id),
            url: String::from(url),
            participant: participant.clone(),
        });
        let changed = self.notes().change(self.store(), |data| {
            data.icons
                .retain(|icon| icon.conversation_id != conversation_id);
            data.icons.extend(kept.clone());
        });
        if let Err(e) = changed {
            platform_log(LOG_TAG, format!("encrypted icon not kept: {:?}", e));
            return None;
        }
        self.descriptions()
            .0
            .lock()
            .unwrap()
            .entry(String::from(conversation_id))
            .or_default()
            .icon = None;

        Some(match kept {
            Some(icon) => self.told_icon(icon),
            None => GroupMetadata::Icon {
                url: None,
                content_type: None,
                participant,
            },
        })
    }

    /// The icon `icon` as the app is told of it, with the Content-Type the
    /// key of the icon kept tells
    fn told_icon(&self, icon: Icon) -> GroupMetadata {
        let content_type = self
            .metadata_key(&icon.conversation_id, |keys| keys.icon.as_ref())
            .map(|key| key.content_type)
            .filter(|content_type| !content_type.is_empty());
        GroupMetadata::Icon {
            url: Some(icon.url),
            content_type,
            participant: icon.participant,
        }
    }

    /// What the app is to be told of the group chat `conversation_id` once
    /// the device took what its Conversation Focus sent: the subject kept by
    /// take_metadata() if it opens now, and the icon again if its download
    /// did not open and another key of the icon is kept now (RCC.16 sections
    /// 9.7.1.4, 9.7.1.5, 10.5.4); a subject that still does not open has the
    /// keys of the group checked
    pub fn metadata_opened(&self, conversation_id: &str) -> Vec<GroupMetadata> {
        let mut told = Vec::new();
        let (subject, icon_tag) = {
            let descriptions = self.descriptions().0.lock().unwrap();
            match descriptions.get(conversation_id) {
                Some(unopened) => (unopened.subject.clone(), unopened.icon.clone()),
                None => return told,
            }
        };

        if let Some((ciphertext, participant)) = subject {
            match self.open_subject(conversation_id, &ciphertext) {
                Some(subject) => {
                    self.forget_unopened(conversation_id, |unopened| {
                        if unopened.subject.as_ref().map(|(c, _)| c) == Some(&ciphertext) {
                            unopened.subject = None;
                        }
                    });
                    told.push(GroupMetadata::Subject {
                        subject: Some(subject),
                        participant,
                    });
                }
                None => self.recoveries().check(conversation_id, false),
            }
        }

        if let Some(tag) = icon_tag {
            if self.icon_key_tag(conversation_id) != tag {
                self.forget_unopened(conversation_id, |unopened| unopened.icon = None);
                let icon = self.notes().read(|data| icon_of(data, conversation_id));
                told.extend(icon.map(|icon| self.told_icon(icon)));
            }
        }
        told
    }

    fn forget_unopened(&self, conversation_id: &str, forget: impl FnOnce(&mut Unopened)) {
        if let Some(unopened) = self
            .descriptions()
            .0
            .lock()
            .unwrap()
            .get_mut(conversation_id)
        {
            forget(unopened);
        }
    }

    /// The subject `ciphertext` of the group chat `conversation_id` decrypted
    /// with the key of the subject kept (RCC.16 section 9.7.1.5, Annex C.3);
    /// None if it does not open with it, or if none is kept
    fn open_subject(&self, conversation_id: &str, ciphertext: &[u8]) -> Option<String> {
        let key = self.metadata_key(conversation_id, |keys| keys.subject.as_ref())?;
        let subject =
            decrypt_file(ciphertext, &key.file_name, key.encryption_info.as_ref()?).ok()?;
        Some(String::from_utf8_lossy(&subject).into_owned())
    }

    /// The key of the subject or of the icon, as `key_of` tells, kept for the
    /// group chat `conversation_id`
    fn metadata_key(&self, conversation_id: &str, key_of: KeyOf) -> Option<FileMetadata> {
        self.store()
            .peek_conversation(conversation_id.as_bytes(), |conversation, client| {
                conversation.group_metadata(client)
            })
            .ok()?
            .ok()?
            .group_subject_icon_keys
            .as_ref()
            .and_then(key_of)
            .cloned()
    }

    /// The tag of the key of the icon kept for the group chat
    /// `conversation_id`, empty if none is
    fn icon_key_tag(&self, conversation_id: &str) -> Vec<u8> {
        self.metadata_key(conversation_id, |keys| keys.icon.as_ref())
            .and_then(|key| key.encryption_info)
            .map(|info| info.hmac_tag)
            .unwrap_or_default()
    }

    /// The Conversation-ID of the group chat whose icon is at `url`, if one's
    /// is
    pub(super) fn icon_at(&self, url: &str) -> Option<String> {
        self.notes().read(|data| {
            data.icons
                .iter()
                .find(|icon| icon.url == url)
                .map(|icon| icon.conversation_id.clone())
        })
    }

    /// `ciphertext`, downloaded from the URL of the icon of the group chat
    /// `conversation_id`, decrypted with the key of the icon kept, its tag
    /// checked first (RCC.16 section 9.7.1.4, Annex C.3); None if it does not
    /// open with it, or if none is kept, which has the keys of the group
    /// checked, and the icon told again once another key is kept
    pub(super) fn open_icon(&self, conversation_id: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let key = self.metadata_key(conversation_id, |keys| keys.icon.as_ref());
        let opened = key.as_ref().and_then(|key| {
            decrypt_file(ciphertext, &key.file_name, key.encryption_info.as_ref()?).ok()
        });
        if opened.is_none() {
            let tag = key
                .and_then(|key| key.encryption_info)
                .map(|info| info.hmac_tag)
                .unwrap_or_default();
            self.descriptions()
                .0
                .lock()
                .unwrap()
                .entry(String::from(conversation_id))
                .or_default()
                .icon = Some(tag);
            self.recoveries().check(conversation_id, false);
        }
        opened
    }

    /// Lets go of the subject and icon of the group chat `conversation_id`
    pub(super) fn forget_metadata(&self, conversation_id: &str) {
        self.descriptions().forget(conversation_id);
        let forgotten = self.notes().change(self.store(), |data| {
            data.icons
                .retain(|icon| icon.conversation_id != conversation_id)
        });
        if let Err(e) = forgotten {
            platform_log(LOG_TAG, format!("encrypted icon not forgotten: {:?}", e));
        }
    }
}

impl E2eeDevice {
    /// The icon `icon` of a group chat, of `content_type`, encrypted with a
    /// key of its own under the name GROUP_ICON_FILE_NAME (RCC.16 section
    /// 9.7.1.1, Annex C.2): the ciphertext to upload, and its key as the
    /// FileMetadata of the icon (section 9.7.1.1.3)
    pub fn seal_icon(&self, icon: &[u8], content_type: &str) -> Option<SealedFile> {
        seal_file(icon, GROUP_ICON_FILE_NAME, content_type)
    }

    /// The control message changing the encrypted subject or icon of the
    /// group chat `conversation_id` as `change` does, `from` and `to` its own
    /// (RCC.16 sections 9.7.1.4 to 9.7.1.7): a CPIM message of a multipart
    /// body, the `message/mls-rcs-client` of the Commit, then the CPM group
    /// data request (section 7.13.1); None if the group is not encrypted,
    /// out of step with its Conversation Focus, or if there is no icon or
    /// subject to delete
    ///
    /// The Commit setting one is bundled with the PrivateMessage of its key,
    /// whose Message-ID is that of the control message. An icon set is one
    /// uploaded sealed with seal_icon(), the request telling its URL. Not
    /// while a Commit of the device waits for the Focus to accept it.
    pub fn change_metadata(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        change: &MetadataChange,
    ) -> Result<Option<Vec<u8>>, GroupError> {
        if self.encryption_ended(conversation_id)
            || self.heals().ongoing(conversation_id)
            || self.needs_healing(conversation_id)
            || self.new_era_due(conversation_id)
        {
            return Ok(None);
        }
        // the icon as uploaded: its URL and its key
        let icon = match change {
            MetadataChange::Icon(Some(uploaded)) => {
                let url = file_urls(&uploaded.xml).0;
                let key = proto::decode::<FileMetadata>(&uploaded.metadata).ok();
                let Some((url, key)) = url.zip(key.filter(|key| {
                    key.file_name == GROUP_ICON_FILE_NAME && key.encryption_info.is_some()
                })) else {
                    platform_log(LOG_TAG, "icon not uploaded sealed as one");
                    return Ok(None);
                };
                Some((url, key))
            }
            _ => None,
        };

        let message_id = super::group::new_message_id();
        let made =
            self.store()
                .with_conversation(conversation_id.as_bytes(), |conversation, client| {
                    if conversation.has_pending_commit() {
                        return Ok(Err(GroupError::Pending));
                    }
                    let id = message_id.as_bytes();
                    let (output, target, data) = match (change, &icon) {
                        (MetadataChange::Subject(Some(subject)), _) => {
                            let (output, encrypted) =
                                conversation.set_group_subject(client, subject, id)?;
                            let subject = general_purpose::STANDARD.encode(encrypted.ciphertext);
                            (output, TARGET_ENCRYPTED_SUBJECT, Some(subject))
                        }
                        (MetadataChange::Subject(None), _) => (
                            conversation.delete_group_subject(client)?,
                            TARGET_ENCRYPTED_SUBJECT,
                            None,
                        ),
                        (MetadataChange::Icon(Some(_)), Some((url, key))) => {
                            let encryption_info = key.encryption_info.as_ref().unwrap();
                            let output = conversation.commit_group_icon(
                                client,
                                encryption_info,
                                &key.content_type,
                                id,
                            )?;
                            (output, TARGET_ENCRYPTED_ICON, Some(url.clone()))
                        }
                        (MetadataChange::Icon(_), _) => (
                            conversation.delete_group_icon(client)?,
                            TARGET_ENCRYPTED_ICON,
                            None,
                        ),
                    };
                    match output.to_client_message() {
                        Ok(client_message) => Ok(Ok((client_message, target, data))),
                        Err(e) => {
                            conversation.discard_pending_commit(client)?;
                            Err(e)
                        }
                    }
                });
        let (client_message, target, data) = match made {
            Ok(made) => made?,
            // nothing to delete
            Err(StoreError::Mls(ErrorKind::InvalidState)) => return Ok(None),
            Err(e) => return Err(GroupError::Store(e)),
        };
        let request = group_data_request(target, data.as_deref());
        Ok(Some(self.sent_with(
            conversation_id,
            from,
            to,
            message_id,
            &client_message,
            Some(request.as_bytes()),
        )))
    }
}

/// The CPM Group Session Data Management request setting the encrypted
/// subject or icon `target` to `data`, or deleting it if None (RCC.16
/// sections 7.13.1, 9.7.1.4 to 9.7.1.7)
pub(super) fn group_data_request(target: &str, data: Option<&str>) -> String {
    let (action, data) = match data {
        Some(data) => (
            "set",
            format!(
                "<data><{}>{}</{}></data>",
                target,
                quick_xml::escape::escape(data),
                target
            ),
        ),
        None => ("delete", String::new()),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<cpm-group-management xmlns=\"urn:oma:xml:cpm:groupdata:1.0\" id=\"{}\">\n\
<group-data>\n<request>\n<target>{}</target>\n<action>{}</action>\n{}\
</request>\n</group-data>\n</cpm-group-management>\n",
        String::from_utf8_lossy(&create_raw_alpha_numeric_string(10)),
        target,
        action,
        match data.is_empty() {
            true => data,
            false => data + "\n",
        }
    )
}

/// The icon `data` keeps of the group chat `conversation_id`, if one
fn icon_of(data: &NotesData, conversation_id: &str) -> Option<Icon> {
    data.icons
        .iter()
        .find(|icon| icon.conversation_id == conversation_id)
        .cloned()
}

/// The icons `icons`, as the notes of the device hold them
pub(super) fn encode(icons: &[Icon]) -> Vec<u8> {
    let mut data = Vec::new();
    for icon in icons {
        put(&mut data, icon.conversation_id.as_bytes());
        put(&mut data, icon.url.as_bytes());
        match &icon.participant {
            Some(participant) => {
                data.push(1);
                put(&mut data, participant.as_bytes());
            }
            None => data.push(0),
        }
    }
    data
}

/// The icons `reader` reads, as encode() puts them
pub(super) fn decode(reader: &mut NotesReader) -> Option<Vec<Icon>> {
    let mut icons = Vec::new();
    while !reader.is_empty() {
        let conversation_id = reader.string()?;
        let url = reader.string()?;
        let participant = match reader.flag()? {
            true => Some(reader.string()?),
            false => None,
        };
        icons.push(Icon {
            conversation_id,
            url,
            participant,
        });
    }
    Some(icons)
}
