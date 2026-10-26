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

//! New Eras of the MLS groups of group chats (RCC.16 section 8.3)

use rust_rcs_core::mls::rcs::credential_tel_uris;
use rust_rcs_core::mls::rcs::era::EraBase;
use rust_rcs_core::mls::rcs::proto::MlsGroupInfo;
use rust_rcs_core::mls::ErrorKind;

use super::device::E2eeDevice;
use super::group::GroupError;
use super::kds::Recipient;
use super::store::StoreError;

impl E2eeDevice {
    /// Makes the next Era of the MLS group of the group chat
    /// `conversation_id`, with all the Clients of `recipients`, its
    /// Participants besides the user, as the Home KDS is asked for their
    /// KeyPackages: the CPIM message, `from` and `to` its own, carrying the
    /// `message/mls-rcs-client` the INVITE restarting the group is to carry
    /// (RCC.16 sections 7.9.2, 8.1.2, 8.3.1)
    ///
    /// The Era follows that of `group_info`, the MlsGroupInfo its Conversation
    /// Focus gave, or else that of the group the device has, whose GroupContext
    /// extensions it copies. The continuity token goes on in it, unless a
    /// Participant is not a member of that group, or the group has members the
    /// group of the device does not have (section 8.3.1.2).
    ///
    /// The group of the Era before is let go of once the KeyPackages are
    /// fetched. The Commit is applied once the Focus accepts it.
    pub async fn create_next_era(
        &self,
        conversation_id: &str,
        from: &str,
        to: &str,
        recipients: Vec<Recipient>,
        group_info: Option<&MlsGroupInfo>,
    ) -> Result<Vec<u8>, GroupError> {
        let base = match group_info {
            Some(group_info) => EraBase::of_group_info(group_info)
                .map_err(|e| GroupError::Store(StoreError::Mls(e)))?,
            None => self
                .store()
                .peek_conversation(conversation_id.as_bytes(), |conversation, _| {
                    EraBase::of_conversation(conversation)
                })
                .map_err(GroupError::Store)?,
        };
        if base.group_id() != conversation_id.as_bytes() {
            return Err(GroupError::Store(StoreError::Mls(
                ErrorKind::UnexpectedMessage,
            )));
        }

        // the Participants of the RCS conversation, the user among them
        let mut participants: Vec<String> = self
            .store()
            .credential()
            .and_then(|credential| credential_tel_uris(&credential).ok())
            .and_then(|tel_uris| tel_uris.into_iter().next())
            .into_iter()
            .collect();
        participants.extend(recipients.iter().map(|recipient| recipient.tel_uri.clone()));
        let key_packages = self.key_packages(recipients).await?;

        let (_, client_message) = self
            .store()
            .add_conversation(|client| {
                let participants: Vec<&str> = participants.iter().map(|p| &p[..]).collect();
                let kept = client.load_conversation(base.group_id()).ok();
                let renew = !base.continuity_holds(kept.as_ref(), &participants);
                drop(kept);

                let mut conversation = client.create_next_era(&base, renew)?;
                let key_packages: Vec<&[u8]> = key_packages.iter().map(|kp| &kp[..]).collect();
                let made = conversation
                    .add_members(client, &key_packages)
                    .and_then(|output| output.to_client_message());
                match made {
                    Ok(client_message) => Ok((conversation, client_message)),
                    Err(e) => {
                        let _ = conversation.delete(client);
                        Err(e)
                    }
                }
            })
            .map_err(GroupError::Store)?;

        Ok(self.sent_in(conversation_id, from, to, &client_message))
    }
}
