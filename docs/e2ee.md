# End-to-end encryption (GSMA RCC.16)

This guide is for apps that use the client's C API and want their chats encrypted end to end, as GSMA RCC.16 v4.0 specifies on top of MLS (RFC 9420). It covers:
- building with E2EE;
- what the app has to provide;
- the order of the calls;
- what the client does on its own;
- what is not covered yet.

The declarations are in [`src/librust_rcs_client.h`](../src/librust_rcs_client.h), under "end-to-end encryption".

## What is encrypted

- **1-to-1 chats** (RCC.16 section 8.1.1), with a contact who advertises E2EE and whose KeyPackages the Home KDS has.
- **Group chats** (section 8.1), when every participant advertises E2EE when the group is created.
- **Delivery and display notifications** in those chats are signed (sections 9.1.3, 9.1.4). Those that come are checked, and a forged one is dropped.
- **Files sent in those chats**: they are encrypted before upload, and decrypted as they are downloaded (section 9.1.2).
- **The subject and icon of encrypted groups** (section 9.7.1).

Not encrypted:
- standalone messages (pager and large mode);
- chats with chatbots;
- multimedia conferences.

## Building

Build the library with the `e2ee` feature:

```
cargo build --features e2ee
```

The functions `rcs_client_set_e2ee`, `rcs_client_e2ee_enrol`, `rcs_client_identity_verification_code` and `rcs_kds_request_*` exist only in a library built with it. Without them, chats go unencrypted as before.

## What the app provides

The client does the MLS and RCC.16 side. Four things are left to the app.

### 1. Access to the Home KDS

The protocol between a client and its Home KDS is the operator's, so the client asks the app to make three requests. Each callback is handed a `struct rcs_kds_request *`. Answer it exactly once, at once or later, from any thread, with one of the `rcs_kds_request_*` functions.

| Callback | Asked to | Answer with |
| --- | --- | --- |
| `rcs_kds_enrol_function` | enrol the device: tel URI, Cipher Suite, MLS signature key, Client ID, DER encoded ParticipantInformation, and the ACS Signed Encryption Identity Proof (NULL if ACS gave none) | `rcs_kds_request_enrolled` with the certificate chain, Client Certificate first |
| `rcs_kds_upload_function` | upload KeyPackages of the device | `rcs_kds_request_uploaded` |
| `rcs_kds_fetch_function` | fetch the KeyPackages of Participants, by tel URI and the Home KDS their capabilities name, in the first of the Cipher Suites given that all of them have | `rcs_kds_request_add_key_packages` for each Participant, then `rcs_kds_request_fetched` |

Any of them can be answered with `rcs_kds_request_failed`: `refused` 0 if the Home KDS could not be reached, else non-zero with its reason (which may be NULL). In `rcs_kds_request_add_key_packages`, a Participant the Home KDS has nothing for is told with its status:
- 1: not found;
- 2: malformed number;
- 3: no Cipher Suite in common;
- 4: unavailable.

The device uses `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`. At enrolment it uploads 10 KeyPackages and one of last resort.

### 2. The roots to trust

Give `rcs_client_set_e2ee` the DER encoded root certificates the Client Certificates of your network chain to (Annex A). Also give it the Vendor ID of your Home KDS (`home_kds`), which the client advertises in its capabilities.

### 3. Keeping the MLS state

All the E2EE state of the device goes through the `rcs_e2ee_save_state_function` you give. That covers its keys, its groups, and what it notes besides MLS, such as messages to re-send and groups to heal.
- **Each call gives the whole state.** Keep it in place of the one before, durably and encrypted at rest, for example with a key from the platform's keystore.
- **Return non-zero only once it is kept.** If you return 0, the change is undone and what needed it fails. For example, a message that would have been encrypted with it is not sent.
- **Don't call into the client** from the callback.
- **The first call comes from `rcs_client_set_e2ee` itself**, to keep the Participant Key it makes.

Pass the state you kept back to `rcs_client_set_e2ee` (`saved_state`) when the client is made again. Losing it loses the device's enrolment and the keys of its groups.

**A change to an encrypted conversation's MLS group is dropped if its session ends before the Focus accepts it:** when the Focus sends a BYE, the MSRP connection is lost, the app ends the session, or the client stops (the change is then dropped once the client is made again). That covers a participant added or removed, a subject or icon changed and a key update, and a leave if the client stopped before the Focus answered it. The Focus accepts a change only in the session that carried it (section 6.2.4), so the change would otherwise stay pending and block the group: nothing could be encrypted or signed in it. Ask for the change again if you still want it.
- **If the Focus never got it, or refused it,** the group goes on as before. A refusal that arrives later is still recognised, and not passed to the app.
- **If the Focus did accept it,** the device is out of step with the group. The group heals itself once that shows, for example when a message from another member can't be decrypted (section 10.1).

**A new encrypted group or chat whose INVITE the Focus hadn't answered when the client stopped is kept waiting instead.** Its first Commit, which the INVITE carried, stays pending, as the Focus may have made the group. The Focus makes a group only once it validated that Commit (section 8.2.1), and the client learns it did when it's invited in again:
- **a group:** when its Focus invites the client into it without a Welcome. The app is asked to take the invitation, as the client never learned the group's URI;
- **a chat:** when the contact invites the client into a new session of it, without a Welcome. The chat is kept then, with the token that INVITE carries.

The Commit is applied then, and the conversation is encrypted as for its other members. A group or chat the Focus never made is waited for 30 days at most. After that, its Commit is dropped the next time the client starts a new group or chat.

### 4. Group chat identifiers

Keep what `group_chat_ids_callback` tells you for each group, and give it back with `rcs_client_set_group_chat_ids` once the client is made again. That includes the MLS-Opaque-Token the Conversation Focus gives (section 6.1.3). Without it, the client cannot:
- restart an encrypted group with the identifiers its Focus knows it by;
- move an unencrypted group back to encrypted on schedule (see below).

## The order of the calls

```c
struct rcs_runtime *runtime = new_rcs_runtime();
struct rcs_client *client = new_rcs_client(runtime, ...);

// before configuring: the configuration requests carry what ACS signs the
// device's encryption identity for (RCC.16 section 4.1)
int32_t set = rcs_client_set_e2ee(client, home_kds, roots, root_lens, root_count,
                                  saved_state, saved_state_len,
                                  save_state, kds_enrol, kds_upload, kds_fetch, context);

rcs_client_start_config(runtime, client, on_config_progress, on_config_result, context);
// once configured
rcs_client_setup(runtime, client, ims_config, rcs_config);

// enrol, then connect whatever the result: without E2EE if enrolling failed
rcs_client_e2ee_enrol(runtime, client, on_enrolled, context);
// in on_enrolled: rcs_client_connect(runtime, client);
```

`rcs_client_set_e2ee` returns:
- 0: done;
- -1: an argument missing, or a root that is not a certificate;
- -2: a saved state that cannot be read;
- -3: the state could not be kept.

`rcs_e2ee_enrol_result_callback` is told:
- 0: enrolled, or its certificate renewed;
- 1: enrolled already;
- -1: E2EE not set, or no tel URI configured;
- -2: the Home KDS could not be reached;
- -3: it refused;
- -4: the certificate it issued is not one others would add the device with;
- -5: the MLS state could not be made or kept.

The client advertises E2EE in its capabilities only once enrolled. If enrolling fails, connect anyway: chats then go unencrypted, and you can try enrolling again later.

**Call `rcs_client_e2ee_enrol` again from time to time**, for example once a day. The device renews its certificate once it has less than 60 days left, and keeps its groups through the renewal (section 9.5.3). Otherwise the call does nothing.

## What the client does on its own

- **Chats with contacts:** `rcs_client_send_message` to a contact goes in an encrypted 1-to-1 chat when there is one, or starts one:
  - when the contact advertises E2EE v1 and the Home KDS has its KeyPackages. Messages sent meanwhile wait, and go in order;
  - otherwise, they go as they would without E2EE;
  - a chat unused for 30 days starts again in a new Era (section 8.3).
- **Group chats:** `rcs_client_create_group_chat` makes the group encrypted when every participant can take part. The group chat listener and the invitation callback tell you how each group stands:
  - the invitation callback's `encrypted` is 1 for an encrypted group. One the client cannot join is declined with 488, and you are not told of it;
  - event 4: the group moved to unencrypted (section 11.2);
  - event 5: it is encrypted again (section 11.1);
  - events 6 and 7: the encrypted subject and icon, decrypted, as they are set or deleted.
- **Adding and removing participants** goes through the Focus as before, along with the MLS Commits they need. A participant who cannot be removed from the MLS group is refused with 488.
- **Notifications:** the client sends delivery notifications itself as messages are taken. Send display notifications with `rcs_client_send_display_notification`: in an encrypted chat it signs them in the chat's session (section 9.1.4). `rcs_client_send_imdn_report` sends what it is given by SIP MESSAGE, unsigned, so don't use it for encrypted chats.
- **Files:** upload a file for a chat with the function for it, then send the XML the result callback gives as the message, within a day. The file and thumbnail are encrypted before upload when the message goes encrypted:
  - to a group, `rcs_client_upload_group_file`, giving the group's Conversation-ID: while the group is encrypted;
  - to a contact, `rcs_client_upload_chat_file`, giving the contact: when the message goes in an encrypted 1-to-1 chat. That is the one kept with the contact while it is encrypted, or a new one if the contact advertises E2EE, which the upload asks over OPTIONS. If the message goes unencrypted after all, as when the Home KDS has no KeyPackages of the contact, it is refused with 488: upload the file again with `rcs_client_upload_file` and send that.

  A file uploaded otherwise, as with `rcs_client_upload_file`, is not sent in an encrypted chat: its message fails with 500. A file received encrypted is decrypted as `rcs_client_download_file` or `rcs_client_download_message_file` downloads it:
  - the whole file is downloaded, whatever `start` is;
  - its key is used once, so download it once.
- **Keeping groups in step:**
  - self-healing when the device misses something (section 10.1);
  - key updates (section 9.5.2);
  - replacing members whose keys are old or whose certificates expired (section 9.5.4);
  - new Eras when healing fails (section 8.3);
  - telling senders of messages that could not be decrypted, and taking the messages they re-send (sections 10.2 to 10.4);
  - moving a group to unencrypted when it cannot stay encrypted, and back once it can (section 11).

  None of this needs the app.
- **Moving back to encrypted** is also checked on schedule while the engine runs: about weekly for unencrypted groups with a message in the last 30 days (section 11.1.1).

## User aliases

Set the user's alias with `rcs_client_set_user_alias` (NULL for none). The client sends it as RCC.07 section 2.5.3.3 has it: as the display name of the From of the requests starting a chat, a group chat or a standalone message, and in a group chat also in the CPIM From of each message.

In an encrypted chat or group, the alias is never sent in the clear (RCC.16 section 9.1.5):
- **It goes encrypted** for the conversation's MLS group, in the `encrypted-alias` parameter of the From's URI. That covers a new session of a chat kept, a group restarted, and each message of an encrypted group, whose CPIM From the encryption otherwise leaves in the clear (section 7.5.7).
- **In the INVITE starting a chat or group**, or restarting one in a new Era, it goes encrypted in the epoch the first Commit the INVITE carries leads to, which those it invites join in.
- **It is left out** when it cannot go so that its members can decrypt it, as while the device cannot encrypt for the group.

Set `rcs_client_set_alias_listener` to be told the alias each sender gives itself: its URI, the alias, and `encrypted`. The alias comes from:
- the From of a chat invitation;
- the Referred-By of a group chat invitation, which also gives `inviter_name`;
- the CPIM From of a message of a group chat;
- the From of a standalone message.

An encrypted alias is decrypted in the conversation's MLS group, and told with `encrypted` 1 only if a Client of that URI's user encrypted it. One that cannot be decrypted is not told, though a display name next to it is, with `encrypted` 0. That is the case of one another client encrypts for the INVITE starting a conversation in the epoch before its first Commit, which those it invites never join. Each sender's alias is told once, and again when it changes.

An alias is the sender's own claim. Show it as unchecked for a contact not in the address book, and the address book's name otherwise (RCC.07 section 2.5.3.3).

## Identity verification

Show the user the code they and a contact compare to check that nobody stands between them (section 5.5):

```c
char code[81];
if (rcs_client_identity_verification_code(client, contact_uri, conversation_id, code) == 0) {
    // 80 digits, the same on both sides; show them, for example in groups of
    // five, or as a QR code
}
```

`conversation_id` may be NULL. Without it, the contact's key is looked for in the encrypted 1-to-1 chat with them; with it, in that group chat too. The function returns:
- 0: written;
- -1: E2EE is not set, or `contact` or `code` is NULL;
- -2: the device holds no valid certificate of the user;
- -3: no valid certificate of the contact is known in those chats.

Nothing is written unless it returns 0.

## What the app is not told

- **No per-message flag:** the message callback gives the message as it was sent, decrypted. Whether a group is encrypted is told through the group events above. For a 1-to-1 chat there is no indication yet.
- **No reasons in the open:** negative delivery notifications with RCC.16 failure reasons reach the app as IMDN documents, the reason inside them. A client's `<expired-credential>` uses the value 14 in its signature, which RCC.16 does not define yet.

## Not covered yet

- **A new Era of a group or chat whose INVITE wasn't answered before the client stopped** is dropped as other changes are, and the group heals once another member's message shows it out of step. Only a new group or chat is kept waiting for the Focus.
- **RCS Video encryption** (section 9.8).
