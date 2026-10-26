/*
 * Copyright 2023 宋昊文
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdint.h>

struct rcs_runtime;
struct rcs_client;

#define rcs_multi_conference_v1_event_type_on_user_joined 0
#define rcs_multi_conference_v1_event_type_on_user_left 1
#define rcs_multi_conference_v1_event_type_on_conference_ended 2

struct rcs_messaging_session;

struct rcs_multi_conference_v1;
struct rcs_multi_conference_v1_event;

extern struct rcs_runtime *new_rcs_runtime();

typedef void (*state_change_callback) (int state, void *context);

void state_change_callback_context_release(void *context);

#define rcs_message_service_cpm_one_to_one 0
#define rcs_message_service_cpm_standalone 1
#define rcs_message_service_deferred_one_to_one 2

typedef void (*message_callback) (int service_type, struct rcs_messaging_session *session,
                                const char *contact_uri, const char *content_type, const char *content_body,
                                const char *imdn_message_id, const char *cpim_date, const char *cpim_from,
                                void *context);

void message_callback_context_release(void *context);

typedef void (*multi_conference_v1_event_listener_function) (uint16_t event_type, struct rcs_multi_conference_v1_event *event, void *context);

struct multi_conference_v1_invite_response {
    uint16_t status_code;
    const char *answer_sdp;
    multi_conference_v1_event_listener_function event_listener;
    void *event_listener_context;
};

struct multi_conference_v1_invite_response_receiver;

extern void multi_conference_v1_invite_response_receiver_send_response(struct multi_conference_v1_invite_response_receiver *receiver, struct multi_conference_v1_invite_response *response);

extern void free_multi_conference_v1_invite_response_receiver(struct multi_conference_v1_invite_response_receiver *receiver);

typedef void (*multi_conference_v1_invite_handler_function) (struct rcs_multi_conference_v1 *conference, const char *offer_sdp, size_t offer_sdp_len, struct multi_conference_v1_invite_response_receiver *response_receiver, void *context);

void multi_conference_v1_invite_handler_context_release(void *context);

extern struct rcs_client *new_rcs_client(struct rcs_runtime *runtime, int32_t subscription_id, uint16_t mcc, uint16_t mnc, const char *imsi, const char *imei, const char *msisdn, const char *fs_root_dir, state_change_callback state_cb, void *state_cb_context, message_callback message_cb, void *message_cb_context, multi_conference_v1_invite_handler_function multi_conference_v1_invite_handler, void *multi_conference_v1_invite_handler_context);

typedef void (*auto_config_process_callback) (int32_t status_code, void *context);

typedef void (*auto_config_result_callback) (int32_t status_code, const char *ims_config, const char *rcs_config, const char *extra, void *context);

void auto_config_callback_context_release(void *context);

// configuration
extern void rcs_client_start_config(struct rcs_runtime *runtime, struct rcs_client *client, auto_config_process_callback p_cb, auto_config_result_callback r_cb, void *context);

extern void rcs_client_input_otp(struct rcs_runtime *runtime, struct rcs_client *client, const char *otp);

extern void rcs_client_setup(struct rcs_runtime *runtime, struct rcs_client *client, const char *ims_config, const char *rcs_config);

extern void rcs_client_connect(struct rcs_runtime *runtime, struct rcs_client *client);

// capability discovery (RCC.07 section 2.6.1.1): told what a contact answered an OPTIONS with, to be taken as RCC.07
// table 6 says: its final status code (0 if none came, 403 if the client is not registered to ask), and the feature
// tags of the Contact of a 200, ';' separated
typedef void (*capabilities_callback) (uint16_t status_code, const char *feature_tags, void *context);

// asks contact_uri for its capabilities over SIP OPTIONS, telling it those of this client; 400 if it is NULL or empty;
// the context is released with message_result_callback_context_release
extern void rcs_client_query_capabilities(struct rcs_runtime *runtime, struct rcs_client *client, const char *contact_uri,
                                capabilities_callback cb, void *context);

// end-to-end encryption (GSMA RCC.16), in a library built with the e2ee feature; the contexts below are
// released with message_result_callback_context_release()
//
// in order: new_rcs_client, rcs_client_set_e2ee, rcs_client_start_config, rcs_client_setup,
// rcs_client_e2ee_enrol, then rcs_client_connect once enrolled, or without E2EE if it failed

// a request to the app's Home KDS, answered once with one of the rcs_kds_request_* functions, at once or later,
// from any thread
struct rcs_kds_request;

// asks the app to enrol the device: its tel URI and Cipher Suite, its MLS signature key, the Client ID and the DER
// encoded ParticipantInformation for its Client Certificate, and the ACS Signed Encryption Identity Proof (NULL if
// there is none); answered with rcs_kds_request_enrolled or rcs_kds_request_failed
typedef void (*rcs_kds_enrol_function) (const char *tel_uri, uint16_t ciphersuite, const uint8_t *signature_key,
                                size_t signature_key_len, const char *client_id, const uint8_t *participant_information,
                                size_t participant_information_len, const uint8_t *identity_proof, size_t identity_proof_len,
                                struct rcs_kds_request *request, void *context);

// asks the app to upload KeyPackages of the device; answered with rcs_kds_request_uploaded or rcs_kds_request_failed
typedef void (*rcs_kds_upload_function) (const uint8_t *const *key_packages, const size_t *key_package_lens, size_t count,
                                struct rcs_kds_request *request, void *context);

// asks the app for the KeyPackages of Participants, by tel URI and Home KDS capability value, in the first of the
// Cipher Suites all of them have; answered with rcs_kds_request_add_key_packages for each Participant then
// rcs_kds_request_fetched, or with rcs_kds_request_failed
typedef void (*rcs_kds_fetch_function) (const uint16_t *ciphersuites, size_t ciphersuite_count, const char *const *tel_uris,
                                const char *const *home_kds, size_t recipient_count, struct rcs_kds_request *request,
                                void *context);

// has the app keep the MLS state of the device, encrypted, in place of the one kept before; not 0 if it did; it must
// not call into the client
typedef int32_t (*rcs_e2ee_save_state_function) (const uint8_t *state, size_t state_len, void *context);

// answers an enrolment with the certificate chain the Home KDS issued, Client Certificate first
extern void rcs_kds_request_enrolled(struct rcs_kds_request *request, const uint8_t *const *certificates,
                                const size_t *certificate_lens, size_t count);

// answers an upload as done
extern void rcs_kds_request_uploaded(struct rcs_kds_request *request);

// adds to the answer of a fetch what the Home KDS has for the Participant at tel_uri: its KeyPackages (status 0), or
// that it was not found (1), its number was malformed (2), it has no Cipher Suite in common (3), or it is unavailable (4)
extern void rcs_kds_request_add_key_packages(struct rcs_kds_request *request, const char *tel_uri, int32_t status,
                                const uint8_t *const *key_packages, const size_t *key_package_lens, size_t count);

// answers a fetch with what was added to it
extern void rcs_kds_request_fetched(struct rcs_kds_request *request);

// answers a request as failed: the Home KDS could not be reached (refused 0), or refused it for reason (may be NULL)
extern void rcs_kds_request_failed(struct rcs_kds_request *request, int32_t refused, const char *reason);

// has the client encrypt end to end with the Home KDS of Vendor ID home_kds, trusting the DER encoded roots; its MLS
// state is taken from saved_state (NULL if none) and kept from now on with save, called at once to keep a Participant
// Key made; the configuration requests from now on carry what ACS signs the encryption identity of the device for;
// 0 if done, -1 for an argument missing or a root not one, -2 for a saved state not one, -3 if the state could not be
// kept
extern int32_t rcs_client_set_e2ee(struct rcs_client *client, uint32_t home_kds, const uint8_t *const *roots,
                                const size_t *root_lens, size_t root_count, const uint8_t *saved_state, size_t saved_state_len,
                                rcs_e2ee_save_state_function save, rcs_kds_enrol_function enrol, rcs_kds_upload_function upload,
                                rcs_kds_fetch_function fetch, void *context);

// told how enrolling went: 0 enrolled, or its certificate renewed, 1 already was, -1 E2EE not set or no tel URI configured, -2 the Home KDS could not
// be reached, -3 it refused, -4 the certificate it issued is not one others would add the device with, -5 the MLS state
// could not be made or kept
typedef void (*rcs_e2ee_enrol_result_callback) (int32_t status, void *context);

// enrols the device with its Home KDS for the identity it was configured with, unless it holds a certificate others
// would still add it with, with more than 60 days left; one with less is renewed, the device keeping its groups
// (RCC.16 section 9.5.3); once configured, before connecting, and again from time to time for the renewal
extern void rcs_client_e2ee_enrol(struct rcs_runtime *runtime, struct rcs_client *client, rcs_e2ee_enrol_result_callback cb,
                                void *context);

extern void rcs_client_disconnect(struct rcs_runtime *runtime, struct rcs_client *client);

// messaging
typedef void (*message_result_callback) (uint16_t status_code, const char *reason_phrase, void *context);

void message_result_callback_context_release(void *context);

#define recipient_type_contact 0
#define recipient_type_chatbot 1
#define recipient_type_group 2
#define recipient_type_resource_list 3

extern void rcs_client_send_message(struct rcs_runtime *runtime, struct rcs_client *client, const char *message_type, const char *message_content, const char *recipient,
                                int8_t recipient_type,
                                message_result_callback cb, void *context);

// as rcs_client_send_message, with the imdn.Message-ID that delivery and display notifications of the message give, or a new one if NULL
extern void rcs_client_send_message_with_imdn_id(struct rcs_runtime *runtime, struct rcs_client *client, const char *message_type, const char *message_content, const char *recipient,
                                int8_t recipient_type, const char *imdn_message_id,
                                message_result_callback cb, void *context);

typedef void (*group_chat_result_callback) (uint16_t status_code, const char *reason_phrase, const char *conference_uri, void *context);

// starts a new group chat through the provisioned conference factory, about subject unless NULL;
// the callback is told the URI of the group once it starts (NULL if it did not), messages to it being sent with recipient_type_group;
// with E2EE set and enrolled, the group is created encrypted (RCC.16 section 8.1) when every participant advertises E2EE v1
// and the Home KDS has KeyPackages of each, and unencrypted otherwise
extern void rcs_client_create_group_chat(struct rcs_runtime *runtime, struct rcs_client *client,
                                const char *const *participants, size_t participant_count, const char *subject,
                                group_chat_result_callback cb, void *context);

// told of a group chat taken part in: joined (event 0), a participant's status (1), left (2),
// that an invitation to it waiting for the user's answer was withdrawn by whoever sent it (3),
// or that it is no longer encrypted end to end, as RCC.16 section 11.2 moves it to unencrypted (4);
// for 1, the participant's URI, display name (or NULL) and status: connected, pending, ..., departed, booted, disconnected
typedef void (*group_chat_event_callback) (int32_t event, const char *conference_uri, const char *participant_uri,
                                const char *display_name, const char *status, void *context);

// sets the group chat listener; the context of one set before is released
extern void rcs_client_set_group_chat_listener(struct rcs_client *client, group_chat_event_callback cb, void *context);

// told of an invitation to a group chat not known before: the group's URI and Conversation-ID, then its subject and the URI
// and display name of whoever invited, each NULL if not told; pending != 0 if it waits for the user's answer, as group chats
// are not accepted automatically (AutAcceptGroupChat 0), else it is being accepted, and joined (event 0) once it is;
// encrypted != 0 if the group is encrypted end to end (RCC.16), its MLS group joined; an encrypted group the client cannot
// join is declined (488) without being told of
typedef void (*group_chat_invitation_callback) (const char *conference_uri, const char *conversation_id, const char *subject,
                                const char *inviter_uri, const char *inviter_name, int32_t pending, int32_t encrypted,
                                void *context);

// sets the group chat invitation listener; the context of one set before is released
extern void rcs_client_set_group_chat_invitation_listener(struct rcs_client *client, group_chat_invitation_callback cb, void *context);

// told of the identifiers of a group chat, once known or changed, for the app to keep and give back with
// rcs_client_set_group_chat_ids once the client is made again, so that the group is restarted with them and known
// when its focus restarts it; mls_opaque_token is what the requests of the conversation carry for its focus (RCC.16
// section 6.1.3), NULL if the focus gave none
typedef void (*group_chat_ids_callback) (const char *conference_uri, const char *conversation_id, const char *contribution_id,
                                const char *mls_opaque_token, void *context);

// sets the group chat identifiers listener; the context of one set before is released
extern void rcs_client_set_group_chat_ids_listener(struct rcs_client *client, group_chat_ids_callback cb, void *context);

// gives back the identifiers of a group chat the app kept; nothing if any but mls_opaque_token (NULL if none was
// given) is NULL or empty
extern void rcs_client_set_group_chat_ids(struct rcs_client *client, const char *conference_uri, const char *conversation_id,
                                const char *contribution_id, const char *mls_opaque_token);

// accepts (accept != 0) or declines the invitation to the group chat that waits for the user's answer: 404 if there is none
extern void rcs_client_answer_group_chat_invitation(struct rcs_runtime *runtime, struct rcs_client *client, const char *conference_uri,
                                int accept, message_result_callback cb, void *context);

// asks the focus of the group, in the session there is with it, to invite participants: 404 if there is no session
extern void rcs_client_add_group_chat_participants(struct rcs_client *client, const char *conference_uri,
                                const char *const *participants, size_t participant_count,
                                message_result_callback cb, void *context);

// asks the focus of the group, in the session there is with it, to remove a participant: 404 if there is no session;
// in an encrypted group, 488 if the participant cannot be removed from its MLS group
extern void rcs_client_remove_group_chat_participant(struct rcs_client *client, const char *conference_uri,
                                const char *participant, message_result_callback cb, void *context);

// leaves the group chat for good, where ending its session leaves it only until the next; its session is restarted first if there is none;
// a restart refused with 404 or 403 means the user already takes no part in the group
extern void rcs_client_leave_group_chat(struct rcs_runtime *runtime, struct rcs_client *client, const char *conference_uri,
                                message_result_callback cb, void *context);

// tells the recipient, in the chat session there is with it, that the user is composing (active != 0) or no longer is;
// no session is started for it: 404 if there is none
extern void rcs_client_send_is_composing(struct rcs_runtime *runtime, struct rcs_client *client, const char *recipient,
                                int8_t recipient_type, int active,
                                message_result_callback cb, void *context);

// ends the chat session with a contact or a group: 404 if there is none; a message sent to it from now on starts another
extern void rcs_client_end_chat_session(struct rcs_client *client, const char *recipient,
                                message_result_callback cb, void *context);

typedef void (*send_imdn_report_result_callback) (uint16_t status_code, const char *reason_phrase, void *context);

void send_imdn_report_result_callback_context_release(void *context);

// sends an IMDN document (RFC 5438) to the sender of a message, by the service it came by: a chat (0) or standalone messaging (1)
extern void rcs_client_send_imdn_report(struct rcs_runtime *runtime, struct rcs_client *client,
                                const char *imdn_content, const char *sender_uri, int sender_service_type, struct rcs_messaging_session *session,
                                send_imdn_report_result_callback callback, void *context);

// tells the sender of a message lately taken that it was displayed, if it asked to be told: 404 if the message is not known, 403 if it did not ask
extern void rcs_client_send_display_notification(struct rcs_runtime *runtime, struct rcs_client *client, const char *imdn_message_id,
                                send_imdn_report_result_callback callback, void *context);

typedef void (*upload_file_progress_callback) (uint32_t current, int32_t total, void *context);

void upload_file_progress_callback_context_release(void *context);

typedef void (*upload_file_result_callback) (uint16_t status_code, const char *reason_phrase, const char *result_xml, void *context);

void upload_file_result_callback_context_release(void *context);

extern void rcs_client_upload_file(struct rcs_runtime *runtime, struct rcs_client *client, const char *tid,
                                const char *file_path, const char *file_name, const char *file_mime, const char *file_hash,
                                const char *thumbnail_path, const char *thumbnail_name, const char *thumbnail_mime, const char *thumbnail_hash,
                                upload_file_progress_callback progress_cb, void* progress_cb_context,
                                upload_file_result_callback result_cb, void *result_cb_context);

typedef void (*download_file_progress_callback) (uint32_t current, int32_t total, void *context);

void download_file_progress_callback_context_release(void *context);

typedef void (*download_file_result_callback) (uint16_t status_code, const char *reason_phrase, void *context);

void download_file_result_callback_context_release(void *context);

extern void rcs_client_download_file(struct rcs_runtime *runtime, struct rcs_client *client,
                                const char *file_uri, const char *download_path, uint32_t start, int32_t total,
                                download_file_progress_callback progress_cb, void *progress_cb_context,
                                download_file_result_callback result_cb, void *result_cb_context);

// as rcs_client_download_file, with what the message that brought the file's URL tells, for the download proxy to be told
// if one is provisioned (ftHTTPDLURI): its imdn.Message-ID, its other party (a contact, or a group by its URI) and the
// Conversation-ID of the group chat it came in, each NULL if not known; that of a group the client has had a session with
// is told without being given
extern void rcs_client_download_message_file(struct rcs_runtime *runtime, struct rcs_client *client,
                                const char *file_uri, const char *download_path, uint32_t start, int32_t total,
                                const char *imdn_message_id, const char *other_party, const char *conversation_id,
                                download_file_progress_callback progress_cb, void *progress_cb_context,
                                download_file_result_callback result_cb, void *result_cb_context);

extern void destroy_rcs_messaging_session(struct rcs_messaging_session *session);

// conference
extern char *rcs_multi_conference_v1_event_get_user_joined(struct rcs_multi_conference_v1_event *event);

extern char *rcs_multi_conference_v1_event_get_user_left(struct rcs_multi_conference_v1_event *event);

extern void free_rcs_multi_conference_v1_event(struct rcs_multi_conference_v1_event *event);

void multi_conference_v1_event_listener_context_release(void *context);

typedef void (*multi_conference_v1_create_result_callback) (struct rcs_multi_conference_v1 *conference, const char *sdp, size_t sdp_len, void *context);

void multi_conference_v1_create_result_callback_context_release(void *context);

extern void rcs_client_create_multi_conference_v1(struct rcs_runtime *runtime, struct rcs_client *client, const char *recipients, const char *offer_sdp, multi_conference_v1_event_listener_function event_listener, void *event_listener_context, multi_conference_v1_create_result_callback result_callback, void *result_callback_context);

typedef void (*multi_conference_v1_join_result_callback) (struct rcs_multi_conference_v1 *conference, const char *sdp, size_t sdp_len, void *context);

void multi_conference_v1_join_result_callback_context_release(void *context);

extern void rcs_client_join_multi_conference_v1(struct rcs_runtime *runtime, struct rcs_client *client, const char *conference_id, const char *offer_sdp, multi_conference_v1_event_listener_function event_listener, void *event_listener_context, multi_conference_v1_join_result_callback result_callback, void *result_callback_context);

extern void rcs_multi_conference_v1_keep_alive(struct rcs_runtime *runtime, struct rcs_multi_conference_v1 *conference);

extern void destroy_rcs_multi_conference(struct rcs_multi_conference_v1 *conference);

// extern void rcs_multi_conference_invite_more();

// extern void rcs_multi_conference_get_updated_info();

typedef void (*retrieve_specific_chatbots_result_callback) (uint16_t status_code, const char *reason_phrase, const char *specific_chatbots, const char *response_etag, uint32_t expiry, void *context);

void retrieve_specific_chatbots_result_callback_context_release(void *context);

extern void rcs_client_retrieve_specific_chatbots(struct rcs_runtime *runtime, struct rcs_client *client, const char *local_etag, retrieve_specific_chatbots_result_callback cb, void *context);

typedef void (*search_chatbot_result_callback) (uint16_t status_code, const char *reason_phrase, const char *chatbot_search_result_list_json, void *context);

void search_chatbot_result_callback_context_release(void *context);

extern void rcs_client_search_chatbot(struct rcs_runtime *runtime, struct rcs_client *client, const char *query, uint32_t start, uint32_t num, search_chatbot_result_callback cb, void *context);

typedef void (*retrieve_chatbot_info_result_callback) (uint16_t status_code, const char *reason_phrase, const char *chatbot_info, const char *response_etag, uint32_t expiry, void *context);

void retrieve_chatbot_info_result_callback_context_release(void *context);

extern void rcs_client_retrieve_chatbot_info(struct rcs_runtime *runtime, struct rcs_client *client, const char *chatbot_sip_uri, const char *local_etag, retrieve_chatbot_info_result_callback cb, void *context);

// destroy
extern void destroy_rcs_client(struct rcs_client *client);
