# RCS Video Chat (GSMA RCC.07 section 3.7.5)

RCS Video Chat is the WebRTC video call RCC.07 v18.0 starts from a conversation: a Messaging-Initiated Video Call (MIVC). The client signals a 1-to-1 call in the chat with the contact, and a group call in the group chat, through the group's Controlling Function. It keeps the call's timers. The app's WebRTC stack does the media, to the contact or to the SFU of the group.

- **The client** carries the SDP offer and answer, the ICE candidates and the media updates between the two sides. They go as `rcs/video-chat+proto` messages of the chat's MSRP session, which the app never sees (section 3.7.5.2.3). It also runs the call's timers and reports joining and leaving to the Service Provider.
- **The app** gathers the ICE candidates, makes the SDP, connects DTLS-SRTP and picks the codecs (sections 3.7.5.2.1, 3.7.5.3). It tells the client when the media connects or goes down.

A call goes on at a time, 1-to-1 or of a group. Group calls are taken in groups not encrypted end to end for now.

## Configuration

`rcs_client_get_video_chat_config` gives the MIVC configuration of the Service Provider (section A.1.3):

- **`technology`** is the MIVC TECHNOLOGY:
  - 0: no MIVCs;
  - 1: ViLTE alone, which is the dialler's (IR.94), not this client's;
  - 2: ViLTE preferred, with RCS Video Chat as fallback;
  - 3: RCS Video Chat alone.

  With 2, offer ViLTE when the contact is capable of it, and RCS Video Chat otherwise (section 3.7.3.3).
- **`turn_mandatory`** is 1 when the ICE candidates offered must be those of the TURN servers given, and no others (section 3.7.5.2.1). The call fails if none of them can be reached.
- **The TurnCredentials** are told to the callback, one call each: the URIs of the TURN servers (RFC 7065), with the username and password they share.

## Taking calls

Set the listener with `rcs_client_set_video_chat_listener`. Setting it tells the client the app takes RCS Video Chats. From then on, the client advertises `+g.gsma.rcs.videochat` in OPTIONS exchanges whenever `technology` is 2 or 3 (section 3.7.3.6).

To know whether a contact takes RCS Video Chats, look for that tag in what `rcs_client_query_capabilities` gives.

The listener has three callbacks.

### The call's events

| `event` | what happened | `sdp` | `reason` |
|---|---|---|---|
| 0 incoming | a call offered by the contact, the callee alerted | the SDP offer | |
| 1 alerting | the callee is alerted | | |
| 2 answered | the callee answered; connect the media | the SDP answer | |
| 3 rejected | the callee rejected it | | the RejectReason: 1 by the user, 2 another call went on |
| 4 not answered | no answer in time; the client cancelled it | | |
| 5 missed | cancelled, not answered in time, too old, or offered while another call went on | | |
| 6 ended | hung up by the contact, or failed as the media did not connect in time | | the HangupReason: 1 hung up, 2 timed out |
| 7 failed | the chat message the call needed could not be sent | | its status code |
| 8 connect | the SFU answered a group call the client offers; connect to it | the SFU's SDP answer | |

For a group call, `contact_uri` is the group's URI, and:
- event 0 gives the SFU's SDP offer, with `reason` 1 for a call going on already, not to ring (section 3.7.5.5.7);
- events 1 and 2 come as the first participant is alerted and answers;
- event 6 can come with reason 3, the SFU having found the client disconnected.

The call is over after events 3 to 7. A group call goes on for the others.

### ICE candidates

These are the candidates of the contact to add and remove. `reconnecting` is not 0 if the media had connected and is to connect again (section 3.7.5.4.8.2).

### Media updates

These are the views the contact prefers to receive, and the bandwidth it can take (section 3.7.5.4.8.3).

### Group calls

`rcs_client_set_group_video_chat_listener` sets two more callbacks:
- **each participant:** alerted (0), answered (1), rejected the call (2, with the RejectReason) or left it (3, with the HangupReason, 3 if the SFU found it disconnected);
- **the participants as the Controlling Function has them:** each with its MSISDN, its SFU user id, whether it joined, and its streams, which the SFU's media is known by.

## The order of the calls

**Calling:**

1. Make the SDP offer: full ICE, UDP candidates only, the DTLS fingerprint, and the codecs (section 3.7.5.2.1).
2. Call `rcs_client_start_video_chat` with it. It writes the call_id to a buffer of 37 bytes at least.
3. Event 1 tells you the callee is alerted.
4. Event 2 gives the SDP answer: apply it and connect.
5. Call `rcs_client_video_chat_media_connected` once the media is up.

**Answered:**

1. Event 0 gives the SDP offer. Alert the user.
2. If the user answers, make the SDP answer and call `rcs_client_accept_video_chat`.
3. Connect, and call `rcs_client_video_chat_media_connected` once the media is up.

**During the call:**

- After an IP address change, gather the candidates again and send them with `rcs_client_update_video_chat_ice_candidates`.
- When the media goes down, call `rcs_client_video_chat_media_disconnected`, then `rcs_client_video_chat_media_connected` once it is back.
- Send the views you prefer with `rcs_client_update_video_chat_media`, as network conditions change.

**A group call** (section 3.7.5.5):

1. Make the SDP offer to the SFU, and call `rcs_client_start_group_video_chat` with the group's URI.
2. Event 8 gives the SFU's answer: connect to it, and call `rcs_client_video_chat_media_connected` once up.
3. Events 1 and 2 come as the first participant is alerted and answers; the participant callbacks tell of each.

Offered one, event 0 gives the SFU's offer: answer it with `rcs_client_accept_video_chat` as for a 1-to-1 call. The AcceptInvitation goes with the SDP answer as the user answers, which the SFU needs to connect; section 3.7.5.5.3 has it sent once the media connected. ICE candidates and media updates go to the Controlling Function alone.

**Ending:** `rcs_client_hang_up_video_chat` does what the user meant by the call's state:

- it cancels a call not answered yet;
- it rejects a call offered;
- it hangs up otherwise.

When the contact hangs up, the client answers with a Hangup of its own (section 3.7.5.4.4). Close the media when event 6 comes. In a group call, a participant hanging up leaves the call to the others; nothing is answered.

## Timers

The timers are multiples of SIP's T1, 500 ms (section 3.7.5.2.4):

| timer | for | after |
|---|---|---|
| Timer_Alpha | the callee to be alerted | 32 s, then cancelled: event 4 |
| Timer_Beta | the callee to answer | 32 s, then cancelled: event 4 |
| Timer_Gamma | a call offered to ring, from when it was sent | 32 s, then missed: event 5. An older one is missed at once, without alerting. |
| Timer_Delta | the media to connect, once answered or after an ICE update | 10 s, then hung up: event 6, reason 2 |
| Timer_Epsilon | the media to connect again, once down | 10 s, then hung up: event 6, reason 2. Not for a group call, whose SFU waits for it (Timer_Zeta). |

## Reporting

If the configuration has an MIVC REPORTING URI, the client sends it a SIP MESSAGE (section 3.7.5.2.5):

- **JOIN** the first time the media connects, for a group call once it is answered too;
- **LEAVE** once a call joined ends.

A group call is reported by the Conversation-ID of the group.

## E2EE

With the `e2ee` feature, the messages of a call go in the chat with the contact as any message does. If the chat is encrypted, they go encrypted (RCC.16 section 9.8.1), and a contact that advertises E2EE gets a new encrypted chat. The media is protected by the DTLS-SRTP of WebRTC, end to end between the two devices.

In a group encrypted end to end, the signalling is to be signed and the media encrypted with SFrame (section 9.8.2), which the client does not do yet. A group call is not started there (event 7 with 488), and one offered there is not taken.

## Where RCC.07 is silent

The client:

- **reports with the content type `rcs/video-chat+proto`.** RCC.07 gives none for the VideoChatEventNotification of the SIP MESSAGE; this is the one its other video chat messages use.
- **reports with the callee of the call as `one_to_one_participant_uri`,** as section 3.7.5.2.3.4 has it. When this client is the callee, that is its own URI.
- **does not ask for delivery notifications of the call's messages.** The AckInvitation tells of the invitation's delivery.
- **takes a call's messages only from its contact.** Its tel URI and a SIP URI of its number count as the same.
- **rejects with `REJECT_REASON_ALREADY_IN_PROGRESS`** a call offered while another goes on, and tells the app it was missed.
- **treats a Hangup before the call is answered as a cancel.**
- **rings for Timer_Gamma** a call whose CPIM DateTime cannot be read, or lies ahead of the clock.
- **sends the AcceptInvitation of a group call with the SDP answer as the user answers,** where section 3.7.5.5.3 has it sent once the media connected, which it cannot without the answer.
- **sends an ICE or media update of a group call with a VideoChatMessage of its call_id alone,** for the Controlling Function to know the call.
- **lets Timer_Beta run on as a participant of a group call rejects it,** waiting for the others, where section 3.7.5.5.4 has it stopped.
- **takes a group call's signals of the participant of the CPIM From** of the ServerGroupVideoMessage relaying them, and a Hangup of its own as the SFU's.

## Not covered yet

- **Group RCS Video Chats in groups encrypted end to end** (RCC.16 section 9.8.2): their signalling signed, and their media encrypted with SFrame, which rust-rcs-core keys from the MLS group.
- **gRPC-configured clients** (RCC.30 section 3.1.4).
