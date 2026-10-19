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

//! Requests to the HTTP content server, authorized as it asks: by GBA (3GPP
//! TS 33.222) or by Digest with the ftHTTPCSUser and ftHTTPCSPwd provisioned

use std::sync::Arc;

use futures::{AsyncBufRead, AsyncReadExt};
use rust_rcs_core::{
    ffi::log::platform_log,
    http::{request::Request, response::Response, HttpClient},
    internet::{header, Header},
    security::{
        authentication::{
            digest::{DigestAnswerParams, DigestCredentials},
            AuthenticationMethod, AuthenticationMethods,
        },
        gba::{self, GbaContext},
        SecurityContext,
    },
    util::rand,
};
use url::Url;

const LOG_TAG: &str = "fthttp";

pub type ResponseBody = Box<dyn AsyncBufRead + Send + Unpin>;

/// What a request is authorized with
pub enum Auth<'r> {
    /// What the server last told of itself, if anything
    Stored,
    /// The answer to the challenge of a 401 the server gave
    ChallengeOf(&'r Header),
}

/// The content server, and what requests to it are made with
pub struct ContentServer<'a> {
    pub http_client: &'a Arc<HttpClient>,
    pub gba_context: &'a Arc<GbaContext>,
    pub security_context: &'a Arc<SecurityContext>,
    /// ftHTTPCSUser and ftHTTPCSPwd, for the content server asking for
    /// Digest outside GBA
    pub credentials: Option<Credentials<'a>>,
    /// The user the requests are made for, as X-3GPP-Intended-Identity
    pub msisdn: Option<&'a str>,
}

/// The credentials provisioned for the content server, which no other host
/// is answered with, as the URL of a file to download comes from its sender
pub struct Credentials<'a> {
    /// The host of ftHTTPCSURI
    pub host: &'a str,
    pub user: &'a str,
    pub password: &'a str,
}

/// The request-target of a request for `url` (RFC 9112 section 3.2.1), which
/// a Digest answer is for
pub fn request_target(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{}", url.path(), query),
        None => String::from(url.path()),
    }
}

/// The Host header value of a request for `url`: its host, and its port if
/// not the scheme's own (RFC 9110 section 7.2)
pub fn host_header(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => String::from(host),
    })
}

impl ContentServer<'_> {
    /// Sends a `method` request for `url`, `make` adding its own headers and
    /// body, authorized as `auth` says. A request the server challenges is
    /// made again, once, with the answer to the challenge, unless
    /// `answer_challenge` is false. None if the request could not be sent.
    pub async fn send<M>(
        &self,
        method: &'static [u8],
        url: &Url,
        make: M,
        progress: Arc<dyn Fn(usize) + Send + Sync>,
        auth: Auth<'_>,
        answer_challenge: bool,
    ) -> Option<(Response, Option<ResponseBody>)>
    where
        M: Fn(&mut Request),
    {
        let host = url.host_str()?;
        let target = request_target(url);

        let mut conn = self.http_client.connect(url, false).await.ok()?;

        let mut answer = match auth {
            Auth::Stored => self
                .security_context
                .preload_auth(self.gba_context, host, conn.cipher_id(), method, None)
                .map(|mut answer| {
                    platform_log(LOG_TAG, "using stored authorization info");
                    answer.uri = target.as_bytes().to_vec();
                    answer
                }),
            Auth::ChallengeOf(www_authenticate) => Some(
                self.answer(www_authenticate, host, conn.cipher_id(), method, &target)
                    .await?,
            ),
        };

        let mut challenged = !answer_challenge;

        loop {
            let mut req = Request::new_with_default_headers(
                method,
                &host_header(url)?,
                url.path(),
                url.query(),
            );

            if let Some(msisdn) = self.msisdn {
                req.headers.push(Header::new(
                    b"X-3GPP-Intended-Identity",
                    format!("tel:{}", msisdn),
                ));
            }

            if let Some(answer) = &answer {
                authorize(&mut req, answer);
            }

            make(&mut req);

            let progress = Arc::clone(&progress);
            let (resp, mut body) = conn.send(req, move |n| progress(n)).await.ok()?;

            platform_log(
                LOG_TAG,
                format!(
                    "{} {} answered with {}",
                    String::from_utf8_lossy(method),
                    target,
                    resp.status_code
                ),
            );

            if resp.status_code == 401 && !challenged {
                challenged = true;

                if let Some(www_authenticate) =
                    header::search(&resp.headers, b"WWW-Authenticate", false)
                {
                    // the 401 read to its end, the answer goes on a
                    // connection of its own, as GBA keys it to the cipher
                    // suite the connection has
                    if let Some(body) = &mut body {
                        let mut data = Vec::new();
                        let _ = body.read_to_end(&mut data).await;
                    }
                    conn = self.http_client.connect(url, false).await.ok()?;

                    if let Some(new_answer) = self
                        .answer(www_authenticate, host, conn.cipher_id(), method, &target)
                        .await
                    {
                        answer = Some(new_answer);
                        continue;
                    }
                }
            }

            if (200..300).contains(&resp.status_code) {
                if let (Some(authentication_info), Some(answer)) = (
                    header::search(&resp.headers, b"Authentication-Info", false),
                    &answer,
                ) {
                    if let Some(challenge) = &answer.challenge {
                        self.security_context.update_auth_info(
                            authentication_info,
                            host,
                            format!("\"{}\"", target).as_bytes(),
                            challenge,
                            false,
                        );
                    }
                }
            }

            return Some((resp, body));
        }
    }

    /// The answer to the challenge of a 401 to a `method` request for
    /// `target`: by GBA when the server asks for it, else by Digest with the
    /// credentials provisioned
    pub async fn answer(
        &self,
        www_authenticate: &Header,
        host: &str,
        cipher_id: Option<(u8, u8)>,
        method: &'static [u8],
        target: &str,
    ) -> Option<DigestAnswerParams> {
        match gba::try_process_401_response(
            self.gba_context,
            host.as_bytes(),
            cipher_id,
            method,
            format!("\"{}\"", target).as_bytes(),
            None,
            www_authenticate,
            self.http_client,
            self.security_context,
        )
        .await
        {
            Some(Ok(answer)) => return Some(answer),
            Some(Err(_)) => {
                platform_log(LOG_TAG, "GBA authentication failed");
                return None;
            }
            None => {}
        }

        let credentials = self.credentials.as_ref()?;
        if !credentials.host.eq_ignore_ascii_case(host) {
            platform_log(LOG_TAG, "not answering another host with the credentials");
            return None;
        }
        let (user, password) = (credentials.user, credentials.password);

        for method_ in AuthenticationMethods::new(www_authenticate.get_value()) {
            if let AuthenticationMethod::Digest(challenge) = method_ {
                return Some(DigestAnswerParams {
                    realm: challenge.realm.to_vec(),
                    algorithm: Some(challenge.algorithm.to_vec()),
                    username: user.as_bytes().to_vec(),
                    uri: target.as_bytes().to_vec(),
                    challenge: Some(challenge.to_challenge()),
                    credentials: Some(DigestCredentials {
                        password: password.as_bytes().to_vec(),
                        client_data: Some(method.to_vec()),
                        client_nonce: Some((rand::create_raw_alpha_numeric_string(16), 1)),
                        entity_digest: None,
                        extra_params: Vec::new(),
                    }),
                });
            }
        }

        None
    }
}

/// Adds the Authorization header of `answer` to `req`
fn authorize(req: &mut Request, answer: &DigestAnswerParams) {
    let algorithm = answer
        .challenge
        .as_ref()
        .map(|challenge| &challenge.algorithm[..]);
    if let Ok(authorization) = answer.make_authorization_header(algorithm, false, false) {
        if let Ok(authorization) = String::from_utf8(authorization) {
            req.headers
                .push(Header::new(b"Authorization", authorization));
        }
    }
}

/// The text of `body`, read to its end
pub async fn read_text(body: Option<ResponseBody>) -> Option<String> {
    let mut data = Vec::new();
    body?.read_to_end(&mut data).await.ok()?;
    String::from_utf8(data).ok()
}

/// The reason phrase of `resp`
pub fn reason_phrase(resp: &Response) -> String {
    String::from_utf8_lossy(&resp.reason_phrase).into_owned()
}
