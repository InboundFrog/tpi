// Copyright 2023 Turing Machines
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

//! Wrapper for `reqwest::Request` that asks for authentication if needed.

use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderValue, USER_AGENT};
use reqwest::multipart::Form;
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode};
use url::Url;

use crate::cli::ApiVersion;
use crate::prompt;

pub struct Request {
    host: String,
    ver: ApiVersion,
    creds: (Option<String>, Option<String>),
    inner: reqwest::Request,
    multipart: Option<Form>,
}

impl Request {
    pub fn new(
        host: String,
        ver: ApiVersion,
        creds: (Option<String>, Option<String>),
        user_agent: &str,
    ) -> Result<Self> {
        let url = url_from_host(&host, ver.scheme())?;
        let mut inner = reqwest::Request::new(Method::GET, url);
        inner
            .headers_mut()
            .insert(USER_AGENT, HeaderValue::from_str(user_agent)?);

        Ok(Self {
            host,
            ver,
            creds,
            inner,
            multipart: None,
        })
    }

    pub fn to_post(&self) -> Result<Self> {
        let url = url_from_host(&self.host, self.ver.scheme())?;
        let inner = reqwest::Request::new(Method::POST, url);

        Ok(Self {
            host: self.host.clone(),
            ver: self.ver,
            creds: self.creds.clone(),
            inner,
            multipart: None,
        })
    }

    pub fn set_multipart(&mut self, form: Form) {
        self.multipart = Some(form);
    }

    pub async fn send(mut self, client: Client) -> Result<Response> {
        let mut authenticated = cfg!(not(feature = "localhost"));

        // Attempts: [unauthenticated (localhost only),] cached token, fresh credentials.
        for _ in 0..3 {
            let mut builder =
                RequestBuilder::from_parts(client.clone(), self.inner.try_clone().unwrap());

            if authenticated {
                let token = self.get_bearer_token(&client).await?;
                builder = builder.bearer_auth(token);
            }

            // A multipart body is a stream and can only be sent once.
            let has_body = self.multipart.is_some();
            if let Some(form) = self.multipart.take() {
                builder = builder.multipart(form);
            }

            let resp = builder.send().await?;
            if resp.status() != StatusCode::UNAUTHORIZED {
                return Ok(resp);
            }

            delete_cached_token(&self.host);
            if has_body {
                bail!("unauthorized: session expired, run the command again to log in");
            }
            authenticated = true;
        }

        bail!("unauthorized")
    }

    async fn get_bearer_token(&mut self, client: &Client) -> Result<String> {
        // If either credentials are supplied, use them
        if self.creds.0.is_some() || self.creds.1.is_some() {
            return request_token(&self.host, self.ver, &self.creds, client).await;
        }

        // Else, try retrieving cached token from a file
        if let Some(token) = get_cached_token(&self.host) {
            return Ok(token);
        }

        // If it doesn't exist, ask on an interactive prompt
        request_token(&self.host, self.ver, &self.creds, client).await
    }

    pub fn url(&self) -> &Url {
        self.inner.url()
    }

    pub fn url_mut(&mut self) -> &mut Url {
        self.inner.url_mut()
    }

    pub fn clone(&self) -> Self {
        let inner = self
            .inner
            .try_clone()
            .expect("request cannot be cloned: body is a stream");

        Self {
            host: self.host.clone(),
            ver: self.ver,
            creds: self.creds.clone(),
            inner,
            multipart: None,
        }
    }
}

impl Deref for Request {
    type Target = reqwest::Request;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Request {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

fn url_from_host(host: &str, scheme: &str) -> Result<Url> {
    let mut url = Url::parse(&format!("{}://{}", scheme, host))?;
    url.set_path("api/bmc");
    Ok(url)
}

fn get_cached_token(host: &str) -> Option<String> {
    std::fs::read_to_string(get_cache_file_location(host)?).ok()
}

fn delete_cached_token(host: &str) {
    if let Some(path) = get_cache_file_location(host) {
        let _ = std::fs::remove_file(path);
    }
}

/// Tokens are cached per host so that a token issued by one BMC is never
/// sent to another.
fn get_cache_file_location(host: &str) -> Option<PathBuf> {
    let mut path = dirs::cache_dir()?;

    let host: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    path.push(format!("tpi_token_{host}"));

    Some(path)
}

async fn request_token(
    host: &str,
    ver: ApiVersion,
    creds: &(Option<String>, Option<String>),
    client: &Client,
) -> Result<String> {
    let mut auth_url = url_from_host(host, ver.scheme())?;

    auth_url
        .path_segments_mut()
        .expect("URL cannot be a base")
        .push("authenticate");

    // Save token to a file only if credentials weren't supplied from the command line
    let save_token = creds.0.is_none() && creds.1.is_none();

    let (username, password) = match creds.clone() {
        (Some(username), Some(password)) => (username, password),
        (Some(username), None) => {
            let password = prompt::password("Password")?;
            (username, password)
        }
        (None, Some(password)) => {
            let username = prompt::simple("User")?;
            (username, password)
        }
        (None, None) => {
            let username = prompt::simple("User")?;
            let password = prompt::password("Password")?;
            (username, password)
        }
    };

    let body = serde_json::json!({
        "username": username,
        "password": password
    });

    let resp = client.post(auth_url).json(&body).send().await?;

    match resp.status() {
        StatusCode::OK => {
            let json = resp.json::<serde_json::Value>().await?;
            let token = get_param(&json, "id")?;

            if save_token {
                if let Err(e) = cache_token(host, &token) {
                    eprintln!("Warning: failed to cache token: {e:#}");
                }
            }

            Ok(token)
        }
        StatusCode::FORBIDDEN => bail!(
            "{}",
            resp.text()
                .await
                .unwrap_or("could not authenticate".to_string())
        ),
        x => bail!("Unexpected status code {x}"),
    }
}

fn get_param(results: &serde_json::Value, key: &str) -> Result<String> {
    Ok(results
        .get(key)
        .with_context(|| format!("API error: Expected `{key}` attribute"))?
        .as_str()
        .with_context(|| format!("API error: `{key}` value is not a string"))?
        .to_owned())
}

fn cache_token(host: &str, token: &str) -> Result<()> {
    let Some(path) = get_cache_file_location(host) else {
        bail!("no cache directory available");
    };

    // Remove the token file used by older versions, which was shared by all hosts.
    if let Some(mut legacy) = dirs::cache_dir() {
        legacy.push("tpi_token");
        let _ = std::fs::remove_file(legacy);
    }

    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    // The token grants full BMC access: keep it private to the current user.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

    options
        .open(&path)
        .and_then(|mut f| f.write_all(token.as_bytes()))
        .with_context(|| format!("{}", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_file_is_per_host() {
        let a = get_cache_file_location("turingpi.local").unwrap();
        let b = get_cache_file_location("[::1]:8080").unwrap();
        assert!(a.ends_with("tpi_token_turingpi.local"));
        assert!(b.ends_with("tpi_token____1__8080"));
        assert_ne!(Some(a), get_cache_file_location("turingpi.local:8080"));
    }
}
