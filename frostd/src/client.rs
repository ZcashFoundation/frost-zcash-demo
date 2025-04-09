//! Client for the frostd server.
use thiserror::Error;
use uuid::Uuid;

use crate::{self as frostd};

/// A Client error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("server error: {0}")]
    ServerError(#[from] frostd::Error),
    #[error("connection error: {0}")]
    ConnectionError(#[from] reqwest::Error),
}

/// A frostd Client that allows calling frostd API methods.
pub struct Client {
    host_port: String,
    client: reqwest::Client,
    access_token: Option<Uuid>,
}

impl Client {
    /// Create a new client that will connect to the given host/port in
    /// `host:port` format.
    pub fn new(host_port: String) -> Self {
        Self {
            host_port,
            client: reqwest::Client::new(),
            access_token: None,
        }
    }

    async fn call<A, O>(&self, name: &str, args: &A) -> Result<O, Error>
    where
        A: serde::Serialize,
        O: serde::de::DeserializeOwned,
    {
        let req = self
            .client
            .post(format!("{}/{}", self.host_port, name))
            .json(args);
        let req = if let Some(token) = &self.access_token {
            req.bearer_auth(token.to_string())
        } else {
            req
        };
        let response = req.send().await?;
        if !response.status().is_success() {
            if response.status() == reqwest::StatusCode::INTERNAL_SERVER_ERROR {
                let err = response.json::<frostd::LowError>().await?;
                let err: frostd::Error = err.into();
                Err(err.into())
            } else {
                Err(Error::ConnectionError(
                    response
                        .error_for_status()
                        .expect_err("we know the response is not success"),
                ))
            }
        } else {
            Ok(response.json::<O>().await?)
        }
    }

    pub async fn challenge(&self) -> Result<frostd::ChallengeOutput, Error> {
        self.call("challenge", &()).await
    }

    /// Login to the server. This will internally set the access token for the
    /// client so that other authenticated methods can be called.
    pub async fn login(&mut self, args: &frostd::LoginArgs) -> Result<frostd::LoginOutput, Error> {
        let login_output: frostd::LoginOutput = self.call("login", args).await?;
        self.access_token = Some(login_output.access_token);
        Ok(login_output)
    }

    /// Log out from the server. This will clear the cached access token.
    pub async fn logout(&mut self) -> Result<(), Error> {
        self.call::<(), ()>("login", &()).await?;
        self.access_token = None;
        Ok(())
    }

    pub async fn create_new_session(
        &self,
        args: &frostd::CreateNewSessionArgs,
    ) -> Result<frostd::CreateNewSessionOutput, Error> {
        self.call("create_new_session", args).await
    }

    pub async fn list_sessions(&self) -> Result<frostd::ListSessionsOutput, Error> {
        self.call("list_sessions", &()).await
    }

    pub async fn get_session_info(
        &self,
        args: &frostd::GetSessionInfoArgs,
    ) -> Result<frostd::GetSessionInfoOutput, Error> {
        self.call("get_session_info", args).await
    }

    pub async fn send(&self, args: &frostd::SendArgs) -> Result<(), Error> {
        self.call("send", args).await
    }

    pub async fn receive(
        &self,
        args: &frostd::ReceiveArgs,
    ) -> Result<frostd::ReceiveOutput, Error> {
        self.call("receive", args).await
    }

    pub async fn close_session(&self, args: &frostd::CloseSessionArgs) -> Result<(), Error> {
        self.call("close_session", args).await
    }
}
