//! HTTP implementation of the Comms trait.

use std::{
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
};

use async_trait::async_trait;
use eyre::eyre;
use frost_core::{
    self as frost, round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier,
};

use super::Comms;
use crate::args::ProcessedArgs;

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    username: String,
    password: String,
    access_token: String,
    should_logout: bool,
    _phantom: PhantomData<C>,
}

use server::{SendCommitmentsArgs, SendSignatureSharesArgs, SendSigningPackageArgs, Uuid};

// TODO: Improve error handling for invalid session id
impl<C> HTTPComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: Uuid::parse_str(&args.session_id).ok(),
            username: args.username.clone(),
            password: args.password.clone(),
            access_token: args.authentication_token.clone().unwrap_or_default(),
            should_logout: args.authentication_token.is_none(),
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C> Comms<C> for HTTPComms<C>
where
    C: Ciphersuite + 'static,
{
    async fn get_signing_package(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        commitments: SigningCommitments<C>,
        identifier: Identifier<C>,
        rerandomized: bool,
    ) -> Result<
        (
            frost::SigningPackage<C>,
            Option<frost_rerandomized::Randomizer<C>>,
        ),
        Box<dyn Error>,
    > {
        if self.access_token.is_empty() {
            self.access_token = self
                .client
                .post(format!("{}/login", self.host_port))
                .json(&server::LoginArgs {
                    username: self.username.clone(),
                    password: self.password.clone(),
                })
                .send()
                .await?
                .json::<server::LoginOutput>()
                .await?
                .access_token
                .to_string();
        }

        let session_id = match self.session_id {
            Some(s) => s,
            None => {
                // Get session ID from server
                let r = self
                    .client
                    .post(format!("{}/list_sessions", self.host_port))
                    .bearer_auth(&self.access_token)
                    .send()
                    .await?
                    .json::<server::ListSessionsOutput>()
                    .await?;
                if r.session_ids.len() > 1 {
                    return Err(eyre!("user has more than one FROST session active, which is still not supported by this tool").into());
                } else if r.session_ids.is_empty() {
                    return Err(eyre!("User has no current sessions active. The Coordinator should either specify your username, or manually share the session ID which you can specify with --session_id").into());
                }
                r.session_ids[0]
            }
        };
        self.session_id = Some(session_id);

        // Send Commitments to Server
        let send_commitments_args = SendCommitmentsArgs {
            identifier,
            commitments: vec![commitments],
        };
        self.client
            .post(format!("{}/send", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendArgs {
                session_id,
                // Empty recipients: Coordinator
                recipients: vec![],
                msg: serde_json::to_vec(&send_commitments_args)?,
            })
            .send()
            .await?;

        eprint!("Waiting for coordinator to send signing package...");

        // Receive SigningPackage from Coordinator

        let r: SendSigningPackageArgs<C> = loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::ReceiveArgs {
                    session_id,
                    as_coordinator: false,
                })
                .send()
                .await?
                .json::<server::ReceiveOutput>()
                .await?;
            if r.msgs.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                eprintln!("\nSigning package received");
                eprintln!("\n{}", String::from_utf8(r.msgs[0].msg.clone()).unwrap());
                break serde_json::from_slice(&r.msgs[0].msg)?;
            }
        };

        if rerandomized {
            let signing_package = r
                .signing_package
                .first()
                .ok_or(eyre!("missing signing package"))?;
            let randomizer = r.randomizer.first().ok_or(eyre!("missing randomizer"))?;
            Ok((signing_package.clone(), Some(*randomizer)))
        } else {
            let signing_package = r
                .signing_package
                .first()
                .ok_or(eyre!("missing signing package"))?;
            Ok((signing_package.clone(), None))
        }
    }

    async fn send_signature_share(
        &mut self,
        identifier: Identifier<C>,
        signature_share: SignatureShare<C>,
    ) -> Result<(), Box<dyn Error>> {
        // Send signature share to Coordinator

        eprintln!("Sending signature share to coordinator...");

        let send_signature_shares_args = SendSignatureSharesArgs {
            identifier,
            signature_share: vec![signature_share],
        };

        let _r = self
            .client
            .post(format!("{}/send", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendArgs {
                session_id: self.session_id.unwrap(),
                // Empty recipients: Coordinator
                recipients: vec![],
                msg: serde_json::to_vec(&send_signature_shares_args)?,
            })
            .send()
            .await?;

        if self.should_logout {
            let _r = self
                .client
                .post(format!("{}/logout", self.host_port))
                .bearer_auth(&self.access_token)
                .send()
                .await?;
        }

        Ok(())
    }
}
