//! HTTP implementation of the Comms trait.

use async_trait::async_trait;

use frost_core::{self as frost, Ciphersuite};

use eyre::eyre;

use frost::{round1::SigningCommitments, round2::SignatureShare, Identifier};

use super::Comms;

use std::env;
use std::io::{BufRead, Write};

use std::error::Error;

use std::marker::PhantomData;
use std::time::Duration;

use crate::args::Args;

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    username: String,
    password: String,
    access_token: String,
    _phantom: PhantomData<C>,
}

use server::Uuid;

// TODO: Improve error handling for invalid session id
impl<C> HTTPComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &Args) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        let password = env::var(&args.password).map_err(|_| eyre!("The password argument must specify the name of a environment variable containing the password"))?;
        Ok(Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: Uuid::parse_str(&args.session_id).ok(),
            username: args.username.clone(),
            password,
            access_token: String::new(),
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
                    return Err(eyre!("User has no current session actives. The Coordinator should either specify your username, or manually share the session ID which you can specify with --session_id").into());
                }
                r.session_ids[0]
            }
        };
        self.session_id = Some(session_id);

        // Send Commitments to Server
        self.client
            .post(format!("{}/send_commitments", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendCommitmentsArgs {
                session_id,
                identifier: identifier.into(),
                commitments: vec![(&commitments).try_into()?],
            })
            .send()
            .await?;

        eprint!("Waiting for coordinator to send signing package...");

        // Receive SigningPackage from Coordinator

        let r = loop {
            let r = self
                .client
                .post(format!("{}/get_signing_package", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::GetSigningPackageArgs { session_id })
                .send()
                .await?;
            if r.status() != 200 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                eprintln!("\nSigning package received");
                break r.json::<server::GetSigningPackageOutput>().await?;
            }
        };

        let signing_package = if rerandomized {
            let signing_package = r
                .signing_package
                .first()
                .ok_or(eyre!("missing signing package"))?;
            let randomizer = r.randomizer.first().ok_or(eyre!("missing randomizer"))?;
            (signing_package.try_into()?, Some(randomizer.try_into()?))
        } else {
            let signing_package = r
                .signing_package
                .first()
                .ok_or(eyre!("missing signing package"))?;
            (signing_package.try_into()?, None)
        };

        Ok(signing_package)
    }

    async fn send_signature_share(
        &mut self,
        identifier: Identifier<C>,
        signature_share: SignatureShare<C>,
    ) -> Result<(), Box<dyn Error>> {
        // Send signature share to Coordinator

        eprintln!("Sending signature share to coordinator...");

        let _r = self
            .client
            .post(format!("{}/send_signature_share", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendSignatureShareArgs {
                identifier: identifier.into(),
                session_id: self.session_id.unwrap(),
                signature_share: vec![signature_share.into()],
            })
            .send()
            .await?;

        let _r = self
            .client
            .post(format!("{}/logout", self.host_port))
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        Ok(())
    }
}
