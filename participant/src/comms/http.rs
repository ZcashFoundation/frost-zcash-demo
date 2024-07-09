//! HTTP implementation of the Comms trait.

use async_trait::async_trait;

use frost_core::SigningPackage;
use frost_core::{self as frost, serde, serde::Deserialize, serde::Serialize, Ciphersuite};

use eyre::eyre;

use frost::{round1::SigningCommitments, round2::SignatureShare, Identifier};
use frost_rerandomized::Randomizer;

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
    coordinator: String,
    _phantom: PhantomData<C>,
}

use server::Uuid;

// TODO: deduplicate with coordinator
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(bound = "C: Ciphersuite")]
pub struct SendCommitmentsArgs<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub commitments: Vec<SigningCommitments<C>>,
}

// TODO: deduplicate with coordinator
#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
#[serde(crate = "self::serde")]
#[serde(bound = "C: Ciphersuite")]
pub struct SendSigningPackageArgs<C: Ciphersuite> {
    pub signing_package: Vec<SigningPackage<C>>,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub aux_msg: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub randomizer: Vec<Randomizer<C>>,
}

// TODO: deduplicate with coordinator
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(bound = "C: Ciphersuite")]
pub struct SendSignatureSharesArgs<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub signature_share: Vec<SignatureShare<C>>,
}

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
            coordinator: String::new(),
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
                    return Err(eyre!("User has no current sessions active. The Coordinator should either specify your username, or manually share the session ID which you can specify with --session_id").into());
                }
                r.session_ids[0]
            }
        };
        self.session_id = Some(session_id);

        let r = self
            .client
            .post(format!("{}/get_session_info", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::GetSessionInfoArgs { session_id })
            .send()
            .await?
            .json::<server::GetSessionInfoOutput>()
            .await?;
        self.coordinator = r.coordinator;

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

        let _r = self
            .client
            .post(format!("{}/logout", self.host_port))
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        Ok(())
    }
}
