//! HTTP implementation of the Comms trait.

use async_trait::async_trait;

use frost_core as frost;

use frost_core::Ciphersuite;

use eyre::eyre;
use server::Uuid;

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
    vec,
};

use super::Comms;
use crate::args::Args;

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    username: String,
    password: String,
    access_token: String,
    signers: Vec<String>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &Args) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        let password = env::var(&args.password).map_err(|_| eyre!("The password argument must specify the name of a environment variable containing the password"))?;
        Ok(Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: None,
            username: args.username.clone(),
            password,
            access_token: String::new(),
            signers: args.signers.clone(),
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite + 'static> Comms<C> for HTTPComms<C> {
    async fn get_signing_commitments(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        _pub_key_package: &PublicKeyPackage<C>,
        num_signers: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>> {
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

        let r = self
            .client
            .post(format!("{}/create_new_session", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::CreateNewSessionArgs {
                usernames: self.signers.clone(),
                num_signers,
                message_count: 1,
            })
            .send()
            .await?
            .json::<server::CreateNewSessionOutput>()
            .await?;

        if self.signers.is_empty() {
            eprintln!(
                "Send the following session ID to participants: {}",
                r.session_id
            );
        }
        self.session_id = Some(r.session_id);
        eprint!("Waiting for participants to send their commitments...");

        let r = loop {
            let r = self
                .client
                .post(format!("{}/get_commitments", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::GetCommitmentsArgs {
                    session_id: r.session_id,
                })
                .send()
                .await?;
            if r.status() != 200 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                break r.json::<server::GetCommitmentsOutput>().await?;
            }
        };
        eprintln!();

        let commitments = r
            .commitments
            .first()
            .ok_or(eyre!("empty commitments"))?
            .iter()
            .map(|(i, c)| Ok((i.try_into()?, c.try_into()?)))
            .collect::<Result<_, Box<dyn Error>>>()?;

        Ok(commitments)
    }

    async fn get_signature_shares(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        signing_package: &SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>> {
        // Send SigningPackage to all participants
        eprintln!("Sending SigningPackage to participants...");

        let _r = self
            .client
            .post(format!("{}/send_signing_package", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendSigningPackageArgs {
                aux_msg: Default::default(),
                session_id: self.session_id.unwrap(),
                signing_package: vec![signing_package.try_into()?],
                randomizer: randomizer.map(|r| vec![r.into()]).unwrap_or_default(),
            })
            .send()
            .await?
            .bytes()
            .await?;

        eprintln!("Waiting for participants to send their SignatureShares...");

        let r = loop {
            let r = self
                .client
                .post(format!("{}/get_signature_shares", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::GetSignatureSharesArgs {
                    session_id: self.session_id.unwrap(),
                })
                .send()
                .await?;
            if r.status() != 200 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
            } else {
                break r.json::<server::GetSignatureSharesOutput>().await?;
            }
        };
        eprintln!();

        let _r = self
            .client
            .post(format!("{}/close_session", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::CloseSessionArgs {
                session_id: self.session_id.unwrap(),
            })
            .send()
            .await?;

        let _r = self
            .client
            .post(format!("{}/logout", self.host_port))
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        let signature_shares = r
            .signature_shares
            .first()
            .ok_or(eyre!("empty signature_shares"))?
            .iter()
            .map(|(i, c)| Ok((i.try_into()?, c.try_into()?)))
            .collect::<Result<_, Box<dyn Error>>>()?;

        Ok(signature_shares)
    }
}
