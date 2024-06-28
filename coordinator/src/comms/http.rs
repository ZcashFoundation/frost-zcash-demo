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
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &Args) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: None,
            _phantom: Default::default(),
        }
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
        let r = self
            .client
            .post(format!("{}/create_new_session", self.host_port))
            .json(&server::CreateNewSessionArgs {
                usernames: vec![],
                num_signers,
                message_count: 1,
            })
            .send()
            .await?
            .json::<server::CreateNewSessionOutput>()
            .await?;

        eprintln!(
            "Send the following session ID to participants: {}",
            r.session_id
        );
        self.session_id = Some(r.session_id);
        eprint!("Waiting for participants to send their commitments...");

        let r = loop {
            let r = self
                .client
                .post(format!("{}/get_commitments", self.host_port))
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
