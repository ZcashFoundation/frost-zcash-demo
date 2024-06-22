//! HTTP implementation of the Comms trait.

use async_trait::async_trait;

use frost_core::{self as frost, Ciphersuite};

use eyre::eyre;

use frost::{round1::SigningCommitments, round2::SignatureShare, Identifier};

use super::Comms;

use std::io::{BufRead, Write};

use std::error::Error;

use std::marker::PhantomData;
use std::time::Duration;

use crate::args::Args;

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Uuid,
    _phantom: PhantomData<C>,
}

use server::Uuid;

// TODO: Improve error handling for invalid session id
impl<C> HTTPComms<C>
where
    C: Ciphersuite,
{
    pub fn new(args: &Args) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: Uuid::parse_str(&args.session_id).expect("invalid session id"),
            _phantom: Default::default(),
        }
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
        // Send Commitments to Server
        self.client
            .post(format!("{}/send_commitments", self.host_port))
            .json(&server::SendCommitmentsArgs {
                session_id: self.session_id,
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
                .json(&server::GetSigningPackageArgs {
                    session_id: self.session_id,
                })
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
            .json(&server::SendSignatureShareArgs {
                identifier: identifier.into(),
                session_id: self.session_id,
                signature_share: vec![signature_share.into()],
            })
            .send()
            .await?;

        Ok(())
    }
}
