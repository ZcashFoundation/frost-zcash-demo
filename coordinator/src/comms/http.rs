//! HTTP implementation of the Comms trait.

use async_trait::async_trait;

use frost_core::{self as frost, serde, serde::Deserialize, serde::Serialize};

use frost_core::Ciphersuite;

use eyre::eyre;
use frost_rerandomized::Randomizer;
use itertools::Itertools;
use server::{Msg, Uuid};

use frost::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Identifier,
    SigningPackage,
};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
    vec,
};

use super::Comms;
use crate::args::Args;

/// The current state of the server, and the required data for the state.
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub enum SessionState<C: Ciphersuite> {
    /// Waiting for participants to send their commitments.
    WaitingForCommitments {
        /// Commitments sent by participants so far, for each message being
        /// signed.
        commitments: HashMap<Identifier<C>, Vec<SigningCommitments<C>>>,
        usernames: HashMap<String, Identifier<C>>,
    },
    /// Commitments have been sent by all participants; ready to be fetched by
    /// the coordinator. Waiting for coordinator to send the SigningPackage.
    CommitmentsReady {
        /// All commitments sent by participants, for each message being signed.
        commitments: HashMap<Identifier<C>, Vec<SigningCommitments<C>>>,
        usernames: HashMap<String, Identifier<C>>,
    },
    /// SigningPackage ready to be fetched by participants. Waiting for
    /// participants to send their signature shares.
    WaitingForSignatureShares {
        /// Identifiers of the participants that sent commitments in the
        /// previous state.
        identifiers: HashSet<Identifier<C>>,
        /// Signature shares sent by participants so far, for each message being
        /// signed.
        signature_shares: HashMap<Identifier<C>, Vec<SignatureShare<C>>>,
    },
    /// SignatureShares have been sent by all participants; ready to be fetched
    /// by the coordinator.
    SignatureSharesReady {
        /// Signature shares sent by participants, for each message being signed.
        signature_shares: HashMap<Identifier<C>, Vec<SignatureShare<C>>>,
    },
}

impl<C> Default for SessionState<C>
where
    C: Ciphersuite,
{
    fn default() -> Self {
        SessionState::WaitingForCommitments {
            commitments: Default::default(),
            usernames: Default::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(bound = "C: Ciphersuite")]
pub struct SendCommitmentsArgs<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub commitments: Vec<SigningCommitments<C>>,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(bound = "C: Ciphersuite")]
pub struct SendSignatureSharesArgs<C: Ciphersuite> {
    pub identifier: Identifier<C>,
    pub signature_share: Vec<SignatureShare<C>>,
}

impl<C: Ciphersuite> SessionState<C> {
    fn recv(&mut self, args: &Args, msg: Msg, num_signers: u16) -> Result<(), Box<dyn Error>> {
        match self {
            SessionState::WaitingForCommitments { .. } => {
                let send_commitments_args: SendCommitmentsArgs<C> =
                    serde_json::from_slice(&msg.msg)?;
                self.send_commitments(args, msg.sender, send_commitments_args, num_signers)?;
            }
            SessionState::WaitingForSignatureShares { .. } => {
                let send_signature_shares_args: SendSignatureSharesArgs<C> =
                    serde_json::from_slice(&msg.msg)?;
                self.send_signature_shares_args(args, msg.sender, send_signature_shares_args)?;
            }
            _ => return Err(eyre!("received message during wrong state").into()),
        }
        Ok(())
    }

    fn send_commitments(
        &mut self,
        args: &Args,
        username: String,
        send_commitments_args: SendCommitmentsArgs<C>,
        num_signers: u16,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForCommitments {
            commitments,
            usernames,
        } = self
        {
            if send_commitments_args.commitments.len() != 1 {
                return Err(eyre!("wrong number of commitments").into());
            }

            // Add commitment to map.
            // Currently ignores the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            commitments.insert(
                send_commitments_args.identifier,
                send_commitments_args.commitments,
            );
            eprintln!(
                "added commitments, currently {}/{}",
                commitments.len(),
                num_signers
            );
            usernames.insert(username, send_commitments_args.identifier);

            // If complete, advance to next state
            if commitments.len() == num_signers as usize {
                *self = SessionState::CommitmentsReady {
                    commitments: commitments.clone(),
                    usernames: usernames.clone(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    fn are_commitments_ready(&self) -> bool {
        matches!(self, SessionState::CommitmentsReady { .. })
    }

    #[allow(clippy::type_complexity)]
    fn get_commitments(
        &mut self,
        args: &Args,
    ) -> Result<
        (
            Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>>,
            HashMap<String, Identifier<C>>,
        ),
        Box<dyn Error>,
    > {
        if let SessionState::CommitmentsReady {
            commitments,
            usernames,
        } = self
        {
            // Convert the BTreeMap<Identifier, Vec<SigningCommitments>> map
            // into a Vec<BTreeMap<Identifier, SigningCommitments>> map to make
            // it easier for the coordinator to build the SigningPackages.
            let commitments: Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>> = (0..1)
                .map(|i| commitments.iter().map(|(id, c)| (*id, c[i])).collect())
                .collect();
            Ok((commitments, usernames.clone()))
        } else {
            panic!("wrong state");
        }
    }

    fn send_signing_package(
        &mut self,
        _args: &Args,
        signing_package: Vec<SigningPackage<C>>,
        randomizer: Vec<Randomizer<C>>,
        aux_msg: Vec<u8>,
    ) -> Result<SendSigningPackageArgs<C>, Box<dyn Error>> {
        if let SessionState::CommitmentsReady {
            commitments,
            usernames: _,
        } = self
        {
            *self = SessionState::WaitingForSignatureShares {
                identifiers: commitments.keys().cloned().collect(),
                signature_shares: Default::default(),
            };
            Ok(SendSigningPackageArgs {
                signing_package,
                randomizer,
                aux_msg,
            })
        } else {
            panic!("wrong state");
        }
    }

    fn are_signature_shares_ready(&self) -> bool {
        matches!(self, SessionState::SignatureSharesReady { .. })
    }

    fn send_signature_shares_args(
        &mut self,
        args: &Args,
        _username: String,
        send_signature_shares_args: SendSignatureSharesArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForSignatureShares {
            identifiers,
            signature_shares,
        } = self
        {
            if send_signature_shares_args.signature_share.len() != 1 {
                return Err(eyre!("wrong number of signature shares").into());
            }
            if !identifiers.contains(&send_signature_shares_args.identifier) {
                return Err(eyre!("invalid identifier").into());
            }

            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            signature_shares.insert(
                send_signature_shares_args.identifier,
                send_signature_shares_args.signature_share,
            );
            // If complete, advance to next state
            if signature_shares.keys().cloned().collect::<HashSet<_>>() == *identifiers {
                *self = SessionState::SignatureSharesReady {
                    signature_shares: signature_shares.clone(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    #[allow(clippy::type_complexity)]
    fn get_signature_shares(
        &mut self,
        args: &Args,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SignatureShare<C>>>, Box<dyn Error>> {
        if let SessionState::SignatureSharesReady { signature_shares } = self {
            // Convert the BTreeMap<Identifier, Vec<SigningCommitments>> map
            // into a Vec<BTreeMap<Identifier, SigningCommitments>> map to make
            // it easier for the coordinator to build the SigningPackages.
            let signature_shares = (0..1)
                .map(|i| signature_shares.iter().map(|(id, s)| (*id, s[i])).collect())
                .collect();
            Ok(signature_shares)
        } else {
            panic!("wrong state");
        }
    }
}

pub struct HTTPComms<C: Ciphersuite> {
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    username: String,
    password: String,
    access_token: String,
    signers: Vec<String>,
    num_signers: u16,
    args: Args,
    state: SessionState<C>,
    usernames: HashMap<String, Identifier<C>>,
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
            num_signers: 0,
            args: args.clone(),
            state: Default::default(),
            usernames: Default::default(),
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
        self.num_signers = num_signers;
        eprint!("Waiting for participants to send their commitments...");

        loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::ReceiveArgs {
                    session_id: r.session_id,
                    as_coordinator: true,
                })
                .send()
                .await?
                .json::<server::ReceiveOutput>()
                .await?;
            for msg in r.msgs {
                self.state.recv(&self.args, msg, self.num_signers)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.are_commitments_ready() {
                break;
            }
        }
        eprintln!();

        let (commitments, usernames) = self.state.get_commitments(&self.args)?;
        self.usernames = usernames;

        // TODO: support more than 1
        Ok(commitments[0].clone())
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

        let send_signing_package_args = self.state.send_signing_package(
            &self.args,
            vec![signing_package.clone()],
            randomizer.map(|r| vec![r]).unwrap_or_default(),
            Default::default(),
        )?;

        let _r = self
            .client
            .post(format!("{}/send", self.host_port))
            .bearer_auth(&self.access_token)
            .json(&server::SendArgs {
                session_id: self.session_id.unwrap(),
                recipients: self.usernames.keys().cloned().collect_vec(),
                msg: serde_json::to_vec(&send_signing_package_args)?,
            })
            .send()
            .await?
            .bytes()
            .await?;

        eprintln!("Waiting for participants to send their SignatureShares...");

        loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: true,
                })
                .send()
                .await?
                .json::<server::ReceiveOutput>()
                .await?;
            for msg in r.msgs {
                self.state.recv(&self.args, msg, self.num_signers)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.are_signature_shares_ready() {
                break;
            }
        }
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

        let signature_shares = self.state.get_signature_shares(&self.args)?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }
}
