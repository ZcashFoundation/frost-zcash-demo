//! HTTP implementation of the Comms trait.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    io::{BufRead, Write},
    marker::PhantomData,
    time::Duration,
    vec,
};

use async_trait::async_trait;
use eyre::eyre;
use frost_core::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Ciphersuite,
    Identifier, SigningPackage,
};
use itertools::Itertools;

use server::{Msg, SendCommitmentsArgs, SendSignatureSharesArgs, SendSigningPackageArgs, Uuid};

use super::Comms;
use crate::args::ProcessedArgs;

#[derive(Clone, Debug)]
pub struct SessionStateArgs {
    pub num_messages: usize,
    pub num_signers: usize,
}

/// The current state of a session.
///
/// This can be used by a Coordinator to help maitain state and handle
/// messages from the Participants.
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub enum SessionState<C: Ciphersuite> {
    /// Waiting for participants to send their commitments.
    WaitingForCommitments {
        /// Session arguments
        args: SessionStateArgs,
        /// Commitments sent by participants so far, for each message being
        /// signed.
        commitments: HashMap<Identifier<C>, Vec<SigningCommitments<C>>>,
        usernames: HashMap<String, Identifier<C>>,
    },
    /// Commitments have been sent by all participants. Coordinator can create
    /// SigningPackage and send to participants. Waiting for participants to
    /// send their signature shares.
    WaitingForSignatureShares {
        /// Session arguments
        args: SessionStateArgs,
        /// All commitments sent by participants, for each message being signed.
        commitments: HashMap<Identifier<C>, Vec<SigningCommitments<C>>>,
        /// Username -> Identifier mapping.
        usernames: HashMap<String, Identifier<C>>,
        /// Signature shares sent by participants so far, for each message being
        /// signed.
        signature_shares: HashMap<Identifier<C>, Vec<SignatureShare<C>>>,
    },
    /// SignatureShares have been sent by all participants; ready to be fetched
    /// by the coordinator.
    SignatureSharesReady {
        /// Session arguments
        args: SessionStateArgs,
        /// Signature shares sent by participants, for each message being signed.
        signature_shares: HashMap<Identifier<C>, Vec<SignatureShare<C>>>,
    },
}

impl<C: Ciphersuite> SessionState<C> {
    /// Create a new SessionState for the given number of messages and signers.
    pub fn new(num_messages: usize, num_signers: usize) -> Self {
        let args = SessionStateArgs {
            num_messages,
            num_signers,
        };
        Self::WaitingForCommitments {
            args,
            commitments: Default::default(),
            usernames: Default::default(),
        }
    }

    /// Handle a Msg received from a participant.
    ///
    /// This should be called for new Msgs until [`are_commitments_ready()`]
    /// returns true, and after the SigningPackage is sent to the participants,
    /// it should be called for new Msgs until [`are_signature_shares_ready()`]
    /// returns true.
    pub fn recv(&mut self, msg: Msg) -> Result<(), Box<dyn Error>> {
        match self {
            SessionState::WaitingForCommitments { .. } => {
                let send_commitments_args: SendCommitmentsArgs<C> =
                    serde_json::from_slice(&msg.msg)?;
                self.handle_commitments(msg.sender, send_commitments_args)?;
            }
            SessionState::WaitingForSignatureShares { .. } => {
                let send_signature_shares_args: SendSignatureSharesArgs<C> =
                    serde_json::from_slice(&msg.msg)?;
                self.handle_signature_share(msg.sender, send_signature_shares_args)?;
            }
            _ => return Err(eyre!("received message during wrong state").into()),
        }
        Ok(())
    }

    /// Handle commitments sent by a participant.
    fn handle_commitments(
        &mut self,
        username: String,
        send_commitments_args: SendCommitmentsArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForCommitments {
            args,
            commitments,
            usernames,
        } = self
        {
            if send_commitments_args.commitments.len() != args.num_messages {
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
            usernames.insert(username, send_commitments_args.identifier);

            // If complete, advance to next state
            if commitments.len() == args.num_signers {
                *self = SessionState::WaitingForSignatureShares {
                    args: args.clone(),
                    commitments: commitments.clone(),
                    usernames: usernames.clone(),
                    signature_shares: Default::default(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns if all participants sent their commitments.
    /// When this returns `true`, [`commitments()`] can be called.
    pub fn has_commitments(&self) -> bool {
        matches!(self, SessionState::WaitingForSignatureShares { .. })
    }

    /// Returns:
    /// - A vector (one item per message) of maps linking a participant identifier
    ///   and the SigningCommitments they have sent.
    /// - A map linking usernames to participant identifiers.
    #[allow(clippy::type_complexity)]
    pub fn commitments(
        &mut self,
    ) -> Result<
        (
            Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>>,
            HashMap<String, Identifier<C>>,
        ),
        Box<dyn Error>,
    > {
        if let SessionState::WaitingForSignatureShares {
            args,
            commitments,
            usernames,
            ..
        } = self
        {
            // Convert the BTreeMap<Identifier, Vec<SigningCommitments>> map
            // into a Vec<BTreeMap<Identifier, SigningCommitments>> map to make
            // it easier for the coordinator to build the SigningPackages.
            let commitments: Vec<BTreeMap<Identifier<C>, SigningCommitments<C>>> = (0..args
                .num_messages)
                .map(|i| commitments.iter().map(|(id, c)| (*id, c[i])).collect())
                .collect();
            Ok((commitments, usernames.clone()))
        } else {
            panic!("wrong state");
        }
    }

    /// Returns if all participants sent their SignatureShares.
    /// When this returns `true`, [`signature_shares()`] can be called.
    pub fn has_signature_shares(&self) -> bool {
        matches!(self, SessionState::SignatureSharesReady { .. })
    }

    /// Handle signature share sent by a participant.
    fn handle_signature_share(
        &mut self,
        _username: String,
        send_signature_shares_args: SendSignatureSharesArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForSignatureShares {
            args,
            commitments,
            signature_shares,
            ..
        } = self
        {
            if send_signature_shares_args.signature_share.len() != args.num_messages {
                return Err(eyre!("wrong number of signature shares").into());
            }
            if !commitments.contains_key(&send_signature_shares_args.identifier) {
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
            if signature_shares.keys().cloned().collect::<HashSet<_>>()
                == commitments.keys().cloned().collect::<HashSet<_>>()
            {
                *self = SessionState::SignatureSharesReady {
                    args: args.clone(),
                    signature_shares: signature_shares.clone(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns a vector (one item per message) of maps linking a participant
    /// identifier and the SignatureShare they have sent.
    #[allow(clippy::type_complexity)]
    pub fn signature_shares(
        &mut self,
    ) -> Result<Vec<BTreeMap<Identifier<C>, SignatureShare<C>>>, Box<dyn Error>> {
        if let SessionState::SignatureSharesReady {
            args,
            signature_shares,
        } = self
        {
            // Convert the BTreeMap<Identifier, Vec<SigningCommitments>> map
            // into a Vec<BTreeMap<Identifier, SigningCommitments>> map to make
            // it easier for the coordinator to build the SigningPackages.
            let signature_shares = (0..args.num_messages)
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
    access_token: String,
    num_signers: u16,
    args: ProcessedArgs<C>,
    state: SessionState<C>,
    usernames: HashMap<String, Identifier<C>>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: None,
            access_token: String::new(),
            num_signers: 0,
            args: args.clone(),
            state: SessionState::new(args.messages.len(), args.num_signers as usize),
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
                username: self.args.username.clone(),
                password: self.args.password.clone(),
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
                usernames: self.args.signers.clone(),
                num_signers,
                message_count: 1,
            })
            .send()
            .await?
            .json::<server::CreateNewSessionOutput>()
            .await?;

        if self.args.signers.is_empty() {
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
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_commitments() {
                break;
            }
        }
        eprintln!();

        let (commitments, usernames) = self.state.commitments()?;
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
        eprintln!("Sending SigningPackage to participants...");
        let send_signing_package_args = SendSigningPackageArgs {
            signing_package: vec![signing_package.clone()],
            aux_msg: Default::default(),
            randomizer: randomizer.map(|r| vec![r]).unwrap_or_default(),
        };
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
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_signature_shares() {
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

        let signature_shares = self.state.signature_shares()?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }
}
