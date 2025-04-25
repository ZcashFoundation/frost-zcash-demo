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
use eyre::{eyre, OptionExt};
use frost_core::{
    keys::PublicKeyPackage, round1::SigningCommitments, round2::SignatureShare, Ciphersuite,
    Identifier, SigningPackage,
};
use rand::thread_rng;

use crate::api::{self, Msg, PublicKey, SendSigningPackageArgs, Uuid};
use crate::cipher::Cipher;
use crate::client::Client;

use super::super::args::ProcessedArgs;
use super::Comms;

#[derive(Clone, Debug)]
pub struct SessionStateArgs {
    pub num_messages: usize,
    pub num_signers: usize,
}

/// The current state of a session.
///
/// This can be used by a Coordinator to help maitain state and handle
/// messages from the Participants.
#[derive(Debug)]
pub enum SessionState<C: Ciphersuite> {
    /// Waiting for participants to send their commitments.
    WaitingForCommitments {
        /// Session arguments
        args: SessionStateArgs,
        /// Commitments sent by participants so far, for each message being
        /// signed.
        commitments: HashMap<Identifier<C>, Vec<SigningCommitments<C>>>,
        pubkeys: HashMap<PublicKey, Identifier<C>>,
    },
    /// Commitments have been sent by all participants. Coordinator can create
    /// SigningPackage and send to participants. Waiting for participants to
    /// send their signature shares.
    WaitingForSignatureShares {
        /// Session arguments
        args: SessionStateArgs,
        /// All commitments sent by participants, for each message being signed.
        commitments: HashMap<Identifier<C>, Vec<SigningCommitments<C>>>,
        /// Pubkey -> Identifier mapping.
        pubkeys: HashMap<PublicKey, Identifier<C>>,
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
    pub fn new(
        num_messages: usize,
        num_signers: usize,
        pubkeys: HashMap<PublicKey, Identifier<C>>,
    ) -> Self {
        let args = SessionStateArgs {
            num_messages,
            num_signers,
        };
        Self::WaitingForCommitments {
            args,
            commitments: Default::default(),
            pubkeys,
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
                let send_commitments_args: Vec<SigningCommitments<C>> =
                    serde_json::from_slice(&msg.msg)?;
                self.handle_commitments(msg.sender, send_commitments_args)?;
            }
            SessionState::WaitingForSignatureShares { .. } => {
                let send_signature_shares_args: Vec<SignatureShare<C>> =
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
        pubkey: PublicKey,
        commitments: Vec<SigningCommitments<C>>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForCommitments {
            args,
            commitments: commitments_map,
            pubkeys,
        } = self
        {
            if commitments.len() != args.num_messages {
                return Err(eyre!("wrong number of commitments").into());
            }
            let identifier = *pubkeys.get(&pubkey).ok_or(eyre!("unknown participant"))?;

            // Add commitment to map.
            // Currently ignores the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            commitments_map.insert(identifier, commitments);

            // If complete, advance to next state
            if commitments_map.len() == args.num_signers {
                *self = SessionState::WaitingForSignatureShares {
                    args: args.clone(),
                    commitments: commitments_map.clone(),
                    pubkeys: pubkeys.clone(),
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
            HashMap<PublicKey, Identifier<C>>,
        ),
        Box<dyn Error>,
    > {
        if let SessionState::WaitingForSignatureShares {
            args,
            commitments,
            pubkeys,
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
            Ok((commitments, pubkeys.clone()))
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
        pubkey: PublicKey,
        signature_shares: Vec<SignatureShare<C>>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForSignatureShares {
            args,
            commitments,
            signature_shares: signature_shares_map,
            pubkeys,
        } = self
        {
            if signature_shares.len() != args.num_messages {
                return Err(eyre!("wrong number of signature shares").into());
            }
            let identifier = *pubkeys.get(&pubkey).ok_or(eyre!("unknown participant"))?;
            if !commitments.contains_key(&identifier) {
                return Err(eyre!("invalid identifier").into());
            }

            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            signature_shares_map.insert(identifier, signature_shares);
            // If complete, advance to next state
            if signature_shares_map.keys().cloned().collect::<HashSet<_>>()
                == commitments.keys().cloned().collect::<HashSet<_>>()
            {
                *self = SessionState::SignatureSharesReady {
                    args: args.clone(),
                    signature_shares: signature_shares_map.clone(),
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
    client: Client,
    session_id: Option<Uuid>,
    args: ProcessedArgs<C>,
    state: SessionState<C>,
    pubkeys: HashMap<PublicKey, Identifier<C>>,
    cipher: Option<Cipher>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: Client::new(format!("https://{}:{}", args.ip, args.port)),
            session_id: None,
            args: args.clone(),
            state: SessionState::new(
                args.messages.len(),
                args.num_signers as usize,
                args.signers.clone(),
            ),
            pubkeys: Default::default(),
            cipher: None,
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
        _num_signers: u16,
    ) -> Result<BTreeMap<Identifier<C>, SigningCommitments<C>>, Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .args
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        self.client
            .login(&api::LoginArgs {
                challenge,
                pubkey: self
                    .args
                    .comm_pubkey
                    .clone()
                    .ok_or_eyre("comm_pubkey must be specified")?,
                signature: signature.to_vec(),
            })
            .await?;

        eprintln!("Creating signing session...");
        let r = self
            .client
            .create_new_session(&api::CreateNewSessionArgs {
                pubkeys: self.args.signers.keys().cloned().collect(),
                message_count: 1,
            })
            .await?;

        if self.args.signers.is_empty() {
            eprintln!(
                "Send the following session ID to participants: {}",
                r.session_id
            );
        }
        self.session_id = Some(r.session_id);

        let Some(comm_privkey) = &self.args.comm_privkey else {
            return Err(eyre!("comm_privkey must be specified").into());
        };

        // If encryption is enabled, create the Noise objects

        let mut cipher = Cipher::new(
            comm_privkey.clone(),
            self.args.signers.keys().cloned().collect(),
        )?;

        eprint!("Waiting for participants to send their commitments...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: r.session_id,
                    as_coordinator: true,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_commitments() {
                break;
            }
        }
        eprintln!();

        self.cipher = Some(cipher);

        let (commitments, pubkeys) = self.state.commitments()?;
        self.pubkeys = pubkeys;

        // TODO: support more than 1
        Ok(commitments[0].clone())
    }

    async fn send_signing_package_and_get_signature_shares(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        signing_package: &SigningPackage<C>,
        randomizer: Option<frost_rerandomized::Randomizer<C>>,
    ) -> Result<BTreeMap<Identifier<C>, SignatureShare<C>>, Box<dyn Error>> {
        eprintln!("Sending SigningPackage to participants...");
        let cipher = self
            .cipher
            .as_mut()
            .expect("cipher must have been set before");
        let send_signing_package_args = SendSigningPackageArgs {
            signing_package: vec![signing_package.clone()],
            aux_msg: Default::default(),
            randomizer: randomizer.map(|r| vec![r]).unwrap_or_default(),
        };
        // We need to send a message separately for each recipient even if the
        // message is the same, because they are (possibly) encrypted
        // individually for each recipient.
        let pubkeys: Vec<_> = self.pubkeys.keys().cloned().collect();
        for recipient in pubkeys {
            let msg = cipher.encrypt(
                Some(&recipient),
                serde_json::to_vec(&send_signing_package_args)?,
            )?;
            let _r = self
                .client
                .send(&api::SendArgs {
                    session_id: self.session_id.unwrap(),
                    recipients: vec![recipient.clone()],
                    msg,
                })
                .await?;
        }

        eprintln!("Waiting for participants to send their SignatureShares...");

        loop {
            let r = self
                .client
                .receive(&api::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: true,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
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
            .close_session(&api::CloseSessionArgs {
                session_id: self.session_id.unwrap(),
            })
            .await?;

        let _r = self.client.logout().await?;

        let signature_shares = self.state.signature_shares()?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }

    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(session_id) = self.session_id {
            let _r = self
                .client
                .close_session(&api::CloseSessionArgs { session_id })
                .await?;
        }
        Ok(())
    }
}
