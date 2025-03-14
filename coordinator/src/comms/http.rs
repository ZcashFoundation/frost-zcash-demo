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

use frostd::{Msg, PublicKey, SendSigningPackageArgs, Uuid};
use participant::comms::http::Noise;
use rand::thread_rng;
use xeddsa::{xed25519, Sign as _};

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
    client: reqwest::Client,
    host_port: String,
    session_id: Option<Uuid>,
    access_token: Option<String>,
    args: ProcessedArgs<C>,
    state: SessionState<C>,
    pubkeys: HashMap<PublicKey, Identifier<C>>,
    // The "send" Noise objects by pubkey of recipients.
    send_noise: Option<HashMap<PublicKey, Noise>>,
    // The "receive" Noise objects by pubkey of senders.
    recv_noise: Option<HashMap<PublicKey, Noise>>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            host_port: format!("https://{}:{}", args.ip, args.port),
            session_id: None,
            access_token: None,
            args: args.clone(),
            state: SessionState::new(
                args.messages.len(),
                args.num_signers as usize,
                args.signers.clone(),
            ),
            pubkeys: Default::default(),
            send_noise: None,
            recv_noise: None,
            _phantom: Default::default(),
        })
    }

    // Encrypts a message for a given recipient.
    fn encrypt(&mut self, recipient: &PublicKey, msg: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
        let noise_map = self
            .send_noise
            .as_mut()
            .expect("send_noise must have been set previously");
        let noise = noise_map
            .get_mut(recipient)
            .ok_or_eyre("unknown recipient")?;
        let mut encrypted = vec![0; frostd::MAX_MSG_SIZE];
        let len = noise.write_message(&msg, &mut encrypted)?;
        encrypted.truncate(len);
        Ok(encrypted)
    }

    // Decrypts a message.
    // Note that this authenticates the `sender` in the `Msg` struct; if the
    // sender is tampered with, the message would fail to decrypt.
    fn decrypt(&mut self, msg: Msg) -> Result<Msg, Box<dyn Error>> {
        let noise_map = self
            .recv_noise
            .as_mut()
            .expect("recv_noise must have been set previously");
        let noise = noise_map
            .get_mut(&msg.sender)
            .ok_or_eyre("unknown sender")?;
        let mut decrypted = vec![0; frostd::MAX_MSG_SIZE];
        decrypted.resize(frostd::MAX_MSG_SIZE, 0);
        let len = noise.read_message(&msg.msg, &mut decrypted)?;
        decrypted.truncate(len);
        Ok(Msg {
            sender: msg.sender,
            msg: decrypted,
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
        let challenge = self
            .client
            .post(format!("{}/challenge", self.host_port))
            .json(&frostd::ChallengeArgs {})
            .send()
            .await?
            .json::<frostd::ChallengeOutput>()
            .await?
            .challenge;

        let privkey = xed25519::PrivateKey::from(
            &TryInto::<[u8; 32]>::try_into(
                self.args
                    .comm_privkey
                    .clone()
                    .ok_or_eyre("comm_privkey must be specified")?,
            )
            .map_err(|_| eyre!("invalid comm_privkey"))?,
        );
        let signature: [u8; 64] = privkey.sign(challenge.as_bytes(), &mut rng);

        self.access_token = Some(
            self.client
                .post(format!("{}/login", self.host_port))
                .json(&frostd::KeyLoginArgs {
                    challenge,
                    pubkey: self
                        .args
                        .comm_pubkey
                        .clone()
                        .ok_or_eyre("comm_pubkey must be specified")?,
                    signature: signature.to_vec(),
                })
                .send()
                .await?
                .json::<frostd::LoginOutput>()
                .await?
                .access_token
                .to_string(),
        );

        eprintln!("Creating signing session...");
        let r = self
            .client
            .post(format!("{}/create_new_session", self.host_port))
            .bearer_auth(self.access_token.as_ref().expect("was just set"))
            .json(&frostd::CreateNewSessionArgs {
                pubkeys: self.args.signers.keys().cloned().collect(),
                message_count: 1,
            })
            .send()
            .await?
            .json::<frostd::CreateNewSessionOutput>()
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

        let mut send_noise_map = HashMap::new();
        let mut recv_noise_map = HashMap::new();
        for comm_participant_pubkey in self.args.signers.keys() {
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let send_noise = Noise::new(
                builder
                    .local_private_key(comm_privkey)
                    .remote_public_key(&comm_participant_pubkey.0)
                    .build_initiator()?,
            );
            let builder = snow::Builder::new(
                "Noise_K_25519_ChaChaPoly_BLAKE2s"
                    .parse()
                    .expect("should be a valid cipher"),
            );
            let recv_noise = Noise::new(
                builder
                    .local_private_key(comm_privkey)
                    .remote_public_key(&comm_participant_pubkey.0)
                    .build_responder()?,
            );
            send_noise_map.insert(comm_participant_pubkey.clone(), send_noise);
            recv_noise_map.insert(comm_participant_pubkey.clone(), recv_noise);
        }
        self.send_noise = Some(send_noise_map);
        self.recv_noise = Some(recv_noise_map);

        eprint!("Waiting for participants to send their commitments...");

        loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(self.access_token.as_ref().expect("was just set"))
                .json(&frostd::ReceiveArgs {
                    session_id: r.session_id,
                    as_coordinator: true,
                })
                .send()
                .await?
                .json::<frostd::ReceiveOutput>()
                .await?;
            for msg in r.msgs {
                let msg = self.decrypt(msg)?;
                self.state.recv(msg)?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_commitments() {
                break;
            }
        }
        eprintln!();

        let (commitments, pubkeys) = self.state.commitments()?;
        self.pubkeys = pubkeys;

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
        // We need to send a message separately for each recipient even if the
        // message is the same, because they are (possibly) encrypted
        // individually for each recipient.
        let pubkeys: Vec<_> = self.pubkeys.keys().cloned().collect();
        for recipient in pubkeys {
            let msg = self.encrypt(&recipient, serde_json::to_vec(&send_signing_package_args)?)?;
            let _r = self
                .client
                .post(format!("{}/send", self.host_port))
                .bearer_auth(
                    self.access_token
                        .as_ref()
                        .expect("must have been set before"),
                )
                .json(&frostd::SendArgs {
                    session_id: self.session_id.unwrap(),
                    recipients: vec![recipient.clone()],
                    msg,
                })
                .send()
                .await?
                .bytes()
                .await?;
        }

        eprintln!("Waiting for participants to send their SignatureShares...");

        loop {
            let r = self
                .client
                .post(format!("{}/receive", self.host_port))
                .bearer_auth(
                    self.access_token
                        .as_ref()
                        .expect("must have been set before"),
                )
                .json(&frostd::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: true,
                })
                .send()
                .await?
                .json::<frostd::ReceiveOutput>()
                .await?;
            for msg in r.msgs {
                let msg = self.decrypt(msg)?;
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
            .bearer_auth(
                self.access_token
                    .as_ref()
                    .expect("must have been set before"),
            )
            .json(&frostd::CloseSessionArgs {
                session_id: self.session_id.unwrap(),
            })
            .send()
            .await?
            .bytes()
            .await?;

        let _r = self
            .client
            .post(format!("{}/logout", self.host_port))
            .bearer_auth(
                self.access_token
                    .as_ref()
                    .expect("must have been set before"),
            )
            .send()
            .await?
            .bytes()
            .await?;

        let signature_shares = self.state.signature_shares()?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }

    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        if let (Some(session_id), Some(access_token)) = (self.session_id, self.access_token.clone())
        {
            let _r = self
                .client
                .post(format!("{}/close_session", self.host_port))
                .bearer_auth(access_token)
                .json(&frostd::CloseSessionArgs { session_id })
                .send()
                .await?
                .bytes()
                .await?;
        }
        Ok(())
    }
}
