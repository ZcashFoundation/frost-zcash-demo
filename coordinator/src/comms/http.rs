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

use participant::comms::http::Noise;
use rand::thread_rng;
use server::{Msg, SendCommitmentsArgs, SendSignatureSharesArgs, SendSigningPackageArgs, Uuid};
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
        pubkeys: HashMap<Vec<u8>, Identifier<C>>,
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
        pubkeys: HashMap<Vec<u8>, Identifier<C>>,
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
            pubkeys: Default::default(),
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
        pubkey: Vec<u8>,
        send_commitments_args: SendCommitmentsArgs<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForCommitments {
            args,
            commitments,
            pubkeys: usernames,
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
            usernames.insert(pubkey, send_commitments_args.identifier);

            // If complete, advance to next state
            if commitments.len() == args.num_signers {
                *self = SessionState::WaitingForSignatureShares {
                    args: args.clone(),
                    commitments: commitments.clone(),
                    pubkeys: usernames.clone(),
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
            HashMap<Vec<u8>, Identifier<C>>,
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
        _username: Vec<u8>,
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
    pubkeys: HashMap<Vec<u8>, Identifier<C>>,
    should_logout: bool,
    // The "send" Noise objects by pubkey of recipients.
    send_noise: Option<HashMap<Vec<u8>, Noise>>,
    // The "receive" Noise objects by pubkey of senders.
    recv_noise: Option<HashMap<Vec<u8>, Noise>>,
    _phantom: PhantomData<C>,
}

impl<C: Ciphersuite> HTTPComms<C> {
    pub fn new(args: &ProcessedArgs<C>) -> Result<Self, Box<dyn Error>> {
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            host_port: format!("http://{}:{}", args.ip, args.port),
            session_id: None,
            access_token: args.authentication_token.clone().unwrap_or_default(),
            num_signers: 0,
            args: args.clone(),
            state: SessionState::new(args.messages.len(), args.num_signers as usize),
            pubkeys: Default::default(),
            should_logout: args.authentication_token.is_none(),
            send_noise: None,
            recv_noise: None,
            _phantom: Default::default(),
        })
    }

    // Encrypts a message for a given recipient if encryption is enabled.
    fn encrypt_if_needed(
        &mut self,
        recipient: &Vec<u8>,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(noise_map) = &mut self.send_noise {
            let noise = noise_map
                .get_mut(recipient)
                .ok_or_eyre("unknown recipient")?;
            let mut encrypted = vec![0; 65535];
            let len = noise.write_message(&msg, &mut encrypted)?;
            encrypted.truncate(len);
            Ok(encrypted)
        } else {
            Ok(msg)
        }
    }

    // Decrypts a message if encryption is enabled.
    // Note that this authenticates the `sender` in the `Msg` struct; if the
    // sender is tampered with, the message would fail to decrypt.
    fn decrypt_if_needed(&mut self, msg: Msg) -> Result<Msg, Box<dyn Error>> {
        if let Some(noise_map) = &mut self.recv_noise {
            let noise = noise_map
                .get_mut(&msg.sender)
                .ok_or_eyre("unknown sender")?;
            let mut decrypted = vec![0; 65535];
            decrypted.resize(65535, 0);
            let len = noise.read_message(&msg.msg, &mut decrypted)?;
            decrypted.truncate(len);
            Ok(Msg {
                sender: msg.sender,
                msg: decrypted,
            })
        } else {
            Ok(msg)
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
        let mut rng = thread_rng();
        let challenge = self
            .client
            .post(format!("{}/challenge", self.host_port))
            .json(&server::ChallengeArgs {})
            .send()
            .await?
            .json::<server::ChallengeOutput>()
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

        self.access_token = self
            .client
            .post(format!("{}/key_login", self.host_port))
            .json(&server::KeyLoginArgs {
                uuid: challenge,
                pubkey: self
                    .args
                    .comm_pubkey
                    .clone()
                    .ok_or_eyre("comm_pubkey must be specified")?,
                signature: signature.to_vec(),
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
                pubkeys: self.args.signers.clone(),
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

        // If encryption is enabled, create the Noise objects
        (self.send_noise, self.recv_noise) = if let (
            Some(comm_privkey),
            Some(comm_participant_pubkey_getter),
        ) = (
            &self.args.comm_privkey,
            &self.args.comm_participant_pubkey_getter,
        ) {
            let mut send_noise_map = HashMap::new();
            let mut recv_noise_map = HashMap::new();
            for pubkey in &self.args.signers {
                let comm_participant_pubkey = comm_participant_pubkey_getter(pubkey).ok_or_eyre("A participant in specified FROST session is not registered in the coordinator's address book")?;
                let builder = snow::Builder::new(
                    "Noise_K_25519_ChaChaPoly_BLAKE2s"
                        .parse()
                        .expect("should be a valid cipher"),
                );
                let send_noise = Noise::new(
                    builder
                        .local_private_key(comm_privkey)
                        .remote_public_key(&comm_participant_pubkey)
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
                        .remote_public_key(&comm_participant_pubkey)
                        .build_responder()?,
                );
                send_noise_map.insert(pubkey.clone(), send_noise);
                recv_noise_map.insert(pubkey.clone(), recv_noise);
            }
            (Some(send_noise_map), Some(recv_noise_map))
        } else {
            (None, None)
        };

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
                let msg = self.decrypt_if_needed(msg)?;
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
            let msg = self
                .encrypt_if_needed(&recipient, serde_json::to_vec(&send_signing_package_args)?)?;
            let _r = self
                .client
                .post(format!("{}/send", self.host_port))
                .bearer_auth(&self.access_token)
                .json(&server::SendArgs {
                    session_id: self.session_id.unwrap(),
                    recipients: vec![server::PublicKey(recipient.clone())],
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
                let msg = self.decrypt_if_needed(msg)?;
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

        if self.should_logout {
            let _r = self
                .client
                .post(format!("{}/logout", self.host_port))
                .bearer_auth(&self.access_token)
                .send()
                .await?;
        }

        let signature_shares = self.state.signature_shares()?;

        // TODO: support more than 1
        Ok(signature_shares[0].clone())
    }
}
