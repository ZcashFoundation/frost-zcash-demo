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
    keys::dkg::{round1, round2},
    Ciphersuite, Identifier,
};

use frostd::{cipher::Cipher, client::Client, Msg, PublicKey, Uuid};
use rand::thread_rng;

use super::Comms;
use crate::args::ProcessedArgs;

/// The current state of a session.
///
/// This can be used by a DKG Participant to help maintain state and handle
/// messages from the other Participants.
#[derive(Debug)]
pub enum SessionState<C: Ciphersuite> {
    /// Waiting for participants to send their commitments.
    WaitingForRound1Packages {
        /// Pubkey -> Identifier mapping. This is set during the
        /// get_identifier() call of HTTPComms.
        pubkeys: HashMap<PublicKey, Identifier<C>>,
        /// Round 1 Packages sent by participants so far.
        round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
    },
    /// Waiting for participants to send their broadcasts of other participant's
    /// commitments. See documentation of [`handle_round1_package_broadcast()`]
    /// for details.
    WaitingForRound1PackagesBroadcast {
        /// Pubkey -> Identifier mapping.
        pubkeys: HashMap<PublicKey, Identifier<C>>,
        /// Original Round 1 Packages sent by the other participants.
        round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
        /// Broadcasted Round 1 Packages sent by the other participants,
        /// keyed by original sender, then by the sender of the broadcast.
        round1_broadcasted_packages:
            BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, round1::Package<C>>>,
    },
    /// Round 1 Packages have been sent by all other participants. Round 2
    /// Package can be created sent to other participants. Waiting for other
    /// participants to send their Round 2 Packages.
    WaitingForRound2Packages {
        /// Pubkey -> Identifier mapping.
        pubkeys: HashMap<PublicKey, Identifier<C>>,
        /// Round 1 Packages sent by participants.
        round1_packages: BTreeMap<Identifier<C>, round1::Package<C>>,
        /// Round 2 Packages sent by participants so far
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    },
    /// Round 2 Packages have been sent by all other participants; ready to be
    /// fetched by this participant.
    Round2PackagesReady {
        /// Pubkey -> Identifier mapping.
        pubkeys: HashMap<PublicKey, Identifier<C>>,
        /// Round 2 Packages sent by participants so far
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    },
}

impl<C: Ciphersuite> Default for SessionState<C> {
    fn default() -> Self {
        Self::WaitingForRound1Packages {
            pubkeys: Default::default(),
            round1_packages: Default::default(),
        }
    }
}

impl<C: Ciphersuite> SessionState<C> {
    /// Handle a Msg received from a participant.
    ///
    /// This should be called for new Msgs until [`are_commitments_ready()`]
    /// returns true, and after the SigningPackage is sent to the participants,
    /// it should be called for new Msgs until [`are_signature_shares_ready()`]
    /// returns true.
    pub fn recv(&mut self, msg: Msg, self_identifier: Identifier<C>) -> Result<(), Box<dyn Error>> {
        match self {
            SessionState::WaitingForRound1Packages { .. } => {
                let round1_package: round1::Package<C> = serde_json::from_slice(&msg.msg)?;
                self.handle_round1_package(msg.sender, round1_package)?;
            }
            SessionState::WaitingForRound1PackagesBroadcast { .. } => {
                let (identifier, round1_package): (Identifier<C>, round1::Package<C>) =
                    serde_json::from_slice(&msg.msg)?;
                self.handle_round1_package_broadcast(
                    msg.sender,
                    self_identifier,
                    identifier,
                    round1_package,
                )?;
            }
            SessionState::WaitingForRound2Packages { .. } => {
                let round2_package: round2::Package<C> = serde_json::from_slice(&msg.msg)?;
                self.handle_round2_package(msg.sender, round2_package)?;
            }
            _ => return Err(eyre!("received message during wrong state").into()),
        }
        Ok(())
    }

    /// Handle commitments sent by a participant.
    fn handle_round1_package(
        &mut self,
        pubkey: PublicKey,
        round1_package: round1::Package<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForRound1Packages {
            pubkeys,
            round1_packages,
        } = self
        {
            let identifier = *pubkeys.get(&pubkey).ok_or(eyre!("unknown participant"))?;
            // Add Round 1 Package to map.
            // Currently ignores the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            round1_packages.insert(identifier, round1_package);

            // If complete, advance to next state
            if round1_packages.len() == pubkeys.len() - 1 {
                if pubkeys.len() > 2 {
                    *self = SessionState::WaitingForRound1PackagesBroadcast {
                        pubkeys: pubkeys.clone(),
                        round1_packages: round1_packages.clone(),
                        round1_broadcasted_packages: Default::default(),
                    }
                } else {
                    // if pubkeys.len() == 2 then the echo broadcast protocol
                    // degenerates into a simple broadcast, so we can just skip
                    // the echo broadcast round.
                    *self = SessionState::WaitingForRound2Packages {
                        pubkeys: pubkeys.clone(),
                        round1_packages: round1_packages.clone(),
                        round2_packages: Default::default(),
                    }
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Handle broadcast package sent from another participant.
    ///
    /// This implements Goldwasser-Lindell echo-broadcast protocol (Protocol 1
    /// from [1]). We use the following terminology in the comments of this
    /// function.
    ///
    /// - The original sender is the participant that wants to broadcast their
    ///   package. The `round1_package` will thus contain the package sent by
    ///   each original sender.
    /// - The broadcaster sender is the participant that, after receiving the
    ///   original sender package, broadcasts it to all other participants
    ///   (excluding themselves, and the original sender).
    /// - After all that is done, each echo-broadcast session is validated. It
    ///   is valid if every broadcast package is equal to the original package
    ///   sent by the original sender.
    ///
    /// Note that here we are keeping track of n-1 echo-broadcasts in parallel,
    /// one for each original sender. In each of the n-1 echo-broadcast
    /// sessions, we should receive n-2 broadcast packages (since we are
    /// excluding the original sender and ourselves).
    ///
    /// [1]: https://eprint.iacr.org/2002/040.pdf
    fn handle_round1_package_broadcast(
        &mut self,
        sender_pubkey: PublicKey,
        self_identifier: Identifier<C>,
        original_identifier: Identifier<C>,
        round1_package: round1::Package<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForRound1PackagesBroadcast {
            pubkeys,
            round1_packages,
            round1_broadcasted_packages,
        } = self
        {
            let sender_identifier = *pubkeys
                .get(&sender_pubkey)
                .ok_or(eyre!("unknown participant"))?;
            // The `original_identifier` is not authenticated; we need to check
            // if it is truly part of the DKG session.
            if !pubkeys.values().any(|&id| id == original_identifier) {
                return Err(eyre!("unknown participant"))?;
            }
            // Make sure nothing strange is going on.
            if original_identifier == self_identifier {
                return Err(eyre!("received own broadcast Round 1 Package").into());
            }
            if original_identifier == sender_identifier {
                return Err(eyre!("received redundant broadcast Round 1 Package").into());
            }
            // Check if broadcast package is equal to the original package.
            if round1_packages
                .get(&original_identifier)
                .ok_or_eyre("Round 1 Package not found")?
                != &round1_package
            {
                return Err(eyre!("broadcast mismatch").into());
            }

            // Add broadcast Round 1 Package to the original sender's map.
            if round1_broadcasted_packages
                .entry(original_identifier)
                .or_insert_with(BTreeMap::new)
                .insert(sender_identifier, round1_package)
                .is_some()
            {
                return Err(eyre!("duplicated broadcast Round 1 Package").into());
            }

            // Set of all other participants' identifiers
            let other_identifiers = round1_packages.keys().cloned().collect::<HashSet<_>>();

            // If complete, advance to next state. First, check if we have
            // package maps for all other participants (original senders).
            if round1_broadcasted_packages
                .keys()
                .cloned()
                .collect::<HashSet<_>>()
                == other_identifiers
                // Then, validate each original sender's map.
                && round1_broadcasted_packages
                    .iter()
                    .all(|(original_identifier, map)| {
                        let mut map_identifiers = map.keys().cloned().collect::<HashSet<_>>();
                        map_identifiers.insert(*original_identifier);
                        //  Check if the map has all the other participants'
                        // identifiers, excluding the original sender. (Or
                        // alternatively, if the `other_identifiers` is equal to
                        // `map_identifiers` when the original sender is added
                        // to it.)
                        map_identifiers == other_identifiers
                        // And finally, check if the broadcasted packages are
                        // all equal to the package received from the original
                        // sender in the previous round. Since we have already
                        // checked them above before inserting them in
                        // `round1_broadcasted_packages` this should always be
                        // true; but it's safer to double check.
                            && map.values().all(|package| {
                                Some(package)
                                    == round1_packages
                                        .get(original_identifier)
                            })
                    })
            {
                *self = SessionState::WaitingForRound2Packages {
                    pubkeys: pubkeys.clone(),
                    round1_packages: round1_packages.clone(),
                    round2_packages: Default::default(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns if all participants sent their Round 1 Packages.
    /// When this returns `true`, [`round1_packages()`] can be called, but
    /// its contents have not been checked via echo broadcast.
    pub fn has_round1_packages(&self) -> bool {
        matches!(
            self,
            SessionState::WaitingForRound1PackagesBroadcast { .. }
                | SessionState::WaitingForRound2Packages { .. }
        )
    }

    /// Returns a map linking a participant identifier and the Round 1 Package
    /// they have sent.
    #[allow(clippy::type_complexity)]
    pub fn round1_packages(
        &mut self,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        match self {
            SessionState::WaitingForRound2Packages {
                round1_packages, ..
            }
            | SessionState::WaitingForRound1PackagesBroadcast {
                round1_packages, ..
            } => Ok(round1_packages.clone()),
            _ => panic!("wrong state"),
        }
    }

    /// Returns if all participants sent their broadcast Round 1 Packages,
    /// or if the echo broadcast round should be skipped.
    ///
    /// When this returns `true`, [`round1_packages()`] can be called,
    /// and its contents are ensured to be checked via echo broadcast.
    pub fn has_round1_broadcast_packages(&self) -> bool {
        matches!(self, SessionState::WaitingForRound2Packages { .. })
    }

    /// Returns if all participants sent their Round 2 Packages.
    /// When this returns `true`, [`round2_packages()`] can be called.
    pub fn has_round2_packages(&self) -> bool {
        matches!(self, SessionState::Round2PackagesReady { .. })
    }

    /// Handle signature share sent by a participant.
    fn handle_round2_package(
        &mut self,
        pubkey: PublicKey,
        round2_package: round2::Package<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let SessionState::WaitingForRound2Packages {
            pubkeys,
            round1_packages,
            round2_packages,
        } = self
        {
            let identifier = pubkeys.get(&pubkey).ok_or(eyre!("unknown participant"))?;
            if !round1_packages.contains_key(identifier) {
                return Err(eyre!("unkown participant").into());
            }

            // Currently ignoring the possibility of overwriting previous values
            // (it seems better to ignore overwrites, which could be caused by
            // poor networking connectivity leading to retries)
            round2_packages.insert(*identifier, round2_package);
            // If complete, advance to next state
            if round2_packages.keys().cloned().collect::<HashSet<_>>()
                == round1_packages.keys().cloned().collect::<HashSet<_>>()
            {
                *self = SessionState::Round2PackagesReady {
                    pubkeys: pubkeys.clone(),
                    round2_packages: round2_packages.clone(),
                }
            }
            Ok(())
        } else {
            panic!("wrong state");
        }
    }

    /// Returns a map linking a participant identifier and the Round 2 Package
    /// they have sent.
    #[allow(clippy::type_complexity)]
    pub fn round2_packages(
        &mut self,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        if let SessionState::Round2PackagesReady {
            round2_packages, ..
        } = self
        {
            Ok(round2_packages.clone())
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
    identifier: Option<Identifier<C>>,
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
            state: SessionState::default(),
            identifier: None,
            pubkeys: Default::default(),
            cipher: None,
            _phantom: Default::default(),
        })
    }
}

#[async_trait(?Send)]
impl<C: Ciphersuite + 'static> Comms<C> for HTTPComms<C> {
    async fn get_identifier_and_max_signers(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>> {
        let mut rng = thread_rng();

        eprintln!("Logging in...");
        let challenge = self.client.challenge().await?.challenge;

        let signature: [u8; 64] = self
            .args
            .comm_privkey
            .clone()
            .ok_or_eyre("comm_privkey must be specified")?
            .sign(challenge.as_bytes(), &mut rng)?;

        let comm_pubkey = self
            .args
            .comm_pubkey
            .clone()
            .ok_or_eyre("comm_pubkey must be specified")?;

        self.client
            .login(&frostd::LoginArgs {
                challenge,
                pubkey: comm_pubkey.clone(),
                signature: signature.to_vec(),
            })
            .await?;

        let session_id = if !self.args.participants.is_empty() {
            eprintln!("Creating DKG session...");
            let r = self
                .client
                .create_new_session(&frostd::CreateNewSessionArgs {
                    pubkeys: self.args.participants.clone(),
                    message_count: 1,
                })
                .await?;
            r.session_id
        } else {
            eprintln!("Joining DKG session...");
            match self.session_id {
                Some(s) => s,
                None => {
                    // Get session ID from server
                    let r = self.client.list_sessions().await?;
                    if r.session_ids.len() > 1 {
                        return Err(eyre!("user has more than one FROST session active; use `frost-client sessions` to list them and specify the session ID with `-S`").into());
                    } else if r.session_ids.is_empty() {
                        return Err(eyre!("User has no current sessions active").into());
                    }
                    r.session_ids[0]
                }
            }
        };
        self.session_id = Some(session_id);

        eprintln!("Getting session info...");
        // Get all participants' public keys, and derive their identifiers
        // from them.
        let session_info = self
            .client
            .get_session_info(&frostd::GetSessionInfoArgs { session_id })
            .await?;
        self.pubkeys = session_info
            .pubkeys
            .iter()
            .map(|p| {
                Ok((
                    p.clone(),
                    Identifier::<C>::derive(&[session_id.as_bytes(), &p.0[..]].concat())?,
                ))
            })
            .collect::<Result<_, frost_core::Error<C>>>()?;

        if self.pubkeys.len() < 2 {
            return Err(eyre!("DKG session must have at least 2 participants").into());
        }

        // Copy the pubkeys into the state.
        match self.state {
            SessionState::WaitingForRound1Packages {
                ref mut pubkeys, ..
            } => {
                *pubkeys = self.pubkeys.clone();
            }
            _ => unreachable!("wrong state"),
        }

        // Compute this user's identifier by deriving it from the concatenation
        // of the session ID and the communication public key.
        // This ensures the identifier is unique and that participants can
        // derive each other's identifiers.
        let input = [session_id.as_bytes(), &comm_pubkey.0[..]].concat();
        let identifier = Identifier::<C>::derive(&input)?;
        self.identifier = Some(identifier);
        Ok((identifier, self.pubkeys.len() as u16))
    }

    async fn get_round1_packages(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        let (Some(comm_privkey), Some(comm_participant_pubkey_getter)) = (
            &self.args.comm_privkey,
            &self.args.comm_participant_pubkey_getter,
        ) else {
            return Err(
                eyre!("comm_privkey and comm_participant_pubkey_getter must be specified").into(),
            );
        };

        let cipher = Cipher::new(
            comm_privkey.clone(),
            self.pubkeys.keys().map(|pubkey| comm_participant_pubkey_getter(pubkey).ok_or_eyre(
                "A participant in specified FROST session is not registered in the user's address book"
            )).collect::<Result<_,_>>()?,
        )?;
        self.cipher = Some(cipher);
        let cipher = self.cipher.as_mut().expect("was just set");

        // Send Round 1 Package to all other participants
        for pubkey in self.pubkeys.clone().keys() {
            if Some(pubkey) == self.args.comm_pubkey.as_ref() {
                continue;
            }
            let msg = cipher.encrypt(Some(pubkey), serde_json::to_vec(&round1_package)?)?;
            self.client
                .send(&frostd::SendArgs {
                    session_id: self.session_id.expect("set before"),
                    recipients: vec![pubkey.clone()],
                    msg,
                })
                .await?;
        }

        eprint!("Waiting for other participants to send their Round 1 Packages...");

        loop {
            let r = self
                .client
                .receive(&frostd::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state
                    .recv(msg, self.identifier.expect("must have been set"))?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_round1_packages() {
                break;
            }
        }
        eprintln!();

        // We might need to skip the echo broadcast if its not needed (e.g.
        // only 2 participants)
        if !self.state.has_round1_broadcast_packages() {
            // Broadcast received Round 1 Packages to all other participants
            for (recipient_pubkey, recipient_identifier) in self.pubkeys.clone().iter() {
                // No need to broadcast to oneself
                if Some(recipient_pubkey) == self.args.comm_pubkey.as_ref() {
                    continue;
                }
                for (sender_identifier, package) in self.state.round1_packages()?.iter() {
                    // No need to broadcast back to the sender
                    if *sender_identifier == *recipient_identifier {
                        continue;
                    }
                    let msg = cipher.encrypt(
                        Some(recipient_pubkey),
                        serde_json::to_vec(&(*sender_identifier, package))?,
                    )?;
                    self.client
                        .send(&frostd::SendArgs {
                            session_id: self.session_id.expect("set before"),
                            recipients: vec![recipient_pubkey.clone()],
                            msg,
                        })
                        .await?;
                }
            }

            eprint!("Waiting for other participants to send their broadcasted Round 1 Packages...");

            loop {
                let r = self
                    .client
                    .receive(&frostd::ReceiveArgs {
                        session_id: self.session_id.unwrap(),
                        as_coordinator: false,
                    })
                    .await?;
                for msg in r.msgs {
                    let msg = cipher.decrypt(msg)?;
                    self.state
                        .recv(msg, self.identifier.expect("must have been set"))?;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                eprint!(".");
                if self.state.has_round1_broadcast_packages() {
                    break;
                }
            }
            eprintln!();
        }

        self.state.round1_packages()
    }

    async fn get_round2_packages(
        &mut self,
        _input: &mut dyn BufRead,
        _output: &mut dyn Write,
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>> {
        let cipher = self.cipher.as_mut().expect("was just set");
        // Send Round 2 Packages to all other participants
        for (pubkey, identifier) in self.pubkeys.clone().into_iter() {
            if Some(&pubkey) == self.args.comm_pubkey.as_ref() {
                continue;
            }
            let msg = cipher.encrypt(
                Some(&pubkey),
                serde_json::to_vec(
                    &round2_packages
                        .get(&identifier)
                        .ok_or_eyre("must have Round 2 Package for the given identifier")?,
                )?,
            )?;
            self.client
                .send(&frostd::SendArgs {
                    session_id: self.session_id.expect("set before"),
                    recipients: vec![pubkey.clone()],
                    msg,
                })
                .await?;
        }

        eprint!("Waiting for other participants to send their Round 2 Packages...");

        loop {
            let r = self
                .client
                .receive(&frostd::ReceiveArgs {
                    session_id: self.session_id.unwrap(),
                    as_coordinator: false,
                })
                .await?;
            for msg in r.msgs {
                let msg = cipher.decrypt(msg)?;
                self.state
                    .recv(msg, self.identifier.expect("must have been set"))?;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            eprint!(".");
            if self.state.has_round2_packages() {
                break;
            }
        }
        eprintln!();

        if !self.args.participants.is_empty() {
            let _r = self
                .client
                .close_session(&frostd::CloseSessionArgs {
                    session_id: self.session_id.unwrap(),
                })
                .await?;
        }

        let _r = self.client.logout().await?;

        self.state.round2_packages()
    }

    fn get_pubkey_identifier_map(
        &self,
    ) -> Result<HashMap<PublicKey, Identifier<C>>, Box<dyn Error>> {
        match &self.state {
            SessionState::Round2PackagesReady { pubkeys, .. } => Ok(pubkeys.clone()),
            _ => Err(eyre!("wrong state").into()),
        }
    }

    async fn cleanup_on_error(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(session_id) = self.session_id {
            let _r = self
                .client
                .close_session(&frostd::CloseSessionArgs { session_id })
                .await?;
        }
        Ok(())
    }
}
