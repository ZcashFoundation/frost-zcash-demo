//! Session state management for the DKG and Coordinator.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
};

use eyre::{eyre, OptionExt};

use frost_core::keys::dkg::{round1, round2};
use frost_core::{round1::SigningCommitments, round2::SignatureShare, Ciphersuite, Identifier};

use crate::api::{Msg, PublicKey};

/// Arguments for the coordinator session state.
#[derive(Clone, Debug)]
pub struct CoordinatorSessionStateArgs {
    pub num_messages: usize,
    pub num_signers: usize,
}

/// The current state of a session.
///
/// This can be used by a Coordinator to help maintain state and handle
/// messages from the Participants.
#[derive(Debug)]
pub enum CoordinatorSessionState<C: Ciphersuite> {
    /// Waiting for participants to send their commitments.
    WaitingForCommitments {
        /// Session arguments
        args: CoordinatorSessionStateArgs,
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
        args: CoordinatorSessionStateArgs,
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
        args: CoordinatorSessionStateArgs,
        /// Signature shares sent by participants, for each message being signed.
        signature_shares: HashMap<Identifier<C>, Vec<SignatureShare<C>>>,
    },
}

impl<C: Ciphersuite> CoordinatorSessionState<C> {
    /// Create a new SessionState for the given number of messages and signers.
    pub fn new(
        num_messages: usize,
        num_signers: usize,
        pubkeys: HashMap<PublicKey, Identifier<C>>,
    ) -> Self {
        let args = CoordinatorSessionStateArgs {
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
            CoordinatorSessionState::WaitingForCommitments { .. } => {
                let send_commitments_args: Vec<SigningCommitments<C>> =
                    serde_json::from_slice(&msg.msg)?;
                self.handle_commitments(msg.sender, send_commitments_args)?;
            }
            CoordinatorSessionState::WaitingForSignatureShares { .. } => {
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
        if let CoordinatorSessionState::WaitingForCommitments {
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
                *self = CoordinatorSessionState::WaitingForSignatureShares {
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
        matches!(
            self,
            CoordinatorSessionState::WaitingForSignatureShares { .. }
        )
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
        if let CoordinatorSessionState::WaitingForSignatureShares {
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
        matches!(self, CoordinatorSessionState::SignatureSharesReady { .. })
    }

    /// Handle signature share sent by a participant.
    fn handle_signature_share(
        &mut self,
        pubkey: PublicKey,
        signature_shares: Vec<SignatureShare<C>>,
    ) -> Result<(), Box<dyn Error>> {
        if let CoordinatorSessionState::WaitingForSignatureShares {
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
                *self = CoordinatorSessionState::SignatureSharesReady {
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
        if let CoordinatorSessionState::SignatureSharesReady {
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

/// The current state of a DKG session.
///
/// This can be used by a DKG Participant to help maintain state and handle
/// messages from the other Participants.
#[derive(Debug)]
pub enum DKGSessionState<C: Ciphersuite> {
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

impl<C: Ciphersuite> Default for DKGSessionState<C> {
    fn default() -> Self {
        Self::WaitingForRound1Packages {
            pubkeys: Default::default(),
            round1_packages: Default::default(),
        }
    }
}

impl<C: Ciphersuite> DKGSessionState<C> {
    /// Handle a Msg received from a participant.
    ///
    /// This should be called for new Msgs until [`are_commitments_ready()`]
    /// returns true, and after the SigningPackage is sent to the participants,
    /// it should be called for new Msgs until [`are_signature_shares_ready()`]
    /// returns true.
    pub fn recv(&mut self, msg: Msg, self_identifier: Identifier<C>) -> Result<(), Box<dyn Error>> {
        match self {
            DKGSessionState::WaitingForRound1Packages { .. } => {
                let round1_package: round1::Package<C> = serde_json::from_slice(&msg.msg)?;
                self.handle_round1_package(msg.sender, round1_package)?;
            }
            DKGSessionState::WaitingForRound1PackagesBroadcast { .. } => {
                let (identifier, round1_package): (Identifier<C>, round1::Package<C>) =
                    serde_json::from_slice(&msg.msg)?;
                self.handle_round1_package_broadcast(
                    msg.sender,
                    self_identifier,
                    identifier,
                    round1_package,
                )?;
            }
            DKGSessionState::WaitingForRound2Packages { .. } => {
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
        if let DKGSessionState::WaitingForRound1Packages {
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
                    *self = DKGSessionState::WaitingForRound1PackagesBroadcast {
                        pubkeys: pubkeys.clone(),
                        round1_packages: round1_packages.clone(),
                        round1_broadcasted_packages: Default::default(),
                    }
                } else {
                    // if pubkeys.len() == 2 then the echo broadcast protocol
                    // degenerates into a simple broadcast, so we can just skip
                    // the echo broadcast round.
                    *self = DKGSessionState::WaitingForRound2Packages {
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
        if let DKGSessionState::WaitingForRound1PackagesBroadcast {
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
                *self = DKGSessionState::WaitingForRound2Packages {
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
            DKGSessionState::WaitingForRound1PackagesBroadcast { .. }
                | DKGSessionState::WaitingForRound2Packages { .. }
        )
    }

    /// Returns a map linking a participant identifier and the Round 1 Package
    /// they have sent.
    #[allow(clippy::type_complexity)]
    pub fn round1_packages(
        &mut self,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>> {
        match self {
            DKGSessionState::WaitingForRound2Packages {
                round1_packages, ..
            }
            | DKGSessionState::WaitingForRound1PackagesBroadcast {
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
        matches!(self, DKGSessionState::WaitingForRound2Packages { .. })
    }

    /// Returns if all participants sent their Round 2 Packages.
    /// When this returns `true`, [`round2_packages()`] can be called.
    pub fn has_round2_packages(&self) -> bool {
        matches!(self, DKGSessionState::Round2PackagesReady { .. })
    }

    /// Handle signature share sent by a participant.
    fn handle_round2_package(
        &mut self,
        pubkey: PublicKey,
        round2_package: round2::Package<C>,
    ) -> Result<(), Box<dyn Error>> {
        if let DKGSessionState::WaitingForRound2Packages {
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
                *self = DKGSessionState::Round2PackagesReady {
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
        if let DKGSessionState::Round2PackagesReady {
            round2_packages, ..
        } = self
        {
            Ok(round2_packages.clone())
        } else {
            panic!("wrong state");
        }
    }
}
