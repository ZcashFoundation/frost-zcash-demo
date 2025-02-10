pub mod cli;
pub mod http;

use frost_core::{
    self as frost,
    keys::dkg::{round1, round2},
    Ciphersuite,
};

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    io::{BufRead, Write},
};

use async_trait::async_trait;

use frost::Identifier;

#[async_trait(?Send)]
pub trait Comms<C: Ciphersuite> {
    /// Return this participant's identifier (in case it's derived from other
    /// information) and the number of participants in the signing session.
    async fn get_identifier_and_max_signers(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>>;

    /// Send the Round 1 package to other participants (using echo broadcast),
    /// and receive their Round 1 packages.
    async fn get_round1_packages(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>>;

    /// Send the Round 2 packages to other participants, and receive their Round
    /// 2 packages.
    async fn get_round2_packages(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>>;

    /// Return the map of public keys to identifiers for all participants.
    fn get_pubkey_identifier_map(&self) -> Result<HashMap<Vec<u8>, Identifier<C>>, Box<dyn Error>>;
}
