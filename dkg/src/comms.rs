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
};

use tokio::io::{AsyncBufRead as BufRead, AsyncWrite as Write};

use async_trait::async_trait;

use frost::Identifier;

#[async_trait]
pub trait Comms<C: Ciphersuite>: Send {
    async fn get_identifier(
        &mut self,
        input: &mut (dyn BufRead + Send + Sync + Unpin),
        output: &mut (dyn Write + Send + Sync + Unpin),
    ) -> Result<(Identifier<C>, u16), Box<dyn Error>>;

    async fn get_round1_packages(
        &mut self,
        input: &mut (dyn BufRead + Send + Sync + Unpin),
        output: &mut (dyn Write + Send + Sync + Unpin),
        round1_package: round1::Package<C>,
    ) -> Result<BTreeMap<Identifier<C>, round1::Package<C>>, Box<dyn Error>>;

    async fn get_round2_packages(
        &mut self,
        input: &mut (dyn BufRead + Send + Sync + Unpin),
        output: &mut (dyn Write + Send + Sync + Unpin),
        round2_packages: BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> Result<BTreeMap<Identifier<C>, round2::Package<C>>, Box<dyn Error>>;

    fn get_pubkey_identifier_map(&self) -> Result<HashMap<Vec<u8>, Identifier<C>>, Box<dyn Error>>;
}
