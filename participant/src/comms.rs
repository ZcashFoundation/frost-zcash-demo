pub mod cli;
pub mod socket;

#[cfg(not(feature = "redpallas"))]
use frost_ed25519 as frost;
#[cfg(feature = "redpallas")]
use reddsa::frost::redpallas as frost;

use frost::SigningPackage;

use std::{
    error::Error,
    io::{BufRead, Write},
};

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    SigningPackage(SigningPackage),
}

#[allow(async_fn_in_trait)]
pub trait Comms {
    async fn get_signing_package(
        &mut self,
        input: &mut dyn BufRead,
        output: &mut dyn Write,
        #[cfg(feature = "redpallas")] randomizer: frost::round2::Randomizer,
    ) -> Result<SigningPackage, Box<dyn Error>>;
}
