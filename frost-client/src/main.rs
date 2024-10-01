pub mod args;
pub mod ciphersuite_helper;
pub mod config;
pub mod contact;
pub mod coordinator;
pub mod group;
pub mod init;
pub mod login;
pub mod participant;
pub mod trusted_dealer;
pub mod write_atomic;

use std::error::Error;

use args::{Args, Command};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    stable_eyre::install()?;
    let args = Args::parse();

    match args.command {
        Command::Init { .. } => init::init(&args.command).await,
        Command::Login { .. } => login::login(&args.command).await,
        Command::Export { .. } => contact::export(&args.command),
        Command::Import { .. } => contact::import(&args.command),
        Command::Contacts { .. } => contact::list(&args.command),
        Command::Groups { .. } => group::list(&args.command),
        Command::TrustedDealer { .. } => trusted_dealer::trusted_dealer(&args.command),
        Command::Coordinator { .. } => crate::coordinator::run(&args.command).await,
        Command::Participant { .. } => crate::participant::run(&args.command).await,
    }?;

    Ok(())
}
