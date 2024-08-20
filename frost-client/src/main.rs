pub mod args;
pub mod config;
pub mod contact;
pub mod init;
pub mod login;

use std::error::Error;

use args::{Args, Command};
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    match args.command {
        Command::Init { .. } => init::init(&args.command).await,
        Command::Login { .. } => login::login(&args.command).await,
        Command::Export { .. } => contact::export(&args.command),
        Command::Import { .. } => contact::import(&args.command),
        Command::Contacts { .. } => contact::list(&args.command),
    }?;

    Ok(())
}
