use std::error::Error;

use crate::{
    args::Command,
    config::{CommunicationKey, Config},
};

pub(crate) async fn init(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Init { config } = (*args).clone() else {
        panic!("invalid Command");
    };

    let mut config = Config::read(config)?;

    if config.communication_key.is_some() {
        eprintln!("Skipping keypair generation; keypair already generated and stored");
    } else {
        eprintln!("Generating keypair... ");
        let builder = snow::Builder::new("Noise_K_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let keypair = builder.generate_keypair().unwrap();
        config.communication_key = Some(CommunicationKey {
            privkey: keypair.private.clone(),
            pubkey: keypair.public.clone(),
        });
    };

    eprintln!(
        "Writing to config file at {}...",
        config.path().expect("should not be None").display()
    );
    config.write()?;
    eprintln!("Done.");

    Ok(())
}
