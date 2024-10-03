use std::error::Error;
use std::rc::Rc;

use coordinator::cli::cli_for_processed_args;
use eyre::eyre;
use eyre::Context;
use eyre::OptionExt;

use frost_core::keys::PublicKeyPackage;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use frost_rerandomized::RandomizedCiphersuite;
use reddsa::frost::redpallas::PallasBlake2b512;
use reqwest::Url;

use crate::{args::Command, config::Config};

pub(crate) async fn run(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator { config, group, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    if group.ciphersuite == Ed25519Sha512::ID {
        run_for_ciphersuite::<Ed25519Sha512>(args).await
    } else if group.ciphersuite == PallasBlake2b512::ID {
        run_for_ciphersuite::<PallasBlake2b512>(args).await
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) async fn run_for_ciphersuite<C: RandomizedCiphersuite + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::Coordinator {
        config,
        server_url,
        group,
        signers,
        message,
        randomizer,
        signature,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let group = config.group.get(&group).ok_or_eyre("Group not found")?;

    let public_key_package: PublicKeyPackage<C> = postcard::from_bytes(&group.public_key_package)?;

    let mut input = Box::new(std::io::stdin().lock());
    let mut output = std::io::stdout();

    let server_url =
        server_url.unwrap_or(group.server_url.clone().ok_or_eyre("server-url required")?);
    let server_url_parsed =
        Url::parse(&format!("http://{}", server_url)).wrap_err("error parsing server-url")?;

    let registry = config
        .registry
        .get(&server_url)
        .ok_or_eyre("Not registered in the given server")?;

    let group_participants = group.participant.clone();
    let pargs = coordinator::args::ProcessedArgs {
        cli: false,
        http: true,
        username: registry.username.clone(),
        password: String::new(),
        signers: signers.clone(),
        num_signers: signers.len() as u16,
        public_key_package,
        messages: coordinator::args::read_messages(&message, &mut output, &mut input)?,
        randomizers: coordinator::args::read_randomizers(&randomizer, &mut output, &mut input)?,
        signature,
        ip: server_url_parsed
            .host_str()
            .ok_or_eyre("host missing in URL")?
            .to_owned(),
        port: server_url_parsed.port().unwrap_or(2744),
        authentication_token: Some(
            registry
                .token
                .clone()
                .ok_or_eyre("Not logged in in the given server")?,
        ),
        comm_privkey: Some(
            config
                .communication_key
                .ok_or_eyre("user not initialized")?
                .privkey
                .clone(),
        ),
        comm_participant_pubkey_getter: Some(Rc::new(move |participant_username| {
            group_participants
                .values()
                .find(|p| p.username == Some(participant_username.to_string()))
                .map(|p| p.pubkey.clone())
        })),
    };

    cli_for_processed_args(pargs, &mut input, &mut output).await?;

    Ok(())
}
