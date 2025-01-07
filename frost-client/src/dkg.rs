use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    sync::Arc,
};

use eyre::{eyre, Context as _, OptionExt};

use dkg::cli::MaybeIntoEvenY;
use frost_core::Ciphersuite;
use frost_ed25519::Ed25519Sha512;
use reqwest::Url;
use tokio::io::BufReader;

use crate::{
    args::Command,
    config::{Config, Group, Participant},
};

pub(crate) async fn dkg(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Dkg { ciphersuite, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    if ciphersuite == "ed25519" {
        dkg_for_ciphersuite::<Ed25519Sha512>(args).await
    } else if ciphersuite == "redpallas" {
        dkg_for_ciphersuite::<reddsa::frost::redpallas::PallasBlake2b512>(args).await
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) async fn dkg_for_ciphersuite<C: Ciphersuite + MaybeIntoEvenY + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::Dkg {
        config: config_path,
        description,
        server_url,
        ciphersuite: _,
        threshold,
        participants,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();

    let config = Config::read(config_path.clone())?;

    let server_url_parsed =
        Url::parse(&format!("https://{}", server_url)).wrap_err("error parsing server-url")?;

    let comm_pubkey = config
        .communication_key
        .clone()
        .ok_or_eyre("user not initialized")?
        .pubkey;

    let mut participants = participants
        .iter()
        .map(|s| Ok(hex::decode(s)?.to_vec()))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    // Add ourselves if not already in the list
    if !participants.is_empty() && !participants.contains(&comm_pubkey) {
        participants.push(comm_pubkey.clone());
    }

    let dkg_config = dkg::args::ProcessedArgs {
        cli: false,
        http: true,
        ip: server_url_parsed
            .host_str()
            .ok_or_eyre("host missing in URL")?
            .to_owned(),
        port: server_url_parsed.port().unwrap_or(2744),
        comm_privkey: Some(
            config
                .communication_key
                .clone()
                .ok_or_eyre("user not initialized")?
                .privkey,
        ),
        comm_pubkey: Some(comm_pubkey),
        comm_participant_pubkey_getter: Some(Arc::new(move |participant_pubkey| {
            config
                .contact_by_pubkey(participant_pubkey)
                .map(|p| p.pubkey.clone())
                .ok()
        })),
        min_signers: threshold,
        max_signers: None,
        participants,
        identifier: None,
    };

    // Generate key shares
    let (key_package, public_key_package, pubkey_map) =
        dkg::cli::cli_for_processed_args::<C>(dkg_config, &mut input, &mut output).await?;

    // Reverse pubkey_map
    let pubkey_map = pubkey_map
        .into_iter()
        .map(|(k, v)| (v, k))
        .collect::<HashMap<_, _>>();

    // Create participants map
    let mut participants = BTreeMap::new();
    for identifier in public_key_package.verifying_shares().keys() {
        let pubkey = pubkey_map.get(identifier).ok_or_eyre("missing pubkey")?;
        let participant = Participant {
            identifier: identifier.serialize(),
            pubkey: pubkey.clone(),
        };
        participants.insert(hex::encode(identifier.serialize()), participant);
    }

    let group = Group {
        ciphersuite: C::ID.to_string(),
        description: description.clone(),
        key_package: postcard::to_allocvec(&key_package)?,
        public_key_package: postcard::to_allocvec(&public_key_package)?,
        participant: participants.clone(),
        server_url: Some(server_url.clone()),
    };
    // Re-read the config because the old instance is tied to the
    // `comm_participant_pubkey_getter` callback.
    // TODO: is this an issue?
    let mut config = Config::read(config_path)?;
    config.group.insert(
        hex::encode(public_key_package.verifying_key().serialize()?),
        group,
    );
    config.write()?;

    Ok(())
}
