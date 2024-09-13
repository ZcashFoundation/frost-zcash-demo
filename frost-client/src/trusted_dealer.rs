use eyre::{eyre, OptionExt};
use std::{collections::BTreeMap, error::Error};

use frost_core::{keys::KeyPackage, Ciphersuite};
use frost_ed25519::Ed25519Sha512;
use rand::thread_rng;
use trusted_dealer::MaybeIntoEvenY;

use crate::{
    args::Command,
    config::{Config, Group, Participant},
};

pub(crate) fn trusted_dealer(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::TrustedDealer { ciphersuite, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    if ciphersuite == "ed25519" {
        trusted_dealer_for_ciphersuite::<Ed25519Sha512>(args)
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) fn trusted_dealer_for_ciphersuite<C: Ciphersuite + MaybeIntoEvenY + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::TrustedDealer {
        config,
        ciphersuite: _,
        threshold,
        num_signers,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    if config.len() != num_signers as usize {
        return Err(
            eyre!("The `config` option must specify `num_signers` different config files").into(),
        );
    }

    let trusted_dealer_config = trusted_dealer::Config {
        max_signers: num_signers,
        min_signers: threshold,
        secret: vec![],
    };
    let mut rng = thread_rng();

    // Generate key shares
    let (shares, public_key_package) =
        trusted_dealer::trusted_dealer::<C, _>(&trusted_dealer_config, &mut rng)?;

    // First pass over configs; create participants map
    let mut participants = BTreeMap::new();
    for (identifier, path) in shares.keys().zip(config.iter()) {
        let config = Config::read(Some(path.to_string()))?;
        let pubkey = config
            .communication_key
            .ok_or_eyre("config not initialized")?
            .pubkey;
        let participant = Participant {
            identifier: identifier.serialize(),
            pubkey,
            server_url: None,
            username: None,
        };
        participants.insert(hex::encode(identifier.serialize()), participant);
    }

    // Second pass over configs; write group information
    for (share, path) in shares.values().zip(config.iter()) {
        let mut config = Config::read(Some(path.to_string()))?;
        let key_package: KeyPackage<C> = share.clone().try_into()?;
        let group = Group {
            key_package: postcard::to_allocvec(&key_package)?,
            public_key_package: postcard::to_allocvec(&public_key_package)?,
            participant: participants.clone(),
        };
        config.group.insert(
            hex::encode(public_key_package.verifying_key().serialize()?),
            group,
        );
        config.write()?;
    }

    Ok(())
}
