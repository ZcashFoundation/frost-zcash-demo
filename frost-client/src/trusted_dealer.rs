use std::{collections::BTreeMap, error::Error};

use eyre::{eyre, OptionExt};
use itertools::izip;
use rand::thread_rng;

use frost_core::{keys::KeyPackage, Ciphersuite};
use frost_ed25519::Ed25519Sha512;
use trusted_dealer::MaybeIntoEvenY;

use crate::{
    args::Command,
    config::{Config, Group, Participant},
    contact::Contact,
};

pub(crate) fn trusted_dealer(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::TrustedDealer { ciphersuite, .. } = (*args).clone() else {
        panic!("invalid Command");
    };

    if ciphersuite == "ed25519" {
        trusted_dealer_for_ciphersuite::<Ed25519Sha512>(args)
    } else if ciphersuite == "redpallas" {
        trusted_dealer_for_ciphersuite::<reddsa::frost::redpallas::PallasBlake2b512>(args)
    } else {
        Err(eyre!("unsupported ciphersuite").into())
    }
}

pub(crate) fn trusted_dealer_for_ciphersuite<C: Ciphersuite + MaybeIntoEvenY + 'static>(
    args: &Command,
) -> Result<(), Box<dyn Error>> {
    let Command::TrustedDealer {
        config,
        description,
        ciphersuite: _,
        threshold,
        num_signers,
        names,
        server_url,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    if config.len() != num_signers as usize {
        return Err(
            eyre!("The `config` option must specify `num_signers` different config files").into(),
        );
    }
    if names.len() != num_signers as usize {
        return Err(eyre!("The `names` option must specify `num_signers` names").into());
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
    let mut contacts = Vec::new();
    for (identifier, path, name) in izip!(shares.keys(), config.iter(), names.iter()) {
        let config = Config::read(Some(path.to_string()))?;
        let pubkey = config
            .communication_key
            .ok_or_eyre("config not initialized")?
            .pubkey;
        let participant = Participant {
            identifier: identifier.serialize(),
            pubkey: pubkey.clone(),
        };
        participants.insert(hex::encode(identifier.serialize()), participant);
        let contact = Contact {
            version: None,
            name: name.clone(),
            pubkey,
        };
        contacts.push(contact);
    }

    // Second pass over configs; write group information
    for (share, path) in shares.values().zip(config.iter()) {
        let mut config = Config::read(Some(path.to_string()))?;
        // IMPORTANT: the TrustedDealer command is intended for tests only, see
        // comment in [`Command::TrustedDealer`]. If you're using this code as a
        // reference, note that participants should not convert a SecretShare
        // into a KeyPackage without first checking if
        // [`SecretShare::commitment()`] is the same for all participants using
        // a broadcast channel.
        let key_package: KeyPackage<C> = share.clone().try_into()?;
        let group = Group {
            ciphersuite: C::ID.to_string(),
            description: description.clone(),
            key_package: postcard::to_allocvec(&key_package)?,
            public_key_package: postcard::to_allocvec(&public_key_package)?,
            participant: participants.clone(),
            server_url: server_url.clone(),
        };
        config.group.insert(
            hex::encode(public_key_package.verifying_key().serialize()?),
            group,
        );
        for c in &contacts {
            config.contact.insert(c.name.clone(), c.clone());
        }
        config.write()?;
    }

    Ok(())
}
