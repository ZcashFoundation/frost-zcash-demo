use std::error::Error;

use eyre::{eyre, OptionExt};
use serde::{Deserialize, Serialize};

use crate::{args::Command, config::Config};

/// A FROST contact, which critically has the public key required to
/// send and receive encrypted and authenticated messages to them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contact {
    /// Format version. Only 0 supported for now. It is an Option since
    /// we don't want the version when writing it to the config file.
    pub version: Option<u8>,
    /// Name of the contact.
    pub name: String,
    /// Public key of the contact.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub pubkey: Vec<u8>,
}

impl Contact {
    /// Returns a human-readable summary of the contact; used when it is
    /// printed to the terminal.
    pub fn as_human_readable_summary(&self) -> String {
        format!(
            "Name: {}\nPublic Key: {}\n",
            self.name,
            hex::encode(&self.pubkey)
        )
    }

    /// Returns the contact encoded as a text string, with Bech32.
    pub fn as_text(&self) -> Result<String, Box<dyn Error>> {
        let bytes = postcard::to_allocvec(self)?;
        let hrp = bech32::Hrp::parse("zffrost").expect("valid hrp");
        Ok(bech32::encode::<bech32::Bech32m>(hrp, &bytes)?)
    }

    /// Creates a Contact from the given encoded text string.
    pub fn from_text(s: &str) -> Result<Self, Box<dyn Error>> {
        let (hrp, bytes) = bech32::decode(s)?;
        if hrp.as_str() != "zffrost" {
            return Err(eyre!("invalid contact format").into());
        }
        let contact: Contact = postcard::from_bytes(&bytes)?;
        if contact.version != Some(0) {
            return Err(eyre!("invalid contact version").into());
        }
        Ok(contact)
    }
}

/// Import a contact into the user's address book, in the config file.
pub(crate) fn import(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Import {
        contact: text_contact,
        config,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let mut config = Config::read(config)?;

    let mut contact = Contact::from_text(&text_contact)?;
    if config.contact.contains_key(&contact.name) {
        return Err(eyre!(
            "contact with name {} already exists. Either remove the existing \
            one, or ask the sender to change their display name when exporting",
            &contact.name
        )
        .into());
    }
    if config.contact.values().any(|c| c.pubkey == contact.pubkey) {
        return Err(eyre!(
            "pubkey {} already registered for {}",
            hex::encode(&contact.pubkey),
            &contact.name,
        )
        .into());
    }
    if config.communication_key.as_ref().map(|c| &c.pubkey) == Some(&contact.pubkey) {
        return Err(eyre!(
            "pubkey {} already registered for yourself",
            hex::encode(&contact.pubkey)
        )
        .into());
    }
    // We don't want the version when writing to the config file.
    contact.version = None;
    config.contact.insert(contact.name.clone(), contact.clone());

    eprintln!("Imported this contact:");
    eprint!("{}", contact.as_human_readable_summary());

    config.write()?;

    Ok(())
}

/// Export a contact from the user's address book in the config file.
pub(crate) fn export(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Export { name, config } = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    // Build the contact to export.
    let contact = Contact {
        version: Some(0),
        name,
        pubkey: config
            .communication_key
            .ok_or(eyre!("pubkey not generated yet"))?
            .pubkey,
    };

    eprintln!("Exporting this information:");
    eprint!("{}", contact.as_human_readable_summary());
    eprintln!(
        "Check if contains the expected information. If it does, copy the following \
        contact string and send to other participants you want to use FROST with:"
    );
    eprintln!("{}", contact.as_text()?);

    Ok(())
}

/// List the contacts in the address book in the config file.
pub(crate) fn list(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Contacts { config } = (*args).clone() else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    for contact in config.contact.values() {
        eprint!("{}", contact.as_human_readable_summary());
        eprintln!("{}", contact.as_text()?);
        eprintln!();
    }

    Ok(())
}

/// Remove a contact from the user's address book in the config file.
pub(crate) fn remove(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::RemoveContact { config, pubkey } = (*args).clone() else {
        panic!("invalid Command");
    };

    let mut config = Config::read(config)?;

    let name = config
        .contact
        .iter()
        .find_map(|(name, c)| {
            if hex::encode(c.pubkey.clone()) == pubkey {
                Some(name.clone())
            } else {
                None
            }
        })
        .clone()
        .ok_or_eyre("contact not found")?;

    config.contact.remove(&name);

    config.write()?;

    Ok(())
}
