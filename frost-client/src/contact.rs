use std::error::Error;

use eyre::eyre;
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
    /// The URL of the server where the contact is registered, if any.
    pub server_url: Option<String>,
    /// The username of the contact on `server_url`, if registered.
    pub username: Option<String>,
}

impl Contact {
    /// Returns a human-readable summary of the contact; used when it is
    /// printed to the terminal.
    pub fn as_human_readable_summary(&self) -> String {
        let mut s = format!(
            "Name: {}\nPublic Key: {}\n",
            self.name,
            hex::encode(&self.pubkey)
        );
        if let Some(server_url) = &self.server_url {
            s += format!("Server URL: {}\n", server_url).as_str();
        }
        if let Some(username) = &self.username {
            s += format!("Username: {}\n", username).as_str();
        }
        s
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
    let Command::Export {
        name,
        server_url,
        config,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    // Get the server_url to export depending on whether the user has registered
    // in a server, or if they are registered in multiple servers.
    let server_url = if config.registry.is_empty() && server_url.is_some() {
        return Err(eyre!("User has not been registered yet").into());
    } else if config.registry.is_empty() {
        None
    } else if config.registry.len() > 1 {
        let Some(server_url) = &server_url else {
            return Err(eyre!(
                "More than one registry found. Specify which one with the server_url argument"
            )
            .into());
        };
        // There are multiple server registrations. Try to match one using
        // `server_url` with a simple substring test.
        let matches: Vec<_> = config
            .registry
            .keys()
            .filter(|k| k.contains(server_url))
            .collect();
        if matches.is_empty() {
            return Err(eyre!("server_url not found").into());
        } else if matches.len() > 1 {
            return Err(eyre!(
                "Multiple registries matches the server_url argument; make it more specific"
            )
            .into());
        }
        Some(matches[0].clone())
    } else {
        Some(
            config
                .registry
                .first_key_value()
                .expect("should have an entry")
                .0
                .clone(),
        )
    };

    // Build the contact to export.
    let contact = Contact {
        version: Some(0),
        name,
        pubkey: config
            .communication_key
            .ok_or(eyre!("pubkey not generated yet"))?
            .pubkey,
        server_url: server_url.clone(),
        username: server_url.map(|s| config.registry[&s].username.clone()),
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
