use core::str;
use std::{
    collections::BTreeMap,
    error::Error,
    path::{Path, PathBuf},
    str::FromStr,
};

use eyre::{eyre, OptionExt};
use serde::{Deserialize, Serialize};

use crate::{ciphersuite_helper::ciphersuite_helper, contact::Contact, write_atomic};

/// The config file, which is serialized with serde.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// The path the config was loaded from.
    #[serde(skip)]
    path: Option<PathBuf>,
    pub version: u8,
    /// The communication key pair for the user.
    pub communication_key: Option<CommunicationKey>,
    /// The address book of the user, keyed by each contact's name.
    #[serde(default)]
    pub contact: BTreeMap<String, Contact>,
    /// The FROST groups the user belongs to, keyed by hex-encoded verifying key
    #[serde(default)]
    pub group: BTreeMap<String, Group>,
}

impl Config {
    pub fn contact_by_pubkey(&self, pubkey: &[u8]) -> Result<Contact, Box<dyn Error>> {
        Ok(self
            .contact
            .values()
            .find(|c| c.pubkey == pubkey)
            .cloned()
            .ok_or_eyre("contact not found")?)
    }
}

/// The communication key pair for the user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommunicationKey {
    /// The private key.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub privkey: Vec<u8>,
    /// The public key.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub pubkey: Vec<u8>,
}

/// A FROST group the user belongs to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// A human-readable description of the group to make it easier to select
    /// groups
    pub description: String,
    /// The ciphersuite being used for the group
    pub ciphersuite: String,
    /// The encoded public key package for the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub public_key_package: Vec<u8>,
    /// The user's encoded key package for the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub key_package: Vec<u8>,
    /// The default server the participants are using, if any.
    pub server_url: Option<String>,
    /// The group participants, keyed by hex-encoded identifier
    pub participant: BTreeMap<String, Participant>,
}

impl Group {
    /// Returns a human-readable summary of the contact; used when it is
    /// printed to the terminal.
    pub fn as_human_readable_summary(&self, config: &Config) -> Result<String, Box<dyn Error>> {
        let helper = ciphersuite_helper(&self.ciphersuite)?;
        let info = helper.group_info(&self.key_package, &self.public_key_package)?;
        let mut s = format!(
            "Group \"{}\"\nPublic key {}\nServer URL: {}\nThreshold: {}\nParticipants: {}\n",
            self.description,
            info.hex_verifying_key,
            self.server_url.clone().unwrap_or_default(),
            info.threshold,
            info.num_participants
        );
        for participant in self.participant.values() {
            let contact = config.contact_by_pubkey(&participant.pubkey)?;
            s += &format!("\t{} ({})\n", contact.name, hex::encode(contact.pubkey));
        }
        Ok(s)
    }
}

/// A FROST group participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    /// The identifier of the participant in the group.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub identifier: Vec<u8>,
    /// The communication public key for the participant.
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub pubkey: Vec<u8>,
}

impl Config {
    /// Returns the default path of the config
    /// ($HOME/.config/frost/credentials.toml in Linux) if `path` is None,
    /// otherwise parse the given path and return it.
    pub fn parse_path(path: Option<String>) -> Result<PathBuf, Box<dyn Error>> {
        if let Some(path) = path {
            Ok(PathBuf::from_str(&path)?)
        } else {
            Ok(dirs::config_local_dir()
                .unwrap()
                .join("frost")
                .join("credentials.toml"))
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Read the config from given path, or the default path if None.
    /// If the path does not exist, it will load a default (empty) config.
    /// Calling `write()` later will write to the specified path.
    pub fn read(path: Option<String>) -> Result<Self, Box<dyn Error>> {
        let path = Self::parse_path(path)?;
        if !path.exists() {
            return Ok(Config {
                path: Some(path),
                ..Default::default()
            });
        }
        let bytes = std::fs::read(&path)?;
        let s = str::from_utf8(&bytes)?;
        let mut config: Config = toml::from_str(s)?;
        config.path = Some(path);
        Ok(config)
    }

    /// Write the config to path it was loaded from.
    pub fn write(&self) -> Result<(), Box<dyn Error>> {
        let s = toml::to_string_pretty(self)?;
        let bytes = s.as_bytes();
        Ok(write_atomic::write_file(
            self.path
                .clone()
                .ok_or_else(|| eyre!("path not specified"))?,
            bytes,
        )?)
    }
}
