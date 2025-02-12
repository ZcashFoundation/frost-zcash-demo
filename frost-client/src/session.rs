use std::error::Error;

use eyre::{eyre, OptionExt as _};
use rand::thread_rng;
use xeddsa::{xed25519, Sign as _};

use crate::{args::Command, config::Config};

pub(crate) async fn list(args: &Command) -> Result<(), Box<dyn Error>> {
    let Command::Sessions {
        config,
        group,
        server_url,
        close_all,
    } = (*args).clone()
    else {
        panic!("invalid Command");
    };

    let config = Config::read(config)?;

    let server_url = if let Some(server_url) = server_url {
        server_url
    } else if let Some(group) = group {
        let group = config.group.get(&group).ok_or_eyre("Group not found")?;
        group
            .server_url
            .clone()
            .ok_or_eyre("the group specified does not have an associated server URL")?
    } else {
        return Err(eyre!("must specify either server_url or group").into());
    };

    let comm_privkey = config
        .communication_key
        .clone()
        .ok_or_eyre("user not initialized")?
        .privkey
        .clone();
    let comm_pubkey = config
        .communication_key
        .clone()
        .ok_or_eyre("user not initialized")?
        .pubkey
        .clone();

    let client = reqwest::Client::new();
    let host_port = format!("https://{}", server_url);

    let mut rng = thread_rng();

    let challenge = client
        .post(format!("{}/challenge", host_port))
        .json(&frostd::ChallengeArgs {})
        .send()
        .await?
        .json::<frostd::ChallengeOutput>()
        .await?
        .challenge;

    let privkey = xed25519::PrivateKey::from(
        &TryInto::<[u8; 32]>::try_into(comm_privkey.clone())
            .map_err(|_| eyre!("invalid comm_privkey"))?,
    );
    let signature: [u8; 64] = privkey.sign(challenge.as_bytes(), &mut rng);

    let access_token = client
        .post(format!("{}/login", host_port))
        .json(&frostd::KeyLoginArgs {
            challenge,
            pubkey: comm_pubkey.clone(),
            signature: signature.to_vec(),
        })
        .send()
        .await?
        .json::<frostd::LoginOutput>()
        .await?
        .access_token
        .to_string();

    // Get session ID from server
    let r = client
        .post(format!("{}/list_sessions", host_port))
        .bearer_auth(&access_token)
        .send()
        .await?
        .json::<frostd::ListSessionsOutput>()
        .await?;

    if r.session_ids.is_empty() {
        eprintln!("No active sessions.");
    } else {
        for session_id in r.session_ids {
            let r = client
                .post(format!("{}/get_session_info", host_port))
                .bearer_auth(&access_token)
                .json(&frostd::GetSessionInfoArgs { session_id })
                .send()
                .await?
                .json::<frostd::GetSessionInfoOutput>()
                .await?;
            let coordinator = config.contact_by_pubkey(&r.coordinator_pubkey);
            let participants: Vec<_> = r
                .pubkeys
                .iter()
                .map(|pubkey| config.contact_by_pubkey(&pubkey.0))
                .collect();
            eprintln!("Session with ID {}", session_id);
            eprintln!(
                "Coordinator: {}",
                coordinator
                    .map(|c| c.name)
                    .unwrap_or("(Unknown contact)".to_string())
            );
            eprintln!("Signers: {}", participants.len());
            for participant in participants {
                if let Ok(participant) = participant {
                    eprintln!(
                        "\t{}\t({})",
                        participant.name,
                        hex::encode(participant.pubkey)
                    );
                } else {
                    eprintln!("\t(Unknown contact)");
                }
            }
            eprintln!();

            if close_all {
                let _r = client
                    .post(format!("{}/close_session", host_port))
                    .bearer_auth(&access_token)
                    .json(&frostd::CloseSessionArgs { session_id })
                    .send()
                    .await?
                    .bytes()
                    .await?;
            }
        }
    }

    Ok(())
}
