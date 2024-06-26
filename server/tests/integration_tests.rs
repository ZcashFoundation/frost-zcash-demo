use std::{collections::BTreeMap, time::Duration};

use axum_test::TestServer;
use rand::thread_rng;
use server::{args::Args, router, SerializedSignatureShare, SerializedSigningPackage};

use frost_core as frost;

#[tokio::test]
async fn test_main_router_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    test_main_router::<frost_ed25519::Ed25519Sha512>(false).await
}

#[tokio::test]
async fn test_main_router_redpallas() -> Result<(), Box<dyn std::error::Error>> {
    test_main_router::<reddsa::frost::redpallas::PallasBlake2b512>(true).await
}

/// Test the entire FROST signing flow using axum_test.
/// This is a good example of the overall flow but it's not a good example
/// of the client code, see the next test for that.
///
/// Also note that this simulates multiple clients using loops. In practice,
/// each client will run independently.
async fn test_main_router<
    C: frost_core::Ciphersuite + frost_rerandomized::RandomizedCiphersuite + 'static,
>(
    rerandomized: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create key shares
    let mut rng = thread_rng();
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::<C>::Default,
        &mut rng,
    )
    .unwrap();
    let key_packages: BTreeMap<_, _> = shares
        .iter()
        .map(|(identifier, secret_share)| {
            (
                *identifier,
                frost::keys::KeyPackage::try_from(secret_share.clone()).unwrap(),
            )
        })
        .collect();

    // Instantiate test server using axum_test
    let router = router();
    let server = TestServer::new(router)?;

    // As the coordinator, create a new signing session with all participants,
    // for 2 messages
    let res = server
        .post("/create_new_session")
        .json(&server::CreateNewSessionArgs {
            num_signers: 2,
            message_count: 2,
        })
        .await;
    res.assert_status_ok();
    let r: server::CreateNewSessionOutput = res.json();
    let session_id = r.session_id;

    // Generate commitments (one SigningCommitments for each message)
    // and send them to the server; for each participant

    // Map to store the SigningNonces (for each message, for each participant)
    let mut nonces_map = BTreeMap::<_, _>::new();
    for (identifier, key_package) in key_packages.iter().take(2) {
        // As participant `identifier`

        // Get the number of messages (the participants wouldn't know without
        // asking the server).
        let res = server
            .post("/get_session_info")
            .json(&server::GetSessionInfoArgs { session_id })
            .await;
        res.assert_status_ok();
        let r: server::GetSessionInfoOutput = res.json();

        // Generate SigningCommitments and SigningNonces for each message
        let mut nonces_vec = Vec::new();
        let mut commitments_vec = Vec::new();
        for _ in 0..r.message_count {
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            nonces_vec.push(nonces);
            commitments_vec.push((&commitments).try_into()?);
        }

        // Store nonces for later use
        nonces_map.insert(*identifier, nonces_vec);

        // Send commitments to server
        let res = server
            .post("/send_commitments")
            .json(&server::SendCommitmentsArgs {
                identifier: (*identifier).into(),
                session_id,
                commitments: commitments_vec,
            })
            .await;
        if res.status_code() != 200 {
            panic!("status code: {}; error: {}", res.status_code(), res.text());
        }
    }

    // As the coordinator, get the commitments
    let res = server
        .post("/get_commitments")
        .json(&server::GetCommitmentsArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetCommitmentsOutput = res.json();
    // Deserialize commitments in the response
    let commitments = r
        .commitments
        .iter()
        .map(|m| {
            m.iter()
                .map(|(i, c)| Ok((i.try_into()?, c.try_into()?)))
                .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // As the coordinator, choose messages and create one SigningPackage
    // and one RandomizedParams for each.
    let message1 = "Hello, world!".as_bytes();
    let message2 = "Ola mundo!".as_bytes();
    let aux_msg = "Aux msg".as_bytes();
    let messages = [message1, message2];
    let signing_packages = messages
        .iter()
        .enumerate()
        .map(|(i, msg)| frost::SigningPackage::new(commitments[i].clone(), msg))
        .collect::<Vec<_>>();

    // Will not be used if rerandomized == false but we generate anyway for simplicity
    let randomized_params = signing_packages
        .iter()
        .map(|p| frost_rerandomized::RandomizedParams::new(pubkeys.verifying_key(), p, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;

    // As the coordinator, send the SigningPackages to the server
    let res = server
        .post("/send_signing_package")
        .json(&server::SendSigningPackageArgs {
            session_id,
            signing_package: signing_packages
                .iter()
                .map(std::convert::TryInto::<SerializedSigningPackage>::try_into)
                .collect::<Result<_, _>>()?,
            randomizer: if rerandomized {
                randomized_params
                    .iter()
                    .map(|p| (*p.randomizer()).into())
                    .collect()
            } else {
                Vec::new()
            },
            aux_msg: aux_msg.to_owned(),
        })
        .await;
    res.assert_status_ok();

    // As each participant, get SigningPackages and generate the SignatureShares
    // for each.
    for (identifier, key_package) in key_packages.iter().take(2) {
        // As participant `identifier`

        // Get SigningPackages
        let res = server
            .post("get_signing_package")
            .json(&server::GetSigningPackageArgs { session_id })
            .await;
        res.assert_status_ok();
        let r: server::GetSigningPackageOutput = res.json();

        // Generate SignatureShares for each SigningPackage
        let signature_share = if rerandomized {
            r.signing_package
                .iter()
                .zip(r.randomizer.iter())
                .enumerate()
                .map(|(i, (signing_package, randomizer))| {
                    frost_rerandomized::sign(
                        &signing_package.try_into()?,
                        &nonces_map[identifier][i],
                        key_package,
                        randomizer.try_into()?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            r.signing_package
                .iter()
                .enumerate()
                .map(|(i, signing_package)| {
                    frost::round2::sign(
                        &signing_package.try_into()?,
                        &nonces_map[identifier][i],
                        key_package,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        // Send SignatureShares to the server
        let res = server
            .post("/send_signature_share")
            .json(&server::SendSignatureShareArgs {
                identifier: (*identifier).into(),
                session_id,
                signature_share: signature_share
                    .iter()
                    .map(|s| std::convert::Into::<SerializedSignatureShare>::into(*s))
                    .collect(),
            })
            .await;
        res.assert_status_ok();
    }

    // As the coordinator, get SignatureShares
    let res = server
        .post("/get_signature_shares")
        .json(&server::GetSignatureSharesArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetSignatureSharesOutput = res.json();

    let signature_shares = r
        .signature_shares
        .iter()
        .map(|m| {
            m.iter()
                .map(|(i, s)| Ok((i.try_into()?, s.try_into()?)))
                .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Generate the final Signature for each message
    let signatures = if rerandomized {
        signing_packages
            .iter()
            .enumerate()
            .map(|(i, p)| {
                frost_rerandomized::aggregate(
                    p,
                    &signature_shares[i],
                    &pubkeys,
                    &randomized_params[i],
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        signing_packages
            .iter()
            .enumerate()
            .map(|(i, p)| frost::aggregate(p, &signature_shares[i], &pubkeys))
            .collect::<Result<Vec<_>, _>>()?
    };

    // Close the session
    let res = server
        .post("/close_session")
        .json(&server::CloseSessionArgs { session_id })
        .await;
    res.assert_status_ok();

    // Verify signatures to test if they were generated correctly
    if rerandomized {
        for (i, p) in randomized_params.iter().enumerate() {
            p.randomized_verifying_key()
                .verify(messages[i], &signatures[i])?;
        }
    } else {
        for (i, m) in messages.iter().enumerate() {
            pubkeys.verifying_key().verify(m, &signatures[i])?;
        }
    }

    Ok(())
}

/// Actually spawn the HTTP server and connect to it using reqwest.
/// A better example on how to write client code.
#[tokio::test]
async fn test_http() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn server for testing
    tokio::spawn(async move {
        server::run(&Args {
            ip: "127.0.0.1".to_string(),
            port: 2744,
        })
        .await
        .unwrap();
    });

    // Wait for server to start listening
    // TODO: this could possibly be not enough, use some retry logic instead
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Call create_new_session
    let client = reqwest::Client::new();
    let r = client
        .post("http://127.0.0.1:2744/create_new_session")
        .json(&server::CreateNewSessionArgs {
            num_signers: 2,
            message_count: 1,
        })
        .send()
        .await?
        .json::<server::CreateNewSessionOutput>()
        .await?;
    println!("{}", r.session_id);

    Ok(())
}
