use std::{collections::BTreeMap, time::Duration};

use axum_test::TestServer;
use rand::thread_rng;
use server::{args::Args, router};

use reddsa::frost::redpallas as frost;

/// Test the entire FROST signing flow using axum_test.
/// This is a good example of the overall flow but it's not a good example
/// of the client code, see the next test for that.
///
/// Also note that this simulates multiple clients using loops. In practice,
/// each client will run independently.
#[tokio::test]
async fn test_main_router() -> Result<(), Box<dyn std::error::Error>> {
    // Create key shares
    let mut rng = thread_rng();
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
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
            identifiers: key_packages.keys().copied().collect::<Vec<_>>(),
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
    for (identifier, key_package) in key_packages.iter() {
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
            commitments_vec.push(commitments);
        }

        // Store nonces for later use
        nonces_map.insert(*identifier, nonces_vec);

        // Send commitments to server
        let res = server
            .post("/send_commitments")
            .json(&server::SendCommitmentsArgs {
                identifier: *identifier,
                session_id,
                commitments: commitments_vec,
            })
            .await;
        res.assert_status_ok();
    }

    // As the coordinator, get the commitments
    let res = server
        .post("/get_commitments")
        .json(&server::GetCommitmentsArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetCommitmentsOutput = res.json();
    let commitments = r.commitments;

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
    let randomized_params = signing_packages
        .iter()
        .map(|p| frost::RandomizedParams::new(pubkeys.verifying_key(), p, &mut rng))
        .collect::<Result<Vec<_>, _>>()?;

    // As the coordinator, send the SigningPackages to the server
    let res = server
        .post("/send_signing_package")
        .json(&server::SendSigningPackageArgs {
            session_id,
            signing_package: signing_packages.clone(),
            randomizer: randomized_params.iter().map(|p| *p.randomizer()).collect(),
            aux_msg: aux_msg.to_owned(),
        })
        .await;
    res.assert_status_ok();

    // As each participant, get SigningPackages and generate the SignatureShares
    // for each.
    for (identifier, key_package) in key_packages.iter() {
        // As participant `identifier`

        // Get SigningPackages
        let res = server
            .post("get_signing_package")
            .json(&server::GetSigningPackageArgs { session_id })
            .await;
        res.assert_status_ok();
        let r: server::GetSigningPackageOutput = res.json();

        // Generate SignatureShares for each SigningPackage
        let signature_share = r
            .signing_package
            .iter()
            .zip(r.randomizer.iter())
            .enumerate()
            .map(|(i, (signing_package, randomizer))| {
                frost::round2::sign(
                    signing_package,
                    &nonces_map[identifier][i],
                    key_package,
                    *randomizer,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Send SignatureShares to the server
        let res = server
            .post("/send_signature_share")
            .json(&server::SendSignatureShareArgs {
                session_id,
                identifier: *identifier,
                signature_share,
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

    // Generate the final Signature for each message
    let signatures = signing_packages
        .iter()
        .enumerate()
        .map(|(i, p)| frost::aggregate(p, &r.signature_shares[i], &pubkeys, &randomized_params[i]))
        .collect::<Result<Vec<_>, _>>()?;

    // Close the session
    let res = server
        .post("/close_session")
        .json(&server::CloseSessionArgs { session_id })
        .await;
    res.assert_status_ok();

    // Verify signatures to test if they were generated correctly
    for (i, p) in randomized_params.iter().enumerate() {
        p.randomized_verifying_key()
            .verify(messages[i], &signatures[i])?;
    }

    Ok(())
}

/// Actually spawn the HTTP server and connect to it using reqwest.
/// A better example on how to write client code.
#[tokio::test]
async fn test_http() -> Result<(), Box<dyn std::error::Error>> {
    // Create test values
    let mut rng = thread_rng();
    let (shares, _pubkeys) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
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
            identifiers: key_packages.keys().copied().collect::<Vec<_>>(),
            message_count: 1,
        })
        .send()
        .await?
        .json::<server::CreateNewSessionOutput>()
        .await?;
    println!("{}", r.session_id);

    Ok(())
}
