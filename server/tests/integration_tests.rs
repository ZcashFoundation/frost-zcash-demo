use std::collections::BTreeMap;

use axum_test::TestServer;
use rand::thread_rng;
use server::router;

use reddsa::frost::redpallas as frost;

#[tokio::test]
async fn test_main_router() -> Result<(), Box<dyn std::error::Error>> {
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

    let router = router();
    let server = TestServer::new(router)?;
    let res = server
        .post("/create_new_session")
        .json(&server::CreateNewSessionArgs {
            identifiers: key_packages.keys().copied().collect::<Vec<_>>(),
        })
        .await;
    res.assert_status_ok();
    let r: server::CreateNewSessionOutput = res.json();
    let session_id = r.session_id;

    let mut nonces_map = BTreeMap::<_, _>::new();
    for (identifier, key_package) in key_packages.iter() {
        let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces_map.insert(*identifier, nonces);
        let res = server
            .post("/send_commitments")
            .json(&server::SendCommitmentsArgs {
                identifier: *identifier,
                session_id,
                commitments,
            })
            .await;
        res.assert_status_ok();
    }

    let res = server
        .post("/get_commitments")
        .json(&server::GetCommitmentsArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetCommitmentsOutput = res.json();
    let commitments = r.commitments;

    let message = "Hello, world!".as_bytes();
    let signing_package = frost::SigningPackage::new(commitments, message);
    let randomized_params =
        frost::RandomizedParams::new(pubkeys.verifying_key(), &signing_package, &mut rng)?;

    let res = server
        .post("/send_signing_package")
        .json(&server::SendSigningPackageArgs {
            session_id,
            signing_package: signing_package.clone(),
            randomizer: *randomized_params.randomizer(),
        })
        .await;
    res.assert_status_ok();

    for (identifier, key_package) in key_packages.iter() {
        let res = server
            .post("get_signing_package")
            .json(&server::GetSigningPackageArgs { session_id })
            .await;
        res.assert_status_ok();
        let r: server::GetSigningPackageOutput = res.json();

        let signature_share = frost::round2::sign(
            &r.signing_package,
            &nonces_map[identifier],
            key_package,
            r.randomizer,
        )?;

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

    let res = server
        .post("/get_signature_shares")
        .json(&server::GetSignatureSharesArgs { session_id })
        .await;
    res.assert_status_ok();
    let r: server::GetSignatureSharesOutput = res.json();

    let signature = frost::aggregate(
        &signing_package,
        &r.signature_shares,
        &pubkeys,
        &randomized_params,
    )?;

    randomized_params
        .randomized_verifying_key()
        .verify(message, &signature)?;

    Ok(())
}
