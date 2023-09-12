use frost_ed25519 as frost;

use frost::keys::IdentifierList;
use frost::Identifier;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::BufWriter;

use rand::thread_rng;

use trusted_dealer::inputs::request_inputs as trusted_dealer_input;
use trusted_dealer::trusted_dealer_keygen::trusted_dealer_keygen;

use participant::round2::round_2_request_inputs as participant_input_round_2;
use participant::{
    round1::request_inputs as participant_input_round_1, round2::generate_signature,
};

#[test]
fn trusted_dealer_journey() {
    let mut buf = BufWriter::new(Vec::new());
    let mut rng = thread_rng();

    // Trusted dealer

    let dealer_input = "3\n5\n\n";

    let dealer_config = trusted_dealer_input(&mut dealer_input.as_bytes(), &mut buf).unwrap();

    let (shares, pubkeys) =
        trusted_dealer_keygen(&dealer_config, IdentifierList::Default, &mut rng).unwrap();

    // Coordinator step 1

    let num_of_participants = 3;

    let id_input_1 = "0100000000000000000000000000000000000000000000000000000000000000";
    let id_input_2 = "0200000000000000000000000000000000000000000000000000000000000000";
    let id_input_3 = "0300000000000000000000000000000000000000000000000000000000000000";

    let participant_id_1 = Identifier::try_from(1).unwrap();
    let participant_id_2 = Identifier::try_from(2).unwrap();
    let participant_id_3 = Identifier::try_from(3).unwrap();

    let step_1_input = format!(
        "{}\n{}\n{}\n{}\n{}\n",
        serde_json::to_string(&pubkeys).unwrap(),
        num_of_participants,
        id_input_1,
        id_input_2,
        id_input_3
    );

    let participants_config =
        coordinator::step_1::step_1(&mut step_1_input.as_bytes(), &mut buf).unwrap();

    // Participants round 1

    let mut key_packages: HashMap<_, _> = HashMap::new();

    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share).unwrap();
        key_packages.insert(identifier, key_package);
    }

    let mut nonces_map = HashMap::new();
    let mut commitments_map = BTreeMap::new();

    for participant_index in 1..=3 {
        let participant_identifier = Identifier::try_from(participant_index).unwrap();

        let share = key_packages[&participant_identifier].secret_share();

        let round_1_input = format!(
            "{}\n",
            &serde_json::to_string(&key_packages[&participant_identifier]).unwrap()
        );
        let round_1_config =
            participant_input_round_1(&mut round_1_input.as_bytes(), &mut buf).unwrap();

        assert_eq!(
            round_1_config.key_package,
            key_packages[&participant_identifier]
        );

        let (nonces, commitments) = frost::round1::commit(share, &mut rng);

        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // Coordinator step 2

    let mut signature_shares = HashMap::new();
    let message = "74657374";

    let step_2_input = format!(
        "{}\n{}\n{}\n{}\n",
        message,
        serde_json::to_string(&commitments_map[&participant_id_1]).unwrap(),
        serde_json::to_string(&commitments_map[&participant_id_2]).unwrap(),
        serde_json::to_string(&commitments_map[&participant_id_3]).unwrap()
    );

    let signing_package = coordinator::step_2::step_2(
        &mut step_2_input.as_bytes(),
        &mut buf,
        vec![participant_id_1, participant_id_2, participant_id_3],
    )
    .unwrap();

    // Participants round 2

    for participant_identifier in nonces_map.keys() {
        let round_2_input = format!("{}\n", serde_json::to_string(&signing_package).unwrap());
        let round_2_config =
            participant_input_round_2(&mut round_2_input.as_bytes(), &mut buf).unwrap();
        let signature = generate_signature(
            round_2_config,
            &key_packages[participant_identifier],
            &nonces_map[participant_identifier],
        )
        .unwrap();
        signature_shares.insert(*participant_identifier, signature);
    }

    // coordinator step 3

    let step_3_input = format!(
        "{}\n{}\n{}\n",
        serde_json::to_string(&signature_shares[&participant_id_1]).unwrap(),
        serde_json::to_string(&signature_shares[&participant_id_2]).unwrap(),
        serde_json::to_string(&signature_shares[&participant_id_3]).unwrap()
    );
    let group_signature = coordinator::step_3::step_3(
        &mut step_3_input.as_bytes(),
        &mut buf,
        participants_config,
        signing_package,
    );

    // verify

    let is_signature_valid = pubkeys
        .group_public()
        .verify("test".as_bytes(), &group_signature)
        .is_ok();
    assert!(is_signature_valid);
}
