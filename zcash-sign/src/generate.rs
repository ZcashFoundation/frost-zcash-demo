use rand::{Rng, RngCore};

use orchard::keys::{FullViewingKey, SpendValidatingKey, SpendingKey};

/// Generate an Orchard `FullViewingKey` from the given `SpendValidatingKey`,
/// which should correspond to a FROST group public key (`VerifyingKey`).
///
/// The operation is randomized;s different calls will generate different
/// `FullViewingKey`s for different `SpendValidatingKey`s.
pub fn generate(rng: &mut impl RngCore, ak: &SpendValidatingKey) -> FullViewingKey {
    let sk = loop {
        let random_bytes = rng.gen::<[u8; 32]>();
        let sk = SpendingKey::from_bytes(random_bytes);
        if sk.is_some().into() {
            break sk.unwrap();
        }
    };

    FullViewingKey::from_sk_ak(&sk, ak.clone())
}
