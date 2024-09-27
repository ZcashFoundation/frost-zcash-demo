/// A ZF-FROST-encoded header for human-readable formats.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Header {
    /// Format version
    pub version: u8,
    /// Ciphersuite ID
    pub ciphersuite: String,
}

/// A ZF-FROST-encoded generic struct with a Header. Used to parse an arbitrary
/// ZF FROST struct and extract the ciphersuite from the header.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GenericStruct {
    /// The header
    pub header: Header,
}

mod test {
    use super::*;

    #[test]
    fn test_generic_struct() {
        let s ="00b169f0da0301000000000000000000000000000000000000000000000000000000000000003634b8378c436c688dc691f36686108956896d2d5d4f46b9a8de26c8febc9cc202000000000000000000000000000000000000000000000000000000000000000e2e0cab91fe6049305d0130f042cf12166e47eb2c08233cc121be0e83eddf4803000000000000000000000000000000000000000000000000000000000000005d537c848db0608432bf2abcf449446101658ba0063f3e0b9c1525c3eaf4021807033d126c4c10045d37b889834d3cae70d00655f2def067f04cd902b74c9dff";
        let b = hex::decode(s).unwrap();
        let _generic: GenericStruct = postcard::from_bytes(&b).unwrap();
    }
}
