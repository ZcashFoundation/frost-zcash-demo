use std::collections::HashMap;

use serde::{Deserialize, Serialize};
pub use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct SerializedIdentifier(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub Vec<u8>,
);

impl<C: frost_core::Ciphersuite> From<frost_core::Identifier<C>> for SerializedIdentifier {
    fn from(identifier: frost_core::Identifier<C>) -> Self {
        Self(identifier.serialize().as_ref().to_vec())
    }
}

impl<C: frost_core::Ciphersuite> TryFrom<&SerializedIdentifier> for frost_core::Identifier<C> {
    type Error = frost_core::Error<C>;

    fn try_from(serialized_identifier: &SerializedIdentifier) -> Result<Self, Self::Error> {
        frost_core::Identifier::<C>::deserialize(
            &serialized_identifier
                .clone()
                .0
                .try_into()
                .map_err(|_| frost_core::Error::<C>::DeserializationError)?,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializedSigningCommitments(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub Vec<u8>,
);

impl<C: frost_core::Ciphersuite> TryFrom<&frost_core::round1::SigningCommitments<C>>
    for SerializedSigningCommitments
{
    type Error = frost_core::Error<C>;

    fn try_from(
        signing_commitments: &frost_core::round1::SigningCommitments<C>,
    ) -> Result<Self, Self::Error> {
        Ok(Self(signing_commitments.serialize()?))
    }
}

impl<C: frost_core::Ciphersuite> TryFrom<&SerializedSigningCommitments>
    for frost_core::round1::SigningCommitments<C>
{
    type Error = frost_core::Error<C>;

    fn try_from(
        serialized_signing_commitments: &SerializedSigningCommitments,
    ) -> Result<Self, Self::Error> {
        frost_core::round1::SigningCommitments::<C>::deserialize(&serialized_signing_commitments.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializedSigningPackage(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub Vec<u8>,
);

impl<C: frost_core::Ciphersuite> TryFrom<&frost_core::SigningPackage<C>>
    for SerializedSigningPackage
{
    type Error = frost_core::Error<C>;

    fn try_from(signing_package: &frost_core::SigningPackage<C>) -> Result<Self, Self::Error> {
        Ok(Self(signing_package.serialize()?))
    }
}

impl<C: frost_core::Ciphersuite> TryFrom<&SerializedSigningPackage>
    for frost_core::SigningPackage<C>
{
    type Error = frost_core::Error<C>;

    fn try_from(
        serialized_signing_package: &SerializedSigningPackage,
    ) -> Result<Self, Self::Error> {
        frost_core::SigningPackage::<C>::deserialize(&serialized_signing_package.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializedRandomizer(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub Vec<u8>,
);

impl<C: frost_core::Ciphersuite> From<frost_rerandomized::Randomizer<C>> for SerializedRandomizer {
    fn from(randomizer: frost_rerandomized::Randomizer<C>) -> Self {
        Self(randomizer.serialize().as_ref().to_vec())
    }
}

impl<C: frost_core::Ciphersuite> TryFrom<&SerializedRandomizer>
    for frost_rerandomized::Randomizer<C>
{
    type Error = frost_core::Error<C>;

    fn try_from(serialized_randomizer: &SerializedRandomizer) -> Result<Self, Self::Error> {
        frost_rerandomized::Randomizer::<C>::deserialize(
            &serialized_randomizer
                .0
                .clone()
                .try_into()
                .map_err(|_| frost_core::Error::<C>::DeserializationError)?,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializedSignatureShare(
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub Vec<u8>,
);

impl<C: frost_core::Ciphersuite> From<frost_core::round2::SignatureShare<C>>
    for SerializedSignatureShare
{
    fn from(randomizer: frost_core::round2::SignatureShare<C>) -> Self {
        Self(randomizer.serialize().as_ref().to_vec())
    }
}

impl<C: frost_core::Ciphersuite> TryFrom<&SerializedSignatureShare>
    for frost_core::round2::SignatureShare<C>
{
    type Error = frost_core::Error<C>;

    fn try_from(serialized_randomizer: &SerializedSignatureShare) -> Result<Self, Self::Error> {
        frost_core::round2::SignatureShare::<C>::deserialize(
            serialized_randomizer
                .0
                .clone()
                .try_into()
                .map_err(|_| frost_core::Error::<C>::DeserializationError)?,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateNewSessionArgs {
    pub num_signers: u16,
    pub message_count: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateNewSessionOutput {
    pub session_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSessionInfoArgs {
    pub session_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSessionInfoOutput {
    pub num_signers: u16,
    pub message_count: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendCommitmentsArgs {
    pub session_id: Uuid,
    pub identifier: SerializedIdentifier,
    pub commitments: Vec<SerializedSigningCommitments>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCommitmentsArgs {
    pub session_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetCommitmentsOutput {
    pub commitments: Vec<HashMap<SerializedIdentifier, SerializedSigningCommitments>>,
}

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
pub struct SendSigningPackageArgs {
    pub session_id: Uuid,
    pub signing_package: Vec<SerializedSigningPackage>,
    #[serde(
        serialize_with = "serdect::slice::serialize_hex_lower_or_bin",
        deserialize_with = "serdect::slice::deserialize_hex_or_bin_vec"
    )]
    pub aux_msg: Vec<u8>,
    #[derivative(Debug = "ignore")]
    pub randomizer: Vec<SerializedRandomizer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSigningPackageArgs {
    pub session_id: Uuid,
}

#[derive(Serialize, Deserialize, derivative::Derivative)]
#[derivative(Debug)]
pub struct GetSigningPackageOutput {
    pub signing_package: Vec<SerializedSigningPackage>,
    #[derivative(Debug = "ignore")]
    pub randomizer: Vec<SerializedRandomizer>,
    pub aux_msg: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SendSignatureShareArgs {
    pub session_id: Uuid,
    pub identifier: SerializedIdentifier,
    pub signature_share: Vec<SerializedSignatureShare>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSignatureSharesArgs {
    pub session_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetSignatureSharesOutput {
    pub signature_shares: Vec<HashMap<SerializedIdentifier, SerializedSignatureShare>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloseSessionArgs {
    pub session_id: Uuid,
}
