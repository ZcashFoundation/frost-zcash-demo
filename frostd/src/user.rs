use std::str::FromStr;

use axum::{extract::FromRequestParts, http::request::Parts, RequestPartsExt};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use uuid::Uuid;

use crate::{state::SharedState, Error, PublicKey};

/// An User
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct User {
    pub(crate) pubkey: PublicKey,
    pub(crate) current_token: Uuid,
}

/// Read a User from a request. This is used to authenticate users. If any axum
/// handler has an User argument, this will be called and the authentication
/// will be carried out.
impl FromRequestParts<SharedState> for User {
    type Rejection = Error;

    #[tracing::instrument(err(Debug), skip(parts, state))]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| Error::Unauthorized)?;
        // Decode the user data
        let access_token = Uuid::from_str(bearer.token()).map_err(|_| Error::Unauthorized)?;

        let pubkey = state
            .access_tokens
            .read()
            .unwrap()
            .get(&access_token)
            .cloned();

        if let Some(pubkey) = pubkey {
            Ok(User {
                pubkey,
                current_token: access_token,
            })
        } else {
            return Err(Error::Unauthorized);
        }
    }
}
