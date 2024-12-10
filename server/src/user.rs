use std::str::FromStr;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use eyre::eyre;
use uuid::Uuid;

use crate::{state::SharedState, AppError};

/// An User
#[derive(Debug)]
#[allow(dead_code)]
pub struct User {
    pub(crate) pubkey: Vec<u8>,
    pub(crate) current_token: Uuid,
}

/// Read a User from a request. This is used to authenticate users. If any axum
/// handler has an User argument, this will be called and the authentication
/// will be carried out.
#[async_trait]
impl FromRequestParts<SharedState> for User {
    type Rejection = AppError;

    #[tracing::instrument(err(Debug), skip(parts, state))]
    // Can be removed after this fix is released
    // https://github.com/rust-lang/rust-clippy/issues/12281
    #[allow(clippy::blocks_in_conditions)]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("Bearer token missing").into(),
                )
            })?;
        // Decode the user data
        let access_token = Uuid::from_str(bearer.token()).map_err(|_| {
            AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("invalid access token").into(),
            )
        })?;

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
            return Err(AppError(
                StatusCode::INTERNAL_SERVER_ERROR,
                eyre!("user not found").into(),
            ));
        }
    }
}
