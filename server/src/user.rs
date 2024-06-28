use std::str::FromStr;

use crate::state::SharedState;

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};

use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use sqlx::{FromRow, SqlitePool};
use tokio::task;
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct User {
    pub(crate) id: i64,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) pubkey: Vec<u8>,
    pub(crate) access_token: Option<Uuid>,
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(serde_json::json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub(crate) async fn create_user(
    db: SqlitePool,
    username: &str,
    password: &str,
    pubkey: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: enforce mininum password length
    let password = password.to_owned();
    let pwhash = task::spawn_blocking(|| password_auth::generate_hash(password)).await?;
    sqlx::query(
        r#"
        insert into users (username, password, pubkey)
        values (?, ?, ?)
        "#,
    )
    .bind(username)
    .bind(pwhash)
    .bind(pubkey)
    .execute(&db)
    .await?;
    Ok(())
}

pub(crate) async fn authenticate_user(
    db: SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<User>, Box<dyn std::error::Error>> {
    let user: Option<User> = sqlx::query_as("select * from users where username = ? ")
        .bind(username)
        .fetch_optional(&db)
        .await?;

    // Verifying the password is blocking and potentially slow, so we'll do so via
    // `spawn_blocking`.
    let password = password.to_owned();
    let r: Result<_, password_auth::VerifyError> = task::spawn_blocking(|| {
        // We're using password-based authentication--this works by comparing our form
        // input with an argon2 password hash.
        Ok(user.filter(|user| password_auth::verify_password(password, &user.password).is_ok()))
    })
    .await?;
    Ok(r?)
}

pub(crate) async fn refresh_access_token(
    db: SqlitePool,
    id: i64,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let access_token = Uuid::new_v4();

    sqlx::query(
        r#"
        update users set access_token = ? where id = ?
        "#,
    )
    .bind(access_token)
    .bind(id)
    .execute(&db)
    .await?;

    Ok(access_token)
}

pub(crate) async fn get_user_for_access_token(
    db: SqlitePool,
    access_token: Uuid,
) -> Result<Option<User>, Box<dyn std::error::Error>> {
    let user: Option<User> = sqlx::query_as("select * from users where access_token = ? ")
        .bind(access_token)
        .fetch_optional(&db)
        .await?;
    Ok(user)
}

#[async_trait]
impl FromRequestParts<SharedState> for User {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let access_token = Uuid::from_str(bearer.token()).map_err(|_| AuthError::InvalidToken)?;

        let db = {
            let state_lock = state.read().unwrap();
            state_lock.db.clone()
        };

        let user = get_user_for_access_token(db, access_token)
            .await
            .map_err(|_| AuthError::InvalidToken)?;

        match user {
            Some(user) => Ok(user),
            None => return Err(AuthError::InvalidToken),
        }
    }
}
