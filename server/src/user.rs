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
use sqlx::{FromRow, SqlitePool};
use tokio::task;
use uuid::Uuid;

use crate::{state::SharedState, AppError};

/// An User, as stored in the database.
#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct User {
    pub(crate) id: i64,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) pubkey: Vec<u8>,
    #[sqlx(skip)]
    pub(crate) access_tokens: Vec<AccessToken>,
    #[sqlx(skip)]
    pub(crate) current_token: Option<Uuid>,
}

#[derive(Debug, FromRow)]
#[allow(dead_code)]
pub struct AccessToken {
    pub(crate) id: i64,
    pub(crate) user_id: i64,
    pub(crate) access_token: Option<Uuid>,
}

/// Create user in the database.
///
/// The password is hashed and its hash is written in the DB.
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

/// Get user from database, or None if it's not registered.
pub(crate) async fn get_user(
    db: SqlitePool,
    username: &str,
) -> Result<Option<User>, Box<dyn std::error::Error>> {
    let user: Option<User> = sqlx::query_as("select * from users where username = ? ")
        .bind(username)
        .fetch_optional(&db)
        .await?;
    if let Some(mut user) = user {
        let access_tokens: Vec<AccessToken> =
            sqlx::query_as("select * from access_tokens where user_id = ?")
                .bind(user.id)
                .fetch_all(&db)
                .await?;
        user.access_tokens = access_tokens;
        Ok(Some(user))
    } else {
        Ok(None)
    }
}

/// Delete an User from the database, given its database ID.
pub(crate) async fn delete_user(db: SqlitePool, id: i64) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r#"
        delete from users where id = ?
        "#,
    )
    .bind(id)
    .execute(&db)
    .await?;
    Ok(())
}

/// Authenticate user registered in the database. Returns the User if
/// authentication is successful, or None if the username or password is wrong.
///
/// The given password is hashed and verified against the stored hash.
pub(crate) async fn authenticate_user(
    db: SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<User>, Box<dyn std::error::Error>> {
    let user: Option<User> = get_user(db, username).await?;

    // Verifying the password is blocking and potentially slow, so we'll do so
    // via `spawn_blocking`.
    let password = password.to_owned();
    let r: Result<_, password_auth::VerifyError> = task::spawn_blocking(|| {
        // We're using password-based authentication--this works by comparing our form
        // input with an argon2 password hash.
        Ok(user.filter(|user| password_auth::verify_password(password, &user.password).is_ok()))
    })
    .await?;
    Ok(r?)
}

/// Refreshes the user's access token, identified by its id in the database.
///
/// Generates a new token and overwrites the old one in the database, if any.
pub(crate) async fn add_access_token(
    db: SqlitePool,
    id: i64,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let access_token = Uuid::new_v4();

    sqlx::query(
        r#"
        insert into access_tokens (user_id, access_token)
        values (?, ?)
        "#,
    )
    .bind(id)
    .bind(access_token)
    .execute(&db)
    .await?;

    Ok(access_token)
}

/// Remove a user's access token.
pub(crate) async fn remove_access_token(
    db: SqlitePool,
    access_token: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r#"
        delete from access_tokens where access_token = ?
        "#,
    )
    .bind(access_token)
    .execute(&db)
    .await?;

    Ok(())
}

/// Return the User for a given access token, or None if there is no match.
pub(crate) async fn get_user_for_access_token(
    db: SqlitePool,
    access_token: Uuid,
) -> Result<Option<User>, Box<dyn std::error::Error>> {
    let user: Option<User> = sqlx::query_as(
        r#"
        select * from users inner join access_tokens on users.id = access_tokens.user_id where access_tokens.access_token = ?
        "#,
    )
    .bind(access_token)
    .fetch_optional(&db)
    .await?;
    Ok(user)
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

        let user = if let Some(pubkey) = pubkey {
            Some(User {
                id: -1,
                username: String::new(),
                password: String::new(),
                pubkey,
                access_tokens: vec![],
                current_token: Some(access_token),
            })
        } else {
            get_user_for_access_token(state.db.clone(), access_token)
                .await
                .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?
        };

        match user {
            Some(mut user) => {
                user.current_token = Some(access_token);
                Ok(user)
            }
            None => {
                return Err(AppError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    eyre!("user not found").into(),
                ))
            }
        }
    }
}
