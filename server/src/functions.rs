use axum::{extract::State, Json};
use uuid::Uuid;
use xeddsa::{xed25519, Verify as _};

use crate::{
    state::{Session, SharedState},
    types::*,
    user::User,
    AppError,
};

/// Implement the challenge API.
#[tracing::instrument(ret, err(Debug), skip(state, _args))]
pub(crate) async fn challenge(
    State(state): State<SharedState>,
    Json(_args): Json<ChallengeArgs>,
) -> Result<Json<ChallengeOutput>, AppError> {
    // Create new challenge.
    let challenge = Uuid::new_v4();

    state.challenges.write().unwrap().insert(challenge);

    let output = ChallengeOutput { challenge };
    Ok(Json(output))
}

/// Implement the key_login API.
#[tracing::instrument(ret, err(Debug), skip(state, args))]
pub(crate) async fn login(
    State(state): State<SharedState>,
    Json(args): Json<KeyLoginArgs>,
) -> Result<Json<KeyLoginOutput>, AppError> {
    // Check if the user sent the credentials
    if args.signature.is_empty() || args.pubkey.is_empty() {
        return Err(AppError::InvalidArgument("signature or pubkey".into()));
    }

    let pubkey = TryInto::<[u8; 32]>::try_into(args.pubkey.clone())
        .map_err(|_| AppError::InvalidArgument("pubkey".into()))?;
    let pubkey = xed25519::PublicKey(pubkey);
    let signature = TryInto::<[u8; 64]>::try_into(args.signature)
        .map_err(|_| AppError::InvalidArgument("signature".into()))?;
    pubkey
        .verify(args.uuid.as_bytes(), &signature)
        .map_err(|_| AppError::Unauthorized)?;

    let mut challenges = state.challenges.write().unwrap();
    if !challenges.remove(&args.uuid) {
        return Err(AppError::Unauthorized);
    }
    drop(challenges);

    let access_token = Uuid::new_v4();

    let mut access_tokens = state.access_tokens.write().unwrap();
    access_tokens.insert(access_token, args.pubkey);

    let token = KeyLoginOutput { access_token };

    Ok(Json(token))
}

/// Implement the logout API.
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn logout(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<()>, AppError> {
    state
        .access_tokens
        .write()
        .unwrap()
        .remove(&user.current_token);
    Ok(Json(()))
}

/// Implement the create_new_session API.
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn create_new_session(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<CreateNewSessionArgs>,
) -> Result<Json<CreateNewSessionOutput>, AppError> {
    if args.message_count == 0 {
        return Err(AppError::InvalidArgument("message_count".into()));
    }

    // Create new session object.
    let id = Uuid::new_v4();

    let mut sessions = state.sessions.sessions.write().unwrap();
    let mut sessions_by_pubkey = state.sessions.sessions_by_pubkey.write().unwrap();

    // Save session ID in global state
    for pubkey in &args.pubkeys {
        sessions_by_pubkey
            .entry(pubkey.0.clone())
            .or_default()
            .insert(id);
    }
    // Create Session object
    let session = Session {
        pubkeys: args.pubkeys.into_iter().map(|p| p.0).collect(),
        coordinator_pubkey: user.pubkey,
        num_signers: args.num_signers,
        message_count: args.message_count,
        queue: Default::default(),
    };
    // Save session into global state.
    sessions.insert(id, session);

    let user = CreateNewSessionOutput { session_id: id };
    Ok(Json(user))
}

/// Implement the create_new_session API.
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn list_sessions(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<ListSessionsOutput>, AppError> {
    let sessions_by_pubkey = state.sessions.sessions_by_pubkey.read().unwrap();

    let session_ids = sessions_by_pubkey
        .get(&user.pubkey)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();

    Ok(Json(ListSessionsOutput { session_ids }))
}

/// Implement the get_session_info API
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn get_session_info(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<GetSessionInfoArgs>,
) -> Result<Json<GetSessionInfoOutput>, AppError> {
    let sessions = state.sessions.sessions.read().unwrap();
    let sessions_by_pubkey = state.sessions.sessions_by_pubkey.read().unwrap();

    let user_sessions = sessions_by_pubkey
        .get(&user.pubkey)
        .ok_or(AppError::SessionNotFound)?;

    if !user_sessions.contains(&args.session_id) {
        return Err(AppError::SessionNotFound);
    }

    let session = sessions
        .get(&args.session_id)
        .ok_or(AppError::SessionNotFound)?;

    Ok(Json(GetSessionInfoOutput {
        num_signers: session.num_signers,
        message_count: session.message_count,
        pubkeys: session.pubkeys.iter().cloned().map(PublicKey).collect(),
        coordinator_pubkey: session.coordinator_pubkey.clone(),
    }))
}

/// Implement the send API
// TODO: get identifier from channel rather from arguments
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn send(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<SendArgs>,
) -> Result<(), AppError> {
    // Get the mutex lock to read and write from the state
    let mut sessions = state.sessions.sessions.write().unwrap();

    // TODO: change to get_mut and modify in-place, if HashMapDelay ever
    // adds support to it
    let mut session = sessions
        .remove(&args.session_id)
        .ok_or(AppError::SessionNotFound)?;

    let recipients = if args.recipients.is_empty() {
        vec![Vec::new()]
    } else {
        args.recipients.into_iter().map(|p| p.0).collect()
    };
    for pubkey in &recipients {
        session
            .queue
            .entry(pubkey.clone())
            .or_default()
            .push_back(Msg {
                sender: user.pubkey.clone(),
                msg: args.msg.clone(),
            });
    }
    sessions.insert(args.session_id, session);

    Ok(())
}

/// Implement the recv API
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn receive(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<ReceiveArgs>,
) -> Result<Json<ReceiveOutput>, AppError> {
    // Get the mutex lock to read and write from the state
    let sessions = state.sessions.sessions.read().unwrap();

    // TODO: change to get_mut and modify in-place, if HashMapDelay ever
    // adds support to it. This will also simplify the code since
    // we have to do a workaround in order to not renew the timeout if there
    // are no messages. See https://github.com/AgeManning/delay_map/issues/26
    let session = sessions
        .get(&args.session_id)
        .ok_or(AppError::SessionNotFound)?;

    let pubkey = if user.pubkey == session.coordinator_pubkey && args.as_coordinator {
        Vec::new()
    } else {
        user.pubkey
    };

    // If there are no new messages, we don't want to renew the timeout.
    // Thus only if there are new messages we drop the read-only lock
    // to get the write lock and re-insert the updated session.
    let msgs = if session.queue.contains_key(&pubkey) {
        drop(sessions);
        let mut sessions = state.sessions.sessions.write().unwrap();
        let mut session = sessions
            .remove(&args.session_id)
            .ok_or(AppError::SessionNotFound)?;
        let msgs = session.queue.entry(pubkey).or_default().drain(..).collect();
        sessions.insert(args.session_id, session);
        msgs
    } else {
        vec![]
    };

    Ok(Json(ReceiveOutput { msgs }))
}

/// Implement the close_session API.
#[tracing::instrument(ret, err(Debug), skip(state, user))]
pub(crate) async fn close_session(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<CloseSessionArgs>,
) -> Result<Json<()>, AppError> {
    let mut sessions = state.sessions.sessions.write().unwrap();
    let mut sessions_by_pubkey = state.sessions.sessions_by_pubkey.write().unwrap();

    let user_sessions = sessions_by_pubkey
        .get(&user.pubkey)
        .ok_or(AppError::SessionNotFound)?;

    if !user_sessions.contains(&args.session_id) {
        return Err(AppError::SessionNotFound);
    }

    let session = sessions
        .get(&args.session_id)
        .ok_or(AppError::SessionNotFound)?;

    if session.coordinator_pubkey != user.pubkey {
        return Err(AppError::NotCoordinator);
    }

    for username in session.pubkeys.clone() {
        if let Some(v) = sessions_by_pubkey.get_mut(&username) {
            v.remove(&args.session_id);
        }
    }
    sessions.remove(&args.session_id);
    Ok(Json(()))
}
