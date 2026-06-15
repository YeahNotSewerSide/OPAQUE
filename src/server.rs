//! Server-side OPAQUE state machine.
//!
//! [`Server`] holds long-lived cryptographic parameters and is cheap to clone
//! (Arc-backed). Create one at startup and share it across request handlers.
//!
//! [`OpaqueSession`] is a per-request, per-user state machine. Create a new
//! one for every registration or login attempt via [`Server::initiate_session`].

use std::sync::Arc;

use curve25519_dalek::{RistrettoPoint, Scalar};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngExt as _;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    NH, NM, NN, NSEED, OpaqueError,
    utils::{
        build_preamble, decompress, derive_dh_keypair, derive_keys, dh, hash, mac_fn,
        oprf_derive_key,
    },
    wire_structs::{Ke1, Ke2, Ke3, RegistrationRecord, RegistrationRequest, RegistrationResponse},
};

/// Long-lived server configuration. Cheap to clone (Arc-backed).
///
/// Holds the server's static AKE keypair and OPRF seed. These are derived
/// from the seeds passed to [`Server::new`] and must be kept secret and
/// stable — regenerating them invalidates all stored [`RegistrationRecord`]s.
///
/// `Send + Sync`: safe to share across threads (e.g. as Axum `State`).
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    /// Static AKE keypair — shared across all clients
    static_sk: Scalar,
    pub static_pk: RistrettoPoint,
    /// Global OPRF seed — used to derive per-client OPRF keys
    oprf_seed: [u8; NH],
    /// Server identity string (e.g. b"example.com")
    identity: Vec<u8>,
}

impl Server {
    /// Create a server from persisted seeds.
    ///
    /// # Parameters
    /// - `identity` — server identity bytes sent to the client (e.g. `b"example.com"`)
    /// - `oprf_seed` — 64-byte secret seed used to derive per-client OPRF keys (RFC 9807 §5.2.2)
    /// - `key_seed` — 64-byte secret seed used to derive the static AKE keypair
    ///
    /// Both seeds must be randomly generated, kept secret, and persisted.
    /// Using different seeds between restarts breaks all existing sessions.
    pub fn new(identity: impl Into<Vec<u8>>, oprf_seed: [u8; NH], key_seed: [u8; NH]) -> Self {
        let static_sk = Scalar::from_bytes_mod_order_wide(&key_seed);
        let static_pk = RistrettoPoint::mul_base(&static_sk);
        Self {
            inner: Arc::new(ServerInner {
                static_sk,
                static_pk,
                oprf_seed,
                identity: identity.into(),
            }),
        }
    }

    /// Returns the server's static public key as 32 compressed Ristretto255 bytes.
    ///
    /// This is included in every [`RegistrationResponse`] and [`Ke2`] message;
    /// it does not need to be kept secret.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.static_pk.compress().to_bytes()
    }

    /// Returns the server identity bytes provided at construction.
    pub fn identity(&self) -> &[u8] {
        &self.inner.identity
    }

    /// Create a new [`OpaqueSession`] for `credential_identifier`.
    ///
    /// `credential_identifier` uniquely identifies the user server-side
    /// (e.g. their primary key, username, or email). It is used to derive
    /// the per-client OPRF key and must be consistent between registration
    /// and all subsequent logins.
    ///
    /// Create a fresh session for every registration and every login attempt —
    /// sessions are not reusable.
    pub fn initiate_session(&self, credential_identifier: impl Into<Vec<u8>>) -> OpaqueSession {
        OpaqueSession {
            server: self.clone(),
            credential_identifier: credential_identifier.into(),
            state: SessionState::Idle,
        }
    }
}

// =============================================================================
// Session state machine
// =============================================================================

/// All states an OpaqueSession can be in, per side.
enum SessionState {
    Idle,

    // --- Registration states (server side) ---
    RegistrationAwaitingRecord {
        // nothing extra needed server-side between req→resp and record
    },

    // --- Login states (server side) ---
    LoginAwaitingKe3 {
        expected_client_mac: [u8; NM],
        session_key: [u8; NH],
    },

    // --- Terminal ---
    Completed,
}

// Asserts the session is in the expected state variant
macro_rules! matches_state {
    ($state:expr, $pat:pat) => {
        if matches!($state, $pat) {
            Ok(())
        } else {
            Err(OpaqueError::InvalidState("unexpected session state"))
        }
    };
}

/// Per-user, per-request OPAQUE state machine.
///
/// Drives both the registration and login flows on the server side.
/// Holds an `Arc` back to the parent [`Server`], so it is `Send + Sync`
/// without any lifetime parameters.
///
/// **Not reusable.** Once a session reaches `Completed` (or returns an
/// error), discard it and create a new one via [`Server::initiate_session`].
pub struct OpaqueSession {
    server: Server,
    credential_identifier: Vec<u8>,
    state: SessionState,
}

// SAFETY: same reasoning as Server — no raw pointers or cell types.
unsafe impl Send for OpaqueSession {}
unsafe impl Sync for OpaqueSession {}

impl OpaqueSession {
    // -------------------------------------------------------------------------
    // Registration — server side (RFC 9807 §5)
    // -------------------------------------------------------------------------

    /// Registration step 1 (server) — RFC 9807 §5.2.2 CreateRegistrationResponse.
    ///
    /// Evaluates the client's blinded element under the per-client OPRF key
    /// and returns the server's static public key.
    ///
    /// # Errors
    /// [`OpaqueError::InvalidState`] if the session is not in the initial `Idle` state.
    pub fn registration_start(
        &mut self,
        request: &RegistrationRequest,
    ) -> Result<RegistrationResponse, OpaqueError> {
        matches_state!(&self.state, SessionState::Idle)?;

        let oprf_key = oprf_derive_key(&self.server.inner.oprf_seed, &self.credential_identifier);
        let blinded = decompress(&request.blinded_element);
        let evaluated = (blinded * oprf_key).compress().to_bytes();

        self.state = SessionState::RegistrationAwaitingRecord {};
        Ok(RegistrationResponse {
            evaluated_element: evaluated,
            server_public_key: self.server.public_key_bytes(),
        })
    }

    /// Registration step 2 (server) — receive and echo the [`RegistrationRecord`].
    ///
    /// The returned record must be persisted by the caller (e.g. written to a
    /// database keyed by `credential_identifier`). The framework does not store it.
    ///
    /// # Errors
    /// [`OpaqueError::InvalidState`] if [`registration_start`] has not been called.
    pub fn registration_finish(
        &mut self,
        record: RegistrationRecord,
    ) -> Result<RegistrationRecord, OpaqueError> {
        matches_state!(&self.state, SessionState::RegistrationAwaitingRecord { .. })?;
        self.state = SessionState::Completed;
        Ok(record)
    }

    // -------------------------------------------------------------------------
    // Login — server side (RFC 9807 §6)
    // -------------------------------------------------------------------------

    /// Login step 1 (server) — RFC 9807 §6.2.2 GenerateKE2 + §6.4.4 AuthServerRespond.
    ///
    /// Re-evaluates the OPRF, constructs the credential response from the stored
    /// record, generates an ephemeral keypair, performs 3DH, and produces the
    /// server MAC over the transcript.
    ///
    /// # Parameters
    /// - `ke1` — [`Ke1`] received from the client
    /// - `record` — the [`RegistrationRecord`] previously stored for this user
    /// - `client_identity` — must match the identity used during registration
    ///
    /// # Errors
    /// [`OpaqueError::InvalidState`] if the session is not in the `Idle` state.
    pub fn login_start(
        &mut self,
        ke1: &Ke1,
        record: &RegistrationRecord,
        client_identity: &[u8],
    ) -> Result<Ke2, OpaqueError> {
        matches_state!(&self.state, SessionState::Idle)?;

        let mut rng = rand::rng();
        let server = &self.server.inner;

        // Credential retrieval: re-evaluate OPRF
        let oprf_key = oprf_derive_key(&server.oprf_seed, &self.credential_identifier);
        let blinded = decompress(&ke1.blinded_element);
        let evaluated_element = (blinded * oprf_key).compress().to_bytes();

        // Server ephemeral keypair
        let mut keyshare_seed = [0u8; NSEED];
        rng.fill(&mut keyshare_seed);
        let (server_ephemeral_sk, server_ephemeral_pk) = derive_dh_keypair(&keyshare_seed);
        let server_ephemeral_pk_bytes: [u8; 32] = server_ephemeral_pk.compress().to_bytes();

        let mut server_nonce = [0u8; NN];
        rng.fill(&mut server_nonce);

        let ke2 = Ke2 {
            evaluated_element,
            envelope_nonce: record.envelope_nonce,
            envelope_auth_tag: record.envelope_auth_tag,
            server_public_key: server.static_pk.compress().to_bytes(),
            server_nonce,
            server_ephemeral_pk: server_ephemeral_pk_bytes,
            server_mac: [0u8; NM],
        };

        // 3DH — server perspective (§6.4.4):
        //   dh1 = server_ephemeral_sk × client_ephemeral_pk  (ephemeral–ephemeral)
        //   dh2 = server_static_sk   × client_ephemeral_pk  (static–ephemeral)
        //   dh3 = server_ephemeral_sk × client_static_pk    (ephemeral–static)
        let client_ephemeral_pk = decompress(&ke1.client_ephemeral_pk);
        let client_static_pk = decompress(&record.client_public_key);
        let dh1 = dh(&server_ephemeral_sk, &client_ephemeral_pk);
        let dh2 = dh(&server.static_sk, &client_ephemeral_pk);
        let dh3 = dh(&server_ephemeral_sk, &client_static_pk);
        let ikm: Vec<u8> = [dh1.as_ref(), dh2.as_ref(), dh3.as_ref()].concat();

        let preamble = build_preamble(client_identity, ke1, &server.identity, &ke2);
        let (km2, km3, session_key) = derive_keys(&ikm, &preamble);

        let server_mac = mac_fn(&km2, &hash(&preamble));
        let expected_client_mac = mac_fn(
            &km3,
            &hash(&[preamble.as_slice(), server_mac.as_ref()].concat()),
        );

        self.state = SessionState::LoginAwaitingKe3 {
            expected_client_mac,
            session_key,
        };

        Ok(Ke2 { server_mac, ..ke2 })
    }

    /// Login step 2 (server) — RFC 9807 §6.2.4 ServerFinish.
    ///
    /// Verifies the client MAC from [`Ke3`], completing mutual authentication.
    ///
    /// # Errors
    /// - [`OpaqueError::ClientAuthenticationError`] — client MAC did not verify
    /// - [`OpaqueError::InvalidState`] — [`login_start`] has not been called
    ///
    /// # Returns
    /// The [`SessionKey`] shared with the client. Both sides derive an identical
    /// key; any mismatch indicates a protocol violation.
    pub fn login_finish(&mut self, ke3: &Ke3) -> Result<SessionKey, OpaqueError> {
        let (expected_client_mac, session_key) = match &self.state {
            SessionState::LoginAwaitingKe3 {
                expected_client_mac,
                session_key,
            } => (*expected_client_mac, *session_key),
            _ => return Err(OpaqueError::InvalidState("expected LoginAwaitingKe3")),
        };

        if ke3.client_mac != expected_client_mac {
            return Err(OpaqueError::ClientAuthenticationError);
        }

        self.state = SessionState::Completed;
        Ok(SessionKey(session_key))
    }
}

/// A 64-byte symmetric session key shared by client and server after a
/// successful login.
///
/// Derived via 3DH + HKDF; neither party can predict it before the handshake
/// completes. Can be used directly or via the JWT helpers.
pub struct SessionKey(pub [u8; NH]);

impl SessionKey {
    /// Mint a JWT signed with HMAC-SHA-256 keyed by the session key.
    ///
    /// The caller is responsible for constructing appropriate claims (expiry,
    /// audience, subject, etc.).
    pub fn mint_jwt<T: Serialize>(&self, header: &Header, claims: &T) -> anyhow::Result<String> {
        jsonwebtoken::encode(header, claims, &EncodingKey::from_secret(&self.0))
            .map_err(|e| anyhow::anyhow!(e))
    }

    /// Verify and decode a JWT previously minted with [`mint_jwt`].
    ///
    /// Validates the HS256 signature and requires `aud == "access"`.
    ///
    /// # Errors
    /// Returns an error if the signature is invalid, the token is expired,
    /// or the audience claim does not match.
    pub fn verify_jwt<T: DeserializeOwned>(&self, token: &str) -> anyhow::Result<T> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["access"]);

        Ok(
            jsonwebtoken::decode::<T>(token, &DecodingKey::from_secret(&self.0), &validation)
                .map_err(|e| anyhow::anyhow!(e))?
                .claims,
        )
    }
}
