// =============================================================================
// Server
// =============================================================================

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

/// Long-lived server parameters. Cheap to clone (Arc internals).
/// Send + Sync so it can be shared across threads (e.g. in an Axum state).
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
    /// Generate a new server with fresh random keys.
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

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.static_pk.compress().to_bytes()
    }

    pub fn identity(&self) -> &[u8] {
        &self.inner.identity
    }

    /// Create a new session. The returned OpaqueSession is Send + Sync and
    /// holds an Arc reference back to this Server.
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

/// A per-user session. Drives both registration and login as a state machine.
/// Holds an Arc<ServerInner> so it is Send + Sync without lifetime parameters.
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

    /// Step 1 of registration (server): process RegistrationRequest → RegistrationResponse.
    /// RFC 9807 §5.2.2 CreateRegistrationResponse.
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

    /// Step 2 of registration (server): receive and store RegistrationRecord.
    /// In a real application, the caller persists the returned record to a database.
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

    /// Step 1 of login (server): process KE1 → KE2.
    /// RFC 9807 §6.2.2 GenerateKE2 + §6.4.4 AuthServerRespond.
    ///
    /// `record`          — the RegistrationRecord previously stored for this client
    /// `client_identity` — the client's identity string (e.g. their username/email)
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

    /// Step 2 of login (server): verify KE3, return session key.
    /// RFC 9807 §6.2.4 ServerFinish.
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

// Output of a completed login on both sides
pub struct SessionKey(pub [u8; NH]);

impl SessionKey {
    pub fn mint_jwt<T: Serialize>(&self, header: &Header, claims: &T) -> anyhow::Result<String> {
        jsonwebtoken::encode(header, claims, &EncodingKey::from_secret(&self.0))
            .map_err(|e| anyhow::anyhow!(e))
    }

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
