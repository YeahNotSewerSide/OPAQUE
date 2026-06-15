# OPAQUE

A Rust implementation of the [OPAQUE](https://datatracker.ietf.org/doc/rfc9807/) asymmetric password-authenticated key exchange (aPAKE) protocol.

OPAQUE lets a client authenticate to a server using a password **without the server ever seeing the password** - not during registration, not during login, never. The server stores only a `RegistrationRecord`; an attacker who steals the database cannot run an offline dictionary attack without also compromising the server's private key.

---

## Protocol overview

```
REGISTRATION (3 messages)

Client                              Server
  |-- RegistrationRequest -------->  |   (blinded password)
  |<-- RegistrationResponse -------  |   (OPRF evaluation + server pk)
  |-- RegistrationRecord -------->   |   (envelope + client pk; stored in DB)


LOGIN (3 messages)

Client                              Server
  |-- KE1 ------------------------>  |   (blinded password + ephemeral pk)
  |<-- KE2 -----------------------   |   (OPRF eval + envelope + server MAC)
  |-- KE3 ------------------------>  |   (client MAC)

Both sides derive identical SessionKey.
```

Cryptographic primitives used:

| Role | Primitive |
|---|---|
| OPRF group | Ristretto255 (curve25519-dalek) |
| KDF | HKDF-SHA-512 |
| MAC | HMAC-SHA-512 |
| AKE | 3DH over Ristretto255 |

> **Production note:** The `stretch` function in `utils.rs` is currently the identity function. Before shipping, replace it with Argon2id or scrypt so that `randomized_password` is memory-hard.

---

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
opaque_framework = { git = "https://github.com/YeahNotSewerSide/OPAQUE.git" }
```

---

## Quick start

```rust
use opaque_framework::{NH, client, server::Server};
use rand::RngExt as _;

// --- Server setup (once at startup, share via Arc / Axum State) ---
let mut rng = rand::rng();
let mut oprf_seed = [0u8; NH];
let mut key_seed  = [0u8; 64];
rng.fill(&mut oprf_seed);
rng.fill(&mut key_seed);

let server = Server::new(b"example.com", oprf_seed, key_seed);

// --- Registration ---
let password            = b"correct horse battery staple";
let credential_id       = b"user@example.com";
let client_identity     = b"user@example.com";
let server_identity     = server.identity().to_vec();

// Client → Server
let (blind, reg_request) = client::registration_start(password);

// Server → Client
let mut reg_session = server.initiate_session(credential_id);
let reg_response    = reg_session.registration_start(&reg_request)?;

// Client → Server (store `record` in your DB keyed by credential_id)
let (record, _export_key) =
    client::registration_finish(&blind, &reg_response, &server_identity, client_identity);
let stored_record = reg_session.registration_finish(record)?;

// --- Login ---
// Client → Server
let login_state = client::login_start(password);
let ke1 = &login_state.ke1;

// Server → Client  (load `stored_record` from DB first)
let mut login_session = server.initiate_session(credential_id);
let ke2 = login_session.login_start(ke1, &stored_record, client_identity)?;

// Client → Server
let (ke3, client_key, _export_key) =
    client::login_finish(login_state, &ke2, &server_identity, client_identity)?;

// Server - verify and obtain session key
let server_key = login_session.login_finish(&ke3)?;

assert_eq!(client_key.0, server_key.0); // identical session keys ✓
```

See [`examples/full_flow.rs`](examples/full_flow.rs) for the complete working example including JWT minting.

---

## Using the session key

`SessionKey` wraps a 64-byte symmetric key shared by both parties after a successful login. Two JWT helpers are provided:

```rust
use jsonwebtoken::Header;

#[derive(serde::Serialize, serde::Deserialize)]
struct Claims { sub: String, exp: usize, aud: String }

let token  = session_key.mint_jwt(&Header::default(), &claims)?;
let claims = session_key.verify_jwt::<Claims>(&token)?;
```

`verify_jwt` expects the audience claim to equal `"access"` and uses HS256.

---

## Module structure

| Module | Description |
|---|---|
| `server` | `Server` (long-lived config) and `OpaqueSession` (per-request state machine) |
| `client` | Stateless free functions for registration and login |
| `wire_structs` | Plain byte-array structs that cross the network |
| `utils` | Cryptographic primitives (OPRF, HKDF, HMAC, 3DH helpers) |

---

## Security considerations

- **OPRF seed and server key seed must be secret and persistent.** Losing them invalidates all existing registration records.
- **`credential_identifier`** must uniquely identify a user server-side. Using the same value as `client_identity` (e.g. email) is fine.
- **`export_key`** is a 64-byte key derived from the client's password that the server never sees. It can be used for end-to-end encrypted storage or other client-side secrets.
- **Password stretching** is currently a no-op. Replace `stretch()` in `utils.rs` with Argon2id before production use.
- Wire structs have no serialization layer - add `serde` derives or manual encoding before sending over a real transport.

---

## Running the example

```sh
cargo run --example full_flow
```

---

## License

MIT
