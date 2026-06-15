//! Low-level cryptographic primitives used by [`client`] and [`server`].
//!
//! Not part of the stable public API — subject to change without notice.
//! Consumers should go through the `client` and `server` modules.

use curve25519_dalek::{RistrettoPoint, Scalar, ristretto::CompressedRistretto};
use hkdf::Hkdf;
use hmac::digest::KeyInit;
use rand::RngExt as _;
use sha2::{Digest as _, Sha512};

use crate::{
    HmacSha512, NH, NM, NN,
    wire_structs::{Ke1, Ke2},
};

// =============================================================================
// Primitives
// =============================================================================

/// HKDF-Extract (RFC 5869) with SHA-512.
/// Returns a 64-byte pseudorandom key.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; NH] {
    let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
    prk.into()
}

/// HKDF-Expand (RFC 5869) with SHA-512.
/// `len` must not exceed 255 × 64 bytes.
pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let h = Hkdf::<Sha512>::from_prk(prk).unwrap();
    let mut okm = vec![0u8; len];
    h.expand(info, &mut okm).unwrap();
    okm
}

/// Derives a labeled 64-byte secret: `HKDF-Expand(prk, label || context, 64)`.
pub fn derive_secret(prk: &[u8], label: &[u8], context: &[u8]) -> [u8; NH] {
    let info: Vec<u8> = [label, context].concat();
    let out = hkdf_expand(prk, &info, NH);
    out.try_into().unwrap()
}

/// HMAC-SHA-512 over `msg` with `key`. Returns 64 bytes.
pub fn mac_fn(key: &[u8], msg: &[u8]) -> [u8; NM] {
    use hmac::Mac;
    let mut h = <HmacSha512 as KeyInit>::new_from_slice(key).unwrap();
    h.update(msg);
    h.finalize().into_bytes().into()
}

/// SHA-512 of `msg`. Returns 64 bytes.
pub fn hash(msg: &[u8]) -> [u8; NH] {
    Sha512::digest(msg).into()
}

/// Scalar multiplication on Ristretto255: returns `(point × scalar)` compressed.
pub fn dh(scalar: &Scalar, point: &RistrettoPoint) -> [u8; 32] {
    (point * scalar).compress().to_bytes()
}

/// Decompress a 32-byte Ristretto255 point.
///
/// # Panics
/// Panics if `bytes` is not a valid compressed Ristretto255 point.
pub fn decompress(bytes: &[u8; 32]) -> RistrettoPoint {
    CompressedRistretto(*bytes).decompress().unwrap()
}

/// Deterministically derive a Ristretto255 keypair from `seed` via HKDF.
///
/// Returns `(scalar, public_key)`.
pub fn derive_dh_keypair(seed: &[u8]) -> (Scalar, RistrettoPoint) {
    let prk = hkdf_extract(b"OPAQUE-DeriveKeyPair", seed);
    let expanded = hkdf_expand(&prk, b"OPAQUE-DeriveKeyPair", 64);
    let sk = Scalar::from_bytes_mod_order_wide(expanded[..64].try_into().unwrap());
    (sk, RistrettoPoint::mul_base(&sk))
}

// NOTE: Stretch(msg) — identity; replace with Argon2id in production
// TODO: Function should accept also algorithm to use
fn stretch(msg: &[u8]) -> Vec<u8> {
    msg.to_vec()
}

/// Derive the per-client OPRF scalar from the server's global seed
/// and the client's `credential_identifier` — RFC 9807 §5.2.2.
pub fn oprf_derive_key(oprf_seed: &[u8; NH], credential_identifier: &[u8]) -> Scalar {
    // RFC 9807 §5.2.2: seed = Expand(oprf_seed, cred_id || "OprfKey", Nok)
    let seed = hkdf_expand(oprf_seed, &[credential_identifier, b"OprfKey"].concat(), 64);
    Scalar::from_bytes_mod_order_wide(seed[..64].try_into().unwrap())
}

/// Hash `password` to a Ristretto255 point and apply a random blinding scalar.
///
/// Returns `(blind, blinded_element)`.
/// The caller must keep `blind` to call [`oprf_finalize`] later.
pub fn oprf_blind(password: &[u8]) -> (Scalar, RistrettoPoint) {
    let point = RistrettoPoint::from_uniform_bytes(&hash(password));
    let mut rng = rand::rng();
    let mut bytes = [0u8; 64];
    rng.fill(&mut bytes);
    let blind = Scalar::from_bytes_mod_order_wide(&bytes);
    (blind, point * blind)
}

/// Remove the blinding scalar from the server's evaluated element and hash
/// the result to produce the 64-byte OPRF output.
pub fn oprf_finalize(evaluated: &RistrettoPoint, blind: &Scalar) -> [u8; NH] {
    hash((evaluated * blind.invert()).compress().as_bytes())
}

/// Derive the randomized password from the OPRF output (RFC 9807 §3.2.1).
///
/// The result is the key from which envelope keys and the client keypair
/// are derived. Currently uses an identity `stretch` function — replace
/// with Argon2id before production use.
pub fn randomized_password(oprf_output: &[u8; NH]) -> [u8; NH] {
    let stretched = stretch(oprf_output);
    hkdf_extract(b"", &[oprf_output.as_ref(), stretched.as_slice()].concat())
}

/// Build the envelope auth tag message:
/// `nonce || server_pk || u16(len(server_id)) || server_id || u16(len(client_id)) || client_id`
pub fn envelope_mac_msg(
    nonce: &[u8; NN],
    server_pk: &[u8],
    server_identity: &[u8],
    client_identity: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        NN + server_pk.len() + server_identity.len() + client_identity.len() + 2 + 2,
    );
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(server_pk);
    msg.extend_from_slice(&(server_identity.len() as u16).to_be_bytes());
    msg.extend_from_slice(server_identity);
    msg.extend_from_slice(&(client_identity.len() as u16).to_be_bytes());
    msg.extend_from_slice(client_identity);
    msg
}

fn ke1_bytes(ke1: &Ke1) -> Vec<u8> {
    [
        ke1.blinded_element.as_ref(),
        ke1.client_nonce.as_ref(),
        ke1.client_ephemeral_pk.as_ref(),
    ]
    .concat()
}

fn credential_response_bytes(ke2: &Ke2) -> Vec<u8> {
    [
        ke2.evaluated_element.as_ref(),
        ke2.envelope_nonce.as_ref(),
        ke2.envelope_auth_tag.as_ref(),
    ]
    .concat()
}

/// Build the KE2 transcript preamble used in MAC and key derivation.
/// Format: `"OPAQUEv1-" || u16(len(ctx)) || ctx || u16(len(cid)) || cid || KE1 || u16(len(sid)) || sid || CredentialResponse || server_nonce || server_ephemeral_pk`
pub fn build_preamble(
    client_identity: &[u8],
    ke1: &Ke1,
    server_identity: &[u8],
    ke2: &Ke2,
) -> Vec<u8> {
    let context = b"";
    let mut p = Vec::new();
    p.extend_from_slice(b"OPAQUEv1-");
    p.extend_from_slice(&(context.len() as u16).to_be_bytes());
    p.extend_from_slice(context);
    p.extend_from_slice(&(client_identity.len() as u16).to_be_bytes());
    p.extend_from_slice(client_identity);
    p.extend_from_slice(&ke1_bytes(ke1));
    p.extend_from_slice(&(server_identity.len() as u16).to_be_bytes());
    p.extend_from_slice(server_identity);
    p.extend_from_slice(&credential_response_bytes(ke2));
    p.extend_from_slice(&ke2.server_nonce);
    p.extend_from_slice(&ke2.server_ephemeral_pk);
    p
}

/// Derive `(km2, km3, session_key)` from the 3DH IKM and transcript preamble.
///
/// - `km2` — key for the server MAC
/// - `km3` — key for the client MAC
/// - `session_key` — 64-byte shared secret
pub fn derive_keys(ikm: &[u8], preamble: &[u8]) -> ([u8; NH], [u8; NH], [u8; NH]) {
    let prk = hkdf_extract(b"", ikm);
    let preamble_hash = hash(preamble);
    let handshake_secret = derive_secret(&prk, b"HandshakeSecret", &preamble_hash);
    let session_key = derive_secret(&prk, b"SessionKey", &preamble_hash);
    let km2 = derive_secret(&handshake_secret, b"ServerMAC", b"");
    let km3 = derive_secret(&handshake_secret, b"ClientMAC", b"");
    (km2, km3, session_key)
}
