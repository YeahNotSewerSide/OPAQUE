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

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; NH] {
    let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
    prk.into()
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let h = Hkdf::<Sha512>::from_prk(prk).unwrap();
    let mut okm = vec![0u8; len];
    h.expand(info, &mut okm).unwrap();
    okm
}

pub fn derive_secret(prk: &[u8], label: &[u8], context: &[u8]) -> [u8; NH] {
    let info: Vec<u8> = [label, context].concat();
    let out = hkdf_expand(prk, &info, NH);
    out.try_into().unwrap()
}

pub fn mac_fn(key: &[u8], msg: &[u8]) -> [u8; NM] {
    use hmac::Mac;
    let mut h = <HmacSha512 as KeyInit>::new_from_slice(key).unwrap();
    h.update(msg);
    h.finalize().into_bytes().into()
}

pub fn hash(msg: &[u8]) -> [u8; NH] {
    Sha512::digest(msg).into()
}

pub fn dh(scalar: &Scalar, point: &RistrettoPoint) -> [u8; 32] {
    (point * scalar).compress().to_bytes()
}

pub fn decompress(bytes: &[u8; 32]) -> RistrettoPoint {
    CompressedRistretto(*bytes).decompress().unwrap()
}

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

pub fn oprf_derive_key(oprf_seed: &[u8; NH], credential_identifier: &[u8]) -> Scalar {
    // RFC 9807 §5.2.2: seed = Expand(oprf_seed, cred_id || "OprfKey", Nok)
    let seed = hkdf_expand(oprf_seed, &[credential_identifier, b"OprfKey"].concat(), 64);
    Scalar::from_bytes_mod_order_wide(seed[..64].try_into().unwrap())
}

pub fn oprf_blind(password: &[u8]) -> (Scalar, RistrettoPoint) {
    let point = RistrettoPoint::from_uniform_bytes(&hash(password));
    let mut rng = rand::rng();
    let mut bytes = [0u8; 64];
    rng.fill(&mut bytes);
    let blind = Scalar::from_bytes_mod_order_wide(&bytes);
    (blind, point * blind)
}

pub fn oprf_finalize(evaluated: &RistrettoPoint, blind: &Scalar) -> [u8; NH] {
    hash((evaluated * blind.invert()).compress().as_bytes())
}

pub fn randomized_password(oprf_output: &[u8; NH]) -> [u8; NH] {
    let stretched = stretch(oprf_output);
    hkdf_extract(b"", &[oprf_output.as_ref(), stretched.as_slice()].concat())
}

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

pub fn derive_keys(ikm: &[u8], preamble: &[u8]) -> ([u8; NH], [u8; NH], [u8; NH]) {
    let prk = hkdf_extract(b"", ikm);
    let preamble_hash = hash(preamble);
    let handshake_secret = derive_secret(&prk, b"HandshakeSecret", &preamble_hash);
    let session_key = derive_secret(&prk, b"SessionKey", &preamble_hash);
    let km2 = derive_secret(&handshake_secret, b"ServerMAC", b"");
    let km3 = derive_secret(&handshake_secret, b"ClientMAC", b"");
    (km2, km3, session_key)
}

fn base64url(data: &[u8]) -> String {
    base64_encode(data)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

fn base64url_decode(s: &str) -> Vec<u8> {
    let mut t = s.replace('-', "+").replace('_', "/");
    while t.len() % 4 != 0 {
        t.push('=');
    }
    base64_decode(&t)
}

fn base64_encode(data: &[u8]) -> String {
    const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0] as u32,
            if chunk.len() > 1 { chunk[1] as u32 } else { 0 },
            if chunk.len() > 2 { chunk[2] as u32 } else { 0 },
        ];
        let n = (b[0] << 16) | (b[1] << 8) | b[2];
        out.push(C[((n >> 18) & 63) as usize] as char);
        out.push(C[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            C[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            C[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Vec<u8> {
    const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    for chunk in bytes.chunks(4) {
        let i = |c: u8| C.iter().position(|&x| x == c).unwrap() as u32;
        let (b0, b1) = (i(chunk[0]), i(chunk[1]));
        out.push(((b0 << 2) | (b1 >> 4)) as u8);
        if chunk.len() > 2 {
            let b2 = i(chunk[2]);
            out.push(((b1 << 4) | (b2 >> 2)) as u8);
            if chunk.len() > 3 {
                out.push(((b2 << 6) | i(chunk[3])) as u8);
            }
        }
    }
    out
}
