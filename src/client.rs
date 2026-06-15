use curve25519_dalek::Scalar;
use rand::RngExt as _;

use crate::{
    NH, NN, NSEED, OpaqueError,
    server::SessionKey,
    utils::{
        build_preamble, decompress, derive_dh_keypair, derive_keys, dh, envelope_mac_msg, hash,
        hkdf_expand, mac_fn, oprf_blind, oprf_finalize, randomized_password,
    },
    wire_structs::{Ke1, Ke2, Ke3, RegistrationRecord, RegistrationRequest, RegistrationResponse},
};

pub struct ClientLoginState {
    pub blind: Scalar,
    pub client_ephemeral_sk: Scalar,
    pub ke1: Ke1,
}
/// Registration step 1 (client): blind password, build RegistrationRequest.
pub fn registration_start(password: &[u8]) -> (Scalar, RegistrationRequest) {
    let (blind, blinded) = oprf_blind(password);
    (
        blind,
        RegistrationRequest {
            blinded_element: blinded.compress().to_bytes(),
        },
    )
}

/// Registration step 2 (client): finalize OPRF, build envelope, return record + export_key.
/// RFC 9807 §5.2.3 FinalizeRegistrationRequest.
pub fn registration_finish(
    blind: &Scalar,
    response: &RegistrationResponse,
    server_identity: &[u8],
    client_identity: &[u8],
) -> (RegistrationRecord, [u8; NH]) {
    let evaluated = decompress(&response.evaluated_element);
    let oprf_output = oprf_finalize(&evaluated, blind);
    let rand_pwd = randomized_password(&oprf_output);

    let mut rng = rand::rng();
    let mut nonce = [0u8; NN];
    rng.fill(&mut nonce);

    let masking_key_vec = hkdf_expand(&rand_pwd, b"MaskingKey", NH);
    let auth_key = hkdf_expand(&rand_pwd, &[&nonce[..], b"AuthKey"].concat(), NH);
    let export_key_vec = hkdf_expand(&rand_pwd, &[&nonce[..], b"ExportKey"].concat(), NH);
    let pk_seed = hkdf_expand(&rand_pwd, &[&nonce[..], b"PrivateKey"].concat(), NSEED);

    let (_, client_pk) = derive_dh_keypair(&pk_seed);
    let client_pk_bytes: [u8; 32] = client_pk.compress().to_bytes();

    let mac_msg = envelope_mac_msg(
        &nonce,
        &response.server_public_key,
        server_identity,
        client_identity,
    );
    let auth_tag = mac_fn(&auth_key, &mac_msg);

    let mut masking_key = [0u8; NH];
    masking_key.copy_from_slice(&masking_key_vec);
    let mut export_key = [0u8; NH];
    export_key.copy_from_slice(&export_key_vec);

    (
        RegistrationRecord {
            client_public_key: client_pk_bytes,
            masking_key,
            envelope_nonce: nonce,
            envelope_auth_tag: auth_tag,
        },
        export_key,
    )
}

/// Login step 1 (client): blind password, generate ephemeral keypair, build KE1.
/// RFC 9807 §6.2.1 GenerateKE1.
pub fn login_start(password: &[u8]) -> ClientLoginState {
    let (blind, blinded) = oprf_blind(password);
    let mut rng = rand::rng();
    let mut client_nonce = [0u8; NN];
    rng.fill(&mut client_nonce);
    let mut keyshare_seed = [0u8; NSEED];
    rng.fill(&mut keyshare_seed);
    let (client_ephemeral_sk, client_ephemeral_pk) = derive_dh_keypair(&keyshare_seed);
    let ke1 = Ke1 {
        blinded_element: blinded.compress().to_bytes(),
        client_nonce,
        client_ephemeral_pk: client_ephemeral_pk.compress().to_bytes(),
    };
    ClientLoginState {
        blind,
        client_ephemeral_sk,
        ke1,
    }
}

/// Login step 2 (client): recover credentials from envelope, run 3DH, verify server,
/// produce KE3 + session_key + export_key.
/// RFC 9807 §6.2.3 GenerateKE3 + §6.4.3 AuthClientFinalize.
pub fn login_finish(
    state: ClientLoginState,
    ke2: &Ke2,
    server_identity: &[u8],
    client_identity: &[u8],
) -> Result<(Ke3, SessionKey, [u8; NH]), OpaqueError> {
    // Recover randomized_password
    let evaluated = decompress(&ke2.evaluated_element);
    let oprf_output = oprf_finalize(&evaluated, &state.blind);
    let rand_pwd = randomized_password(&oprf_output);

    // Recover client keypair from envelope (RFC 9807 §4.1.3)
    let auth_key = hkdf_expand(
        &rand_pwd,
        &[ke2.envelope_nonce.as_ref(), b"AuthKey"].concat(),
        NH,
    );
    let export_key_vec = hkdf_expand(
        &rand_pwd,
        &[ke2.envelope_nonce.as_ref(), b"ExportKey"].concat(),
        NH,
    );
    let pk_seed = hkdf_expand(
        &rand_pwd,
        &[ke2.envelope_nonce.as_ref(), b"PrivateKey"].concat(),
        NSEED,
    );

    let (client_sk, client_pk) = derive_dh_keypair(&pk_seed);
    let client_pk_bytes: [u8; 32] = client_pk.compress().to_bytes();

    // Verify envelope auth tag
    let mac_msg = envelope_mac_msg(
        &ke2.envelope_nonce,
        &ke2.server_public_key,
        server_identity,
        client_identity,
    );
    let expected_tag = mac_fn(&auth_key, &mac_msg);
    if ke2.envelope_auth_tag != expected_tag {
        return Err(OpaqueError::EnvelopeRecoveryError);
    }

    // 3DH — client perspective (§6.4.3):
    //   dh1 = client_ephemeral_sk × server_ephemeral_pk  (ephemeral–ephemeral)
    //   dh2 = client_ephemeral_sk × server_static_pk     (ephemeral–static)
    //   dh3 = client_static_sk   × server_ephemeral_pk  (static–ephemeral)
    let server_ephemeral_pk = decompress(&ke2.server_ephemeral_pk);
    let server_static_pk = decompress(&ke2.server_public_key);
    let dh1 = dh(&state.client_ephemeral_sk, &server_ephemeral_pk);
    let dh2 = dh(&state.client_ephemeral_sk, &server_static_pk);
    let dh3 = dh(&client_sk, &server_ephemeral_pk);
    let ikm: Vec<u8> = [dh1.as_ref(), dh2.as_ref(), dh3.as_ref()].concat();

    let preamble = build_preamble(client_identity, &state.ke1, server_identity, ke2);
    let (km2, km3, session_key) = derive_keys(&ikm, &preamble);

    let expected_server_mac = mac_fn(&km2, &hash(&preamble));
    if ke2.server_mac != expected_server_mac {
        return Err(OpaqueError::ServerAuthenticationError);
    }

    let client_mac = mac_fn(
        &km3,
        &hash(&[preamble.as_slice(), expected_server_mac.as_ref()].concat()),
    );

    let mut export_key = [0u8; NH];
    export_key.copy_from_slice(&export_key_vec);
    let _ = client_pk_bytes; // suppress unused warning

    Ok((Ke3 { client_mac }, SessionKey(session_key), export_key))
}
