// =============================================================================
// main — full flow using the framework
// =============================================================================

use chrono::Duration;
use chrono::Utc;
use jsonwebtoken::Header;
use opaque_framework::NH;
use opaque_framework::client;
use opaque_framework::server::*;
use opaque_framework::wire_structs::Ke1;
use rand::RngExt as _;

fn main() {
    // =========================================================================
    // Server setup — create once, share via Arc (e.g. Axum state)
    // =========================================================================
    let mut rng = rand::rng();
    let mut oprf_seed = [0u8; NH];
    rng.fill(&mut oprf_seed);
    let mut key_seed = [0u8; 64];
    rng.fill(&mut key_seed);

    let server = Server::new(b"example.com".to_vec(), oprf_seed, key_seed);
    println!("=== SERVER SETUP ===");
    println!("server_pk[:8]: {:?}\n", &server.public_key_bytes()[..8]);

    let credential_identifier = b"user@example.com";
    let client_identity = b"user@example.com";
    let server_identity = server.identity().to_vec();
    let password = b"correct horse battery staple";

    // =========================================================================
    // REGISTRATION
    // =========================================================================
    println!("=== REGISTRATION ===");

    // [CLIENT] step 1
    let (blind, reg_request) = client::registration_start(password);
    println!("[client → server] RegistrationRequest");

    // [SERVER] step 1 — initiate a session for this credential
    let mut reg_session = server.initiate_session(credential_identifier.to_vec());
    let reg_response = reg_session.registration_start(&reg_request).unwrap();
    println!("[server → client] RegistrationResponse");

    // [CLIENT] step 2 — finalize, get record + export_key
    let (record, export_key_reg) =
        client::registration_finish(&blind, &reg_response, &server_identity, client_identity);
    println!("[client → server] RegistrationRecord");
    println!("  client_pk[:8]:   {:?}", &record.client_public_key[..8]);
    println!("  masking_key[:8]: {:?}", &record.masking_key[..8]);

    // [SERVER] step 2 — store record (caller would persist to DB here)
    let stored_record = reg_session.registration_finish(record).unwrap();
    println!("[server] record stored\n");

    // =========================================================================
    // LOGIN
    // =========================================================================
    println!("=== LOGIN ===");

    // [CLIENT] step 1
    let login_state = client::login_start(password);
    println!("[client → server] KE1");
    println!(
        "  client_nonce[:8]:       {:?}",
        &login_state.ke1.client_nonce[..8]
    );
    let ke1 = Ke1 {
        blinded_element: login_state.ke1.blinded_element,
        client_nonce: login_state.ke1.client_nonce,
        client_ephemeral_pk: login_state.ke1.client_ephemeral_pk,
    };

    // [SERVER] step 1 — new session for login (stateless: each login gets its own session)
    let mut login_session = server.initiate_session(credential_identifier.to_vec());
    let ke2 = login_session
        .login_start(&ke1, &stored_record, client_identity)
        .unwrap();
    println!("[server → client] KE2");
    println!("  server_nonce[:8]:       {:?}", &ke2.server_nonce[..8]);
    println!(
        "  server_ephemeral_pk[:8]:{:?}",
        &ke2.server_ephemeral_pk[..8]
    );
    println!("  server_mac[:8]:         {:?}", &ke2.server_mac[..8]);

    // [CLIENT] step 2 — verify server, produce KE3 + session_key
    let (ke3, client_session_key, export_key_login) =
        client::login_finish(login_state, &ke2, &server_identity, client_identity).unwrap();
    println!("[client → server] KE3");
    println!("  client_mac[:8]: {:?}", &ke3.client_mac[..8]);

    // [SERVER] step 2 — verify client, get session_key
    let server_session_key = login_session.login_finish(&ke3).unwrap();

    assert_eq!(
        client_session_key.0, server_session_key.0,
        "session keys must match"
    );
    assert_eq!(export_key_login, export_key_reg, "export_key must match");
    println!("\n[both] session_key matches ✓");
    println!("[both] export_key matches  ✓");
    println!("session_key[:8]: {:?}\n", &server_session_key.0[..8]);

    // =========================================================================
    // JWT
    // =========================================================================
    println!("=== JWT ===");
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    pub struct Claims {
        pub sub: String,
        pub exp: usize,
        pub aud: String,
    }
    let exp = (Utc::now() + Duration::minutes(10)).timestamp() as usize;
    let claims = Claims {
        sub: "user@example.com".to_string(),
        exp,
        aud: "access".into(),
    };

    let token = server_session_key
        .mint_jwt(&Header::default(), &claims)
        .unwrap();
    println!("[server] minted: {}...", &token);
    let claims = server_session_key.verify_jwt::<Claims>(&token).unwrap();
    println!("[server] verified, claims={:?} ✓", claims);
    assert_eq!(claims.sub, "user@example.com");

    println!("\nAll checks passed.");
}
