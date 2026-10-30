use shadowborn_core::*;
fn key(c: char) -> String {
    format!("{}A=", c.to_string().repeat(42))
}
fn fixture() -> State {
    State {
        schema_version: 1,
        config: Config::parse(include_str!("../../../config/server.example.toml")).unwrap(),
        server_private_key: Secret::new(key('B')).unwrap(),
        server_public_key: key('C'),
        peers: vec![],
    }
}
#[test]
fn unsafe_configuration_is_rejected() {
    let input = include_str!("../../../config/server.example.toml");
    for (from, to) in [
        ("query_logging = false", "query_logging = true"),
        ("no_activity_logs = true", "no_activity_logs = false"),
        ("telemetry = false", "telemetry = true"),
        ("store_peer_activity = false", "store_peer_activity = true"),
        ("peer_isolation = true", "peer_isolation = false"),
        (
            "restrict_peer_lan_access = true",
            "restrict_peer_lan_access = false",
        ),
        (
            "public_management_api = false",
            "public_management_api = true",
        ),
        (
            "auto_apply_on_install = false",
            "auto_apply_on_install = true",
        ),
        ("10.89.0.1/24", "10.89.0.0/24"),
        ("ens3", "eth0;id"),
        ("198.51.100.8/32", "0.0.0.0/0"),
        ("schema_version = 1", "schema_version = 2"),
    ] {
        assert!(Config::parse(&input.replace(from, to)).is_err(), "{to}");
    }
    assert!(Config::parse(&format!("{input}\nunknown = true\n")).is_err());
}
#[test]
fn peer_allocation_duplicate_keys_and_revocation() {
    let mut state = fixture();
    state
        .add("laptop".into(), key('D'), Secret::new(key('E')).unwrap())
        .unwrap();
    assert_eq!(state.peers[0].address.to_string(), "10.89.0.2");
    assert!(state
        .add("other".into(), key('D'), Secret::new(key('F')).unwrap())
        .is_err());
    let old = state.clone();
    state.disable("laptop", true).unwrap();
    assert!(state.peers[0].psk.is_none());
    state.disable("laptop", false).unwrap();
    assert_eq!(state.peers[0].status, PeerStatus::Revoked);
    assert!(state
        .add("laptop".into(), key('F'), Secret::new(key('G')).unwrap())
        .is_err());
    let restored = state.restore_authorization(old).unwrap();
    assert_eq!(restored.peers[0].status, PeerStatus::Revoked);
    assert!(!server_wireguard(&restored).unwrap().contains("[Peer]"));
}
#[test]
fn disabled_peer_cannot_be_reenabled_by_old_backup() {
    let mut state = fixture();
    let empty = state.clone();
    state
        .add("laptop".into(), key('D'), Secret::new(key('E')).unwrap())
        .unwrap();
    state.disable("laptop", false).unwrap();
    let restored = state.restore_authorization(empty).unwrap();
    assert_eq!(restored.peers[0].status, PeerStatus::Disabled);
    assert!(client_template(&restored, "laptop").is_err());
}
#[test]
fn canonical_key_and_input_boundaries() {
    for name in ["../../x", "--help", "x\nPostUp=id", "x;id", ""] {
        assert!(!valid_name(name));
    }
    assert!(validate_key(&format!("{}=", "A".repeat(43))).is_err());
    assert!(validate_key(&format!("{}B=", "B".repeat(42))).is_err());
    assert!(validate_key(&key('B')).is_ok());
    let mut state = fixture();
    assert!(state
        .add(
            "laptop".into(),
            state.server_public_key.clone(),
            Secret::new(key('D')).unwrap()
        )
        .is_err());
}
#[test]
fn firewall_and_wireguard_bound_each_peer() {
    let mut state = fixture();
    state
        .add("laptop".into(), key('D'), Secret::new(key('E')).unwrap())
        .unwrap();
    let wg = server_wireguard(&state).unwrap();
    let nft = server_firewall(&state).unwrap();
    assert!(wg.contains("AllowedIPs = 10.89.0.2/32"));
    assert!(!wg.contains("0.0.0.0/0"));
    assert!(nft.contains("169.254.0.0/16"));
    assert!(nft.contains("iifname \"wg-shadowborn\" jump vpn_input"));
    assert!(nft.contains("oifname \"ens3\" ip saddr @peers accept"));
    assert!(nft.contains("meta nfproto ipv6 drop"));
    assert!(!nft.contains("flush ruleset"));
    assert!(
        nft.find("jump vpn_input").unwrap()
            < nft.find("ct state established,related accept").unwrap()
    );
    let client = client_template(&state, "laptop").unwrap();
    assert!(client.contains("0.0.0.0/0, ::/0"));
    assert!(client.contains("<DEVICE_PRIVATE_KEY>"));
    assert!(!client.contains(state.server_private_key.expose()));
}
#[test]
fn no_activity_history_in_state_or_generated_services() {
    let state = fixture();
    let serialized = serde_json::to_value(&state).unwrap();
    let mut fields = serialized
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort();
    assert_eq!(
        fields,
        vec![
            "config",
            "peers",
            "schema_version",
            "server_private_key",
            "server_public_key"
        ]
    );
    let files = bundle(&state).unwrap();
    for (name, content) in &files {
        if name.ends_with(".service") || name == "wg-quick-shadowborn.conf" {
            for directive in ["StandardOutput=null", "StandardError=null", "LimitCORE=0"] {
                assert!(content.contains(directive));
            }
        }
        for forbidden in [
            "nflog",
            " log prefix",
            "counter",
            "PostUp",
            "SaveConfig = true",
            "syslog: yes",
            "log-queries: yes",
            "log-replies: yes",
            "log-servfail: yes",
        ] {
            assert!(!content.contains(forbidden), "{name}: {forbidden}");
        }
    }
    let dns = &files["unbound.conf"];
    for expected in [
        "use-syslog: no",
        "log-queries: no",
        "log-replies: no",
        "log-servfail: no",
        "statistics-interval: 0",
        "control-enable: no",
        "forward-first: no",
        "@853#dns.quad9.net",
    ] {
        assert!(dns.contains(expected));
    }
    assert!(!format!("{state:?}").contains(state.server_private_key.expose()));
    assert!(
        !serde_json::to_string(&plan(&state.config, Some(&state)).unwrap())
            .unwrap()
            .contains(state.server_private_key.expose())
    );
}
#[test]
fn state_rejects_added_history_and_corrupt_address_assignments() {
    let mut state = fixture();
    state
        .add("laptop".into(), key('D'), Secret::new(key('E')).unwrap())
        .unwrap();
    state.peers[0].address = "10.90.0.2".parse().unwrap();
    assert!(state.validate().is_err());
    let mut value = serde_json::to_value(fixture()).unwrap();
    value["handshake_history"] = serde_json::json!([]);
    assert!(serde_json::from_value::<State>(value).is_err());
}
