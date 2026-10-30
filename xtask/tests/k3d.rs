#![forbid(unsafe_code)]
use serde_json::json;
use xtask::{Result, deployment, grype, sbom, security, util};

#[test]
fn fixed_k3d_configuration_is_private_pinned_and_addon_free() -> Result {
    let name = "sync-smoke-fixture";
    let volume = format!("k3d-{name}-data");
    let config = deployment::k3d_config(name, &volume, 12345)?;
    assert_eq!(config["image"], deployment::K3S);
    assert_eq!(config["servers"], 1);
    assert_eq!(config["agents"], 0);
    assert_eq!(config["kubeAPI"]["hostIP"], "127.0.0.1");
    assert_eq!(
        config["options"]["kubeconfig"]["updateDefaultKubeconfig"],
        false
    );
    assert_eq!(
        config["options"]["kubeconfig"]["switchCurrentContext"],
        false
    );
    assert_eq!(config["options"]["k3d"]["disableLoadbalancer"], true);
    assert_eq!(config["options"]["runtime"]["hostPidMode"], false);
    assert_eq!(config["options"]["runtime"]["serversMemory"], "4g");
    let args = config["options"]["k3s"]["extraArgs"].as_array().unwrap();
    assert!(
        args.iter()
            .any(|v| v["arg"] == format!("--pause-image={}", deployment::PAUSE))
    );
    assert!(args.iter().any(|v| v["arg"] == "--disable=coredns,traefik,servicelb,metrics-server,local-storage"));
    assert!(args.iter().any(|v| v["arg"] == "--disable-helm-controller"));
    for bad in [
        "default",
        "sync-smoke-../escape",
        "sync-smoke-UPPER",
        "sync-smoke-abcdefghijklmnopqrstuvwxyz",
    ] {
        assert!(deployment::k3d_config(bad, &volume, 12345).is_err());
    }
    for bad in ["/operator/data", "unowned-volume", "data:/other", "${HOME}"] {
        assert!(deployment::k3d_config(name, bad, 12345).is_err());
    }
    assert!(deployment::k3d_config(name, &volume, 0).is_err());
    let root = xtask::root();
    let inventory = security::inventory(&root)?;
    for image in [deployment::K3S, deployment::K3D_TOOLS, deployment::PAUSE] {
        assert!(inventory.contains_key(image));
    }
    assert!(!inventory.keys().any(|v| v.starts_with("kindest/node:")));
    Ok(())
}

#[test]
#[ignore = "fixed public pause-image catalog diagnostic; network retrieval only, no vulnerability/acceptance claim"]
fn pause_catalog_records_missing_inventory_not_zero_findings() -> Result {
    let root = xtask::root();
    let directory = root.join(".work/k3d-pause-diagnostic");
    std::fs::create_dir(&directory)?;
    std::fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    for (name, platform) in [("amd64", "linux/amd64"), ("arm64", "linux/arm64")] {
        let container = util::Container::new(&root, "sync-pause-diagnostic");
        let mut command = util::cmd("docker", &[], &root);
        command.args(security::sandbox_args(&container.name)).args([
            "--env",
            "SYFT_CHECK_FOR_APP_UPDATE=false",
            sbom::SYFT,
            &format!("registry:{}", deployment::PAUSE),
            "--platform",
            platform,
            "-o",
            "syft-json",
        ]);
        let bytes = util::output(&mut command, 300)?;
        let catalog = util::strict_json(&bytes)?;
        let packages = catalog["artifacts"]
            .as_array()
            .ok_or("Missing pause catalog artifacts")?;
        std::fs::write(directory.join(format!("{name}.syft.json")), &bytes)?;
        util::write_json(
            &directory.join(format!("{name}.json")),
            &json!({
                "image":deployment::PAUSE,"requested_platform":platform,
            "subject_validation":"rejected-vacuous-catalog",
                "catalog_digest":util::digest(&bytes),"packages":packages.len(),"findings":null,
                "native_inventory_approved":false,"release_accepted":false,
                "scope":"catalog diagnostic only; no vulnerability scan or missing-payload waiver"
            }),
        )?;
        assert!(
            packages.is_empty(),
            "Review changed pause catalog capability rather than infer acceptance"
        );
        assert!(grype::image_subject(&catalog).is_err());
    }
    Ok(())
}

#[test]
fn kubeconfig_rejects_remote_extra_external_and_missing_credentials() -> Result {
    let base = json!({
        "current-context":"k3d-sync-smoke-fixture",
        "contexts":[{"name":"k3d-sync-smoke-fixture","context":{"cluster":"fixture","user":"fixture-user"}}],
        "clusters":[{"name":"fixture","cluster":{"server":"https://127.0.0.1:12345","certificate-authority-data":"synthetic"}}],
        "users":[{"name":"fixture-user","user":{"client-certificate-data":"synthetic","client-key-data":"synthetic"}}]
    });
    deployment::private_kubeconfig(&base, "sync-smoke-fixture", 12345)?;
    for (path, value) in [
        ("/current-context", json!("operator")),
        (
            "/clusters/0/cluster/server",
            json!("https://provider.invalid:12345"),
        ),
        ("/clusters/0/cluster/server", json!("https://0.0.0.0:12345")),
        (
            "/clusters/0/cluster/server",
            json!("https://localhost:12345"),
        ),
        (
            "/clusters/0/cluster/certificate-authority-data",
            json!(null),
        ),
        ("/users/0/user/client-key-data", json!("")),
        ("/users/0/user/client-certificate-data", json!(null)),
        ("/clusters/0/name", json!(null)),
        ("/contexts/0/context/user", json!("operator")),
        ("/users", json!([])),
    ] {
        let mut value_base = base.clone();
        *value_base.pointer_mut(path).unwrap() = value;
        assert!(
            deployment::private_kubeconfig(&value_base, "sync-smoke-fixture", 12345).is_err(),
            "{path}"
        );
    }
    for key in [
        "exec",
        "auth-provider",
        "token",
        "client-key",
        "client-certificate",
    ] {
        let mut value = base.clone();
        value["users"][0]["user"][key] = json!("synthetic external authority");
        assert!(deployment::private_kubeconfig(&value, "sync-smoke-fixture", 12345).is_err());
    }
    for field in ["clusters", "users", "contexts"] {
        let mut value = base.clone();
        let extra = value[field][0].clone();
        value[field].as_array_mut().unwrap().push(extra);
        assert!(deployment::private_kubeconfig(&value, "sync-smoke-fixture", 12345).is_err());
    }
    Ok(())
}
