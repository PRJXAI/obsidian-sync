//! Additive, fixed-input Go binary diagnostics, never an image gate or VEX approval.
use serde_json::{Value, json};
use std::{
    collections::BTreeSet, fs, io::Read, os::unix::fs::PermissionsExt, path::Path, time::Duration,
};
use xtask::{Result, deployment, ensure, grype, sbom, security, util};

fn messages(bytes: &[u8]) -> Result<Vec<Value>> {
    Ok(serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<_, _>>()?)
}
fn metadata(bytes: &[u8]) -> Result<Value> {
    let values = messages(bytes)?;
    ensure(values.len() == 2, "Incomplete extraction")?;
    ensure(
        values[0] == json!({"name":"govulncheck-extract","version":"0.1.0"}),
        "Unexpected extraction protocol",
    )?;
    let bin = &values[1];
    ensure(
        bin["goos"] == "linux" && bin["goarch"] == "arm64",
        "Unexpected binary platform",
    )?;
    ensure(
        (bin.get("modules").is_none() || bin["modules"].is_array())
            && bin["goVersion"]
                .as_str()
                .is_some_and(|v| v.starts_with("go1.")),
        "Missing build information",
    )?;
    Ok(bin.clone())
}
fn extracted(bytes: &[u8]) -> Result<Value> {
    let bin = metadata(bytes)?;
    ensure(
        bin["pkgSymbols"].as_array().is_some_and(|s| !s.is_empty()),
        "No symbol coverage",
    )?;
    Ok(bin)
}
fn advisory_id(id: &str) -> bool {
    id.len() == 12
        && id.starts_with("GO-")
        && id.as_bytes()[7] == b'-'
        && id.as_bytes()[3..7].iter().all(u8::is_ascii_digit)
        && id.as_bytes()[8..].iter().all(u8::is_ascii_digit)
}
#[test]
fn incomplete_or_cross_platform_symbols_are_not_negative_evidence() {
    assert!(extracted(b"{}").is_err());
    assert!(metadata(b"{\"name\":\"govulncheck-extract\",\"version\":\"changed\"}\n{}").is_err());
    let mut bin = json!({"goos":"linux","goarch":"arm64","goVersion":"go1.26.8","modules":[],"pkgSymbols":[{"pkg":"main","name":"main"}]});
    let header = json!({"name":"govulncheck-extract","version":"0.1.0"});
    let encode = |v: &Value| format!("{header}\n{v}\n");
    assert!(extracted(encode(&bin).as_bytes()).is_ok());
    bin["goos"] = json!("windows");
    assert!(extracted(encode(&bin).as_bytes()).is_err());
    bin["goos"] = json!("linux");
    bin["pkgSymbols"] = json!([]);
    assert!(extracted(encode(&bin).as_bytes()).is_err());
    assert!(extracted(format!("{}\n{{}}", encode(&bin)).as_bytes()).is_err());
    bin.as_object_mut().expect("object").remove("modules");
    assert!(metadata(encode(&bin).as_bytes()).is_ok());
    assert!(extracted(encode(&bin).as_bytes()).is_err());
    bin["goVersion"] = Value::Null;
    assert!(metadata(encode(&bin).as_bytes()).is_err());
    assert!(advisory_id("GO-2026-6612"));
    for id in [
        "../GO-2026-1",
        "GO-2026-../x",
        "GO-2026-6612/",
        "GO-abcd-1234",
        "GO-ééé-12",
    ] {
        assert!(!advisory_id(id));
    }
}

#[test]
#[ignore = "fixed public-image binary diagnostics; requires the separately built govulncheck v1.9.0 Linux arm64 tool; no approval"]
fn inspect_fixed_go_binaries_offline() -> Result {
    let root = xtask::root();
    util::install_cancellation()?;
    util::local_docker(&root)?;
    let endpoint = if std::env::var("DOCKER_CONTEXT").is_ok_and(|v| !v.is_empty()) {
        None
    } else {
        std::env::var("DOCKER_HOST").ok()
    }
    .map(Ok)
    .unwrap_or_else(|| {
        util::text(
            &mut util::cmd(
                "docker",
                &[
                    "context",
                    "inspect",
                    "--format",
                    "{{.Endpoints.docker.Host}}",
                ],
                &root,
            ),
            30,
        )
    })?;
    ensure(endpoint.starts_with("unix:///"), "Local Docker required")?;
    let docker = || {
        let mut c = util::cmd("docker", &["--host", &endpoint], &root);
        for key in [
            "DOCKER_CONTEXT",
            "DOCKER_HOST",
            "DOCKER_DEFAULT_PLATFORM",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ] {
            c.env_remove(key);
        }
        c
    };
    ensure(
        util::text(
            docker().args(["version", "--format", "{{.Server.Arch}}"]),
            30,
        )? == "arm64",
        "Native arm64 daemon required",
    )?;
    let work = root.join(".work/exploitability-20261030");
    let tool = work.join("go/bin/linux_arm64/govulncheck");
    let tool_metadata = tool.symlink_metadata()?;
    ensure(
        tool_metadata.is_file()
            && tool_metadata.len() > 0
            && tool_metadata.len() <= 64 * 1024 * 1024,
        "Bounded regular govulncheck tool required",
    )?;
    let tool_hash = util::hash(&tool)?;
    let output = work.join("go-symbols");
    ensure(!output.exists(), "Refusing existing diagnostic")?;
    fs::create_dir(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    let db = output.join("db");
    fs::create_dir_all(db.join("index"))?;
    fs::create_dir(db.join("ID"))?;
    let mut inputs = Vec::new();
    let mut modules = BTreeSet::from(["stdlib".to_string()]);
    let targets = [
        (0, grype::GRYPE, "/grype"),
        (1, sbom::SYFT, "/syft"),
        (
            3,
            "docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b",
            "/bin/dockerfile-frontend",
        ),
        (4, security::GITLEAKS, "/usr/bin/gitleaks"),
        (5, deployment::K3D_TOOLS, "/app/k3d-tools"),
        (6, deployment::K3S, "/bin/k3s"),
        (6, deployment::K3S, "/bin/runc"),
        (6, deployment::K3S, "/bin/cni"),
        (6, deployment::K3S, "/bin/containerd-shim-runc-v2"),
    ];
    for image in targets
        .iter()
        .map(|(_, image, _)| *image)
        .collect::<BTreeSet<_>>()
    {
        util::logged(
            docker().args(["pull", "--platform", "linux/arm64", image]),
            &output.join(format!(
                "pull-{}.log",
                &util::digest(image.as_bytes())[..16]
            )),
            180,
        )?;
    }
    let invoke = |image: &str, arguments: &[&str], blob: Option<&Path>| -> Result<util::Captured> {
        let guard = util::Container::new(&root, "sync-go-symbols");
        let mut c = docker();
        c.args(security::sandbox_args(&guard.name));
        c.args([
            "--pull",
            "never",
            "--platform",
            "linux/arm64",
            "--network",
            "none",
            "--entrypoint",
            "/analysis/govulncheck",
            "--volume",
            &format!("{}:/analysis/govulncheck:ro", tool.display()),
        ]);
        // Override declared K3s volumes: no anonymous volumes or workload initialization.
        for path in [
            "/var/lib/cni",
            "/var/lib/kubelet",
            "/var/lib/rancher/k3s",
            "/var/log",
        ] {
            c.args([
                "--tmpfs",
                &format!("{path}:rw,noexec,nosuid,nodev,size=1m,mode=1777"),
            ]);
        }
        if let Some(blob) = blob {
            c.args([
                "--volume",
                &format!("{}:/analysis/input.json:ro", blob.display()),
                "--volume",
                &format!("{}:/db:ro", db.display()),
            ]);
        }
        c.arg(image).args(arguments);
        let result = util::capture(&mut c, 180)?;
        ensure(
            util::text(
                docker().args([
                    "ps",
                    "-a",
                    "-q",
                    "--filter",
                    &format!("name=^{}$", guard.name),
                ]),
                30,
            )?
            .is_empty(),
            "Diagnostic container cleanup incomplete",
        )?;
        Ok(result)
    };
    for (n, (index, image, path)) in targets.iter().enumerate() {
        let catalog = root.join(format!(
            ".work/security/sbom-chain/arm64/image-{index:02}.syft.json"
        ));
        let identity = util::text(
            docker().args([
                "image",
                "inspect",
                "--platform",
                "linux/arm64",
                "--format",
                "{{.Id}}",
                image,
            ]),
            30,
        )?;
        ensure(
            util::json(&catalog)?["source"]["metadata"]["manifestDigest"] == identity,
            "Binary image differs from original catalog",
        )?;
        let result = invoke(image, &["-mode=extract", path], None)?;
        let file = output.join(format!("binary-{n:02}.json"));
        fs::write(&file, &result.stdout)?;
        fs::write(output.join(format!("binary-{n:02}.stderr")), &result.stderr)?;
        ensure(
            result.success,
            "Binary extraction failed; raw diagnostics retained",
        )?;
        let bin = metadata(&result.stdout)?;
        // Only request advisory data for the two symbol-bearing subjects. Missing
        // symbols stay explicit failures; module-level fallback is not reachability.
        if extracted(&result.stdout).is_ok() {
            for module in bin["modules"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(std::iter::once(&bin["main"]))
            {
                if let Some(path) = module["Path"].as_str() {
                    modules.insert(path.to_string());
                }
                if let Some(path) = module["Replace"]["Path"].as_str() {
                    modules.insert(path.to_string());
                }
            }
        }
        inputs.push(json!({"image":image,"engine_native_manifest":identity,"binary":path,"blob":file.file_name().and_then(|s|s.to_str()),"blob_sha256":util::hash(&file)?,"catalog_sha256":util::hash(&catalog)?,"symbols":bin["pkgSymbols"].as_array().map_or(0, Vec::len),"symbol_coverage_qualified":extracted(&result.stdout).is_ok(),"go_version":bin["goVersion"]}));
        util::write_json(
            &output.join("inputs.json"),
            &json!({"tool":"golang.org/x/vuln/cmd/govulncheck@v1.9.0","tool_sha256":tool_hash,"platform":"linux/arm64","inputs":inputs,"approval":false}),
        )?;
    }
    ensure(
        inputs
            .iter()
            .any(|input| input["symbol_coverage_qualified"] == true),
        "No symbol coverage in any binary; no vulnerability matching or negative conclusions permitted",
    )?;
    // Public advisory retrieval is a distinct phase; all analysis remains offline.
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut total = 0usize;
    let mut manifest = Vec::new();
    let mut fetch = |relative: &str| -> Result<Value> {
        util::check_cancelled()?;
        let response = client
            .get(format!("https://vuln.go.dev/{relative}"))
            .send()?;
        ensure(response.status().is_success(), "Advisory retrieval failed")?;
        let mut bytes = Vec::new();
        response.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        total += bytes.len();
        ensure(
            bytes.len() <= 4 * 1024 * 1024 && total <= 64 * 1024 * 1024,
            "Advisory snapshot limit",
        )?;
        let doc = util::strict_json(&bytes)?;
        fs::write(db.join(relative), &bytes)?;
        manifest.push(json!({"path":relative,"sha256":util::digest(&bytes)}));
        Ok(doc)
    };
    fetch("index/db.json")?;
    let index = fetch("index/modules.json")?;
    let mut ids = BTreeSet::new();
    for module in index.as_array().ok_or("Invalid module index")? {
        if module["path"].as_str().is_some_and(|p| modules.contains(p)) {
            for vuln in module["vulns"].as_array().ok_or("Invalid index entry")? {
                let id = vuln["id"].as_str().ok_or("Missing advisory identity")?;
                ensure(advisory_id(id), "Unsafe advisory identity")?;
                ids.insert(id.to_string());
            }
        }
    }
    ensure(
        !ids.is_empty() && ids.len() <= 512,
        "Advisory coverage/entry limit",
    )?;
    for id in &ids {
        let doc = fetch(&format!("ID/{id}.json"))?;
        ensure(doc["id"] == *id, "Advisory identity mismatch")?;
    }
    util::write_json(
        &output.join("database.json"),
        &json!({"retrieved_at":chrono::Utc::now().to_rfc3339(),"files":manifest,"total_bytes":total,"advisories":ids.len()}),
    )?;
    for (n, input) in inputs.iter().enumerate() {
        if input["symbol_coverage_qualified"] != true {
            continue;
        }
        let result = invoke(
            sbom::SYFT,
            &[
                "-mode=binary",
                "-scan=symbol",
                "-json",
                "-db=file:///db",
                "/analysis/input.json",
            ],
            Some(&output.join(format!("binary-{n:02}.json"))),
        )?;
        let file = output.join(format!("analysis-{n:02}.json"));
        fs::write(&file, &result.stdout)?;
        fs::write(
            output.join(format!("analysis-{n:02}.stderr")),
            &result.stderr,
        )?;
        ensure(
            result.success,
            "Symbol diagnostic failed; raw output retained",
        )?;
        let findings = messages(&result.stdout)?;
        util::write_json(
            &output.join(format!("summary-{n:02}.json")),
            &json!({"input":input,"report_sha256":util::hash(&file)?,"symbol_advisories":findings.iter().filter_map(|m| { let f=&m["finding"]; f["trace"][0]["function"].as_str().and_then(|_| f["osv"].as_str().map(String::from)) }).collect::<BTreeSet<_>>(),"binary_mode_has_no_call_graph":true,"absence_does_not_prove_unreachable":true,"approval":false}),
        )?;
    }
    ensure(
        inputs
            .iter()
            .all(|input| input["symbol_coverage_qualified"] == true),
        "Some binary symbol coverage remains incomplete",
    )
}
