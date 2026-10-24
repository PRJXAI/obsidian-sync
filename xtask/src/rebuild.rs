//! Local-only supplier experiments. Never replace production pins or publish images.
use crate::{Result, ensure, grype, images, sbom, security, util};
use chrono::Utc;
use serde_json::json;
use std::{fs, path::Path, process::Command};

pub const GO: &str = "golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c";
pub const STATIC: &str = "cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde";
pub const GIT: &str = "cgr.dev/chainguard/git:latest@sha256:6b5b402aaba4db9a6446e363d70bcc158c773c5d00c75d4bcd68691fdaa539cc";

pub struct Spec {
    pub name: &'static str,
    pub repository: &'static str,
    pub revision: &'static str,
    pub version: &'static str,
    pub package: &'static str,
    pub tests: &'static [&'static str],
    pub updates: &'static [&'static str],
}
pub const SPECS: &[Spec] = &[
    Spec {
        name: "syft",
        repository: "https://github.com/anchore/syft.git",
        revision: "f15c3343e29dfb20cf6d82c820e7090b49808c96",
        version: "1.55.0",
        package: "./cmd/syft",
        tests: &["./syft/format/..."],
        updates: &[],
    },
    Spec {
        name: "grype",
        repository: "https://github.com/anchore/grype.git",
        revision: "afe2742527d98d822da06c9f32eed86fe3d193e0",
        version: "0.121.0",
        package: "./cmd/grype",
        tests: &["./grype/match/...", "./grype/presenter/..."],
        updates: &[],
    },
    Spec {
        name: "gitleaks",
        repository: "https://github.com/gitleaks/gitleaks.git",
        revision: "83d9cd684c87d95d656c1458ef04895a7f1cbd8e",
        version: "8.30.1",
        package: ".",
        tests: &[
            "./detect/...",
            "./sources/...",
            "./report/...",
            "./regexp/...",
        ],
        updates: &[
            "github.com/klauspost/compress@v1.20.1",
            "github.com/mholt/archives@v0.1.5",
            "github.com/nwaples/rardecode/v2@v2.2.0",
            "github.com/ulikunitz/xz@v0.5.15",
            "golang.org/x/crypto@v0.58.0",
            "golang.org/x/sys@v0.49.0",
            "golang.org/x/text@v0.43.0",
        ],
    },
];
pub fn spec(name: &str) -> Result<&'static Spec> {
    SPECS
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| "Unsupported supplier".into())
}
pub fn dockerfile(spec: &Spec) -> String {
    let base = if spec.name == "gitleaks" { GIT } else { STATIC };
    format!(
        "FROM {base}\nLABEL org.opencontainers.image.source=\"{}\" org.opencontainers.image.revision=\"{}\" org.opencontainers.image.version=\"{}-local-rebuild\"\nCOPY --chown=65532:65532 binary /usr/local/bin/{}\nUSER 65532:65532\nENTRYPOINT [\"/usr/local/bin/{}\"]\n",
        spec.repository, spec.revision, spec.version, spec.name, spec.name
    )
}
fn git(root: &Path, args: &[&str]) -> Command {
    let mut c = util::cmd(
        "git",
        &[
            "-c",
            "credential.helper=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "protocol.file.allow=never",
        ],
        root,
    );
    c.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args);
    c
}
#[derive(Clone, Copy)]
enum Mode {
    Fetch,
    Compile,
    Test,
}
fn compiler(
    root: &Path,
    container: &util::Container,
    source: &Path,
    output: &Path,
    cache: &Path,
    image: &str,
    mode: Mode,
) -> Command {
    let offline = !matches!(mode, Mode::Fetch);
    let mut c = util::cmd("docker", &[], root);
    let mut args = security::sandbox_args(&container.name);
    // Compilers/tests execute temporary binaries; scanner scratch stays noexec.
    for (flag, value) in [
        ("--memory", "6g"),
        ("--pids-limit", "256"),
        ("--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=2g,mode=1777"),
    ] {
        let index = args.iter().position(|s| s == flag).expect("sandbox bound");
        args[index + 1] = value.into();
    }
    c.args(args);
    if offline {
        c.args([
            "--network",
            "none",
            "--env",
            "GOPROXY=off",
            "--env",
            "GOSUMDB=off",
            "--volume",
            &format!("{}:/cache/modules:ro", cache.join("modules").display()),
        ]);
    }
    c.args([
        "--env",
        "GOTOOLCHAIN=local",
        "--env",
        "GOPATH=/cache/gopath",
        "--env",
        "CGO_ENABLED=0",
        "--env",
        "GOMAXPROCS=2",
        "--env",
        "GOMEMLIMIT=4GiB",
        "--env",
        "GOCACHE=/cache/build",
        "--env",
        "GOMODCACHE=/cache/modules",
        "--volume",
        &format!(
            "{}:/src{}",
            source.display(),
            if matches!(mode, Mode::Compile) {
                ":ro"
            } else {
                ""
            }
        ),
        "--volume",
        &format!("{}:/out", output.display()),
        "--volume",
        &format!("{}:/cache", cache.display()),
        "--workdir",
        "/src",
        image,
        "go",
    ]);
    c
}
fn go(
    root: &Path,
    source: &Path,
    output: &Path,
    cache: &Path,
    offline: bool,
    args: &[&str],
    log: &str,
) -> Result {
    let container = util::Container::new(root, "sync-supplier-go");
    let image = util::json(&output.join("compiler-image.json"))?;
    let image = image["Id"].as_str().ok_or("Missing compiler image")?;
    ensure(images::is_digest(image), "Mutable compiler identity")?;
    let mode = if args.first() == Some(&"test") {
        Mode::Test
    } else if offline {
        Mode::Compile
    } else {
        Mode::Fetch
    };
    let mut c = compiler(
        root,
        &container,
        source,
        &output.join("compiler-output"),
        cache,
        image,
        mode,
    );
    c.args(args);
    util::logged(&mut c, &output.join(log), 2400)
}
fn copy_test_source(source: &Path, destination: &Path) -> Result {
    for item in walkdir::WalkDir::new(source).follow_links(false) {
        let item = item?;
        let target = destination.join(item.path().strip_prefix(source)?);
        if item.file_type().is_dir() {
            fs::create_dir_all(target)?;
        } else if item.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(item.path())?, target)?;
        } else {
            ensure(item.file_type().is_file(), "Special supplier input")?;
            fs::write(&target, util::read(item.path(), 256 * 1024 * 1024)?)?;
            fs::set_permissions(target, item.metadata()?.permissions())?;
        }
    }
    Ok(())
}
pub fn run(root: &Path, name: &str, platform: &str) -> Result {
    let spec = spec(name)?;
    util::local_docker(root)?;
    let base = root.join(".work/tool-rebuild");
    fs::create_dir_all(&base)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(base.join("build.lock"))?;
    lock.try_lock()?;
    let daemon = util::text(
        &mut util::cmd("docker", &["info", "--format", "{{.Architecture}}"], root),
        30,
    )?;
    ensure(
        matches!(
            (platform, daemon.as_str()),
            ("linux/arm64", "aarch64" | "arm64") | ("linux/amd64", "x86_64" | "amd64")
        ),
        "Use native platform; no silent emulation",
    )?;
    let output = tempfile::Builder::new()
        .prefix(&format!("{name}-"))
        .tempdir_in(&base)?
        .keep();
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    println!(
        "Local supplier experiment: {}",
        output.strip_prefix(root)?.display()
    );
    let builder = output.join("compiler");
    fs::create_dir(&builder)?;
    fs::write(
        builder.join("Dockerfile"),
        format!(
            "FROM {GO} AS compiler\nFROM {GIT}\nCOPY --from=compiler /usr/local/go /usr/local/go\nENV PATH=/usr/local/go/bin:/usr/bin:/bin\nENTRYPOINT []\n"
        ),
    )?;
    let compiler_tag = "obsidian-sync-tool-go:local-compiler";
    util::logged(
        &mut util::cmd(
            "docker",
            &["build", "--network=none", "-t", compiler_tag, "."],
            &builder,
        ),
        &output.join("compiler-build.log"),
        600,
    )?;
    let compiler_image = images::inspect(root, compiler_tag)?;
    util::write_json(&output.join("compiler-image.json"), &compiler_image)?;
    let source = output.join("source");
    fs::create_dir(&source)?;
    fs::create_dir(output.join("compiler-output"))?;
    util::logged(&mut git(&source, &["init"]), &output.join("init.log"), 30)?;
    util::logged(
        &mut git(
            &source,
            &["fetch", "--depth=1", spec.repository, spec.revision],
        ),
        &output.join("fetch.log"),
        180,
    )?;
    ensure(
        util::text(&mut git(&source, &["rev-parse", "FETCH_HEAD"]), 30)? == spec.revision,
        "Wrong supplier revision",
    )?;
    util::logged(
        &mut git(&source, &["checkout", "--detach", "FETCH_HEAD"]),
        &output.join("checkout.log"),
        30,
    )?;
    util::logged(
        &mut git(
            &source,
            &[
                "archive",
                "--format=tar",
                "--output",
                output
                    .join("upstream.tar")
                    .to_str()
                    .ok_or("Invalid archive path")?,
                "HEAD",
            ],
        ),
        &output.join("archive.log"),
        60,
    )?;
    let cache = base.join("go-cache");
    fs::create_dir_all(&cache)?;
    if !spec.updates.is_empty() {
        let mut args = vec!["get"];
        args.extend_from_slice(spec.updates);
        go(root, &source, &output, &cache, false, &args, "update.log")?;
    }
    go(
        root,
        &source,
        &output,
        &cache,
        false,
        &["mod", "download", "all"],
        "download.log",
    )?;
    go(
        root,
        &source,
        &output,
        &cache,
        true,
        &["mod", "verify"],
        "verify.log",
    )?;
    let changes = util::text(&mut git(&source, &["diff", "--name-only", "HEAD"]), 30)?;
    ensure(
        changes.lines().all(|p| ["go.mod", "go.sum"].contains(&p)),
        "Unexpected supplier source changes",
    )?;
    let locks = ["go.mod", "go.sum"]
        .iter()
        .map(|name| {
            fs::copy(source.join(name), output.join(name))?;
            Ok(json!({"path":name,"digest":util::hash(&output.join(name))?}))
        })
        .collect::<Result<Vec<_>>>()?;
    let flags = if name == "gitleaks" {
        format!(
            "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version={}",
            spec.version
        )
    } else {
        format!(
            "-s -w -X main.version={} -X main.gitCommit={} -X main.gitDescription=local-rebuild",
            spec.version, spec.revision
        )
    };
    let mut args = vec![
        "build",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=false",
        "-p=2",
        "-ldflags",
        &flags,
        "-o",
        "/out/binary",
    ];
    if name != "gitleaks" {
        args.extend([
            "-tags",
            "containers_image_openpgp,exclude_graphdriver_btrfs",
        ]);
    }
    args.push(spec.package);
    go(root, &source, &output, &cache, true, &args, "build.log")?;
    go(
        root,
        &source,
        &output,
        &cache,
        true,
        &["version", "-m", "/out/binary"],
        "binary-modules.txt",
    )?;
    fs::write(
        output.join("binary"),
        util::read(&output.join("compiler-output/binary"), 256 * 1024 * 1024)?,
    )?;
    fs::set_permissions(
        output.join("binary"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )?;
    let mut imports = vec![
        "list",
        "-buildvcs=false",
        "-mod=readonly",
        "-deps",
        "-f",
        "{{.ImportPath}}",
    ];
    if name != "gitleaks" {
        imports.extend([
            "-tags",
            "containers_image_openpgp,exclude_graphdriver_btrfs",
        ]);
    }
    imports.push(spec.package);
    go(
        root,
        &source,
        &output,
        &cache,
        true,
        &imports,
        "compiled-packages.txt",
    )?;
    let mut tests = vec!["test", "-mod=readonly", "-p=2", "-short"];
    if name != "gitleaks" {
        tests.extend([
            "-tags",
            "containers_image_openpgp,exclude_graphdriver_btrfs",
        ]);
    }
    tests.extend_from_slice(spec.tests);
    let test_source = output.join("test-source");
    copy_test_source(&source, &test_source)?;
    let fixtures = if name == "syft" {
        prepare_syft_fixtures(root, &test_source, &output)?
    } else {
        Vec::new()
    };
    let tests_passed = go(
        root,
        &test_source,
        &output,
        &cache,
        true,
        &tests,
        "tests.log",
    )
    .is_ok();
    util::check_cancelled()?;
    let context = output.join("image");
    fs::create_dir(&context)?;
    fs::copy(output.join("binary"), context.join("binary"))?;
    fs::write(context.join("Dockerfile"), dockerfile(spec))?;
    let tag = format!(
        "obsidian-sync-tool-{name}:candidate-{}",
        platform.split('/').next_back().ok_or("Invalid platform")?
    );
    util::logged(
        &mut util::cmd(
            "docker",
            &[
                "build",
                "--network=none",
                "--platform",
                platform,
                "-t",
                &tag,
                ".",
            ],
            &context,
        ),
        &output.join("image.log"),
        600,
    )?;
    let inspected = images::inspect(root, &tag)?;
    let id = inspected["Id"]
        .as_str()
        .ok_or("Missing candidate identity")?;
    let container = util::Container::new(root, "sync-supplier-version");
    let mut c = util::cmd("docker", &[], root);
    c.args(security::sandbox_args(&container.name))
        .args(["--network", "none", id, "version"]);
    util::logged(&mut c, &output.join("version.log"), 60)?;
    let material = images::export(root, id, &output.join("candidate.tar"))?;
    sbom::scan(
        root,
        "docker-archive:/input/image.tar",
        &output.join("candidate.tar"),
        "/input/image.tar",
        &output,
        "candidate",
    )?;
    let db = root.join(".work/grype-cache");
    grype::database(root, &db, &output)?;
    let compiler_id = compiler_image["Id"]
        .as_str()
        .ok_or("Missing compiler identity")?;
    let compiler_material = images::export(root, compiler_id, &output.join("compiler.tar"))?;
    sbom::scan(
        root,
        "docker-archive:/input/image.tar",
        &output.join("compiler.tar"),
        "/input/image.tar",
        &output,
        "compiler",
    )?;
    let compiler_findings = grype::scan(
        root,
        &output.join("compiler.syft.json"),
        &output,
        &db,
        "compiler",
    )?;
    let baseline_image = match name {
        "syft" => sbom::SYFT,
        "grype" => grype::GRYPE,
        "gitleaks" => security::GITLEAKS,
        _ => unreachable!(),
    };
    sbom::catalog_registry(root, baseline_image, platform, &output, "baseline")?;
    let baseline_findings = grype::scan(
        root,
        &output.join("baseline.syft.json"),
        &output,
        &db,
        "baseline",
    )?;
    let findings = grype::scan(
        root,
        &output.join("candidate.syft.json"),
        &output,
        &db,
        "candidate",
    )?;
    let smoke_passed = smoke(root, name, id, &output, &db).is_ok();
    util::check_cancelled()?;
    util::write_json(
        &output.join("experiment.json"),
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"tool":name,"upstream_repository":spec.repository,"upstream_revision":spec.revision,"upstream_archive_sha256":util::hash(&output.join("upstream.tar"))?,"compiler_image":GO,"compiler_runtime":GIT,"compiler_identity":compiler_image["Id"],"compiler_material":compiler_material,"compiler_findings":compiler_findings,"dependency_updates":spec.updates,"locks":locks,"binary_sha256":util::hash(&output.join("binary"))?,"compiled_packages_sha256":util::hash(&output.join("compiled-packages.txt"))?,"image":material,"test_fixture_materials":fixtures,"upstream_selected_tests_passed":tests_passed,"repository_contract_smoke_passed":smoke_passed,"baseline_image":baseline_image,"baseline_findings":baseline_findings,"findings":findings,"production_pins_changed":false,"authorization":"local experiment only; not approved, signed or published"}),
    )?;
    println!(
        "Candidate {name}: {findings} matches; upstream selected tests passed: {tests_passed}"
    );
    ensure(
        findings == 0 && compiler_findings == 0 && tests_passed && smoke_passed,
        "Supplier experiment still has findings/test failures; not accepted",
    )
}
fn prepare_syft_fixtures(
    root: &Path,
    source: &Path,
    output: &Path,
) -> Result<Vec<serde_json::Value>> {
    use sha2::{Digest, Sha256};
    // Update only the disposable Alpine round-trip fixture, never golden outputs
    // or supplier implementation. Use an already inventoried base, not EOL 3.18.
    let alpine = source.join("syft/format/syftjson/testdata/image-alpine/Dockerfile");
    fs::write(&alpine, format!("FROM {}\n", security::HELPER))?;
    let mut materials = Vec::new();
    for (name, parent) in [
        ("image-simple", "syft/format/internal/testutil"),
        ("image-alpine", "syft/format/syftjson"),
    ] {
        let parent = source.join(parent).join("testdata");
        let context = parent.join(name);
        let mut hash = Sha256::new();
        for item in walkdir::WalkDir::new(&context)
            .sort_by_file_name()
            .follow_links(false)
        {
            let item = item?;
            if item.file_type().is_file() {
                hash.update(util::read(item.path(), util::JSON_LIMIT)?);
            } else {
                ensure(item.file_type().is_dir(), "Unexpected fixture link")?;
            }
        }
        let version = hex::encode(hash.finalize());
        let tag = format!("stereoscope-fixture-{name}:{version}");
        util::logged(
            &mut util::cmd(
                "docker",
                &["build", "--network=none", "-t", &tag, "."],
                &context,
            ),
            &output.join(format!("fixture-{name}.log")),
            300,
        )?;
        let cache = parent.join("cache");
        fs::create_dir_all(&cache)?;
        let archive = cache.join(format!("stereoscope-fixture-{name}-{version}.tar"));
        let material = images::export(root, &tag, &archive)?;
        materials.push(json!({"fixture":name,"context_sha256":version,"image":material,"patch":if name=="image-alpine" { "disposable round-trip fixture base refreshed; golden expectations unchanged" } else { "none" }}));
    }
    Ok(materials)
}
fn smoke(root: &Path, name: &str, image: &str, output: &Path, db: &Path) -> Result {
    if name == "gitleaks" {
        return smoke_secrets(root, image, output);
    }
    let temporary = tempfile::Builder::new()
        .prefix("supplier-smoke-")
        .tempdir_in(root.join(".work"))?;
    let reports = output.join("contract-smoke");
    fs::create_dir(&reports)?;
    if name == "syft" {
        let source = temporary.path().join("source");
        fs::create_dir(&source)?;
        sbom::stage_source(root, &source)?;
        sbom::scan_with_image(
            root,
            "dir:/source",
            &source,
            "/source",
            &reports,
            "source",
            image,
        )?;
        let catalog = util::json(&reports.join("source.syft.json"))?;
        grype::validate_catalog(&catalog)?;
        sbom::source_complete(
            root,
            catalog["artifacts"]
                .as_array()
                .ok_or("Missing native packages")?,
        )?;
        let cdx = util::json(&reports.join("source.cdx.json"))?;
        sbom::source_complete(
            root,
            cdx["components"].as_array().ok_or("Missing CDX packages")?,
        )?;
        for (name, tag) in [
            ("runtime", "obsidian-sync:local"),
            ("builder", "obsidian-sync:builder"),
        ] {
            let archive = temporary.path().join(format!("{name}.tar"));
            let material = images::export(root, tag, &archive)?;
            sbom::scan_with_image(
                root,
                "docker-archive:/input/image.tar",
                &archive,
                "/input/image.tar",
                &reports,
                name,
                image,
            )?;
            let subject =
                grype::image_subject(&util::json(&reports.join(format!("{name}.syft.json")))?)?;
            ensure(
                subject["ImageID"] == material["config_digest"]
                    && subject["DiffIDs"] == material["layers"],
                "Candidate catalog image substitution",
            )?;
        }
    } else {
        let archive = temporary.path().join("runtime.tar");
        images::export(root, "obsidian-sync:local", &archive)?;
        sbom::scan(
            root,
            "docker-archive:/input/image.tar",
            &archive,
            "/input/image.tar",
            &reports,
            "runtime",
        )?;
        for (name, input, expected) in [
            ("runtime", reports.join("runtime.syft.json"), 0),
            (
                "vulnerable",
                output.join("baseline.syft.json"),
                util::json(&output.join("baseline.scan.json"))?["findings"]
                    .as_u64()
                    .ok_or("Missing baseline count")? as usize,
            ),
        ] {
            let scratch = tempfile::Builder::new()
                .prefix("supplier-grype-")
                .tempdir_in(root.join(".work"))?;
            let container = util::Container::new(root, "sync-candidate-grype");
            let mut c = grype::command(root, &container, db, true);
            c.args([
                "--volume",
                &format!("{}:/input/sbom.json:ro", input.display()),
                "--volume",
                &format!("{}:/reports", scratch.path().display()),
                image,
                "sbom:/input/sbom.json",
                "--output",
                "json",
                "--file",
                "/reports/report.json",
            ]);
            util::logged(&mut c, &reports.join(format!("{name}.log")), 600)?;
            let bytes = util::read(&scratch.path().join("report.json"), util::JSON_LIMIT)?;
            let matches = grype::validate_report(
                &util::json(&input)?,
                &util::strict_json(&bytes)?,
                Utc::now(),
            )?;
            fs::write(reports.join(format!("{name}.grype.json")), bytes)?;
            ensure(
                matches.len() == expected,
                "Candidate changed baseline detection",
            )?;
        }
    }
    Ok(())
}
fn smoke_secrets(root: &Path, image: &str, output: &Path) -> Result {
    let temporary = tempfile::Builder::new()
        .prefix("supplier-secrets-")
        .tempdir_in(root.join(".work"))?;
    let repository = temporary.path().join("repo");
    fs::create_dir(&repository)?;
    util::quiet(&mut git(&repository, &["init", "-q"]), 30)?;
    let token = format!("{}{}", "ghp_", &util::random_hex().repeat(2)[..36]);
    fs::write(repository.join("fixture.txt"), format!("token={token}\n"))?;
    util::quiet(&mut git(&repository, &["add", "."]), 30)?;
    for message in ["synthetic fixture", "remove synthetic fixture"] {
        util::quiet(
            &mut git(
                &repository,
                &[
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-qm",
                    message,
                ],
            ),
            30,
        )?;
        if repository.join("fixture.txt").exists() {
            fs::remove_file(repository.join("fixture.txt"))?;
            util::quiet(&mut git(&repository, &["add", "-u"]), 30)?;
        }
    }
    let mirror = temporary.path().join("history.git");
    security::history_snapshot(&repository, &mirror)?;
    for (mode, input, expected) in [("git", mirror, false), ("dir", repository, true)] {
        let scratch = tempfile::Builder::new()
            .prefix("supplier-secret-output-")
            .tempdir_in(root.join(".work"))?;
        let container = util::Container::new(root, "sync-candidate-gitleaks");
        let mut c = util::cmd("docker", &[], root);
        c.args(security::sandbox_args(&container.name)).args([
            "--network",
            "none",
            "--volume",
            &format!("{}:/input:ro", input.display()),
            "--volume",
            &format!("{}:/reports", scratch.path().display()),
            "--env",
            "GIT_CONFIG_COUNT=1",
            "--env",
            "GIT_CONFIG_KEY_0=safe.directory",
            "--env",
            "GIT_CONFIG_VALUE_0=/input",
            image,
            mode,
            "/input",
            "--redact=100",
            "--no-banner",
            "--log-level=error",
            "--report-format=json",
            "--report-path=/reports/report.json",
        ]);
        if mode == "git" {
            c.arg("--log-opts=--all");
        }
        let result = util::capture(&mut c, 120)?;
        for channel in [&result.stdout, &result.stderr] {
            ensure(
                !channel.windows(token.len()).any(|v| v == token.as_bytes()),
                "Candidate leaked synthetic token in diagnostics",
            )?;
        }
        fs::write(
            output.join(format!("secret-{mode}.log")),
            [&result.stdout[..], &result.stderr[..]].concat(),
        )?;
        ensure(
            result.success == expected,
            "Candidate failed secret fixture exit behavior",
        )?;
        let bytes = util::read(&scratch.path().join("report.json"), util::JSON_LIMIT)?;
        for channel in [&bytes, &result.stdout, &result.stderr] {
            ensure(
                !channel.windows(token.len()).any(|v| v == token.as_bytes()),
                "Candidate leaked synthetic token instead of redacting",
            )?;
        }
        let report = util::strict_json(&bytes)?;
        let findings = report.as_array().ok_or("Invalid secret fixture report")?;
        ensure(
            findings.is_empty() == expected,
            "Candidate lost historical secret coverage",
        )?;
        fs::write(output.join(format!("secret-{mode}.json")), bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compile_inputs_are_readonly_without_writable_parent_aliases() {
        let root = Path::new("/fixture");
        let container = util::Container::inert(root, "compiler-test");
        let c = compiler(
            root,
            &container,
            Path::new("/fixture/source"),
            Path::new("/fixture/results"),
            Path::new("/fixture/cache"),
            "sha256:fixture",
            Mode::Compile,
        );
        let args = c
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|v| v == ["--network", "none"]));
        assert!(args.iter().any(|s| s == "/fixture/source:/src:ro"));
        assert!(
            args.iter()
                .any(|s| s == "/fixture/cache/modules:/cache/modules:ro")
        );
        assert!(!args.iter().any(|s| s.starts_with("/fixture:")));
        assert!(!args.iter().any(|s| s.contains("docker.sock")));
        assert_eq!(args.iter().filter(|s| *s == "--tmpfs").count(), 1);
        assert!(
            args.iter()
                .any(|s| s.contains("/tmp:rw,exec,nosuid,nodev,size=2g"))
        );
    }
    #[test]
    fn test_copy_keeps_links_without_following_them_or_mutating_build_source() -> Result {
        let temp = tempfile::tempdir()?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        fs::write(source.join("go.mod"), "public fixture")?;
        std::os::unix::fs::symlink("/not-mounted/operator-file", source.join("link"))?;
        let target = temp.path().join("test-source");
        copy_test_source(&source, &target)?;
        assert_eq!(
            fs::read_link(target.join("link"))?,
            Path::new("/not-mounted/operator-file")
        );
        fs::write(target.join("go.mod"), "changed in throwaway test")?;
        assert_eq!(fs::read_to_string(source.join("go.mod"))?, "public fixture");
        Ok(())
    }
}
