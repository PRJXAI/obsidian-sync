#![forbid(unsafe_code)]
use std::fs;
use xtask::Result;

fn uploaded_paths(workflow: &str, name: &str) -> Vec<String> {
    let marker = format!("          name: {name}\n");
    let section = workflow.split_once(&marker).expect("named upload").1;
    let mut lines = section.lines();
    let path = lines
        .next()
        .expect("upload path")
        .trim()
        .strip_prefix("path: ")
        .expect("explicit upload path");
    if path != "|" {
        return vec![path.into()];
    }
    lines
        .take_while(|line| line.starts_with("            "))
        .map(|line| line.trim().into())
        .collect()
}

#[test]
fn publication_keeps_required_ci_fresh_validation_and_private_artifact_boundaries() -> Result {
    let text = fs::read_to_string(xtask::root().join(".github/workflows/ci.yml"))?;
    assert_eq!(
        uploaded_paths(&text, "build-images"),
        [
            ".work/ci-images/runtime.tar",
            ".work/ci-images/builder.tar",
            ".work/ci-images/SHA256SUMS"
        ]
    );
    assert_eq!(
        uploaded_paths(&text, "security-reports"),
        [".work/public-security/"]
    );
    assert_eq!(
        uploaded_paths(&text, "published-application"),
        [
            ".work/published-application/release.json",
            ".work/published-application/subjects.checksums"
        ]
    );
    let sbom = uploaded_paths(&text, "sbom-materials");
    assert_eq!(sbom.len(), 11);
    let mut expected = Vec::new();
    for name in ["source", "runtime", "builder"] {
        for format in ["cdx", "spdx", "syft"] {
            expected.push(format!(".work/sbom/{name}.{format}.json"));
        }
    }
    expected.extend([
        ".work/sbom/native-toolchain.txt".into(),
        ".work/sbom/materials.json".into(),
    ]);
    assert_eq!(sbom, expected);
    let (checks, publish) = text.split_once("\n  publish:\n").expect("publication job");
    assert!(!checks.contains("packages: write"));
    for required in [
        "needs: [required-ci, build, sbom]",
        "github.event_name == 'workflow_dispatch'",
        "github.ref == 'refs/heads/main'",
        "inputs.publish && inputs.redistribution_reviewed",
        "needs['required-ci'].result == 'success'",
        "PUBLISH_REDISTRIBUTION_APPROVED_SHA: ${{ github.sha }}",
    ] {
        assert!(publish.contains(required), "{required}");
    }
    let scan = publish
        .find("run: cargo xtask scan-sbom")
        .expect("fresh analysis");
    let login = publish
        .find("name: Registry login for application publication (after fresh analysis)")
        .expect("write-credential registry login");
    let read_login = publish
        .find("name: Optional read-only tool authentication")
        .expect("private tool pull authentication");
    assert!(read_login < scan);
    let read_section = &publish[read_login..scan];
    assert!(read_section.contains("if: env.DEVSECOPS_READ_TOKEN_AVAILABLE == 'true'"));
    assert!(read_section.contains("password: ${{ secrets.DEVSECOPS_PACKAGES_READ_TOKEN }}"));
    assert!(
        !read_section.contains("secrets.GITHUB_TOKEN") && !read_section.contains("github.token")
    );
    for job in ["security", "sbom"] {
        let start = checks
            .find(&format!("\n  {job}:\n"))
            .expect("image-consuming job");
        let section = checks[start..]
            .split("\n  integration:\n")
            .next()
            .unwrap()
            .split("\n  required-ci:\n")
            .next()
            .unwrap();
        assert!(section.contains("packages: read"));
        assert!(
            section
                .contains("password: ${{ secrets.DEVSECOPS_PACKAGES_READ_TOKEN || github.token }}")
        );
    }
    let promote = publish
        .find("run: cargo xtask publish-image")
        .expect("verified promotion");
    let attest = publish
        .find("uses: actions/attest-build-provenance@")
        .expect("provenance");
    let upload = publish
        .find("name: published-application")
        .expect("published identities");
    assert!(scan < login && login < promote && promote < attest && attest < upload);
    assert!(!publish.contains("docker build"));
    assert!(
        !text.contains("run: |"),
        "CI orchestration remains Rust, not inline shell"
    );
    Ok(())
}
