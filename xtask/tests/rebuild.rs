#![forbid(unsafe_code)]
use xtask::{Result, policy, rebuild, security};

#[test]
fn only_explicit_supplier_commits_and_dependency_versions_are_accepted() -> Result {
    for spec in rebuild::SPECS {
        assert!(policy::is_revision(spec.revision));
        assert!(spec.repository.starts_with("https://github.com/"));
        assert!(!spec.tests.is_empty());
        for update in spec.updates {
            assert!(update.contains("@v"));
            assert!(!update.contains("latest"));
        }
        assert_eq!(rebuild::spec(spec.name)?.revision, spec.revision);
    }
    for bad in ["unknown", "../syft", "syft;docker push", ""] {
        assert!(rebuild::spec(bad).is_err());
    }
    Ok(())
}

#[test]
fn supplier_images_add_only_the_binary_with_no_build_or_publish_instructions() {
    for spec in rebuild::SPECS {
        let file = rebuild::dockerfile(spec);
        assert!(file.contains("USER 65532:65532"));
        assert!(file.contains("-local-rebuild"));
        assert_eq!(file.lines().filter(|s| s.starts_with("COPY ")).count(), 1);
        assert!(!file.contains("RUN "));
        assert!(!file.contains("push"));
        assert!(file.contains(&format!("ENTRYPOINT [\"/usr/local/bin/{}\"]", spec.name)));
        assert!(file.starts_with(&format!(
            "FROM {}\n",
            if spec.name == "gitleaks" {
                rebuild::GIT
            } else {
                rebuild::STATIC
            }
        )));
    }
    // Adding a compiler scratch exception must not change scanner restrictions.
    let args = security::sandbox_args("fixture");
    assert!(
        args.iter()
            .any(|s| s.contains("/tmp:rw,noexec,nosuid,nodev"))
    );
}
