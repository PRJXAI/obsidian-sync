//! Synthetic control-plane processes only; never contacts Docker/Kubernetes.
use super::*;
use std::process::Stdio;

#[test]
fn fixture_child() -> Result {
    let Some(path) = std::env::var_os("XTASK_K3D_CLEANUP_CASE") else {
        return Ok(());
    };
    let root = PathBuf::from(path);
    let scenario = fs::read_to_string(root.join("scenario"))?;
    let mut cluster = Cluster {
        root: root.clone(),
        name: "sync-smoke-fixture".into(),
        kubeconfig: root.join("kubeconfig"),
        endpoint: "unix:///synthetic-k3d.sock".into(),
        armed: false,
    };
    if scenario == "existing" {
        assert!(cluster.resources_absent(false).is_err());
        return Ok(());
    }
    cluster.armed = true;
    if scenario == "cancel" {
        util::install_cancellation()?;
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while util::check_cancelled().is_ok() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(util::check_cancelled().is_err());
        cluster.remove()?;
        assert!(!cluster.armed);
    } else if ["residual", "delete-fails"].contains(&scenario.as_str()) {
        assert!(cluster.remove().is_err());
    } else {
        // The same armed guard unwinds partial-create/errors without accepting them.
        let failure: Result = Err("Synthetic creation failure".into());
        assert!(failure.is_err());
    }
    Ok(())
}

#[test]
fn existing_partial_canceled_and_residual_clusters_are_fenced() -> Result {
    let work = tempfile::tempdir()?;
    let binary = work.path().join("control");
    util::quiet(
        &mut util::cmd(
            "rustc",
            &[
                "--edition=2024",
                "-Dwarnings",
                "xtask/tests/fixtures/k3d_control.rs",
                "-o",
                binary.to_str().ok_or("Invalid fixture path")?,
            ],
            &crate::root(),
        ),
        60,
    )?;
    for scenario in ["existing", "partial", "cancel", "residual", "delete-fails"] {
        let case = work.path().join(scenario);
        fs::create_dir(&case)?;
        let case = case.canonicalize()?;
        fs::write(case.join("scenario"), scenario)?;
        if scenario == "delete-fails" {
            fs::write(case.join("delete-fails"), "synthetic")?;
        }
        if ["existing", "residual"].contains(&scenario) {
            fs::write(case.join("residual"), "synthetic")?;
        }
        for program in ["k3d", "docker"] {
            fs::copy(&binary, case.join(program))?;
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "deployment::k3d_cleanup::fixture_child",
                "--nocapture",
            ])
            .env("XTASK_K3D_CLEANUP_CASE", &case)
            .env("PATH", &case)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let result = util::capture(&mut command, 20)?;
        assert!(
            result.success,
            "{scenario}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let calls = fs::read_to_string(case.join("calls"))?;
        assert_eq!(
            calls.contains("k3d [\"cluster\", \"delete\", \"sync-smoke-fixture\"]"),
            scenario != "existing"
        );
        assert!(!calls.contains("create") && !calls.contains("operator"));
        if ["cancel", "delete-fails"].contains(&scenario) {
            assert!(calls.contains("volume"));
        }
        if scenario == "delete-fails" {
            assert!(calls.contains("sync-smoke-fixture-data"));
            assert!(calls.contains("sync-smoke-fixture-server-0"));
            assert!(calls.contains("sync-smoke-fixture-tools"));
        }
    }
    Ok(())
}
