#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use xtask::{Result, clients, deployment, docs, images, policy, sbom, security};

#[derive(Parser)]
#[command(about = "Rust repository, infrastructure, security and SBOM tooling")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}
#[derive(Subcommand)]
enum Task {
    Check,
    CheckFeatures,
    SyncGenerated {
        #[arg(long)]
        check: bool,
    },
    Docs {
        #[command(subcommand)]
        action: Doc,
    },
    VerifyImage,
    /// Content binding only: requires a trusted scan, not release authorization.
    VerifyRelease {
        #[arg(long)]
        image: String,
        #[arg(long)]
        scan_report: PathBuf,
    },
    GenerateSbom {
        #[arg(long, default_value = "obsidian-sync:local")]
        runtime_image: String,
        #[arg(long, default_value = "obsidian-sync:builder")]
        builder_image: String,
        #[arg(long, requires = "builder_archive")]
        runtime_archive: Option<PathBuf>,
        #[arg(long, requires = "runtime_archive")]
        builder_archive: Option<PathBuf>,
    },
    ScanSecurity,
    ScanSources,
    ScanSbom {
        #[arg(long, default_value = ".work/sbom")]
        sbom_dir: PathBuf,
    },
    ScanSupplyChain {
        #[arg(long,default_value="linux/amd64",value_parser=["linux/amd64","linux/arm64"])]
        platform: String,
    },
    TestLivesync {
        #[arg(long, conflicts_with = "image")]
        storage_config: Option<PathBuf>,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        benchmark: bool,
    },
    TestS3,
    SmokeCompose,
    SmokeKubernetes,
    ValidateDeployments,
    TestBuildContext,
    Benchmark,
    CiGate,
    CheckReleasePolicy {
        #[arg(long)]
        source_revision: String,
    },
    FindingsLedger {
        #[arg(long,default_value="linux/amd64",value_parser=["linux/amd64","linux/arm64"])]
        platform: String,
        #[arg(long)]
        source_revision: String,
    },
    PublishSecuritySummary {
        #[arg(long)]
        source_revision: String,
    },
}
#[derive(Subcommand)]
enum Doc {
    Check,
    Review {
        #[arg(long)]
        reason: String,
    },
    Create {
        path: PathBuf,
        #[arg(long)]
        title: String,
    },
    Update {
        path: PathBuf,
        #[arg(long)]
        from_file: PathBuf,
    },
    Delete {
        path: PathBuf,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        yes: bool,
    },
}
fn execute(command: Task) -> Result {
    xtask::util::install_cancellation()?;
    let root = xtask::root();
    match command {
        Task::Check => deployment::check(&root, false),
        Task::CheckFeatures => deployment::check(&root, true),
        Task::SyncGenerated { check } => docs::sync(&root, check),
        Task::Docs { action } => match action {
            Doc::Check => docs::check(&root),
            Doc::Review { reason } => docs::review(&root, &reason),
            Doc::Create { path, title } => docs::create(&root, &path, &title),
            Doc::Update { path, from_file } => docs::update(&root, &path, &from_file),
            Doc::Delete { path, reason, yes } => docs::delete(&root, &path, &reason, yes),
        },
        Task::VerifyImage => images::verify_image(&root),
        Task::VerifyRelease { image, scan_report } => {
            images::verify_release(&root, &image, &scan_report)
        }
        Task::GenerateSbom {
            runtime_image,
            builder_image,
            runtime_archive,
            builder_archive,
        } => sbom::generate(
            &root,
            &runtime_image,
            &builder_image,
            runtime_archive.as_deref().zip(builder_archive.as_deref()),
        ),
        Task::ScanSecurity => security::scan_security(&root),
        Task::ScanSources => security::scan_sources(&root),
        Task::ScanSbom { sbom_dir } => xtask::grype::scan_generated(&root, &sbom_dir),
        Task::ScanSupplyChain { platform } => xtask::supply_sbom::scan(&root, &platform),
        Task::TestLivesync {
            storage_config,
            image,
            benchmark,
        } => clients::livesync(
            &root,
            storage_config.as_deref(),
            image.as_deref(),
            benchmark,
        ),
        Task::TestS3 => deployment::s3(&root),
        Task::SmokeCompose => deployment::compose(&root),
        Task::SmokeKubernetes => deployment::kubernetes(&root),
        Task::ValidateDeployments => deployment::validate(&root),
        Task::TestBuildContext => deployment::test_build_context(&root),
        Task::Benchmark => deployment::benchmark(&root),
        Task::CiGate => policy::aggregate(),
        Task::CheckReleasePolicy { source_revision } => policy::preflight(&root, &source_revision),
        Task::FindingsLedger {
            platform,
            source_revision,
        } => xtask::supply_sbom::ledger(&root, &platform, &source_revision),
        Task::PublishSecuritySummary { source_revision } => {
            xtask::supply_sbom::public_summary(&root, &source_revision)
        }
    }
}
fn main() -> std::process::ExitCode {
    match execute(Cli::parse().command).and_then(|()| xtask::util::check_cancelled()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!(
                "Task failed; no clean scan, verified release, or acceptance is implied. Raw command/provider errors are withheld; inspect approved local evidence."
            );
            std::process::ExitCode::FAILURE
        }
    }
}
