//! Case-local benchmark for diagnostic-rich `workspace/diagnostic` requests.
//!
//! The test reuses the repository's in-memory LSP fixture so the timed region
//! begins at request submission and ends only when the complete response has
//! been received and validated.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use lsp_types::WorkspaceDocumentDiagnosticReport;
use ruff_db::system::SystemPath;
use ty_server::{ClientOptions, DiagnosticMode};

use crate::TestServerBuilder;

const FILE_COUNT: usize = 48;
const ERRORS_PER_FILE: usize = 64;

fn diagnostic_rich_source(file_index: usize) -> String {
    let mut source = String::with_capacity(ERRORS_PER_FILE * 64);

    for error_index in 0..ERRORS_PER_FILE {
        writeln!(source, "def error_{file_index}_{error_index}() -> str:").unwrap();
        writeln!(source, "    return {error_index}").unwrap();
        source.push('\n');
    }

    source
}

fn as_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[test]
fn workspace_diagnostic_contention_benchmark() -> anyhow::Result<()> {
    let workspace_root = SystemPath::new("src");
    let mut builder = TestServerBuilder::new()?
        .with_workspace(workspace_root, None)?
        .with_initialization_options(
            ClientOptions::default().with_diagnostic_mode(DiagnosticMode::Workspace),
        )
        .with_full_diagnostic_output()
        .enable_diagnostic_related_information(true);

    for file_index in 0..FILE_COUNT {
        let file_name = format!("src/error_{file_index:03}.py");
        builder = builder.with_file(
            SystemPath::new(&file_name),
            diagnostic_rich_source(file_index),
        )?;
    }

    let mut server = builder.build().wait_until_workspaces_are_initialized();

    ty_server::perfloop_probe::reset();
    let started = Instant::now();
    let report = server.workspace_diagnostic_request(None, None);
    let request_ns = as_ns(started.elapsed());
    let lock_stats = ty_server::perfloop_probe::snapshot();

    assert_eq!(report.items.len(), FILE_COUNT);

    let mut reported_diagnostics = 0;
    let mut diagnostics_with_rendered_data = 0;
    for item in report.items {
        let WorkspaceDocumentDiagnosticReport::WorkspaceFullDocumentDiagnosticReport(report) = item
        else {
            panic!("a request without prior IDs must return full reports");
        };

        let items = report.full_document_diagnostic_report.items;
        assert_eq!(items.len(), ERRORS_PER_FILE);
        diagnostics_with_rendered_data += items.iter().filter(|item| item.data.is_some()).count();
        reported_diagnostics += items.len();
    }

    assert_eq!(reported_diagnostics, FILE_COUNT * ERRORS_PER_FILE);
    assert_eq!(diagnostics_with_rendered_data, reported_diagnostics);
    assert_eq!(lock_stats.acquisitions, FILE_COUNT as u64);
    assert!(lock_stats.total_hold_ns > 0);

    println!("{{\"metric\":\"workspace_diagnostic_ns\",\"value\":{request_ns}}}");
    println!(
        "{{\"metric\":\"workspace_diagnostic_lock_wait_ns\",\"value\":{}}}",
        lock_stats.total_wait_ns
    );
    println!(
        "{{\"metric\":\"workspace_diagnostic_lock_hold_ns\",\"value\":{}}}",
        lock_stats.total_hold_ns
    );
    println!(
        "LOCK_PROFILE acquisitions={} wait_ns={} hold_ns={}",
        lock_stats.acquisitions, lock_stats.total_wait_ns, lock_stats.total_hold_ns
    );

    Ok(())
}
