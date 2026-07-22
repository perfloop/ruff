use std::{num::NonZeroUsize, sync::Arc};

use anyhow::Context;
use lsp_server::Connection;
use ruff_db::system::{OsSystem, SystemPathBuf};

use crate::db::Db;
pub use crate::logging::{LogLevel, init_logging};
pub use crate::server::Server;
pub use crate::session::{ClientOptions, DiagnosticMode, GlobalOptions, WorkspaceOptions};
pub use document::{NotebookDocument, PositionEncoding, TextDocument};
pub(crate) use session::Session;

/// Temporary lock timing for the case-local workspace-diagnostic benchmark.
///
/// This module is compiled only by the benchmark's `perfloop-probe` feature.
/// The probe timestamps the unchanged production mutex acquisition and records
/// after releasing the mutex, so it does not use a probe-specific lock path.
#[cfg(feature = "perfloop-probe")]
pub mod perfloop_probe {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[derive(Clone, Copy, Debug)]
    pub struct LockStats {
        pub acquisitions: u64,
        pub total_wait_ns: u64,
        pub total_hold_ns: u64,
    }

    static ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_WAIT_NS: AtomicU64 = AtomicU64::new(0);
    static TOTAL_HOLD_NS: AtomicU64 = AtomicU64::new(0);

    pub fn reset() {
        ACQUISITIONS.store(0, Ordering::Relaxed);
        TOTAL_WAIT_NS.store(0, Ordering::Relaxed);
        TOTAL_HOLD_NS.store(0, Ordering::Relaxed);
    }

    pub fn snapshot() -> LockStats {
        LockStats {
            acquisitions: ACQUISITIONS.load(Ordering::Relaxed),
            total_wait_ns: TOTAL_WAIT_NS.load(Ordering::Relaxed),
            total_hold_ns: TOTAL_HOLD_NS.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record_lock(wait: Duration, hold: Duration) {
        let to_ns = |duration: Duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);

        ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
        TOTAL_WAIT_NS.fetch_add(to_ns(wait), Ordering::Relaxed);
        TOTAL_HOLD_NS.fetch_add(to_ns(hold), Ordering::Relaxed);
    }
}

mod capabilities;
mod db;
mod document;
mod logging;
mod server;
mod session;
mod system;

pub(crate) const SERVER_NAME: &str = "ty";
pub(crate) const DIAGNOSTIC_NAME: &str = "ty";

/// A common result type used in most cases where a
/// result type is needed.
pub(crate) type Result<T> = anyhow::Result<T>;

pub fn run_server() -> anyhow::Result<()> {
    let _ = print_interactive_warning();
    let four = NonZeroUsize::new(4).unwrap();

    // by default, we set the number of worker threads to `num_cpus`, with a maximum of 4.
    let worker_threads = std::thread::available_parallelism()
        .unwrap_or(four)
        .min(four);

    let (connection, io_threads) = Connection::stdio();

    let cwd = {
        let cwd = std::env::current_dir().context("Failed to get the current working directory")?;
        SystemPathBuf::from_path_buf(cwd).map_err(|path| {
            anyhow::anyhow!(
                "The current working directory `{}` contains non-Unicode characters. \
                    ty only supports Unicode paths.",
                path.display()
            )
        })?
    };

    // This is to complement the `LSPSystem` if the document is not available in the index.
    let fallback_system = Arc::new(OsSystem::new(cwd));

    let server_result = Server::new(worker_threads, connection, fallback_system, false)
        .context("Failed to start server")?
        .run();

    let io_result = io_threads.join();

    let result = match (server_result, io_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(server), Err(io)) => Err(server).context(format!("IO thread error: {io}")),
        (Err(server), _) => Err(server),
        (_, Err(io)) => Err(io).context("IO thread error"),
    };

    if let Err(err) = result.as_ref() {
        tracing::warn!("Server shut down with an error: {err}");
    } else {
        tracing::info!("Server shut down");
    }

    result
}

fn print_interactive_warning() -> std::io::Result<()> {
    use std::io::{IsTerminal, Write};

    if std::io::stdin().is_terminal() {
        let mut stderr = std::io::stderr().lock();
        writeln!(
            stderr,
            "WARNING: the ty LSP server should not be run interactively"
        )?;
        writeln!(
            stderr,
            "See https://docs.astral.sh/ty/editors/ for how to configure your editor"
        )?;
    }
    Ok(())
}
