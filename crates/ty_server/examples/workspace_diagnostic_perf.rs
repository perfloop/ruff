//! Standalone workspace-diagnostic workload used by the performance case.
//!
//! The driver talks to the public LSP server over an in-memory LSP connection.
//! It deliberately uses a multi-file, diagnostic-rich workspace so that every
//! worker has to construct a full document diagnostic report. The measured
//! interval starts when it sends `workspace/diagnostic` and ends when the
//! complete LSP response is received.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use lsp_server::{Connection, Message, Request as ServerRequest, RequestId, Response};
use lsp_types::{
    ClientCapabilities, ConfigurationParams, ConfigurationRequest, DiagnosticClientCapabilities,
    InitializeParams, InitializeRequest, InitializedNotification, InitializedParams, Notification,
    PartialResultParams, ProgressToken, Request, TextDocumentClientCapabilities,
    WorkDoneProgressCreateRequest, WorkDoneProgressParams, WorkspaceClientCapabilities,
    WorkspaceDiagnosticParams, WorkspaceDiagnosticReport, WorkspaceDiagnosticRequest,
    WorkspaceDocumentDiagnosticReport, WorkspaceFolder, WorkspaceFoldersInitializeParams,
};
use ruff_db::system::{OsSystem, SystemPathBuf};
use serde_json::Value;
use ty_server::{ClientOptions, DiagnosticMode, Server};

const FILES: usize = 64;
const DIAGNOSTICS_PER_FILE: usize = 64;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum Workload {
    Rich,
    Sparse,
}

impl Workload {
    fn parse() -> Result<Self> {
        let argument = std::env::args().nth(1);
        match argument.as_deref() {
            Some("--sample") | Some("--probe-rich") => Ok(Self::Rich),
            Some("--probe-sparse") => Ok(Self::Sparse),
            _ => bail!("usage: workspace_diagnostic_perf [--sample|--probe-rich|--probe-sparse]"),
        }
    }

    const fn expected_diagnostics_per_file(self) -> usize {
        match self {
            Self::Rich => DIAGNOSTICS_PER_FILE,
            Self::Sparse => 1,
        }
    }
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(workload: Workload) -> Result<Self> {
        let root = std::env::current_dir()
            .context("failed to determine the repository root")?
            .join(".perfloop-workspace-diagnostic")
            .join(format!(
                "{}-{}",
                std::process::id(),
                workload.expected_diagnostics_per_file()
            ));

        if root.exists() {
            fs::remove_dir_all(&root)
                .with_context(|| format!("failed to remove stale fixture at {}", root.display()))?;
        }
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create fixture at {}", root.display()))?;
        fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"workspace-diagnostic-perf\"\nversion = \"0.0.0\"\nrequires-python = \">=3.12\"\n",
        )
        .context("failed to write the fixture configuration")?;

        for file_index in 0..FILES {
            let mut source = String::with_capacity(DIAGNOSTICS_PER_FILE * 36);
            for diagnostic_index in 0..DIAGNOSTICS_PER_FILE {
                let value = file_index * DIAGNOSTICS_PER_FILE + diagnostic_index;
                if matches!(workload, Workload::Rich) || diagnostic_index == 0 {
                    writeln!(source, "value_{value}: str = {value}")?;
                } else {
                    writeln!(source, "value_{value}: str = \"value_{value}\"")?;
                }
            }
            fs::write(root.join(format!("module_{file_index:03}.py")), source)
                .with_context(|| format!("failed to write fixture module {file_index}"))?;
        }

        Ok(Self { root })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct ServerClient {
    connection: Connection,
    next_request_id: i32,
    options: ClientOptions,
}

impl ServerClient {
    fn start(root: &Path) -> Result<(Self, JoinHandle<Result<()>>)> {
        let (server_connection, client_connection) = Connection::memory();
        let server_root = SystemPathBuf::from_path_buf(root.to_path_buf())
            .map_err(|path| anyhow!("fixture path is not valid UTF-8: {}", path.display()))?;
        let worker_threads = NonZeroUsize::new(1).ok_or_else(|| anyhow!("one is non-zero"))?;

        let server_thread = std::thread::spawn(move || -> Result<()> {
            let system = Arc::new(OsSystem::new(&server_root));
            let server = Server::new(worker_threads, server_connection, system, false)
                .map_err(|error| anyhow!("failed to start LSP server: {error}"))?;
            server
                .run()
                .map_err(|error| anyhow!("LSP server stopped with an error: {error}"))
        });

        let options = ClientOptions::default().with_diagnostic_mode(DiagnosticMode::Workspace);
        let mut client = Self {
            connection: client_connection,
            next_request_id: 0,
            options,
        };
        client.initialize(root)?;
        Ok((client, server_thread))
    }

    fn initialize(&mut self, root: &Path) -> Result<()> {
        let workspace_uri = lsp_types::Uri::from_file_path(root)
            .map_err(|()| anyhow!("failed to convert fixture root to an LSP URI"))?;
        let capabilities = ClientCapabilities {
            text_document: Some(TextDocumentClientCapabilities {
                diagnostic: Some(DiagnosticClientCapabilities::default()),
                ..TextDocumentClientCapabilities::default()
            }),
            workspace: Some(WorkspaceClientCapabilities {
                configuration: Some(true),
                ..WorkspaceClientCapabilities::default()
            }),
            experimental: Some(serde_json::json!({"fullDiagnosticOutput": true})),
            ..ClientCapabilities::default()
        };
        let params = InitializeParams {
            capabilities,
            workspace_folders_initialize_params: WorkspaceFoldersInitializeParams {
                workspace_folders: Some(
                    vec![WorkspaceFolder {
                        uri: workspace_uri,
                        name: "workspace-diagnostic-perf".to_string(),
                    }]
                    .into(),
                ),
            },
            initialization_options: Some(
                serde_json::to_value(&self.options)
                    .context("failed to serialize workspace diagnostic options")?,
            ),
            ..InitializeParams::default()
        };

        let initialize_id = self.send_request(InitializeRequest::METHOD.as_str(), params)?;
        let initialize_result = self.await_response(&initialize_id)?;
        let _: lsp_types::InitializeResult = serde_json::from_value(initialize_result)
            .context("server returned an invalid initialize response")?;
        self.send_notification(
            InitializedNotification::METHOD.as_str(),
            InitializedParams {},
        )?;
        self.wait_until_configured()
    }

    fn workspace_diagnostic(&mut self) -> Result<WorkspaceDiagnosticReport> {
        let params = WorkspaceDiagnosticParams {
            identifier: Some("ty".to_string()),
            previous_result_ids: Vec::new(),
            work_done_progress_params: WorkDoneProgressParams {
                work_done_token: Some(ProgressToken::String(
                    "workspace-diagnostic-perf".to_string(),
                )),
            },
            partial_result_params: PartialResultParams::default(),
        };
        let request_id = self.send_request(WorkspaceDiagnosticRequest::METHOD.as_str(), params)?;
        let response = self.await_response(&request_id)?;
        serde_json::from_value(response)
            .context("server returned an invalid workspace diagnostic response")
    }

    fn shutdown(&mut self) -> Result<()> {
        let request_id =
            self.send_request(lsp_types::ShutdownRequest::METHOD.as_str(), Value::Null)?;
        let _ = self.await_response(&request_id)?;
        self.send_notification(lsp_types::ExitNotification::METHOD.as_str(), Value::Null)
    }

    fn send_request(&mut self, method: &str, params: impl serde::Serialize) -> Result<RequestId> {
        self.next_request_id += 1;
        let request_id = RequestId::from(self.next_request_id);
        self.send(Message::Request(ServerRequest::new(
            request_id.clone(),
            method.to_string(),
            params,
        )))?;
        Ok(request_id)
    }

    fn send_notification(&self, method: &str, params: impl serde::Serialize) -> Result<()> {
        self.send(Message::Notification(lsp_server::Notification::new(
            method.to_string(),
            params,
        )))
    }

    fn send(&self, message: Message) -> Result<()> {
        self.connection
            .sender
            .send(message)
            .map_err(|error| anyhow!("LSP server disconnected: {error}"))
    }

    fn wait_until_configured(&mut self) -> Result<()> {
        loop {
            match self.receive()? {
                Message::Request(request)
                    if request.method == ConfigurationRequest::METHOD.as_str() =>
                {
                    self.handle_server_request(request)?;
                    return Ok(());
                }
                Message::Request(request) => self.handle_server_request(request)?,
                Message::Notification(_) => {}
                Message::Response(response) => {
                    bail!(
                        "received an unexpected response during initialization for request {}",
                        response.id
                    );
                }
            }
        }
    }

    fn await_response(&mut self, expected_id: &RequestId) -> Result<Value> {
        loop {
            match self.receive()? {
                Message::Response(response) if response.id == *expected_id => {
                    if let Some(error) = response.error {
                        bail!(
                            "server returned an error for request {expected_id}: {}",
                            error.message
                        );
                    }
                    return response
                        .result
                        .ok_or_else(|| anyhow!("server response for {expected_id} had no result"));
                }
                Message::Response(response) => {
                    bail!(
                        "received an unexpected response for request {} while waiting for {expected_id}",
                        response.id
                    );
                }
                Message::Request(request) => self.handle_server_request(request)?,
                Message::Notification(_) => {}
            }
        }
    }

    fn receive(&self) -> Result<Message> {
        self.connection
            .receiver
            .recv_timeout(RESPONSE_TIMEOUT)
            .map_err(|error| anyhow!("timed out waiting for an LSP message: {error}"))
    }

    fn handle_server_request(&self, request: ServerRequest) -> Result<()> {
        if request.method == ConfigurationRequest::METHOD.as_str() {
            let params: ConfigurationParams = serde_json::from_value(request.params)
                .context("server sent invalid workspace/configuration parameters")?;
            let mut values = Vec::with_capacity(params.items.len());
            for item in params.items {
                if item.section.as_deref() == Some("ty") {
                    values.push(
                        serde_json::to_value(&self.options)
                            .context("failed to serialize workspace configuration")?,
                    );
                } else {
                    values.push(Value::Null);
                }
            }
            return self.send(Message::Response(Response::new_ok(request.id, values)));
        }

        if request.method == WorkDoneProgressCreateRequest::METHOD.as_str() {
            return self.send(Message::Response(Response::new_ok(request.id, Value::Null)));
        }

        bail!(
            "server sent an unsupported client request: {}",
            request.method
        )
    }
}

struct Measurement {
    elapsed: Duration,
    reports: usize,
    diagnostic_items: usize,
}

fn marker(stage: &str) -> Result<()> {
    let Some(path) = std::env::var_os("PERFLOOP_PROBE_STATUS_FILE") else {
        return Ok(());
    };
    fs::write(&path, stage).with_context(|| {
        format!(
            "failed to write probe status marker at {}",
            PathBuf::from(path).display()
        )
    })
}

fn run(workload: Workload) -> Result<Measurement> {
    marker("starting")?;
    let fixture = Fixture::new(workload)?;
    let (mut client, server_thread) = ServerClient::start(&fixture.root)?;
    marker("ready")?;

    marker("active")?;
    let start = Instant::now();
    let report = client.workspace_diagnostic()?;
    let elapsed = start.elapsed();
    marker("complete")?;

    let mut reports = 0usize;
    let mut diagnostic_items = 0usize;
    for item in report.items {
        match item {
            WorkspaceDocumentDiagnosticReport::WorkspaceFullDocumentDiagnosticReport(full) => {
                reports += 1;
                diagnostic_items += full.full_document_diagnostic_report.items.len();
            }
            WorkspaceDocumentDiagnosticReport::WorkspaceUnchangedDocumentDiagnosticReport(_) => {
                bail!(
                    "fresh workspace diagnostic request unexpectedly returned an unchanged report"
                );
            }
        }
    }

    let expected_diagnostics = FILES * workload.expected_diagnostics_per_file();
    if reports != FILES || diagnostic_items < expected_diagnostics {
        bail!(
            "workspace diagnostic response was incomplete: expected at least {expected_diagnostics} diagnostics across {FILES} reports, got {diagnostic_items} diagnostics across {reports} reports"
        );
    }

    client.shutdown()?;
    drop(client);
    server_thread
        .join()
        .map_err(|_| anyhow!("LSP server thread panicked"))??;

    Ok(Measurement {
        elapsed,
        reports,
        diagnostic_items,
    })
}

fn main() -> Result<()> {
    ruff_db::set_program_version("workspace-diagnostic-perf".to_string())
        .map_err(|error| anyhow!("failed to set program version: {error}"))?;

    let measurement = run(Workload::parse()?)?;
    println!(
        "{}",
        serde_json::json!({
            "metric": "workspace_diagnostic_ns",
            "value": measurement.elapsed.as_nanos(),
        })
    );
    println!(
        "{}",
        serde_json::json!({
            "metric": "workspace_diagnostic_reports",
            "value": measurement.reports,
        })
    );
    println!(
        "{}",
        serde_json::json!({
            "metric": "workspace_diagnostic_items",
            "value": measurement.diagnostic_items,
        })
    );
    Ok(())
}
