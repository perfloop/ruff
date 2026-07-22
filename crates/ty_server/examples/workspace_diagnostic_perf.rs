//! Standalone workspace-diagnostic workload used by the performance case.
//!
//! The driver talks to the public LSP server over an in-memory LSP connection.
//! It deliberately uses a multi-file, diagnostic-rich workspace so that every
//! worker has to construct a full document diagnostic report. The measured
//! interval starts when it sends `workspace/diagnostic` and ends when the
//! complete LSP response is received. Each proof sample warms one instance,
//! then reports the arithmetic mean of four fresh request/response spans.

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

const MEASURED_REQUESTS: u32 = 4;
const SAMPLE_SHAPE: WorkloadShape = WorkloadShape {
    files: 64,
    diagnostics_per_file: 64,
};
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum Workload {
    Rich,
    Sparse,
}

impl Workload {
    const fn expected_diagnostics_per_file(self, shape: WorkloadShape) -> usize {
        match self {
            Self::Rich => shape.diagnostics_per_file,
            Self::Sparse => 1,
        }
    }
}

#[derive(Clone, Copy)]
struct WorkloadShape {
    files: usize,
    diagnostics_per_file: usize,
}

struct RunPlan {
    workload: Workload,
    shape: WorkloadShape,
    measured_requests: u32,
    warmup: bool,
}

impl RunPlan {
    fn parse() -> Result<Self> {
        let argument = std::env::args().nth(1);
        match argument.as_deref() {
            Some("--sample") => Ok(Self {
                workload: Workload::Rich,
                shape: SAMPLE_SHAPE,
                measured_requests: MEASURED_REQUESTS,
                warmup: true,
            }),
            Some("--sparse-sample") => Ok(Self {
                workload: Workload::Sparse,
                shape: SAMPLE_SHAPE,
                measured_requests: MEASURED_REQUESTS,
                warmup: true,
            }),
            _ => bail!("usage: workspace_diagnostic_perf [--sample|--sparse-sample]"),
        }
    }
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(workload: Workload, shape: WorkloadShape, run_index: u32) -> Result<Self> {
        let root = std::env::current_dir()
            .context("failed to determine the repository root")?
            .join(".perfloop-workspace-diagnostic")
            .join(format!(
                "{}-{}-{}-{run_index}",
                std::process::id(),
                shape.files,
                workload.expected_diagnostics_per_file(shape)
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

        for file_index in 0..shape.files {
            let mut source = String::with_capacity(shape.diagnostics_per_file * 36);
            for diagnostic_index in 0..shape.diagnostics_per_file {
                let value = run_index as usize * shape.files * shape.diagnostics_per_file
                    + file_index * shape.diagnostics_per_file
                    + diagnostic_index;
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
            // Test mode suppresses only process-global logging initialization, allowing the
            // fixed set of fresh server instances used for one benchmark sample.
            let server = Server::new(worker_threads, server_connection, system, true)
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

fn run_once(plan: &RunPlan, run_index: u32) -> Result<Measurement> {
    let fixture = Fixture::new(plan.workload, plan.shape, run_index)?;
    let (mut client, server_thread) = ServerClient::start(&fixture.root)?;

    let start = Instant::now();
    let report = client.workspace_diagnostic()?;
    let elapsed = start.elapsed();

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

    let expected_diagnostics =
        plan.shape.files * plan.workload.expected_diagnostics_per_file(plan.shape);
    if reports != plan.shape.files || diagnostic_items < expected_diagnostics {
        bail!(
            "workspace diagnostic response was incomplete: expected at least {expected_diagnostics} diagnostics across {} reports, got {diagnostic_items} diagnostics across {reports} reports",
            plan.shape.files
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

fn run(plan: RunPlan) -> Result<Measurement> {
    if plan.warmup {
        let _ = run_once(&plan, 0)?;
    }

    let mut elapsed = Duration::ZERO;
    let mut reports = 0usize;
    let mut diagnostic_items = 0usize;
    for run_index in 1..=plan.measured_requests {
        let measurement = run_once(&plan, run_index)?;
        elapsed += measurement.elapsed;
        reports = measurement.reports;
        diagnostic_items = measurement.diagnostic_items;
    }

    Ok(Measurement {
        elapsed: elapsed / plan.measured_requests,
        reports,
        diagnostic_items,
    })
}

fn main() -> Result<()> {
    ruff_db::set_program_version("workspace-diagnostic-perf".to_string())
        .map_err(|error| anyhow!("failed to set program version: {error}"))?;

    let measurement = run(RunPlan::parse()?)?;
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
