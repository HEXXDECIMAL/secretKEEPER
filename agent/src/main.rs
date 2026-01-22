//! SecretKeeper Agent - Secret exfiltration prevention daemon.

mod cli;
mod config;
mod error;
mod ipc;
mod monitor;
mod process;
mod rules;
mod storage;

use crate::cli::{Args, Command};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::ipc::IpcServer;
use crate::monitor::{create_monitor, Mechanism, MonitorContext};
use crate::rules::RuleEngine;
use crate::storage::Storage;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_args();

    match &args.command {
        Some(Command::Version) => {
            print_version();
            return Ok(());
        }
        Some(Command::Check) => {
            return check_prerequisites();
        }
        Some(Command::CheckFda) => {
            // Silent FDA check - exit 0 if granted, 1 if not
            if check_full_disk_access() {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        }
        Some(Command::Validate { verbose }) => {
            return validate_config(&args, *verbose);
        }
        Some(Command::ListProtected { detailed }) => {
            return list_protected(&args, *detailed);
        }
        Some(Command::ShowConfig { format }) => {
            return show_config(&args, format);
        }
        Some(Command::Status) => {
            return show_status(&args).await;
        }
        Some(Command::DumpExceptions) => {
            return dump_exceptions(&args);
        }
        Some(Command::Run) | None => {
            // Continue to run the agent
        }
    }

    // Load configuration early so we can use its log_level
    let config = load_config(&args)?;

    // Initialize logging for daemon mode using config's log_level
    init_logging(&args, &config.agent.log_level);

    // Check root privileges
    if !args.skip_root_check && !is_root() {
        eprintln!("Error: secretkeeper-agent must be run as root");
        eprintln!("Try: sudo secretkeeper-agent");
        return Err(Error::NotRoot);
    }

    run_agent(&args, config).await
}

async fn run_agent(args: &Args, config: Config) -> Result<()> {
    tracing::info!("SecretKeeper v{} starting", VERSION);
    tracing::info!("Enforcement mode: {}", args.mode);
    tracing::info!("Protected file rules: {}", config.protected_files.len());
    for pf in &config.protected_files {
        tracing::info!("  [{}]: {}", pf.id, pf.patterns.join(", "));
    }
    if !config.excluded_patterns.is_empty() {
        tracing::info!("Excluded patterns: {}", config.excluded_patterns.join(", "));
    }

    // Open storage
    let storage = Arc::new(Storage::open(&config.agent.database_path)?);
    tracing::info!("Database: {}", config.agent.database_path.display());

    // Build rule engine
    let global_exclusions: Vec<rules::AllowRule> = config
        .global_exclusions
        .iter()
        .cloned()
        .map(Into::into)
        .collect();

    let mut rule_engine = RuleEngine::new(config.protected_files.clone(), global_exclusions);

    // Load exceptions from database
    let exceptions = storage.get_exceptions()?;
    if !exceptions.is_empty() {
        tracing::info!("Loaded {} exceptions from database", exceptions.len());
        rule_engine.set_exceptions(exceptions);
    }

    // Wrap rule engine in Arc<RwLock> for sharing between monitor and IPC
    let rule_engine = Arc::new(RwLock::new(rule_engine));

    // Serialize config for IPC
    let config_toml = toml::to_string_pretty(&config).unwrap_or_default();

    // Create shared state for mode and degraded mode
    let mode = Arc::new(RwLock::new(args.mode.clone()));
    let degraded_mode = Arc::new(RwLock::new(false));

    // Create IPC server
    let ipc_server = IpcServer::new(
        &config.agent.socket_path,
        storage.clone(),
        mode.clone(),
        degraded_mode.clone(),
        config_toml,
        rule_engine.clone(),
    )
    .await?;
    tracing::info!("IPC socket: {}", config.agent.socket_path.display());

    // Get event sender for monitor
    let event_tx = ipc_server.event_sender();

    // Create monitor context with rate limiting
    let monitor_context = Arc::new(MonitorContext::new(
        config.clone(),
        rule_engine,
        storage.clone(),
        event_tx,
        mode.clone(),
        degraded_mode.clone(),
    ));

    // Parse mechanism
    let mechanism: Mechanism = args.mechanism.parse()?;
    tracing::info!("Monitor mechanism: {:?}", mechanism.resolve());

    // Create monitor
    let mut monitor = create_monitor(mechanism, monitor_context)?;

    // Run IPC server in background
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server.run().await {
            tracing::error!("IPC server error: {}", e);
        }
    });

    // Set up signal handling
    let shutdown = setup_signal_handler();

    tracing::info!("Agent ready - monitoring file access");

    // Run monitor
    tokio::select! {
        result = monitor.start() => {
            if let Err(e) = result {
                tracing::error!("Monitor error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown => {
            tracing::info!("Received shutdown signal");
            monitor.stop().await?;
        }
    }

    // Clean up
    ipc_handle.abort();
    tracing::info!("SecretKeeper agent stopped");

    Ok(())
}

fn print_version() {
    println!("secretkeeper-agent {}", VERSION);
    println!();
    println!("Build info:");
    println!("  Target: {}", std::env::consts::ARCH);
    println!("  OS: {}", std::env::consts::OS);

    #[cfg(target_os = "macos")]
    println!("  Monitor: eslogger (Endpoint Security)");

    #[cfg(target_os = "linux")]
    println!("  Monitor: fanotify");

    #[cfg(target_os = "freebsd")]
    println!("  Monitor: dtrace");
}

fn check_prerequisites() -> Result<()> {
    println!("Checking system prerequisites...\n");

    let mut all_ok = true;

    // Check if running as root
    let is_root = is_root();
    print_check("Running as root", is_root, Some("Required for monitoring"));
    if !is_root {
        all_ok = false;
    }

    // Platform-specific checks
    #[cfg(target_os = "macos")]
    {
        // Check eslogger availability
        let eslogger_available = std::process::Command::new("which")
            .arg("eslogger")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        print_check(
            "eslogger available",
            eslogger_available,
            Some("macOS 13+ built-in"),
        );
        if !eslogger_available {
            all_ok = false;
        }

        // Check macOS version
        let macos_version = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let major_version: u32 = macos_version
            .trim()
            .split('.')
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let macos_ok = major_version >= 13;
        print_check(
            &format!("macOS version ({})", macos_version.trim()),
            macos_ok,
            Some("Requires macOS 13+"),
        );
        if !macos_ok {
            all_ok = false;
        }

        // Check Full Disk Access by actually testing eslogger
        // This is the only reliable way to check FDA
        let has_fda = check_full_disk_access();
        print_check(
            "Full Disk Access",
            has_fda,
            Some("Required for file monitoring"),
        );
        if !has_fda {
            println!("      To grant FDA: System Settings > Privacy & Security > Full Disk Access");
            println!("      Add: /Library/PrivilegedHelperTools/secretkeeper-agent");
            all_ok = false;
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Check fanotify capability
        let has_cap = std::process::Command::new("capsh")
            .arg("--print")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.contains("cap_sys_admin"))
            .unwrap_or(false);
        print_check(
            "CAP_SYS_ADMIN capability",
            has_cap || is_root,
            Some("Required for fanotify"),
        );
    }

    #[cfg(target_os = "freebsd")]
    {
        // Check dtrace availability
        let dtrace_available = std::process::Command::new("which")
            .arg("dtrace")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        print_check("dtrace available", dtrace_available, None);
        if !dtrace_available {
            all_ok = false;
        }
    }

    // Check config directory
    let config_path = config::default_config_path();
    let config_dir = config_path.parent().unwrap_or(&config_path);
    let config_dir_exists = config_dir.exists();
    print_check(
        &format!("Config directory ({})", config_dir.display()),
        config_dir_exists,
        Some("Will be created on install"),
    );

    // Check socket directory
    let socket_path = config::default_socket_path();
    let socket_dir = socket_path.parent().unwrap_or(&socket_path);
    let socket_dir_exists = socket_dir.exists();
    print_check(
        &format!("Socket directory ({})", socket_dir.display()),
        socket_dir_exists,
        None,
    );

    println!();
    if all_ok {
        println!("All prerequisites satisfied.");
        Ok(())
    } else {
        println!("Some prerequisites are not met.");
        Err(Error::config("Prerequisites check failed"))
    }
}

fn print_check(name: &str, ok: bool, note: Option<&str>) {
    let status = if ok { "OK" } else { "FAIL" };
    let symbol = if ok { "✓" } else { "✗" };
    print!("  {} {} {}", symbol, status, name);
    if let Some(n) = note {
        print!(" ({})", n);
    }
    println!();
}

/// Check if Full Disk Access is granted by testing eslogger.
/// This is the only reliable way to check FDA on macOS.
#[cfg(target_os = "macos")]
#[allow(clippy::lines_filter_map_ok)]
fn check_full_disk_access() -> bool {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    // Run eslogger briefly and check for FDA error
    let mut child = match Command::new("eslogger")
        .args(["open", "--format", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Give it a moment to start and potentially fail
    std::thread::sleep(Duration::from_millis(500));

    // Check if it's still running (good sign) or exited (might be FDA error)
    match child.try_wait() {
        Ok(Some(_status)) => {
            // Process exited - check stderr for FDA error
            if let Some(stderr) = child.stderr.take() {
                let reader = BufReader::new(stderr);
                for line in reader.lines().filter_map(|l| l.ok()) {
                    if line.contains("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
                        || line.contains("Not permitted to create an ES Client")
                    {
                        return false;
                    }
                }
            }
            // Exited for some other reason - assume no FDA
            false
        }
        Ok(None) => {
            // Still running - has FDA!
            let _ = child.kill();
            true
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "macos"))]
fn check_full_disk_access() -> bool {
    // FDA is macOS-specific
    true
}

fn validate_config(args: &Args, verbose: bool) -> Result<()> {
    println!("Validating configuration...\n");

    let config = match load_config(args) {
        Ok(c) => {
            println!("  ✓ Configuration loaded successfully");
            c
        }
        Err(e) => {
            println!("  ✗ Configuration error: {}", e);
            return Err(e);
        }
    };

    // Validate each section
    println!("\nConfiguration summary:");
    println!("  Agent:");
    println!("    Log level: {}", config.agent.log_level);
    println!("    Socket: {}", config.agent.socket_path.display());
    println!("    Database: {}", config.agent.database_path.display());

    println!("  Monitoring:");
    println!("    Mechanism: {}", config.monitoring.mechanism);
    println!("    Buffer size: {}", config.monitoring.buffer_size);

    println!("  Enforcement:");
    println!("    Mode: {}", config.enforcement.mode);
    println!(
        "    History retention: {} days",
        config.enforcement.history_retention_days
    );

    println!("  Protected files: {} rules", config.protected_files.len());
    println!(
        "  Global exclusions: {} rules",
        config.global_exclusions.len()
    );
    println!("  Exceptions: {} rules", config.exceptions.len());
    println!(
        "  Excluded patterns: {} patterns",
        config.excluded_patterns.len()
    );

    if verbose {
        println!("\nProtected file rules:");
        for pf in &config.protected_files {
            println!("  [{}]", pf.id);
            for pattern in &pf.patterns {
                println!("    Pattern: {}", pattern);
            }
            println!("    Allow rules: {}", pf.allow.len());
        }
    }

    println!("\n✓ Configuration is valid");
    Ok(())
}

fn list_protected(args: &Args, detailed: bool) -> Result<()> {
    let config = load_config(args)?;

    println!("Protected file patterns:\n");

    for pf in &config.protected_files {
        println!("[{}]", pf.id);
        for pattern in &pf.patterns {
            println!("  {}", pattern);
        }

        if detailed && !pf.allow.is_empty() {
            println!("  Allow rules:");
            for rule in &pf.allow {
                let mut conditions = Vec::new();
                if let Some(ref base) = rule.base {
                    conditions.push(format!("base={}", base));
                }
                if let Some(ref path) = rule.path {
                    conditions.push(format!("path={}", path));
                }
                if let Some(ref team_id) = rule.team_id {
                    conditions.push(format!("team_id={}", team_id));
                }
                if let Some((min, max)) = rule.euid {
                    if min == max {
                        conditions.push(format!("euid={}", min));
                    } else {
                        conditions.push(format!("euid={}-{}", min, max));
                    }
                }
                if let Some(platform) = rule.platform_binary {
                    conditions.push(format!("platform_binary={}", platform));
                }
                println!("    - {}", conditions.join(", "));
            }
        }
        println!();
    }

    println!("Excluded patterns (never protected):");
    for pattern in &config.excluded_patterns {
        println!("  {}", pattern);
    }

    Ok(())
}

fn show_config(args: &Args, format: &str) -> Result<()> {
    let config = load_config(args)?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        _ => {
            // Default to TOML format
            println!(
                "{}",
                toml::to_string_pretty(&config).map_err(|e| Error::config(e.to_string()))?
            );
        }
    }

    Ok(())
}

async fn show_status(args: &Args) -> Result<()> {
    let config = load_config(args)?;

    println!("SecretKeeper Agent Status\n");

    // Check if socket exists
    let socket_exists = config.agent.socket_path.exists();
    println!(
        "Agent running: {}",
        if socket_exists { "Yes" } else { "No" }
    );
    println!("Socket: {}", config.agent.socket_path.display());

    if socket_exists {
        // Try to connect and get status
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        match UnixStream::connect(&config.agent.socket_path).await {
            Ok(stream) => {
                let (reader, mut writer) = stream.into_split();
                writer.write_all(b"{\"action\":\"status\"}\n").await.ok();

                let mut reader = BufReader::new(reader);
                let mut response = String::new();
                if reader.read_line(&mut response).await.is_ok() {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response) {
                        println!();
                        if let Some(mode) = json.get("mode").and_then(|v| v.as_str()) {
                            println!("Mode: {}", mode);
                        }
                        if let Some(uptime) = json.get("uptime_secs").and_then(|v| v.as_u64()) {
                            println!("Uptime: {}s", uptime);
                        }
                        if let Some(clients) =
                            json.get("connected_clients").and_then(|v| v.as_u64())
                        {
                            println!("Connected clients: {}", clients);
                        }
                        if let Some(violations) =
                            json.get("total_violations").and_then(|v| v.as_u64())
                        {
                            println!("Total violations: {}", violations);
                        }
                    }
                }
            }
            Err(e) => {
                println!("Could not connect to agent: {}", e);
            }
        }
    }

    // Check database
    if config.agent.database_path.exists() {
        println!("\nDatabase: {}", config.agent.database_path.display());
        if let Ok(storage) = Storage::open(&config.agent.database_path) {
            if let Ok(count) = storage.count_violations() {
                println!("Recorded violations: {}", count);
            }
            if let Ok(exceptions) = storage.get_exceptions() {
                println!("Active exceptions: {}", exceptions.len());
            }
        }
    }

    Ok(())
}

fn dump_exceptions(args: &Args) -> Result<()> {
    let config = load_config(args)?;

    if !config.agent.database_path.exists() {
        eprintln!(
            "Database not found: {}",
            config.agent.database_path.display()
        );
        eprintln!("No exceptions to dump.");
        return Ok(());
    }

    let storage = Storage::open(&config.agent.database_path)?;
    let exceptions = storage.get_exceptions()?;

    if exceptions.is_empty() {
        eprintln!("# No exceptions found in database");
        return Ok(());
    }

    println!(
        "# Exceptions exported from {}",
        config.agent.database_path.display()
    );
    println!("# Generated: {}", chrono::Utc::now().to_rfc3339());
    println!("# Count: {}", exceptions.len());
    println!();

    for exception in exceptions {
        println!("[[exceptions]]");
        if let Some(ref process_path) = exception.process_path {
            println!("process_path = \"{}\"", escape_toml_string(process_path));
        }
        if let Some(ref signer_type) = exception.signer_type {
            println!("signer_type = \"{}\"", signer_type);
        }
        if let Some(ref team_id) = exception.team_id {
            println!("team_id = \"{}\"", escape_toml_string(team_id));
        }
        if let Some(ref signing_id) = exception.signing_id {
            println!("signing_id = \"{}\"", escape_toml_string(signing_id));
        }
        println!(
            "file_pattern = \"{}\"",
            escape_toml_string(&exception.file_pattern)
        );
        if let Some(ref expires_at) = exception.expires_at {
            println!("expires_at = \"{}\"", expires_at.to_rfc3339());
        }
        if let Some(ref comment) = exception.comment {
            println!("comment = \"{}\"", escape_toml_string(comment));
        }
        println!();
    }

    Ok(())
}

fn escape_toml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn init_logging(args: &Args, config_log_level: &str) {
    // CLI flags take precedence, then config, then default to warn
    let filter = if args.debug {
        "debug,rusqlite=warn"
    } else if args.verbose {
        "info,rusqlite=warn"
    } else {
        // Use config's log_level
        match config_log_level {
            "trace" => "trace,rusqlite=warn",
            "debug" => "debug,rusqlite=warn",
            "info" => "info,rusqlite=warn",
            "warn" => "warn",
            "error" => "error",
            _ => "info,rusqlite=warn", // Default to info if unrecognized
        }
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .init();
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(not(unix))]
    {
        false
    }
}

fn load_config(args: &Args) -> Result<Config> {
    match &args.config {
        Some(path) => config::load_config(path),
        None => {
            let default_path = config::default_config_path();
            if default_path.exists() {
                config::load_config(&default_path)
            } else {
                Ok(Config::default())
            }
        }
    }
}

async fn setup_signal_handler() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT");

        tokio::select! {
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
}
