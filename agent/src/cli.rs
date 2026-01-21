//! Command-line interface definitions.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// SecretKeeper - Prevent secret exfiltration from your system
#[derive(Parser, Debug)]
#[command(name = "secretkeeper-agent")]
#[command(author, version, about)]
#[command(after_help = "EXAMPLES:
    # Start in block mode (default) - requires Full Disk Access
    sudo secretkeeper-agent

    # Start in best-effort mode (try to stop processes, can't prevent access)
    sudo secretkeeper-agent --mode best-effort

    # Start in monitor-only mode (log but don't block or stop)
    sudo secretkeeper-agent --mode monitor

    # Use custom config file
    sudo secretkeeper-agent --config /path/to/config.toml

    # Validate configuration
    secretkeeper-agent validate --config /path/to/config.toml

    # List protected files
    secretkeeper-agent list-protected

    # Check agent status
    secretkeeper-agent status
")]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Enforcement mode: "block" (prevent access, requires FDA), "best-effort" (try to stop processes), or "monitor" (log only)
    #[arg(short = 'm', long, default_value = "block")]
    pub mode: String,

    /// Monitoring mechanism (auto, eslogger, esf, fanotify, dtrace)
    #[arg(short = 'M', long, default_value = "auto")]
    pub mechanism: String,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Enable debug output
    #[arg(short, long)]
    pub debug: bool,

    /// Skip root privilege check (for testing only)
    #[arg(long, hide = true)]
    pub skip_root_check: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the agent daemon (default if no command specified)
    Run,

    /// Validate configuration file
    Validate {
        /// Show detailed validation output
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show current agent status
    Status,

    /// List all protected file patterns
    ListProtected {
        /// Show allow rules for each pattern
        #[arg(short, long)]
        detailed: bool,
    },

    /// Show loaded configuration
    ShowConfig {
        /// Output format (toml, json)
        #[arg(short, long, default_value = "toml")]
        format: String,
    },

    /// Check system prerequisites
    Check,

    /// Show version and build info
    Version,
}

impl Args {
    pub fn parse_args() -> Self {
        Args::parse()
    }
}
