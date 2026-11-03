#![recursion_limit = "256"]

//! Kinbase: the Company-memory member of the three-store Kindex system.
//!
//! Foundation rewrite (dispatch 009): the modules below implement the
//! ratified data model, canonicalization, signing, scanners, the private
//! store, the Codebase store, the reducer, the Company service/client/cache,
//! the launcher, and process containment. `repository.rs` (status/doctor/
//! fsck/repo commands) is present on disk but not yet compiled because it
//! depends on the not-yet-written `adapters` and `hooks` modules; the CLI
//! surface is not yet wired to this foundation (see the Coder report).
pub mod adapters;
pub mod classifier;
pub mod classify;
pub mod cli;
pub mod codebase;
pub mod command_types;
pub mod company;
pub mod config;
pub mod corpus;
pub mod crypto;
pub mod dream;
pub mod error;
pub mod hash;
pub mod hooks;
pub mod http;
pub mod ingest;
pub mod json;
pub mod launcher;
pub mod ledger_index;
pub mod lifecycle;
pub mod model;
pub mod oidc;
pub mod output;
pub mod paths;
#[cfg(feature = "personal-recall")]
pub mod personal_kindex;
pub mod private;
pub mod projector;
pub mod questions;
pub mod reducer;
pub mod repository;
pub mod sandbox;
pub mod scanner;
pub mod score;
pub mod secret_mask;
pub mod session;
pub mod store;
pub mod time;
pub mod usage;

pub use crate::command_types::*;
pub use clap::Parser;

#[derive(Parser)]
#[command(name = "kinbase", version = env!("CARGO_PKG_VERSION"), about = "Three-store knowledge system for brownfield coding")]
pub struct Cli {
    #[arg(long, global = true, help = "Emit canonical JSON receipts")]
    pub json: bool,
    #[command(subcommand)]
    pub command: Command,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    Personal,
    Company,
    Codebase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Codex,
    Claude,
}
