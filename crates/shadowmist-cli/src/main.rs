use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use shadowmist_core::*;
use shadowmist_platform_linux as linux;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(name="shadowmist",version,about="Reversible Linux network privacy; no anonymity guarantee",after_help=PRIVACY_LIMITS)]
struct Cli {
    #[arg(long,global=true,default_value=linux::DEFAULT_CONFIG)]
    config: PathBuf,
    #[arg(long,global=true,default_value=linux::DEFAULT_STATE)]
    state_dir: PathBuf,
    #[arg(
        long,
        global = true,
        help = "Show local MACs/addresses/profile UUIDs at the console"
    )]
    verbose: bool,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Status {
        #[arg(long)]
        json: bool,
        #[arg(
            long,
            help = "Issue uncached lookups only to configured health_domains"
        )]
        probe: bool,
    },
    Doctor {
        #[arg(long)]
        json: bool,
    },
    Audit {
        #[arg(long)]
        json: bool,
    },
    Interfaces {
        #[arg(long)]
        json: bool,
    },
    Dns {
        #[command(subcommand)]
        command: DnsCommands,
    },
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
    Apply {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        #[arg(
            long = "replace-search-domain",
            value_name = "DOMAIN",
            help = "Explicitly replace this enrolled link's ordinary DNS search domain; local names may stop resolving (repeat for multiple domains)"
        )]
        replace_search_domains: Vec<String>,
    },
    Restore {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    #[command(hide = true)]
    Recover {
        #[arg(long)]
        transaction: Option<String>,
    },
    Version,
}
#[derive(Subcommand)]
enum DnsCommands {
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        probe: bool,
    },
}
#[derive(Subcommand)]
enum IdentityCommands {
    Status {
        #[arg(long)]
        json: bool,
    },
    Rotate {
        #[arg(long)]
        interface: String,
        #[arg(long)]
        reconnect: bool,
        #[arg(long)]
        acknowledge_disconnect: bool,
        #[arg(long)]
        force_remote: bool,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Balanced,
    Observe,
    Strict,
}
#[derive(Subcommand)]
enum ProfileCommands {
    Set { profile: Mode },
}
#[derive(Subcommand)]
enum ConfigCommands {
    Validate,
    Show {
        #[arg(long)]
        json: bool,
    },
}
fn print_report(r: &Report, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(r).expect("serializable report")
        );
        return;
    }
    println!(
        "Shadow Mist {:?} | profile {:?}\nDNS: {:?} — {}",
        r.state, r.profile, r.dns.state, r.dns.reason
    );
    for f in &r.findings {
        println!(
            "{:?} {}: {}\n  {}",
            f.severity, f.code, f.evidence, f.mitigation
        );
    }
    println!("\n{}", r.limitations);
}
fn print_plan(p: &Plan, json: bool, verbose: bool) {
    if json {
        if verbose {
            println!("{}", serde_json::to_string_pretty(p).unwrap());
        } else {
            let mut value = serde_json::to_value(p).unwrap();
            if let Some(changes) = value["changes"].as_array_mut() {
                for c in changes {
                    c["before"] = "[redacted]".into();
                    c["after"] = "[redacted]".into();
                    if c["target"].get("uuid").is_some() {
                        c["target"]["uuid"] = "[redacted]".into();
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
        }
        return;
    }
    println!(
        "{} planned change(s); reconnect: {}; live DNS: {}",
        p.changes.len(),
        p.reconnect,
        p.dns_live
    );
    for (i, c) in p.changes.iter().enumerate() {
        let key = match &c.target {
            Target::Nm { key, .. } | Target::Resolved { key, .. } => key,
        };
        println!("{}. {}: {}", i + 1, key, c.reason);
        if verbose {
            println!("   {:?}: {:?} -> {:?}", c.target, c.before, c.after);
        }
    }
    for warning in &p.warnings {
        println!("WARN: {warning}");
    }
    println!("Recovery: sudo shadowmist restore --dry-run; sudo shadowmist restore");
}
fn run(cli: Cli) -> Result<u8> {
    if matches!(cli.command, Commands::Version) {
        println!(
            "shadowmist {} (status schema {})",
            env!("CARGO_PKG_VERSION"),
            SCHEMA_VERSION
        );
        return Ok(0);
    }
    let mut config = if matches!(
        cli.command,
        Commands::Restore { .. } | Commands::Recover { .. }
    ) {
        linux::load_config(&cli.config).unwrap_or_else(|_| {
            eprintln!(
                "Configuration unavailable/invalid; recovery uses recorded journal values only."
            );
            Config::default()
        })
    } else {
        linux::load_config(&cli.config).map_err(|e| e.context("invalid input: configuration"))?
    };
    if cli.verbose {
        eprintln!("Local sensitive identifiers may appear in console output.");
    }
    match cli.command {
        Commands::Config {
            command: ConfigCommands::Validate,
        } => {
            config.validate()?;
            println!("Configuration valid (schema {})", config.schema_version);
            Ok(0)
        }
        Commands::Config {
            command: ConfigCommands::Show { json },
        } => {
            if json {
                println!("{}", serde_json::to_string_pretty(&config)?);
            } else {
                println!("{}", toml::to_string_pretty(&config)?);
            }
            Ok(0)
        }
        Commands::Profile {
            command: ProfileCommands::Set { profile },
        } => {
            linux::secure_config(&cli.config)?;
            config.general.profile=match profile{Mode::Balanced=>Profile::Balanced,Mode::Observe=>Profile::Observe,Mode::Strict=>bail!("unsupported: strict mode requires phase 2 enforcement and isolated verification")};
            config.validate()?;
            let _lock = linux::lock_state(&cli.state_dir)?;
            let backup = cli
                .config
                .with_extension(format!("toml.{}.bak", linux::transaction_id()));
            linux::atomic_write(&backup, &std::fs::read(&cli.config)?, 0o600)?;
            linux::atomic_write(
                &cli.config,
                toml::to_string_pretty(&config)?.as_bytes(),
                0o644,
            )?;
            println!("Profile saved. Network settings remain until explicit apply/restore. Restart daemon to reload configuration.");
            Ok(0)
        }
        Commands::Apply {
            dry_run,
            json,
            replace_search_domains,
        } => {
            if replace_search_domains
                .iter()
                .any(|domain| !valid_search_domain(domain))
            {
                bail!("invalid input: replace-search-domain requires a literal search domain, without routing prefixes or wildcards")
            }
            if dry_run {
                let h = linux::discover(&config);
                let p = plan_replacing_search_domains(&config, &h, &replace_search_domains);
                print_plan(&p, json, cli.verbose);
                return Ok(if p.warnings.is_empty() { 0 } else { 2 });
            }
            let (p, j) = linux::apply_replacing_search_domains(
                &config,
                &cli.config,
                &cli.state_dir,
                &replace_search_domains,
            )?;
            print_plan(&p, json, cli.verbose);
            if !json {
                println!(
                    "{}",
                    if j.is_some() {
                        "Transaction committed. MAC/IPv6 policy applies on next activation."
                    } else {
                        "No changes applied."
                    }
                );
            }
            Ok(if p.warnings.is_empty() { 0 } else { 2 })
        }
        Commands::Restore { dry_run, json } => {
            let journals = linux::restore(&cli.state_dir, &config, dry_run)?;
            if json {
                let view:Vec<_>=journals.iter().map(|j|serde_json::json!({"id":j.id,"state":j.state,"changes":j.attempted,"dns_live":j.dns_live})).collect();
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                println!("{} transaction(s) {}. Persistent profiles are restored; an already active MAC/IPv6 address is preserved until next activation.",journals.len(),if dry_run{"would be restored (zero changes)"}else{"restored"});
                for j in journals {
                    println!(
                        "{}: {} recorded changes; conflicts preserve administrator values",
                        j.id, j.attempted
                    );
                    if dry_run {
                        for c in j.changes[..j.attempted].iter().rev() {
                            let key = match &c.target {
                                Target::Nm { key, .. } | Target::Resolved { key, .. } => key,
                            };
                            println!("  Restore {key}: {}", c.reason);
                            if cli.verbose {
                                println!("    {:?}: {:?} -> {:?}", c.target, c.after, c.before);
                            }
                        }
                    }
                }
            }
            Ok(0)
        }
        Commands::Recover { transaction } => {
            let n = linux::recover(&cli.state_dir, &config, transaction.as_deref())?;
            println!("Recovered {n} incomplete transaction(s)");
            Ok(0)
        }
        Commands::Identity {
            command:
                IdentityCommands::Rotate {
                    interface,
                    reconnect,
                    acknowledge_disconnect,
                    force_remote,
                },
        } => {
            eprintln!("Explicit reconnection can drop SSH, VPN, calls and sessions. MAC changes do not change public IP.");
            linux::rotate(
                &config,
                &cli.config,
                &cli.state_dir,
                &interface,
                reconnect,
                acknowledge_disconnect,
                force_remote,
            )?;
            println!("Effective MAC rotation and reconnection verified.");
            Ok(0)
        }
        command => {
            if matches!(command, Commands::Status { probe: false, .. })
                && !cli.verbose
                && cli.config == std::path::Path::new(linux::DEFAULT_CONFIG)
                && cli.state_dir == std::path::Path::new(linux::DEFAULT_STATE)
            {
                if let Some(r) = linux::published_status(config.general.reconcile_seconds * 2 + 30)
                {
                    let json = matches!(command, Commands::Status { json: true, .. });
                    print_report(&r, json);
                    return Ok(
                        if matches!(r.state, Protection::Verified | Protection::Observe) {
                            0
                        } else {
                            2
                        },
                    );
                }
            }
            let (json, probe) = match command {
                Commands::Status { json, probe }
                | Commands::Dns {
                    command: DnsCommands::Status { json, probe },
                } => (json, probe),
                Commands::Doctor { json }
                | Commands::Audit { json }
                | Commands::Interfaces { json }
                | Commands::Identity {
                    command: IdentityCommands::Status { json },
                } => (json, false),
                _ => unreachable!(),
            };
            let h = linux::discover(&config);
            let mut r = linux::report(&config, &h, &cli.state_dir, probe);
            if !cli.verbose {
                r = r.redacted();
            }
            match command {
                Commands::Interfaces { .. } | Commands::Identity { .. } => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&r.interfaces)?);
                    } else {
                        for i in &r.interfaces {
                            println!(
                                "{}: {} / {}; eligible physical: {}; effective MAC: {}",
                                i.name,
                                i.kind,
                                i.state,
                                !i.excluded,
                                i.effective_mac
                                    .as_deref()
                                    .unwrap_or("redacted; use --verbose")
                            );
                        }
                        for c in &h.connections {
                            let policy = c
                                .settings
                                .get(if c.kind == "802-11-wireless" {
                                    "802-11-wireless.cloned-mac-address"
                                } else {
                                    "802-3-ethernet.cloned-mac-address"
                                })
                                .map(String::as_str)
                                .unwrap_or("unknown");
                            println!(
                                "{}: configured MAC policy {}; enrolled: {}",
                                c.interface,
                                policy,
                                config.general.enrolled_profiles.contains(&c.uuid)
                            );
                        }
                        println!("{}", PRIVACY_LIMITS);
                    }
                }
                Commands::Dns { .. } => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&r.dns)?);
                    } else {
                        println!(
                            "DNS {:?}: {}\nScope: {}\nApplication-wide enforcement: {}",
                            r.dns.state, r.dns.reason, r.dns.scope, r.dns.enforced
                        );
                    }
                }
                _ => print_report(&r, json),
            }
            Ok(
                if matches!(r.state, Protection::Verified | Protection::Observe) {
                    0
                } else {
                    2
                },
            )
        }
    }
}
fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { 3 } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("shadowmist: {e:#}");
            let text = format!("{e:#}");
            ExitCode::from(if text.contains("unsupported") {
                4
            } else if text.contains("invalid input") {
                3
            } else if text.contains("DEGRADED") {
                2
            } else {
                5
            })
        }
    }
}
