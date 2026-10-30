use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use shadowborn_core::{Config, PeerStatus, State};
use shadowborn_platform as platform;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "shadowborn",
    version,
    about = "Shadowborn gateway provisioning; live apply and strict activation are release-gated"
)]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/shadowborn/config.toml")]
    config: PathBuf,
    #[arg(long, global = true, default_value = "/var/lib/shadowborn")]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Version,
    Doctor,
    Validate,
    Init {
        #[arg(long)]
        dry_run: bool,
    },
    Plan {
        #[arg(long)]
        json: bool,
    },
    /// Export a new root-only directory. Does not install or activate networking.
    Render {
        #[arg(long)]
        output: PathBuf,
    },
    /// Live application remains unsupported; dry-run prints the provisioning plan.
    Apply {
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Status,
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },
    Firewall {
        #[command(subcommand)]
        command: FirewallCommand,
    },
    Backup {
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        output: PathBuf,
    },
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        dry_run: bool,
    },
    Uninstall {
        #[arg(long)]
        plan: bool,
    },
}
#[derive(Subcommand)]
enum ServerCommand {
    Status,
}
#[derive(Subcommand)]
enum DnsCommand {
    Status,
}
#[derive(Subcommand)]
enum FirewallCommand {
    Plan,
}
#[derive(Subcommand)]
enum PeerCommand {
    List,
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_key: String,
    },
    /// Explicit convenience flow: creates a client private key in server memory.
    Issue {
        #[arg(long)]
        name: String,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        accept_server_key_generation: bool,
    },
    Disable {
        #[arg(long)]
        name: String,
        #[arg(long)]
        confirm: bool,
    },
    Revoke {
        #[arg(long)]
        name: String,
        #[arg(long)]
        confirm: bool,
    },
    RotatePsk {
        #[arg(long)]
        name: String,
        #[arg(long)]
        confirm: bool,
    },
    ExportPublic {
        #[arg(long)]
        name: String,
    },
    Show {
        #[arg(long)]
        name: String,
        #[arg(long, required = true)]
        redacted: bool,
    },
}
#[derive(Subcommand)]
enum ClientCommand {
    Profile {
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
    },
    Lockdown {
        #[command(subcommand)]
        command: LockdownCommand,
    },
}
#[derive(Subcommand)]
enum LockdownCommand {
    Plan,
    Status,
    Enable {
        #[arg(long)]
        confirm: bool,
    },
    Disable {
        #[arg(long)]
        confirm: bool,
    },
}
fn config(cli: &Cli) -> Result<Config> {
    Config::parse(&fs::read_to_string(&cli.config).context("cannot read server configuration")?)
}
fn read_state(cli: &Cli) -> Result<State> {
    platform::require_root()?;
    platform::Store::decode(&platform::read_secret(&cli.state_dir.join("state.json"))?)
}
fn emit(value: impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn confirm(value: bool) -> Result<()> {
    if !value {
        bail!("explicit --confirm is required")
    }
    Ok(())
}
fn status(cli: &Cli) -> Result<()> {
    let configured = cli.state_dir.join("state.json").exists();
    emit(
        serde_json::json!({"schema_version":1,"state_path_visible":configured,"tunnel":"UNKNOWN","egress":"NOT_TESTED","dns_privacy":"UNKNOWN","activity_logging_runtime":"UNKNOWN","strict_client":"UNSUPPORTED","scope":"No runtime activity was queried or persisted; provisioning is not proof of deployment"}),
    )
}
fn provisioning_plan(cli: &Cli) -> Result<()> {
    emit(shadowborn_core::plan(&config(cli)?, None)?)
}
fn peer_command(cli: &Cli, cmd: &PeerCommand) -> Result<()> {
    match cmd {
        PeerCommand::List => {
            let state = read_state(cli)?;
            emit(state.peers.iter().map(|p|serde_json::json!({"name":p.name,"address":p.address,"status":p.status})).collect::<Vec<_>>())
        }
        PeerCommand::Show { name, .. } => {
            let state = read_state(cli)?;
            let p = state.peer(name)?;
            emit(
                serde_json::json!({"name":p.name,"address":p.address,"status":p.status,"public_key":"[REDACTED]","psk":"[REDACTED]"}),
            )
        }
        PeerCommand::ExportPublic { name } => {
            let state = read_state(cli)?;
            let p = state.peer(name)?;
            emit(
                serde_json::json!({"name":p.name,"public_key":p.public_key,"address":p.address,"status":p.status,"server_public_key":state.server_public_key}),
            )
        }
        _ => {
            platform::require_root()?;
            let store = platform::Store::open(&cli.state_dir, false)?;
            let before = store.load()?;
            platform::require_offline(&before.config)?;
            let mut after = before.clone();
            let mut artifact: Option<&Path> = None;
            match cmd {
                PeerCommand::Add { name, public_key } => after.add(
                    name.clone(),
                    public_key.clone(),
                    platform::generate_key(true)?,
                )?,
                PeerCommand::Issue {
                    name,
                    recipient,
                    bundle,
                    accept_server_key_generation,
                } => {
                    if !accept_server_key_generation {
                        bail!("requires --accept-server-key-generation: this generates the client private key on the server")
                    }
                    let key = platform::generate_key(false)?;
                    after.add(
                        name.clone(),
                        platform::public_key(&key)?,
                        platform::generate_key(true)?,
                    )?;
                    let profile = shadowborn_core::client_template(&after, name)?
                        .replace("<DEVICE_PRIVATE_KEY>", key.expose());
                    let encrypted = platform::encrypt(recipient, profile.as_bytes())?;
                    platform::write_new_secret(bundle, &encrypted)?;
                    artifact = Some(bundle);
                }
                PeerCommand::Disable { name, confirm: ok } => {
                    confirm(*ok)?;
                    after.disable(name, false)?;
                }
                PeerCommand::Revoke { name, confirm: ok } => {
                    confirm(*ok)?;
                    after.disable(name, true)?;
                }
                PeerCommand::RotatePsk { name, confirm: ok } => {
                    confirm(*ok)?;
                    let p = after
                        .peers
                        .iter_mut()
                        .find(|p| p.name == *name)
                        .context("peer not found")?;
                    if p.status == PeerStatus::Revoked {
                        bail!("revoked identity cannot be reused")
                    }
                    p.psk = Some(platform::generate_key(true)?);
                }
                _ => unreachable!(),
            }
            if let Err(error) = store.save(Some(&before), &after) {
                if let Some(path) = artifact {
                    let _ = fs::remove_file(path);
                }
                return Err(error);
            }
            println!("Provisioning authorization updated. No running gateway was modified; previous exports are stale.");
            Ok(())
        }
    }
}
fn execute(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Version => {
            println!(
                "shadowborn {} (provisioning preview)",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Commands::Doctor => {
            let tools = [
                "wg",
                "wg-quick",
                "nft",
                "unbound",
                "unbound-checkconf",
                "age",
                "systemctl",
            ]
            .map(|name| {
                (
                    name,
                    ["/usr/bin", "/usr/sbin"]
                        .iter()
                        .any(|p| Path::new(p).join(name).is_file()),
                )
            });
            emit(
                serde_json::json!({"schema_version":1,"tools":tools.into_iter().collect::<std::collections::BTreeMap<_,_>>(),"network_mutations":false,"live_apply":"UNSUPPORTED","kernel_wireguard":"NOT_TESTED","ssh_safety":"NOT_TESTED","no_logs_runtime":"UNKNOWN","legacy_client":"independent; not inspected or changed"}),
            )
        }
        Commands::Validate => {
            config(cli)?;
            println!("Server configuration valid (deployment readiness NOT TESTED).");
            Ok(())
        }
        Commands::Plan { .. } => provisioning_plan(cli),
        Commands::Init { dry_run: true } => provisioning_plan(cli),
        Commands::Init { dry_run: false } => {
            platform::require_root()?;
            let config = config(cli)?;
            platform::require_offline(&config)?;
            let store = platform::Store::open(&cli.state_dir, true)?;
            let private = platform::generate_key(false)?;
            let public = platform::public_key(&private)?;
            let state = State {
                schema_version: 1,
                config,
                server_private_key: private,
                server_public_key: public,
                peers: vec![],
            };
            store.save(None, &state)?;
            println!("Private gateway provisioning state initialized. No networking changed.");
            Ok(())
        }
        Commands::Render { output } => {
            let state = read_state(cli)?;
            platform::require_offline(&state.config)?;
            platform::export_bundle(output, &state)?;
            println!("Private VM review bundle written. Not installed or activated.");
            Ok(())
        }
        Commands::Apply { dry_run: true, .. } => provisioning_plan(cli),
        Commands::Apply { confirm: ok, .. } => {
            confirm(*ok)?;
            platform::unsupported("automatic live apply")
        }
        Commands::Status
        | Commands::Server {
            command: ServerCommand::Status,
        } => status(cli),
        Commands::Dns {
            command: DnsCommand::Status,
        } => emit(
            serde_json::json!({"supported_upstream":"quad9-dot","availability":"UNKNOWN","transport_verified":"NOT_TESTED","query_logging_runtime":"UNKNOWN","probes_issued":false}),
        ),
        Commands::Peer { command } => peer_command(cli, command),
        Commands::Client {
            command: ClientCommand::Profile { name, output },
        } => {
            let state = read_state(cli)?;
            platform::write_new_secret(
                output,
                shadowborn_core::client_template(&state, name)?.as_bytes(),
            )?;
            println!("Secret STANDARD template written; insert the device private key locally. No strict protection installed.");
            Ok(())
        }
        Commands::Client {
            command:
                ClientCommand::Lockdown {
                    command: LockdownCommand::Plan | LockdownCommand::Status,
                },
        } => emit(
            serde_json::json!({"state":"UNSUPPORTED","enforced":false,"required":"persistent inet default-deny firewall; endpoint/fwmark allowlist; boot/suspend/IPv6 packet tests"}),
        ),
        Commands::Client {
            command: ClientCommand::Lockdown { .. },
        } => platform::unsupported("strict client lockdown"),
        Commands::Firewall {
            command: FirewallCommand::Plan,
        } => {
            let state = read_state(cli)?;
            print!("{}", shadowborn_core::server_firewall(&state)?);
            Ok(())
        }
        Commands::Backup { recipient, output } => {
            let state = read_state(cli)?;
            let encrypted = platform::encrypt(recipient, &serde_json::to_vec(&state)?)?;
            platform::write_new_secret(output, &encrypted)?;
            println!("Encrypted configuration/key backup written; contains no activity history.");
            Ok(())
        }
        Commands::Restore {
            input,
            identity,
            confirm: ok,
            dry_run,
        } => {
            platform::require_root()?;
            if !dry_run {
                confirm(*ok)?;
            }
            let current = read_state(cli)?;
            platform::require_offline(&current.config)?;
            let backup = platform::Store::decode(&platform::decrypt(
                identity,
                &platform::read_secret(input)?,
            )?)?;
            let next = current.restore_authorization(backup)?;
            if *dry_run {
                println!("Offline restore validated; disabled/revoked identities remain restricted. No changes written.");
                return Ok(());
            }
            let store = platform::Store::open(&cli.state_dir, false)?;
            store.save(Some(&current), &next)?;
            println!("Offline configuration restored with current revocations preserved. No network changes.");
            Ok(())
        }
        Commands::Uninstall { plan: true } => emit(
            serde_json::json!({"network_mutations":false,"installer":"scripts/uninstall-server.sh","retained":["configuration","keys","authorization state"],"live_deployment":"manual recovery required before file removal"}),
        ),
        Commands::Uninstall { plan: false } => {
            platform::unsupported("automatic removal of a live gateway; use uninstall --plan")
        }
    }
}
fn main() {
    // Limit accidental secret exposure through core dumps; do not touch host-wide policy.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    let cli = Cli::parse();
    if let Err(error) = execute(&cli) {
        eprintln!("shadowborn: {error}");
        std::process::exit(1)
    }
}
