use anyhow::{Context, Result};
use clap::Parser;
use shadowmist_core::*;
use shadowmist_platform_linux as linux;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
    sync::{mpsc, RwLock, Semaphore},
    time::Instant,
};
static LOG_LEVEL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2);

#[derive(Parser)]
#[command(
    version,
    about = "Shadow Mist passive event and approved-policy health monitor"
)]
struct Args {
    #[arg(long,default_value=linux::DEFAULT_CONFIG)]
    config: PathBuf,
    #[arg(long,default_value=linux::DEFAULT_STATE)]
    state_dir: PathBuf,
    #[arg(long,default_value=linux::DEFAULT_RUNTIME)]
    runtime_dir: PathBuf,
    #[arg(long, help = "Exit after the first read-only assessment")]
    once: bool,
}
fn log(level: &str, event: &str) {
    let priority = match level {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        _ => 3,
    };
    if priority > LOG_LEVEL.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    println!(
        "{}",
        serde_json::json!({"level":level,"event":event,"timestamp":timestamp()})
    );
}

async fn events(tx: mpsc::Sender<()>) {
    let mut backoff = 1;
    loop {
        if let Some(binary) = linux::binary("nmcli") {
            let mut command = tokio::process::Command::new(binary);
            command
                .args(["monitor"])
                .env_clear()
                .env("LC_ALL", "C")
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .stdin(Stdio::null())
                .kill_on_drop(true);
            if let Ok(mut child) = command.spawn() {
                if let Some(stdout) = child.stdout.take() {
                    let mut lines = BufReader::new(stdout).lines();
                    while let Ok(Some(_)) = lines.next_line().await {
                        let _ = tx.try_send(());
                        backoff = 1;
                    }
                }
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }
        log("warn", "networkmanager_event_stream_unavailable_retrying");
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}
async fn serve(listener: UnixListener, status: Arc<RwLock<String>>) {
    let slots = Arc::new(Semaphore::new(16));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let status = status.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut request = [0u8; 16];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request)).await
            {
                if &request[..n] == b"status\n" {
                    let payload = status.read().await.clone();
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        stream.write_all(payload.as_bytes()),
                    )
                    .await;
                }
            }
            let _ = stream.shutdown().await;
        });
    }
}
async fn assess(config: Config, state: PathBuf, previous: Option<Host>) -> Result<(Host, Report)> {
    tokio::task::spawn_blocking(move||{
        let health=linux::monitor_health(&config,&state);
        let health_error=health.is_err();
        let host=linux::discover(&config);let mut r=linux::report(&config,&host,&state,false);
        if health.is_ok_and(|verified|verified)&&r.dns.state==Protection::Configured{r.dns.state=Protection::Verified;r.dns.reason="Fresh approved uncached lookups succeeded during the owned-policy health check; authenticated DoT remains required. Resolver scope only, no packet capture.".into();r.state=Protection::Verified;}
        if config.network_audit.check_gateway_changes{if let Some(previous)=previous{if let Some(f)=linux::route_change(&previous,&host){r.findings.push(f);}}}
        if health_error{r.state=Protection::Degraded;r.findings.push(Finding{code:"OWNED_POLICY_HEALTH".into(),severity:Severity::Warn,evidence:"Approved settings drifted or health/recovery failed; inspect root-owned journal locally".into(),mitigation:"Review shadowmist status and restore; no automatic overwrite of external changes".into()});}
        Ok((host,r.redacted()))
    }).await?
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = linux::load_config(&args.config)?;
    LOG_LEVEL.store(
        match config.logging.level.as_str() {
            "error" => 0,
            "warn" => 1,
            "debug" => 3,
            _ => 2,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
    if args.once {
        let host = linux::discover(&config);
        let r = linux::report(&config, &host, &args.state_dir, false).redacted();
        println!("{}", serde_json::to_string_pretty(&r)?);
        return Ok(());
    }
    linux::private_dir(&args.runtime_dir)?;
    if linux::is_root() {
        std::fs::set_permissions(&args.runtime_dir, std::fs::Permissions::from_mode(0o755))?;
    }
    // Prevent a second daemon from unlinking a live socket.
    let _instance = linux::lock_state(&args.runtime_dir)?;
    if linux::is_root() {
        let c = config.clone();
        let s = args.state_dir.clone();
        tokio::task::spawn_blocking(move || linux::recover(&s, &c, None)).await??;
    }
    let socket = args.runtime_dir.join("status.sock");
    if socket.exists() {
        let meta = std::fs::symlink_metadata(&socket)?;
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() {
            anyhow::bail!("refusing to replace non-socket runtime path")
        };
        std::fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket).context("cannot bind status-only Unix socket")?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
    let status = Arc::new(RwLock::new(
        "{\"schema_version\":1,\"state\":\"STARTING\"}\n".into(),
    ));
    let server = tokio::spawn(serve(listener, status.clone()));
    let (tx, mut rx) = mpsc::channel(32);
    let monitor = tokio::spawn(events(tx));
    let mut interval = tokio::time::interval(Duration::from_secs(config.general.reconcile_seconds));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last = Instant::now() - Duration::from_secs(10);
    let mut previous = None;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    log("info", "started_observation_no_implicit_enrollment");
    loop {
        let event = tokio::select! {_=tokio::signal::ctrl_c()=>break,_=terminate.recv()=>break,_=interval.tick()=>false,Some(_)=rx.recv()=>true};
        if event {
            if !config.general.check_on_connect {
                continue;
            };
            tokio::time::sleep(Duration::from_millis(750)).await;
            while rx.try_recv().is_ok() {}
            if last.elapsed() < Duration::from_secs(2) {
                continue;
            }
        }
        match assess(config.clone(), args.state_dir.clone(), previous.take()).await {
            Ok((host, r)) => {
                previous = Some(host);
                let payload = serde_json::to_string(&r)? + "\n";
                *status.write().await = payload.clone();
                linux::atomic_write(
                    &args.runtime_dir.join("status.json"),
                    payload.as_bytes(),
                    0o644,
                )?;
                log("info", "assessment_complete");
            }
            Err(_) => log("error", "assessment_failed_sensitive_details_suppressed"),
        }
        last = Instant::now();
    }
    monitor.abort();
    server.abort();
    let _ = std::fs::remove_file(socket);
    log(
        "info",
        "stopped_persistent_settings_require_explicit_restore",
    );
    Ok(())
}
