use std::path::PathBuf;

use mmdf_client::{logging, MmdfConfig, ProxyServer};

fn usage() -> ! {
    eprintln!("mmdf-client [--config FILE] [--gen-config] [--export-ca PATH] [--test-sni IP SNI] [--version]");
    std::process::exit(2);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_file: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--gen-config" => {
                let c = MmdfConfig::default();
                println!("{}", toml::to_string_pretty(&c).unwrap());
                return;
            }
            "--export-ca" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                logging::init("info");
                let p = mmdf_client::mitm::CaManager::ca_crt_path();
                match std::fs::copy(&p, &args[i]) {
                    Ok(_) => println!("CA exported to {}", args[i]),
                    Err(e) => {
                        eprintln!("no CA yet ({e}); start the proxy once first");
                        std::process::exit(1);
                    }
                }
                return;
            }
            "--test-sni" => {
                if i + 2 >= args.len() {
                    usage();
                }
                logging::init("warn");
                let rt_ip = args[i + 1].clone();
                let sni = args[i + 2].clone();
                match mmdf_client::fronting::probe_sni(&rt_ip, &sni).await {
                    Ok(ms) => println!("OK {sni} via {rt_ip} in {ms}ms"),
                    Err(e) => {
                        eprintln!("FAIL {sni} via {rt_ip}: {e}");
                        std::process::exit(1);
                    }
                }
                return;
            }
            "--version" => {
                println!("mmdf-client {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--config" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                cfg_file = Some(args[i].clone());
            }
            _ => usage(),
        }
        i += 1;
    }

    let raw = match cfg_file {
        Some(f) => std::fs::read_to_string(&f).unwrap_or_else(|e| {
            eprintln!("read {f}: {e}");
            std::process::exit(1);
        }),
        None => {
            let p = PathBuf::from("mmdf.toml");
            if p.exists() {
                std::fs::read_to_string(p).unwrap()
            } else {
                eprintln!("no config: --config FILE or ./mmdf.toml (see --gen-config)");
                std::process::exit(1);
            }
        }
    };
    let cfg = match MmdfConfig::parse_mixed(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = cfg.validate() {
        eprintln!("config: {e}");
        std::process::exit(1);
    }
    logging::init(&cfg.log_level.clone());
    let server = std::sync::Arc::new(ProxyServer::new(cfg));
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    // never closes: runs until Ctrl-C
    let srv = server.clone();
    tokio::spawn(async move {
        let _ = srv.run(rx).await;
    });
    println!("mmdf-client running. Ctrl-C to stop.");
    let _ = tokio::signal::ctrl_c().await;
}
