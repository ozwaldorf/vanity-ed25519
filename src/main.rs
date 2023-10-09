use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

use clap::Parser;
use fastcrypto::{
    ed25519::Ed25519KeyPair,
    encoding::{Base58, Encoding},
    traits::{KeyPair, ToFromBytes},
};
use fleek_crypto::{NodeSecretKey, SecretKey};
use rand::rngs::ThreadRng;

#[derive(Debug, Parser)]
struct Args {
    /// Prefix to search for
    prefix: String,
    /// Output directory to save to
    #[arg(short, long, default_value = "out")]
    out_dir: String,
    /// Number of dedicated threads to spawn
    #[arg(short, long, default_value_t = 8)]
    threads: usize,
}

fn main() {
    let args = Args::parse();
    let out_dir: PathBuf = args.out_dir.into();
    if !out_dir.is_dir() {
        fs::create_dir_all(&out_dir).expect("Failed to create output directory");
    }

    let (tx, rx) = mpsc::channel();
    let counter = Arc::new(AtomicUsize::default());
    let prefix = args.prefix.to_lowercase();

    // Spawn key generation threads
    for _ in 0..args.threads {
        let tx = tx.clone();
        let counter = counter.clone();
        let prefix = prefix.clone();

        std::thread::spawn(move || {
            let mut rng = ThreadRng::default();
            loop {
                let pair = Ed25519KeyPair::generate(&mut rng);
                let pk = Base58::encode(pair.public().as_bytes());

                if pk[..prefix.len()].to_lowercase() == prefix {
                    tx.send((pk, pair.private())).expect("failed to send tx");
                }

                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    let mut timer = Instant::now();
    let mut stdout = std::io::stdout().lock();

    loop {
        if let Ok((pk, secret)) = rx.recv_timeout(Duration::from_millis(100)) {
            println!("\r\x1b[KFound {pk}");
            let pem = NodeSecretKey::from(secret).encode_pem();
            let path = out_dir.join(pk).with_extension("pem");
            fs::write(path, pem).expect("Failed to write pem file");
        }

        let elapsed = timer.elapsed().as_millis() as usize;
        if elapsed >= 1000 {
            let count = counter.load(Ordering::Relaxed) / elapsed * 1_000;
            write!(stdout, "\r\x1b[K{} keys/second", count).unwrap();
            stdout.flush().unwrap();
            timer = Instant::now();
            counter.fetch_sub(count, Ordering::Relaxed);
        }
    }
}
