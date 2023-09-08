use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use clap::Parser;
use fastcrypto::{
    ed25519::Ed25519KeyPair,
    encoding::Base64,
    traits::{KeyPair, ToFromBytes},
};
use rand::rngs::ThreadRng;

#[derive(Debug, Parser)]
struct Args {
    prefix: String,
    #[arg(short, long, default_value_t = 8)]
    threads: usize,
}

fn main() {
    let args = Args::parse();

    let (tx, rx) = crossbeam_channel::bounded(256);
    let counter = Arc::new(AtomicUsize::default());

    // Spawn key generation threads
    for _ in 0..args.threads {
        let tx = tx.clone();
        let counter = counter.clone();
        std::thread::spawn(move || {
            let mut rng = ThreadRng::default();
            loop {
                let pair = Ed25519KeyPair::generate(&mut rng);
                tx.send((
                    Base64::from_bytes(pair.public().as_bytes()).encoded(),
                    pair.private().as_bytes().to_vec(),
                ))
                .expect("failed to send tx");
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
    }

    let mut timer = Instant::now();
    let prefix = args.prefix.to_lowercase();
    let mut stdout = std::io::stdout().lock();

    // Process keys
    while let Ok((key, secret)) = rx.recv() {
        if timer.elapsed().as_secs() >= 1 {
            let count = counter.load(Ordering::Relaxed);
            write!(stdout, "\r\x1b[K{} keys/second", count).unwrap();
            stdout.flush().unwrap();
            timer = Instant::now();
            counter.fetch_sub(count, Ordering::Relaxed);
        }

        if key.to_lowercase().starts_with(&prefix) {
            let secret = Base64::from_bytes(&secret).encoded();
            println!("\r\x1b[KFound:  {key}\n  Key:  {secret}");
        }
    }
}
