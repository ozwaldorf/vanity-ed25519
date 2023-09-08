use std::{io::Write, sync::mpsc::sync_channel, time::Instant};

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

    let (tx, rx) = sync_channel(256);

    // Spawn key generation threads
    for _ in 0..args.threads {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut rng = ThreadRng::default();
            loop {
                let pair = Ed25519KeyPair::generate(&mut rng);
                tx.send((
                    Base64::from_bytes(pair.public().as_bytes()).encoded(),
                    pair.private().as_bytes().to_vec(),
                ))
                .expect("failed to send tx");
            }
        });
    }

    let mut timer = Instant::now();
    let mut count = 0;
    let prefix = args.prefix.to_lowercase();
    let mut stdout = std::io::stdout().lock();

    // Process keys
    while let Ok((key, secret)) = rx.recv() {
        if timer.elapsed().as_secs() >= 1 {
            write!(stdout, "\r\x1b[K{} keys/second", count).unwrap();
            stdout.flush().unwrap();
            timer = Instant::now();
            count = 0;
        }

        if key.to_lowercase().starts_with(&prefix) {
            let secret = Base64::from_bytes(&secret).encoded();
            println!("\r\x1b[KFound:  {key}\n  Key:  {secret}");
        }
        count += 1;
    }
}
