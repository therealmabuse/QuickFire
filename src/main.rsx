use hex::decode as hex_decode;
use num_bigint::BigUint;
use num_cpus;
use num_traits::ToPrimitive;
use rand::{rngs::ThreadRng, Rng};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use crossbeam_channel::{bounded, select};
use ctrlc;
use std::collections::HashSet;

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn ripemd160_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut num = BigUint::from_bytes_be(data);
    let base = BigUint::from(ALPHABET.len());
    let mut encoded = String::new();

    while &num > &BigUint::from(0u32) {
        let rem = (&num % &base).to_usize().unwrap();
        num /= &base;
        encoded.insert(0, ALPHABET.chars().nth(rem).unwrap());
    }

    for &_byte in data.iter().take_while(|&&b| b == 0) {
        encoded.insert(0, '1');
    }

    encoded
}

fn public_key_to_p2pkh_address(public_key: &PublicKey) -> String {
    let pubkey_bytes = public_key.serialize();
    let sha256 = sha256_digest(&pubkey_bytes);
    let ripemd160 = ripemd160_digest(&sha256);

    let mut address_bytes = vec![0x00];
    address_bytes.extend(&ripemd160);
    let checksum = &sha256_digest(&sha256_digest(&address_bytes))[..4];
    address_bytes.extend(checksum);
    base58_encode(&address_bytes)
}

fn hex_to_biguint(hex: &str) -> BigUint {
    BigUint::from_bytes_be(&hex_decode(hex).expect("Invalid hex"))
}

fn biguint_to_32bytes(b: &BigUint) -> [u8; 32] {
    let mut bytes = b.to_bytes_be();
    if bytes.len() > 32 {
        panic!("BigUint too large to fit in 32 bytes");
    }
    while bytes.len() < 32 {
        bytes.insert(0, 0);
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    result
}

fn generate_random_in_range(rng: &mut ThreadRng, start: &BigUint, end: &BigUint) -> BigUint {
    let range = end - start;
    let bytes = range.to_bytes_be();
    let mut random_bytes = vec![0u8; bytes.len()];
    
    rng.fill(&mut random_bytes[..]);
    
    let random_num = BigUint::from_bytes_be(&random_bytes);
    start + (random_num % range)
}

fn main() {
    println!("=== Optimized BTC Paper Wallet Maker with Batched Range Search ===");

    let start_hex = "000000000000000000000000000000000000000000000064a4df70ae8667c25e";
    let end_hex   = "000000000000000000000000000000000000000000000079edefffffffffffff";
                     
    let mut start = hex_to_biguint(start_hex);
    let mut end = hex_to_biguint(end_hex);

    if start > end {
        std::mem::swap(&mut start, &mut end);
    }

    println!("Search range:\nFrom: {}\nTo:   {}\n", start_hex, end_hex);

    print!("Enter the Bitcoin addresses to search for (comma separated): ");
    io::stdout().flush().unwrap();
    let mut target_addresses_input = String::new();
    io::stdin().read_line(&mut target_addresses_input).unwrap();
    let target_addresses: HashSet<String> = target_addresses_input
        .trim()
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    print!("Choose search mode (1 - Sequential, 2 - Random): ");
    io::stdout().flush().unwrap();
    let mut mode = String::new();
    io::stdin().read_line(&mut mode).unwrap();
    let mode = mode.trim();

    let num_threads = num_cpus::get();
    println!("Using {} workers...\n", num_threads);

    let target_addresses = Arc::new(target_addresses);
    let secp = Arc::new(Secp256k1::new());
    let found = Arc::new(AtomicBool::new(false));
    let key_counter = Arc::new(AtomicU64::new(0));
    let start_time = Instant::now();
    let shutdown = Arc::new(AtomicBool::new(false));

    // Setup Ctrl-C handler
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::SeqCst);
        println!("\nReceived shutdown signal, finishing current work...");
    }).expect("Error setting Ctrl-C handler");

    // Channel for status updates
    let (status_sender, status_receiver) = bounded(1024);
    // Channel for results
    let (result_sender, result_receiver) = bounded(1);

    // Status thread
    let status_thread = {
        let key_counter = Arc::clone(&key_counter);
        thread::spawn(move || {
            let mut last_count = 0u64;
            let mut last_status = (BigUint::default(), String::new());

            loop {
                // Process all pending status updates
                while let Ok((hex, addr)) = status_receiver.try_recv() {
                    last_status = (hex, addr);
                }

                let total = key_counter.load(Ordering::Relaxed);
                let delta = total - last_count;
                last_count = total;
                let elapsed = start_time.elapsed().as_secs().max(1);
                let avg_kps = total as f64 / elapsed as f64;

                println!(
                    "[Status] Last key: {:x} | Addr: {} | ΔKeys: {} | Avg: {:.2} keys/sec",
                    last_status.0, last_status.1, delta, avg_kps
                );

                thread::sleep(Duration::from_secs(45));
            }
        })
    };

    if mode == "1" {
        // Sequential search mode - improved with work stealing
        let current_position = Arc::new(std::sync::Mutex::new(start.clone()));
        
        for _ in 0..num_threads {
            let target_addresses = Arc::clone(&target_addresses);
            let secp = Arc::clone(&secp);
            let found = Arc::clone(&found);
            let key_counter = Arc::clone(&key_counter);
            let current_position = Arc::clone(&current_position);
            let status_sender = status_sender.clone();
            let end = end.clone();
            let shutdown = shutdown.clone();
            let result_sender = result_sender.clone();

            thread::spawn(move || {
                let mut local_counter = 0u64;
                let mut last_report_time = Instant::now();
                let batch_size = 100_000u64;
                
                loop {
                    if found.load(Ordering::Relaxed) || shutdown.load(Ordering::SeqCst) {
                        break;
                    }

                    // Get next batch
                    let (batch_start, batch_end) = {
                        let mut pos = current_position.lock().unwrap();
                        if *pos >= end {
                            break; // No more work
                        }
                        let batch_start = pos.clone();
                        *pos += batch_size;
                        let batch_end = std::cmp::min(pos.clone(), end.clone());
                        (batch_start, batch_end)
                    };

                    let mut current = batch_start;
                    while current < batch_end {
                        if found.load(Ordering::Relaxed) || shutdown.load(Ordering::SeqCst) {
                            break;
                        }

                        let priv_bytes = biguint_to_32bytes(&current);
                        if let Ok(secret_key) = SecretKey::from_slice(&priv_bytes) {
                            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                            let address = public_key_to_p2pkh_address(&public_key);

                            // Send status update occasionally
                            if last_report_time.elapsed() > Duration::from_secs(5) {
                                let _ = status_sender.send((current.clone(), address.clone()));
                                last_report_time = Instant::now();
                            }

                            local_counter += 1;
                            if local_counter >= 10_000 {
                                key_counter.fetch_add(local_counter, Ordering::Relaxed);
                                local_counter = 0;
                            }

                            if target_addresses.contains(&address) {
                                found.store(true, Ordering::Relaxed);
                                let _ = result_sender.send((current, address));
                                break;
                            }
                        }

                        current += 1u32;
                    }
                }
            });
        }
    } else {
        // Random search mode
        for _ in 0..num_threads {
            let target_addresses = Arc::clone(&target_addresses);
            let secp = Arc::clone(&secp);
            let found = Arc::clone(&found);
            let key_counter = Arc::clone(&key_counter);
            let status_sender = status_sender.clone();
            let start_range = start.clone();
            let end_range = end.clone();
            let shutdown = shutdown.clone();
            let result_sender = result_sender.clone();

            thread::spawn(move || {
                let mut rng = rand::thread_rng();
                let mut local_counter = 0u64;
                let mut last_report_time = Instant::now();
                
                loop {
                    if found.load(Ordering::Relaxed) || shutdown.load(Ordering::SeqCst) {
                        break;
                    }

                    let current = generate_random_in_range(&mut rng, &start_range, &end_range);
                    let priv_bytes = biguint_to_32bytes(&current);
                    if let Ok(secret_key) = SecretKey::from_slice(&priv_bytes) {
                        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                        let address = public_key_to_p2pkh_address(&public_key);

                        // Send status update occasionally
                        if last_report_time.elapsed() > Duration::from_secs(5) {
                            let _ = status_sender.send((current.clone(), address.clone()));
                            last_report_time = Instant::now();
                        }

                        local_counter += 1;
                        if local_counter >= 10_000 {
                            key_counter.fetch_add(local_counter, Ordering::Relaxed);
                            local_counter = 0;
                        }

                        if target_addresses.contains(&address) {
                            found.store(true, Ordering::Relaxed);
                            let _ = result_sender.send((current, address));
                            break;
                        }
                    }
                }
            });
        }
    }

    // Wait for results or shutdown
    select! {
        recv(result_receiver) -> result => {
            if let Ok((key, addr)) = result {
                println!("\n✅ MATCH FOUND!");
                println!("Private Key (hex): {:x}", key);
                println!("Address: {}", addr);
            }
        },
        default(Duration::from_secs(1)) => {
            while !shutdown.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(100));
            }
            println!("\n🛑 Shutdown requested. Finalizing...");
        }
    }

    // Signal all threads to stop
    found.store(true, Ordering::SeqCst);
    shutdown.store(true, Ordering::SeqCst);

    // Wait for status thread to finish
    status_thread.join().unwrap();

    let total_keys = key_counter.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed().as_secs_f64();
    println!("\nFinal statistics:");
    println!("Total keys checked: {}", total_keys);
    println!("Total time: {:.2} seconds", elapsed);
    println!("Average speed: {:.2} keys/sec", total_keys as f64 / elapsed);
}