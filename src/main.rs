use hex::decode as hex_decode;
use num_bigint::BigUint;
use num_cpus;
use num_traits::ToPrimitive;
use rand::{rngs::ThreadRng, Rng};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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

    let start_hex = "000000000000000000000000000000000000000000000061b6cdd0d367fdfce8";
    let end_hex   = "00000000000000000000000000000000000000000000006efedeffffffffffff";

    let mut start = hex_to_biguint(start_hex);
    let mut end = hex_to_biguint(end_hex);

    if start > end {
        std::mem::swap(&mut start, &mut end);
    }

    println!("Search range:\nFrom: {}\nTo:   {}\n", start_hex, end_hex);

    print!("Enter the Bitcoin address to search for: ");
    io::stdout().flush().unwrap();
    let mut target_address = String::new();
    io::stdin().read_line(&mut target_address).unwrap();
    let target_address = target_address.trim().to_string();

    print!("Choose search mode (1 - Sequential, 2 - Random): ");
    io::stdout().flush().unwrap();
    let mut mode = String::new();
    io::stdin().read_line(&mut mode).unwrap();
    let mode = mode.trim();

    let num_threads = num_cpus::get();
    let batches_per_thread = 3;
    let total_batches = num_threads * batches_per_thread;

    println!(
        "Using {} workers with {} batches each...\n",
        num_threads, batches_per_thread
    );

    let target_address = Arc::new(target_address);
    let secp = Arc::new(Secp256k1::new());
    let found = Arc::new(Mutex::new(None));
    let last_status = Arc::new(Mutex::new((BigUint::default(), String::new())));
    let key_counter = Arc::new(Mutex::new(0u64));
    let start_time = Instant::now();

    // Status thread: last key, addr, keys/sec
    {
        let last_status = Arc::clone(&last_status);
        let key_counter = Arc::clone(&key_counter);
        thread::spawn(move || {
            let mut last_count = 0u64;

            loop {
                thread::sleep(Duration::from_secs(45));
                let (hex, addr) = &*last_status.lock().unwrap();
                let total = *key_counter.lock().unwrap();
                let delta = total - last_count;
                last_count = total;
                let elapsed = start_time.elapsed().as_secs().max(1);
                let avg_kps = total as f64 / elapsed as f64;

                println!(
                    "[Status] Last key: {:x} | Addr: {} | ΔKeys: {} | Avg: {:.2} keys/sec",
                    hex, addr, delta, avg_kps
                );
            }
        });
    }

    let mut handles = vec![];

    if mode == "1" {
        // Sequential search mode (original)
        let total_range = &end - &start;
        let batch_size = &total_range / BigUint::from(total_batches as u32);

        for i in 0..total_batches {
            let batch_start = &start + &batch_size * BigUint::from(i as u32);
            let batch_end = if i == total_batches - 1 {
                end.clone()
            } else {
                &batch_start + &batch_size
            };

            let target_address = Arc::clone(&target_address);
            let secp = Arc::clone(&secp);
            let found = Arc::clone(&found);
            let last_status = Arc::clone(&last_status);
            let key_counter = Arc::clone(&key_counter);

            let handle = thread::spawn(move || {
                let mut current = batch_start.clone();
                while current < batch_end {
                    if found.lock().unwrap().is_some() {
                        return;
                    }

                    let priv_bytes = biguint_to_32bytes(&current);
                    if let Ok(secret_key) = SecretKey::from_slice(&priv_bytes) {
                        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                        let address = public_key_to_p2pkh_address(&public_key);

                        {
                            let mut status = last_status.lock().unwrap();
                            *status = (current.clone(), address.clone());
                        }

                        {
                            let mut counter = key_counter.lock().unwrap();
                            *counter += 1;
                        }

                        if address == *target_address {
                            *found.lock().unwrap() = Some((current, address));
                            return;
                        }
                    }

                    current += 1u32;
                }
            });

            handles.push(handle);
        }
    } else {
        // Random search mode
        for _ in 0..total_batches {
            let target_address = Arc::clone(&target_address);
            let secp = Arc::clone(&secp);
            let found = Arc::clone(&found);
            let last_status = Arc::clone(&last_status);
            let key_counter = Arc::clone(&key_counter);
            let start_range = start.clone();
            let end_range = end.clone();

            let handle = thread::spawn(move || {
                let mut rng = rand::thread_rng();
                loop {
                    if found.lock().unwrap().is_some() {
                        return;
                    }

                    let current = generate_random_in_range(&mut rng, &start_range, &end_range);
                    let priv_bytes = biguint_to_32bytes(&current);
                    if let Ok(secret_key) = SecretKey::from_slice(&priv_bytes) {
                        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                        let address = public_key_to_p2pkh_address(&public_key);

                        {
                            let mut status = last_status.lock().unwrap();
                            *status = (current.clone(), address.clone());
                        }

                        {
                            let mut counter = key_counter.lock().unwrap();
                            *counter += 1;
                        }

                        if address == *target_address {
                            *found.lock().unwrap() = Some((current, address));
                            return;
                        }
                    }
                }
            });

            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let result = found.lock().unwrap();
    match &*result {
        Some((key, addr)) => {
            println!("\n✅ MATCH FOUND!");
            println!("Private Key (hex): {:x}", key);
            println!("Address: {}", addr);
        }
        None => {
            println!("\n❌ No match found in the defined range.");
        }
    }
}