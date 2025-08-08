use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::{BufRead, BufReader};
use bitcoin::{PublicKey, Address, Network};
use bitcoin::secp256k1::{Secp256k1, All};
use std::fs::OpenOptions;
use std::io::Write;
use rand::Rng;
use hex;

static STOP: AtomicBool = AtomicBool::new(false);
static KEY_COUNT: AtomicU64 = AtomicU64::new(0);

struct Status {
    last_key: String,
    last_address: String,
    start_time: Instant,
}

fn main() {
    println!("Bitcoin Private Key Hunter");
    println!("--------------------------");
    
    // Get range input
    let from = get_input("Enter starting hex (e.g., 0000...0001): ");
    let to = get_input("Enter ending hex (e.g., ffff...ffff): ");
    
    // Validate inputs
    if from.len() != to.len() {
        println!("Error: Start and end must be the same length");
        return;
    }
    
    // Find the common static prefix
    let static_prefix = find_common_prefix(&from, &to);
    let varying_part_length = from.len() - static_prefix.len();
    
    // Get target addresses from file
    let target_file = get_input("Enter path to target addresses file: ");
    let target_addresses = match read_addresses_from_file(&target_file) {
        Ok(addrs) => {
            println!("Loaded {} target addresses", addrs.len());
            addrs
        },
        Err(e) => {
            println!("Error reading addresses file: {}", e);
            return;
        }
    };
    
    // Menu
    println!("\nSelect mode:");
    println!("1. Normal mode");
    println!("2. Crazy mode 1 (alternating letters/numbers)");
    println!("3. Crazy mode 2 (alternating pairs)");
    
    let choice = get_input("Enter choice (1-3): ");
    
    // Setup CTRL+C handler
    ctrlc::set_handler(move || {
        STOP.store(true, Ordering::SeqCst);
        println!("\nStopping... Please wait for current operations to complete.");
    }).expect("Error setting Ctrl-C handler");
    
    // Get number of threads (use all available cores)
    let num_threads = num_cpus::get();
    println!("\nStarting {} worker threads...", num_threads);
    
    // Create shared status tracker
    let status = Arc::new(std::sync::Mutex::new(Status {
        last_key: String::new(),
        last_address: String::new(),
        start_time: Instant::now(),
    }));
    
    // Start status thread
    let status_clone = status.clone();
    thread::spawn(move || {
        let mut last_count = 0;
        loop {
            thread::sleep(Duration::from_secs(45));
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            
            let status = status_clone.lock().unwrap();
            let current_count = KEY_COUNT.load(Ordering::SeqCst);
            let elapsed = status.start_time.elapsed().as_secs();
            let rate = if elapsed > 0 {
                (current_count - last_count) / 45
            } else {
                0
            };
            
            println!("\n--- Status Update ---");
            println!("Total keys checked: {}", current_count);
            println!("Keys per second: {}", rate);
            println!("Last key: {}", status.last_key);
            println!("Last address: {}", status.last_address);
            println!("Elapsed time: {} seconds", elapsed);
            println!("-------------------");
            
            last_count = current_count;
        }
    });
    
    // Create worker threads
    let mut handles = vec![];
    let target_addresses = Arc::new(target_addresses);
    
    for _ in 0..num_threads {
        let from = from.clone();
        let to = to.clone();
        let static_prefix = static_prefix.clone();
        let target_addresses = target_addresses.clone();
        let choice = choice.clone();
        let status = status.clone();
        
        let handle = thread::spawn(move || {
            let secp: Secp256k1<All> = Secp256k1::new();
            let mut rng = rand::thread_rng();
            let mut local_count = 0;
            
            while !STOP.load(Ordering::SeqCst) {
                let private_key = match choice.trim() {
                    "1" => generate_normal(&from, &to, &static_prefix, varying_part_length, &mut rng),
                    "2" => generate_crazy1(&from, &to, &static_prefix, varying_part_length, &mut rng),
                    "3" => generate_crazy2(&from, &to, &static_prefix, varying_part_length, &mut rng),
                    _ => continue,
                };
                
                if let Some(address) = private_key_to_address(&private_key, &secp) {
                    // Update status
                    {
                        let mut status = status.lock().unwrap();
                        status.last_key = private_key.clone();
                        status.last_address = address.clone();
                    }
                    
                    local_count += 1;
                    if local_count % 10000 == 0 {
                        KEY_COUNT.fetch_add(10000, Ordering::SeqCst);
                        local_count = 0;
                    }
                    
                    // Check against all target addresses
                    if target_addresses.contains(&address) {
                        found_match(&private_key, &address);
                        STOP.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            KEY_COUNT.fetch_add(local_count, Ordering::SeqCst);
        });
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
    
    let elapsed = status.lock().unwrap().start_time.elapsed().as_secs();
    let total_keys = KEY_COUNT.load(Ordering::SeqCst);
    println!("\nScanning stopped.");
    println!("Final stats:");
    println!("Total keys checked: {}", total_keys);
    println!("Total time: {} seconds", elapsed);
    println!("Average speed: {} keys/sec", total_keys / elapsed.max(1));
}

fn read_addresses_from_file(path: &str) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut addresses = Vec::new();
    
    for line in reader.lines() {
        let line = line?.trim().to_string();
        if !line.is_empty() {
            addresses.push(line);
        }
    }
    
    Ok(addresses)
}

// [All other functions remain exactly the same as in previous version]

fn get_input(prompt: &str) -> String {
    println!("{}", prompt);
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    input.trim().to_string()
}

fn find_common_prefix(a: &str, b: &str) -> String {
    let mut prefix = String::new();
    for (ca, cb) in a.chars().zip(b.chars()) {
        if ca == cb {
            prefix.push(ca);
        } else {
            break;
        }
    }
    prefix
}

fn generate_normal(
    from: &str,
    to: &str,
    static_prefix: &str,
    varying_length: usize,
    rng: &mut impl Rng
) -> String {
    let from_num = u128::from_str_radix(&from[static_prefix.len()..], 16)
        .expect("Invalid start hex varying part");
    let to_num = u128::from_str_radix(&to[static_prefix.len()..], 16)
        .expect("Invalid end hex varying part");
    
    let random_num = rng.gen_range(from_num..=to_num);
    format!("{}{:0width$x}", static_prefix, random_num, width = varying_length)
}

fn generate_crazy1(
    from: &str,
    to: &str,
    static_prefix: &str,
    varying_length: usize,
    rng: &mut impl Rng
) -> String {
    let from_num = u128::from_str_radix(&from[static_prefix.len()..], 16)
        .expect("Invalid start hex varying part");
    let to_num = u128::from_str_radix(&to[static_prefix.len()..], 16)
        .expect("Invalid end hex varying part");
    
    let random_num = rng.gen_range(from_num..=to_num);
    let hex_str = format!("{:0width$x}", random_num, width = varying_length);
    
    let mut result = String::new();
    let mut next_letter = rng.gen_bool(0.5);
    
    for _ in hex_str.chars() {
        if next_letter {
            result.push(get_random_hex_letter(rng));
        } else {
            result.push(get_random_hex_digit(rng));
        }
        next_letter = !next_letter;
    }
    
    format!("{}{}", static_prefix, result)
}

fn generate_crazy2(
    from: &str,
    to: &str,
    static_prefix: &str,
    varying_length: usize,
    rng: &mut impl Rng
) -> String {
    let from_num = u128::from_str_radix(&from[static_prefix.len()..], 16)
        .expect("Invalid start hex varying part");
    let to_num = u128::from_str_radix(&to[static_prefix.len()..], 16)
        .expect("Invalid end hex varying part");
    
    let random_num = rng.gen_range(from_num..=to_num);
    let hex_str = format!("{:0width$x}", random_num, width = varying_length);
    
    let mut result = String::new();
    let mut next_letter = rng.gen_bool(0.5);
    let mut count = 0;
    
    for _ in hex_str.chars() {
        if count == 2 {
            next_letter = !next_letter;
            count = 0;
        }
        
        if next_letter {
            result.push(get_random_hex_letter(rng));
        } else {
            result.push(get_random_hex_digit(rng));
        }
        count += 1;
    }
    
    format!("{}{}", static_prefix, result)
}

fn get_random_hex_letter(rng: &mut impl Rng) -> char {
    let letters = ['a', 'b', 'c', 'd', 'e', 'f'];
    letters[rng.gen_range(0..letters.len())]
}

fn get_random_hex_digit(rng: &mut impl Rng) -> char {
    let digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
    digits[rng.gen_range(0..digits.len())]
}

fn private_key_to_address(private_key: &str, secp: &Secp256k1<All>) -> Option<String> {
    if let Ok(bytes) = hex::decode(private_key) {
        if let Ok(secret_key) = bitcoin::PrivateKey::from_slice(&bytes, Network::Bitcoin) {
            let public_key = PublicKey::from_private_key(secp, &secret_key);
            let address = Address::p2pkh(&public_key, Network::Bitcoin);
            return Some(address.to_string());
        }
    }
    None
}

fn found_match(private_key: &str, address: &str) {
    println!("\nMATCH FOUND!");
    println!("Address: {}", address);
    println!("Private Key: {}", private_key);
    
    // Save to file
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("found_keys.txt")
        .expect("Unable to open file");
    
    writeln!(file, "Address: {}", address).expect("Unable to write to file");
    writeln!(file, "Private Key: {}", private_key).expect("Unable to write to file");
    writeln!(file, "----------------------").expect("Unable to write to file");
}