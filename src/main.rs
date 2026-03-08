use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

/// High-performance SSH log analyzer to detect brute-force attempts from Linux auth.log
#[derive(Parser, Debug)]
#[command(name = "log_analyzer")]
#[command(author, version, about)]
struct Args {
    /// Path to the auth.log file to analyze
    #[arg(short, long, required = true)]
    file: PathBuf,

    /// Only show attackers with at least this many failed attempts (default: 1 = show all)
    #[arg(short, long, default_value_t = 1)]
    threshold: usize,

    /// Export the filtered Top Attackers list to a CSV file (e.g. for firewall blocklists)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Path to MaxMind GeoIP DB (e.g. GeoLite2-Country.mmdb) for country lookup
    #[arg(short, long)]
    geoip: Option<PathBuf>,

    /// AbuseIPDB API key (or set ABUSEIPDB_API_KEY in .env / environment)
    #[arg(short, long, env = "ABUSEIPDB_API_KEY")]
    abuseipdb: Option<String>,
}

/// Aggregated data for a single attacking IP
struct AttackerStats {
    attempt_count: u64,
    usernames: HashSet<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let args = Args::parse();

    let file = File::open(&args.file)?;
    let reader = BufReader::new(file);

    // Regex captures: (1) optional "invalid user " group, (2) username, (3) IP address
    // Matches: "Failed password for admin from 198.51.100.22..."
    //     and: "Failed password for invalid user root from 203.0.113.45..."
    let re = regex::Regex::new(
        r"Failed password for (?:invalid user )?(\S+) from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})",
    )?;

    let mut attackers: HashMap<String, AttackerStats> = HashMap::new();
    let mut total_failed_attempts: u64 = 0;

    for line in reader.lines() {
        let line = line?;
        if let Some(caps) = re.captures(&line) {
            let username = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
            let ip = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

            total_failed_attempts += 1;
            attackers
                .entry(ip.clone())
                .or_insert(AttackerStats {
                    attempt_count: 0,
                    usernames: HashSet::new(),
                })
                .attempt_count += 1;
            attackers.get_mut(&ip).unwrap().usernames.insert(username);
        }
    }

    // Build sorted "Top Attackers" list (descending by attempt count)
    let mut sorted: Vec<_> = attackers.into_iter().collect();
    sorted.sort_by(|a, b| b.1.attempt_count.cmp(&a.1.attempt_count));

    // --- Report ---
    let threshold = args.threshold;
    println!("═══════════════════════════════════════════════════════════════");
    println!("              SSH BRUTE-FORCE LOG ANALYSIS REPORT");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    println!("  Total failed login attempts analyzed: {}", total_failed_attempts);
    println!("  Showing attackers with >= {} failed attempts", threshold);
    println!();
    println!("  Top Attackers (by failed attempt count)");
    println!("  ---------------------------------------");

    let threshold_u64 = threshold as u64;
    let filtered: Vec<_> = sorted.iter().filter(|(_, stats)| stats.attempt_count >= threshold_u64).collect();

    // Optional GeoIP: open DB and resolve country for each filtered IP
    let geo_reader = match &args.geoip {
        Some(path) => match maxminddb::Reader::open_readfile(path) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("Warning: could not open GeoIP database {:?}: {}", path, e);
                None
            }
        },
        None => None,
    };
    let country_codes: Option<Vec<String>> = geo_reader.as_ref().map(|reader| {
        filtered
            .iter()
            .map(|(ip, _)| lookup_country(reader, ip))
            .collect()
    });

    // Optional AbuseIPDB: fetch abuse confidence score for each filtered IP (with rate-limit sleep)
    let abuse_scores: Option<Vec<String>> = args.abuseipdb.as_ref().map(|api_key| {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());
        let mut scores = Vec::with_capacity(filtered.len());
        for (idx, (ip, _)) in filtered.iter().enumerate() {
            if idx > 0 {
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
            scores.push(fetch_abuse_score(&client, api_key, ip));
        }
        scores
    });

    if filtered.is_empty() {
        println!("  No attackers met the threshold of {} attempts.", threshold);
    } else {
        for (i, (ip, stats)) in filtered.iter().enumerate() {
            let mut usernames: Vec<_> = stats.usernames.iter().map(String::as_str).collect();
            usernames.sort();
            let username_list = usernames.join(", ");
            let country_display = country_codes
                .as_ref()
                .map(|c| format!(" [{}]", c[i]))
                .unwrap_or_default();
            let abuse_display = abuse_scores
                .as_ref()
                .map(|s| format!(" | Abuse Score: {} | ", s[i]))
                .unwrap_or_else(|| " | ".to_string());
            println!(
                "    IP: {}{}  {} Attempts: {}  |  Usernames: [{}]",
                ip, country_display, abuse_display, stats.attempt_count, username_list
            );
        }
    }

    println!();
    if let Some(output_path) = &args.output {
        if let Err(e) = write_attackers_csv(
            output_path,
            &filtered,
            country_codes.as_deref(),
            abuse_scores.as_deref(),
        ) {
            eprintln!("Error writing CSV to {:?}: {}", output_path, e);
            std::process::exit(1);
        }
        println!("  Exported {} attacker(s) to {}", filtered.len(), output_path.display());
    }
    println!("═══════════════════════════════════════════════════════════════");

    Ok(())
}

/// Fetches AbuseIPDB abuse confidence score for an IP. Returns "N/A" on any failure.
fn fetch_abuse_score(client: &reqwest::blocking::Client, api_key: &str, ip: &str) -> String {
    let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={}", ip);
    let res = client
        .get(&url)
        .header("Key", api_key)
        .header("Accept", "application/json")
        .send();
    let res = match res {
        Ok(r) => r,
        Err(_) => return "N/A".to_string(),
    };
    let status = res.status();
    let body = match res.text() {
        Ok(b) => b,
        Err(_) => return "N/A".to_string(),
    };
    if !status.is_success() {
        return "N/A".to_string();
    }
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(_) => return "N/A".to_string(),
    };
    let score = json
        .get("data")
        .and_then(|d| d.get("abuseConfidenceScore"))
        .and_then(|s| s.as_u64())
        .map(|n| n.min(100));
    match score {
        Some(s) => format!("{}%", s),
        None => "N/A".to_string(),
    }
}

/// Returns ISO country code for an IP using the MaxMind reader, or "Unknown" on parse/lookup failure.
fn lookup_country(reader: &maxminddb::Reader<Vec<u8>>, ip_str: &str) -> String {
    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return "Unknown".to_string(),
    };
    let result = match reader.lookup(ip) {
        Ok(r) => r,
        Err(_) => return "Unknown".to_string(),
    };
    match result.decode::<maxminddb::geoip2::Country>() {
        Ok(Some(record)) => record
            .country
            .iso_code
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string()),
        _ => "Unknown".to_string(),
    }
}

/// Writes the filtered attackers to a CSV file with headers: IP, Country, Abuse Score, Attempts, Usernames.
fn write_attackers_csv(
    path: &std::path::Path,
    filtered: &[&(String, AttackerStats)],
    country_codes: Option<&[String]>,
    abuse_scores: Option<&[String]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["IP", "Country", "Abuse Score", "Attempts", "Usernames"])?;
    for (i, (ip, stats)) in filtered.iter().enumerate() {
        let mut usernames: Vec<_> = stats.usernames.iter().map(String::as_str).collect();
        usernames.sort();
        let usernames_str = usernames.join(";");
        let country = country_codes
            .and_then(|c| c.get(i))
            .map(String::as_str)
            .unwrap_or("Unknown");
        let abuse = abuse_scores
            .and_then(|a| a.get(i))
            .map(String::as_str)
            .unwrap_or("N/A");
        wtr.write_record([
            ip.as_str(),
            country,
            abuse,
            &stats.attempt_count.to_string(),
            &usernames_str,
        ])?;
    }
    wtr.flush()?;
    Ok(())
}
