use std::path::PathBuf;
use chrono::{Duration, Utc};
use rand::{distributions::Uniform, Rng};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::blocking::{Client, multipart::{Form, Part}};
use serde::Serialize;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about = "Uploads an XPI to addons.thunderbird.net using JWT auth")]
struct Args {
        /// Print verbose debugging output
        #[arg(long)]
        verbose: bool,
    /// API key (JWT issuer)
    #[arg(long)]
    api_key: Option<String>,

    /// API secret (JWT signing secret)
    #[arg(long)]
    api_secret: Option<String>,

    /// Addon GUID
    #[arg(long)]
    addon_guid: Option<String>,

    /// Version
    #[arg(long)]
    version: Option<String>,

    /// Path to XPI file
    #[arg(long)]
    xpi_path: Option<String>,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    jti: String,
    exp: usize,
    iat: usize,
}

fn random_jti(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let die = Uniform::from(0..CHARS.len());
    (0..len)
        .map(|_| CHARS[rng.sample(die)] as char)
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    let args = Args::parse();


    // Parameterize all inputs: CLI flag > env var > default (for non-secrets)
    let api_key = args.api_key.or_else(|| env::var("API_KEY").ok());
    let api_secret = args.api_secret.or_else(|| env::var("API_SECRET").ok());
    let addon_guid = args.addon_guid.or_else(|| env::var("ADDON_GUID").ok());
    let version = args.version.or_else(|| env::var("VERSION").ok());
    let xpi_path = args.xpi_path.or_else(|| env::var("XPI_PATH").ok());

    // Error if any required parameter is missing, and print which
    let mut missing = Vec::new();
    if api_key.is_none() { missing.push("api_key"); }
    if api_secret.is_none() { missing.push("api_secret"); }
    if addon_guid.is_none() { missing.push("addon_guid"); }
    if version.is_none() { missing.push("version"); }
    if xpi_path.is_none() { missing.push("xpi_path"); }
    if !missing.is_empty() {
        eprintln!("Error: missing required parameter(s): {}", missing.join(", "));
        std::process::exit(1);
    }
    let api_key = api_key.unwrap();
    let api_secret = api_secret.unwrap();
    let addon_guid = addon_guid.unwrap();
    let version = version.unwrap();
    let xpi_path = xpi_path.unwrap();

    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + Duration::seconds(60)).timestamp() as usize;

    let claims = Claims {
        iss: api_key.clone(),
        jti: random_jti(64),
        exp,
        iat,
    };

    let header = Header::new(Algorithm::HS256);
    let token = encode(&header, &claims, &EncodingKey::from_secret(api_secret.as_bytes()))?;

    let url = format!(
        "https://addons.thunderbird.net/api/v3/addons/{}/versions/{}/",
        addon_guid, version
    );

    if args.verbose {
        println!("[DEBUG] api_key: {}", api_key);
        println!("[DEBUG] api_secret: {}", "*hidden*");
        println!("[DEBUG] addon_guid: {}", addon_guid);
        println!("[DEBUG] version: {}", version);
        println!("[DEBUG] xpi_path: {}", xpi_path);
        println!("[DEBUG] JWT claims: {{ iss: {}, jti: {}, exp: {}, iat: {} }}", claims.iss, claims.jti, claims.exp, claims.iat);
        println!("[DEBUG] JWT token: {}", token);
        println!("[DEBUG] Upload URL: {}", url);
    }

    let path = PathBuf::from(&xpi_path);
    let file_part = Part::file(path.clone())?;
    let form = Form::new().part("upload", file_part);

    let client = Client::new();
    if args.verbose {
        println!("[DEBUG] Sending PUT request with multipart form...");
    }
    let resp = client
        .put(&url)
        .header("Authorization", format!("JWT {}", token))
        .multipart(form)
        .send()?;

    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    println!("{} {}", status.as_u16(), body);

    Ok(())
}
