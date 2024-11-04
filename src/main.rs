use deku::DekuContainerRead;
use reqwest::Client;
use reqwest::Error;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ops::Sub;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration, Instant};

use base64::prelude::*;
use ct_structs::v1::*;
use futures::{FutureExt, StreamExt};
use serde::Deserialize;
use serde::Serialize;
use serde_json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use warp::{
    ws::{Message, WebSocket},
    Filter,
};
use x509_parser::prelude::*;

const ENTRIES_PER_REQUEST: usize = 16;
const REQUEST_SLEEP_TIME: Duration = Duration::from_secs(2);
/// If we see the same domain within 10 minutes, ignore it
const IGNORE_DUPLICATE_TIME: Duration = Duration::from_secs(60 * 10);
/// Maximum age of timestamp in milliseconds
const MAX_ENTRY_AGE: u128 = 1000 * 60 * 30;

/// Entries are made up of these.
#[derive(Debug, Deserialize)]
struct Entry {
    leaf_input: String,
    // extra_data: String,
}

/// This is the type we receive from the get-entries endpoint.
#[derive(Debug, Deserialize)]
struct Entries {
    entries: Vec<Entry>,
}

// ParsedEntry needs to be serializable so we can send it over WebSocket
#[derive(Debug, Serialize)]
struct ParsedEntry {
    log: String,
    timestamp: u64,
    issuer: String,
    domain: String,
}

/// get_first_cn_as_str gets the first organization found as a string.
fn get_first_org_as_str<'a>(name: &'a X509Name<'_>) -> Option<&'a str> {
    name.iter_organization()
        .next()
        .and_then(|cn| cn.as_str().ok())
}

/// get_first_cn_as_str gets the first common name found as a string.
fn get_first_cn_as_str<'a>(name: &'a X509Name<'_>) -> Option<&'a str> {
    name.iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
}

/// parse_entry gets the issuer and domain name from an Entry containing a
/// base64 encoded leaf_input.
fn parse_entry(log: &str, entry: Entry) -> Option<ParsedEntry> {
    // We use expects here because the servers should always return correct
    // data.  If there's a decoding error, it's probably on our end.
    let leaf_input_bytes = BASE64_STANDARD
        .decode(entry.leaf_input)
        .expect("expected valid base64 leaf_input");
    // let extra_data_bytes = BASE64_STANDARD.decode(entry.extra_data).expect("expected valid base64 extra_data");

    let (_, merkle_tree_leaf) = MerkleTreeLeaf::from_bytes((&leaf_input_bytes, 0))
        .expect("failed to parse merkle tree leaf");

    if let TreeLeafEntry::TimestampedEntry(ts_entry) = &merkle_tree_leaf.entry {
        match &ts_entry.signed_entry {
            SignedEntry::X509Entry(x509_entry) => {
                let (_, x509_certificate) = X509Certificate::from_der(&x509_entry.certificate)
                    .expect("failed to parse x509 certificate");

                let issuer = get_first_org_as_str(x509_certificate.issuer());
                let subject = get_first_cn_as_str(x509_certificate.subject());
                if let (Some(issuer_name), Some(domain_name)) = (issuer, subject) {
                    return Some(ParsedEntry {
                        log: log.to_string(),
                        issuer: issuer_name.to_string(),
                        domain: domain_name.to_string(),
                        timestamp: ts_entry.timestamp,
                    });
                }
            }
            SignedEntry::PrecertEntry(precert_entry) => {
                let (_, tbs_certificate) = TbsCertificate::from_der(&precert_entry.tbs_certificate)
                    .expect("failed to parse tbs certificate");

                let issuer = get_first_org_as_str(tbs_certificate.issuer());
                let subject = get_first_cn_as_str(tbs_certificate.subject());
                if let (Some(issuer_name), Some(domain_name)) = (issuer, subject) {
                    return Some(ParsedEntry {
                        log: log.to_string(),
                        issuer: issuer_name.to_string(),
                        domain: domain_name.to_string(),
                        timestamp: ts_entry.timestamp,
                    });
                }
            }
            _ => unreachable!(),
        }
    }

    None
}

/// get_entries retrieves entries from a CT log.  Requires an HTTP client,
/// base URL for the log, and indices to retrieve.
async fn get_entries(
    client: &reqwest::Client,
    base_url: &str,
    start: usize,
    end: usize,
) -> Result<Entries, Error> {
    // println!("start = {}, end = {}", start, end);

    client
        .get(format!(
            "{}ct/v1/get-entries?start={}&end={}",
            base_url, start, end
        ))
        .send()
        .await
        .expect("failed to send request")
        .json::<Entries>()
        .await
}

/// get_max_entry uses binary search to find the highest entry index that we
/// can access without an error.  This is the latest index.  We have to do
/// this because there is no endpoint to get the latest entry index and not
/// all CT log implementation say the value of it in the error message.
async fn get_max_entry(client: &reqwest::Client, base_url: &str) -> usize {
    let mut l: usize = 0;
    let mut r: usize = usize::MAX;
    while l <= r {
        let m = l + (r - l) / 2;
        let result = get_entries(client, base_url, m, m).await;

        if let Ok(entries) = result {
            if entries.entries.len() > 0 {
                // If we get entries, then we know we have data at that index
                l = m + 1;
            } else {
                // If we get no entries, index is still too high
                r = m - 1;
            }
        } else {
            // If we get an error, index is still too high
            r = m - 1;
        }

        sleep(REQUEST_SLEEP_TIME).await;
    }
    r
}

// Track active connections using client IDs
type Clients = Arc<RwLock<HashSet<u64>>>;

// Generate unique client IDs
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

async fn client_connection(
    ws: WebSocket,
    broadcast_rx: broadcast::Receiver<String>,
    clients: Clients,
) {
    let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
    let (client_ws_sender, _) = ws.split();

    // Add client ID to active connections
    clients.write().await.insert(client_id);

    let broadcast_rcv =
        tokio_stream::wrappers::BroadcastStream::new(broadcast_rx).map(|msg| match msg {
            Ok(encoded_message) => Ok(Message::text(encoded_message)),
            Err(_) => Ok(Message::text("Error processing message")),
        });

    let forward_task = broadcast_rcv.forward(client_ws_sender).map(|result| {
        if let Err(e) = result {
            eprintln!("Error forwarding message to client {}: {}", client_id, e);
        }
    });

    forward_task.await;

    // Client disconnected, remove from active connections
    clients.write().await.remove(&client_id);
    println!("Client {} disconnected", client_id);
}

#[tokio::main]
async fn main() {
    // Generate using:
    // curl https://www.gstatic.com/ct/log_list/v3/log_list.json | jq .operators[].logs[].url | sed '$!s/$/,/'
    const BASE_URLS: &'static [&'static str] = &[
        "https://ct.googleapis.com/logs/us1/argon2024/",
        "https://ct.googleapis.com/logs/us1/argon2025h1/",
        "https://ct.googleapis.com/logs/us1/argon2025h2/",
        "https://ct.googleapis.com/logs/us1/argon2026h1/",
        "https://ct.googleapis.com/logs/us1/argon2026h2/",
        "https://ct.googleapis.com/logs/eu1/xenon2024/",
        "https://ct.googleapis.com/logs/eu1/xenon2025h1/",
        "https://ct.googleapis.com/logs/eu1/xenon2025h2/",
        "https://ct.googleapis.com/logs/eu1/xenon2026h1/",
        "https://ct.googleapis.com/logs/eu1/xenon2026h2/",
        "https://ct.cloudflare.com/logs/nimbus2024/",
        "https://ct.cloudflare.com/logs/nimbus2025/",
        "https://ct.cloudflare.com/logs/nimbus2026/",
        "https://yeti2024.ct.digicert.com/log/",
        "https://yeti2025.ct.digicert.com/log/",
        "https://nessie2024.ct.digicert.com/log/",
        "https://nessie2025.ct.digicert.com/log/",
        "https://wyvern.ct.digicert.com/2024h2/",
        "https://wyvern.ct.digicert.com/2025h1/",
        "https://wyvern.ct.digicert.com/2025h2/",
        "https://wyvern.ct.digicert.com/2026h1/",
        "https://wyvern.ct.digicert.com/2026h2/",
        "https://sphinx.ct.digicert.com/2024h2/",
        "https://sphinx.ct.digicert.com/2025h1/",
        "https://sphinx.ct.digicert.com/2025h2/",
        "https://sphinx.ct.digicert.com/2026h1/",
        "https://sphinx.ct.digicert.com/2026h2/",
        "https://sabre.ct.comodo.com/",
        "https://sabre2024h2.ct.sectigo.com/",
        "https://sabre2025h1.ct.sectigo.com/",
        "https://sabre2025h2.ct.sectigo.com/",
        "https://mammoth2024h2.ct.sectigo.com/",
        "https://mammoth2025h1.ct.sectigo.com/",
        "https://mammoth2025h2.ct.sectigo.com/",
        "https://mammoth2026h1.ct.sectigo.com/",
        "https://mammoth2026h2.ct.sectigo.com/",
        "https://sabre2026h1.ct.sectigo.com/",
        "https://sabre2026h2.ct.sectigo.com/",
        "https://oak.ct.letsencrypt.org/2024h2/",
        "https://oak.ct.letsencrypt.org/2025h1/",
        "https://oak.ct.letsencrypt.org/2025h2/",
        "https://oak.ct.letsencrypt.org/2026h1/",
        "https://oak.ct.letsencrypt.org/2026h2/",
        "https://ct2024.trustasia.com/log2024/",
        "https://ct2025-a.trustasia.com/log2025a/",
        "https://ct2025-b.trustasia.com/log2025b/",
        "https://ct2026-a.trustasia.com/log2026a/",
        "https://ct2026-b.trustasia.com/log2026b/",
    ];

    let (broadcast_tx, _) = broadcast::channel::<String>(1024);
    let broadcast_tx = Arc::new(broadcast_tx);

    // Initialize clients set
    let clients: Clients = Arc::new(RwLock::new(HashSet::new()));

    let (entry_tx, mut entry_rx) = mpsc::channel(BASE_URLS.len());

    // Spawn the original certificate monitoring tasks
    for base_url in BASE_URLS {
        let entry_tx: tokio::sync::mpsc::Sender<ParsedEntry> = entry_tx.clone();
        let base_url = base_url.to_string();

        tokio::spawn(async move {
            let client = Client::new();
            let mut start_index = get_max_entry(&client, &base_url).await;
            println!("{}: start index {}", base_url, start_index);

            loop {
                match get_entries(
                    &client,
                    &base_url,
                    start_index,
                    start_index + ENTRIES_PER_REQUEST,
                )
                .await
                {
                    Ok(entries) => {
                        start_index += entries.entries.len();

                        for entry in entries.entries {
                            if let Some(parsed_entry) = parse_entry(&base_url, entry) {
                                if let Err(e) = entry_tx.send(parsed_entry).await {
                                    panic!("Receiver dropped: {}", e);
                                }
                            }
                        }
                    }
                    // Pretty much all errors are due to the log not having
                    // the indices we requested, i.e. we are completely caught
                    // up.  So we can just ignore here.
                    Err(_) => {} // Err(e) => println!("failed to get entries: {}", e),
                }

                sleep(REQUEST_SLEEP_TIME).await;
            }
        });
    }

    // Spawn broadcasting task
    // This listens to the MPSC queue and broadcasts the new parsed entries to
    // all WebSocket clients.
    let broadcast_tx_clone = broadcast_tx.clone();
    tokio::spawn(async move {
        let mut seen: HashMap<String, Instant> = HashMap::new();

        while let Some(parsed_entry) = entry_rx.recv().await {
            let current_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            if (u128::from(parsed_entry.timestamp) + MAX_ENTRY_AGE) < current_epoch {
                continue;
            }

            let now = Instant::now();
            if let Some(last_seen) = seen.get(&parsed_entry.domain) {
                // If we have seen a domain in the past IGNORE_DUPLICATE_TIME,
                // don't show it again.  This is because some certificates are
                // submitted to multiple logs.
                if now.sub(*last_seen) <= IGNORE_DUPLICATE_TIME {
                    continue;
                }
            }
            seen.insert(parsed_entry.domain.clone(), now);

            let encoded_message = serde_json::to_string(&parsed_entry).unwrap_or_default();
            // Broadcast the entry to all connected WebSocket clients
            if let Err(e) = broadcast_tx_clone.send(encoded_message.clone()) {
                eprintln!("Error broadcasting message: {}", e);
            }

            println!(
                "{} - {} ({}: {})",
                parsed_entry.issuer, parsed_entry.domain, parsed_entry.log, parsed_entry.timestamp
            );
        }
    });

    // Start the server
    const PORT: u16 = 5555;
    println!("Server starting at http://127.0.0.1:{}", PORT);

    let root_route = warp::path::end().and(warp::fs::file("./static/index.html"));
    let about_route = warp::path("about").and(warp::fs::file("./static/about.html"));
    let static_route = warp::path("static").and(warp::fs::dir("./static/data"));

    // Clone for WebSocket route
    let ws_route = warp::path("ws")
        .and(warp::ws())
        .map(move |ws: warp::ws::Ws| {
            let broadcast_rx = broadcast_tx.clone().subscribe();
            let clients = clients.clone();
            ws.on_upgrade(move |socket| client_connection(socket, broadcast_rx, clients))
        });

    let routes = warp::get().and(
        root_route
            .or(about_route.clone())
            .or(static_route.clone())
            .or(ws_route.clone()),
    );
    warp::serve(routes).run(([127, 0, 0, 1], PORT)).await;
}
