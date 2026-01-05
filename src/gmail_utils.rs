use chrono::DateTime;
use gmail1::api::{Message, MessagePart};
use google_gmail1 as gmail1;
use hyper_rustls::HttpsConnectorBuilder;

use std::{fs::File, io::Read};

pub struct GmailConfig {
    pub service_account_json: String,
    pub impersonate_user: String,
    pub sender: String,
    pub subject: String,
}

fn parse_rfc2822_to_iso(date_str: &str) -> Option<String> {
    DateTime::parse_from_rfc2822(date_str)
        .ok()
        .map(|dt| dt.to_rfc3339())
}

fn extract_header_value(headers: &[gmail1::api::MessagePartHeader], name: &str) -> Option<String> {
    headers.iter()
        .find(|h| h.name.as_deref().map(|n| n.eq_ignore_ascii_case(name)).unwrap_or(false))
        .and_then(|h| h.value.clone())
}

fn collect_attachments(parts: &[MessagePart], out: &mut Vec<(String, Vec<u8>)>) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    for part in parts {
        if let Some(fname) = &part.filename {
            if !fname.is_empty() {
                if let Some(body) = &part.body {
                    if let Some(data) = &body.data {
                        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(data) {
                            out.push((fname.clone(), bytes));
                        }
                    }
                }
            }
        }
        if let Some(sub) = &part.parts {
            collect_attachments(sub, out);
        }
    }
}

pub async fn list_and_download(cfg: GmailConfig) -> Result<(), anyhow::Error> {
    // Load service account JSON
    let mut file = File::open(&cfg.service_account_json)?;
    let mut json = String::new();
    file.read_to_string(&mut json)?;

    let key: gmail1::oauth2::ServiceAccountKey = serde_json::from_str(&json)?;
    let auth = gmail1::oauth2::ServiceAccountAuthenticator::builder(key)
        .subject(cfg.impersonate_user.clone())
        .build()
        .await?;

    // Build HTTPS client
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);

    // Create Gmail hub
    let hub = gmail1::Gmail::new(client, auth);

    // Search query
    let query = format!("from:{} subject:{}", cfg.sender, cfg.subject);

    let list = hub.users().messages_list("me")
        .q(&query)
        .max_results(50)
        .add_scope("https://www.googleapis.com/auth/gmail.readonly")
        .doit().await?.1;

    let messages = match list.messages {
        Some(msgs) => msgs,
        None => {
            println!("No messages found");
            return Ok(());
        }
    };

    println!("Found {} messages", messages.len());

    for m in messages {
        let id = m.id.unwrap();
        let full: Message = hub.users().messages_get("me", &id)
            .format("full")
            .add_scope("https://www.googleapis.com/auth/gmail.readonly")
            .doit().await?.1;

        // Extract headers
        if let Some(payload) = &full.payload {
            if let Some(ref headers) = payload.headers {
                let date_iso = extract_header_value(headers, "Date")
                    .and_then(|d| parse_rfc2822_to_iso(&d))
                    .unwrap_or_default();
                let from = extract_header_value(headers, "From").unwrap_or_default();
                let subject = extract_header_value(headers, "Subject").unwrap_or_default();

                println!("{} | {} | <{}>", date_iso, from, subject.as_str().trim().replace("\n", ""));
            }
        }

        // Collect attachments through inline bodies
        let mut attachments = Vec::new();
        if let Some(payload) = &full.payload {
            if let Some(parts) = &payload.parts {
                collect_attachments(parts, &mut attachments);
            }
        }

        println!("  {} attachments", attachments.len());

        for (filename, data) in attachments {
            std::fs::write(&filename, &data)?;
            println!("Saved attachment: {}", filename);
        }
    }
    Ok(())
}
