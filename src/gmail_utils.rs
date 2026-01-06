use chrono::{DateTime, Datelike, FixedOffset};
use gmail1::api::{Message, MessagePart};
use google_gmail1 as gmail1;

use base64::Engine;
use hyper::{Body, Client, Request};
use hyper_rustls::HttpsConnectorBuilder;
use std::{fs::File, io::Read};

pub struct GmailConfig {
    pub service_account_json: String,
    pub impersonate_user: String,
    pub sender: String,
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

/// Represents a Gmail attachment, either inline data or needs separate fetch
#[derive(Debug)]
pub struct GmailAttachment {
    pub filename: String,
    pub data: Option<Vec<u8>>,      // Some if body.data exists
    pub attachment_id: Option<String>, // Some if body.attachmentId exists
}

/// Recursively collects attachments from payload parts
pub fn collect_attachments(parts: &[MessagePart], out: &mut Vec<GmailAttachment>) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    for part in parts {
        if let Some(fname) = &part.filename {
            if !fname.is_empty() {
                let mut attachment = GmailAttachment {
                    filename: fname.clone(),
                    data: None,
                    attachment_id: None,
                };

                if let Some(body) = &part.body {
                    // Small inline attachment
                    if let Some(data_str) = &body.data {
                        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(data_str) {
                            attachment.data = Some(decoded);
                        }
                    }

                    // Large attachment requiring separate fetch
                    if let Some(att_id) = &body.attachment_id {
                        attachment.attachment_id = Some(att_id.clone());
                    }
                }

                out.push(attachment);
            }
        }

        // Recurse into nested parts (multipart/mixed)
        if let Some(subparts) = &part.parts {
            collect_attachments(subparts, out);
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
    let hub = gmail1::Gmail::new(client, auth.clone());

    // Search query
    let query = format!("from:{} after:2025/01/05", cfg.sender);

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

        let mut prefix = "target/".to_string();
        // Extract headers
        if let Some(payload) = &full.payload {
            if let Some(ref headers) = payload.headers {
                let date_header = extract_header_value(headers, "Date").unwrap();
                let date_iso = parse_rfc2822_to_iso(&date_header)
                    .unwrap_or_default();

                let dt = DateTime::parse_from_rfc2822(&date_header).unwrap_or_default();
                let billing_period = previous_month_period(dt);
                prefix.extend(billing_period.as_str().chars());
                prefix.extend("-".chars());

                let from = extract_header_value(headers, "From").unwrap_or_default();
                let subject = extract_header_value(headers, "Subject")
                    .unwrap_or_default()
                    .as_str().trim().replace("\n", "");
                if subject.as_str().find("Vaše faktura za doménu origis.cz je k dispozici").is_some() {
                    prefix.extend("origis-cz-GoogleWorkspace-".chars())
                }
                if subject.as_str().find("Google Cloud Platform & APIs: Vaše faktura za doménu 009FE9-96B906-0B6266 je k dispozici").is_some() {
                    prefix.extend("origis-cz-GoogleCloud-".chars())
                }
                println!("{} | {} | <{}>", date_iso, from, subject);
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


        // Download all attachments
        download_all_attachments(&auth, &id, &attachments, &prefix).await?;
    }
    Ok(())
}

fn previous_month_period(dt: DateTime<FixedOffset>) -> String {
    let mut year = dt.year();
    let mut month = dt.month(); // 1..=12

    if month == 1 {
        year -= 1;
        month = 12;
    } else {
        month -= 1;
    }

    format!("{:04}-{:02}", year, month)
}

use anyhow::Result;
use std::io::Write;

/// Downloads all attachments for a single message
///
/// # Arguments
/// - `hub`: Gmail hub
/// - `attachments`: list of attachments returned from `collect_attachments`
/// - `message_id`: the message ID
///
/// This will:
/// - Write inline attachments directly
/// - Fetch large attachments via Gmail API if `attachment_id` exists
pub async fn download_all_attachments<A>(
    auth: &A,
    message_id: &str,
    attachments: &Vec<GmailAttachment>,
    prefix: &str,
) -> Result<()>
where
    A: google_gmail1::client::GetToken + Clone + Send + Sync + 'static,
{
    // Build HTTPS client for raw HTTP fetch
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder().build::<_, Body>(https);

    // Get access token from the authenticator
    let token = auth
        .get_token(&["https://www.googleapis.com/auth/gmail.readonly"])
        .await.map_err(|e| anyhow::anyhow!("{:?}", e))?
        .unwrap()
        .as_str()
        .to_string();

    for att in attachments {
        if let Some(data) = &att.data {
            // Small inline attachment
            let mut file = File::create(format!("{prefix}{}", &att.filename))?;
            file.write_all(data)?;
            println!("Saved inline attachment: {}", att.filename);
        } else if let Some(att_id) = &att.attachment_id {
            // Large attachment: fetch via raw HTTP
            let url = format!(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}/attachments/{}",
                message_id, att_id
            );

            let req = Request::builder()
                .uri(url)
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())?;

            let res = client.request(req).await?;
            let body_bytes = hyper::body::to_bytes(res.into_body()).await?;

            #[derive(serde::Deserialize)]
            struct AttachmentResponse { data: String }
            let r: AttachmentResponse = serde_json::from_slice(&body_bytes)?;

            match decode_gmail_attachment(&r.data) {
                Ok(decoded) => {
                    let mut file = File::create(format!("{prefix}{}", &att.filename))?;
                    file.write_all(&decoded)?;
                    println!("  * Downloaded attachment via API: {}", att.filename);
                }
                Err(e) => {
                    println!("  ! DATA/b64: {:?}", r.data);
                    println!("  ! Failed to decode attachment: {}", e);
                }
            }
        }
    }

    Ok(())
}

use base64::engine::general_purpose::URL_SAFE;

/// Decode Gmail attachment data (handles missing padding)
pub fn decode_gmail_attachment(data: &str) -> anyhow::Result<Vec<u8>> {
    // Gmail sometimes omits padding, so we need to pad manually
    let mut s = data.to_string();
    let rem = s.len() % 4;
    if rem != 0 {
        s.extend(std::iter::repeat('=').take(4 - rem));
    }

    let decoded = URL_SAFE.decode(s.as_bytes())?;
    Ok(decoded)
}
