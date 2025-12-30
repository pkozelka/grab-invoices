use google_gmail1::Gmail;
use google_gmail1::hyper;
use google_gmail1::hyper_rustls;
use google_gmail1::yup_oauth2::{self, InstalledFlowAuthenticator, InstalledFlowReturnMethod};
use std::path::Path;
use chrono::{Utc, TimeZone};
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Authentication using the crate's internal yup_oauth2
    let secret = yup_oauth2::read_application_secret("credentials.json").await?;
    let auth = InstalledFlowAuthenticator::builder(secret, InstalledFlowReturnMethod::HTTPRedirect)
        .persist_tokens_to_disk("token.json")
        .build()
        .await?;

    // Fix: .with_native_roots() returns a Result in newer hyper-rustls
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()? 
        .https_or_http()
        .enable_http1()
        .build();

    let client = hyper::Client::builder().build(connector);
    let hub = Gmail::new(client, auth);

    // 2. Search
    let query = "from:payments-noreply@google.com has:attachment";
    let (_, list_res) = hub.users().messages_list("me").q(query).doit().await?;

    let messages = match list_res.messages {
        Some(m) => m,
        None => {
            println!("No invoices found.");
            return Ok(());
        }
    };

    tokio::fs::create_dir_all("google_invoices").await?;

    for msg_ref in messages {
        let msg_id = msg_ref.id.unwrap();
        let (_, message) = hub.users().messages_get("me", &msg_id).doit().await?;

        let internal_date = message.internal_date.unwrap_or(0);
        let date_time = Utc.timestamp_millis_opt(internal_date).unwrap();
        let date_prefix = date_time.format("%Y-%m").to_string();

        if let Some(payload) = message.payload {
            if let Some(parts) = payload.parts {
                process_parts(&hub, &msg_id, &date_prefix, parts).await?;
            }
        }
    }

    Ok(())
}

async fn process_parts(
    hub: &Gmail<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>,
    msg_id: &str,
    date_prefix: &str,
    parts: Vec<google_gmail1::api::MessagePart>,
) -> Result<(), Box<dyn std::error::Error>> {
    for part in parts {
        let filename = part.filename.clone().unwrap_or_default();
        
        if filename.to_lowercase().ends_with(".pdf") {
            if let Some(body) = part.body {
                if let Some(attachment_id) = body.attachment_id {
                    let (_, attachment) = hub.users().messages_attachments_get("me", msg_id, &attachment_id).doit().await?;
                    
                    if let Some(data) = attachment.data {
                        // Fix: Use the new Engine-based base64 decoding
                        let decoded = general_purpose::URL_SAFE.decode(data)?;
                        let new_filename = format!("{}_{}", date_prefix, filename);
                        let path = Path::new("google_invoices").join(new_filename);
                        
                        tokio::fs::write(&path, decoded).await?;
                        println!("Downloaded: {}", path.display());
                    }
                }
            }
        }
    }
    Ok(())
}
