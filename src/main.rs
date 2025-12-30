use google_gmail1::api;
use google_gmail1::Gmail;
// Use the versions of hyper and oauth2 that google_gmail1 is built with
use google_gmail1::client::google_cloud_metadata::hyper;
use google_gmail1::yup_oauth2::{self, InstalledFlowAuthenticator, InstalledFlowReturnMethod};
use std::path::Path;
use chrono::{Utc, TimeZone};
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Authentication
    let secret = yup_oauth2::read_application_secret("credentials.json").await?;
    let auth = InstalledFlowAuthenticator::builder(secret, InstalledFlowReturnMethod::HTTPRedirect)
        .persist_tokens_to_disk("token.json")
        .build()
        .await?;

    // Use the connector builder provided by the crate's internal hyper_rustls
    let connector = google_gmail1::hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()? // Note: adding ? here for version 0.25+
        .https_or_http()
        .enable_http1()
        .build();

    let client = hyper::Client::builder().build(connector);
    let hub = Gmail::new(client, auth);

    // 2. Search
    let query = "from:payments-noreply@google.com has:attachment";
    let (_, list_res) = hub.users().messages_list("me").q(query).doit().await?;

    if let Some(messages) = list_res.messages {
        tokio::fs::create_dir_all("google_invoices").await?;

        for msg_ref in messages {
            let msg_id = msg_ref.id.unwrap();
            let (_, message) = hub.users().messages_get("me", &msg_id).doit().await?;

            let internal_date = message.internal_date.unwrap_or(0);
            let date_time = Utc.timestamp_millis_opt(internal_date).unwrap();
            let date_prefix = date_time.format("%Y-%m").to_string();

            if let Some(payload) = message.payload {
                process_parts(&hub, &msg_id, &date_prefix, payload.parts.unwrap_or_default()).await?;
            }
        }
    } else {
        println!("No invoices found.");
    }

    Ok(())
}

// We use an async recursion strategy to find PDFs in nested email parts
#[async_recursion::async_recursion]
async fn process_parts<S>(
    hub: &Gmail<S>,
    msg_id: &str,
    date_prefix: &str,
    parts: Vec<api::MessagePart>,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
{
    for part in parts {
        let filename = part.filename.clone().unwrap_or_default();

        if filename.to_lowercase().ends_with(".pdf") {
            if let Some(body) = part.body {
                if let Some(attachment_id) = body.attachment_id {
                    let (_, attachment) = hub.users()
                        .messages_attachments_get("me", msg_id, &attachment_id)
                        .doit()
                        .await?;

                    if let Some(data) = attachment.data {
                        let decoded = general_purpose::URL_SAFE.decode(data)?;
                        let new_filename = format!("{}_{}", date_prefix, filename);
                        let path = Path::new("google_invoices").join(new_filename);

                        tokio::fs::write(&path, decoded).await?;
                        println!("Downloaded: {}", path.display());
                    }
                }
            }
        }

        // Recurse into nested parts if they exist
        if let Some(nested_parts) = part.parts {
            process_parts(hub, msg_id, date_prefix, nested_parts).await?;
        }
    }
    Ok(())
}
