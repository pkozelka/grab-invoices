use google_gmail1::Gmail;
use std::path::Path;
use chrono::{Utc, TimeZone};
use base64::{engine::general_purpose, Engine as _};

// Use the exact types the crate expects to satisfy trait bounds
type HttpClient = google_gmail1::hyper::Client<google_gmail1::hyper_rustls::HttpsConnector<google_gmail1::hyper::client::HttpConnector>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Authentication
    let secret = yup_oauth2::read_application_secret("credentials.json").await?;
    let auth = yup_oauth2::InstalledFlowAuthenticator::builder(secret, yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect)
        .persist_tokens_to_disk("token.json")
        .build()
        .await?;

    // 2. Build the Connector - using .expect() as required by your compiler version
    let connector = google_gmail1::hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native roots")
        .https_or_http()
        .enable_http1()
        .build();

    let client: HttpClient = google_gmail1::hyper::Client::builder().build(connector);
    let hub = Gmail::new(client, auth);

    // 3. Search
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
                let mut stack = vec![payload];
                while let Some(current_part) = stack.pop() {
                    if let Some(parts) = current_part.parts {
                        for part in parts {
                            let filename = part.filename.clone().unwrap_or_default();
                            if filename.to_lowercase().ends_with(".pdf") {
                                if let Some(body) = part.body {
                                    if let Some(att_id) = body.attachment_id {
                                        // Direct download
                                        let (_, attachment) = hub.users()
                                            .messages_attachments_get("me", &msg_id, &att_id)
                                            .doit()
                                            .await?;

                                        if let Some(data) = attachment.data {
                                            let decoded = general_purpose::URL_SAFE.decode(data)?;
                                            let new_name = format!("{}_{}", date_prefix, filename);
                                            let path = Path::new("google_invoices").join(new_name);
                                            tokio::fs::write(&path, decoded).await?;
                                            println!("Downloaded: {}", path.display());
                                        }
                                    }
                                }
                            }
                            stack.push(part);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
