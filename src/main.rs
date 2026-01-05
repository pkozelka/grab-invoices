use google_gmail1::Gmail;
// IMPORTANT: Import oauth2 directly from the gmail crate's re-export
use std::path::Path;
use chrono::{Utc, TimeZone};
use base64::{engine::general_purpose, Engine as _};
use google_gmail1::hyper::client::HttpConnector;
use google_gmail1::hyper_rustls::HttpsConnector;
use google_gmail1::oauth2::authenticator::Authenticator;
use google_gmail1::oauth2::{ServiceAccountAuthenticator, ServiceAccountKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Authentication using the re-exported types
    // let secret = yup_oauth2::read_application_secret("credentials.json").await?;
    // let auth = InstalledFlowAuthenticator::builder(secret, InstalledFlowReturnMethod::HTTPRedirect)
    //     .persist_tokens_to_disk("token.json")
    //     .build()
    //     .await?;
    let who="origis@origis.info";
    let auth = create_auth(who).await;


    // 2. Build the Connector using the gmail crate's internal hyper/rustls versions
    let connector = google_gmail1::hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native roots")
        .https_or_http()
        .enable_http1()
        .build();

    let client = google_gmail1::hyper::Client::builder().build(connector);
    let hub = Gmail::new(client, auth);

    // 3. Search for Google Billing emails
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
                    // Check if this part is a PDF
                    let filename = current_part.filename.clone().unwrap_or_default();
                    if filename.to_lowercase().ends_with(".pdf") {
                        if let Some(body) = current_part.body {
                            if let Some(att_id) = body.attachment_id {
                                let (_, attachment) = hub.users()
                                    .messages_attachments_get("me", &msg_id, &att_id)
                                    .doit()
                                    .await?;

                                if let Some(data) = attachment.data {
                                    let decoded = general_purpose::URL_SAFE.decode(data)?;
                                    let new_name = format!("{}_{}", date_prefix, filename);
                                    let path = Path::new("google_invoices").join(new_name);
                                    tokio::fs::write(&path, decoded).await?;
                                    // println!("Downloaded: {}", path);
                                    println!("Downloaded: {}", path.display());
                                }
                            }
                        }
                    }
                    // Push nested parts to stack
                    if let Some(parts) = current_part.parts {
                        for part in parts {
                            stack.push(part);
                        }
                    }
                }
            }
        }
    } else {
        println!("No matching invoices found.");
    }

    Ok(())
}

async fn create_auth(who: &str) -> Authenticator<HttpsConnector<HttpConnector>> {
    let credentials_json = std::fs::read_to_string("credentials.json").unwrap();
    let key = parse_service_account_key(credentials_json.as_str())
        .unwrap();
    ServiceAccountAuthenticator::builder(key)
        .subject(who)
        .build()
        .await
        .unwrap()
}


fn parse_service_account_key(json: &str) -> std::io::Result<ServiceAccountKey> {
    serde_json::from_str(json).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Bad service account key: {}", e),
        )
    })
}
