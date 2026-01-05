use gmail1::api::ListMessagesResponse;
use google_gmail1 as gmail1;
use google_gmail1::oauth2::{
    ServiceAccountAuthenticator,
    ServiceAccountKey,
};
use hyper_rustls::HttpsConnectorBuilder;

use google_gmail1::api::{Message, MessagePartHeader};
use std::fs::File;
use std::io::Read;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ===== CONFIG =====
    let service_account_file = "service_account.json";
    let user_to_impersonate = "petr.kozelka@origis.cz";
    let sender = "payments-noreply@google.com";
    let subject = "Google Workspace";
    let max_results = 10;

    // ===== LOAD SERVICE ACCOUNT =====
    let mut key_file = File::open(service_account_file)?;
    let mut key_json = String::new();
    key_file.read_to_string(&mut key_json)?;
    println!("key_json: {}", key_json);
    let service_account_key: ServiceAccountKey = serde_json::from_str(&key_json)?;

    // ===== AUTHENTICATOR =====
    let auth = ServiceAccountAuthenticator::builder(service_account_key)
        .subject(user_to_impersonate.to_string()) // impersonation
        .build()
        .await?;

    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let client = hyper::Client::builder().build::<_, hyper::Body>(connector);

    let hub = gmail1::Gmail::new(client, auth);

    // ===== SEARCH QUERY =====
    let query = format!("from:{} subject:{}", sender, subject);

    // ===== LIST MESSAGES =====
    let call = hub
        .users()
        .messages_list("me")
        .q(&query)
        .max_results(max_results);
    let result: ListMessagesResponse = call
        .doit()
        .await?
        .1;

    if let Some(messages) = result.messages {
        println!("Found {} messages", messages.len());

        for msg in messages {
            println!("-------------");
            if let Some(id) = msg.id {
                let msg: Message = hub
                    .users()
                    .messages_get("me", &id)
                    .format("metadata")
                    .add_metadata_headers("From")
                    .add_metadata_headers("Subject")
                    .add_metadata_headers("Date")
                    .add_scope("https://www.googleapis.com/auth/gmail.readonly")
                    .doit()
                    .await?
                    .1;
                println!("Snippet: {:?}", msg.snippet);
                for MessagePartHeader { name, value } in msg.payload.unwrap().headers.unwrap() {
                    println!("* {:?} = {:?}",  name, value);
                }
            }
        }
    } else {
        println!("No messages found");
    }

    Ok(())
}
