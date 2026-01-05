mod gmail_utils;

use gmail_utils::{GmailConfig, list_and_download};
use std::env;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Configuration from args/env
    // Example: SENDER="alerts@example.com" SUBJECT="Invoice"
    let creds = env::var("GOOGLE_SERVICE_ACCOUNT_JSON").unwrap_or("service_account.json".to_string());
    let sender = env::var("SENDER").unwrap_or("payments-noreply@google.com".to_string());
    let subject = env::var("SUBJECT").unwrap_or("Google Workspace".to_string());

    let config = GmailConfig {
        service_account_json: creds,
        impersonate_user: env::var("IMPERSONATE_USER").unwrap_or("petr.kozelka@origis.cz".to_string()),
        sender,
        subject,
    };

    list_and_download(config).await
}
