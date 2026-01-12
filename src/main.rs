use serenity::{
    async_trait,
    model::{channel::Message, gateway::Ready},
    prelude::*,
};

use regex::Regex;
use reqwest::Client as HttpClient;
use serde_json::Value;
use url::Url;

struct Handler;

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _: Context, ready: Ready) {
        println!("🛡️ SecureIV conectado como {}", ready.user.name);
    }

    async fn message(&self, ctx: Context, msg: Message) {
        if msg.author.bot {
            return;
        }

        let re = Regex::new(r"https?://\S+").unwrap();
        let http_client = HttpClient::new();

        for m in re.find_iter(&msg.content) {
            let link = m.as_str();

            let result = scan_link(&http_client, link).await;

            let response = match result.score {
                0..=29 => format!(" `{}`\n **Seguro**", link),

                30..=59 => format!(
                    " `{}`\n **Sospechoso**\n• {}",
                    link,
                    result.reasons.join("\n• ")
                ),

                _ => {
                    let _ = msg.delete(&ctx.http).await;
                    format!(
                        " **LINK MALICIOSO BLOQUEADO**\n• {}\nScore: {}",
                        result.reasons.join("\n• "),
                        result.score
                    )
                }
            };

            let _ = msg.channel_id.say(&ctx.http, response).await;
        }
    }
}

#[derive(Default)]
struct ScanResult {
    score: u8,
    reasons: Vec<String>,
}

async fn scan_link(client: &HttpClient, link: &str) -> ScanResult {
    let mut result = ScanResult::default();

    let url = match Url::parse(link) {
        Ok(u) => u,
        Err(_) => {
            result.score = 80;
            result.reasons.push("URL malformada".into());
            return result;
        }
    };

    heuristic_scan(&url, &mut result);

    result.score += scan_virustotal(client, link).await;

    result.score = result.score.min(100);
    result
}

fn heuristic_scan(url: &Url, result: &mut ScanResult) {
    let host = url.host_str().unwrap_or("");

    if url.scheme() != "https" {
        result.score += 20;
        result.reasons.push("No usa HTTPS".into());
    }

    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        result.score += 30;
        result.reasons.push("Usa IP directa".into());
    }

    let bad_words = ["free", "gift", "login", "verify", "bonus", "crypto"];
    if bad_words.iter().any(|w| host.contains(w)) {
        result.score += 25;
        result.reasons.push("Dominio con palabras sospechosas".into());
    }

    let bad_tlds = [".ru", ".tk", ".zip", ".top"];
    if bad_tlds.iter().any(|t| host.ends_with(t)) {
        result.score += 20;
        result.reasons.push("TLD sospechoso".into());
    }
}

async fn scan_virustotal(client: &HttpClient, url: &str) -> u8 {
    let key = match std::env::var("VT_API_KEY") {
        Ok(k) => k,
        Err(_) => return 0,
    };

    // 1️⃣ Enviar URL a VirusTotal
    let submit = client
        .post("https://www.virustotal.com/api/v3/urls")
        .header("x-apikey", &key)
        .form(&[("url", url)])
        .send()
        .await;

    let Ok(submit) = submit else { return 0 };
    let Ok(json) = submit.json::<Value>().await else { return 0 };

    let analysis_id = json["data"]["id"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if analysis_id.is_empty() {
        return 0;
    }

    // 2️⃣ Esperar a que VT analice
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // 3️⃣ Obtener reporte
    let report = client
        .get(format!(
            "https://www.virustotal.com/api/v3/analyses/{}",
            analysis_id
        ))
        .header("x-apikey", key)
        .send()
        .await;

    let Ok(report) = report else { return 0 };
    let Ok(json) = report.json::<Value>().await else { return 0 };

    let stats = &json["data"]["attributes"]["stats"];

    let malicious = stats["malicious"].as_u64().unwrap_or(0);
    let suspicious = stats["suspicious"].as_u64().unwrap_or(0);

    ((malicious * 20) + (suspicious * 10)).min(60) as u8
}

#[tokio::main]
async fn main() {
    let token = std::env::var("DISCORD_TOKEN")
        .expect("Falta DISCORD_TOKEN");

    let intents = GatewayIntents::GUILD_MESSAGES | GatewayIntents::MESSAGE_CONTENT;

    let mut client = serenity::Client::builder(&token, intents)
        .event_handler(Handler)
        .await
        .expect("Error creando el cliente");

    if let Err(e) = client.start().await {
        println!("Error: {:?}", e);
    }
}
