use std::net::SocketAddr;

use anyhow::Result;
use chat_core::{Chat, ChatType, Message};
use futures::StreamExt;
use reqwest::{
    multipart::{Form, Part},
    StatusCode,
};
use reqwest_eventsource::{Event, EventSource};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

const WILD_ADDR: &str = "0.0.0.0:0";

#[derive(Debug, Deserialize)]
struct AuthToken {
    token: String,
}

struct ChatServer {
    addr: SocketAddr,
    token: String,
    client: reqwest::Client,
}

struct NotifyServer;

#[tokio::test]
async fn chat_server_should_work() -> Result<()> {
    let (tdb, state) = chat_server::AppState::new_for_test().await?;
    let chat_server = ChatServer::new(state).await?;
    let db_url = tdb.url();
    NotifyServer::new(&db_url, &chat_server.token).await?;
    let _chat = chat_server.create_chat().await?;
    let _msg = chat_server.create_message(1).await?;

    Ok(())
}

impl NotifyServer {
    async fn new(db_url: &str, token: &str) -> Result<Self> {
        let mut config = notify_server::AppConfig::load()?;
        config.server.db_url = db_url.to_string();
        let app = notify_server::get_router(config).await?;
        let listener = TcpListener::bind(WILD_ADDR).await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let mut es = EventSource::get(format!("http://{}/events?token={}", addr, token));

        tokio::spawn(async move {
            while let Some(event) = es.next().await {
                match event {
                    Ok(Event::Open) => println!("connected"),
                    Ok(Event::Message(msg)) => match msg.event.as_ref() {
                        "NewChat" => {
                            println!("NewChat: {:?}", msg.data);
                            let chat: chat_core::Chat = serde_json::from_str(&msg.data).unwrap();
                            assert_eq!(chat.name.as_ref().unwrap(), "test");
                            assert_eq!(chat.members, vec![1, 2]);
                            assert_eq!(chat.r#type, chat_core::ChatType::PrivateChannel);
                        }
                        "NewMessage" => {
                            let message: chat_core::Message =
                                serde_json::from_str(&msg.data).unwrap();
                            assert_eq!(message.content, "hello");
                            assert_eq!(message.chat_id, 1);
                        }
                        _ => {}
                    },
                    Err(err) => {
                        println!("error: {:?}", err);
                        es.close();
                    }
                }
            }
        });

        Ok(NotifyServer)
    }
}

impl ChatServer {
    async fn new(state: chat_server::AppState) -> Result<Self> {
        let app = chat_server::get_router(state).await?;
        let listener = TcpListener::bind(WILD_ADDR).await?;
        let addr = listener.local_addr()?;

        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let mut ret = Self {
            addr,
            token: "".to_string(),
            client: reqwest::Client::new(),
        };
        ret.token = ret.signin().await?;

        Ok(ret)
    }

    async fn signin(&self) -> Result<String> {
        let res = self
            .client
            .post(&format!("http://{}/api/signin", self.addr))
            .header("Content-Type", "application/json")
            .body(r#"{"email":"tchen@acme.org","password":"123456"}"#)
            .send()
            .await?;
        assert_eq!(res.status(), 200);
        let ret: AuthToken = res.json().await?;
        Ok(ret.token)
    }

    async fn create_chat(&self) -> Result<Chat> {
        let res = self
            .client
            .post(&format!("http://{}/api/chats", self.addr))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .body(
                r#"{
                    "name": "test",
                    "members": [1, 2],
                    "public": false
                }"#,
            )
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::CREATED);
        let chat: Chat = res.json().await?;
        assert_eq!(chat.name.as_ref().unwrap(), "test");
        assert_eq!(chat.members, vec![1, 2]);
        assert_eq!(chat.r#type, ChatType::PrivateChannel);
        Ok(chat)
    }

    async fn create_message(&self, chat_id: u64) -> Result<Message> {
        let data = include_bytes!("../Cargo.toml");
        let files = Part::bytes(data)
            .file_name("Cargo.toml")
            .mime_str("text/plain")?;
        let form = Form::new().part("file", files);

        let res = self
            .client
            .post(&format!("http://{}/api/upload", self.addr))
            .header("Authorization", format!("Bearer {}", self.token))
            .multipart(form)
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let ret: Vec<String> = res.json().await?;

        let body = serde_json::to_string(&json!({
            "content": "hello",
                "files": ret,
        }))?;
        let res = self
            .client
            .post(&format!("http://{}/api/chats/{}", self.addr, chat_id))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;
        assert_eq!(res.status(), StatusCode::CREATED);
        let message: Message = res.json().await?;
        assert_eq!(message.content, "hello");
        assert_eq!(message.chat_id, chat_id as i64);
        assert_eq!(message.files, ret);
        Ok(message)
    }
}
