pub mod middlewares;
pub mod utils;

pub use utils::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: i64,
    pub ws_id: i64,
    #[sqlx(default)]
    pub ws_name: String,
    pub fullname: String,
    pub email: String,
    #[sqlx(default)]
    #[serde(skip)]
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatUser {
    pub id: i64,
    pub fullname: String,
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: i64,
    pub name: String,
    pub owner_id: i64,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
impl User {
    pub fn new(id: i64, fullname: &str, email: &str) -> Self {
        Self {
            id,
            ws_id: 0,
            ws_name: "".to_string(),
            fullname: fullname.to_string(),
            email: email.to_string(),
            password_hash: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq, ToSchema)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Chat {
    pub id: i64,
    pub name: Option<String>,
    pub r#type: ChatType,
    pub members: Vec<i64>,
    #[serde(alias = "wsId")]
    pub ws_id: i64,
    #[serde(alias = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, sqlx::Type, Deserialize, Serialize, ToSchema)]
#[sqlx(type_name = "chat_type", rename_all = "snake_case")]
#[serde(rename_all = "camelCase")]
pub enum ChatType {
    #[serde(alias = "single")]
    Single,
    #[serde(alias = "group")]
    Group,
    #[serde(alias = "private_channel")]
    PrivateChannel,
    #[serde(alias = "public_channel")]
    PublicChannel,
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq, ToSchema)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Message {
    pub id: i64,
    #[serde(alias = "chatId")]
    pub chat_id: i64,
    #[serde(alias = "senderId")]
    pub sender_id: i64,
    pub content: String,
    pub files: Vec<String>,
    #[serde(alias = "createdAt")]
    pub created_at: DateTime<Utc>,
}
