mod chat;
mod file;
mod user;
mod workspace;

pub use chat::CreateChat;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
pub use user::{CreateUser, SigninUser};

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq)]
pub struct User {
    pub id: i64,
    pub ws_id: i64,
    pub fullname: String,
    pub email: String,
    #[sqlx(default)]
    #[serde(skip)]
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq)]
pub struct ChatUser {
    pub id: i64,
    pub fullname: String,
    pub email: String,
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq)]
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
            fullname: fullname.to_string(),
            email: email.to_string(),
            password_hash: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, FromRow, Clone, PartialEq)]
pub struct Chat {
    pub id: i64,
    pub name: Option<String>,
    pub r#type: ChatType,
    pub members: Vec<i64>,
    pub ws_id: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, sqlx::Type, Deserialize, Serialize)]
#[sqlx(type_name = "chat_type", rename_all = "snake_case")]
pub enum ChatType {
    Single,
    Group,
    PrivateChannel,
    PublicChannel,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChatFile {
    pub ext: String, // extract ext from filename or use mime type
    pub hash: String,
}
