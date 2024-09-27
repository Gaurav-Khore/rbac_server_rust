use std::sync::Mutex;

use actix_web::{HttpRequest, HttpResponse};
use async_graphql::{Error, ErrorExtensions};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

const JWT_SECRET: &[u8] = b"rbac_secret";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub role: Vec<String>,
    pub exp: usize,
}

pub async fn create_jwt(
    uid: &str,
    role: Vec<String>,
) -> Result<String, jsonwebtoken::errors::Error> {
    println!("Hello from the create_jwt ");

    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(15))
        .expect("Valid Timestamp")
        .timestamp();
    println!("Expiration = {:?}", expiration);
    let claims = Claims {
        sub: uid.to_string(),
        role: role,
        exp: expiration as usize,
    };

    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
}

pub fn extract_jwt(req: Mutex<HttpRequest>) -> Option<String> {
    if let Some(auth_header) = req.lock().unwrap().headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer") {
                let token = auth_str.trim_start_matches("Bearer ");
                return Some(token.to_string());
            }
        }
    }
    None
    // Err(Error::new("Invalid Authorization").extend_with(|_,x| x.set("details","Missing Authorization")))
    // Err(HttpResponse::Unauthorized().body("Missing or Invalid Authorization"))
}

pub fn decode_jwt(token: String) -> async_graphql::Result<Claims> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    match decode::<Claims>(&token, &DecodingKey::from_secret(JWT_SECRET), &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(e) => Err(Error::new("Invalid Authorization")
            .extend_with(|_, x| x.set("details", "Invalid Authorization"))),
    }
}
