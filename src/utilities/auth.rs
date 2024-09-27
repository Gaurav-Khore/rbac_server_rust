use async_graphql::ErrorExtensions;
use sqlx::{Pool, Postgres};

use crate::{
    db::roles::fetch_role_permission,
    utilities::jwt::{decode_jwt, Claims},
};

#[derive(Debug)]
pub struct AuthPerm {
    pub sub: String,
    pub role: Vec<String>,
    pub perm: Vec<String>,
}
pub async fn authorize(
    pool: &Pool<Postgres>,
    token: Option<String>,
) -> async_graphql::Result<AuthPerm> {
    if token.is_none() {
        return Err(async_graphql::Error::new("Token Not Found")
            .extend_with(|_, e| e.set("details", "Token is required.")));
    }
    let token = token.unwrap();
    let claim: Claims = match decode_jwt(token) {
        Ok(v) => v,
        Err(e) => {
            return Err(e);
        }
    };
    let vec_perm = match fetch_role_permission(pool, claim.role.clone()).await {
        Ok(v) => v,
        Err(e) => {
            println!("Error add_role:- {:?}", e);
            return Err(e);
        }
    };

    Ok(AuthPerm {
        sub: claim.sub,
        role: claim.role,
        perm: vec_perm,
    })
}
