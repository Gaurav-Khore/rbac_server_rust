use std::time::Duration;

use actix_web::{http, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use api::graphql_api::graphql_handler;
use async_graphql::{
    Context, EmptyMutation, EmptySubscription, Error, ErrorExtensions, Object, Schema,
};
use async_graphql_actix_web::{GraphQL, GraphQLRequest, GraphQLResponse};
use clap::{Arg, Command};
use db::{db_config::init_db, users::check_user_info};
use graphql::{mutations::Mutation, queries::Query};
use hmac::{Hmac, Mac};
use postgres::Client;
use serde::Deserialize;
use sqlx::{pool::PoolOptions, postgres::PgPoolOptions, PgPool, Pool, Postgres, Row};
use thiserror::Error;
use tokio::sync::Mutex;
use utilities::jwt::create_jwt;
use sha2::Sha256;

// modules imported
pub mod db {
    pub mod db_config;
    pub mod permissions;
    pub mod roles;
    pub mod users;
}
pub mod api {
    pub mod graphql_api;
}
pub mod utilities {
    pub mod auth;
    pub mod jwt;
}
pub mod graphql {
    pub mod mutations;
    pub mod queries;
}

pub struct AppState {
    schema: Mutex<MySchema>,
}

type MySchema = Schema<Query, Mutation, EmptySubscription>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    // command line arguments
    let matches = Command::new("rbac_server").version("0.1.0").arg(
        Arg::new("DB_URL").short('D').long("DB_URL").help("give the postgress database URL: \n postgres://username:password@host \n replace username , password and host")
    ).get_matches();

    let url = matches.get_one::<String>("DB_URL").unwrap().to_string();
    // initialize and connect to the postgres database
    // "postgres://postgres:gaurav@localhost/"
    let db_pool = match PgPoolOptions::new().max_connections(20).connect(&url).await {
        Ok(v) => v,
        Err(e) => {
            panic!("Error on connecting the postgress database = {:?}", e);
        }
    };

    init_db(&db_pool).await;
    // actix web server
    let schema = Schema::build(Query, Mutation, EmptySubscription)
        .data(db_pool.clone())
        .finish();
    let app_state = web::Data::new(AppState {
        schema: Mutex::new(schema.clone()),
    });
    HttpServer::new(move || {
        // cors = Cross Origin Resource Sharing
        let cors = actix_cors::Cors::default()
            .allowed_origin("http://localhost:5173")
            .allowed_methods(vec!["GET", "POST"])
            .allowed_headers(vec![http::header::CONTENT_TYPE , http::header::AUTHORIZATION]);
        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .route("/", web::post().to(graphql_handler))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
