use std::sync::{Arc, Mutex};

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, Responder, ResponseError};
use async_graphql::Response;
use async_graphql_actix_web::{GraphQLRequest, GraphQLResponse};

use crate::{utilities::jwt::extract_jwt, AppState};

pub async fn graphql_handler(
    data: web::Data<AppState>,
    http_req: HttpRequest,
    req: GraphQLRequest,
) -> GraphQLResponse{
    let schema = data.schema.lock().await;

    // let header = http_req.headers().get("Authorization").unwrap().clone();
    let http_req = Mutex::new(http_req);
    let token = extract_jwt(http_req);
    let ctx = req.into_inner().data(token);
    schema.execute(ctx).await.into()
}
