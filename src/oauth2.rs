pub mod oauth2 {
    use serde::{Deserialize, Serialize};
    use sqlx::{MySqlPool};
    use crate::{ServerErrorRejection, main::{ApiError, TokenBody}};

    // Utility
    struct OAuthClient {
        client_id: String,
        client_secret_hash: String,
        redirect_uris: Vec<String>,
        allowed_scopes: Vec<String>,
        name: String,
        logo_uri: String
    }

    async fn fetch_client(client_id: &str, sql_pool: &MySqlPool) -> anyhow::Result<Option<OAuthClient>> {
        let db_client = sqlx::query!(r#"
            SELECT * FROM oauth2_apps WHERE client_id=?
        "#, client_id).fetch_optional(sql_pool).await?;
        Ok(db_client.map(|db_client| OAuthClient {
            client_id: client_id.to_owned(),
            client_secret_hash: db_client.client_secret_hash,
            name: db_client.name,
            logo_uri: db_client.logo_uri,
            allowed_scopes: db_client.allowed_scopes.split(" ").map(|scope| scope.to_owned()).collect(),
            redirect_uris: db_client.redirect_uris.split(",").map(|scope| scope.to_owned()).collect()
        }))
    }

    // Req / Res

    #[derive(Deserialize)]
    pub struct ValidateClient {
        client_id: String,
        redirect_uri: String,
        scopes: String
    }

    #[derive(Serialize)]
    pub struct ValidatedClientInfo {
        name: String,
        logo_uri: String
    }

    pub async fn validate_client(validate_client_req: ValidateClient, sql_pool: &MySqlPool) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
        match fetch_client(&validate_client_req.client_id, sql_pool).await {
            Ok(client) => {
                if let Some(client) = client {
                    if !client.redirect_uris.contains(&validate_client_req.redirect_uri) {
                        Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("bad redirect_uri")), warp::http::StatusCode::BAD_REQUEST))
                    } else {
                        let mut has_bad_scope = false;
                        for scope in validate_client_req.scopes.split(" ") {
                            if !client.allowed_scopes.contains(&scope.to_owned()) {
                                has_bad_scope = true;
                            }
                        }
                        if has_bad_scope {
                            Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid scope(s)")), warp::http::StatusCode::BAD_REQUEST))
                        } else {
                            Ok(warp::reply::with_status(warp::reply::json(&ValidatedClientInfo {name: client.name, logo_uri: client.logo_uri}), warp::http::StatusCode::OK))
                        }
                    }
                } else {
                    Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid client_id")), warp::http::StatusCode::BAD_REQUEST))
                }
            }
            Err(err) => {
                eprintln!("Error occured {}", err);
                Err(warp::reject::custom(ServerErrorRejection {}))
            }
        }
    }
}