pub mod settings {
    use std::env;
    use serde::{Deserialize, Serialize};
    use sqlx::{MySqlConnection, MySqlPool};
    use crate::main::{ApiError, TokenBody};

    // Req / Res

    // Update Setting Req - PUT
    #[derive(Deserialize)]
    pub struct UpdateSettingReq {
        pub name: String,
        pub value: String
    }
    // Get Setting Res - GET
    #[derive(Serialize)]
    struct SettingRes {
        value: String
    }

    // Utility

    pub async fn delete_user_settings(user_id: u64, conn: &mut MySqlConnection) -> Result<(), sqlx::Error> {
        let _res = sqlx::query!(r#"
            DELETE FROM settings WHERE user_id = ?
        "#, user_id).execute(conn).await?;
        Ok(())
    }

    // Routes

    pub async fn update_setting(user: TokenBody, update_setting_req: UpdateSettingReq, sql_pool: &MySqlPool) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
        // A setting name > 30 characters would be rejected later on as it wouldn't be a part of the server's .env configuration, but just in-case here's a check for it
        if update_setting_req.name.len() > 30 {
            return Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("setting names must be < 30 characters")), warp::http::StatusCode::BAD_REQUEST)));
        }
        if update_setting_req.value.len() > 30 {
            return Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("setting values must be < 30 characters")), warp::http::StatusCode::BAD_REQUEST)));
        }
        if let Ok(allowed_settings) = env::var("ALLOWED_SETTINGS") {
            if allowed_settings.split(",").find(|&setting| setting == update_setting_req.name).is_some() {
                match user.sub.parse::<u64>() {
                    Ok(user_id) => {
                        if let Ok(res) = sqlx::query!(r#"
                            INSERT INTO settings(user_id, name, value) VALUES (?, ?, ?)
                            ON DUPLICATE KEY UPDATE value=?
                        "#, user_id, update_setting_req.name, update_setting_req.value, update_setting_req.value).execute(sql_pool).await {
                            if res.rows_affected() == 1 {
                                // setting was created
                                let hostname = match env::var("HOSTNAME") {
                                    Ok(hostname) => hostname,
                                    Err(_e) => "localhost".to_owned()
                                };
                                Ok(Box::new(warp::reply::with_status(warp::reply::with_header(warp::reply(), "location", hostname + "/settings/" + &update_setting_req.name), warp::http::StatusCode::CREATED)))
                            } else {
                                // Setting was updated or left untouched
                                Ok(Box::new(warp::reply::with_status(warp::reply(), warp::http::StatusCode::NO_CONTENT)))
                            }
                        } else {
                            eprintln!("Failed to update setting!");
                            Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR)))
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to parse user id! {:?}", e);
                        Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR)))
                    }
                }
            } else {
                Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid setting")), warp::http::StatusCode::BAD_REQUEST)))
            }
        } else {
            Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid setting")), warp::http::StatusCode::BAD_REQUEST)))
        }
    }

    pub async fn get_setting(name: String, user: TokenBody, sql_pool: &MySqlPool) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
        match user.sub.parse::<u64>() {
            Ok(user_id) => {
                match sqlx::query!(r#"
                    SELECT value FROM settings WHERE user_id=? AND name=?
                "#, user_id, name).fetch_one(sql_pool).await {
                    Ok(setting) =>  {
                        Ok(warp::reply::with_status(warp::reply::json(&SettingRes {value: setting.value}), warp::http::StatusCode::OK))
                    }
                    Err(e) => {
                        if let sqlx::Error::RowNotFound = e {
                            Err(warp::reject::not_found())
                        } else {
                            eprintln!("Failed to get setting! {:?}", e);
                            Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to parse user id! {:?}", e);
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
            }
        }
    }
}