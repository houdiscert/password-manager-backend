// This is the houdiscert Password Manager API.

use std::{env, error::Error, pin::Pin, sync::Arc, time::{Duration, SystemTime}};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng}};
use base64::{prelude::{BASE64_URL_SAFE_NO_PAD, BASE64_STANDARD}, Engine};
use dotenvy::dotenv;
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use snowflaked::sync::Generator;
use sqlx::MySqlPool;
use warp::{Filter, filters::body::BodyDeserializeError, reject::{InvalidHeader, MethodNotAllowed, MissingHeader, PayloadTooLarge, Rejection}};

use crate::{main::{ApiError, TokenBody}, settings::settings::{delete_user_settings, get_setting, update_setting}};

mod settings;

const MIN_PASSWORD_LEN: usize = 12;

//#[derive(Debug)]
//struct NotJsonRejection;

//impl warp::reject::Reject for NotJsonRejection {}

/// Parse a JSON payload from the request body.
/*fn json_payload() -> impl Filter<Extract = (json::JsonValue,), Error = Rejection> + Copy {
    warp::body::bytes().and_then(|bytes: bytes::Bytes| async move {
        let body_str: String = String::from_utf8(bytes.to_vec()).unwrap_or(String::new());
        return match json::parse(body_str.as_str()) {
            Ok(json_obj) => Ok(json_obj),
            Err(_e) => Err(warp::reject::custom(NotJsonRejection))
        }
    })
}*/

#[derive(Debug)]
struct NoAuthRejection;
impl warp::reject::Reject for NoAuthRejection {}

#[derive(Deserialize)]
struct JWTHeader {
    alg: String,
    typ: String
}

// Handling auth

/// Extracts an Authorization Bearer token from the request's Authorization header, and returns the JWT payload, rejecting on invalid/missing tokens.
fn auth(pool: &MySqlPool) -> impl Filter<Extract = (TokenBody,), Error = Rejection> + Clone {
    warp::header::<String>("Authorization").and(warp::any().map(move || pool)).and_then(async |auth_jwt: String, pool: &MySqlPool| {
        if auth_jwt.starts_with("Bearer ") {
            let auth_jwt = auth_jwt.replacen("Bearer ", "", 1);
            let jwt_parts: Vec<&str> = auth_jwt.splitn(3, '.').collect();
            if jwt_parts.len() == 3 {
                let header = BASE64_URL_SAFE_NO_PAD.decode(jwt_parts[0]).map_err(|_err| NoAuthRejection)?;
                if let Ok(header) = serde_json::from_str::<JWTHeader>(str::from_utf8(&header).map_err(|_err| NoAuthRejection)?) {
                    if header.alg == "HS256" && header.typ == "JWT" {
                        let jwt_unsigned = jwt_parts[0].to_owned() + "." + jwt_parts[1];
                        // Test if signing the unsigned jwt makes it match the signed jwt
                        let key_base_64 = BASE64_STANDARD.decode(env::var("JWT_KEY").map_err(|_err| NoAuthRejection)?).map_err(|_err| NoAuthRejection)?;
                        let mut mac = HmacSha256::new_from_slice(&key_base_64).map_err(|_err| NoAuthRejection)?;
                        mac.update(jwt_unsigned.as_bytes());
                        let sig_bytes = BASE64_URL_SAFE_NO_PAD.decode(jwt_parts[2]).map_err(|_err| NoAuthRejection)?;
                        if mac.verify_slice(&sig_bytes).is_ok() {
                            // JWT is valid, now decode the payload
                            let decoded_payload = BASE64_URL_SAFE_NO_PAD.decode(jwt_parts[1]).map_err(|_err| NoAuthRejection)?;
                            if let Ok(payload) = serde_json::from_str::<TokenBody>(str::from_utf8(&decoded_payload).map_err(|_err| NoAuthRejection)?) {
                                // test vid
                                if let Ok(user_id) = payload.sub.parse::<u64>() {
                                    if let Ok(vid_truth) = sqlx::query_scalar!(r#"
                                        SELECT validation_id FROM users WHERE id = ?
                                    "#, user_id).fetch_one(pool).await {
                                        if let Ok(vid_provided) = payload.vid.parse::<u64>() {
                                            if vid_truth.cast_unsigned() == vid_provided {
                                                // finally, test exp
                                                let exp = SystemTime::UNIX_EPOCH + Duration::from_secs(payload.exp);
                                                if exp.duration_since(SystemTime::now()).is_ok() {
                                                    // Token is valid
                                                    return Ok(payload);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Failed to verify authorization so reject it
        Err(warp::reject::custom(NoAuthRejection))
    })
}

// Logging in - token generation
pub mod main {
    use serde::{Deserialize, Serialize};

    /// An API error is an error from the Houdiscert Password Manager API. {"error": "msg"}. The format is specifically designed to be the same as the Houdiscert API's error format, seeing as Houdiscert Password Manager is a part of houdiscert. If an error is defined its text should be assumed to be API as the frontend may rely on specific text values
    #[derive(Serialize)]
    pub struct ApiError {
        pub error: String
    }

    impl ApiError {
        pub fn new(error: String) -> ApiError {
            return ApiError { error }
        }
        // Convenience fn to make an ApiError from a string literal.
        pub fn from_str(error: &str) -> ApiError {
            return ApiError::new(error.to_owned())
        }
    }

    #[derive(Deserialize, Serialize)]
    pub struct TokenBody {
        pub iat: u64,
        pub exp: u64,
        pub sub: String,
        pub vid: String
    }
}
type HmacSha256 = Hmac<Sha256>;
async fn make_new_token(user_id: u64, validation_id: u64, token_exp: Option<u64>) -> Result<String, Box<dyn Error>> {
    // Generate a Token (JWT)
    const HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;
    let iat = SystemTime::UNIX_EPOCH.elapsed()?;
    let exp = iat + Duration::from_hours(1);
    let exp = if let Some(provided_exp) = token_exp {
        provided_exp
    } else {
        exp.as_secs()
    };
    let uid = user_id.to_string();
    let validation_id = validation_id.to_string();
    let body = serde_json::to_string(&TokenBody { iat: iat.as_secs(), exp: exp, sub: uid, vid: validation_id })?;
    let jwt_unsigned = BASE64_URL_SAFE_NO_PAD.encode(String::from(HEADER).as_bytes()) + "." + &BASE64_URL_SAFE_NO_PAD.encode(body.as_bytes());
    let key_base_64 = BASE64_STANDARD.decode(env::var("JWT_KEY")?)?;
    let mut mac = HmacSha256::new_from_slice(&key_base_64)?;
    mac.update(jwt_unsigned.as_bytes());
    let sig_bytes = mac.finalize().into_bytes();
    Ok(jwt_unsigned + "." + &BASE64_URL_SAFE_NO_PAD.encode(sig_bytes))
}
async fn login_user(user_id: i64, validation_id: i64, email: String, name: String) -> Result<warp::reply::WithStatus<warp::reply::Json>, Box<dyn Error>> {
    // Generate a Token (JWT)
    let final_jwt = make_new_token(user_id.cast_unsigned(), validation_id.cast_unsigned(), Option::None).await?;
    let login_res = LoginResponse { email, name, token: final_jwt };
    // Return the new token
    Ok(warp::reply::with_status(warp::reply::json(&login_res), warp::http::StatusCode::OK))
}

// Route Data (structs containing req/res payloads for certain routes)
// Login POST - req
#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String
}
#[derive(Serialize)]
// Login POST - res
struct LoginResponse {
    email: String,
    name: String,
    token: String
}

// Signup POST - req
#[derive(Deserialize)]
struct SignupReq {
    email: String,
    name: String,
    password: String
}

// Add Data POST - req
#[derive(Deserialize)]
struct AddDataReq {
    r#type: String,
    name: String,
    content: String
}
#[derive(Serialize)]
struct DataRes {
    id: String,
    r#type: String,
    name: String,
    content: String
}

// Update Data PATCH - req
#[derive(Deserialize)]
struct UpdateDataReq {
    name: String,
    content: String
}

// Invalidate Sessions - res
#[derive(Serialize)]
struct InvalidateSessionsRes {
    token: String
}

impl DataRes {
    fn new(id: String, kind: String, name: String, content: String) -> DataRes {
        DataRes { id: id, r#type: kind, name: name, content: content }
    }
}

#[derive(Serialize)]
struct ListRes<'a> {
    id: String,
    name: &'a str,
    r#type: &'a str
}

// DATABASE STRUCTURE

/// Sets up the database tables 
async fn setup_db(sql_pool: &sqlx::MySqlPool) -> Result<(), sqlx::Error> {
    // 1. Create the users table:
    sqlx::query!(r#"
        CREATE TABLE IF NOT EXISTS users(
         id BIGINT PRIMARY KEY,
         email VARCHAR(254) NOT NULL,
         name VARCHAR(100) NOT NULL,
         password VARCHAR(100) NOT NULL,
         validation_id BIGINT NOT NULL
        );
    "#).execute(sql_pool).await?;
    // 2. Create the data table
    sqlx::query!(r#"
        CREATE TABLE IF NOT EXISTS user_data(
         user_id BIGINT NOT NULL,
         id BIGINT NOT NULL,
         type TEXT NOT NULL,
         name VARCHAR(30) NOT NULL,
         content TEXT NOT NULL,
         PRIMARY KEY(user_id, id)
        );
    "#).execute(sql_pool).await?;
    // 3. Make the settings table
    sqlx::query!(r#"
        CREATE TABLE IF NOT EXISTS settings(
         user_id BIGINT NOT NULL,
         name VARCHAR(30) NOT NULL,
         value VARCHAR(30) NOT NULL,
         PRIMARY KEY(user_id, name)
        );
    "#).execute(sql_pool).await?;
    Ok(())
}

#[derive(Debug)]
struct DataAddRej {}
impl warp::reject::Reject for DataAddRej {}

/// A rejection which ends up being unhandled until the main server route recover() and thus is equivalent to a 500 server error
#[derive(Debug)]
struct ServerErrorRejection {}
impl warp::reject::Reject for ServerErrorRejection {}

// Data Routes
async fn add_data(user: TokenBody, add_data_req: AddDataReq, sql_pool: &MySqlPool, snowflake: &Generator) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    if add_data_req.name.len() > 30 {
        return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("'name' must be 30 characters or less")), warp::http::StatusCode::BAD_REQUEST));
    }
    if let Ok(allowed_data) = env::var("ALLOWED_DATA") {
        if allowed_data.split(",").find(|&r#type| r#type == add_data_req.r#type).is_none() {
            return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid data type")), warp::http::StatusCode::BAD_REQUEST));
        }
    }
    // Restrict names of the "setting" data type
    if add_data_req.r#type == "setting" {
        if let Ok(allowed_settings) = env::var("ALLOWED_SETTINGS") {
            if allowed_settings.split(",").find(|&setting| setting == add_data_req.name).is_none() {
                return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid setting")), warp::http::StatusCode::BAD_REQUEST));
            }
        }
    }
    let id = snowflake.generate::<u64>();
    match user.sub.parse::<u64>() {
        Ok(user_id) => {
            sqlx::query!(r#"
                INSERT INTO user_data(user_id, id, type, name, content) VALUES (?, ?, ?, ?, ?);
            "#, user_id, id, add_data_req.r#type, add_data_req.name, add_data_req.content).execute(sql_pool).await
                .map(|_res| warp::reply::with_status(warp::reply::json(&DataRes::new(id.to_string(), add_data_req.r#type, add_data_req.name, add_data_req.content)), warp::http::StatusCode::OK)).map_err(|_e| warp::reject::custom(DataAddRej {}))
        }
        Err(e) => {
            eprintln!("Failed to parse user id! {:?}", e);
            Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}
async fn get_data(data_id: u64, user: TokenBody, sql_pool: &MySqlPool) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    match user.sub.parse::<u64>() {
        Ok(user_id) => {
            if let Ok(data) = sqlx::query!(r#"
                SELECT type,name,content FROM user_data WHERE user_id = ? AND id = ?;
            "#, user_id, data_id).fetch_one(sql_pool).await {
                return Ok(warp::reply::with_status(warp::reply::json(&DataRes::new(data_id.to_string(), data.r#type, data.name, data.content)), warp::http::StatusCode::OK));
            }
        }
        Err(e) => {
            eprintln!("Failed to parse user id! {:?}", e);
            return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR));
        }
    }
    Err(warp::reject::not_found())
}
async fn list_data(user: TokenBody, sql_pool: &MySqlPool) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    match user.sub.parse::<u64>() {
        Ok(user_id) => {
            if let Ok(data) = sqlx::query!(r#"
                SELECT id,type,name FROM user_data WHERE user_id = ?;
            "#, user_id).fetch_all(sql_pool).await {
                return Ok(warp::reply::with_status(warp::reply::json(&data.iter().map(|data| ListRes { id: data.id.cast_unsigned().to_string(), r#type: &data.r#type, name: &data.name }).collect::<Vec<ListRes>>()), warp::http::StatusCode::OK));
            }
        }
        Err(e) => {
            eprintln!("Failed to parse user id! {:?}", e);
            return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR));
        }
    }
    Err(warp::reject::not_found())
}
async fn update_data(data_id: u64, user: TokenBody, update_data_req: UpdateDataReq, sql_pool: &MySqlPool) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    match user.sub.parse::<u64>() {
        Ok(user_id) => {
            if let Ok(data) = sqlx::query!(r#"
                SELECT type,content FROM user_data WHERE user_id = ? AND id = ?;
            "#, user_id, data_id).fetch_one(sql_pool).await {
                return sqlx::query!(r#"
                    UPDATE user_data SET content = ?, name = ? WHERE user_id = ? AND id = ?;
                "#, update_data_req.content, update_data_req.name, user_id, data_id).execute(sql_pool).await
                    .map(|_res| warp::reply::with_status(warp::reply::json(&DataRes::new(data_id.to_string(), data.r#type, update_data_req.name, update_data_req.content)), warp::http::StatusCode::OK)).map_err(|_e| warp::reject::custom(DataAddRej {}))
            }
        }
        Err(e) => {
            eprintln!("Failed to parse user id! {:?}", e);
            return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR));
        }
    }
    Err(warp::reject::not_found())
}
async fn delete_data(data_id: u64, user: TokenBody, sql_pool: &MySqlPool) -> Result<Box<dyn warp::Reply>, warp::Rejection> {
    match user.sub.parse::<u64>() {
        Ok(user_id) => {
            if sqlx::query!(r#"
                DELETE FROM user_data WHERE user_id = ? AND id = ?;
            "#, user_id, data_id).execute(sql_pool).await.is_ok() {
                return Ok(Box::new(warp::reply::with_status(warp::reply(), warp::http::StatusCode::NO_CONTENT)));
            }
        }
        Err(e) => {
            eprintln!("Failed to parse user id! {:?}", e);
            return Ok(Box::new(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR)));
        }
    }
    Err(warp::reject::not_found())
}
async fn invalidate_sessions(user: TokenBody, sql_pool: &MySqlPool, snowflake: &Generator) -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
    // Assign a new validation id to the user, causing any previously-generated JWT tokens to be invalid in auth()
    let validation_id: u64 = snowflake.generate();
    match user.sub.parse::<u64>() {
        Ok(user_id) => {
            match sqlx::query!(r#"
                UPDATE users SET validation_id = ? WHERE id = ?
            "#, validation_id, user_id).execute(sql_pool).await {
                Ok(_res) => {
                    Ok(warp::reply::with_status(warp::reply::json(&InvalidateSessionsRes {token: make_new_token(user_id, validation_id, Option::Some(user.exp)).await.map_err(|e| {
                        eprintln!("Failed to generate success response for token invalidation! {:?}", e);
                        warp::reject::custom(ServerErrorRejection {})
                    })?}), warp::http::StatusCode::OK))
                }
                Err(e) => {
                    eprintln!("Failed to reset user validation id! {:?}", e);
                    Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to parse user id! {:?}", e);
            Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}
async fn delete_account(user: TokenBody, sql_pool: &MySqlPool) -> Result<warp::http::StatusCode, warp::Rejection> {
    if let Ok(user_id) = user.sub.parse::<u64>() {
        // Delete the user's account, data, and settings
        // Transaction to ensure each deletion is completed 
        match sql_pool.begin().await {
            Ok(mut transaction) => {
                // 1. Delete the user
                if let Ok(result) = sqlx::query!(r#"
                    DELETE FROM users WHERE id = ? LIMIT 1
                "#, user_id).execute(&mut *transaction).await && result.rows_affected() != 1 {
                    eprintln!("Failed to delete a user {}", user.sub);
                    if let Err(e) = transaction.rollback().await {
                        eprintln!("Failed rollback! {:?}", e);
                    }
                    Err(warp::reject::custom(ServerErrorRejection {}))
                } else {
                    // 2. Delete data
                    if sqlx::query!(r#"
                        DELETE FROM user_data WHERE user_id = ?
                    "#, user_id).execute(&mut *transaction).await.is_err() {
                        eprintln!("Failed to delete user data of {}", user.sub);
                        if let Err(e) = transaction.rollback().await {
                            eprintln!("Failed rollback! {:?}", e);
                        }
                        Err(warp::reject::custom(ServerErrorRejection {}))
                    } else {
                        // 3. Delete settings
                        if delete_user_settings(user_id, &mut *&mut transaction).await.is_ok() {
                            if transaction.commit().await.is_ok() {
                                Ok(warp::http::StatusCode::NO_CONTENT)
                            } else {
                                eprintln!("failed to commit deletion of user {}", user.sub);
                                Err(warp::reject::custom(ServerErrorRejection {}))
                            }
                        } else {
                            eprintln!("Failed to delete user settings of {}", user.sub);
                            if let Err(e) = transaction.rollback().await {
                                eprintln!("Failed rollback! {:?}", e);
                            }
                            Err(warp::reject::custom(ServerErrorRejection {}))
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to start a transaction: {:?}", e);
                Err(warp::reject::custom(ServerErrorRejection {}))
            }
        }
    } else {
        eprintln!("Failed to parse user id: {}", user.sub);
        Err(warp::reject::custom(ServerErrorRejection {}))
    }
}

/// Returns a rejection recovery function that includes the necessary boilerplate to handle invalid fields/methods/json and a catch-all server error for other issues.
fn handle_api_rejections<'a>(invalid_field_msgs: &'a[(&str, &str)], method_not_allowed: &'a str) -> impl Fn(warp::Rejection) -> Pin<Box<dyn Future<Output=Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection>> + Send + 'a>>  + Clone {
    move |rej: Rejection| {
        Box::pin(async move {
            if let Some(e) = rej.find::<BodyDeserializeError>() {
                if let Some(cause) = e.source() {
                    for (field, msg) in invalid_field_msgs {
                        if cause.to_string().contains(field) {
                            return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str(msg)), warp::http::StatusCode::BAD_REQUEST));
                        }
                    }
                }
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("invalid json")), warp::http::StatusCode::BAD_REQUEST))
            } else if let Some(_e) = rej.find::<PayloadTooLarge>() {
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("request body too large")), warp::http::StatusCode::PAYLOAD_TOO_LARGE))
            } else if let Some(_e) = rej.find::<MethodNotAllowed>() {
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str(method_not_allowed)), warp::http::StatusCode::METHOD_NOT_ALLOWED))
            } else if let Some(_e) = rej.find::<NoAuthRejection>() {
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Unauthorized")), warp::http::StatusCode::UNAUTHORIZED))
            } else if let Some(e) = rej.find::<InvalidHeader>() {
                if e.name() == "authorization" {
                    Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Unauthorized")), warp::http::StatusCode::UNAUTHORIZED))
                } else {
                    Err(rej)
                }
            } else if let Some(e) = rej.find::<MissingHeader>() {
                if e.name() == "authorization" {
                    Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Unauthorized")), warp::http::StatusCode::UNAUTHORIZED))
                } else {
                    Err(rej)
                }
            } else if let Some(_e) = rej.find::<DataAddRej>() {
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Invalid or failed data add request")), warp::http::StatusCode::UNAUTHORIZED))
            } else {
                Err(rej)
            }
        })
    }
}

// Route code

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // .env
    // Variables: DB_URL=mysql://user:password@host/dbname  PORT=4300  JWT_KEY=AbCd=  PROD_ORIGIN=https://pm.houdiscert.com (used for cors on prod, if excluded any origin is allowed for testing localhost)
    dotenv().ok();
    // DB
    let db_url = &env::var("DB_URL")?;
    let sql_pool = sqlx::MySqlPool::connect(db_url).await?; // Connect to db
    setup_db(&sql_pool).await?;
    // Snowflake
    let snowflake: Generator = Generator::builder().epoch(SystemTime::UNIX_EPOCH + Duration::from_millis(1613881813179)).instance(2).build();
    // Email validation
    let email_regex = Regex::new(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$")?;

    let borrowed_pool: &'static MySqlPool = Box::leak(Box::new(sql_pool));
    let borrowed_snowflake: &'static Generator = Box::leak(Box::new(snowflake));
    let borrowed_regex = Arc::new(email_regex);

    // API routes

    // Define route: /login
    /*
        POST

        Body:
        email: string
        password: string
     */
    let login = warp::path!("login")
        .and(warp::post())
        .and(warp::body::content_length_limit(4096))
        .and(warp::body::json())
        .and(warp::any().map(move || borrowed_pool))
        .and_then(async move |login_req: LoginRequest, sql_pool: &MySqlPool| -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
            // Look for a user with the given password
            if let Ok(user) = sqlx::query!(r#"
                SELECT * FROM users WHERE email = ?
            "#, login_req.email).fetch_one(sql_pool).await {
                if let Ok(hash) = PasswordHash::new(&user.password) {
                    return match Argon2::default().verify_password(login_req.password.as_bytes(), &hash) {
                        Ok(()) => Ok(login_user(user.id, user.validation_id, user.email, user.name).await.unwrap_or_else(|err| { eprintln!("Failed to create login token: {}", err); warp::reply::with_status(warp::reply::json(&ApiError::from_str("failed to create login token")), warp::http::StatusCode::INTERNAL_SERVER_ERROR) })),
                        Err(_e) => Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Invalid user or password")), warp::http::StatusCode::BAD_REQUEST))
                    }
                }
            }
            Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Invalid user or password")), warp::http::StatusCode::BAD_REQUEST))
        }).recover(handle_api_rejections(&[("email", "missing or invalid 'email'"), ("password", "missing or invalid 'password'")], "/login requires POST"));
    let create_acc = warp::path!("accounts")
        .and(warp::post())
        .and(warp::body::content_length_limit(4096))
        .and(warp::body::json())
        .and(warp::any().map(move || borrowed_pool))
        .and(warp::any().map(move || borrowed_snowflake))
        .and(warp::any().map(move || borrowed_regex.clone()))
        .and_then(async move |signup_req: SignupReq, sql_pool: &MySqlPool, snowflake: &Generator, email_regex: Arc<Regex>| -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
            // Make sure the user does not already exist
            match sqlx::query_scalar!(r#"
                SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)
            "#, signup_req.email).fetch_one(sql_pool).await {
                Ok(exists) => {
                    if exists > 0 { // mariadb doesn't have booleans
                        return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("User with that email already exists")), warp::http::StatusCode::BAD_REQUEST));
                    }
                },
                Err(e) => {
                    eprintln!("Failed to fetch number of existing users for /accounts POST: {}", e);
                    return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR));
                }
            }
            // Make sure the given email is, in fact, an email
            if !email_regex.is_match(&signup_req.email) {
                return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Invalid email")), warp::http::StatusCode::BAD_REQUEST));
            }
            // Make sure the password meets the minimum length
            if signup_req.password.len() < MIN_PASSWORD_LEN {
                return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Password should be at least 12 characters")), warp::http::StatusCode::BAD_REQUEST));
            }
            if signup_req.password == "V3rySecureP4ssword123" {
                return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("Don't use the example password")), warp::http::StatusCode::BAD_REQUEST));
            }
            // TODO: implement cloudflare email sending for email verification idk
            // Create the user account and log into the user
            let user_id: u64 = snowflake.generate();
            let validation_id: u64 = snowflake.generate();
            let salt = SaltString::generate(&mut OsRng);
            match Argon2::default().hash_password(signup_req.password.as_bytes(), &salt) {
                Ok(password_hash) => {
                    if let Err(e) = sqlx::query!(r#"
                        INSERT INTO users(id, email, name, password, validation_id) VALUES (?, ?, ?, ?, ?)
                    "#, user_id, signup_req.email, signup_req.name, password_hash.to_string(), validation_id).execute(sql_pool).await {
                        eprintln!("Failed to create user: {}", e);
                        return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR));
                    }
                },
                Err(e) => {
                    eprintln!("Failed to hash password: {}", e);
                    return Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR));
                }
            }
            
            Ok(login_user(user_id.cast_signed(), validation_id.cast_signed(), signup_req.email, signup_req.name).await.unwrap_or_else(|err| { eprintln!("Failed to create login token: {}", err); warp::reply::with_status(warp::reply::json(&ApiError::from_str("failed to create login token")), warp::http::StatusCode::INTERNAL_SERVER_ERROR) }))
        }).recover(handle_api_rejections(&[("email", "missing or invalid 'email'"), ("name", "missing or invalid 'name'"), ("password", "missing or invalid 'password'")], "/accounts requires POST"));
        let add_data = warp::path!("data")
            .and(warp::post())
            .and(warp::body::content_length_limit(4096))
            .and(auth(borrowed_pool))
            .and(warp::body::json())
            .and(warp::any().map(move || borrowed_pool))
            .and(warp::any().map(move || borrowed_snowflake))
            .and_then(add_data)
            .recover(handle_api_rejections(&[("kind", "Missing data type 'kind'"), ("content", "Missing 'content'")], "/data requires POST"));
        let get_data = warp::path!("data" / u64)
            .and(warp::get())
            .and(auth(borrowed_pool))
            .and(warp::any().map(move || borrowed_pool))
            .and_then(get_data)
            .recover(handle_api_rejections(&[], "/data/:id requires GET"));
        let update_data = warp::path!("data" / u64 / "update")
            .and(warp::patch())
            .and(warp::body::content_length_limit(4096))
            .and(auth(borrowed_pool))
            .and(warp::body::json())
            .and(warp::any().map(move || borrowed_pool))
            .and_then(update_data)
            .recover(handle_api_rejections(&[("content", "Missing 'content'")], "/data/:id/update requires PATCH"));
        let list_data = warp::path!("listdata")
            .and(warp::get())
            .and(auth(borrowed_pool))
            .and(warp::any().map(move || borrowed_pool))
            .and_then(list_data)
            .recover(handle_api_rejections(&[], "/data requires GET"));
        let delete_data = warp::path!("data" / u64 / "del")
            .and(warp::delete())
            .and(auth(borrowed_pool))
            .and(warp::any().map(move || borrowed_pool))
            .and_then(delete_data)
            .recover(handle_api_rejections(&[], "/data/:id/del requires DELETE"));
        let invalidate_sessions = warp::path!("sessions" / "invalidate")
            .and(warp::delete())
            .and(auth(borrowed_pool))
            .and(warp::any().map(move || borrowed_pool))
            .and(warp::any().map(move || borrowed_snowflake))
            .and_then(invalidate_sessions)
            .recover(handle_api_rejections(&[], "/sessions/invalidate requires DELETE"));
        let update_setting = warp::path!("settings")
            .and(warp::put())
            .and(warp::body::content_length_limit(4096))
            .and(auth(borrowed_pool))
            .and(warp::body::json())
            .and(warp::any().map(move || borrowed_pool))
            .and_then(update_setting)
            .recover(handle_api_rejections(&[("name", "missing 'name'"), ("value", "missing 'value'")], "/settings requires PUT"));
        let get_setting = warp::path!("settings" / String)
            .and(warp::get())
            .and(auth(borrowed_pool))
            .and(warp::any().map(move || borrowed_pool))
            .and_then(get_setting)
            .recover(handle_api_rejections(&[], "/settings/:name requires GET"));
        let delete_account = warp::path!("account" / "delete")
            .and(warp::delete())
            .and(auth(borrowed_pool))
            .and(warp::any().map(move || borrowed_pool))
            .and_then(delete_account)
            .recover(handle_api_rejections(&[], "/account/delete requires DELETE"));

        let cors;
        if let Ok(prod_origin) = env::var("PROD_ORIGIN") {
            cors = warp::cors()
            .allow_origin(prod_origin.as_str())
            .allow_headers(vec!["Access-Control-Allow-Origin", "Origin", "Accept", "X-Requested-With", "Content-Type", "Authorization"])
            .allow_methods(&[warp::http::Method::GET, warp::http::Method::POST, warp::http::Method::PATCH, warp::http::Method::PUT, warp::http::Method::DELETE, warp::http::Method::OPTIONS]);
        } else {
            cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["Access-Control-Allow-Origin", "Origin", "Accept", "X-Requested-With", "Content-Type", "Authorization"])
            .allow_methods(&[warp::http::Method::GET, warp::http::Method::POST, warp::http::Method::PATCH, warp::http::Method::PUT, warp::http::Method::DELETE, warp::http::Method::OPTIONS]);
        }

        // Compile routes into one warp instance to serve
        let route = warp::any().and(login.or(create_acc).or(add_data).or(get_data).or(update_data).or(list_data).or(delete_data).or(invalidate_sessions).or(update_setting).or(get_setting).or(delete_account)).recover(async |rej: Rejection| -> Result<warp::reply::WithStatus<warp::reply::Json>, warp::Rejection> {
            if rej.is_not_found() {
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("api route not found")), warp::http::StatusCode::NOT_FOUND))
            } else {
                Ok(warp::reply::with_status(warp::reply::json(&ApiError::from_str("internal server error")), warp::http::StatusCode::INTERNAL_SERVER_ERROR))
            }
        }).with(cors);
        warp::serve(route).run(([127, 0, 0, 1], env::var("PORT")?.parse::<u16>()?)).await;
        borrowed_pool.close().await;
    Ok(())
}