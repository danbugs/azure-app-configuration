use crate::client::Body;
use crate::Exception;
use httpdate::fmt_http_date;
use sha2::{Digest, Sha256};
use surf::http::Method;
use url::Url;
use ring::hmac;

const SIGNED_HEADERS: &str = "date;host;x-ms-content-sha256";

fn get_content_hash_base64(body: &Body) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.value());

    let hashed_content = hasher.finalize();
    base64::encode(&hashed_content)
}

fn get_hmac(secret: Vec<u8>, to_sign: String) -> String {
    let signed_key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
    let signature = hmac::sign(&signed_key, to_sign.as_bytes());
    base64::encode(signature.as_ref())
}

pub(crate) fn create_signed_request<S: Into<String>>(
    access_key: S,
    secret: Vec<u8>,
    url: &Url,
    body: Body,
    method: Method,
) -> Result<surf::Request, Exception> {
    let host = url.host().unwrap().to_string();

    let path = match url.query() {
        Some(_) => format!("{}?{}", url.path(), url.query().unwrap()),
        None => url.path().to_string(),
    };

    let verb = method.to_string().to_uppercase();
    let utc = fmt_http_date(std::time::SystemTime::now());

    let content_hash = get_content_hash_base64(&body);

    let to_sign = format!("{}\n{}\n{};{};{}", verb, path, utc, host, content_hash);

    let encoded_signature = get_hmac(secret, to_sign);

    let mut request = surf::Request::new(method, url.clone());

    let auth_value = format!(
        "HMAC-SHA256 Credential={}&SignedHeaders={}&Signature={}",
        access_key.into(),
        SIGNED_HEADERS,
        encoded_signature
    );

    log::debug!(
        "Request signed with headers\n \
         Date: {}\n \
         x-ms-content-sha256: {}\n \
         Authorization: {}",
        &utc,
        &content_hash,
        &auth_value
    );

    log::debug!("Request body size: {}", body.len());

    request.set_header("Date", utc);
    request.set_header("x-ms-content-sha256", content_hash);
    request.set_header("Authorization", auth_value);
    request.set_header("host", url.host().unwrap().to_string());

    request.body_bytes(body.value());

    Ok(request)
}
