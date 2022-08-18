#![allow(dead_code)]

use std::error::Error;
use std::fmt::Formatter;

#[derive(Debug, Clone)]
pub struct HttpError {
    status: usize,
    url: String,
    content: String,
}

impl HttpError {
    pub fn new<S: Into<String>>(err: usize, url: S, content: S) -> Self {
        HttpError {
            status: err,
            url: url.into(),
            content: content.into(),
        }
    }
}

impl Error for HttpError {}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "Http request error, code: {}, url: {}",
            self.status, self.url
        )
    }
}
