pub use biscuit::errors::Error as Jose;
pub use inth_oauth2::ClientError as Oauth;
pub use reqwest::Error as Http;
// pub use reqwest::UrlError as Url;
pub use serde_json::Error as Json;

use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Jose(#[fail(cause)] Jose),
    #[fail(display = "{}", _0)]
    Oauth(#[fail(cause)] Oauth),
    #[fail(display = "{}", _0)]
    Http(#[fail(cause)] Http),
    // #[fail(display = "{}", _0)]
    // Url(#[fail(cause)] Url),
    #[fail(display = "{}", _0)]
    Json(#[fail(cause)] Json),
    #[fail(display = "{}", _0)]
    Decode(#[fail(cause)] Decode),
    #[fail(display = "{}", _0)]
    Validation(#[fail(cause)] Validation),
    #[fail(display = "{}", _0)]
    Userinfo(#[fail(cause)] Userinfo),
    #[fail(display = "Url must use TLS: '{}'", _0)]
    Insecure(::reqwest::Url),
    #[fail(display = "Scope must contain Openid")]
    MissingOpenidScope,
    #[fail(display = "Url: Path segments is cannot-be-a-base")]
    CannotBeABase,
}

macro_rules! from {
    ($from:ident) => {
        impl From<$from> for Error {
            fn from(e: $from) -> Self {
                Error::$from(e)
            }
        }
    };
}

from!(Jose);
from!(Json);
from!(Oauth);
from!(Http);
// from!(Url);
from!(Decode);
from!(Validation);
from!(Userinfo);

#[derive(Debug, Fail)]
pub enum Decode {
    #[fail(display = "Token Missing a Key Id when the key set has multiple keys")]
    MissingKid,
    #[fail(display = "Token wants this key id not in the key set: {}", _0)]
    MissingKey(String),
    #[fail(display = "JWK Set is empty")]
    EmptySet,
}

#[derive(Debug, Fail)]
pub enum Validation {
    #[fail(display = "{}", _0)]
    Mismatch(#[fail(cause)] Mismatch),
    #[fail(display = "{}", _0)]
    Missing(#[fail(cause)] Missing),
    #[fail(display = "{}", _0)]
    Expired(#[fail(cause)] Expiry),
}

#[derive(Debug, Fail)]
pub enum Mismatch {
    #[fail(
        display = "Client ID and Token authorized party mismatch: '{}', '{}'",
        expected, actual
    )]
    AuthorizedParty { expected: String, actual: String },
    #[fail(
        display = "Configured issuer and token issuer mismatch: '{}' '{}'",
        expected, actual
    )]
    Issuer { expected: String, actual: String },
    #[fail(
        display = "Given nonce does not match token nonce: '{}', '{}'",
        expected, actual
    )]
    Nonce { expected: String, actual: String },
}

#[derive(Debug, Fail)]
pub enum Missing {
    #[fail(display = "Token missing Audience")]
    Audience,
    #[fail(display = "Token missing AZP")]
    AuthorizedParty,
    #[fail(display = "Token missing Auth Time")]
    AuthTime,
    #[fail(display = "Token missing Nonce")]
    Nonce,
}

#[derive(Debug, Fail)]
pub enum Expiry {
    #[fail(display = "Token expired at: {}", _0)]
    Expires(::chrono::naive::NaiveDateTime),
    #[fail(display = "Token is too old: {}", _0)]
    MaxAge(::chrono::Duration),
}

#[derive(Debug, Fail)]
pub enum Userinfo {
    #[fail(display = "Config has no userinfo url")]
    NoUrl,
    #[fail(
        display = "Token and Userinfo Subjects mismatch: '{}', '{}'",
        expected, actual
    )]
    MismatchSubject { expected: String, actual: String },
}
