pub use biscuit::errors::Error as Jose;
pub use serde_json::Error as Json;
pub use inth_oauth2::ClientError as Oauth;
pub use reqwest::Error as Http;
pub use reqwest::UrlError as Url;

use std::fmt::{Display, Formatter, Result};
use std::error::Error as ErrorTrait;

macro_rules! from {
    ($to:ident, $from:ident) => {
        impl From<$from> for $to {
            fn from(e: $from) -> Self {
                $to::$from(e)
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Jose(Jose),
    Json(Json),
    Oauth(Oauth),
    Http(Http),
    Url(Url),
    Decode(Decode),
    Validation(Validation),
    Userinfo(Userinfo),
    Insecure(::reqwest::Url),
    MissingOpenidScope,
}

from!(Error, Jose);
from!(Error, Json);
from!(Error, Oauth);
from!(Error, Http);
from!(Error, Url);
from!(Error, Decode);
from!(Error, Validation);
from!(Error, Userinfo);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use Error::*;
        match *self {
            Jose(ref err)       => Display::fmt(err, f),
            Json(ref err)       => Display::fmt(err, f),
            Oauth(ref err)      => Display::fmt(err, f),
            Http(ref err)       => Display::fmt(err, f),
            Url(ref err)        => Display::fmt(err, f),
            Decode(ref err)     => Display::fmt(err, f),
            Validation(ref err) => Display::fmt(err, f),
            Userinfo(ref err)   => Display::fmt(err, f),
            Insecure(ref url)   => write!(f, "Url must use HTTPS: '{}'", url),
            MissingOpenidScope  => write!(f, "")
        }
    }
}

impl ErrorTrait for Error {
    fn description(&self) -> &str {
        use Error::*;
        match *self {
            Jose(ref err)       => err.description(),
            Json(ref err)       => err.description(),
            Oauth(ref err)      => err.description(),
            Http(ref err)       => err.description(),
            Url(ref err)        => err.description(),
            Decode(ref err)     => err.description(),
            Validation(ref err) => err.description(),
            Userinfo(ref err)   => err.description(),
            Insecure(_)         => "URL must use TLS",
            MissingOpenidScope  => "Scope must contain Openid",
        }
    }

    fn cause(&self) -> Option<&ErrorTrait> {
        use Error::*;
        match *self {
            Jose(ref err)       => Some(err),
            Json(ref err)       => Some(err),
            Oauth(ref err)      => Some(err),
            Http(ref err)       => Some(err),
            Url(ref err)        => Some(err),
            Decode(_)           => None,
            Validation(_)       => None,
            Userinfo(_)         => None,
            Insecure(_)         => None,
            MissingOpenidScope  => None,
        }
    }
}

#[derive(Debug)]
pub enum Decode {
    MissingKid,
    MissingKey(String),
    EmptySet,
}

impl ErrorTrait for Decode {
    fn description(&self) -> &str {
        use Decode::*;
        match *self {
            MissingKid => "Missing Key Id",
            MissingKey(_) => "Token key not in key set",
            EmptySet => "JWK Set is empty",
        }
    }
    fn cause(&self) -> Option<&ErrorTrait> {
        None
    }
}

impl Display for Decode {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use Decode::*;
        match *self {
            MissingKid => write!(f, "Token Missing a Key Id when the key set has multiple keys"),
            MissingKey(ref id) => 
                write!(f, "Token wants this key id not in the key set: {}", id),
            EmptySet => write!(f, "JWK Set is empty!")
        }
    }
}

#[derive(Debug)]
pub enum Validation {
    Mismatch(Mismatch),
    Missing(Missing),
    Expired(Expiry),
}

impl ErrorTrait for Validation {
    fn description(&self) -> &str {
        use error::Validation::*;
        match *self {
            Mismatch(ref mm) => {
                use error::Mismatch::*;
                match *mm {
                    AuthorizedParty {..}    => "Client id and token authorized party mismatch",
                    Issuer {..}             => "Config issuer and token issuer mismatch",
                    Nonce {..}              => "Supplied nonce and token nonce mismatch",
                }
            }
            Missing(ref mi)  => {
                use Missing::*;
                match *mi {
                    Audience        => "Token missing Audience",
                    AuthorizedParty => "Token missing AZP",
                    AuthTime        => "Token missing Auth Time",
                    Nonce           => "Token missing Nonce"
                }
            }
            Expired(ref ex)  => {
                match *ex {
                    Expiry::Expires(_)  => "Token expired",
                    Expiry::MaxAge(_)   => "Token too old"
                }
            }
        }
    }

    fn cause(&self) -> Option<&ErrorTrait> {
        None
    }
}

impl Display for Validation {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use error::Validation::*;
        match *self {
            Mismatch(ref err)   => err.fmt(f),
            Missing(ref err)    => err.fmt(f),
            Expired(ref err)    => err.fmt(f),
        }
    }
}

#[derive(Debug)]
pub enum Mismatch {
    AuthorizedParty { expected: String, actual: String },
    Issuer { expected: String, actual: String },
    Nonce { expected: String, actual: String },
}

impl Display for Mismatch {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use error::Mismatch::*;
        match *self {
            AuthorizedParty  { ref expected, ref actual } => 
        write!(f, "Client ID and Token authorized party mismatch: '{}', '{}'", expected, actual),
            Issuer      { ref expected, ref actual } => 
            write!(f, "Configured issuer and token issuer mismatch: '{}' '{}'", expected, actual),
            Nonce       { ref expected, ref actual } => 
            write!(f, "Given nonce does not match token nonce: '{}', '{}'", expected, actual)
        }
    }
}

#[derive(Debug)]
pub enum Missing {
    Audience,
    AuthorizedParty,
    AuthTime,
    Nonce,
}

impl Display for Missing {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use Missing::*;
        match *self {
            Audience        => write!(f, "Token missing Audience"),
            AuthorizedParty => write!(f, "Token missing AZP"),
            AuthTime        => write!(f, "Token missing Auth Time"),
            Nonce           => write!(f, "Token missing Nonce")
        }
    }
}

#[derive(Debug)]
pub enum Expiry {
    Expires(::chrono::naive::NaiveDateTime),
    MaxAge(::chrono::Duration)
}

impl Display for Expiry {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use Expiry::*;
        match *self {
            Expires(time)   => write!(f, "Token expired at: {}", time),
            MaxAge(age)     => write!(f, "Token is too old: {}", age)
        }
    }
}

#[derive(Debug)]
pub enum Userinfo {
    NoUrl,
    MismatchIssuer { expected: String, actual: String },
    MismatchSubject { expected: String, actual: String },
}

impl ErrorTrait for Userinfo {
    fn description(&self) -> &str {
        use error::Userinfo::*;
        match *self {
            NoUrl                  => "No url",
            MismatchIssuer  { .. } => "Mismatch issuer",
            MismatchSubject { .. } => "Mismatch subject"
        }
    }

    fn cause(&self) -> Option<&ErrorTrait> {
        None
    }
}

impl Display for Userinfo {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use error::Userinfo::*;
        match *self {
            NoUrl => write!(f, "Config has no userinfo url"),
            MismatchIssuer  { ref expected, ref actual } => 
                write!(f, "Token and Userinfo Issuers mismatch: '{}', '{}'", expected, actual),
            MismatchSubject { ref expected, ref actual } => 
                write!(f, "Token and Userinfo Subjects mismatch: '{}', '{}'", expected, actual),
        }
    }
}