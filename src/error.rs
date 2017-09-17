pub use biscuit::errors::Error as Jose;
pub use serde_json::Error as Json;
pub use inth_oauth2::ClientError as Oauth;
pub use reqwest::Error as Reqwest;

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
    Reqwest(Reqwest),
    Decode(Decode),
    Validation(Validation),
    Userinfo(Userinfo),
    Insecure,
}

from!(Error, Jose);
from!(Error, Json);
from!(Error, Oauth);
from!(Error, Reqwest);
from!(Error, Decode);
from!(Error, Validation);
from!(Error, Userinfo);

#[derive(Debug)]
pub enum Decode {
    MissingKid,
    MissingKey,
    EmptySet,
}

#[derive(Debug)]
pub enum Validation {
    Mismatch(Mismatch),
    Missing(Missing),
    Expired(Expiry),
}

#[derive(Debug)]
pub enum Mismatch {
    Audience,
    Authorized,
    Issuer,
    Nonce,
}

#[derive(Debug)]
pub enum Missing {
    AuthorizedParty,
    AuthTime,
    Nonce,
}

#[derive(Debug)]
pub enum Expiry {
    Expires,
    MaxAge,
}

#[derive(Debug)]
pub enum Userinfo {
    NoUrl,
    MismatchSubject,
    
}