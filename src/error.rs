use biscuit;
use inth_oauth2;

pub enum Decode {
    MissingKid,
    MissingKey,
    EmptySet,
}

pub enum Validation {
    Mismatch(Mismatch),
    Missing(Missing),
    Expired(Expiry),
}

pub enum Mismatch {
    Audience,
    Authorized,
    Issuer,
    Nonce,
    Subject,
}
pub enum Missing {
    AuthorizedParty,
    AuthTime,
    Nonce,
    OpenidScope,
}

pub enum Expiry {
    Expires,
    IssuedAt,
    MaxAge,
}

error_chain! {
    foreign_links {
        Oauth(inth_oauth2::ClientError);
        Biscuit(biscuit::errors::Error);
    }

    errors {
        MissingOpenidScope
    }
}