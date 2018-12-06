use biscuit::Empty;
use biscuit::jwk::JWKSet;
use inth_oauth2::provider::Provider;
use inth_oauth2::token::Expiring;
use reqwest::{Client, Url};
use serde_derive::{Deserialize, Serialize};
use url_serde;

use crate::error::Error;
use crate::token::Token;

pub(crate) fn secure(url: &Url) -> Result<(), Error> {
    if url.scheme() != "https" {
        Err(Error::Insecure(url.clone()))
    } else {
        Ok(())
    }
}

// TODO I wish we could impl default for this, but you cannot have a config without issuer etc
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(with = "url_serde")] pub issuer: Url,
    #[serde(with = "url_serde")] pub authorization_endpoint: Url,
    // Only optional in the implicit flow
    // TODO For now, we only support code flows.
    #[serde(with = "url_serde")] pub token_endpoint: Url,
    #[serde(default)] #[serde(with = "url_serde")] pub userinfo_endpoint: Option<Url>,
    #[serde(with = "url_serde")] pub jwks_uri: Url,
    #[serde(default)] #[serde(with = "url_serde")] pub registration_endpoint: Option<Url>,
    #[serde(default)] pub scopes_supported: Option<Vec<String>>,
    // There are only three valid response types, plus combinations of them, and none
    // If we want to make these user friendly we want a struct to represent all 7 types
    pub response_types_supported: Vec<String>,
    // There are only two possible values here, query and fragment. Default is both.
    #[serde(default)] pub response_modes_supported: Option<Vec<String>>,
    // Must support at least authorization_code and implicit.
    #[serde(default)] pub grant_types_supported: Option<Vec<String>>,
    #[serde(default)] pub acr_values_supported: Option<Vec<String>>,
    // pairwise and public are valid by spec, but servers can add more
    pub subject_types_supported: Vec<String>,
    // Must include at least RS256, none is only allowed with response types without id tokens
    pub id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)] pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)] pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)] pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)] pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)] pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)] pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)] pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)] pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    // Spec options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt
    // If omitted, client_secret_basic is used
    #[serde(default)] pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    // Only wanted with jwt auth methods, should have RS256, none not allowed
    #[serde(default)] pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)] pub display_values_supported: Option<Vec<String>>,
    // Valid options are normal, aggregated, and distributed. If omitted, only use normal
    #[serde(default)] pub claim_types_supported: Option<Vec<String>>,
    #[serde(default)] pub claims_supported: Option<Vec<String>>,
    #[serde(default)] #[serde(with = "url_serde")] pub service_documentation: Option<Url>,
    #[serde(default)] pub claims_locales_supported: Option<Vec<String>>,
    #[serde(default)] pub ui_locales_supported: Option<Vec<String>>,
    #[serde(default)] pub claims_parameter_supported: bool,
    #[serde(default)] pub request_parameter_supported: bool,
    #[serde(default = "tru")] pub request_uri_parameter_supported: bool,
    #[serde(default)] pub require_request_uri_registration: bool,
    
    #[serde(default)] #[serde(with = "url_serde")] pub op_policy_uri: Option<Url>,
    #[serde(default)] #[serde(with = "url_serde")] pub op_tos_uri: Option<Url>,
    // This is a NONSTANDARD extension Google uses that is a part of the Oauth discovery draft
    #[serde(default)] pub code_challenge_methods_supported: Option<Vec<String>>,
}

// This seems really dumb...
fn tru() -> bool {
    true
}

pub struct Discovered(pub Config);

impl Provider for Discovered {
    type Lifetime = Expiring;
    type Token = Token;
    fn auth_uri(&self) -> &Url {
        &self.0.authorization_endpoint
    }

    fn token_uri(&self) -> &Url {
        &self.0.token_endpoint
    }
}

/// Get the discovery config document from the given issuer url. Errors are either a reqwest error
/// or an Insecure if the Url isn't https.
pub fn discover(client: &Client, issuer: Url) -> Result<Config, Error> {
    secure(&issuer)?;
    let url = issuer.join(".well-known/openid-configuration")?;
    println!("Urls: {} {}", issuer, url);
    let mut resp = client.get(url).send()?;
    resp.json().map_err(Error::from)
}

/// Get the JWK set from the given Url. Errors are either a reqwest error or an Insecure error if 
/// the url isn't https.
pub fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    secure(&url)?;
    let mut resp = client.get(url).send()?;
    resp.json().map_err(Error::from)
}

#[test]
fn config_google() {
    // Formatting this took time off my lifespan...
    let cfg = r#"{  "issuer": "https://accounts.google.com", 
                    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                    "token_endpoint": "https://www.googleapis.com/oauth2/v4/token",
                    "userinfo_endpoint": "https://www.googleapis.com/oauth2/v3/userinfo",
                    "revocation_endpoint": "https://accounts.google.com/o/oauth2/revoke",
                    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                    "response_types_supported": [ "code", "token", "id_token", "code token",
                                                  "code id_token", "token id_token",
                                                  "code token id_token", "none" ],
                    "subject_types_supported": [ "public" ],
                    "id_token_signing_alg_values_supported": [ "RS256" ],
                    "scopes_supported": [ "openid", "email", "profile" ],
                    "token_endpoint_auth_methods_supported": [ "client_secret_post",
                                                               "client_secret_basic" ],
                    "claims_supported": [ "aud", "email", "email_verified", "exp", "family_name",
                                          "given_name", "iat", "iss", "locale", "name", "picture",
                                          "sub" ],
                    "code_challenge_methods_supported": [ "plain", "S256" ]
                  }"#;
    ::serde_json::from_str::<Config>(cfg).unwrap();
}

#[test]
fn config_minimum() {
    let cfg = r#"{  "issuer": "https://example.com",
                    "authorization_endpoint": "https://example.com/auth",
                    "token_endpoint": "https://example.com/token",
                    "jwks_uri": "https://example.com/certs",
                    "response_types_supported": [ "code" ],
                    "subject_types_supported": [ "public" ],
                    "id_token_signing_alg_values_supported": [ "RS256" ]
                  }"#;
    ::serde_json::from_str::<Config>(cfg).unwrap();
}
