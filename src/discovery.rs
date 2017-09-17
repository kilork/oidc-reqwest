use biscuit::Empty;
use biscuit::jwk::JWKSet;
use inth_oauth2::provider::Provider;
use inth_oauth2::token::Expiring;
use reqwest::{Client, Url};
use url_serde;
use validator::Validate;

use error::Error;
use token::Token;

pub(crate) fn secure(url: &Url) -> Result<(), Error> {
    if url.scheme() != "https" {
        Err(Error::Insecure(url.clone()))
    } else {
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    #[serde(with = "url_serde")]
    pub issuer: Url,
    #[serde(with = "url_serde")]
    pub authorization_endpoint: Url,
    #[serde(with = "url_serde")]
    // Only optional in the implicit flow
    // TODO For now, we only support code flows.
    pub token_endpoint: Url,
    #[serde(with = "url_serde")]
    pub userinfo_endpoint: Option<Url>,
    #[serde(with = "url_serde")]
    pub jwks_uri: Url,
    #[serde(with = "url_serde")]
    pub registration_endpoint: Option<Url>,
    pub scopes_supported: Option<Vec<String>>,
    // There are only three valid response types, plus combinations of them, and none
    // If we want to make these user friendly we want a struct to represent all 7 types
    pub response_types_supported: Vec<String>,
    // There are only two possible values here, query and fragment. Default is both.
    pub response_modes_supported: Option<Vec<String>>,
    // Must support at least authorization_code and implicit.
    pub grant_types_supported: Option<Vec<String>>,
    pub acr_values_supported: Option<Vec<String>>,
    // pairwise and public are valid by spec, but servers can add more
    pub subject_types_supported: Vec<String>,
    // Must include at least RS256, none is only allowed with response types without id tokens
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    // Spec options are client_secret_post, client_secret_basic, client_secret_jwt, private_key_jwt
    // If omitted, client_secret_basic is used
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    // Only wanted with jwt auth methods, should have RS256, none not allowed
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub display_values_supported: Option<Vec<String>>,
    // Valid options are normal, aggregated, and distributed. If omitted, only use normal
    pub claim_types_supported: Option<Vec<String>>,
    pub claims_supported: Option<Vec<Claim>>,
    #[serde(with = "url_serde")]
    pub service_documentation: Option<Url>,
    pub claims_locales_supported: Option<Vec<String>>,
    pub ui_locales_supported: Option<Vec<String>>,
    // default false
    pub claims_parameter_supported: Option<bool>,
    // default false
    pub request_parameter_supported: Option<bool>,
    // default true
    pub request_uri_parameter_supported: Option<bool>,
    // default false
    pub require_request_uri_registration: Option<bool>,
    #[serde(with = "url_serde")]
    pub op_policy_uri: Option<Url>,
    #[serde(with = "url_serde")]
    pub op_tos_uri: Option<Url>,
    // This is a NONSTANDARD extension Google uses that is a part of the Oauth discovery draft
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize)]
pub enum Claim {
    Name(String),
    FamilyName(String),
    GivenName(String),
    MiddleName(String),
    Nickname(String),
    PreferredUsername(String),
    Profile(
        #[serde(with = "url_serde")]
        Url
    ),
    Picture(
        #[serde(with = "url_serde")]
        Url
    ),
    Website(
        #[serde(with = "url_serde")]
        Url
    ),
    Gender(String),
    Birthdate(String),
    Zoneinfo(String),
    Locale(String),
    UpdatedAt(u64),
    Email(Email),
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct Email {
    #[validate(email)]
    pub address: String,
}

pub struct Discovered {
    pub config: Config,
}

impl Provider for Discovered {
    type Lifetime = Expiring;
    type Token = Token;
    fn auth_uri(&self) -> &str {
        self.config.authorization_endpoint.as_ref()
    }

    fn token_uri(&self) -> &str {
        self.config.token_endpoint.as_ref()
    }
}

/// Get the discovery config document from the given issuer url. Errors are either a reqwest error
/// or an Insecure if the Url isn't https.
pub fn discover(client: &Client, issuer: Url) -> Result<Config, Error> {
    secure(&issuer)?;
    let mut resp = client.get(issuer)?.send()?;
    resp.json().map_err(Error::from)
}

/// Get the JWK set from the given Url. Errors are either a reqwest error or an Insecure error if 
/// the url isn't https.
pub fn jwks(client: &Client, url: Url) -> Result<JWKSet<Empty>, Error> {
    secure(&url)?;
    let mut resp = client.get(url)?.send()?;
    resp.json().map_err(Error::from)
}
