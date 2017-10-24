//! # OpenID Connect Client
//!
//! There are two ways to interact with this library - the batteries included magic methods, and
//! the slightly more boilerplate but more fine grained ones. For most users the following is what
//! you want.
//!
//! ```rust,ignore
//! use oidc;
//! use reqwest;
//! use std::default::Default;
//! 
//! let id = "my client".to_string();
//! let secret = "a secret to everybody".to_string();
//! let redirect = reqwest::Url::parse("https://my-redirect.foo")?;
//! let issuer = oidc::issuer::google();
//! let client = oidc::discover(id, secret, redirect, issuer)?;
//! let auth_url = client.auth_url(Default::default());
//! 
//! // ... send your user to auth_url, get an auth_code back at your redirect_url handler
//! 
//! let token = client.authenticate(auth_code, None, None)?;
//! ```
//!
//! That example leaves you with a decoded `Token` that has been validated. Your user is 
//! authenticated!
//!
//! You can also take a more nuanced approach that gives you more fine grained control:
//!
//! ```rust,ignore
//! use oidc;
//! use reqwest;
//! use std::default::Default;
//! 
//! let id = "my client".to_string();
//! let secret = "a secret to everybody".to_string();
//! let redirect = reqwest::Url::parse("https://my-redirect.foo")?;
//! let issuer = oidc::issuer::google();
//! let http = reqwest::Client::new();
//! 
//! let config = oidc::discovery::discover(&http, issuer)?;
//! let jwks = oidc::discovery::jwks(&http, config.jwks_uri.clone())?;
//! let provider = oidc::discovery::Discovered { config };
//! 
//! let client = oidc::new(id, secret, redirect, provider, jwks);
//! let auth_url = client.auth_url(Default::default());
//!
//! // ... send your user to auth_url, get an auth_code back at your redirect_url handler
//! 
//! let mut token = client.request_token(&http, auth_code)?;
//! client.decode_token(&mut token)?;
//! client.validate_token(&token, None, None)?;
//! let userinfo = client.request_userinfo(&http, &token)?;
//! ```
//!
//! This more complicated version uses the discovery module directly. Important distinctions to make
//! between the two:
//!
//! - The complex pattern avoids constructing a new reqwest client every time an outbound method is
//!   called. Especially for token decoding having to rebuild reqwest every time can be a large
//!   performance penalty.
//! - Tokens don't come decoded or validated. You need to do both manually.
//! - This version demonstrates userinfo. It is not required by spec, so make sure its available!
//!   (you get an Error::Userinfo::Nourl if it is not)

extern crate base64;
extern crate biscuit;
extern crate chrono;
extern crate inth_oauth2;
extern crate reqwest;
// We never use serde, but serde_derive needs it here
#[allow(unused_extern_crates)]
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate url_serde;
extern crate validator;
#[macro_use]
extern crate validator_derive;

pub mod discovery;
pub mod error;
pub mod issuer;
pub mod token;

pub use error::Error;

use biscuit::{Empty, SingleOrMultiple};
use biscuit::jwa::{self, SignatureAlgorithm};
use biscuit::jwk::{AlgorithmParameters, JWKSet};
use biscuit::jws::{Compact, Secret};
use chrono::{Duration, NaiveDate, Utc};
use inth_oauth2::token::Token as _t;
use reqwest::{header, Url};
use validator::Validate;

use discovery::{Config, Discovered};
use error::{Decode, Expiry, Mismatch, Missing, Validation};
use token::{Claims, Token};

type IdToken = Compact<Claims, Empty>;

/// OpenID Connect Client for a provider specified at construction.
pub struct Client {
    oauth: inth_oauth2::Client<Discovered>,
    jwks: JWKSet<Empty>,
}

// Common pattern in the Client::decode function when dealing with mismatched keys
macro_rules! wrong_key {
    ($expected:expr, $actual:expr) => (
        Err(error::Jose::WrongKeyType {
                expected: format!("{:?}", $expected),
                actual: format!("{:?}", $actual)
            }.into()
        )
    )
}

impl Client {
    /// Constructs a client from an issuer url and client parameters via discovery
    pub fn discover(id: String, secret: String, redirect: Url, issuer: Url) -> Result<Self, Error> {
        discovery::secure(&redirect)?;
        let client = reqwest::Client::new();
        let config = discovery::discover(&client, issuer)?;
        let jwks = discovery::jwks(&client, config.jwks_uri.clone())?;
        let provider = Discovered { config };
        Ok(Self::new(id, secret, redirect, provider, jwks))
    }

    /// Constructs a client from a given provider, key set, and parameters. Unlike ::discover(..) 
    /// this function does not perform any network operations.
    pub fn new(id: String, secret: 
        String, redirect: Url, provider: Discovered, jwks: JWKSet<Empty>) -> Self {
        Client {
            oauth: inth_oauth2::Client::new(
                provider, 
                id, 
                secret,
                Some(redirect.into_string())),
            jwks
        }
    }

    /// Passthrough to the redirect_url stored in inth_oauth2 as a str.
    pub fn redirect_url(&self) -> &str {
        self.oauth.redirect_uri.as_ref().expect("We always require a redirect to construct client!")
    }

    /// Passthrough to the inth_oauth2::client's request token.
    pub fn request_token(&self,
                         client: &reqwest::Client,
                         auth_code: &str,
    ) -> Result<Token, Error> {
        self.oauth.request_token(client, auth_code).map_err(Error::from)
    }

    /// A reference to the config document of the provider obtained via discovery
    pub fn config(&self) -> &Config {
        &self.oauth.provider.config
    }

    /// Constructs the auth_url to redirect a client to the provider. Options are... optional. Use 
    /// them as needed. Keep the Options struct around for authentication, or at least the nonce 
    /// and max_age parameter - we need to verify they stay the same and validate if you used them.
    pub fn auth_url(&self, options: &Options) -> Url {
        let scope = match options.scope {
            Some(ref scope) => {
                if !scope.contains("openid") {
                    String::from("openid ") + scope
                } else {
                    scope.clone()
                }
            }
            // Default scope value
            None => String::from("openid")
        };

        let mut url = self.oauth.auth_uri(Some(&scope), options.state.as_ref().map(String::as_str));
        {
            let mut query = url.query_pairs_mut();
            if let Some(ref nonce) = options.nonce {
                query.append_pair("nonce", nonce.as_str());
            }
            if let Some(ref display) = options.display {
                query.append_pair("display", display.as_str());
            }
            if let Some(ref prompt) = options.prompt {
                let s = prompt.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
                query.append_pair("prompt", s.as_str());
            }
            if let Some(max_age) = options.max_age {
                query.append_pair("max_age", max_age.num_seconds().to_string().as_str());
            }
            if let Some(ref ui_locales) = options.ui_locales {
                query.append_pair("ui_locales", ui_locales.as_str());
            }
            if let Some(ref claims_locales) = options.claims_locales {
                query.append_pair("claims_locales", claims_locales.as_str());
            }
            if let Some(ref id_token_hint) = options.id_token_hint {
                query.append_pair("id_token_hint", id_token_hint.as_str());
            }
            if let Some(ref login_hint) = options.login_hint {
                query.append_pair("login_hint", login_hint.as_str());
            }
            if let Some(ref acr_values) = options.acr_values {
                query.append_pair("acr_values", acr_values.as_str());
            }
        }
        url
    }

    /// Given an auth_code and auth options, request the token, decode, and validate it.
    pub fn authenticate(&self, auth_code: &str, nonce: Option<&str>, max_age: Option<&Duration>
    ) -> Result<Token, Error> {
        let client = reqwest::Client::new();
        let mut token = self.request_token(&client, auth_code)?;
        self.decode_token(&mut token.id_token)?;
        self.validate_token(&token.id_token, nonce, max_age)?;
        Ok(token)
    }

    /// Mutates a Compact::encoded Token to Compact::decoded. Errors are:
    ///
    /// - Decode::MissingKid if the keyset has multiple keys but the key id on the token is missing
    /// - Decode::MissingKey if the given key id is not in the key set
    /// - Decode::EmptySet if the keyset is empty
    /// - Jose::WrongKeyType if the alg of the key and the alg in the token header mismatch
    /// - Jose::WrongKeyType if the specified key alg isn't a signature algorithm
    /// - Jose error if decoding fails
    pub fn decode_token(&self, token: &mut IdToken) -> Result<(), Error> {
        // This is an early return if the token is already decoded
        if let Compact::Decoded { .. } = *token {
            return Ok(())
        }

        let header = token.unverified_header()?;
        // If there is more than one key, the token MUST have a key id
        let key = if self.jwks.keys.len() > 1 {
            let token_kid = header.registered.key_id.ok_or(Decode::MissingKid)?;
            self.jwks.find(&token_kid).ok_or(Decode::MissingKey(token_kid))?
        } else {
            // TODO We would want to verify the keyset is >1 in the constructor
            // rather than every decode call, but we can't return an error in new().
            self.jwks.keys.first().as_ref().ok_or(Decode::EmptySet)?
        };

        if let Some(alg) = key.common.algorithm.as_ref() {
            if let &jwa::Algorithm::Signature(sig) = alg {
                if header.registered.algorithm != sig {
                    return wrong_key!(sig, header.registered.algorithm);
                }
            } else {
                return  wrong_key!(SignatureAlgorithm::default(), alg);
            }
        }

        let alg = header.registered.algorithm;
        match key.algorithm {
            // HMAC
            AlgorithmParameters::OctectKey { ref value, .. } => {
                match alg {
                    SignatureAlgorithm::HS256 |
                    SignatureAlgorithm::HS384 |
                    SignatureAlgorithm::HS512 => {
                        *token = token.decode(&Secret::Bytes(value.clone()), alg)?;
                        Ok(())
                    }
                    _ =>  wrong_key!("HS256 | HS384 | HS512", alg)
                }
            }
            AlgorithmParameters::RSA(ref params) => {
                match alg {
                    SignatureAlgorithm::RS256 |
                    SignatureAlgorithm::RS384 |
                    SignatureAlgorithm::RS512 => {
                        let pkcs = Secret::Pkcs {
                            n: params.n.clone(),
                            e: params.e.clone(),
                        };
                        *token = token.decode(&pkcs, alg)?;
                        Ok(())
                    }
                    _ =>  wrong_key!("RS256 | RS384 | RS512", alg)
                }
            }
            AlgorithmParameters::EllipticCurve(_) => unimplemented!("No support for EC keys yet"),
        }
    }

    /// Validate a decoded token. If you don't get an error, its valid! Nonce and max_age come from
    /// your auth_uri options. Errors are:
    ///
    /// - Jose Error if the Token isn't decoded
    /// - Validation::Mismatch::Issuer if the provider issuer and token issuer mismatch
    /// - Validation::Mismatch::Nonce if a given nonce and the token nonce mismatch
    /// - Validation::Missing::Nonce if either the token or args has a nonce and the other does not
    /// - Validation::Missing::Audience if the token aud doesn't contain the client id
    /// - Validation::Missing::AuthorizedParty if there are multiple audiences and azp is missing
    /// - Validation::Mismatch::AuthorizedParty if the azp is not the client_id
    /// - Validation::Expired::Expires if the current time is past the expiration time
    /// - Validation::Expired::MaxAge is the token is older than the provided max_age
    /// - Validation::Missing::Authtime if a max_age was given and the token has no auth time
    pub fn validate_token(
        &self, 
        token: &IdToken, 
        nonce: Option<&str>, 
        max_age: Option<&Duration>
    ) -> Result<(), Error> {
        let claims = token.payload()?;

        if claims.iss != self.config().issuer  {
            let expected = self.config().issuer.as_str().to_string();
            let actual = claims.iss.as_str().to_string();
            return Err(Validation::Mismatch(Mismatch::Issuer { expected, actual }).into());
        }

        match nonce {
            Some(expected) => match claims.nonce {
                Some(ref actual) => {
                    if expected != actual {
                        let expected = expected.to_string();
                        let actual = actual.to_string();
                        return Err(Validation::Mismatch(
                            Mismatch::Nonce { expected, actual }).into());
                    }
                }
                None => return Err(Validation::Missing(Missing::Nonce).into()),
            }
            None => if claims.nonce.is_some() { 
                return Err(Validation::Missing(Missing::Nonce).into()) 
            }
        }

        if !claims.aud.contains(&self.oauth.client_id) {
            return Err(Validation::Missing(Missing::Audience).into());
        }
        // By spec, if there are multiple auds, we must have an azp
        if let SingleOrMultiple::Multiple(_) = claims.aud {
            if let None = claims.azp {
                return Err(Validation::Missing(Missing::AuthorizedParty).into());
            }
        }
        // If there is an authorized party, it must be our client_id
        if let Some(ref actual) = claims.azp {
            if actual != &self.oauth.client_id {
                let expected = self.oauth.client_id.to_string();
                let actual = actual.to_string();
                return Err(Validation::Mismatch(Mismatch::AuthorizedParty { 
                    expected, actual 
                }).into());
            }
        }

        let now = Utc::now();
        // Now should never be less than the time this code was written!
        if now.timestamp() < 1504758600 {
            panic!("chrono::Utc::now() can never be before this was written!")
        }
        if claims.exp <= now.timestamp() {
            return Err(Validation::Expired(
                Expiry::Expires(
                    chrono::naive::NaiveDateTime::from_timestamp(claims.exp, 0))).into());
        }

        if let Some(max) = max_age {
            match claims.auth_time {
                Some(time) => {
                    let age = chrono::Duration::seconds(now.timestamp() - time);
                    if age >= *max {
                        return Err(error::Validation::Expired(Expiry::MaxAge(age)).into());
                    }
                }
                None => return Err(Validation::Missing(Missing::AuthTime).into()),
            }
        }

        Ok(())
    }

    /// Get a userinfo json document for a given token at the provider's userinfo endpoint.
    /// Errors are:
    ///
    /// - Userinfo::NoUrl if this provider doesn't have a userinfo endpoint
    /// - Error::Insecure if the userinfo url is not https
    /// - Userinfo::MismatchIssuer if the userinfo origin does not match the provider's issuer
    /// - Error::Jose if the token is not decoded
    /// - Error::Http if something goes wrong getting the document
    /// - Error::Json if the response is not a valid Userinfo document
    /// - Userinfo::MismatchSubject if the returned userinfo document and tokens subject mismatch
    pub fn request_userinfo(&self, client: &reqwest::Client, token: &Token
    ) -> Result<Userinfo, Error> {
        match self.config().userinfo_endpoint {
            Some(ref url) => {
                discovery::secure(&url)?;
                if url.origin() != self.config().issuer.origin() {
                    let expected = self.config().issuer.as_str().to_string();
                    let actual = url.as_str().to_string();
                    return Err(error::Userinfo::MismatchIssuer { expected, actual }.into());
                }
                let claims = token.id_token.payload()?;
                let auth_code = token.access_token().to_string();
                let mut resp = client.get(url.clone())
                    .header(header::Authorization(header::Bearer { token: auth_code }))
                    .send()?;
                let info: Userinfo = resp.json()?;
                if claims.sub != info.sub {
                    let expected = info.sub.clone();
                    let actual = claims.sub.clone();
                    return Err(error::Userinfo::MismatchSubject { expected, actual }.into())
                }
                Ok(info)
            }
            None => Err(error::Userinfo::NoUrl.into())
        }
    }
}

/// Optional parameters that [OpenID specifies](https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters) for the auth URI.
/// Derives Default, so remember to ..Default::default() after you specify what you want.
#[derive(Default)]
pub struct Options {
    /// MUST contain openid. By default this is ONLY openid. Official optional scopes are
    /// email, profile, address, phone, offline_access. Check the Discovery config 
    /// `scopes_supported` to see what is available at your provider!
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub display: Option<Display>,
    pub prompt: Option<std::collections::HashSet<Prompt>>,
    pub max_age: Option<Duration>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
}

/// The userinfo struct contains all possible userinfo fields regardless of scope. [See spec.](https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims)
// TODO is there a way to use claims_supported in config to simplify this struct?
#[derive(Deserialize, Validate)]
pub struct Userinfo {
    pub sub: String,
    #[serde(default)] pub name: Option<String>,
    #[serde(default)] pub given_name: Option<String>,
    #[serde(default)] pub family_name: Option<String>,
    #[serde(default)] pub middle_name: Option<String>,
    #[serde(default)] pub nickname: Option<String>,
    #[serde(default)] pub preferred_username: Option<String>,
    #[serde(default)] #[serde(with = "url_serde")] pub profile: Option<Url>,
    #[serde(default)] #[serde(with = "url_serde")] pub picture: Option<Url>,
    #[serde(default)] #[serde(with = "url_serde")] pub website: Option<Url>,
    #[serde(default)] #[validate(email)] pub email: Option<String>,
    #[serde(default)] pub email_verified: Option<bool>,
    // Isn't required to be just male or female
    #[serde(default)] pub gender: Option<String>,
    // ISO 9601:2004 YYYY-MM-DD or YYYY.
    #[serde(default)] pub birthdate: Option<NaiveDate>,
    // Region/City codes. Should also have a more concrete serializer form.
    #[serde(default)] pub zoneinfo: Option<String>,
    // Usually RFC5646 langcode-countrycode, maybe with a _ sep, could be arbitrary
    #[serde(default)] pub locale: Option<String>,
    // Usually E.164 format number
    #[serde(default)] pub phone_number: Option<String>,
    #[serde(default)] pub phone_number_verified: Option<bool>,
    #[serde(default)] pub address: Option<Address>,
    #[serde(default)] pub updated_at: Option<i64>,
}

/// The four values for the preferred display parameter in the Options. See spec for details.
pub enum Display {
    Page,
    Popup,
    Touch,
    Wap,
}

impl Display {
    fn as_str(&self) -> &'static str {
        use Display::*;
        match *self {
            Page => "page",
            Popup => "popup",
            Touch => "touch",
            Wap => "wap",
        }
    }
}

/// The four possible values for the prompt parameter set in Options. See spec for details.
#[derive(PartialEq, Eq, Hash)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl Prompt {
    fn as_str(&self) -> &'static str {
        use Prompt::*;
        match *self {
            None => "none",
            Login => "login",
            Consent => "consent",
            SelectAccount => "select_account",
        }
    }
}

/// Address Claim struct. Can be only formatted, only the rest, or both.
#[derive(Deserialize)]
pub struct Address {
    #[serde(default)] pub formatted: Option<String>,
    #[serde(default)] pub street_address: Option<String>,
    #[serde(default)] pub locality: Option<String>,
    #[serde(default)] pub region: Option<String>,
    // Countries like the UK use alphanumeric postal codes, so you can't just use a number here
    #[serde(default)] pub postal_code: Option<String>,
    #[serde(default)] pub country: Option<String>,
}

#[test]
fn google() {
    let id = "test".to_string();
    let secret = "a secret to everybody".to_string();
    let redirect = Url::parse("https://example.com/re").unwrap();
    let client = Client::discover(id, secret, redirect, issuer::google()).unwrap();
    client.auth_url(&Default::default());
}

#[test]
fn paypal() {
    let id = "test".to_string();
    let secret = "a secret to everybody".to_string();
    let redirect = Url::parse("https://example.com/re").unwrap();
    let client = Client::discover(id, secret, redirect, issuer::paypal()).unwrap();
    client.auth_url(&Default::default());
}

#[test]
fn salesforce() {
    let id = "test".to_string();
    let secret = "a secret to everybody".to_string();
    let redirect = Url::parse("https://example.com/re").unwrap();
    let client = Client::discover(id, secret, redirect, issuer::salesforce()).unwrap();
    client.auth_url(&Default::default());
}