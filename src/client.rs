use biscuit::Empty;
use biscuit::jwk::JWKSet;
use chrono::{Duration, Utc};
use inth_oauth2;
use url::Url;
use url_serde;
use validator::Validate;

use std::collections::HashSet;

use discovery::{self, Config, Discovered};
use error::{ErrorKind, Result};
use token::{Expiring, Token};

#[derive(Deserialize)]
pub struct Params {
    pub client_id: String,
    pub client_secret: String,
    #[serde(with = "url_serde")]
    pub redirect_url: Url,
}

/// Optional parameters that [OpenID specifies](https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters) for the auth URI.
/// Derives Default, so remember to ..Default::default() after you specify what you want.
#[derive(Default)]
pub struct Options {
    pub  nonce: Option<String>,
    pub display: Option<Display>,
    pub prompt: Option<HashSet<Prompt>>,
    pub max_age: Option<Duration>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
}

pub enum Display {
    Page,
    Popup,
    Touch,
    Wap,
}

impl Display {
    fn as_str(&self) -> &'static str {
        match *self {
            Display::Page => "page",
            Display::Popup => "popup",
            Display::Touch => "touch",
            Display::Wap => "wap",
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl Prompt {
    fn as_str(&self) -> &'static str {
        match self {
            &Prompt::None => "none",
            &Prompt::Login => "login",
            &Prompt::Consent => "consent",
            &Prompt::SelectAccount => "select_account",
        }
    }
}

/// The userinfo struct contains all possible userinfo fields regardless of scope. [See spec.](https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims)
// TODO is there a way to use claims_supported in config to simplify this struct?
#[derive(Deserialize, Validate)]
pub struct Userinfo {
    pub sub: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    #[serde(with = "url_serde")]
    pub profile: Option<Url>,
    #[serde(with = "url_serde")]
    pub picture: Option<Url>,
    #[serde(with = "url_serde")]
    pub website: Option<Url>,
    #[validate(email)]
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    // Isn't required to be just male or female
    pub gender: Option<String>,
    // ISO 9601:2004 YYYY-MM-DD or YYYY. Would be nice to serialize to chrono::Date.
    pub birthdate: Option<String>,
    // Region/City codes. Should also have a more concrete serializer form.
    pub zoneinfo: Option<String>,
    // Usually RFC5646 langcode-countrycode, maybe with a _ sep, could be arbitrary
    pub locale: Option<String>,
    // Usually E.164 format number
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<Address>,
    pub updated_at: Option<i64>,
}

/// Address Claim struct. Can be only formatted, only the rest, or both.
#[derive(Deserialize)]
pub struct Address {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    // Countries like the UK use alphanumeric postal codes, so you can't just use a number here
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

pub struct Client {
    oauth: inth_oauth2::Client<Discovered>,
    jwks: JWKSet<Empty>,
}

impl Client {
    /// Constructs a client from an issuer url and client parameters via discovery
    pub fn discover(issuer: &Url, params: Params) -> Result<Self> {
        let config = discovery::discover(issuer)?;
        let jwks = discovery::jwks(&config.jwks_uri)?;
        let provider = Discovered { config };
        Ok(Self::new(provider, params, jwks))
    }

    /// Constructs a client from a given provider, key set, and parameters. Unlike ::discover(..) 
    /// this function does not perform any network operations.
    fn new(provider: Discovered, params: Params, jwks: JWKSet<Empty>) -> Self {
        Client {
            oauth: inth_oauth2::Client::new(
                provider, 
                params.client_id, 
                params.client_secret,
                Some(params.redirect_url.into_string())),
            jwks
        }
    }

    /// A reference to the config document of the provider obtained via discovery
    pub fn config(&self) -> &Config {
        &self.oauth.provider.config
    }

    /// Constructs the auth_url to redirect a client to the provider. Options are... optional. Use 
    /// them as needed. Keep the Options struct around  for authentication, or at least the nonce 
    /// and max_age parameter - we need to verify they stay the same and validate if you used them.
    pub fn auth_url(&self, scope: &str, state: &str, options: &Options) -> Result<Url>{
        if !scope.contains("openid") {
            return Err(ErrorKind::MissingOpenidScope.into())
        }
        let mut url = self.oauth.auth_uri(Some(&scope), Some(state))?;
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
        Ok(url)
    }

    /// Given an auth_code, request the token, validate it, and if userinfo_endpoint exists
    /// request that and give the response
    pub fn authenticate(&self, auth_code: &str, options: &Options
    ) -> Result<(Token<Expiring>, Option<Userinfo>)> {
        unimplemented!()
    }
}