use biscuit::{Empty, SingleOrMultiple};
use biscuit::jwa::{self, SignatureAlgorithm};
use biscuit::jwk::{AlgorithmParameters, JWKSet};
use biscuit::jws::{Compact, Secret};
use chrono::{Duration, Utc};
use inth_oauth2;
use reqwest::{self, Url};
use url_serde;
use validator::Validate;

use std::collections::HashSet;

use discovery::{self, Config, Discovered};
use error::{self, Decode, Error, Expiry, Mismatch, Missing, Validation};
use token::{Claims, Expiring, Token};

type IdToken = Compact<Claims, Empty>;

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

pub struct Client {
    oauth: inth_oauth2::Client<Discovered>,
    jwks: JWKSet<Empty>,
}

impl Client {
    /// Constructs a client from an issuer url and client parameters via discovery
    pub fn discover(issuer: Url, params: Params) -> Result<Self, Error> {
        let client = reqwest::Client::new()?;
        let config = discovery::discover(&client, issuer)?;
        let jwks = discovery::jwks(&client, config.jwks_uri.clone())?;
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

    pub fn request_token(&self,
                         client: &reqwest::Client,
                         auth_code: &str,
    ) -> Result<Token<Expiring>, error::Oauth> {
        self.oauth.request_token(client, auth_code)
    }

    /// A reference to the config document of the provider obtained via discovery
    pub fn config(&self) -> &Config {
        &self.oauth.provider.config
    }

    /// Constructs the auth_url to redirect a client to the provider. Options are... optional. Use 
    /// them as needed. Keep the Options struct around  for authentication, or at least the nonce 
    /// and max_age parameter - we need to verify they stay the same and validate if you used them.
    pub fn auth_url(&self, scope: &str, state: &str, options: &Options) -> Result<Url, Error>{
        if !scope.contains("openid") {
            unimplemented!()
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

    /// Given an auth_code and auth options, request the token, decode, and validate it.
    pub fn authenticate(&self, auth_code: &str, options: &Options
    ) -> Result<Token<Expiring>, Error> {
        let client = reqwest::Client::new()?;
        let mut token = self.request_token(&client, auth_code)?;
        self.decode_token(&mut token.id_token)?;
        self.validate_token(&token.id_token, 
            options.nonce.as_ref().map(String::as_ref), 
            options.max_age.as_ref())?;
        Ok(token)
    }

    pub fn decode_token(&self, token: &mut IdToken) -> Result<(), Error> {
        // This is an early escape if the token is already decoded
        token.encoded()?;

        let header = token.unverified_header()?;
        // If there is more than one key, the token MUST have a key id
        let key = if self.jwks.keys.len() > 1 {
            let token_kid = header.registered.key_id.ok_or(Decode::MissingKid)?;
            self.jwks.find(&token_kid).ok_or(Decode::MissingKey)?
        } else {
            self.jwks.keys.first().as_ref().ok_or(Decode::EmptySet)?
        };

        if let Some(alg) = key.common.algorithm.as_ref() {
            if let &jwa::Algorithm::Signature(alg) = alg {
                if header.registered.algorithm != alg {
                    return wrong_key!(alg, header.registered.algorithm);
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

    pub fn validate_token(
        &self, 
        token: &IdToken, 
        nonce: Option<&str>, 
        max_age: Option<&Duration>
    ) -> Result<(), Error> {
        let claims = token.payload()?;

        if claims.iss != self.config().issuer {
            return Err(Validation::Mismatch(Mismatch::Issuer).into());
        }

        if let Some(ref nonce) = nonce {
            match claims.nonce {
                Some(ref test) => {
                    if test != nonce {
                        return Err(Validation::Mismatch(Mismatch::Nonce).into());
                    }
                }
                None => return Err(Validation::Missing(Missing::Nonce).into()),
            }
        }

        if !claims.aud.contains(&self.oauth.client_id) {
            return Err(Validation::Mismatch(Mismatch::Audience).into());
        }
        // By spec, if there are multiple auds, we must have an azp
        if let SingleOrMultiple::Multiple(_) = claims.aud {
            if let None = claims.azp {
                return Err(Validation::Missing(Missing::AuthorizedParty).into());
            }
        }
        // If there is an authorized party, it must be our client_id
        if let Some(ref azp) = claims.azp {
            if azp != &self.oauth.client_id {
                return Err(Validation::Mismatch(Mismatch::Authorized).into());
            }
        }

        let now = Utc::now();
        // Now should never be less than the time this code was written!
        if now.timestamp() < 1504758600 {
            panic!("chrono::Utc::now() can never be before this was written!")
        }
        if claims.exp <= now.timestamp() {
            return Err(Validation::Expired(Expiry::Expires).into());
        }

        if let Some(age) = max_age {
            match claims.auth_time {
                Some(time) => {
                    // This is not currently risky business. That could change.
                    if time >= (now - *age).timestamp() {
                        return Err(error::Validation::Expired(error::Expiry::MaxAge).into());
                    }
                }
                None => return Err(Validation::Missing(Missing::AuthTime).into()),
            }
        }

        Ok(())
    }

    pub fn request_userinfo(&self, client: &reqwest::Client, token: &Token<Expiring>) -> Result<Userinfo, Error> {
        match self.config().userinfo_endpoint {
            Some(ref url) => {
                if url.origin() != self.config().issuer.origin() {
                    return Err(error::Userinfo::MismatchIssuer.into());
                }
                unimplemented!()
            }
            None => Err(error::Userinfo::NoUrl.into())
        }
    }
}