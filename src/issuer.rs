use reqwest::Url;

// TODO these should all be const, or even better, static Urls...

pub fn google() -> Url {
    Url::parse("https://accounts.google.com").expect("Static urls should always work!")
}

pub fn paypal() -> Url {
    Url::parse("https://www.paypalobjects.com/").expect("Static urls should always work!")
}

pub fn salesforce() -> Url {
    Url::parse("https://login.salesforce.com").expect("Static urls should always work!")
}

#[test]
fn google_disco() {
    let client = ::reqwest::Client::new();
    ::discovery::discover(&client, google()).unwrap();
}

#[test]
fn paypal_disco() {
    let client = ::reqwest::Client::new();
    ::discovery::discover(&client, paypal()).unwrap();
}

#[test]
fn salesforce_disco() {
    let client = ::reqwest::Client::new();
    ::discovery::discover(&client, salesforce()).unwrap();
}