use reqwest::Url;

// TODO these should all be const, or even better, static Urls...

pub fn google() -> Url {
    Url::parse("https://accounts.google.com").unwrap()
}

pub fn paypal() -> Url {
    Url::parse("https://www.paypalobjects.com/").unwrap()
}

pub fn salesforce() -> Url {
    Url::parse("https://login.salesforce.com").unwrap()
}

#[test]
fn google_disco() {
    let client = ::reqwest::Client::new().unwrap();
    ::discovery::discover(&client, google()).unwrap();
}

#[test]
fn paypal_disco() {
    let client = ::reqwest::Client::new().unwrap();
    ::discovery::discover(&client, paypal()).unwrap();
}

#[test]
fn salesforce_disco() {
    let client = ::reqwest::Client::new().unwrap();
    ::discovery::discover(&client, salesforce()).unwrap();
}