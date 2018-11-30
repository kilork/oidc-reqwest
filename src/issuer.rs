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

/// Microsoft online tentant-dependent tokens
///  * `tenant` - Value that can be used to control who can sign into the application.
pub fn microsoft(tenant: &str) -> Url {
    Url::parse("https://login.microsoftonline.com/")
        .expect("Static urls should always work!")
        .join(tenant)
        .expect("Failed to append tenant")
}

/// For Microsoft online tenant-independent tokens
pub fn microsoft_common() -> Url {
    Url::parse("https://login.microsoftonline.com/common")
        .expect("Static urls should always work!")
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

#[test]
fn microsoft_disco() {
    let client = ::reqwest::Client::new();
    ::discovery::discover(&client, microsoft("common")).unwrap();
}

#[test]
fn microsoft_disco_common() {
    let client = ::reqwest::Client::new();
    ::discovery::discover(&client, microsoft_common()).unwrap();
}