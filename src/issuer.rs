use reqwest::Url;

const STATIC_URL_ERR: &str = "Static urls should always work!";

// TODO these should all be const, or even better, sttic Urls...a

pub fn google() -> Url {
    Url::parse("https://accounts.google.com").expect(STATIC_URL_ERR)
}

pub fn microsoft() -> Url {
    Url::parse("https://login.microsoftonline.com/common/v2.0/").expect(STATIC_URL_ERR)
}

/// Microsoft online tentant-dependent tokens
///  * `tenant` - Value that can be used to control who can sign into the application.
pub fn microsoft_tenant(tenant: &str) -> Url {
    Url::parse("https://login.microsoftonline.com/")
        .expect(STATIC_URL_ERR)
        .join(tenant)
        .expect("Failed to append tenant")
}

pub fn paypal() -> Url {
    Url::parse("https://www.paypalobjects.com").expect(STATIC_URL_ERR)
}

pub fn salesforce() -> Url {
    Url::parse("https://login.salesforce.com").expect(STATIC_URL_ERR)
}

pub fn yahoo() -> Url {
    Url::parse("https://login.yahoo.com").expect(STATIC_URL_ERR)
}

#[cfg(test)]
mod tests {
    use crate::discovery::discover;
    use reqwest::blocking::Client;

    macro_rules! test {
        ($issuer:ident) => {
            #[test]
            fn $issuer() {
                let client = Client::new();
                discover(&client, super::$issuer()).unwrap();
            }
        };
    }

    test!(google);
    test!(microsoft);
    test!(paypal);
    test!(salesforce);
    test!(yahoo);

    #[test]
    fn microsoft_tenant() {
        let client = ::reqwest::blocking::Client::new();
        crate::discovery::discover(&client, super::microsoft_tenant("common")).unwrap();
    }
}
