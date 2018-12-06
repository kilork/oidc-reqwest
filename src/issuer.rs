use reqwest::Url;

const STATIC_URL_ERR_MSG: &str = "Static urls should always work!";

// TODO these should all be const, or even better, sttic Urls...a

pub fn google() -> Url {
    Url::parse("https://accounts.google.com").expect(STATIC_URL_ERR_MSG)
}

pub fn microsoft() -> Url {
    Url::parse("https://login.microsoftonline.com/common/v2.0").expect(STATIC_URL_ERR_MSG)
}

pub fn paypal() -> Url {
    Url::parse("https://www.paypalobjects.com/").expect(STATIC_URL_ERR_MSG)
}

pub fn salesforce() -> Url {
    Url::parse("https://login.salesforce.com").expect(STATIC_URL_ERR_MSG)
}

pub fn yahoo() -> Url {
    Url::parse("https://login.yahoo.com").expect(STATIC_URL_ERR_MSG)
}

#[cfg(test)]
mod tests {
    use reqwest::Client;
    use discovery::discover;

    #[test]
    fn google_disco() {
        let client = Client::new();
        discover(&client, super::google()).unwrap();
    }

    #[test]
    fn microsoft_disco() {
        let client = Client::new();
        let res = discover(&client, super::microsoft());
        println!("Result: {:?}", res);
        res.unwrap();
    }

    #[test]
    fn paypal_disco() {
        let client = Client::new();
        discover(&client, super::paypal()).unwrap();
    }

    #[test]
    fn salesforce_disco() {
        let client = Client::new();
        discover(&client, super::salesforce()).unwrap();
    }

    #[test]
    fn yahoo_disco() {
        let client = Client::new();
        discover(&client, super::yahoo()).unwrap();
    }
}
