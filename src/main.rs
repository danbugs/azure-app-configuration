use async_std::task;
use azure_app_configuration::client::AzureAppConfigClient;

use azure_app_configuration::search_label::SearchLabel;
use std::collections::HashMap;

fn main() {
    task::block_on(async {
        let az = AzureAppConfigClient::new(
            "https://lande-app-configuration.azconfig.io",
            "0-l9-s0:Z6DMwn2DoiKxgVsTIm7h",
            "wgf9BDWeh/+Dtq8DmpsJSUpwrdgYLrXG8svE+VyM06w=",
        );

        let tag1 = String::from("tag1");
        let value1 = String::from("tag2");
        let mut tags = HashMap::new();
        tags.insert(tag1.as_str(), value1.as_str());
        tags.insert("tag2", "tagvalue2");

        let r = az
            .set_key("Bob", "DesdeRust!!!", SearchLabel::All, Some(tags), None)
            .await;

        println!("{:?}", r);
    })
}
