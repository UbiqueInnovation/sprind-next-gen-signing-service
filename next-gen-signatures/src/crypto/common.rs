use json_ld::{
    syntax::{Parse, Value},
    JsonLdProcessor, RemoteDocument, ReqwestLoader,
};
use rdf_types::generator;

pub async fn json_ld_to_rdf(data: &str) -> anyhow::Result<String> {
    let doc = RemoteDocument::new(None, None, Value::parse_str(data)?.0);

    let loader = ReqwestLoader::new();

    let mut generator = generator::Blank::new_with_prefix("b".to_string());

    let mut rdf = doc.to_rdf(&mut generator, &loader).await?;

    Ok(rdf
        .cloned_quads()
        .map(|q| format!("{} .\n", q.to_string()))
        .collect::<String>())
}
