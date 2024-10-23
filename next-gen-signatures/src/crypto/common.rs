use json_ld::{
    syntax::{Parse, Value},
    JsonLdProcessor, RemoteDocument, ReqwestLoader,
};
use oxrdf::Graph;
use oxttl::NTriplesParser;
use rdf_types::generator;

pub async fn json_ld_to_rdf(data: &str, prefix: Option<String>) -> anyhow::Result<String> {
    let doc = RemoteDocument::new(None, None, Value::parse_str(data)?.0);

    let loader = ReqwestLoader::new();

    let mut generator = if let Some(prefix) = prefix {
        generator::Blank::new_with_prefix(prefix)
    } else {
        generator::Blank::new()
    };

    let mut rdf = doc.to_rdf(&mut generator, &loader).await?;

    Ok(rdf
        .cloned_quads()
        .map(|q| format!("{} .\n", q.to_string()))
        .collect::<String>())
}

pub fn get_graph_from_ntriples(ntriples: &str) -> anyhow::Result<Graph> {
    let iter = NTriplesParser::new()
        .for_reader(ntriples.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Graph::from_iter(iter))
}
