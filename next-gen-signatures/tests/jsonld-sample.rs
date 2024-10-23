use iref::IriBuf;
use json_ld::{
    syntax::Print, warning, JsonLdProcessor, Options, RemoteContextReference,
    RemoteDocumentReference, ReqwestLoader,
};
use json_ld::{
    syntax::{Parse, Value},
    RemoteDocument,
};
use next_gen_signatures::crypto::common::json_ld_to_rdf;
use rdf_types::vocabulary::{IndexVocabulary, IriVocabularyMut};
use static_iref::iri;

#[tokio::test]
async fn test_json_ld_to_rdf() {
    let data = r#"
    {
        "@context": "http://schema.org/",
        "@type": "Person",
        "name": "John Doe"
    }"#;

    let rdf = json_ld_to_rdf(data, Some("b".to_string())).await.unwrap();

    println!("{rdf}")
}

#[tokio::test]
async fn jsonld_sample() {
    let doc = RemoteDocument::<IriBuf, Value>::new(
        None,
        None,
        Value::parse_str(
            r#"
{
  "@context": "http://schema.org/",
  "@type": "Person",
  "name": "Jane Doe",
  "jobTitle": "Professor",
  "telephone": "(425) 123-4567",
  "url": "http://www.janedoe.com",
  "stuff": {
    "asdf": "hehe"
  }
}
        "#,
        )
        .unwrap()
        .0,
    );

    let mut loader = ReqwestLoader::new();

    let mut generator = rdf_types::generator::Blank::new_with_prefix("b".to_string());

    let nodes = doc
        .flatten_using(
            &mut generator,
            &mut loader,
            Options {
                ordered: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    println!("{}", nodes.pretty_print());

    let input = RemoteDocument::<IriBuf, Value>::new(None, None, nodes);

    let context = RemoteContextReference::iri(iri!("http://schema.org/").to_owned());

    let mut compact = input
        .compact_using(
            context,
            &mut loader,
            Options {
                ..Default::default()
            },
        )
        .await
        .expect("compaction failed");

    *compact
        .as_object_mut()
        .unwrap()
        .get_mut_or_insert_with("@context", || Value::Null) =
        Value::String("http://schema.org/".into());

    println!("output: {}", compact.pretty_print());
}

#[tokio::test]
async fn jsonld_test() {
    // Creates the vocabulary that will map each `rdf_types::vocabulary::Index`
    // to an actual `IriBuf`.
    let mut vocabulary: IndexVocabulary = IndexVocabulary::new();

    let iri_index = vocabulary.insert(iri!("https://example.com/sample.jsonld"));
    let input = RemoteDocumentReference::iri(iri_index);

    // Use `FsLoader` to redirect any URL starting with `https://example.com/` to
    // the local `example` directory. No HTTP query.
    let mut loader = json_ld::FsLoader::default();
    loader.mount(iri!("https://example.com/").to_owned(), "examples");

    let mut generator = rdf_types::generator::Blank::new();

    let nodes = input
        .flatten_full(
            &mut vocabulary,
            &mut generator,
            None,
            &loader,
            Options::default(),
            warning::PrintWith,
        )
        .await
        .expect("flattening failed");

    println!("{}", nodes.pretty_print());
}
