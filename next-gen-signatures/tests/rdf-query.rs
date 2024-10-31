use next_gen_signatures::rdf::RdfQuery;
use oxrdf::{GraphName, NamedNode, Term};

#[test]
fn test_rdf_query() {
    const RDF: &str = r#"
_:c14n0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Image> .
_:c14n0 <https://www.w3.org/ns/activitystreams#height> "16"^^<http://www.w3.org/2001/XMLSchema#nonNegativeInteger> .
_:c14n0 <https://www.w3.org/ns/activitystreams#name> "Note icon" .
_:c14n0 <https://www.w3.org/ns/activitystreams#url> <http://example.org/note.png> .
_:c14n0 <https://www.w3.org/ns/activitystreams#width> "16"^^<http://www.w3.org/2001/XMLSchema#nonNegativeInteger> .
_:c14n1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Create> .
_:c14n1 <https://www.w3.org/ns/activitystreams#actor> _:c14n3 .
_:c14n1 <https://www.w3.org/ns/activitystreams#object> _:c14n2 .
_:c14n1 <https://www.w3.org/ns/activitystreams#published> "2015-01-25T12:34:56Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:c14n2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Note> .
_:c14n2 <https://www.w3.org/ns/activitystreams#content> "This is a simple note" .
_:c14n3 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Person> .
_:c14n3 <https://www.w3.org/ns/activitystreams#icon> _:c14n0 .
_:c14n3 <https://www.w3.org/ns/activitystreams#name> "Sally" .
    "#;

    let graph = RdfQuery::new(RDF).expect("Failed to parse rdf quads!");

    let json = graph.to_json(
        Some(GraphName::DefaultGraph),
        Some(vec![Term::NamedNode(
            NamedNode::new("https://www.w3.org/ns/activitystreams#Create").unwrap(),
        )]),
        Some(vec!["https://www.w3.org/ns/activitystreams".to_string()]),
    );

    println!("{json:#}");
}
