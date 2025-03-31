/// The RDF format allows for circular relations, while this is powerful
/// it creates problem when you want to index things. By giving a "hint"
/// to the parser, it knows which element should be the root one, and
/// the circular relation is resolved using an `Value::ObjectRef`, which
/// just "points" to the other object.
use oxrdf::{NamedNode, Subject};
use serde_json::json;

#[test]
fn rdf_parse_hint() {
    let source = r#"
    <did:example:obj1> <https://example.org/relation> <did:example:obj2> .
    <did:example:obj2> <https://example.org/circle> <did:example:obj1> .
        "#;

    let rdf = rdf_util::from_str_with_hint(
        source,
        Subject::NamedNode(NamedNode::new_unchecked("did:example:obj1")),
    )
    .unwrap();

    assert_eq!(
        rdf.to_json(),
        json!({
          "@id": "did:example:obj1",
          "https://example.org/relation": {
            "@id": "did:example:obj2",
            "https://example.org/circle": {
              "@id": "did:example:obj1"
            }
          }
        })
    );
}
