use std::collections::{BTreeMap, BTreeSet};

use oxrdf::{NamedNode, Subject};
use rdf_util::{ObjectId, Value};

fn assert_rdf_string_eq<S1: AsRef<str>, S2: AsRef<str>>(left: S1, right: S2) {
    let left = left.as_ref().trim().split("\n").collect::<BTreeSet<&str>>();
    let right = right
        .as_ref()
        .trim()
        .split("\n")
        .collect::<BTreeSet<&str>>();

    assert_eq!(left, right);
}

#[test]
pub fn example() {
    use oxttl::NTriplesParser;

    let source = r#"
<did:example:john> <https://example.org/coolNumber> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<did:example:john> <https://example.org/name> "John Doe" .
<did:example:john> <https://example.org/nested> _:b1 .
_:b1 <https://example.org/test> "John Doe" .
    "#;

    let mut rdf = Value::from(
        NTriplesParser::new()
            .for_reader(source.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    );

    assert_eq!(rdf["https://example.org/name"], "John Doe");

    rdf["https://example.org/birthDate"] = Value::String("2000-01-01".to_string());

    rdf["https://example.org/nested"]["https://example.org/value"] = Value::Object(
        BTreeMap::from([(
            "https://example.org/another".to_string(),
            Value::Typed("one".to_string(), "https://example.org/myType".to_string()),
        )]),
        ObjectId::NamedNode("https://example.org/resource/123".to_string()),
    );

    assert_eq!(rdf["https://example.org/birthDate"], "2000-01-01");

    dbg!(&rdf);

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("a".to_string()),
        r#"<did:example:john> <https://example.org/birthDate> "2000-01-01" .
<did:example:john> <https://example.org/coolNumber> "1337"^^<http://www.w3.org/2001/XMLSchema#integer> .
<did:example:john> <https://example.org/name> "John Doe" .
<did:example:john> <https://example.org/nested> _:b1 .
_:b1 <https://example.org/test> "John Doe" .
_:b1 <https://example.org/value> <https://example.org/resource/123> .
<https://example.org/resource/123> <https://example.org/another> "one"^^<https://example.org/myType> .
"#,
    );

    NTriplesParser::new()
        .for_reader(rdf.to_string().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
}

#[test]
fn test_none_blank_ids() {
    let rdf = Value::Object(
        BTreeMap::from([
            (
                "https://example.org/keys#1".into(),
                Value::Object(
                    BTreeMap::from([(
                        "https://example.org/keys#2".into(),
                        Value::String("value".into()),
                    )]),
                    ObjectId::BlankNode("b1".into()),
                ),
            ),
            (
                "https://example.org/keys#3".into(),
                Value::Object(
                    BTreeMap::from([(
                        "https://example.org/keys#4".into(),
                        Value::String("value".into()),
                    )]),
                    ObjectId::None,
                ),
            ),
        ]),
        ObjectId::None,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("a".into()),
        r#"_:a0 <https://example.org/keys#1> _:b1 .
_:a0 <https://example.org/keys#3> _:a1 .
_:b1 <https://example.org/keys#2> "value" .
_:a1 <https://example.org/keys#4> "value" .
"#,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("b".into()),
        r#"_:b0 <https://example.org/keys#1> _:b1 .
_:b0 <https://example.org/keys#3> _:b2 .
_:b1 <https://example.org/keys#2> "value" .
_:b2 <https://example.org/keys#4> "value" .
"#,
    );
}

#[test]
fn test_parse_hint() {
    let source = r#"
    <did:example:obj1> <https://example.org/relation> <did:example:obj2> .
    <did:example:obj2> <https://example.org/circle> <did:example:obj1> .
        "#;

    let rdf = rdf_util::from_str_with_hint(
        source,
        Subject::NamedNode(NamedNode::new_unchecked("did:example:obj1")),
    )
    .unwrap();

    println!("{:#}", rdf.to_json())
}
