use std::collections::BTreeMap;

use rdf_util::{test::assert_rdf_string_eq, ObjectId, Value};

#[test]
fn rdf_array() {
    let source = r#"
        _:b0 <https://example.org/value> "Hello" .
        _:b0 <https://example.org/value> "World" .
        "#;

    let rdf = rdf_util::from_str(source).unwrap();

    assert_eq!(
        rdf["https://example.org/value"],
        Value::Array(vec![
            Value::String("Hello".into()),
            Value::String("World".into())
        ])
    );
}

#[test]
fn rdf_nested_array() {
    // There is no such thing as "nested arrays" in rdf
    // thus they will be flattened when serializing.

    let rdf = Value::Object(
        BTreeMap::from([(
            "https://example.org/value".into(),
            Value::Array(vec![Value::Array(vec![
                Value::String("Hello".into()),
                Value::String("World".into()),
            ])]),
        )]),
        ObjectId::None,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("b".into()),
        r#"
        _:b0 <https://example.org/value> "Hello" .
        _:b0 <https://example.org/value> "World" .
        "#,
    );
}
