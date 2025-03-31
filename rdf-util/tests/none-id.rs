/// The expected behaviour of `ObjectId::None` is that generally
/// the exact blank id that the object will get doesn't matter,
/// the only thing that matters is that the object will be placed
/// at the correct spot.
use std::collections::BTreeMap;

use rdf_util::{test::assert_rdf_string_eq, ObjectId, Value};

#[test]
pub fn rdf_none_id() {
    let rdf = Value::Object(
        BTreeMap::from([(
            "https://example.org/value".into(),
            Value::String("Hello, World".into()),
        )]),
        // The id of this object will be determined
        // dynamically. (It will be a free blank id)
        ObjectId::None,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("b".into()),
        r#"
        _:b0 <https://example.org/value> "Hello, World" .
        "#,
    );
}

#[test]
pub fn rdf_none_id_skip() {
    let rdf = Value::Object(
        BTreeMap::from([(
            "https://example.org/value".into(),
            Value::ObjectRef(ObjectId::BlankNode("b0".into())),
        )]),
        ObjectId::None,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("b".into()),
        r#"
        _:b1 <https://example.org/value> _:b0 .
        "#,
    );
}

#[test]
pub fn rdf_none_id_no_skip() {
    let rdf = Value::Object(
        BTreeMap::from([(
            "https://example.org/value".into(),
            Value::ObjectRef(ObjectId::BlankNode("b0".into())),
        )]),
        ObjectId::None,
    );

    assert_rdf_string_eq(
        rdf.to_string_with_prefix("a".into()),
        r#"
        _:a0 <https://example.org/value> _:b0 .
        "#,
    );
}

#[test]
fn rdf_none_id_complex() {
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
