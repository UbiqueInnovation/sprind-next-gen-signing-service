use crate::{ObjectId, Value};

use serde_json::{json, Value as JsonValue};

impl Value {
    pub fn to_json(&self) -> JsonValue {
        match self {
            Value::String(s) => json!(s),
            Value::Typed(v, t) => json!({ "@value": v, "@type": t }),
            Value::Object(map, id) => {
                let mut body = json!({});

                for (key, value) in map {
                    body[key] = value.to_json();
                }

                if let ObjectId::NamedNode(id) = id {
                    body["@id"] = json!(id);
                }

                body
            }
            Value::ObjectRef(id) => match id {
                ObjectId::None => json!({}),
                ObjectId::NamedNode(id) | ObjectId::BlankNode(id) => json!({ "@id": id }),
            },
        }
    }
}
