use oxrdf::{Subject, Term};
use oxttl::NQuadsParser;
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;

// JSON-LD Graph representation struct
#[derive(Default)]
pub struct JsonLdGraph {
    nodes: HashMap<String, JsonValue>,
    context: HashMap<String, String>,
}

impl JsonLdGraph {
    fn new() -> Self {
        JsonLdGraph {
            nodes: HashMap::new(),
            context: HashMap::new(),
        }
    }

    fn create_node(&mut self, id: &str) -> JsonValue {
        self.nodes
            .entry(id.to_string())
            .or_insert_with(|| json!({"@id": id}))
            .clone()
    }

    fn add_type(&mut self, id: &str, type_value: &str) {
        if let Some(node) = self.nodes.get_mut(id) {
            node["@type"] = json!(type_value);
        }
    }

    fn add_property_value(&mut self, id: &str, property: &str, value: JsonValue) {
        if let Some(node) = self.nodes.get_mut(id) {
            node[property] = value;
        }
    }

    fn add_to_context(&mut self, property_uri: &str) {
        // Generate a short name from the URI, e.g., use the last segment after '#', '/', or ':' as an alias
        let short_name = property_uri
            .rsplit(|c| c == '#' || c == '/' || c == ':')
            .next()
            .unwrap();
        self.context
            .entry(short_name.to_string())
            .or_insert_with(|| property_uri.to_string());
    }

    fn to_jsonld(&self) -> JsonValue {
        json!({
            "@graph": self.nodes.values().collect::<Vec<_>>()
        })
    }

    pub fn get_context(&self) -> HashMap<String, String> {
        self.context.clone()
    }
}

// Function to convert RDF to JSON-LD and extract context
fn rdf_to_jsonld(rdf_data: &str) -> JsonLdGraph {
    let quads = NQuadsParser::new()
        .for_reader(rdf_data.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let mut json_ld_graph = JsonLdGraph::new();

    for quad in quads {
        let subject_id = match quad.subject {
            Subject::NamedNode(node) => node.into_string(),
            Subject::BlankNode(blank) => blank.to_string(),
        };

        let predicate = quad.predicate.into_string();
        let object = match quad.object {
            Term::Literal(lit) => {
                if lit.datatype().as_str() == "http://www.w3.org/2001/XMLSchema#string" {
                    json!({
                        "@value": lit.value().to_string()
                    })
                } else {
                    json!({
                        "@value": lit.value().to_string(),
                        "@type": lit.datatype().as_str(),
                    })
                }
            }
            Term::NamedNode(node) => {
                json!({"@id": node.into_string()})
            }
            Term::BlankNode(node) => {
                json!({"@id": node.to_string()})
            }
        };

        // Ensure the subject node is created before adding data
        json_ld_graph.create_node(&subject_id);

        // Add to context
        json_ld_graph.add_to_context(&predicate);

        // Check if the predicate is "type" to handle as a type or as a property
        if predicate == "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" {
            json_ld_graph.add_type(&subject_id, &object["@id"].as_str().unwrap());
        } else {
            json_ld_graph.add_property_value(&subject_id, &predicate, object);
        }
    }

    json_ld_graph
}

#[derive(linked_data::Deserialize, serde::Serialize)]
struct Foo {
    #[ld("http://schema.org/name")]
    name: String,
}

// Test function to print the JSON-LD output with context
#[test]
fn test_rdf_to_jsonld() {
    const RDF: &str = r#"
<acct:sally@example.org> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Person> .
<acct:sally@example.org> <https://www.w3.org/ns/activitystreams#icon> _:b1 .
<acct:sally@example.org> <https://www.w3.org/ns/activitystreams#name> "Sally" .
_:b0 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Create> .
_:b0 <https://www.w3.org/ns/activitystreams#actor> <acct:sally@example.org> .
_:b0 <https://www.w3.org/ns/activitystreams#object> _:b2 .
_:b0 <https://www.w3.org/ns/activitystreams#published> "2015-01-25T12:34:56Z"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:b1 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Image> .
_:b1 <https://www.w3.org/ns/activitystreams#height> "16"^^<http://www.w3.org/2001/XMLSchema#nonNegativeInteger> .
_:b1 <https://www.w3.org/ns/activitystreams#name> "Note icon" .
_:b1 <https://www.w3.org/ns/activitystreams#url> <http://example.org/note.png> .
_:b1 <https://www.w3.org/ns/activitystreams#width> "16"^^<http://www.w3.org/2001/XMLSchema#nonNegativeInteger> .
_:b2 <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/ns/activitystreams#Note> .
_:b2 <https://www.w3.org/ns/activitystreams#content> "This is a simple note" .
"#;

    let graph = rdf_to_jsonld(RDF);

    println!(
        "{}",
        serde_json::to_string_pretty(&graph.to_jsonld()).unwrap()
    );
}
