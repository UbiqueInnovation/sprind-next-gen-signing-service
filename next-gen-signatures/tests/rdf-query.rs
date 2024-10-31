use oxrdf::{GraphName, NamedNode, Quad, Subject, Term};
use oxttl::NQuadsParser;
use serde_json::{json, Value as JsonValue};
use std::{collections::HashMap, fmt::Write};

const TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

#[derive(Debug, Clone)]
pub struct RdfQuery {
    quads: Vec<Quad>,
}

impl RdfQuery {
    pub fn new(source: &str) -> Self {
        let quads = NQuadsParser::new()
            .for_reader(source.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        Self { quads }
    }

    pub fn is_empty(&self) -> bool {
        self.quads.is_empty()
    }

    pub fn entries(&self) -> HashMap<String, Term> {
        fn resolve_key(key: NamedNode) -> String {
            let mut key = key.into_string();
            if key == TYPE {
                key = "type".to_string();
            }
            key
        }

        self.quads
            .iter()
            .map(|q| (resolve_key(q.predicate.clone()), q.object.clone()))
            .collect::<HashMap<_, _>>()
    }

    pub fn get_graph_by_name(&self, name: GraphName) -> Self {
        let quads = self
            .quads
            .iter()
            .filter(|quad| quad.graph_name == name)
            .cloned()
            .collect::<Vec<_>>();

        Self { quads }
    }

    pub fn get_graph_by_subjects(&self, subjects: Vec<Subject>) -> Self {
        let quads = self
            .quads
            .iter()
            .filter(|q| subjects.contains(&q.subject))
            .cloned()
            .collect::<Vec<_>>();

        Self { quads }
    }

    pub fn get_graph_by_types(&self, types: Vec<Term>) -> Self {
        let subjects = self
            .quads
            .iter()
            .filter_map(|q| {
                (q.predicate.clone().into_string() == TYPE && types.contains(&q.object))
                    .then_some(q.subject.clone())
            })
            .collect::<Vec<_>>();
        self.get_graph_by_subjects(subjects)
    }

    pub fn to_rdf_string(&self) -> String {
        self.quads.iter().fold(String::new(), |mut output, q| {
            writeln!(output, "{q} .").unwrap();
            output
        })
    }

    fn to_json_impl(&self, lookup: &RdfQuery, context: &Option<Vec<String>>) -> JsonValue {
        let resolve_ctx = |key: String| -> String {
            if let Some(context) = context.as_ref() {
                if let Some(context) = context
                    .iter()
                    .find(|ctx| key.starts_with(&format!("{ctx}#")))
                {
                    key.clone().split_off(context.len() + 1)
                } else {
                    key
                }
            } else {
                key
            }
        };

        let entries = self
            .entries()
            .into_iter()
            .map(|(k, v)| {
                if k == "type" {
                    return (
                        k,
                        JsonValue::String(resolve_ctx(match v {
                            Term::Literal(lit) => lit.value().to_string(),
                            Term::NamedNode(node) => node.into_string(),
                            Term::BlankNode(node) => node.to_string(),
                        })),
                    );
                }

                let k = resolve_ctx(k);

                match v {
                    Term::Literal(val) => (k, JsonValue::String(val.value().to_string())),
                    Term::BlankNode(node) => {
                        let mut graph =
                            lookup.get_graph_by_name(GraphName::BlankNode(node.clone()));
                        if graph.is_empty() {
                            graph = lookup
                                .get_graph_by_subjects(vec![Subject::BlankNode(node.clone())]);
                        }

                        if graph.is_empty() {
                            (k, JsonValue::String(node.to_string()))
                        } else {
                            (k, graph.to_json_impl(lookup, context))
                        }
                    }
                    Term::NamedNode(node) => {
                        let mut graph =
                            lookup.get_graph_by_name(GraphName::NamedNode(node.clone()));
                        if graph.is_empty() {
                            graph = lookup
                                .get_graph_by_subjects(vec![Subject::NamedNode(node.clone())]);
                        }

                        if graph.is_empty() {
                            (k, JsonValue::String(node.into_string()))
                        } else {
                            (k, graph.to_json_impl(lookup, context))
                        }
                    }
                }
            })
            .collect::<HashMap<_, _>>();

        json!(entries)
    }

    pub fn to_json(
        &self,
        graph_name: Option<GraphName>,
        types: Option<Vec<Term>>,
        context: Option<Vec<String>>,
    ) -> JsonValue {
        let mut lookup = self.clone();
        if let Some(graph_name) = graph_name {
            lookup = lookup.get_graph_by_name(graph_name);
        }
        if let Some(types) = types {
            lookup = lookup.get_graph_by_types(types);
        }

        let mut json = lookup.to_json_impl(self, &context);

        if let Some(context) = context {
            json["@context"] = JsonValue::Array(
                context
                    .into_iter()
                    .map(|k| JsonValue::String(k.to_string()))
                    .collect::<Vec<_>>(),
            );
        }

        json
    }
}

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

    let graph = RdfQuery::new(RDF);

    let json = graph.to_json(
        Some(GraphName::DefaultGraph),
        Some(vec![Term::NamedNode(
            NamedNode::new("https://www.w3.org/ns/activitystreams#Create").unwrap(),
        )]),
        Some(vec!["https://www.w3.org/ns/activitystreams".to_string()]),
    );

    println!("{json:#}");
}
