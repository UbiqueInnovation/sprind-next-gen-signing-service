use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
};

use json_ld::{syntax::Parse as _, JsonLdProcessor as _, RemoteDocument, ReqwestLoader};
use oxrdf::{Graph, GraphName, NamedNode, Quad, Subject, Term, Triple};
use oxttl::NQuadsParser;
use rdf_types::generator;
use serde_json::{json, Value as JsonValue};

const TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

#[derive(Debug, Clone)]
pub struct RdfQuery {
    pub quads: Vec<Quad>,
}

#[derive(Debug, Clone)]
pub enum RdfValue {
    Graph(RdfQuery),
    Value(String),
}

impl RdfValue {
    pub fn as_graph(self) -> Result<RdfQuery, Self> {
        match self {
            RdfValue::Graph(graph) => Ok(graph),
            _ => Err(self),
        }
    }

    pub fn as_value(self) -> Result<String, Self> {
        match self {
            RdfValue::Value(value) => Ok(value),
            _ => Err(self),
        }
    }
}

impl RdfQuery {
    pub fn new(source: &str) -> anyhow::Result<Self> {
        let quads = NQuadsParser::new()
            .for_reader(source.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { quads })
    }

    pub async fn from_jsonld(data: &str, prefix: Option<String>) -> anyhow::Result<Self> {
        let doc = RemoteDocument::new(None, None, json_ld::syntax::Value::parse_str(data)?.0);

        let loader = ReqwestLoader::new();

        let mut generator = if let Some(prefix) = prefix {
            generator::Blank::new_with_prefix(prefix)
        } else {
            generator::Blank::new()
        };

        let mut rdf = doc.to_rdf(&mut generator, &loader).await?;

        let rdf = rdf.cloned_quads().fold(String::new(), |mut output, q| {
            let _ = writeln!(output, "{q} .");
            output
        });

        Self::new(&rdf)
    }

    pub fn is_empty(&self) -> bool {
        self.quads.is_empty()
    }

    pub fn ids(&self) -> Vec<String> {
        self.quads
            .iter()
            .filter_map(|q| match &q.subject {
                Subject::NamedNode(n) => Some(n.clone().into_string()),
                _ => None,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    }

    pub fn get(&self, subject: Option<Subject>, predicate: NamedNode) -> Option<Term> {
        self.quads
            .iter()
            .find(|q| {
                subject.as_ref().map(|s| &q.subject == s).unwrap_or(true)
                    && q.predicate == predicate
            })
            .map(|t| t.object.clone())
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

    pub fn get_value(&self, predicate: NamedNode, root: Option<&RdfQuery>) -> Option<RdfValue> {
        let root = root.unwrap_or(self);

        let object = root
            .quads
            .iter()
            .find_map(|q| (q.predicate == predicate).then_some(q.object.clone()))?;

        Some(match object {
            Term::Literal(lit) => RdfValue::Value(format!(
                "\"{}\"^^{}",
                lit.value().to_string(),
                lit.datatype().to_string()
            )),
            Term::BlankNode(node) => {
                let graph = self.get_graph_by_subjects(vec![Subject::BlankNode(node.clone())]);
                if graph.is_empty() {
                    RdfValue::Value(node.to_string())
                } else {
                    RdfValue::Graph(graph)
                }
            }
            Term::NamedNode(node) => {
                let graph = self.get_graph_by_subjects(vec![Subject::NamedNode(node.clone())]);
                if graph.is_empty() {
                    RdfValue::Value(node.to_string())
                } else {
                    RdfValue::Graph(graph)
                }
            }
        })
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

        let mut entries = self
            .entries()
            .into_iter()
            .map(|(k, v)| {
                if k == "type" {
                    return (
                        "@type".to_string(),
                        JsonValue::String(resolve_ctx(match v {
                            Term::Literal(lit) => lit.value().to_string(),
                            Term::NamedNode(node) => node.into_string(),
                            Term::BlankNode(node) => node.to_string(),
                        })),
                    );
                }

                let k = resolve_ctx(k);

                match v {
                    Term::Literal(val) => (
                        k,
                        json!({
                            "@type": val.datatype().as_str(),
                            "@value": val.value().to_string()
                        }),
                    ),
                    Term::BlankNode(node) => {
                        let mut graph =
                            lookup.get_graph_by_name(GraphName::BlankNode(node.clone()));
                        if graph.is_empty() {
                            graph = lookup
                                .get_graph_by_subjects(vec![Subject::BlankNode(node.clone())]);
                        }

                        if graph.is_empty() {
                            (
                                k,
                                json!({
                                    "@id": node.to_string(),
                                }),
                            )
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
                            (
                                k,
                                json!({
                                    "@id": node.into_string(),
                                }),
                            )
                        } else {
                            (k, graph.to_json_impl(lookup, context))
                        }
                    }
                }
            })
            .collect::<HashMap<_, _>>();

        let ids = self.ids();
        if let Some(id) = ids.first() {
            if ids.len() < 2 {
                entries.insert("@id".to_string(), json!(id));
            }
        }

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

    pub fn as_graph(&self, graph_name: GraphName) -> Graph {
        Graph::from_iter(self.quads.iter().filter_map(|q| {
            (q.graph_name == graph_name).then_some(Triple::new(
                q.subject.clone(),
                q.predicate.clone(),
                q.object.clone(),
            ))
        }))
    }
}
