use std::collections::{BTreeMap, BTreeSet};

use oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Subject, Term, Triple};
use serde::{Deserialize, Serialize};

use crate::BlankGenerator;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectId {
    None,
    BlankNode(String),
    NamedNode(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Typed(String, String),
    Object(BTreeMap<String, Value>, ObjectId),
    ObjectRef(ObjectId),
    Array(Vec<Value>),
}

impl Value {
    pub(crate) fn taken_blank_ids(&self) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();

        let mut current = match self {
            Value::Object(m, id) => vec![(m, id)],
            _ => vec![],
        };

        while !current.is_empty() {
            let mut next = Vec::new();

            for (map, id) in current {
                if let ObjectId::BlankNode(id) = id {
                    ids.insert(id.clone());
                }

                for (_, v) in map {
                    if let Value::Object(m, id) = v {
                        next.push((m, id));
                    }
                }
            }

            current = next;
        }

        ids
    }

    pub fn to_string_with_prefix(&self, prefix: String) -> String {
        self.to_graph(Some(prefix)).to_string()
    }

    pub fn to_graph(&self, prefix: Option<String>) -> Graph {
        fn transform_id(
            id: &ObjectId,
            gen: &mut BlankGenerator,
            prefix: &String,
        ) -> NamedOrBlankNode {
            match id {
                ObjectId::None => {
                    NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(gen.next(prefix)))
                }
                ObjectId::BlankNode(b) => NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(b)),
                ObjectId::NamedNode(n) => NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(n)),
            }
        }

        fn process<'a>(
            value: &'a Value,
            next: &mut Vec<(NamedOrBlankNode, &'a BTreeMap<String, Value>)>,
            gen: &mut BlankGenerator,
            prefix: &String,
        ) -> Vec<Term> {
            match value {
                Value::String(s) => vec![Term::Literal(Literal::new_simple_literal(s))],
                Value::Typed(v, t) => vec![Term::Literal(Literal::new_typed_literal(
                    v,
                    NamedNode::new_unchecked(t),
                ))],
                Value::Object(m, id) => {
                    let id = transform_id(id, gen, prefix);

                    next.push((id.clone(), m));

                    vec![match id {
                        NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b),
                        NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n),
                    }]
                }
                Value::ObjectRef(id) => {
                    let id = transform_id(id, gen, prefix);
                    vec![match id {
                        NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b),
                        NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n),
                    }]
                }
                Value::Array(arr) => arr
                    .iter()
                    .map(|v| process(v, next, gen, prefix))
                    .flatten()
                    .collect::<Vec<_>>(),
            }
        }

        let prefix = prefix.unwrap_or("b".to_string());
        let mut gen = BlankGenerator::init(self);

        let mut maps = match self {
            Value::Object(m, id) => {
                vec![(transform_id(id, &mut gen, &prefix), m)]
            }
            _ => Vec::new(),
        };
        let mut triples = Vec::<Triple>::new();

        while !maps.is_empty() {
            let mut next = Vec::new();

            for (id, map) in maps {
                for (k, v) in map {
                    let subject = match id.clone() {
                        NamedOrBlankNode::BlankNode(b) => Subject::BlankNode(b),
                        NamedOrBlankNode::NamedNode(n) => Subject::NamedNode(n),
                    };
                    let predicate = NamedNode::new_unchecked(k);

                    for object in process(v, &mut next, &mut gen, &prefix) {
                        triples.push(Triple {
                            subject: subject.clone(),
                            predicate: predicate.clone(),
                            object,
                        });
                    }
                }
            }

            maps = next;
        }

        Graph::from_iter(triples)
    }

    pub fn as_string(&self) -> Option<&String> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<(&BTreeMap<String, Value>, &ObjectId)> {
        match self {
            Value::Object(m, id) => Some((m, id)),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<(&mut BTreeMap<String, Value>, &mut ObjectId)> {
        match self {
            Value::Object(m, id) => Some((m, id)),
            _ => None,
        }
    }

    pub fn id(&self) -> Option<&ObjectId> {
        match self {
            Self::Object(_, id) | Self::ObjectRef(id) => Some(id),
            _ => None,
        }
    }
}

impl ToString for Value {
    fn to_string(&self) -> String {
        self.to_string_with_prefix("b".to_string())
    }
}

impl<S> PartialEq<S> for ObjectId
where
    S: AsRef<str>,
{
    fn eq(&self, other: &S) -> bool {
        let other = other.as_ref();
        match self {
            ObjectId::None => false,
            ObjectId::BlankNode(n) | ObjectId::NamedNode(n) => n == other,
        }
    }
}
