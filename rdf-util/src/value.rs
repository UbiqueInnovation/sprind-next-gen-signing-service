use std::collections::{BTreeMap, BTreeSet};

use oxrdf::{BlankNode, Graph, Literal, NamedNode, NamedOrBlankNode, Subject, Term, Triple};

use crate::BlankGenerator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectId {
    None,
    BlankNode(String),
    NamedNode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Typed(String, String),
    Object(BTreeMap<String, Value>, ObjectId),
    ObjectRef(ObjectId),
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
        let prefix = prefix.unwrap_or("b".to_string());
        let mut generator = BlankGenerator::init(self);

        let mut transform_id = |id: &ObjectId| -> NamedOrBlankNode {
            match id {
                ObjectId::None => {
                    NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(generator.next(&prefix)))
                }
                ObjectId::BlankNode(b) => NamedOrBlankNode::BlankNode(BlankNode::new_unchecked(b)),
                ObjectId::NamedNode(n) => NamedOrBlankNode::NamedNode(NamedNode::new_unchecked(n)),
            }
        };

        let mut maps = match self {
            Value::Object(m, id) => {
                vec![(transform_id(id), m)]
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
                    let object = match v {
                        Value::String(s) => Term::Literal(Literal::new_simple_literal(s)),
                        Value::Typed(v, t) => Term::Literal(Literal::new_typed_literal(
                            v,
                            NamedNode::new_unchecked(t),
                        )),
                        Value::Object(m, mid) => {
                            let mid = transform_id(mid);

                            next.push((mid.clone(), m));

                            match mid {
                                NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b),
                                NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n),
                            }
                        }
                        Value::ObjectRef(mid) => {
                            let mid = transform_id(mid);
                            match mid {
                                NamedOrBlankNode::BlankNode(b) => Term::BlankNode(b),
                                NamedOrBlankNode::NamedNode(n) => Term::NamedNode(n),
                            }
                        }
                    };

                    triples.push(Triple {
                        subject,
                        predicate,
                        object,
                    });
                }
            }

            maps = next;
        }

        Graph::from_iter(triples)
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
}

impl ToString for Value {
    fn to_string(&self) -> String {
        self.to_string_with_prefix("b".to_string())
    }
}
