use crate::{ObjectId, Value};

impl<S> PartialEq<S> for Value
where
    S: AsRef<str>,
{
    fn eq(&self, other: &S) -> bool {
        match self {
            Value::String(s) => s == other.as_ref(),
            _ => false,
        }
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
