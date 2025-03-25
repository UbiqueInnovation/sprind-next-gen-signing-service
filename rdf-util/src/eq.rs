use crate::Value;

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
