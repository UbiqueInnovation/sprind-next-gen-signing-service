use std::collections::BTreeSet;

/// Compares two rdf strings, independent of the order of the triples
pub fn assert_rdf_string_eq<S1: AsRef<str>, S2: AsRef<str>>(lhs: S1, rhs: S2) {
    let lhs = lhs
        .as_ref()
        .trim()
        .split("\n")
        .map(|it| it.trim())
        .collect::<BTreeSet<&str>>();
    let rhs = rhs
        .as_ref()
        .trim()
        .split("\n")
        .map(|it| it.trim())
        .collect::<BTreeSet<&str>>();
    assert_eq!(lhs, rhs);
}
