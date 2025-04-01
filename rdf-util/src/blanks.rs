use std::collections::BTreeSet;

use crate::Value;

#[derive(Debug, Clone, Default)]
pub struct BlankGenerator {
    used_ids: BTreeSet<String>,
}

impl BlankGenerator {
    pub fn init(value: &Value) -> Self {
        Self {
            used_ids: value.taken_blank_ids(),
        }
    }

    pub fn next<S: AsRef<str>>(&mut self, prefix: S) -> String {
        let prefix = prefix.as_ref();
        let mut count = 0;

        let mut id = format!("{prefix}{count}");
        count += 1;

        while self.used_ids.contains(&id) {
            id = format!("{prefix}{count}");
            count += 1;
        }

        self.used_ids.insert(id.clone());

        id
    }
}
