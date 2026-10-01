//! The model's checklist, `harness.task.todo` (design row H2e). Pure: no
//! I/O. The run loop keeps one [`TodoList`] per run and applies each call to
//! it, in order; the call's result is the list as it now stands.
//!
//! **Where the list lives.** In the run's state and in the tool results
//! that echo it, never in a block that changes earlier in the prompt: the
//! context stays prefix-stable (H1i), and a replay or a resume recomputes
//! the list from the recorded calls, in order, so every result is
//! recomputed rather than re-fed.
//!
//! **What a call does.** `items` replaces the whole list (each item a text
//! and a status: `pending`, `in_progress` or `done`); a call without
//! `items` changes nothing and shows the list. At most [`TODO_MAX_ITEMS`]
//! items (the schema subset has no `maxItems`); each text is one line of 1
//! to 200 characters with no control character. A refused call changes
//! nothing. The item texts are the model's own words: the result is an
//! observation like any other (untrusted, delimited), and the harness's
//! own notices only ever count the items, never quote them.

use std::fmt::Write as _;

use serde_json::Value;

/// Most items a checklist holds.
pub const TODO_MAX_ITEMS: usize = 20;
/// Longest item text, in characters (the schema's bound too).
pub const TODO_MAX_TEXT: usize = 200;

/// An item's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TodoStatus {
    /// Not started.
    Pending,
    /// Being worked on.
    InProgress,
    /// Finished.
    Done,
}

impl TodoStatus {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "in_progress" => Some(Self::InProgress),
            "done" => Some(Self::Done),
            _ => None,
        }
    }

    fn shown(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in progress",
            Self::Done => "done",
        }
    }
}

/// One checklist item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TodoItem {
    /// The model's text.
    pub text: String,
    /// Its status.
    pub status: TodoStatus,
}

/// Why a call was refused (the list is unchanged). The messages are static
/// harness words and numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TodoError {
    /// `items` is not a list of `{text, status}` (the schema refuses this
    /// first; defence in depth).
    #[error("items must be a list of {{text, status}}, status pending, in_progress or done")]
    Shape,
    /// More than [`TODO_MAX_ITEMS`] items.
    #[error("the checklist holds at most 20 items; merge some")]
    TooMany,
    /// Item `0` (1-based) has an empty text.
    #[error("item {0} has an empty text")]
    Empty(usize),
    /// Item `0` (1-based) has a control character (a line break included):
    /// one line per item.
    #[error("item {0} has a line break or another control character; write one line per item")]
    Control(usize),
    /// Item `0` (1-based) is longer than [`TODO_MAX_TEXT`] characters.
    #[error("item {0} is longer than 200 characters")]
    TooLong(usize),
}

/// The run's checklist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TodoList {
    items: Vec<TodoItem>,
}

impl TodoList {
    /// Apply one call's arguments; the result text, or why it was refused.
    pub fn apply(&mut self, args: &Value) -> Result<String, TodoError> {
        let Some(given) = args.get("items") else {
            return Ok(self.render(false));
        };
        let list = given.as_array().ok_or(TodoError::Shape)?;
        if list.len() > TODO_MAX_ITEMS {
            return Err(TodoError::TooMany);
        }
        let mut items = Vec::with_capacity(list.len());
        for (i, v) in list.iter().enumerate() {
            let n = i + 1;
            let (Some(text), Some(status)) = (
                v.get("text").and_then(Value::as_str),
                v.get("status")
                    .and_then(Value::as_str)
                    .and_then(TodoStatus::parse),
            ) else {
                return Err(TodoError::Shape);
            };
            let text = text.trim();
            if text.is_empty() {
                return Err(TodoError::Empty(n));
            }
            if text.chars().any(char::is_control) {
                return Err(TodoError::Control(n));
            }
            if text.chars().count() > TODO_MAX_TEXT {
                return Err(TodoError::TooLong(n));
            }
            items.push(TodoItem {
                text: text.to_owned(),
                status,
            });
        }
        self.items = items;
        Ok(self.render(true))
    }

    /// The items.
    pub fn items(&self) -> &[TodoItem] {
        &self.items
    }

    /// How many items are not done.
    pub fn open(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.status != TodoStatus::Done)
            .count()
    }

    fn count(&self, s: TodoStatus) -> usize {
        self.items.iter().filter(|i| i.status == s).count()
    }

    /// The list as a call's result shows it.
    fn render(&self, updated: bool) -> String {
        let head = if updated {
            "checklist updated"
        } else {
            "checklist"
        };
        if self.items.is_empty() {
            return format!("{head}: empty (call with items to write one)\n");
        }
        let mut s = format!(
            "{head}: {} item(s): {} done, {} in progress, {} pending\n",
            self.items.len(),
            self.count(TodoStatus::Done),
            self.count(TodoStatus::InProgress),
            self.count(TodoStatus::Pending)
        );
        for (i, it) in self.items.iter().enumerate() {
            let _ = writeln!(s, "{}. [{}] {}", i + 1, it.status.shown(), it.text);
        }
        if self.open() == 0 {
            s.push_str("every item is done: if the task is finished, submit it\n");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn items_replace_the_list_and_no_items_shows_it() {
        let mut t = TodoList::default();
        assert_eq!(
            t.apply(&json!({})).unwrap(),
            "checklist: empty (call with items to write one)\n"
        );
        let out = t
            .apply(&json!({"items": [
                {"text": "find the constant", "status": "done"},
                {"text": "  rename it  ", "status": "in_progress"},
                {"text": "run cargo test", "status": "pending"}
            ]}))
            .unwrap();
        assert_eq!(
            out,
            "checklist updated: 3 item(s): 1 done, 1 in progress, 1 pending\n\
             1. [done] find the constant\n\
             2. [in progress] rename it\n\
             3. [pending] run cargo test\n"
        );
        assert_eq!(t.open(), 2);
        assert_eq!(
            t.apply(&json!({})).unwrap(),
            out.replacen(" updated", "", 1)
        );
        let done = t
            .apply(&json!({"items": [{"text": "all", "status": "done"}]}))
            .unwrap();
        assert!(done.ends_with("every item is done: if the task is finished, submit it\n"));
        assert_eq!(t.open(), 0);
        assert_eq!(
            t.apply(&json!({"items": []})).unwrap(),
            "checklist updated: empty (call with items to write one)\n"
        );
    }

    #[test]
    fn a_refused_call_changes_nothing() {
        let mut t = TodoList::default();
        t.apply(&json!({"items": [{"text": "keep", "status": "pending"}]}))
            .unwrap();
        let before = t.clone();
        let many: Vec<Value> = (0..21)
            .map(|i| json!({"text": format!("s{i}"), "status": "pending"}))
            .collect();
        for (args, want) in [
            (json!({"items": many}), TodoError::TooMany),
            (
                json!({"items": [{"text": "a", "status": "pending"}, {"text": " ", "status": "done"}]}),
                TodoError::Empty(2),
            ),
            (
                json!({"items": [{"text": "a\nb", "status": "pending"}]}),
                TodoError::Control(1),
            ),
            (
                json!({"items": [{"text": "x".repeat(201), "status": "pending"}]}),
                TodoError::TooLong(1),
            ),
            (
                json!({"items": [{"text": "a", "status": "finished"}]}),
                TodoError::Shape,
            ),
            (json!({"items": "a"}), TodoError::Shape),
        ] {
            assert_eq!(t.apply(&args), Err(want), "{args}");
            assert_eq!(t, before);
        }
        assert!(t
            .apply(&json!({"items": [{"text": "é".repeat(200), "status": "done"}]}))
            .is_ok());
        for e in [TodoError::Shape, TodoError::TooMany, TodoError::Control(3)] {
            assert!(!e.to_string().is_empty());
        }
    }
}
