//! One error type for the whole pipeline. Messages never echo the offending *value* of a
//! journal field (it may be exactly the sensitive thing); they name the field and the line.

use std::fmt;

#[derive(Debug)]
pub enum SubmitError {
    /// Reading or writing a file.
    Io(String),
    /// Input that does not parse or violates the input schema.
    Input(String),
    /// A field that must be publishable is not (bad token grammar, mixed hardware, ...).
    Refused(String),
    /// The finished bundle still contained something the redactor recognises. Fail closed.
    Leak(String),
    /// Consent gate: the export is not permitted.
    Consent(String),
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::Io(m) => write!(f, "io: {m}"),
            SubmitError::Input(m) => write!(f, "input: {m}"),
            SubmitError::Refused(m) => write!(f, "refused: {m}"),
            SubmitError::Leak(m) => write!(f, "refused (leak check): {m}"),
            SubmitError::Consent(m) => write!(f, "consent: {m}"),
        }
    }
}

impl std::error::Error for SubmitError {}

impl From<std::io::Error> for SubmitError {
    fn from(e: std::io::Error) -> Self {
        SubmitError::Io(e.to_string())
    }
}
