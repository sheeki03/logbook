//! Session / run identifier newtypes.
//!
//! These are thin, string-backed newtypes that keep session and run identity
//! distinct in the type system (so a `SessionId` can't be passed where a
//! `RunId` is expected). They serialize transparently as strings.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::TraceId;

/// Macro to declare a transparent, string-backed id newtype.
macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// Wrap an existing string as this id.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrow the inner string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the inner string.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_string())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_newtype! {
    /// Identifies a logical session (e.g. a debug session, an `logbook agent`
    /// session, or a browser session). Distinct from a [`RunId`].
    SessionId
}

string_newtype! {
    /// Identifies a single captured run (one `logbook <cmd>` invocation),
    /// matching the OpenLogs run-index key.
    RunId
}

string_newtype! {
    /// Stable identifier for a stored [`crate::Event`]. Used as the SQLite
    /// primary key and for idempotent upserts.
    EventId
}

impl SessionId {
    /// Mint a fresh random session id (a trace-width hex string).
    #[must_use]
    pub fn generate() -> Self {
        Self(TraceId::new().to_hex())
    }
}

impl EventId {
    /// Mint a fresh random event id (a trace-width hex string).
    #[must_use]
    pub fn generate() -> Self {
        Self(TraceId::new().to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_are_distinct_types_but_serialize_transparently() {
        let s = SessionId::new("sess-1");
        let r = RunId::from("run-1");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"sess-1\"");
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"run-1\"");
    }

    #[test]
    fn deserializes_from_plain_string() {
        let s: SessionId = serde_json::from_str("\"abc\"").unwrap();
        assert_eq!(s.as_str(), "abc");
    }

    #[test]
    fn generated_session_id_is_trace_width() {
        assert_eq!(SessionId::generate().as_str().len(), 32);
        assert_eq!(EventId::generate().as_str().len(), 32);
    }
}
