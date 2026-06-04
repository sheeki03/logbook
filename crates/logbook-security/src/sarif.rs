//! SARIF 2.1.0 import (plan §7a).
//!
//! SARIF ("Static Analysis Results Interchange Format") is the OASIS-standard
//! JSON envelope emitted by CodeQL, Semgrep (`--sarif`), Trivy
//! (`--format sarif`), and most other static analysers. The shape we consume:
//!
//! ```jsonc
//! {
//!   "version": "2.1.0",
//!   "runs": [{
//!     "tool": { "driver": { "name": "Semgrep", "rules": [ { "id": "…",
//!                "defaultConfiguration": { "level": "error" },
//!                "properties": { "security-severity": "9.1" } } ] } },
//!     "results": [{
//!       "ruleId": "…", "ruleIndex": 0, "level": "error",
//!       "message": { "text": "…" },
//!       "locations": [{ "physicalLocation": {
//!         "artifactLocation": { "uri": "src/db.rs" },
//!         "region": { "startLine": 42 } } }]
//!     }]
//!   }]
//! }
//! ```
//!
//! Severity precedence for each result (most specific wins):
//! 1. the result's own numeric `properties.security-severity`,
//! 2. the result's `level` (`error`/`warning`/`note`/`none`),
//! 3. the *rule's* `properties.security-severity`,
//! 4. the rule's `defaultConfiguration.level`,
//! 5. otherwise `None`.
//!
//! Every `result` across every `run` becomes exactly one [`Finding`] with
//! `source = "sarif"` and `type = "sarif.result"`, so the import test can
//! assert a 1:1 result→finding→event mapping.

use serde::Deserialize;

use logbook_core::Severity;

use crate::error::{Result, SecurityError};
use crate::finding::Finding;

/// The `source` tag recorded on findings imported from SARIF.
pub const SARIF_SOURCE: &str = "sarif";
/// The event `type` for a SARIF-imported finding.
pub const SARIF_TYPE: &str = "sarif.result";

// ---- Minimal SARIF model (only the fields we read) ----------------------

#[derive(Debug, Deserialize)]
struct SarifLog {
    #[serde(default)]
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
struct SarifRun {
    #[serde(default)]
    tool: Tool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Debug, Default, Deserialize)]
struct Tool {
    #[serde(default)]
    driver: Driver,
}

#[derive(Debug, Default, Deserialize)]
struct Driver {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
struct Rule {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "defaultConfiguration")]
    default_configuration: Option<RuleConfig>,
    #[serde(default)]
    properties: Option<Properties>,
}

#[derive(Debug, Default, Deserialize)]
struct RuleConfig {
    #[serde(default)]
    level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Properties {
    /// CVSS-style 0–10 numeric severity (GitHub / CodeQL convention). Stored as
    /// a string in SARIF.
    #[serde(default, rename = "security-severity")]
    security_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SarifResult {
    #[serde(default, rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(default, rename = "ruleIndex")]
    rule_index: Option<usize>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    message: Option<Message>,
    #[serde(default)]
    locations: Vec<Location>,
    #[serde(default)]
    properties: Option<Properties>,
}

#[derive(Debug, Default, Deserialize)]
struct Message {
    #[serde(default)]
    text: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Location {
    #[serde(default, rename = "physicalLocation")]
    physical_location: Option<PhysicalLocation>,
}

#[derive(Debug, Default, Deserialize)]
struct PhysicalLocation {
    #[serde(default, rename = "artifactLocation")]
    artifact_location: Option<ArtifactLocation>,
    #[serde(default)]
    region: Option<Region>,
}

#[derive(Debug, Default, Deserialize)]
struct ArtifactLocation {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Region {
    #[serde(default, rename = "startLine")]
    start_line: Option<u32>,
}

// ---- Public parse entry points -------------------------------------------

/// Parse a SARIF document from a JSON string into normalized [`Finding`]s.
///
/// # Errors
/// Returns [`SecurityError::Parse`] if the bytes are not valid JSON.
pub fn parse_sarif_str(input: &str) -> Result<Vec<Finding>> {
    let log: SarifLog = serde_json::from_str(input).map_err(|source| SecurityError::Parse {
        format: SARIF_SOURCE.to_string(),
        source,
    })?;
    Ok(findings_from_log(&log))
}

/// Parse a SARIF document from an already-deserialized [`serde_json::Value`].
///
/// # Errors
/// Returns [`SecurityError::Parse`] if the value is not a structurally valid
/// SARIF log.
pub fn parse_sarif_value(value: serde_json::Value) -> Result<Vec<Finding>> {
    let log: SarifLog =
        serde_json::from_value(value).map_err(|source| SecurityError::Parse {
            format: SARIF_SOURCE.to_string(),
            source,
        })?;
    Ok(findings_from_log(&log))
}

fn findings_from_log(log: &SarifLog) -> Vec<Finding> {
    let mut out = Vec::new();
    for run in &log.runs {
        let rules = &run.tool.driver.rules;
        let tool_name = run.tool.driver.name.clone();
        for result in &run.results {
            out.push(result_to_finding(result, rules, tool_name.as_deref()));
        }
    }
    out
}

fn result_to_finding(result: &SarifResult, rules: &[Rule], tool_name: Option<&str>) -> Finding {
    // Resolve the rule id, falling back to the rule pointed at by ruleIndex.
    let rule = result
        .rule_index
        .and_then(|i| rules.get(i))
        .or_else(|| {
            result
                .rule_id
                .as_deref()
                .and_then(|id| rules.iter().find(|r| r.id.as_deref() == Some(id)))
        });

    let rule_id = result
        .rule_id
        .clone()
        .or_else(|| rule.and_then(|r| r.id.clone()));

    let severity = resolve_severity(result, rule);

    let (file, line) = result
        .locations
        .iter()
        .find_map(|loc| {
            let phys = loc.physical_location.as_ref()?;
            let uri = phys
                .artifact_location
                .as_ref()
                .and_then(|a| a.uri.clone());
            let line = phys.region.as_ref().and_then(|r| r.start_line);
            // A location is useful if it has at least a uri.
            uri.as_ref()?;
            Some((uri, line))
        })
        .unwrap_or((None, None));

    let message = result.message.as_ref().and_then(|m| m.text.clone());

    let mut finding = Finding {
        source: SARIF_SOURCE.to_string(),
        rule_id,
        severity,
        file,
        line,
        message,
        type_: SARIF_TYPE.to_string(),
    };
    // Keep a breadcrumb of which tool produced it, without inventing a column.
    if let Some(tool) = tool_name {
        if finding.message.is_none() {
            finding.message = Some(format!("{tool} finding"));
        }
    }
    finding
}

/// Apply the severity precedence documented at the top of the module.
fn resolve_severity(result: &SarifResult, rule: Option<&Rule>) -> Option<Severity> {
    // 1. result numeric security-severity
    if let Some(sev) = result
        .properties
        .as_ref()
        .and_then(|p| p.security_severity.as_deref())
        .and_then(severity_from_numeric)
    {
        return Some(sev);
    }
    // 2. result level
    if let Some(sev) = result.level.as_deref().and_then(severity_from_level) {
        return Some(sev);
    }
    // 3. rule numeric security-severity
    if let Some(sev) = rule
        .and_then(|r| r.properties.as_ref())
        .and_then(|p| p.security_severity.as_deref())
        .and_then(severity_from_numeric)
    {
        return Some(sev);
    }
    // 4. rule defaultConfiguration.level
    rule.and_then(|r| r.default_configuration.as_ref())
        .and_then(|c| c.level.as_deref())
        .and_then(severity_from_level)
}

/// Map a SARIF `level` token to a [`Severity`].
///
/// SARIF levels are `error` / `warning` / `note` / `none`. We map `error→High`
/// (real problems worth blocking on), `warning→Medium`, `note→Low`,
/// `none→Info`.
#[must_use]
pub fn severity_from_level(level: &str) -> Option<Severity> {
    match level.trim().to_ascii_lowercase().as_str() {
        "error" => Some(Severity::High),
        "warning" => Some(Severity::Medium),
        "note" => Some(Severity::Low),
        "none" => Some(Severity::Info),
        _ => None,
    }
}

/// Map a numeric CVSS-style `security-severity` string (0–10) to a [`Severity`]
/// using the GitHub code-scanning thresholds (critical ≥9.0, high ≥7.0,
/// medium ≥4.0, low ≥0.1, else info).
#[must_use]
pub fn severity_from_numeric(value: &str) -> Option<Severity> {
    let score: f64 = value.trim().parse().ok()?;
    Some(if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score >= 0.1 {
        Severity::Low
    } else {
        Severity::Info
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "version": "2.1.0",
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "Semgrep",
              "rules": [
                {
                  "id": "rules.sql-injection",
                  "defaultConfiguration": { "level": "error" }
                },
                {
                  "id": "rules.weak-hash",
                  "properties": { "security-severity": "4.5" }
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "rules.sql-injection",
              "ruleIndex": 0,
              "level": "error",
              "message": { "text": "Possible SQL injection via string concatenation" },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "src/db.rs" },
                    "region": { "startLine": 42 }
                  }
                }
              ]
            },
            {
              "ruleId": "rules.weak-hash",
              "ruleIndex": 1,
              "message": { "text": "Use of weak hash function" },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "src/crypto.rs" },
                    "region": { "startLine": 7 }
                  }
                }
              ]
            },
            {
              "ruleId": "rules.todo",
              "level": "note",
              "message": { "text": "Leftover TODO" }
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn parses_each_result_into_one_finding() {
        let findings = parse_sarif_str(SAMPLE).unwrap();
        assert_eq!(findings.len(), 3, "one finding per SARIF result");
        assert!(findings.iter().all(|f| f.source == "sarif"));
        assert!(findings.iter().all(|f| f.type_ == "sarif.result"));
    }

    #[test]
    fn maps_level_and_location() {
        let findings = parse_sarif_str(SAMPLE).unwrap();
        let sqli = &findings[0];
        assert_eq!(sqli.rule_id.as_deref(), Some("rules.sql-injection"));
        assert_eq!(sqli.severity, Some(Severity::High)); // level=error
        assert_eq!(sqli.file.as_deref(), Some("src/db.rs"));
        assert_eq!(sqli.line, Some(42));
        assert!(sqli.message.as_deref().unwrap().contains("SQL injection"));
    }

    #[test]
    fn falls_back_to_rule_numeric_severity() {
        let findings = parse_sarif_str(SAMPLE).unwrap();
        // Second result has no level; rule carries security-severity 4.5 → Medium.
        let weak = &findings[1];
        assert_eq!(weak.rule_id.as_deref(), Some("rules.weak-hash"));
        assert_eq!(weak.severity, Some(Severity::Medium));
    }

    #[test]
    fn note_maps_to_low_and_no_location_is_ok() {
        let findings = parse_sarif_str(SAMPLE).unwrap();
        let todo = &findings[2];
        assert_eq!(todo.severity, Some(Severity::Low));
        assert!(todo.file.is_none());
        assert!(todo.line.is_none());
    }

    #[test]
    fn numeric_severity_thresholds() {
        assert_eq!(severity_from_numeric("9.8"), Some(Severity::Critical));
        assert_eq!(severity_from_numeric("7.0"), Some(Severity::High));
        assert_eq!(severity_from_numeric("4.0"), Some(Severity::Medium));
        assert_eq!(severity_from_numeric("0.1"), Some(Severity::Low));
        assert_eq!(severity_from_numeric("0.0"), Some(Severity::Info));
        assert_eq!(severity_from_numeric("not-a-number"), None);
    }

    #[test]
    fn empty_runs_yields_no_findings() {
        assert!(parse_sarif_str(r#"{"version":"2.1.0","runs":[]}"#).unwrap().is_empty());
        // Missing runs key entirely is also fine (defaults to empty).
        assert!(parse_sarif_str(r#"{"version":"2.1.0"}"#).unwrap().is_empty());
    }

    #[test]
    fn invalid_json_is_a_parse_error() {
        let err = parse_sarif_str("{ not json").unwrap_err();
        assert!(matches!(err, SecurityError::Parse { .. }));
    }

    #[test]
    fn result_property_severity_beats_level() {
        // result-level numeric security-severity should win over level=note.
        let doc = r#"{
          "runs": [{
            "tool": { "driver": { "name": "X" } },
            "results": [{
              "ruleId": "r",
              "level": "note",
              "properties": { "security-severity": "9.5" },
              "message": { "text": "m" }
            }]
          }]
        }"#;
        let f = parse_sarif_str(doc).unwrap();
        assert_eq!(f[0].severity, Some(Severity::Critical));
    }
}
