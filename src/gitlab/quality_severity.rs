use rustsec::advisory::Severity;
use serde::Serialize;

#[allow(dead_code)]
#[derive(Serialize, Debug)]
pub enum QualitySeverity {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

impl Default for QualitySeverity {
    fn default() -> Self {
        Self::Info
    }
}

impl From<Severity> for QualitySeverity {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::None => Self::Info,
            Severity::Low => Self::Info,
            Severity::Medium => Self::Minor,
            Severity::High => Self::Major,
            Severity::Critical => Self::Critical,
        }
    }
}