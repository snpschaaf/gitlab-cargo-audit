use crate::gitlab::quality_report_location::QualityLocation;
use crate::gitlab::quality_severity::QualitySeverity;
use serde::Serialize;

/// Datatype according to:
/// * https://docs.gitlab.com/ee/ci/testing/code_quality.html
/// * https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md#data-types
#[derive(Serialize, Debug)]
pub struct QualityReport {
    /// Must always be "issue".
    #[serde(rename = "type")]
    pub check_type: String,

    ///  A unique name representing the static analysis check that emitted this issue.
    pub check_name: String,

    /// A string explaining the issue that was detected.
    pub description: String,

    /// A markdown snippet describing the issue, including deeper explanations and links to other resources.
    pub content: Option<QualityReportContent>,

    /// At least one category indicating the nature of the issue being reported.
    pub categories: Vec<String>,

    /// A Location object representing the place in the source code where the issue was discovered.
    pub location: QualityLocation,
    pub other_locations: Option<Vec<QualityLocation>>,

    /// A Trace object representing other interesting source code locations related to this issue.
    pub trace: Option<QualityReportTrace>,

    /// An integer indicating a rough estimate of how long it would take to resolve the reported issue.
    pub remediation_points: Option<usize>,

    /// A Severity describing the potential impact of the issue
    pub severity: Option<QualitySeverity>,

    /// A unique, deterministic identifier for the specific issue being reported to allow a user to exclude it from future analyses.
    pub fingerprint: Option<String>,
}

impl Default for QualityReport {
    fn default() -> Self {
        Self {
            description: "".to_string(),
            fingerprint: None,
            severity: Default::default(),
            check_name: "cargo-audit".to_string(),
            categories: vec![ "CVE".to_string() ],
            location: Default::default(),
            trace: None,
            check_type: "issue".to_string(),
            content: None,
            remediation_points: None,
            other_locations: None
        }
    }
}

#[derive(Serialize, Debug, Default)]
pub struct QualityReportContent {
    /// The value of this key should be a Markdown document.
    pub body: String,
}

#[derive(Serialize, Debug, Default)]
pub struct QualityReportTrace {
    /// An array of Location objects.
    pub locations: Vec<QualityLocation>,

    /// When true, this Trace object will be treated like an ordered stacktrace by the CLI and the Code Climate UI
    pub stacktrace: bool,
}