use serde::Serialize;

#[derive(Serialize, Debug, Default)]
pub struct QualityLocation {
    pub path: String,
    pub lines: QualityLocationLine,
}

#[derive(Serialize, Debug, Default)]
pub struct QualityLocationLine {
    pub begin: usize,
    pub end: usize,
}