use serde::Serialize;

#[allow(dead_code)]
#[derive(Serialize, Debug)]
pub enum Confidence {
    Ignore,
    Unknown,
    Experimental,
    Low,
    Medium,
    High,
    Confirmed,
}