//! The scanner: what is visited, the rules, and every report. The
//! `loose-keys` command (`main.rs`) and the app's engine (`gui/`) both use it.

pub mod fsutil;
pub mod report;
pub mod rules;
pub mod scan;
