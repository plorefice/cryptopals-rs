use std::{error::Error, result};

pub mod sets;
pub mod text;

/// Result type used across the module.
type Result<T> = result::Result<T, Box<dyn Error>>;
