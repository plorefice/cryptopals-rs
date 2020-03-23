use std::{error::Error, result};

pub mod sets;

/// Result type used across the module.
type Result<T> = result::Result<T, Box<dyn Error>>;
