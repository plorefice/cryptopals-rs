use std::{error::Error, result};

pub mod crypto;
pub mod sets;
pub mod text;
pub mod utils;

/// Result type used across the module.
type Result<T> = result::Result<T, Box<dyn Error>>;
