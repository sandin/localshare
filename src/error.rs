use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct AuthError {
    pub msg: String
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unauthorized")
    }
}

impl Error for AuthError {}