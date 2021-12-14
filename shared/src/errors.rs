#[derive(Debug)]
pub enum ErrorKind {
    UnsupportedFormat { message: String },
    StateViolation { message: String },
    Serde { message: String },
    Io { source: std::io::Error },
    MalformedMessage { message: String },
    PoisonedLock { message: String },
    SendError { message: String },
    SystemTime { source: std::time::SystemTimeError },
    Configuration { message: String },
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ErrorKind::UnsupportedFormat { message } => {
                write!(formatter, "Unsupported format > {}", message)
            }
            ErrorKind::StateViolation { message } => {
                write!(formatter, "State violation > {}", message)
            }
            ErrorKind::Serde { message } => {
                write!(formatter, "Serde > {}", message)
            }
            ErrorKind::Io { source } => {
                write!(formatter, "Io > {}", source)
            }
            ErrorKind::MalformedMessage { message } => {
                write!(formatter, "Received a message with incorrect format > {}", message)
            }
            ErrorKind::PoisonedLock { message } => {
                write!(formatter, "Ran into a poisoned lock > {}", message)
            }
            ErrorKind::SendError { message } => {
                write!(formatter, "Channel sending > {}", message)
            }
            ErrorKind::SystemTime { source } => {
                write!(formatter, "System time > {}", source)
            }
            ErrorKind::Configuration { message } => {
                write!(formatter, "Incorrect configuration > {}", message)
            }
        }
    }
}

#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Shared Code Error > {}", self.kind)
    }
}

impl std::error::Error for Error {}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error { kind: kind }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Error {
            kind: ErrorKind::Io {
                source: source,
            }
        }
    }
}

impl From<ErrorKind> for std::io::Error {
    fn from(kind: ErrorKind) -> Self {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            Error { kind: kind }
        )
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(source: std::sync::PoisonError<T>) -> Self {
        Error {
            kind: ErrorKind::PoisonedLock {
                message: format!("{}", source),
            }
        }
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(source: std::sync::mpsc::SendError<T>) -> Self {
        Error {
            kind: ErrorKind::SendError {
                message: format!("{}", source)
            }
        }
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(source: std::time::SystemTimeError) -> Self {
        Error {
            kind: ErrorKind::SystemTime {
                source: source,
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn with_error_report<F: FnOnce() -> Result<()>>(run: F) {
    let result = run();

    match &result {
        Err(error) => {
            println!("Error > {}", error);
        }
        _ => {}
    };
}

pub fn is_would_block_io_error(error: &std::io::Error) -> bool {
    match error.kind() {
        std::io::ErrorKind::WouldBlock => true,
        _ => false
    }
}

pub fn is_would_block_error(error: &Error) -> bool {
    match &error.kind {
        ErrorKind::Io { source } => is_would_block_io_error(source),
        _ => false
    }
}

pub fn is_would_block_result<T>(result: &Result<T>) -> bool {
    match result {
        Err(error) => is_would_block_error(error),
        _ => false
    }
}

pub fn is_would_block_io_result<T>(result: &std::io::Result<T>) -> bool {
    match result {
        Err(error) => is_would_block_io_error(error),
        _ => false
    }
}

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(text: T) -> Self {
        let message = format!("{}", text);
        ErrorKind::Serde { message }.into()
    }
}

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(text: T) -> Self {
        let message = format!("{}", text);
        ErrorKind::Serde { message }.into()
    }
}

impl<T> From<ErrorKind> for Result<T> {
    fn from(kind: ErrorKind) -> Self {
        Err(kind.into())
    }
}
