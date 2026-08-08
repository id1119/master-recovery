//! Versioned command/response objects shared by the CLI and browser gateway.

use gp_sim::{DemoOptions, DemoResult};
use serde::{Deserialize, Serialize};

pub const IPC_VERSION: u16 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Command {
    Ping,
    RunDemo { version: u16, options: DemoOptions },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Pong {
        version: u16,
    },
    Snapshot {
        version: u16,
        result: Box<DemoResult>,
    },
    Error {
        version: u16,
        message: String,
    },
}

#[must_use]
pub fn execute(command: Command) -> Response {
    match command {
        Command::Ping => Response::Pong {
            version: IPC_VERSION,
        },
        Command::RunDemo { version, options } if version == IPC_VERSION => {
            match gp_sim::run_demo(&options) {
                Ok(result) => Response::Snapshot {
                    version: IPC_VERSION,
                    result: Box::new(result),
                },
                Err(error) => Response::Error {
                    version: IPC_VERSION,
                    message: error.to_string(),
                },
            }
        }
        Command::RunDemo { .. } => Response::Error {
            version: IPC_VERSION,
            message: "unsupported IPC version".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_version() {
        assert!(matches!(
            execute(Command::RunDemo {
                version: 99,
                options: DemoOptions::default()
            }),
            Response::Error { .. }
        ));
    }
}
