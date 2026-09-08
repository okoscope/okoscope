use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    #[must_use]
    pub fn current() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Self::X86_64),
            "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SyscallError {
    #[error("syscall selection must use a canonical name, not {0:?}")]
    InvalidSelection(String),
    #[error("unsupported syscall {name:?} on {architecture:?}")]
    Unsupported {
        name: String,
        architecture: Architecture,
    },
}

pub fn resolve(name: &str, architecture: Architecture) -> Result<u32, SyscallError> {
    if name.is_empty() || name == "*" || name.chars().all(|c| c.is_ascii_digit()) {
        return Err(SyscallError::InvalidSelection(name.into()));
    }
    let number = match architecture {
        Architecture::X86_64 => match name {
            "ptrace" => 101,
            "capset" => 126,
            "mount" => 165,
            "umount2" => 166,
            "unshare" => 272,
            "setns" => 308,
            "bpf" => 321,
            _ => {
                return Err(SyscallError::Unsupported {
                    name: name.into(),
                    architecture,
                });
            }
        },
        Architecture::Aarch64 => match name {
            "ptrace" => 117,
            "capset" => 91,
            "mount" => 40,
            "umount2" => 39,
            "unshare" => 97,
            "setns" => 268,
            "bpf" => 280,
            _ => {
                return Err(SyscallError::Unsupported {
                    name: name.into(),
                    architecture,
                });
            }
        },
    };
    Ok(number)
}

#[must_use]
pub fn name_for_number(number: u32, architecture: Architecture) -> Option<&'static str> {
    [
        "ptrace", "capset", "mount", "umount2", "unshare", "setns", "bpf",
    ]
    .into_iter()
    .find(|name| resolve(name, architecture) == Ok(number))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_per_architecture() {
        assert_eq!(resolve("ptrace", Architecture::X86_64), Ok(101));
        assert_eq!(resolve("ptrace", Architecture::Aarch64), Ok(117));
    }

    #[test]
    fn rejects_numbers_wildcards_and_unknown_names() {
        assert!(matches!(
            resolve("101", Architecture::X86_64),
            Err(SyscallError::InvalidSelection(_))
        ));
        assert!(matches!(
            resolve("*", Architecture::X86_64),
            Err(SyscallError::InvalidSelection(_))
        ));
        assert!(matches!(
            resolve("read", Architecture::X86_64),
            Err(SyscallError::Unsupported { .. })
        ));
    }
}
