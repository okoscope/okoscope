#[cfg(any(target_os = "linux", test))]
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("failed to read process cgroup: {0}")]
    Io(#[from] std::io::Error),
    #[error("process has no cgroup v2 entry")]
    MissingV2Entry,
    #[error("cgroup inode does not match kernel event: expected {expected}, found {actual}")]
    IdMismatch { expected: u64, actual: u64 },
    #[error("container ID is absent from cgroup path {0:?}")]
    MissingContainerId(String),
}

#[cfg(any(target_os = "linux", test))]
pub fn resolve_container_id(pid: u32, expected_cgroup_id: u64) -> Result<String, CgroupError> {
    use std::os::unix::fs::MetadataExt;

    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let relative = v2_path(&content).ok_or(CgroupError::MissingV2Entry)?;
    let cgroup_path = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    let actual = std::fs::metadata(&cgroup_path)?.ino();
    if actual != expected_cgroup_id {
        return Err(CgroupError::IdMismatch {
            expected: expected_cgroup_id,
            actual,
        });
    }
    extract_container_id(relative).ok_or_else(|| CgroupError::MissingContainerId(relative.into()))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
pub struct CgroupResolver {
    root: PathBuf,
    containers: HashMap<u64, ContainerCgroup>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerCgroup {
    pub inode: u64,
    pub container_id: String,
    pub path: PathBuf,
}

#[cfg(any(target_os = "linux", test))]
impl CgroupResolver {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, CgroupError> {
        let mut resolver = Self {
            root: root.into(),
            containers: HashMap::new(),
        };
        resolver.refresh()?;
        Ok(resolver)
    }

    pub fn resolve(&mut self, pid: u32, cgroup_id: u64) -> Result<String, CgroupError> {
        if let Some(container) = self.containers.get(&cgroup_id) {
            return Ok(container.container_id.clone());
        }
        if let Ok(container) = resolve_container_id(pid, cgroup_id) {
            self.containers.insert(
                cgroup_id,
                ContainerCgroup {
                    inode: cgroup_id,
                    container_id: container.clone(),
                    path: PathBuf::new(),
                },
            );
            return Ok(container);
        }
        self.refresh()?;
        self.containers
            .get(&cgroup_id)
            .map(|value| value.container_id.clone())
            .ok_or_else(|| CgroupError::MissingContainerId(format!("cgroup id {cgroup_id}")))
    }

    pub fn container_cgroups(&mut self) -> Result<Vec<ContainerCgroup>, CgroupError> {
        self.refresh()?;
        Ok(self.containers.values().cloned().collect())
    }

    fn refresh(&mut self) -> Result<(), CgroupError> {
        use std::os::unix::fs::MetadataExt;

        let mut pending = vec![self.root.clone()];
        let mut containers = HashMap::new();
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let path = entry.path();
                pending.push(path.clone());
                let Some(container) = extract_container_id(&path.to_string_lossy()) else {
                    continue;
                };
                let inode = entry.metadata()?.ino();
                containers.insert(
                    inode,
                    ContainerCgroup {
                        inode,
                        container_id: container,
                        path,
                    },
                );
            }
        }
        self.containers = containers;
        Ok(())
    }
}

#[cfg(any(target_os = "linux", test))]
fn v2_path(content: &str) -> Option<&str> {
    content.lines().find_map(|line| line.strip_prefix("0::"))
}

#[cfg(any(target_os = "linux", test))]
fn extract_container_id(path: &str) -> Option<String> {
    path.split(['/', '-', '.'])
        .map(|part| part.trim_end_matches(".scope"))
        .find(|part| part.len() == 64 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_containerd_cgroup() {
        let id = "a".repeat(64);
        let path = format!("/kubepods.slice/cri-containerd-{id}.scope");
        assert_eq!(extract_container_id(&path), Some(id));
        assert_eq!(v2_path(&format!("0::{path}\n")), Some(path.as_str()));
    }
}
