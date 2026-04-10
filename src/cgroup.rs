use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{fs, io};

type DMemLimit = std::collections::HashMap<String, u64>;

const CG_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug)]
pub struct CGroup {
    path: PathBuf,
}

impl CGroup {
    pub fn root() -> CGroup {
        CGroup {
            path: PathBuf::from(CG_ROOT),
        }
    }

    pub fn is_root(&self) -> bool {
        &self.path == CG_ROOT
    }

    pub fn from_path(path: PathBuf) -> CGroup {
        assert!(path.starts_with(CG_ROOT));

        CGroup { path }
    }

    pub fn descendants(&self) -> Vec<CGroup> {
        let Ok(dir) = fs::read_dir(&self.path) else {
            return Default::default();
        };
        dir.filter_map(Result::ok)
            .filter(|e| e.file_type().map(|it| !it.is_dir()).unwrap_or_default())
            .map(|e| CGroup::from_path(e.path()))
            .collect()
    }

    pub fn name(&self) -> String {
        if self.is_root() {
            String::from("")
        } else if let Some(name) = self.path.file_name() {
            name.to_string_lossy().to_string()
        } else {
            String::from("")
        }
    }

    pub fn parent(&self) -> Option<CGroup> {
        if self.is_root() {
            return None;
        }
        self.path
            .parent()
            .map(ToOwned::to_owned)
            .map(CGroup::from_path)
    }

    pub fn active_controllers(&self) -> Option<Vec<String>> {
        fs::read_to_string(self.path.join("cgroup.subtree_control"))
            .ok()?
            .split_ascii_whitespace()
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
            .into()
    }

    pub fn add_controller(&mut self, controller: &str) -> io::Result<()> {
        let control = format!("+{controller}");
        fs::write(self.path.join("cgroup.subtree_control"), control)
    }

    fn parse_limits_file(file: &Path) -> Option<DMemLimit> {
        fn parse_line(line: &str) -> Option<(String, u64)> {
            let (name, value) = {
                let words: Vec<_> = line.split(' ').collect();
                if words.len() != 2 {
                    return None;
                }
                (words[0], words[1])
            };
            let value = if value == "max" {
                u64::MAX
            } else {
                value.parse().ok()?
            };
            Some((name.to_owned(), value))
        }

        let mut limits = DMemLimit::new();
        for line in fs::read_to_string(file).ok()?.lines() {
            let Some((name, value)) = parse_line(line) else {
                eprintln!("WARNING: Unexpected number of words in dmem limit string: \"{line}\"");
                continue;
            };
            limits.insert(name, value);
        }
        Some(limits)
    }

    fn write_limits_file(&self, file: &Path, limit: &DMemLimit) {
        let mut contents = String::new();
        for (name, value) in limit {
            if *value == u64::MAX {
                let _ = writeln!(&mut contents, "{name} max");
                continue;
            }
            let _ = writeln!(&mut contents, "{name} {value}");
        }
        if let Err(e) = fs::write(file, contents)
            && e.kind() != io::ErrorKind::PermissionDenied
        {
            eprintln!("WARNING: Could not write dmem limit file: {e}!");
        }
    }

    fn limit_from_attribute(&self, attrib_name: &str) -> Option<DMemLimit> {
        Self::parse_limits_file(&self.path.join(attrib_name))
    }

    pub fn device_memory_capacity(&self) -> Option<DMemLimit> {
        self.limit_from_attribute("dmem.capacity")
    }

    pub fn write_device_memory_low(&mut self, limit: &DMemLimit) {
        self.write_limits_file(&self.path.join("dmem.low"), limit);
    }
}
