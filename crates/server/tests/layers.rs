//! Keeps the server's layering (see `ARCHITECTURE.md`, "Server layering")
//! from eroding: transport code reaches the database only through services,
//! services know nothing about HTTP or gRPC, and repositories never own a
//! transaction.
//!
//! The checks read the crate's sources. Top-level `#[cfg(test)]` modules are
//! skipped, because tests seed and inspect the database directly.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Code that marks a file as transport: it speaks axum or tonic.
const TRANSPORT_MARKERS: &[&str] = &["axum::", "tonic::"];

/// Data access that belongs in a service or a repository, not in transport.
const DATA_ACCESS: &[&str] = &[
    "Repository::",
    "sqlx::query",
    "resolve_project_access",
    ".begin()",
];

/// Transport files allowed to reach the database directly, and why.
const TRANSPORT_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "auth.rs",
        "the session extractor resolves the bearer token to a principal, which is authentication",
    ),
    (
        "metrics.rs",
        "the scrape endpoint reads gauge snapshots; there is no use case behind them",
    ),
    (
        "main.rs",
        "a startup check logs whether webhook destinations are enabled",
    ),
    (
        "access_api.rs",
        "moves into service::access with the access service change",
    ),
    (
        "invitation_api.rs",
        "moves into service::invitations with the access service change",
    ),
];

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every `.rs` file under `dir`, as a path relative to `src/` with `/`
/// separators, paired with its non-test code.
fn sources(dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("read source directory") {
            let path = entry.expect("read directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let relative = path
                    .strip_prefix(src())
                    .expect("source under src/")
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = fs::read_to_string(&path).expect("read source file");
                files.push((relative, production_code(&text)));
            }
        }
    }
    files.sort();
    files
}

/// `text` without its top-level `#[cfg(test)]` modules. rustfmt puts a
/// module's closing brace alone at column 0, which ends the skipped block.
fn production_code(text: &str) -> String {
    let mut code = String::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if line == "#[cfg(test)]" {
            if let Some(item) = lines.next()
                && item.contains("mod ")
                && item.ends_with('{')
            {
                lines.by_ref().find(|line| *line == "}");
            }
            continue;
        }
        code.push_str(line);
        code.push('\n');
    }
    code
}

fn in_layer(path: &str, layer: &str) -> bool {
    path.starts_with(&format!("{layer}/"))
}

fn is_transport(path: &str, code: &str) -> bool {
    !in_layer(path, "service")
        && !in_layer(path, "repository")
        && TRANSPORT_MARKERS.iter().any(|marker| code.contains(marker))
}

fn hits<'a>(code: &str, patterns: &[&'a str]) -> Vec<&'a str> {
    patterns
        .iter()
        .copied()
        .filter(|pattern| code.contains(pattern))
        .collect()
}

#[test]
fn transport_reaches_the_database_only_through_services() {
    let mut violations = Vec::new();
    for (path, code) in sources(&src()) {
        if !is_transport(&path, &code) || TRANSPORT_EXCEPTIONS.iter().any(|(file, _)| *file == path)
        {
            continue;
        }
        let found = hits(&code, DATA_ACCESS);
        if !found.is_empty() {
            violations.push(format!("{path}: {found:?}"));
        }
    }
    assert!(
        violations.is_empty(),
        "transport code must call a service instead of a repository, a query \
         or a transaction:\n{}",
        violations.join("\n")
    );
}

#[test]
fn transport_exceptions_are_still_needed() {
    let sources = sources(&src());
    for (file, reason) in TRANSPORT_EXCEPTIONS {
        let (_, code) = sources
            .iter()
            .find(|(path, _)| path == file)
            .unwrap_or_else(|| panic!("{file} is listed as an exception but does not exist"));
        assert!(
            !hits(code, DATA_ACCESS).is_empty(),
            "{file} no longer reaches the database; drop its exception ({reason})"
        );
    }
}

#[test]
fn services_know_nothing_about_http_or_grpc() {
    let violations: Vec<_> = sources(&src().join("service"))
        .into_iter()
        .filter_map(|(path, code)| {
            let found = hits(&code, &["axum::", "tonic::", "StatusCode"]);
            (!found.is_empty()).then(|| format!("{path}: {found:?}"))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "services return their own errors and let transport choose status \
         codes:\n{}",
        violations.join("\n")
    );
}

#[test]
fn repositories_never_own_a_transaction() {
    let violations: Vec<_> = sources(&src().join("repository"))
        .into_iter()
        .filter_map(|(path, code)| {
            let found = hits(&code, &[".begin()", ".commit()", ".rollback()"]);
            (!found.is_empty()).then(|| format!("{path}: {found:?}"))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "repositories take an executor; the service opens and commits the \
         transaction:\n{}",
        violations.join("\n")
    );
}

#[test]
fn transport_detection_sees_the_known_entry_points() {
    let transport: Vec<_> = sources(&src())
        .into_iter()
        .filter(|(path, code)| is_transport(path, code))
        .map(|(path, _)| path)
        .collect();
    for expected in [
        "api.rs",
        "session.rs",
        "notification/api.rs",
        "user_auth.rs",
    ] {
        assert!(
            transport.iter().any(|path| path == expected),
            "{expected} should be recognised as transport; found {transport:?}"
        );
    }
}
