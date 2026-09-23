//! Architecture checks.
//!
//! SQL belongs to the repository layer (`crates/server/src/repository`), not to
//! HTTP handlers, workers or domain modules. That rule is stated in
//! `repository/mod.rs`; this test is what enforces it.
//!
//! The migration of existing statements is incremental, so the test is a
//! ratchet: each module outside the repository layer may issue at most the
//! number of `sqlx::query*` calls recorded below, and a module not listed may
//! issue none. Adding SQL outside the repository fails the build. Moving SQL
//! into the repository also fails it until the count here is lowered to match,
//! so the table can only ever shrink — and when it is empty, the rule holds
//! everywhere.
//!
//! Code after a module's `#[cfg(test)]` is not counted: tests seed fixtures
//! with SQL directly, and that is not an architectural concern.

use std::collections::BTreeMap;
use std::path::Path;

/// Remaining `sqlx::query*` calls per module, relative to `crates/server/src`.
/// Lower an entry when you move statements into the repository layer; delete
/// it when it reaches zero. Never raise one.
const REMAINING: &[(&str, usize)] = &[
    ("access_api.rs", 19),
    ("access_audit.rs", 1),
    ("agent_health.rs", 13),
    ("api.rs", 13),
    ("application_credentials.rs", 5),
    ("attention.rs", 14),
    ("auth.rs", 1),
    ("backfill.rs", 2),
    ("bootstrap.rs", 5),
    ("database.rs", 1),
    ("grouping.rs", 3),
    ("ingestion.rs", 2),
    ("inventory.rs", 8),
    ("inventory_api.rs", 16),
    ("inventory_operations.rs", 4),
    ("invitation_api.rs", 23),
    ("main.rs", 1),
    ("metrics.rs", 4),
    ("notification/health.rs", 2),
    ("notification/recovery.rs", 13),
    ("notification/repository.rs", 8),
    ("notification/retention.rs", 8),
    ("notification/retention_settings.rs", 5),
    ("notification/worker.rs", 20),
    ("onboarding.rs", 13),
    ("policy_api.rs", 29),
    ("policy_projection.rs", 5),
    ("policy_recompute.rs", 6),
    ("provisioning.rs", 12),
    ("release_discovery.rs", 13),
    ("resources.rs", 16),
    ("runtime_retention/history.rs", 2),
    ("runtime_retention/settings.rs", 7),
    ("runtime_retention/worker.rs", 28),
    ("session.rs", 5),
    ("termination_projection.rs", 11),
    ("transactional_mail.rs", 9),
    ("user_auth.rs", 17),
];

fn count_outside_repository(root: &Path, dir: &Path, counts: &mut BTreeMap<String, usize>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let relative = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            if relative != "repository" {
                count_outside_repository(root, &path, counts);
            }
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let production = source
            .find("#[cfg(test)]")
            .map_or(source.as_str(), |start| &source[..start]);
        let calls = production.matches("sqlx::query").count();
        if calls > 0 {
            counts.insert(relative, calls);
        }
    }
}

#[test]
fn sql_stays_in_the_repository_layer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut actual = BTreeMap::new();
    count_outside_repository(&root, &root, &mut actual);
    let allowed: BTreeMap<String, usize> = REMAINING
        .iter()
        .map(|(module, calls)| ((*module).to_owned(), *calls))
        .collect();

    let mut problems = Vec::new();
    for (module, calls) in &actual {
        match allowed.get(module) {
            None => problems.push(format!(
                "{module}: {calls} sqlx::query call(s) outside the repository layer; move them into crates/server/src/repository"
            )),
            Some(limit) if calls > limit => problems.push(format!(
                "{module}: {calls} sqlx::query call(s), more than the {limit} still allowed; new SQL belongs in the repository layer"
            )),
            Some(limit) if calls < limit => problems.push(format!(
                "{module}: {calls} sqlx::query call(s), fewer than the {limit} recorded; lower its entry in REMAINING to {calls}"
            )),
            Some(_) => {}
        }
    }
    for module in allowed.keys() {
        if !actual.contains_key(module) {
            problems.push(format!(
                "{module}: no SQL left outside the repository layer; delete its entry from REMAINING"
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}
