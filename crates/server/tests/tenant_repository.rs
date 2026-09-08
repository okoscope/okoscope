use server::bootstrap::{BootstrapConfig, bootstrap};

fn config(organization: &str) -> BootstrapConfig {
    BootstrapConfig {
        organization_id: uuid::Uuid::new_v4(),
        project_id: uuid::Uuid::new_v4(),
        cluster_id: uuid::Uuid::new_v4(),
        application_id: uuid::Uuid::new_v4(),
        organization_slug: organization.into(),
        organization_name: organization.into(),
        project_slug: "payments".into(),
        project_name: "Payments".into(),
        cluster_external_id: "local".into(),
        cluster_name: "Local".into(),
        application_slug: "payment-api".into(),
        application_name: "Payment API".into(),
        cluster_credential: format!("credential-{organization}"),
        api_credential: format!("api-credential-{organization}"),
    }
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn identical_project_slugs_are_isolated_by_organization(pool: sqlx::PgPool) {
    let first = bootstrap(&pool, &config("first")).await.unwrap();
    let second = bootstrap(&pool, &config("second")).await.unwrap();
    assert_ne!(first.organization_id, second.organization_id);
    assert_ne!(first.project_id, second.project_id);
}
