use std::sync::Arc;

use axum::{Router, http::StatusCode, routing::get};
use sqlx::PgPool;

use crate::{
    api, database::verify_schema, metrics, notification::NotificationService, web_api::WebApiConfig,
};

pub fn router(
    pool: PgPool,
    notification_ready: bool,
    notifications: Option<NotificationService>,
    web_api_config: &WebApiConfig,
) -> Router {
    let pool = Arc::new(pool);
    let router = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(
            "/readyz",
            get({
                let pool = pool.clone();
                move || {
                    let pool = pool.clone();
                    async move {
                        if notification_ready && verify_schema(&pool).await.is_ok() {
                            StatusCode::OK
                        } else {
                            StatusCode::SERVICE_UNAVAILABLE
                        }
                    }
                }
            }),
        )
        .merge(metrics::router(
            (*pool).clone(),
            notifications
                .as_ref()
                .is_some_and(|service| service.config.enabled),
        ));
    let delivery_enabled = notifications
        .as_ref()
        .is_some_and(|service| service.config.enabled);
    let api_router = api::router((*pool).clone())
        .merge(crate::user_auth::router((*pool).clone(), web_api_config))
        .merge(crate::onboarding::router((*pool).clone(), web_api_config))
        .merge(crate::attention::router((*pool).clone(), delivery_enabled))
        .merge(crate::inventory_api::router((*pool).clone()))
        .merge(crate::releases::router((*pool).clone()))
        .merge(crate::resources::router((*pool).clone()))
        .merge(crate::navigation::router((*pool).clone()))
        .merge(crate::notification::retention_api::router((*pool).clone()))
        .merge(crate::runtime_retention::api::router((*pool).clone()))
        .merge(crate::policy_api::router((*pool).clone()))
        .merge(crate::provisioning::router(
            (*pool).clone(),
            web_api_config.admin_authenticator.clone(),
            web_api_config.mail.clone(),
        ));
    let api_router = if let Some(notifications) = notifications {
        api_router.merge(crate::notification::api::router(
            (*pool).clone(),
            notifications,
        ))
    } else {
        api_router
    };
    router.merge(crate::web_api::router(api_router, web_api_config))
}
