use std::{fs, path::Path};

use server::transactional_mail::{Locale, TemplateData, render};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = Path::new("target/mail-previews");
    fs::create_dir_all(output)?;
    for (name, data) in templates() {
        for locale in [Locale::En, Locale::Ru] {
            let rendered = render(locale, &data);
            fs::write(
                output.join(format!("{name}-{}.html", locale.as_str())),
                rendered.html,
            )?;
            fs::write(
                output.join(format!("{name}-{}.txt", locale.as_str())),
                rendered.text,
            )?;
        }
    }
    println!("Rendered safe samples in {}", output.display());
    Ok(())
}

fn templates() -> [(&'static str, TemplateData); 4] {
    [
        (
            "verify-email",
            TemplateData::VerifyEmail {
                action_url: "https://okoscope.example/verify-email#SAMPLE_NOT_A_TOKEN".into(),
                organization_name: "Northstar Systems".into(),
                expires_minutes: 1_440,
            },
        ),
        (
            "reset-password",
            TemplateData::ResetPassword {
                action_url: "https://okoscope.example/reset-password#SAMPLE_NOT_A_TOKEN".into(),
                expires_minutes: 30,
            },
        ),
        ("password-changed", TemplateData::PasswordChanged),
        (
            "application-created",
            TemplateData::ApplicationCreated {
                application_name: "Payments API".into(),
                project_name: "Production".into(),
            },
        ),
    ]
}
