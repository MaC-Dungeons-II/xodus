// SPDX-License-Identifier: GPL-3.0-only
//! A deliberately small machine interface. Never serialize PackageDetails:
//! it contains CDN access URLs and key material. Revision hashing is shared
//! with streaming, so changed access URLs do not invalidate a checked version.
use super::streaming::{
    authenticated_package_identity, package_game_version, user_credentials_current,
};
use serde_json::{Value, json};
use std::process::ExitCode;
use xodus::{models::packagespc::PackageDetails, tokens::TokenManager};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
) -> ExitCode {
    if product.len() != 12
        || !product
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return ExitCode::FAILURE;
    }
    if !user_credentials_current(tokens) {
        return ExitCode::from(77);
    }
    let result = async {
        let content = crate::package::get_content_id(client, product.clone(), market)
            .await
            .ok()?;
        let package = crate::package::get_packages(client, tokens, content.clone())
            .await
            .ok()?;
        if package.content_id != content {
            return None;
        }
        projection(&product, &package)
    }
    .await;
    match result {
        Some(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        None => ExitCode::FAILURE,
    }
}

fn projection(product: &str, package: &PackageDetails) -> Option<Value> {
    if uuid::Uuid::parse_str(&package.content_id).is_err() || package.update_predownload {
        return None;
    }
    let files: Vec<_> = package
        .package_files
        .iter()
        .filter(|f| f.file_name.ends_with(".msixvc"))
        .collect();
    if files.len() != 1 {
        return None;
    }
    let file = files[0];
    let version = package_game_version(package, file)?;
    let identity = authenticated_package_identity(package, file)?;
    Some(
        json!({"schema":1, "store_id":product, "content_id":package.content_id,
        "version_id":package.version_id, "version":version,
        "package_identity":identity, "size_bytes":file.file_size}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package() -> PackageDetails {
        serde_json::from_value(json!({"PackageFound":true,"ContentId":"11111111-1111-4111-8111-111111111111",
            "VersionId":"22222222-2222-4222-8222-222222222222","Version":"1.2.3.4",
            "UpdatePredownload":false,"AvailabilityDate":"","PackageFiles":[{
                "ContentId":"11111111-1111-4111-8111-111111111111","VersionId":"22222222-2222-4222-8222-222222222222",
                "FileName":"game.msixvc","FileSize":4096,"FileHash":"public-hash",
                "KeyBlob":"NEVER_SERIALIZE_KEY","CdnRootPaths":["https://invalid.example/PRIVATE_URL"],
                "BackgroundCdnRootPaths":[],"RelativeUrl":"SIGNED_PARAMETERS","UpdateType":0,
                "LicenseUsageType":0,"ModifiedDate":""}]})).unwrap()
    }
    #[test]
    fn only_allowlisted_metadata_is_emitted() {
        let p = package();
        let value = projection("AAAAAAAAAAAA", &p).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 7);
        assert_eq!(
            value["package_identity"],
            authenticated_package_identity(&p, &p.package_files[0]).unwrap()
        );
        let text = value.to_string();
        for private in [
            "NEVER_SERIALIZE",
            "PRIVATE_URL",
            "SIGNED_PARAMETERS",
            "FileHash",
            "FileName",
        ] {
            assert!(!text.contains(private));
        }
    }
    #[test]
    fn ambiguous_unavailable_or_malformed_versions_are_not_updates() {
        let mut p = package();
        p.update_predownload = true;
        assert!(projection("AAAAAAAAAAAA", &p).is_none());
        p.update_predownload = false;
        p.version = "1.2".into();
        assert!(projection("AAAAAAAAAAAA", &p).is_none());
        p.version = "1.2.3.4".into();
        p.package_files.push(p.package_files[0].clone());
        assert!(projection("AAAAAAAAAAAA", &p).is_none());
    }
    #[test]
    fn populated_not_found_response_is_not_an_available_package() {
        let mut p = package();
        p.package_found = false;
        assert!(projection("AAAAAAAAAAAA", &p).is_none());
    }
    #[test]
    fn nonpositive_package_lengths_are_not_published() {
        let mut p = package();
        for size in [0, -1] {
            p.package_files[0].file_size = size;
            assert!(projection("AAAAAAAAAAAA", &p).is_none());
        }
    }
    fn compound_package() -> PackageDetails {
        let mut p = package();
        let revision = "1.8.16.0.aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        p.version = revision.into();
        p.version_id = revision.into();
        p.package_files[0].version_id = revision.into();
        p.package_files[0].file_hash.clear();
        p
    }
    #[test]
    fn authenticated_compound_revision_projects_only_executable_version() {
        let p = compound_package();
        let result = projection("AAAAAAAAAAAA", &p).unwrap();
        assert_eq!(result["version"], "1.8.16.0");
        assert_eq!(result["version_id"], p.version);
        assert_eq!(result.as_object().unwrap().len(), 7);
    }
    #[test]
    fn compound_revision_requires_exact_syntax_and_matching_file_revision() {
        let mut p = compound_package();
        p.package_files[0].version_id = "1.8.16.0.ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee".into();
        assert!(projection("AAAAAAAAAAAA", &p).is_none());
        for suffix in [
            "not-a-guid",
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.extra",
            "",
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee ",
        ] {
            let revision = format!("1.8.16.0.{suffix}");
            p.version = revision.clone();
            p.version_id = revision.clone();
            p.package_files[0].version_id = revision;
            assert!(projection("AAAAAAAAAAAA", &p).is_none());
        }
        let mut p = package();
        p.package_files[0].file_hash.clear();
        assert!(projection("AAAAAAAAAAAA", &p).is_none());
    }
    #[test]
    fn compound_build_and_size_changes_cannot_reuse_checked_revision() {
        let a = compound_package();
        let original = authenticated_package_identity(&a, &a.package_files[0]).unwrap();
        let mut b = a.clone();
        for revision in [
            "1.8.16.0.ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "1.8.17.0.aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        ] {
            b.version = revision.into();
            b.version_id = revision.into();
            b.package_files[0].version_id = revision.into();
            assert_ne!(
                authenticated_package_identity(&b, &b.package_files[0]).unwrap(),
                original
            );
        }
        b = a.clone();
        b.package_files[0].file_size += 1;
        assert_ne!(
            authenticated_package_identity(&b, &b.package_files[0]).unwrap(),
            original
        );
        b = a;
        b.package_files[0].cdn_root_paths = vec!["https://invalid.example/new-access".into()];
        b.package_files[0].relative_url = "rotated-access".into();
        b.package_files[0].key_blob = "rotated-key".into();
        assert_eq!(
            authenticated_package_identity(&b, &b.package_files[0]).unwrap(),
            original
        );
    }
}
