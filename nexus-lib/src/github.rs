// SPDX-License-Identifier: GPL-2.0-only
// nexus/nexus-lib/src/github.rs

use serde::Deserialize;

/// A GitHub release.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub name: Option<String>,
    pub published_at: Option<String>,
    pub prerelease: bool,
    pub draft: bool,
    pub assets: Vec<GitHubAsset>,
}

/// A GitHub release asset (downloadable file).
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    pub content_type: String,
}

/// Errors from GitHub API operations.
#[derive(Debug)]
pub enum GitHubError {
    /// HTTP request failed.
    Http(String),
    /// API returned an error.
    Api(String),
    /// Release or asset not found.
    NotFound(String),
    /// JSON parsing error.
    Parse(String),
}

impl std::fmt::Display for GitHubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitHubError::Http(e) => write!(f, "GitHub API request failed: {e}"),
            GitHubError::Api(e) => write!(f, "GitHub API error: {e}"),
            GitHubError::NotFound(e) => write!(f, "not found: {e}"),
            GitHubError::Parse(e) => write!(f, "failed to parse GitHub response: {e}"),
        }
    }
}

impl std::error::Error for GitHubError {}

/// Client for GitHub Releases API.
pub struct GitHubReleaseClient {
    client: reqwest::Client,
    api_base: String,
}

impl GitHubReleaseClient {
    pub fn new(client: reqwest::Client) -> Self {
        GitHubReleaseClient {
            client,
            api_base: "https://api.github.com".to_string(),
        }
    }

    /// List releases for a repository (e.g., "Work-Fort/Anvil").
    pub async fn list_releases(&self, repo: &str) -> Result<Vec<GitHubRelease>, GitHubError> {
        let url = format!("{}/repos/{}/releases", self.api_base, repo);
        let resp = self.client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "nexus-asset-downloader")
            .send()
            .await
            .map_err(|e| GitHubError::Http(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GitHubError::NotFound(format!("repository '{repo}' not found")));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GitHubError::Api(format!("HTTP {status}: {body}")));
        }

        let releases: Vec<GitHubRelease> = resp.json().await
            .map_err(|e| GitHubError::Parse(e.to_string()))?;

        // Filter out drafts
        Ok(releases.into_iter().filter(|r| !r.draft).collect())
    }

    /// Get a specific release by tag name.
    pub async fn get_release(&self, repo: &str, tag: &str) -> Result<GitHubRelease, GitHubError> {
        let url = format!("{}/repos/{}/releases/tags/{}", self.api_base, repo, tag);
        let resp = self.client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "nexus-asset-downloader")
            .send()
            .await
            .map_err(|e| GitHubError::Http(e.to_string()))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GitHubError::NotFound(format!("release '{tag}' not found in '{repo}'")));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GitHubError::Api(format!("HTTP {status}: {body}")));
        }

        resp.json().await.map_err(|e| GitHubError::Parse(e.to_string()))
    }

    /// Find an asset by name in a release.
    pub fn find_asset<'a>(release: &'a GitHubRelease, name: &str) -> Option<&'a GitHubAsset> {
        release.assets.iter().find(|a| a.name == name)
    }

    /// Download a release asset's content as text (e.g., SHA256SUMS, signing-key.asc).
    pub async fn download_asset_text(&self, asset: &GitHubAsset) -> Result<String, GitHubError> {
        let resp = self.client
            .get(&asset.browser_download_url)
            .header("User-Agent", "nexus-asset-downloader")
            .send()
            .await
            .map_err(|e| GitHubError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(GitHubError::Http(
                format!("HTTP {} downloading {}", resp.status(), asset.name)
            ));
        }

        resp.text().await.map_err(|e| GitHubError::Http(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_release_deserializes() {
        let json = r#"{"tag_name":"v6.18.9","name":"v6.18.9","published_at":"2026-02-15T12:00:00Z","prerelease":false,"draft":false,"assets":[{"name":"vmlinux-6.18.9-x86_64.xz","browser_download_url":"https://example.com/download","size":5000000,"content_type":"application/x-xz"}]}"#;
        let release: GitHubRelease = serde_json::from_str(json).unwrap();
        assert_eq!(release.tag_name, "v6.18.9");
        assert_eq!(release.assets.len(), 1);
        assert_eq!(release.assets[0].name, "vmlinux-6.18.9-x86_64.xz");
    }

    #[test]
    fn find_asset_by_name() {
        let release = GitHubRelease {
            tag_name: "v1.0".to_string(),
            name: Some("v1.0".to_string()),
            published_at: None,
            prerelease: false,
            draft: false,
            assets: vec![
                GitHubAsset {
                    name: "SHA256SUMS".to_string(),
                    browser_download_url: "https://example.com/SHA256SUMS".to_string(),
                    size: 100,
                    content_type: "text/plain".to_string(),
                },
                GitHubAsset {
                    name: "vmlinux-x86_64.xz".to_string(),
                    browser_download_url: "https://example.com/vmlinux.xz".to_string(),
                    size: 5000000,
                    content_type: "application/x-xz".to_string(),
                },
            ],
        };

        assert!(GitHubReleaseClient::find_asset(&release, "SHA256SUMS").is_some());
        assert!(GitHubReleaseClient::find_asset(&release, "vmlinux-x86_64.xz").is_some());
        assert!(GitHubReleaseClient::find_asset(&release, "nonexistent").is_none());
    }

    #[test]
    fn github_error_display() {
        let err = GitHubError::NotFound("repo 'foo' not found".to_string());
        assert!(err.to_string().contains("not found"));

        let err = GitHubError::Http("connection refused".to_string());
        assert!(err.to_string().contains("request failed"));
    }
}
