//! Token 管理模块
//!
//! 负责 Token 过期检测和刷新，使用 Social 认证方式

use anyhow::bail;
use chrono::{DateTime, Duration, Utc};

use crate::kiro::machine_id;
use crate::kiro::model::credentials::KiroCredentials;
use crate::model::config::Config;
use crate::kiro::model::token_refresh::{RefreshRequest, RefreshResponse};

/// 检查 Token 是否在指定时间内过期
fn is_token_expiring_within(credentials: &KiroCredentials, minutes: i64) -> Option<bool> {
    credentials
        .expires_at
        .as_ref()
        .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires| expires <= Utc::now() + Duration::minutes(minutes))
}

/// 检查 Token 是否已过期
///
/// 提前 5 分钟判断为过期，仅支持 RFC3339 格式
pub fn is_token_expired(credentials: &KiroCredentials) -> bool {
    // 如果没有过期时间信息，保守地认为可能需要刷新
    is_token_expiring_within(credentials, 5).unwrap_or(true)
}

/// 检查 Token 是否即将过期（10分钟内）
pub fn is_token_expiring_soon(credentials: &KiroCredentials) -> bool {
    is_token_expiring_within(credentials, 10).unwrap_or(false)
}

/// 验证 refreshToken 的基本有效性
pub fn validate_refresh_token(credentials: &KiroCredentials) -> anyhow::Result<()> {
    let refresh_token = credentials
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("缺少 refreshToken"))?;

    if refresh_token.is_empty() {
        bail!("refreshToken 为空");
    }

    // 检测 refreshToken 是否被截断
    if refresh_token.len() < 100
        || refresh_token.ends_with("...")
        || refresh_token.contains("...")
    {
        bail!(
            "refreshToken 已被截断（长度: {} 字符）。\n\
             这通常是 Kiro IDE 为了防止凭证被第三方工具使用而故意截断的。",
            refresh_token.len()
        );
    }

    Ok(())
}

/// 刷新 Token
///
/// 返回更新后的 KiroCredentials
pub async fn refresh_token(
    credentials: &KiroCredentials,
    config: &Config,
) -> anyhow::Result<KiroCredentials> {
    // 首先验证 refreshToken
    validate_refresh_token(credentials)?;

    let refresh_token = credentials.refresh_token.as_ref().unwrap();
    let region = &config.region;

    let refresh_url = format!("https://prod.{}.auth.desktop.kiro.dev/refreshToken", region);
    let refresh_domain = format!("prod.{}.auth.desktop.kiro.dev", region);
    let machine_id = machine_id::generate_from_credentials(credentials, config)
        .ok_or_else(|| anyhow::anyhow!("无法生成 machineId"))?;
    let kiro_version = &config.kiro_version;

    refresh_token_social(&refresh_url, &refresh_domain, refresh_token, &machine_id, kiro_version, credentials).await
}

/// Social 认证方式刷新 Token
async fn refresh_token_social(
    refresh_url: &str,
    refresh_domain: &str,
    refresh_token: &str,
    machine_id: &str,
    kiro_version: &str,
    original_credentials: &KiroCredentials,
) -> anyhow::Result<KiroCredentials> {
    let client = reqwest::Client::new();

    let body = RefreshRequest {
        refresh_token: refresh_token.to_string(),
    };

    // 符合抓包顺序与大小写
    let response = client
        .post(refresh_url)
        .header("Accept", "application/json, text/plain, */*")
        .header("Content-Type", "application/json")
        .header("User-Agent", format!("KiroIDE-{}-{}", kiro_version, machine_id))
        .header("Accept-Encoding", "gzip, compress, deflate, br")
        .header("host", refresh_domain)
        .header("Connection", "close")
        .json(&body)
        .send()
        .await?;

    handle_refresh_response(response, original_credentials).await
}

/// 处理刷新响应
async fn handle_refresh_response(
    response: reqwest::Response,
    original_credentials: &KiroCredentials,
) -> anyhow::Result<KiroCredentials> {
    let status = response.status();

    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        let error_msg = match status.as_u16() {
            401 => "OAuth 凭证已过期或无效，需要重新认证",
            403 => "权限不足，无法刷新 Token",
            429 => "请求过于频繁，已被限流",
            500..=599 => "服务器错误，AWS OAuth 服务暂时不可用",
            _ => "Token 刷新失败",
        };
        bail!("{}: {} {}", error_msg, status, body_text);
    }

    let data: RefreshResponse = response.json().await?;

    // 创建更新后的凭证
    let mut new_credentials = original_credentials.clone();
    new_credentials.access_token = Some(data.access_token);

    if let Some(new_refresh_token) = data.refresh_token {
        new_credentials.refresh_token = Some(new_refresh_token);
    }

    if let Some(profile_arn) = data.profile_arn {
        new_credentials.profile_arn = Some(profile_arn);
    }

    // 更新过期时间
    if let Some(expires_in) = data.expires_in {
        let expires_at = Utc::now() + Duration::seconds(expires_in);
        new_credentials.expires_at = Some(expires_at.to_rfc3339());
    }

    Ok(new_credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_token_expired_with_expired_token() {
        let mut credentials = KiroCredentials::default();
        // 设置一个过去的时间
        credentials.expires_at = Some("2020-01-01T00:00:00Z".to_string());

        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_with_valid_token() {
        let mut credentials = KiroCredentials::default();
        // 设置一个未来的时间（1小时后）
        let future = Utc::now() + Duration::hours(1);
        credentials.expires_at = Some(future.to_rfc3339());

        assert!(!is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_within_5_minutes() {
        let mut credentials = KiroCredentials::default();
        // 设置 3 分钟后过期（应该被判断为过期）
        let expires = Utc::now() + Duration::minutes(3);
        credentials.expires_at = Some(expires.to_rfc3339());

        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expired_no_expires_at() {
        let credentials = KiroCredentials::default();
        // 没有过期时间，保守地认为过期
        assert!(is_token_expired(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_within_10_minutes() {
        let mut credentials = KiroCredentials::default();
        // 设置 8 分钟后过期
        let expires = Utc::now() + Duration::minutes(8);
        credentials.expires_at = Some(expires.to_rfc3339());

        assert!(is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_is_token_expiring_soon_beyond_10_minutes() {
        let mut credentials = KiroCredentials::default();
        // 设置 15 分钟后过期
        let expires = Utc::now() + Duration::minutes(15);
        credentials.expires_at = Some(expires.to_rfc3339());

        assert!(!is_token_expiring_soon(&credentials));
    }

    #[test]
    fn test_validate_refresh_token_missing() {
        let credentials = KiroCredentials::default();
        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("缺少"));
    }

    #[test]
    fn test_validate_refresh_token_empty() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("".to_string());

        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("为空"));
    }

    #[test]
    fn test_validate_refresh_token_truncated() {
        let mut credentials = KiroCredentials::default();
        credentials.refresh_token = Some("short_token...".to_string());

        let result = validate_refresh_token(&credentials);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("截断"));
    }

    #[test]
    fn test_validate_refresh_token_valid() {
        let mut credentials = KiroCredentials::default();
        // 创建一个足够长的 token（超过 100 字符）
        credentials.refresh_token = Some("a".repeat(150));

        let result = validate_refresh_token(&credentials);
        assert!(result.is_ok());
    }
}
