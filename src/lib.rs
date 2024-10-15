//! # 阿里云 STS SDK

//! 实现了 `AssumeRole` API 的调用，生成一对临时的访问 ID 和访问密钥，可以让前端利用 [ali oss](https://www.npmjs.com/package/ali-oss) 库上传比较大的文件。

//! 使用比较简单：

//! ```rust
//! async fn test_assume_role() {
//!     simple_logger::init_with_level(log::Level::Debug).unwrap();
//!     dotenv::dotenv().ok();

//!     let aid = dotenv::var("ACCESS_KEY_ID").unwrap();
//!     let asec = dotenv::var("ACCESS_KEY_SECRET").unwrap();
//!     let arn = dotenv::var("ARN").unwrap();
//!     let role_session_name = "aliyun-sts-rust-sdk";

//!     let policy = Policy {
//!         version: Versions::V1,
//!         statement: vec![
//!             StatementBlock {
//!                 action: StringOrArray::ArrayValue(vec!["oss:*".to_owned()]),
//!                 effect: Effects::Allow,
//!                 resource: StringOrArray::ArrayValue(vec!["acs:oss:*:*:mi-dev-public/yuanyq-test/file-from-rust.zip".to_owned()]),
//!                 condition: None,
//!             }
//!         ]
//!     };

//!     let req = AssumeRoleRequest::new(&arn, role_session_name, Some(policy), 3600);
//!     let client = StsClient::new("sts.aliyuncs.com", &aid, &asec);

//!     match client.assume_role(req).await {
//!         Ok(r) => {
//!             assert!(r.credentials.is_some());
//!         },
//!         Err(e) => println!("{:?}", e)
//!     }
//! }
//! ```

//! 或者，调用便捷的函数：`sts_for_put_object`:

//! ```rust
//! client.sts_for_put_object(&arn, "mi-dev-public", "yuanyq-test/file-from-rust.zip", 3600)
//! ```

use std::collections::HashMap;

use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client, Method,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize)]
pub enum Versions {
    #[serde(rename = "1")]
    V1,
}

#[derive(Serialize)]
pub enum Effects {
    Allow,
    Deny,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum StringOrArray {
    StringValue(String),
    ArrayValue(Vec<String>),
}

#[derive(Serialize)]
pub struct StatementBlock {
    #[serde(rename = "Effect")]
    pub effect: Effects,

    #[serde(rename = "Action")]
    pub action: StringOrArray,

    #[serde(rename = "Resource")]
    pub resource: StringOrArray,

    #[serde(rename = "Condition", skip_serializing_if = "Option::is_none")]
    pub condition: Option<HashMap<String, StringOrArray>>,
}

///
/// 权限策略。
///
/// 更多信息请参考 [阿里云官方文档](https://help.aliyun.com/zh/ram/user-guide/policy-language/?spm=a2c4g.11186623.0.0.5f0063e7VwDmOd)。
///
#[derive(Serialize)]
pub struct Policy {
    #[serde(rename = "Version")]
    pub version: Versions,

    #[serde(rename = "Statement")]
    pub statement: Vec<StatementBlock>,
}

impl Policy {
    /// 使用 Version1 创建一个 `Policy`。
    pub fn v1<I>(stmts: I) -> Policy
    where
        I: IntoIterator<Item = StatementBlock>,
    {
        Self {
            version: Versions::V1,
            statement: stmts.into_iter().collect(),
        }
    }
}

/// AssumeRole 请求体
#[derive(Serialize)]
pub struct AssumeRoleRequest {
    /// Token 有效期。单位：秒。
    ///
    /// Token 有效期最小值为 `900` 秒，最大值为要扮演角色的 `MaxSessionDuration` 时间。默认值为 `3600` 秒。
    ///
    #[serde(rename = "DurationSeconds")]
    pub duration_seconds: u32,

    ///
    /// 为 STS Token 额外添加的一个权限策略，进一步限制 STS Token 的权限。具体如下：
    ///
    /// - 如果指定该权限策略，则 STS Token 最终的权限策略取 RAM 角色权限策略与该权限策略的交集。
    /// - 如果不指定该权限策略，则 STS Token 最终的权限策略取 RAM 角色的权限策略。
    ///
    ///
    #[serde(rename = "Policy", skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,

    /// 要扮演的 RAM 角色 ARN。
    ///
    #[serde(rename = "RoleArn")]
    pub role_arn: String,

    ///
    /// 角色会话名称。
    ///
    /// 该参数为用户自定义参数。
    /// 通常设置为调用该 API 的用户身份，例如：用户名。在操作审计日志中，
    /// 即使是同一个 RAM 角色执行的操作，
    /// 也可以根据不同的 `RoleSessionName` 来区分实际操作者，以实现用户级别的访问审计。
    ///
    /// 长度为 `2~64` 个字符，可包含英文字母、数字和特殊字符`.@-_`。
    ///
    #[serde(rename = "RoleSessionName")]
    pub role_session_name: String,

    ///
    /// 角色外部 ID。
    /// 该参数为外部提供的用于表示角色的参数信息，主要功能是防止混淆代理人问题。
    ///
    /// 长度为 `2~1224` 个字符，可包含英文字母、数字和特殊字符 `=,.@:/-_。正则为：[\w+=,.@:\/-]*`。
    ///
    #[serde(rename = "ExternalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

impl AssumeRoleRequest {
    pub fn new(
        role_arn: &str,
        role_session_name: &str,
        policy: Option<Policy>,
        duration_seconds: u32,
    ) -> Self {
        Self {
            duration_seconds,
            policy,
            external_id: None,
            role_arn: role_arn.to_owned(),
            role_session_name: role_session_name.to_owned(),
        }
    }
}

/// AssumeRole 响应中的 `AssumeRoleUser`
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AssumeRoleResponseUser {
    #[serde(rename = "Arn")]
    pub arn: String,

    #[serde(rename = "AssumedRoleId")]
    pub assume_role_id: String,
}

/// AssumeRole 响应中的 `Credentials`
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AssumeRoleResponseCredentials {
    #[serde(rename = "SecurityToken")]
    pub security_token: String,

    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "AccessKeySecret")]
    pub access_key_secret: String,

    /// ISO 8601 格式的到期时间，格式为 `yyyy-MM-ddTHH:mm:ssZ`，例如 `2018-01-01T12:00:00Z`
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

/// AssumeRole 的响应
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AssumeRoleResponse {
    #[serde(rename = "RequestId")]
    pub request_id: String,

    #[serde(rename = "AssumeRoleUser")]
    pub assume_role_user: Option<AssumeRoleResponseUser>,

    #[serde(rename = "Credentials")]
    pub credentials: Option<AssumeRoleResponseCredentials>,

    #[serde(rename = "Message")]
    pub message: Option<String>,

    #[serde(rename = "Recommend")]
    pub recommend: Option<String>,

    #[serde(rename = "HostId")]
    pub host_id: Option<String>,

    #[serde(rename = "Code")]
    pub code: Option<String>,
}

pub struct StsClient {
    endpoint: String,
    access_key_id: String,
    access_key_secret: String,
    req_client: Client,
}

impl StsClient {
    pub fn new(endpoint: &str, access_key_id: &str, access_key_secret: &str) -> Self {
        let client = Client::new();
        Self {
            endpoint: endpoint.to_owned(),
            access_key_id: access_key_id.to_owned(),
            access_key_secret: access_key_secret.to_owned(),
            req_client: client,
        }
    }

    /// 生成上传文件到 `${bucket_name}/${object_key}` 的 STS 凭证。
    pub async fn sts_for_put_object(
        &self,
        arn: &str,
        bucket_name: &str,
        object_key: &str,
        duration_seconds: u32,
    ) -> Result<AssumeRoleResponseCredentials, String> {
        let sanitized_object_key = if object_key.starts_with("/") {
            &object_key[1..]
        } else {
            object_key
        };

        let policy = Policy {
            version: Versions::V1,
            statement: vec![StatementBlock {
                action: StringOrArray::ArrayValue(vec!["oss:*".to_owned()]),
                effect: Effects::Allow,
                resource: StringOrArray::ArrayValue(vec![format!(
                    "acs:oss:*:*:{}/{}",
                    bucket_name, sanitized_object_key
                )]),
                condition: None,
            }],
        };

        let req =
            AssumeRoleRequest::new(arn, "aliyun-sts-rust-sdk", Some(policy), duration_seconds);

        match self.assume_role(req).await {
            Ok(r) => {
                if let Some(c) = r.credentials {
                    Ok(c)
                } else {
                    Err(r.message.unwrap_or("调用阿里云服务失败".to_owned()))
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn assume_role(&self, req: AssumeRoleRequest) -> Result<AssumeRoleResponse, String> {
        let mut headers = HeaderMap::new();
        headers.insert("x-acs-action", HeaderValue::from_static("AssumeRole"));

        let AssumeRoleRequest {
            duration_seconds,
            policy,
            role_arn,
            role_session_name,
            external_id,
        } = req;

        let mut payload_map = HashMap::from([
            (
                "DurationSeconds".to_owned(),
                format!("{}", duration_seconds),
            ),
            ("RoleArn".to_owned(), role_arn),
            ("RoleSessionName".to_owned(), role_session_name),
        ]);

        if let Some(eid) = external_id {
            payload_map.insert("ExternalId".to_owned(), eid);
        }

        if let Some(p) = policy {
            payload_map.insert("Policy".to_owned(), serde_json::to_string(&p).unwrap());
        }

        match self
            .do_request(Method::POST, "/", Some(headers), None, Some(payload_map))
            .await
        {
            Ok(content) => {
                let res = match serde_json::from_str(&content) {
                    Ok(r) => Ok(r),
                    Err(_) => Err(format!("Error while parsing response: {}", content)),
                };

                res
            }
            Err(e) => Err(e),
        }
    }

    pub async fn do_request(
        &self,
        method: Method,
        uri: &str,
        headers: Option<HeaderMap>,
        query: Option<HashMap<String, String>>,
        payload: Option<HashMap<String, String>>,
    ) -> Result<String, String> {
        let dt_string = iso_8601_data_time_string();
        let nonce = format!("{}", Utc::now().timestamp_millis());

        let mut all_headers = match headers {
            Some(h) => h,
            None => HeaderMap::new(),
        };

        all_headers.insert("x-sdk-version", HeaderValue::from_static("rust/0.1.0"));
        all_headers.insert("x-acs-version", HeaderValue::from_static("2015-04-01"));
        all_headers.insert(
            "x-acs-signature-nonce",
            HeaderValue::from_str(&nonce).unwrap(),
        );
        all_headers.insert("x-acs-date", HeaderValue::from_str(&dt_string).unwrap());
        all_headers.insert("host", HeaderValue::from_str(&self.endpoint).unwrap());
        all_headers.insert("Accept", HeaderValue::from_static("application/json"));

        let canonical_query_string = match query {
            Some(map) => {
                let mut items = map.iter().collect::<Vec<(_, _)>>();

                items.sort_by(|a, b| a.0.cmp(b.0));
                items
                    .into_iter()
                    .map(|item| {
                        format!(
                            "{}={}",
                            urlencoding::encode(item.0),
                            urlencoding::encode(item.1)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("&")
            }
            None => "".to_owned(),
        };

        // 组装 FORM 表单请求体。这个就不需要按照 key 排序了
        let payload_string = match payload {
            Some(map) => map
                .iter()
                .map(|item| {
                    format!(
                        "{}={}",
                        urlencoding::encode(item.0),
                        urlencoding::encode(item.1)
                    )
                })
                .collect::<Vec<_>>()
                .join("&"),
            None => "".to_string(),
        };

        log::debug!("payload string: \n{}", payload_string);

        let payload_data = payload_string.as_bytes();

        // 对请求体内容做 SHA256 摘要
        let payload_hash_string = sha256(payload_data);
        all_headers.insert(
            "x-acs-content-sha256",
            HeaderValue::from_str(&payload_hash_string).unwrap(),
        );

        // 需要参与签名的请求头
        // 请求头转小写（阿里云公共请求头包含： host 和 x-acs- 开头的）
        // 排序
        let mut canonical_headers = all_headers
            .iter()
            .map(|item| (item.0.to_string().to_lowercase(), item.1))
            .filter(|item| item.0 == "host" || item.0.starts_with("x-acs"))
            .collect::<Vec<(_, _)>>();

        canonical_headers.sort_by(|a, b| a.0.cmp(&b.0));

        // 请求头的名和值使用冒号 (:) 拼接，再使用换行符拼接
        let canonical_header_string = canonical_headers
            .iter()
            .map(|item| format!("{}:{}", item.0, item.1.to_str().unwrap()))
            .collect::<Vec<_>>()
            .join("\n");

        // 请求头的名使用分号（;） 拼接
        let canonical_header_name_string = canonical_headers
            .iter()
            .map(|item| item.0.clone())
            .collect::<Vec<_>>()
            .join(";");

        // 构造规范请求的文本
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n\n{}\n{}",
            method.to_string(),
            uri,
            canonical_query_string,
            canonical_header_string,
            canonical_header_name_string,
            payload_hash_string
        );

        log::info!("canonical request: \n{}", canonical_request);

        // 对规范请求体做 SHA256 摘要
        let canonical_request_hash_string = sha256(canonical_request.as_bytes());

        // 构造加签字符串
        let string_to_sign = format!("ACS3-HMAC-SHA256\n{}", canonical_request_hash_string);

        log::info!("string to sign: {}", string_to_sign);

        // 对加签字符串进行 Hmac-SHA256 摘要
        let key_data = self.access_key_secret.as_bytes();
        let sig = hmac_sha256(key_data, string_to_sign.as_bytes());

        log::info!("signature: {}", sig);

        let auth_header = format!(
            "ACS3-HMAC-SHA256 Credential={},SignedHeaders={},Signature={}",
            self.access_key_id, canonical_header_name_string, sig
        );

        log::info!("auth header: {}", auth_header);

        all_headers.insert(
            "Authorization",
            HeaderValue::from_str(&auth_header).unwrap(),
        );

        if !payload_string.is_empty() {
            all_headers.insert(
                "Content-Length",
                HeaderValue::from_str(format!("{}", payload_data.len()).as_str()).unwrap(),
            );
        }

        all_headers.insert(
            "Content-Type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let full_url = if canonical_query_string.is_empty() {
            format!("https://{}{}", self.endpoint, uri)
        } else {
            format!(
                "https://{}{}?{}",
                self.endpoint, uri, canonical_query_string
            )
        };

        let req = Client::new().request(method, full_url).headers(all_headers);
        let req = if payload_string.is_empty() {
            req
        } else {
            req.body(payload_string)
        };

        let req = req.build().unwrap();

        let response = match self.req_client.execute(req).await.unwrap().text().await {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };

        log::debug!("response: {}", response);

        Ok(response)
    }
}

/// Hmac-SHA256 摘要，返回结果是十六进制小写字符串
fn hmac_sha256(key_data: &[u8], msg_data: &[u8]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key_data).unwrap();
    mac.update(msg_data);
    let mac_data = mac.finalize().into_bytes();
    hex::encode(mac_data)
}

/// SHA256 摘要
fn sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let ret = hasher.finalize();
    hex::encode(ret)
}

/// [官方文档](https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature?spm=a2c4g.11186623.0.0.500d46bc5FXfiO)
/// 按照 ISO 860 标准表示的 UTC 时间，格式为 `yyyy-MM-ddTHH:mm:ssZ`，例如 `2018-01-01T12:00:00Z`。
fn iso_8601_data_time_string() -> String {
    let s = Utc::now().to_rfc3339();
    format!("{}Z", &s[..19])
}

#[cfg(test)]
mod test {
    use crate::{
        iso_8601_data_time_string, AssumeRoleRequest, Effects, Policy, StatementBlock,
        StringOrArray, StsClient, Versions,
    };

    #[test]
    fn test_dt_string() {
        println!("{}", iso_8601_data_time_string());
    }

    /// Testing assume role request serializing
    #[test]
    fn test_ser() {
        dotenv::dotenv().ok();

        let arn = dotenv::var("ARN").unwrap();
        let role_session_name = "aliyun-sts-rust-sdk";

        let policy = Policy {
            version: Versions::V1,
            statement: vec![StatementBlock {
                action: StringOrArray::ArrayValue(vec!["oss:*".to_owned()]),
                effect: Effects::Allow,
                resource: StringOrArray::ArrayValue(vec!["acs:oss:*:*:xxxxxx".to_owned()]),
                condition: None,
            }],
        };

        let req = AssumeRoleRequest::new(&arn, role_session_name, Some(policy), 3600);
        println!("{}", serde_json::to_string(&req).unwrap());
    }

    #[tokio::test]
    async fn test_assume_role() {
        simple_logger::init_with_level(log::Level::Debug).unwrap();
        dotenv::dotenv().ok();

        let aid = dotenv::var("ACCESS_KEY_ID").unwrap();
        let asec = dotenv::var("ACCESS_KEY_SECRET").unwrap();
        let arn = dotenv::var("ARN").unwrap();
        let role_session_name = "aliyun-sts-rust-sdk";

        let policy = Policy {
            version: Versions::V1,
            statement: vec![StatementBlock {
                action: StringOrArray::ArrayValue(vec!["oss:*".to_owned()]),
                effect: Effects::Allow,
                resource: StringOrArray::ArrayValue(vec![
                    "acs:oss:*:*:mi-dev-public/yuanyq-test/file-from-rust.zip".to_owned(),
                ]),
                condition: None,
            }],
        };

        let req = AssumeRoleRequest::new(&arn, role_session_name, Some(policy), 3600);
        let client = StsClient::new("sts.aliyuncs.com", &aid, &asec);

        match client.assume_role(req).await {
            Ok(r) => {
                assert!(r.credentials.is_some());
                println!("{}", serde_json::to_string(&r).unwrap());
            }
            Err(e) => println!("{:?}", e),
        }
    }

    #[tokio::test]
    async fn test_sts_for_put() {
        simple_logger::init_with_level(log::Level::Debug).unwrap();
        dotenv::dotenv().ok();

        let aid = dotenv::var("ACCESS_KEY_ID").unwrap();
        let asec = dotenv::var("ACCESS_KEY_SECRET").unwrap();
        let arn = dotenv::var("ARN").unwrap();

        let client = StsClient::new("sts.aliyuncs.com", &aid, &asec);
        let ret = client
            .sts_for_put_object(
                &arn,
                "mi-dev-public",
                "yuanyq-test/file-from-rust.zip",
                3600,
            )
            .await;
        assert!(ret.is_ok());
        println!("{}", serde_json::to_string(&ret.unwrap()).unwrap());
    }
}
