# 阿里云 STS SDK

[![Crates.io Version](https://img.shields.io/crates/v/aliyun-sts-rust-sdk?_ts_=202503262245)](https://crates.io/crates/aliyun-sts-rust-sdk)
![Crates.io MSRV](https://img.shields.io/crates/msrv/aliyun-sts-rust-sdk?_ts_=202503262245)
[![docs.rs](https://img.shields.io/docsrs/aliyun-sts-rust-sdk)](https://docs.rs/aliyun-sts-rust-sdk)
[![Crates.io License](https://img.shields.io/crates/l/aliyun-sts-rust-sdk?_ts_=202503262245)](https://github.com/yuqiang-yuan/aliyun-sts-rust-sdk?tab=MIT-1-ov-file)

实现了 `AssumeRole` API 的调用，生成一对临时的访问 ID 和访问密钥，可以让前端利用 [ali oss](https://www.npmjs.com/package/ali-oss) 库上传比较大的文件。

如果在后端传输文件，请查看 [ali-oss-rs](https://crates.io/crates/ali-oss-rs)，提供了比较完整的阿里云 OSS API 调用。

使用比较简单：

```rust
async fn test_assume_role() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();
    dotenv::dotenv().ok();

    let aid = dotenv::var("ACCESS_KEY_ID").unwrap();
    let asec = dotenv::var("ACCESS_KEY_SECRET").unwrap();
    let arn = dotenv::var("ARN").unwrap();
    let role_session_name = "aliyun-sts-rust-sdk";

    let policy = Policy {
        version: Versions::V1,
        statement: vec![
            StatementBlock {
                action: StringOrArray::ArrayValue(vec!["oss:*".to_owned()]),
                effect: Effects::Allow,
                resource: StringOrArray::ArrayValue(vec!["acs:oss:*:*:mi-dev-public/yuanyq-test/file-from-rust.zip".to_owned()]),
                condition: None,
            }
        ]
    };

    let req = AssumeRoleRequest::new(&arn, role_session_name, Some(policy), 3600);
    let client = StsClient::new("sts.aliyuncs.com", &aid, &asec);

    match client.assume_role(req).await {
        Ok(r) => {
            assert!(r.credentials.is_some());
        },
        Err(e) => println!("{:?}", e)
    }
}
```

或者，调用便捷的函数：`sts_for_put_object`:

```rust
client.sts_for_put_object(&arn, "mi-dev-public", "yuanyq-test/file-from-rust.zip", 3600)
```
