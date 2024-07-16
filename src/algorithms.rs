pub fn is_digit(s: &str) -> bool {
    s.chars().all(char::is_numeric)
}

pub fn is_alpha(s: &str) -> bool {
    s.chars().all(char::is_alphabetic)
}

pub fn is_alnum(s: &str) -> bool {
    s.chars().all(char::is_alphanumeric)
}

pub fn is_lower(s: &str) -> bool {
    s.chars().all(char::is_lowercase)
}

pub fn validate_hash(hash: &str, length: usize, digits: bool, alpha: bool, alnum: bool) -> bool {
    if hash.len() == length
        && is_alpha(hash) == alpha
        && is_digit(hash) == digits
        && is_alnum(hash) == alnum
    {
        true
    } else {
        false
    }
}


pub fn DESUnix(hash: &str) -> bool {
    validate_hash(hash, 13, false, false, true)
}

pub fn MD5Half(hash: &str) -> bool {
    validate_hash(hash, 16, false, false, true)
}

pub fn MD5Middle(hash: &str) -> bool {
    validate_hash(hash, 16, false, false, true)
}

pub fn MySQL(hash: &str) -> bool {
    validate_hash(hash, 16, false, false, true)
}

pub fn DomainCachedCredentials(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn Haval128(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn Haval128HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD2(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD2HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD4(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD4HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD5(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD5HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn MD5HMACWordpress(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn NTLM(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn RAdminv2x(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn RipeMD128(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn RipeMD128HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn SNEFRU128(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn SNEFRU128HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn Tiger128(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn Tiger128HMAC(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5passsalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltmd5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltpass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltpasssalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltpassusername(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltmd5passsalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltmd5passsalt1(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltmd5saltpass2(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5saltmd5md5passsalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5username0pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5usernameLFpass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5usernamemd5passsalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5passsalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5passmd5salt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5saltpass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5saltmd5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5usernamepasssalt(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5md5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5md5md5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5md5md5md5md5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5sha1pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5sha1md5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5sha1md5sha1pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn md5strtouppermd5pass(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true)
}

pub fn LineageIIC4(hash: &str) -> bool {
    validate_hash(hash, 32, false, false, true) && hash.starts_with("0x")
}

pub fn MD5phpBB3(hash: &str) -> bool {
    validate_hash(hash, 34, false, false, false) && hash.starts_with("$H$")
}

pub fn MD5Unix(hash: &str) -> bool {
    validate_hash(hash, 34, false, false, false) && hash.starts_with("$1$")
}

pub fn MD5Wordpress(hash: &str) -> bool {
    validate_hash(hash, 34, false, false, false) && hash.starts_with("$P$")
}

pub fn MD5APR(hash: &str) -> bool {
    validate_hash(hash, 22, false, false, false) && hash.starts_with("$apr")
}

pub fn SHA1(hash: &str) -> bool {
    validate_hash(hash, 40, false, false, true)
}