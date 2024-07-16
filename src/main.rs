mod algorithms;

use regex::Regex;
use algorithms::*;


fn identify_hash(hash: &str) -> &'static str {

    // identification based on length and content
    match hash.len() {
        4 => "Checksum = 4",
        8 => "Checksum = 8",
        13 if DESUnix(hash) => "DES Unix",
        16 if MD5Half(hash) => "MD5 Half",
        16 if MD5Middle(hash) => "MD5 Middle",
        16 if MySQL(hash) => "MySQL",
        22 if MD5APR(hash) => "MD5 APR",
        32 if DomainCachedCredentials(hash) => "Domain Cached Credentials",
        32 if Haval128(hash) => "Haval128",
        32 if Haval128HMAC(hash) => "Haval128 HMAC",
        32 if MD2(hash) => "MD2",
        32 if MD2HMAC(hash) => "MD2 HMAC",
        32 if MD4(hash) => "MD4",
        32 if MD4HMAC(hash) => "MD4 HMAC",
        32 if MD5(hash) => "MD5",
        32 if MD5HMAC(hash) => "MD5 HMAC",
        32 if MD5HMACWordpress(hash) => "MD5 HMAC Wordpress",
        32 if NTLM(hash) => "NTLM",
        32 if RAdminv2x(hash) => "RAdminv2x",
        32 if RipeMD128(hash) => "RipeMD128",
        32 if RipeMD128HMAC(hash) => "RipeMD128 HMAC",
        32 if SNEFRU128(hash) => "SNEFRU128",
        32 if SNEFRU128HMAC(hash) => "SNEFRU128 HMAC",
        32 if Tiger128(hash) => "Tiger128",
        32 if Tiger128HMAC(hash) => "Tiger128 HMAC",
        32 if md5passsalt(hash) => "MD5 Pass Salt",
        32 if md5saltmd5pass(hash) => "MD5 Salt MD5 Pass",
        32 if md5saltpass(hash) => "MD5 Salt Pass",
        32 if md5saltpasssalt(hash) => "MD5 Salt Pass Salt",
        32 if md5saltpassusername(hash) => "MD5 Salt Pass Username",
        32 if md5saltmd5passsalt(hash) => "MD5 Salt MD5 Pass Salt",
        32 if md5saltmd5passsalt1(hash) => "MD5 Salt MD5 Pass Salt 1",
        32 if md5saltmd5saltpass2(hash) => "MD5 Salt MD5 Salt Pass 2",
        32 if md5saltmd5md5passsalt(hash) => "MD5 Salt MD5 MD5 Pass Salt",
        32 if md5username0pass(hash) => "MD5 Username 0 Pass",
        32 if md5usernameLFpass(hash) => "MD5 Username LF Pass",
        32 if md5usernamemd5passsalt(hash) => "MD5 Username MD5 Pass Salt",
        32 if md5md5pass(hash) => "MD5 MD5 Pass",
        32 if md5md5passsalt(hash) => "MD5 MD5 Pass Salt",
        32 if md5md5passmd5salt(hash) => "MD5 MD5 Pass MD5 Salt",
        32 if md5md5saltpass(hash) => "MD5 MD5 Salt Pass",
        32 if md5md5saltmd5pass(hash) => "MD5 MD5 Salt MD5 Pass",
        32 if md5md5usernamepasssalt(hash) => "MD5 MD5 Username Pass Salt",
        32 if md5md5md5pass(hash) => "MD5 MD5 MD5 Pass",
        32 if md5md5md5md5pass(hash) => "MD5 MD5 MD5 MD5 Pass",
        32 if md5sha1pass(hash) => "MD5 SHA1 Pass",
        32 if md5sha1md5pass(hash) => "MD5 SHA1 MD5 Pass",
        32 if md5sha1md5sha1pass(hash) => "MD5 SHA1 MD5 SHA1 Pass",
        32 if md5strtouppermd5pass(hash) => "MD5 Strtoupper MD5 Pass",
        32 if LineageIIC4(hash) => "LineageIIC4",
        34 if MD5phpBB3(hash) => "MD5 phpBB3",
        34 if MD5Unix(hash) => "MD5 Unix",
        34 if MD5Wordpress(hash) => "MD5 Wordpress",
        40 if SHA1(hash) => "SHA-1",
        _ => "Unknown",
    }
}


fn main() {
    let hashes = vec![
        "d41d8cd98f00b204e9800998ecf8427e",        // MD5 - (╯°□°)╯︵ ┻━┻
        "da39a3ee5e6b4b0d3255bfef95601890afd80709", // SHA-1
        "ae11fd697ec92c7c",              // MD5-Half
        "00112233445566778899aabbccddeeff00112233", // Unknown - (╯°□°)╯︵ ┻━┻
        "0xInvalid" // Unknown
    ];

    for hash in hashes {
        println!("Hash: {} -> Type: {}", hash, identify_hash(hash));
    }
}
