//! Shannon 엔트로피 계산. 암호화된 데이터는 7.2+ 값을 보인다.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// 바이트 슬라이스의 Shannon 엔트로피 (0.0 ~ 8.0 bits/byte).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// 파일 앞부분 최대 `max_bytes`를 샘플링해 엔트로피를 계산한다.
pub fn file_entropy(path: &Path, max_bytes: usize) -> io::Result<f64> {
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; max_bytes];
    let mut read_total = 0;
    loop {
        let n = file.read(&mut buf[read_total..])?;
        if n == 0 {
            break;
        }
        read_total += n;
        if read_total == buf.len() {
            break;
        }
    }
    Ok(shannon_entropy(&buf[..read_total]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_byte_is_zero() {
        assert_eq!(shannon_entropy(&[0xAA; 1024]), 0.0);
    }

    #[test]
    fn all_256_values_is_eight() {
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 1e-9, "expected 8.0, got {e}");
    }

    #[test]
    fn ascii_text_is_mid_range() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        let e = shannon_entropy(&text);
        assert!(e > 3.0 && e < 5.0, "got {e}");
    }
}
