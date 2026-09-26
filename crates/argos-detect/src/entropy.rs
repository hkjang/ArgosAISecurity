//! Shannon 엔트로피 계산. 암호화된 데이터는 7.2+ 값을 보인다.

use argos_common::{config::DetectionConfig, ContentEvidence, ContentSample, FileEvent};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub const MAX_SAMPLE_BYTES: usize = 1024 * 1024;

/// 이전 관찰은 비교 자료일 뿐 정상 복구 지점이나 정상 내용이라는 뜻이 아니다.
pub struct ContentSampler {
    budget: usize,
    max_files: usize,
    history_ms: u64,
    previous: BTreeMap<PathBuf, ContentEvidence>,
}

impl ContentSampler {
    pub fn new(total_bytes: usize, max_files: usize, history_secs: u64) -> Self {
        Self {
            budget: total_bytes.min(MAX_SAMPLE_BYTES),
            max_files: max_files.min(65_536),
            history_ms: history_secs.saturating_mul(1000),
            previous: BTreeMap::new(),
        }
    }

    pub fn observe(&mut self, path: &Path, observed_at_ms: u64) -> io::Result<ContentEvidence> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // 경로 교체 경합으로 FIFO가 되어도 에이전트를 멈추거나 링크를 따라가지 않는다.
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let mut file = options.open(path)?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "정규 파일만 내용 관찰이 가능합니다",
            ));
        }
        let mut evidence = sample_reader(&mut file, before.len(), self.budget, observed_at_ms)?;
        let after = file.metadata()?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "관찰 도중 파일이 변경되어 일관된 표본을 만들 수 없습니다",
            ));
        }
        let horizon = observed_at_ms.saturating_sub(self.history_ms);
        self.previous.retain(|_, value| {
            value.observed_at_ms >= horizon && value.observed_at_ms <= observed_at_ms
        });
        if let Some(previous) = self
            .previous
            .get(path)
            .filter(|p| p.observed_at_ms < observed_at_ms && p.file_size == evidence.file_size)
        {
            let increases: Vec<_> = evidence
                .samples
                .iter()
                .filter_map(|sample| {
                    previous
                        .samples
                        .iter()
                        .find(|old| old.offset == sample.offset && old.length == sample.length)
                        .map(|old| sample.entropy - old.entropy)
                })
                .collect();
            if increases.len() == evidence.samples.len() && !increases.is_empty() {
                evidence.previous_observed_at_ms = Some(previous.observed_at_ms);
                evidence.max_entropy_increase = increases.into_iter().reduce(f64::max);
            }
        }
        if self.max_files > 0 && path.as_os_str().len() <= 4096 {
            if !self.previous.contains_key(path) && self.previous.len() >= self.max_files {
                let oldest = self
                    .previous
                    .iter()
                    .min_by_key(|(path, value)| (value.observed_at_ms, *path))
                    .map(|(path, _)| path.clone());
                if let Some(oldest) = oldest {
                    self.previous.remove(&oldest);
                }
            }
            self.previous.insert(path.to_path_buf(), evidence.clone());
        }
        Ok(evidence)
    }
}

fn sample_reader(
    reader: &mut (impl Read + Seek),
    size: u64,
    requested: usize,
    observed_at_ms: u64,
) -> io::Result<ContentEvidence> {
    let budget = requested.min(MAX_SAMPLE_BYTES);
    let total = size.min(budget as u64) as usize;
    let positions: Vec<(u64, usize)> = if size <= budget as u64 {
        vec![(0, total)]
    } else {
        let lengths = [total.div_ceil(3), (total + 1) / 3, total / 3];
        vec![
            (0, lengths[0]),
            ((size - lengths[1] as u64) / 2, lengths[1]),
            (size - lengths[2] as u64, lengths[2]),
        ]
    };
    let mut samples = Vec::new();
    let mut sampled_bytes = 0;
    let mut file_type = "unknown";
    for (offset, length) in positions.into_iter().filter(|(_, length)| *length > 0) {
        reader.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes)?;
        if offset == 0 {
            file_type = classify(&bytes);
        }
        samples.push(ContentSample {
            offset,
            length: length as u32,
            entropy: shannon_entropy(&bytes),
        });
        sampled_bytes += length;
    }
    Ok(ContentEvidence {
        observed_at_ms,
        file_size: size,
        sampled_bytes,
        budget_bytes: budget,
        file_type: file_type.into(),
        samples,
        complete: sampled_bytes as u64 == size,
        previous_observed_at_ms: None,
        max_entropy_increase: None,
    })
}

fn classify(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        "zip"
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        "gzip"
    } else if bytes.starts_with(b"\xfd7zXZ\0") {
        "xz"
    } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        "zstd"
    } else if bytes.starts_with(b"BZh") {
        "bzip2"
    } else if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        "7z"
    } else if bytes.starts_with(b"Rar!\x1a\x07") {
        "rar"
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        "png"
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        "jpeg"
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        "webp"
    } else if bytes.get(4..8) == Some(b"ftyp") {
        "mp4"
    } else if bytes.starts_with(b"%PDF-") {
        "pdf"
    } else if bytes.starts_with(b"\x7fELF") || bytes.starts_with(b"MZ") {
        "executable"
    } else if !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        "text"
    } else {
        "unknown"
    }
}

/// 수집된 표본만 평가한다. 파일 재조회나 이전 관찰의 정상본 추론은 하지 않는다.
pub(crate) fn encryption_signal(event: &FileEvent, config: &DetectionConfig) -> bool {
    if let Some(content) = event
        .content
        .as_ref()
        .filter(|_| config.content_sampling.enabled)
    {
        if content.samples.is_empty()
            || content.samples.len() > 3
            || content.budget_bytes > MAX_SAMPLE_BYTES
            || content.sampled_bytes > content.budget_bytes
            || content
                .samples
                .iter()
                .any(|sample| sample.length as usize > content.budget_bytes)
            || content
                .samples
                .iter()
                .map(|s| s.length as usize)
                .sum::<usize>()
                != content.sampled_bytes
            || content.samples.iter().any(|s| {
                s.length == 0
                    || s.offset
                        .checked_add(s.length as u64)
                        .is_none_or(|end| end > content.file_size)
                    || !s.entropy.is_finite()
                    || !(0.0..=8.0).contains(&s.entropy)
            })
        {
            return false;
        }
        let high = content
            .samples
            .iter()
            .any(|s| s.entropy >= config.entropy_threshold);
        let comparable = content
            .previous_observed_at_ms
            .is_some_and(|before| before < content.observed_at_ms)
            && content.max_entropy_increase.is_some_and(|delta| {
                delta.is_finite()
                    && delta > 0.0
                    && delta <= 8.0
                    && delta >= config.content_sampling.min_entropy_increase
            });
        let naturally_dense = matches!(
            content.file_type.as_str(),
            "zip"
                | "gzip"
                | "xz"
                | "zstd"
                | "bzip2"
                | "7z"
                | "rar"
                | "png"
                | "jpeg"
                | "webp"
                | "mp4"
                | "pdf"
                | "executable"
        );
        high && (comparable || (!naturally_dense && content.previous_observed_at_ms.is_none()))
    } else {
        config.entropy_sample_bytes > 0
            && event.entropy.is_some_and(|value| {
                value.is_finite() && value >= config.entropy_threshold && value <= 8.0
            })
    }
}

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
    let mut buf = vec![0u8; max_bytes.min(MAX_SAMPLE_BYTES)];
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
    use argos_common::FileAction;
    use std::io::{Cursor, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixture(name: &str, contents: &[u8]) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "argos-content-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn observed_event(content: ContentEvidence) -> FileEvent {
        FileEvent {
            timestamp_ms: content.observed_at_ms,
            pid: 42,
            path: "/data/document".into(),
            action: FileAction::Modify,
            size: Some(content.file_size),
            entropy: content.samples.first().map(|s| s.entropy),
            process: None,
            content: Some(content),
        }
    }

    #[test]
    fn middle_and_tail_rises_are_found_when_head_is_unchanged() {
        for region in [1, 2] {
            let path = fixture("partial", &vec![b'A'; 8192]);
            let mut sampler = ContentSampler::new(768, 2, 600);
            let baseline = sampler.observe(&path, 1000).unwrap();
            assert_eq!(baseline.sampled_bytes, 768);
            assert_eq!(baseline.samples.len(), 3);
            assert!(!baseline.complete);
            let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(baseline.samples[region].offset))
                .unwrap();
            file.write_all(&(0..=255).collect::<Vec<u8>>()).unwrap();
            drop(file);
            let changed = sampler.observe(&path, 2000).unwrap();
            assert_eq!(changed.samples[0].entropy, 0.0);
            assert_eq!(changed.max_entropy_increase, Some(8.0));
            assert_eq!(changed.previous_observed_at_ms, Some(1000));
            let mut config = DetectionConfig::default();
            config.content_sampling.enabled = true;
            assert!(encryption_signal(&observed_event(changed), &config));
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn compressed_high_entropy_without_change_is_not_encryption_evidence() {
        let mut bytes: Vec<_> = (0..=255).cycle().take(8192).collect();
        bytes[..4].copy_from_slice(b"PK\x03\x04");
        let path = fixture("zip", &bytes);
        let mut sampler = ContentSampler::new(768, 2, 600);
        let mut config = DetectionConfig::default();
        config.content_sampling.enabled = true;
        let first = sampler.observe(&path, 1000).unwrap();
        assert_eq!(first.file_type, "zip");
        assert!(first.samples.iter().any(|s| s.entropy > 7.2));
        assert!(!encryption_signal(&observed_event(first), &config));
        let next = sampler.observe(&path, 2000).unwrap();
        assert_eq!(next.max_entropy_increase, Some(0.0));
        assert!(!encryption_signal(&observed_event(next), &config));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn total_bytes_are_bounded_across_positions_and_caller_requested_budget_is_capped() {
        struct Counted {
            input: Cursor<Vec<u8>>,
            bytes: usize,
        }
        impl Read for Counted {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                let n = self.input.read(bytes)?;
                self.bytes += n;
                Ok(n)
            }
        }
        impl Seek for Counted {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.input.seek(position)
            }
        }
        let size = MAX_SAMPLE_BYTES as u64 * 3;
        let mut input = Counted {
            input: Cursor::new(vec![0; size as usize]),
            bytes: 0,
        };
        let evidence = sample_reader(&mut input, size, MAX_SAMPLE_BYTES * 10, 1).unwrap();
        assert_eq!(input.bytes, MAX_SAMPLE_BYTES);
        assert_eq!(evidence.sampled_bytes, MAX_SAMPLE_BYTES);
        for samples in evidence.samples.windows(2) {
            assert!(samples[0].offset + samples[0].length as u64 <= samples[1].offset);
        }
        let mut short = Counted {
            input: Cursor::new(vec![0; 10]),
            bytes: 0,
        };
        let evidence = sample_reader(&mut short, 10, 100, 1).unwrap();
        assert_eq!(short.bytes, 10);
        assert!(evidence.complete);
        assert_eq!(evidence.samples.len(), 1);
    }

    #[test]
    fn observations_are_bounded_expire_and_do_not_compare_different_file_sizes() {
        let a = fixture("cache-a", b"first");
        let b = fixture("cache-b", b"other");
        let mut sampler = ContentSampler::new(768, 1, 1);
        sampler.observe(&a, 1).unwrap();
        sampler.observe(&b, 2).unwrap();
        assert_eq!(sampler.previous.len(), 1);
        assert!(sampler
            .observe(&a, 3)
            .unwrap()
            .previous_observed_at_ms
            .is_none());
        assert!(sampler
            .observe(&a, 2000)
            .unwrap()
            .previous_observed_at_ms
            .is_none());
        std::fs::write(&a, b"different size").unwrap();
        assert!(sampler
            .observe(&a, 2001)
            .unwrap()
            .max_entropy_increase
            .is_none());
        std::fs::remove_file(a).unwrap();
        std::fs::remove_file(b).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sampler_rejects_symbolic_links_and_nonregular_files() {
        let target = fixture("target", b"secret");
        let link = target.with_extension("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut sampler = ContentSampler::new(768, 2, 600);
        assert!(sampler.observe(&link, 1000).is_err());
        assert!(sampler.observe(Path::new("/dev/null"), 1000).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
    }

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
