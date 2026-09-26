//! 등록 직후 기준과 비교하는 읽기 전용 검사. 커널 watch 전체나 원자 스냅샷의 증명은 아니다.
use argos_common::{config::SensorKind, now_ms};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_DEPTH: usize = 64;
const MAX_SCAN_TIME: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageIssue {
    pub code: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootCoverage {
    pub configured_path: PathBuf,
    pub registered_path: PathBuf,
    pub entries_checked: usize,
    pub skipped_symlinks: usize,
    pub issues: Vec<CoverageIssue>,
    pub omitted_issues: usize,
}
impl RootCoverage {
    fn issue(&mut self, code: &str, path: &Path) {
        if self.issues.len() < 32 {
            self.issues.push(CoverageIssue {
                code: code.into(),
                path: path.into(),
            });
        } else {
            self.omitted_issues = self.omitted_issues.saturating_add(1);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageReport {
    /// 완료 시각이 아니라 검사 시작 시각. 오래 걸린 검사 결과를 새 결과로 오인하지 않는다.
    pub checked_at_ms: u64,
    pub assessment: String,
    pub mount_namespace: Option<String>,
    pub roots: Vec<RootCoverage>,
    pub limitations: Vec<String>,
}
impl CoverageReport {
    pub fn has_gap(&self) -> bool {
        self.assessment != "no_observed_gap"
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}
fn identity(meta: &fs::Metadata) -> Identity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Identity {
            device: meta.dev(),
            inode: meta.ino(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Identity {
            device: 0,
            inode: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Mount {
    id: u64,
    point: PathBuf,
    signature: String,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn decode_mount_path(value: &str) -> io::Result<PathBuf> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let sequence = bytes
                .get(i + 1..i + 4)
                .ok_or_else(|| invalid("마운트 경로 escape 오류"))?;
            let decoded = match sequence {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid("마운트 경로 escape 오류")),
            };
            out.push(decoded);
            i += 4;
        } else {
            if bytes[i] == 0 {
                return Err(invalid("마운트 경로 NUL"));
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    // 보고서 JSON과의 경로 동일성을 보존한다. lossy 변환으로 다른 경로를 합치지 않는다.
    let path = String::from_utf8(out).map_err(|_| invalid("마운트 경로 UTF-8 오류"))?;
    if !path.starts_with('/')
        || path.split('/').any(|c| matches!(c, "." | ".."))
        || (path != "/" && (path.contains("//") || path.ends_with('/')))
    {
        return Err(invalid("마운트 경로가 정규 절대 경로가 아닙니다"));
    }
    Ok(path.into())
}

fn parse_mounts(text: &str) -> io::Result<Vec<Mount>> {
    let mut mounts = Vec::new();
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        if mounts.len() >= 65_536 {
            return Err(invalid("마운트 목록 상한"));
        }
        let parts: Vec<_> = line.split_ascii_whitespace().collect();
        let split = parts
            .iter()
            .position(|p| *p == "-")
            .ok_or_else(|| invalid("마운트 목록 형식 오류"))?;
        if split < 6 || parts.len() != split + 4 {
            return Err(invalid("마운트 목록 형식 오류"));
        }
        let id: u64 = parts[0].parse().map_err(|_| invalid("마운트 ID 오류"))?;
        let _: u64 = parts[1]
            .parse()
            .map_err(|_| invalid("마운트 부모 ID 오류"))?;
        let (major, minor) = parts[2]
            .split_once(':')
            .ok_or_else(|| invalid("마운트 장치 번호 오류"))?;
        let _: u64 = major
            .parse()
            .map_err(|_| invalid("마운트 장치 번호 오류"))?;
        let _: u64 = minor
            .parse()
            .map_err(|_| invalid("마운트 장치 번호 오류"))?;
        decode_mount_path(parts[3])?;
        let point = decode_mount_path(parts[4])?;
        if id == 0 || !ids.insert(id) {
            return Err(invalid(
                "마운트 ID/경로가 중복되어 범위를 결정할 수 없습니다",
            ));
        }
        // 공백 표현/항목 순서 차이에 반응하지 않도록 정규화하되 보안 관련 옵션은 보존한다.
        mounts.push(Mount {
            id,
            point,
            signature: parts.join(" "),
        });
    }
    if mounts.is_empty() {
        return Err(invalid("빈 마운트 목록"));
    }
    mounts.sort();
    Ok(mounts)
}

fn read_mounts() -> io::Result<Vec<Mount>> {
    #[cfg(target_os = "linux")]
    {
        let mut bytes = Vec::new();
        fs::File::open("/proc/thread-self/mountinfo")?
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid("마운트 목록 크기 상한"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("마운트 목록 UTF-8 오류"))?;
        parse_mounts(text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux 마운트 정보 없음",
        ))
    }
}
fn namespace() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        fs::read_link("/proc/thread-self/ns/mnt")
            .ok()?
            .to_str()
            .map(str::to_owned)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
fn containing_mount<'a>(path: &Path, mounts: &'a [Mount]) -> Option<&'a Mount> {
    let depth = mounts
        .iter()
        .filter(|m| path.starts_with(&m.point))
        .map(|m| m.point.components().count())
        .max()?;
    let mut candidates = mounts
        .iter()
        .filter(|m| path.starts_with(&m.point) && m.point.components().count() == depth);
    let first = candidates.next()?;
    if candidates.next().is_some() {
        None
    } else {
        Some(first)
    }
}
fn relevant_mounts(path: &Path, mounts: &[Mount]) -> Vec<Mount> {
    let depth = mounts
        .iter()
        .filter(|m| path.starts_with(&m.point))
        .map(|m| m.point.components().count())
        .max();
    mounts
        .iter()
        .filter(|m| {
            (path.starts_with(&m.point) && Some(m.point.components().count()) == depth)
                || m.point.starts_with(path)
        })
        .cloned()
        .collect()
}
fn ambiguous_mount_scope(mounts: &[Mount]) -> bool {
    let mut points = BTreeSet::new();
    mounts.is_empty() || mounts.iter().any(|m| !points.insert(&m.point))
}

struct Registration {
    configured: PathBuf,
    canonical: PathBuf,
    identity: Identity,
    mounts: Option<Vec<Mount>>,
}
pub struct CoverageInspector {
    roots: Vec<Registration>,
    sensor: SensorKind,
    max_entries: usize,
    marked_mounts: BTreeSet<u64>,
    namespace: Option<String>,
}

impl CoverageInspector {
    /// 센서 성공 직후 호출한다. 등록 시점과 원자적으로 묶이지 않으며 baseline은 자동 갱신하지 않는다.
    pub fn new(paths: &[PathBuf], sensor: SensorKind, max_entries: usize) -> io::Result<Self> {
        if paths.is_empty() || paths.len() > 128 || !(1..=50_000).contains(&max_entries) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "coverage: 경로 1~128개, max_entries 1~50000 필요",
            ));
        }
        let mounts = read_mounts().ok();
        let baseline_namespace = namespace();
        let mut marked_mounts = BTreeSet::new();
        let mut roots = Vec::new();
        for path in paths {
            let configured = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()?.join(path)
            };
            let canonical = configured.canonicalize()?;
            if configured.to_str().is_none() || canonical.to_str().is_none() {
                return Err(invalid("coverage 경로는 UTF-8이어야 합니다"));
            }
            let meta = fs::symlink_metadata(&canonical)?;
            if meta.file_type().is_symlink() || configured.canonicalize()? != canonical {
                return Err(invalid("coverage 기준 수집 중 경로가 변경되었습니다"));
            }
            if let Some(m) = mounts
                .as_ref()
                .and_then(|ms| containing_mount(&canonical, ms))
            {
                marked_mounts.insert(m.id);
            }
            roots.push(Registration {
                configured,
                identity: identity(&meta),
                mounts: mounts.as_ref().map(|ms| relevant_mounts(&canonical, ms)),
                canonical,
            });
        }
        let after_mounts = read_mounts().ok();
        if baseline_namespace != namespace()
            || roots.iter().any(|r| {
                r.mounts
                    != after_mounts
                        .as_ref()
                        .map(|m| relevant_mounts(&r.canonical, m))
            })
        {
            return Err(invalid(
                "coverage 기준 수집 중 마운트 정보가 변경되었습니다",
            ));
        }
        Ok(Self {
            roots,
            sensor,
            max_entries,
            marked_mounts,
            namespace: baseline_namespace,
        })
    }
    /// 센서에 실제 전달한 정규 경로와 구성 경로의 현재 대상이 일치해야 한다.
    /// 센서의 성공 반환과 이 검사 사이 inode 교체까지 원자적으로 검증하지는 못한다.
    pub fn new_registered(
        paths: &[PathBuf],
        registered_paths: &[PathBuf],
        sensor: SensorKind,
        max_entries: usize,
    ) -> io::Result<Self> {
        let inspector = Self::new(paths, sensor, max_entries)?;
        if registered_paths.len() != inspector.roots.len()
            || inspector
                .roots
                .iter()
                .zip(registered_paths)
                .any(|(root, expected)| root.canonical != *expected)
        {
            return Err(invalid(
                "센서 등록 경로와 coverage 기준 경로가 일치하지 않습니다",
            ));
        }
        Ok(inspector)
    }
    pub fn inspect(&self) -> CoverageReport {
        let checked_at_ms = now_ms();
        let started = Instant::now();
        let mounts = read_mounts().ok();
        let current_namespace = namespace();
        let mut remaining = self.max_entries;
        let mut roots = Vec::new();
        for registration in &self.roots {
            let path = &registration.canonical;
            let mut row = RootCoverage {
                configured_path: registration.configured.clone(),
                registered_path: path.clone(),
                entries_checked: 0,
                skipped_symlinks: 0,
                issues: vec![],
                omitted_issues: 0,
            };
            if registration.configured.canonicalize().ok().as_ref() != Some(path) {
                row.issue(
                    "configured_target_changed_or_missing",
                    &registration.configured,
                );
            }
            match fs::symlink_metadata(path) {
                Ok(meta)
                    if !meta.file_type().is_symlink()
                        && identity(&meta) == registration.identity => {}
                _ => row.issue("registered_root_replaced_or_missing", path),
            }
            #[cfg(not(unix))]
            row.issue("root_identity_unavailable", path);
            if current_namespace != self.namespace || current_namespace.is_none() {
                row.issue("mount_namespace_changed_or_unknown", path);
            }
            match (&registration.mounts, &mounts) {
                (Some(before), Some(current)) => {
                    let current = relevant_mounts(path, current);
                    if ambiguous_mount_scope(&current) || ambiguous_mount_scope(before) {
                        row.issue("mount_scope_ambiguous", path);
                    }
                    if &current != before {
                        row.issue("mount_topology_changed", path);
                    }
                    if self.sensor == SensorKind::Fanotify {
                        for mount in current
                            .iter()
                            .filter(|m| !self.marked_mounts.contains(&m.id))
                        {
                            row.issue("fanotify_unmarked_mount", &mount.point);
                        }
                    }
                }
                _ => row.issue("mount_topology_unknown", path),
            }
            scan_tree(
                path,
                &registration.identity,
                &mut row,
                &mut remaining,
                started,
            );
            if fs::symlink_metadata(path)
                .ok()
                .filter(|m| !m.file_type().is_symlink())
                .map(|m| identity(&m))
                != Some(registration.identity.clone())
            {
                row.issue("root_changed_during_scan", path);
            }
            if registration.configured.canonicalize().ok().as_ref() != Some(path) {
                row.issue(
                    "configured_target_changed_during_scan",
                    &registration.configured,
                );
            }
            roots.push(row);
        }
        let after_mounts = read_mounts().ok();
        let after_namespace = namespace();
        for (row, registration) in roots.iter_mut().zip(&self.roots) {
            if started.elapsed() > MAX_SCAN_TIME {
                row.issue("scan_time_limit", &registration.canonical);
            }
            if current_namespace != after_namespace
                || mounts
                    .as_ref()
                    .map(|m| relevant_mounts(&registration.canonical, m))
                    != after_mounts
                        .as_ref()
                        .map(|m| relevant_mounts(&registration.canonical, m))
            {
                row.issue("mounts_changed_during_scan", &registration.canonical);
            }
        }
        let gap = roots
            .iter()
            .any(|r| !r.issues.is_empty() || r.omitted_issues > 0);
        CoverageReport { checked_at_ms, assessment: if gap { "gap_or_incomplete" } else { "no_observed_gap" }.into(), mount_namespace: current_namespace, roots, limitations: vec!["등록 직후 기준과 현재 검사 결과의 비교입니다. 커널 watch 전체, 센서 등록과 기준 수집 사이 경합, 다른 컨테이너 감시를 증명하지 않습니다.".into(),"읽기 전용 점검은 내용·쓰기 이벤트 전달을 확인하지 않습니다. 지정 경로의 이벤트 DB 도달은 별도 probe로 시험하세요.".into(),"심볼릭 링크 대상은 탐색하지 않습니다. Linux 하위 순회는 FD와 O_NOFOLLOW를 사용하지만 전체 트리의 원자 스냅샷은 아니며 이동·교체·검사 사이 변화를 놓칠 수 있습니다.".into(),"항목·깊이·검사 시간 예산을 제한합니다. 네트워크 파일시스템의 단일 커널 I/O가 멈추면 강제 중단할 수 없으므로 작업자의 결과 나이를 함께 확인하세요.".into()] }
    }
}

struct Budget {
    remaining: usize,
    started: Instant,
}
impl Budget {
    fn take(&mut self, path: &Path, report: &mut RootCoverage) -> bool {
        if self.started.elapsed() > MAX_SCAN_TIME {
            report.issue("scan_time_limit", path);
            return false;
        }
        if self.remaining == 0 {
            report.issue("scan_limit", path);
            return false;
        }
        self.remaining -= 1;
        report.entries_checked += 1;
        true
    }
}

#[cfg(target_os = "linux")]
fn scan_tree(
    root: &Path,
    expected: &Identity,
    report: &mut RootCoverage,
    remaining: &mut usize,
    started: Instant,
) {
    let mut budget = Budget {
        remaining: *remaining,
        started,
    };
    match open_at(libc::AT_FDCWD, root.as_os_str(), libc::O_PATH) {
        Ok(file) => {
            let matches = file
                .metadata()
                .is_ok_and(|m| !m.file_type().is_symlink() && identity(&m) == *expected);
            if !matches {
                report.issue("root_changed_during_scan", root);
            } else {
                visit_fd(&file, root, 0, report, &mut budget);
            }
        }
        Err(_) => report.issue("metadata_unavailable", root),
    }
    *remaining = budget.remaining;
}

#[cfg(target_os = "linux")]
fn open_at(parent: std::os::fd::RawFd, name: &std::ffi::OsStr, flags: i32) -> io::Result<fs::File> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid("NUL 경로"))?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn visit_fd(
    file: &fs::File,
    path: &Path,
    depth: usize,
    report: &mut RootCoverage,
    budget: &mut Budget,
) {
    use std::os::fd::AsRawFd;
    if !budget.take(path, report) {
        return;
    }
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => {
            report.issue("metadata_unavailable", path);
            return;
        }
    };
    if meta.file_type().is_symlink() {
        report.skipped_symlinks += 1;
        report.issue("symlink_target_not_inspected", path);
        return;
    }
    if !meta.is_file() && !meta.is_dir() {
        report.issue("nonregular_path_not_inspected", path);
        return;
    }
    let fd_path = PathBuf::from(format!("/proc/thread-self/fd/{}", file.as_raw_fd()));
    if !readable(&fd_path, meta.is_dir()) {
        report.issue("read_access_denied", path);
        return;
    }
    if meta.is_dir() {
        if depth >= MAX_DEPTH {
            report.issue("scan_depth_limit", path);
            return;
        }
        let directory = match open_at(
            file.as_raw_fd(),
            std::ffi::OsStr::new("."),
            libc::O_RDONLY | libc::O_DIRECTORY,
        ) {
            Ok(d) => d,
            Err(_) => {
                report.issue("directory_unreadable", path);
                return;
            }
        };
        let directory_path =
            PathBuf::from(format!("/proc/thread-self/fd/{}", directory.as_raw_fd()));
        let entries = match fs::read_dir(directory_path) {
            Ok(e) => e,
            Err(_) => {
                report.issue("directory_unreadable", path);
                return;
            }
        };
        for entry in entries {
            // 항목을 열기 전 예산 확인. 깊이 우선이므로 FD 수도 최대 깊이에 따라 제한된다.
            if budget.remaining == 0 || budget.started.elapsed() > MAX_SCAN_TIME {
                report.issue(
                    if budget.remaining == 0 {
                        "scan_limit"
                    } else {
                        "scan_time_limit"
                    },
                    path,
                );
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    budget.remaining -= 1;
                    report.entries_checked += 1;
                    report.issue("directory_entry_unreadable", path);
                    continue;
                }
            };
            let name = entry.file_name();
            if name.to_str().is_none() {
                budget.remaining -= 1;
                report.entries_checked += 1;
                report.issue("non_utf8_path_not_inspected", path);
                continue;
            }
            let child_path = path.join(&name);
            match open_at(directory.as_raw_fd(), &name, libc::O_PATH) {
                Ok(child) => visit_fd(&child, &child_path, depth + 1, report, budget),
                Err(_) => {
                    budget.remaining -= 1;
                    report.entries_checked += 1;
                    report.issue("metadata_unavailable", &child_path);
                }
            }
        }
    }
    // 이름 교체/상위 디렉터리 이동을 관측하면 불완전으로 표시한다. ABA 경합은 배제하지 못한다.
    if fs::symlink_metadata(path).ok().map(|m| identity(&m)) != Some(identity(&meta)) {
        report.issue("path_changed_during_scan", path);
    }
}

#[cfg(not(target_os = "linux"))]
fn scan_tree(
    root: &Path,
    _expected: &Identity,
    report: &mut RootCoverage,
    remaining: &mut usize,
    started: Instant,
) {
    // Linux 외 플랫폼에서는 FD 기반 보호 범위를 약속하지 않고 결과를 불완전으로 명시한다.
    let mut budget = Budget {
        remaining: *remaining,
        started,
    };
    if budget.take(root, report) {
        report.issue("platform_inventory_unavailable", root);
    }
    *remaining = budget.remaining;
}

#[cfg(target_os = "linux")]
fn readable(path: &Path, directory: bool) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::R_OK | if directory { libc::X_OK } else { 0 },
            libc::AT_EACCESS,
        ) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "argos-coverage-{}-{}-{}",
                std::process::id(),
                now_ms(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn has(report: &CoverageReport, code: &str) -> bool {
        report
            .roots
            .iter()
            .any(|r| r.issues.iter().any(|i| i.code == code))
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unchanged_readable_tree_has_no_observed_gap() {
        let dir = Temp::new();
        fs::write(dir.0.join("ordinary"), b"content").unwrap();
        let report = CoverageInspector::new(&[dir.0.clone()], SensorKind::Notify, 10)
            .unwrap()
            .inspect();
        assert!(!report.has_gap(), "{report:?}");
        assert_eq!(report.roots[0].entries_checked, 2);
    }

    #[test]
    fn roots_replaced_after_registration_are_not_silently_accepted() {
        let dir = Temp::new();
        let root = dir.0.join("root");
        fs::create_dir(&root).unwrap();
        let inspector = CoverageInspector::new(&[root.clone()], SensorKind::Notify, 100).unwrap();
        fs::rename(&root, dir.0.join("old")).unwrap();
        fs::create_dir(&root).unwrap();
        let report = inspector.inspect();
        assert!(report.has_gap());
        assert!(has(&report, "registered_root_replaced_or_missing"));
        assert_eq!(report.roots[0].entries_checked, 0); // replacement tree is not inventoried as the registered root
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn bounds_are_global_and_symlink_targets_are_gaps() {
        let dir = Temp::new();
        fs::write(dir.0.join("a"), b"a").unwrap();
        fs::write(dir.0.join("b"), b"b").unwrap();
        let second = Temp::new();
        let report =
            CoverageInspector::new(&[dir.0.clone(), second.0.clone()], SensorKind::Notify, 2)
                .unwrap()
                .inspect();
        assert!(has(&report, "scan_limit"));
        assert_eq!(
            report
                .roots
                .iter()
                .map(|r| r.entries_checked)
                .sum::<usize>(),
            2
        );
        std::os::unix::fs::symlink(&second.0, dir.0.join("link")).unwrap();
        fs::write(second.0.join("must-not-inspect"), b"secret").unwrap();
        let report = CoverageInspector::new(&[dir.0.clone()], SensorKind::Notify, 100)
            .unwrap()
            .inspect();
        assert_eq!(report.roots[0].skipped_symlinks, 1);
        assert_eq!(report.roots[0].entries_checked, 4);
        assert!(has(&report, "symlink_target_not_inspected"));
        assert!(report.has_gap());
    }

    #[test]
    #[cfg(unix)]
    fn configured_alias_change_and_wrong_registered_path_are_rejected() {
        let dir = Temp::new();
        let first = dir.0.join("one");
        let second = dir.0.join("two");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let alias = dir.0.join("link");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let inspector = CoverageInspector::new_registered(
            &[alias.clone()],
            &[first.clone()],
            SensorKind::Notify,
            10,
        )
        .unwrap();
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&second, &alias).unwrap();
        assert!(has(
            &inspector.inspect(),
            "configured_target_changed_or_missing"
        ));
        assert!(
            CoverageInspector::new_registered(&[alias], &[first], SensorKind::Notify, 10).is_err()
        );
    }

    #[test]
    fn mount_scope_uses_components_ids_and_rejects_ambiguous_paths() {
        let text="1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:1 /other /data/mounted\\040dir rw - ext4 /dev/a rw\n3 1 8:1 / /data-other rw - ext4 /dev/a rw\n";
        let mounts = parse_mounts(text).unwrap();
        let scope = relevant_mounts(Path::new("/data"), &mounts);
        assert_eq!(scope.len(), 2);
        assert_eq!(scope[1].point, PathBuf::from("/data/mounted dir"));
        assert_eq!(
            containing_mount(Path::new("/data/mounted dir/x"), &mounts)
                .unwrap()
                .id,
            2
        );
        let replaced = parse_mounts(&text.replace("2 1 8:1", "4 1 8:1")).unwrap();
        assert_ne!(scope, relevant_mounts(Path::new("/data"), &replaced));
        let unrelated = parse_mounts(&text.replace("3 1 8:1", "9 1 8:1")).unwrap();
        assert_eq!(scope, relevant_mounts(Path::new("/data"), &unrelated));
        for bad in [
            "invalid",
            "1 0 8:1 / / rw - ext4 /dev/a rw\n1 0 8:1 / /foo rw - ext4 /dev/a rw",
        ] {
            assert!(parse_mounts(bad).is_err());
        }
        for bad in [
            "/bad\\999",
            "/bad\\377",
            "/a/../b",
            "relative",
            "/a//b",
            "/bad\\000",
        ] {
            assert!(decode_mount_path(bad).is_err());
        }
        let stacked=parse_mounts("1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:1 / /data rw - ext4 /dev/a rw\n3 1 8:1 / /data rw - ext4 /dev/a rw").unwrap();
        assert!(containing_mount(Path::new("/data/file"), &stacked).is_none());
        assert!(ambiguous_mount_scope(&relevant_mounts(
            Path::new("/data/file"),
            &stacked
        )));
        assert!(!ambiguous_mount_scope(&relevant_mounts(
            Path::new("/other"),
            &stacked
        )));
        assert_eq!(
            decode_mount_path("/a\\134b").unwrap(),
            PathBuf::from("/a\\b")
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn baseline_mount_change_unmarked_fanotify_and_namespace_are_reported() {
        let dir = Temp::new();
        let mut inspector =
            CoverageInspector::new(&[dir.0.clone()], SensorKind::Fanotify, 10).unwrap();
        assert!(inspector.roots[0].mounts.is_some());
        inspector.marked_mounts.clear();
        assert!(has(&inspector.inspect(), "fanotify_unmarked_mount"));
        inspector.roots[0].mounts.as_mut().unwrap()[0].id = u64::MAX;
        inspector.namespace = Some("other-namespace".into());
        let report = inspector.inspect();
        assert!(has(&report, "mount_topology_changed"));
        assert!(has(&report, "mount_namespace_changed_or_unknown"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn inaccessible_tree_is_reported_without_claiming_complete_coverage() {
        use std::os::unix::fs::PermissionsExt;
        let dir = Temp::new();
        let child = dir.0.join("private");
        fs::create_dir(&child).unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0)).unwrap();
        let inspector = CoverageInspector::new(&[dir.0.clone()], SensorKind::Notify, 10).unwrap();
        let report = inspector.inspect();
        // root/CAP_DAC_OVERRIDE의 실제 접근 가능성을 거짓 오류로 보고하지 않는다.
        if !readable(&child, true) {
            assert!(has(&report, "read_access_denied"));
            assert!(report.has_gap());
        }
        fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir(&child).unwrap();
        fs::remove_dir(&dir.0).unwrap();
        assert!(has(&inspector.inspect(), "metadata_unavailable"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn descriptor_scan_does_not_follow_swapped_child_symlink() {
        use std::os::fd::AsRawFd;
        let root = Temp::new();
        let outside = Temp::new();
        fs::write(outside.0.join("not-inspected"), b"secret").unwrap();
        let root_fd = open_at(libc::AT_FDCWD, root.0.as_os_str(), libc::O_PATH).unwrap();
        std::os::unix::fs::symlink(&outside.0, root.0.join("child")).unwrap();
        let child = open_at(
            root_fd.as_raw_fd(),
            std::ffi::OsStr::new("child"),
            libc::O_PATH,
        )
        .unwrap();
        assert!(child.metadata().unwrap().file_type().is_symlink());
        let report = CoverageInspector::new(&[root.0.clone()], SensorKind::Notify, 10)
            .unwrap()
            .inspect();
        assert_eq!(report.roots[0].entries_checked, 2);
        assert_eq!(report.roots[0].skipped_symlinks, 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn deep_and_non_utf8_paths_are_explicitly_incomplete() {
        use std::os::unix::ffi::OsStringExt;
        let dir = Temp::new();
        let mut current = dir.0.clone();
        for _ in 0..MAX_DEPTH + 1 {
            current = current.join("d");
            fs::create_dir(&current).unwrap();
        }
        fs::write(dir.0.join(std::ffi::OsString::from_vec(vec![0xff])), b"x").unwrap();
        let report = CoverageInspector::new(&[dir.0.clone()], SensorKind::Notify, 500)
            .unwrap()
            .inspect();
        assert!(has(&report, "scan_depth_limit"));
        assert!(has(&report, "non_utf8_path_not_inspected"));
        assert!(report.has_gap());
        assert!(report
            .roots
            .iter()
            .all(|r| r.issues.iter().all(|i| i.path.to_str().is_some())));
    }
    #[test]
    fn expired_budget_and_invalid_config_are_explicit() {
        let dir = Temp::new();
        assert!(CoverageInspector::new(&[], SensorKind::Notify, 1).is_err());
        assert!(CoverageInspector::new(&vec![dir.0.clone(); 129], SensorKind::Notify, 1).is_err());
        assert!(CoverageInspector::new(&[dir.0.clone()], SensorKind::Notify, 50_001).is_err());
        let mut row = RootCoverage {
            configured_path: dir.0.clone(),
            registered_path: dir.0.clone(),
            entries_checked: 0,
            skipped_symlinks: 0,
            issues: vec![],
            omitted_issues: 0,
        };
        let mut budget = Budget {
            remaining: 10,
            started: Instant::now() - MAX_SCAN_TIME - Duration::from_secs(1),
        };
        assert!(!budget.take(&dir.0, &mut row));
        assert_eq!(row.issues[0].code, "scan_time_limit");
        assert_eq!(row.entries_checked, 0);
        for _ in 0..100 {
            row.issue("test", &dir.0);
        }
        assert_eq!(row.issues.len(), 32);
        assert_eq!(row.omitted_issues, 69);
    }
}
