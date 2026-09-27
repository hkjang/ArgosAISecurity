//! 내보내기는 읽기 전용이며 이력 삭제나 새 큐로의 중복 판정 이관을 하지 않는다.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};

const FORMAT: &str = "argos-queue-receipt-archive-v1";
const MAX_LINE: u64 = 8192;
const MAX_EXPORT: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct ArchiveExportReport {
    pub format: String,
    pub output: PathBuf,
    pub archived_items: u64,
    pub sha256: String,
    pub size_bytes: u64,
    pub source_preserved: bool,
}
#[derive(Debug, Serialize)]
pub struct ArchiveVerification {
    pub format: String,
    pub archived_items: u64,
    pub sha256: String,
    pub size_bytes: u64,
    /// 수신증명은 서명되지만 파일 인덱스와 전체 이력의 완전성은 서명되지 않는다.
    pub archive_authenticated: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Record {
    #[serde(rename = "header")]
    Header {
        format: String,
        target: QueueTarget,
        archived_items: u64,
        exported_at_ms: u64,
    },
    #[serde(rename = "receipt")]
    Receipt { item: QueueItem },
    #[serde(rename = "trailer")]
    Trailer {
        archived_items: u64,
        content_sha256: String,
    },
}
fn line(record: &Record) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_LINE {
        return Err("수신증명 보관 행은 8KiB를 넘을 수 없습니다".into());
    }
    Ok(bytes)
}
/// 완료 수신증명을 100건씩 읽어 스트리밍한다. 처음 읽은 rowid 상한 이후의 완료는 다음 내보내기에 포함된다.
pub fn export_archive(directory: &Path, output: &Path) -> Result<ArchiveExportReport> {
    let parent = output.parent().ok_or("내보내기 부모 경로 없음")?;
    validate_private_directory(parent)?;
    if output.starts_with(directory) {
        return Err("내보내기는 큐 바깥 전용 디렉터리를 사용하세요".into());
    }
    let conn = open_readonly(directory)?;
    let tx = conn.unchecked_transaction()?;
    let target = metadata(&tx)?.ok_or("큐 대상 없음")?.0;
    let version: u32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let table = if version == 1 {
        "queue_items"
    } else {
        "receipt_archive"
    };
    let (watermark, count): (i64, u64) = tx.query_row(
        &format!("SELECT COALESCE(MAX(rowid),0),COUNT(*) FROM {table} WHERE state='sent'"),
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    tx.commit()?;
    let temporary = parent.join(format!(".argos-vault-archive-{}.tmp", random_id()?));
    let mut file = open_private(&temporary, true)?;
    let result = (|| -> Result<ArchiveExportReport> {
        let mut full_hash = Sha256::new();
        let mut content_hash = Sha256::new();
        let mut size = 0u64;
        let mut emit = |record: &Record, content: bool| -> Result<()> {
            let bytes = line(record)?;
            size = size.saturating_add(bytes.len() as u64);
            if size > MAX_EXPORT {
                return Err("수신증명 내보내기 256MiB 상한 초과".into());
            }
            file.write_all(&bytes)?;
            full_hash.update(&bytes);
            if content {
                content_hash.update(&bytes);
            }
            Ok(())
        };
        emit(
            &Record::Header {
                format: FORMAT.into(),
                target: target.clone(),
                archived_items: count,
                exported_at_ms: crate::now_ms(),
            },
            true,
        )?;
        let mut cursor = 0i64;
        let mut written = 0u64;
        loop {
            let rows = {
                let mut stmt=conn.prepare(&format!("SELECT rowid,{ITEM_COLUMNS} FROM {table} WHERE state='sent' AND rowid>?1 AND rowid<=?2 ORDER BY rowid LIMIT 100"))?;
                let mut rows = stmt.query(params![cursor, watermark])?;
                let mut batch = Vec::new();
                while let Some(row) = rows.next()? {
                    let rowid: i64 = row.get(0)?;
                    // 별도 SELECT는 같은 짧은 읽기 스냅샷의 확정 ID를 사용한다.
                    let id: String = row.get(1)?;
                    let item = conn.query_row(
                        &format!("SELECT {ITEM_COLUMNS} FROM {table} WHERE id=?1"),
                        [id],
                        decode,
                    )?;
                    batch.push((rowid, item));
                }
                batch
            };
            if rows.is_empty() {
                break;
            }
            for (rowid, item) in rows {
                verified_item(&item, &target)?;
                written += 1;
                if written > MAX_ARCHIVE_ITEMS {
                    return Err("수신증명 기록 상한 초과".into());
                }
                emit(&Record::Receipt { item }, true)?;
                cursor = rowid;
            }
        }
        if written != count {
            return Err("내보내기 중 수신증명 이력이 변경되었습니다".into());
        }
        // 클로저의 가변 빌림을 끝내고 trailer를 기록한다.
        drop(emit);
        let trailer = line(&Record::Trailer {
            archived_items: written,
            content_sha256: hex::encode(content_hash.finalize()),
        })?;
        size += trailer.len() as u64;
        if size > MAX_EXPORT {
            return Err("수신증명 내보내기 크기 상한 초과".into());
        }
        file.write_all(&trailer)?;
        full_hash.update(&trailer);
        file.sync_all()?;
        fs::hard_link(&temporary, output)?;
        fs::remove_file(&temporary)?;
        crate::sync_directory(parent)?;
        Ok(ArchiveExportReport {
            format: FORMAT.into(),
            output: output.into(),
            archived_items: written,
            sha256: hex::encode(full_hash.finalize()),
            size_bytes: size,
            source_preserved: true,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
/// 파일 인덱스는 unsigned이다. 서명 수신증명·구조·기록 수·파일 해시 일관성만 검사한다.
pub fn verify_archive(path: &Path, pubkey: &str) -> Result<ArchiveVerification> {
    let public = hex::encode(crate::public_key(pubkey)?.to_bytes());
    private_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    if before.len() > MAX_EXPORT {
        return Err("수신증명 보관 파일 256MiB 상한 초과".into());
    }
    let mut reader = BufReader::new(file);
    let mut content_hash = Sha256::new();
    let mut full_hash = Sha256::new();
    let mut seen = 0u64;
    let mut size = 0u64;
    let mut target = None;
    let mut expected = 0u64;
    let mut trailer = false;
    let mut ids = BTreeSet::new();
    let mut objects = BTreeSet::new();
    loop {
        let mut bytes = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if bytes.len() as u64 > MAX_LINE
            || bytes.last() != Some(&b'\n')
            || size > MAX_EXPORT
            || trailer
        {
            return Err("수신증명 보관 파일 행/크기/끝 구조 오류".into());
        }
        full_hash.update(&bytes);
        let record: Record = serde_json::from_slice(&bytes)?;
        match record {
            Record::Header {
                format,
                target: header,
                archived_items,
                ..
            } if target.is_none() && seen == 0 => {
                if format != FORMAT
                    || archived_items > MAX_ARCHIVE_ITEMS
                    || header.pinned_pubkey != public
                    || !valid_id(&header.agent_id)
                    || !valid_id(&header.key_id)
                {
                    return Err("수신증명 보관 헤더/신뢰 공개키 오류".into());
                }
                expected = archived_items;
                target = Some(header);
                content_hash.update(&bytes);
            }
            Record::Receipt { item } => {
                let target = target.as_ref().ok_or("보관 헤더 없음")?;
                verified_item(&item, target)?;
                seen += 1;
                if seen > expected
                    || !ids.insert(item.id.clone())
                    || !objects.insert((item.kind.clone(), item.sha256.clone()))
                {
                    return Err("보관 수신증명 수/중복 오류".into());
                }
                content_hash.update(&bytes);
            }
            Record::Trailer {
                archived_items,
                content_sha256,
            } if target.is_some() => {
                if archived_items != seen
                    || seen != expected
                    || content_sha256 != hex::encode(content_hash.clone().finalize())
                {
                    return Err("보관 끝 기록 수/내용 해시 불일치".into());
                }
                trailer = true;
            }
            _ => return Err("수신증명 보관 기록 순서 오류".into()),
        }
    }
    if !trailer {
        return Err("완료 trailer가 없는 보관 파일입니다".into());
    }
    let after = reader.get_ref().metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    let mut stable = before.len() == after.len()
        && after.len() == size
        && before.modified()? == after.modified()?
        && !path_after.file_type().is_symlink();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        stable = stable
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && before.dev() == path_after.dev()
            && before.ino() == path_after.ino();
    }
    if !stable {
        return Err("검증 도중 수신증명 보관 파일이 변경되었습니다".into());
    }
    Ok(ArchiveVerification {
        format: FORMAT.into(),
        archived_items: seen,
        sha256: hex::encode(full_hash.finalize()),
        size_bytes: size,
        archive_authenticated: false,
    })
}
