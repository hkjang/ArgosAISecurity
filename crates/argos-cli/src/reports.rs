//! 외부 자원 없이 열 수 있는 조사/복구 보고서. 로그는 HTML로 해석하지 않는다.
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

pub fn write_report(path: &Path, kind: &str, data: Value) -> super::CmdResult {
    let document = render(kind, data)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(document.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn render(kind: &str, data: Value) -> Result<String, serde_json::Error> {
    let payload = serde_json::to_string(&json!({"kind":kind,"data":data}))?
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    Ok(TEMPLATE.replace("PAYLOAD_JSON", &payload))
}

const TEMPLATE: &str = r#"<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>Argos · 검증 보고서</title><style>
:root{color-scheme:dark;font:15px system-ui}body{margin:0;background:#0d1726;color:#e3ebf6}main{max-width:1200px;margin:40px auto;padding:24px}h1{font-size:32px}p{color:#b6c8de;line-height:1.6}.bar{background:#17283d;border:1px solid #344f6d;padding:20px;border-radius:12px;margin:20px 0}input,select,button{padding:10px;background:#213853;color:#fff;border:1px solid #4b6580;border-radius:6px}input[type=range]{width:65%;vertical-align:middle}table{width:100%;border-collapse:collapse}th,td{padding:12px;border-bottom:1px solid #304256;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{color:#7eddd6}code{color:#9ae8df}.warn{color:#ffd294}.tools{display:flex;gap:14px;align-items:center;flex-wrap:wrap}pre{white-space:pre-wrap;max-height:240px;overflow:auto}.muted{color:#8fa8c4}
</style><main><div class="muted">ARGOS AI SECURITY / 검증 가능한 근거</div><h1 id="title"></h1><p id="summary"></p><div class="bar tools" id="controls"></div><div class="bar" id="coverage"></div><table><thead id="head"></thead><tbody id="rows"></tbody></table><p class="muted">이 보고서는 생성 시점의 로컬 증거입니다. 조회 누락과 감시 중단 여부를 별도로 확인하세요. 정상본 표시는 운영자의 검토 판정이며 해시는 내용 무결성만 검증합니다.</p></main>
<script type="application/json" id="evidence">PAYLOAD_JSON</script><script>
const {kind,data}=JSON.parse(document.getElementById('evidence').textContent);
const el=id=>document.getElementById(id),text=(id,t)=>el(id).textContent=t;
function headers(names){const tr=document.createElement('tr');for(const n of names){const c=document.createElement('th');c.textContent=n;tr.append(c)}el('head').replaceChildren(tr)}
function row(values){const tr=document.createElement('tr');for(const v of values){const td=document.createElement('td');td.textContent=v??'—';tr.append(td)}el('rows').append(tr)}
if(kind==='incident'){
 text('title','사건 #'+data.detection.id+' · 시간순 조사');text('summary',data.detection.summary);
 const e=data.evidence,responses=data.response_results??{rows:[],total_rows:0,truncated:false},pages=[['파일',e.files],['탐지',e.detections],['프로세스',e.processes],['대응',responses]];
 text('coverage',`${e.from_ms} ~ ${e.to_ms} ms · `+pages.map(([n,p])=>`${n} ${p.rows.length}/${p.total_rows}건${p.truncated?' (누락 있음)':''}`).join(' / ')+' · 시간 범위 안의 연관 후보이며 인과관계 확정이 아닙니다. 네트워크 증거는 이 조회에 포함되지 않습니다.');
 const identity=(pid,c)=>c?.boot_id&&c?.start_time_ticks!=null?`${pid} / ${c.boot_id} / ${c.start_time_ticks}`:`${pid} / 시작 시각 미확인`;
 const events=[...responses.rows.map(r=>({t:r.result.timestamp_ms,id:'response:'+r.id,key:identity(r.result.pid,r.result),details:r.result.action+' · '+r.result.outcome+' · '+(r.result.error??'')})),...e.files.rows.map(r=>({t:r.event.timestamp_ms,id:'file:'+r.id,key:identity(r.event.pid,r.event.process),details:r.event.action+' '+r.event.path})),...e.processes.rows.map(r=>({t:r.event.timestamp_ms,id:'process:'+r.id,key:identity(r.event.pid,r.event),details:`uid=${r.event.uid}, ppid=${r.event.ppid} (부모 시작 시각 미확인) · ${r.event.exe??''} ${r.event.cmdline}`})),...e.detections.rows.map(r=>({t:r.timestamp_ms,id:'detection:'+r.id,key:identity(r.pid,null),details:`${r.severity} ${r.score} · ${r.summary}`}))].sort((a,b)=>a.t-b.t||a.id.localeCompare(b.id));
 const filter=document.createElement('select');for(const key of ['',...new Set(events.map(e=>e.key))]){const o=document.createElement('option');o.value=key;o.textContent=key||'전체 프로세스';filter.append(o)}
 const slider=document.createElement('input');slider.type='range';slider.min=0;slider.max=events.length;slider.value=events.length;slider.setAttribute('aria-label','타임라인 재생 위치');const label=document.createElement('span');
 const play=document.createElement('button');play.textContent='처음부터 재생';el('controls').append(filter,slider,label,play);headers(['시각 (epoch ms)','근거 ID','PID / 부팅 ID / 시작 ticks','활동']);let timer;
 function draw(){el('rows').replaceChildren();const visible=events.slice(0,Number(slider.value)).filter(e=>!filter.value||e.key===filter.value);for(const e of visible)row([e.t,e.id,e.key,e.details]);label.textContent=slider.value+'/'+events.length}
 filter.onchange=slider.oninput=draw;play.onclick=()=>{clearInterval(timer);slider.value=0;draw();timer=setInterval(()=>{slider.value=Number(slider.value)+1;draw();if(Number(slider.value)>=events.length)clearInterval(timer)},100)};draw();
}else{
 text('title','복구 준비도');text('summary',`생성 시각 ${data.generated_at_ms}ms · 감시 경로 ${data.watch_paths.join(', ')}`);
 text('controls',`정상 복구 지점 보유: ${data.paths.filter(p=>p.known_good_versions>0).length}개 경로 / 기록된 경로: ${data.paths.length}개`);
 text('coverage',`파일 검사 ${data.scanned_files}개 · 백업 기록 누락 ${data.untracked_paths.length}개${data.scan_truncated?' · 검사 상한 초과, 부분 결과':''} · `+data.untracked_paths.join(', '));
 headers(['경로','백업 / 정상본','최신 정상본 시각','용량 제외','마지막 복구 시험']);for(const p of data.paths)row([p.path,`${p.version_count} / ${p.known_good_versions}`,p.latest_known_good_ms,p.oversized_skips,p.last_restore_test_ms==null?'미실시':`${p.last_restore_test_ms}: ${p.last_restore_test_ok?'성공':'실패'} ${p.last_restore_test_error??''}`]);
}
</script></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_paths_cannot_end_json_script() {
        let doc = render(
            "incident",
            json!({"path":"</script><script>alert(1)</script>"}),
        )
        .unwrap();
        assert!(!doc.contains("<script>alert(1)"));
        assert!(doc.contains("\\u003c/script\\u003e"));
    }
}
