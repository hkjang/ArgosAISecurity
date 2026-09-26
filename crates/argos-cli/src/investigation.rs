//! CLI와 조회형 MCP가 같은 읽기 전용 근거 조회를 사용한다.
use argos_storage::{EventStore, EvidenceQuery};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};

pub fn time_range(
    question: &str,
    from: Option<u64>,
    to: Option<u64>,
    now: u64,
) -> Result<(u64, u64, &'static str), String> {
    if from.is_some() || to.is_some() {
        let (from, to) = (
            from.ok_or("--from-ms와 --to-ms를 함께 지정하세요")?,
            to.ok_or("--from-ms와 --to-ms를 함께 지정하세요")?,
        );
        if from > to || to > i64::MAX as u64 {
            return Err("잘못된 조회 구간입니다".into());
        }
        return Ok((from, to, "명시한 구간"));
    }
    let compact = question
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let lower = question.to_lowercase();
    let temporal_count = compact.matches("지난").count()
        + compact.matches("최근").count()
        + lower.matches("last ").count();
    if temporal_count > 1 {
        return Err(
            "여러 기간이 포함되어 있습니다. --from-ms/--to-ms로 조회 구간을 지정하세요".into(),
        );
    }
    let duration = if let Some((_, suffix)) = compact
        .split_once("지난")
        .or_else(|| compact.split_once("최근"))
    {
        let count = suffix.chars().take_while(|c| c.is_ascii_digit()).count();
        let n: u64 = suffix[..count]
            .parse()
            .map_err(|_| "기간을 해석할 수 없습니다. --from-ms/--to-ms를 지정하세요")?;
        let unit = &suffix[count..];
        let multiplier = if unit.starts_with("시간") {
            3_600_000
        } else if unit.starts_with('분') {
            60_000
        } else if unit.starts_with('일') {
            86_400_000
        } else {
            return Err("지원 기간: 지난 N시간/N분/N일; 또는 --from-ms/--to-ms".into());
        };
        Some(
            n.checked_mul(multiplier)
                .filter(|v| *v > 0)
                .ok_or("조회 기간이 너무 크거나 0입니다")?,
        )
    } else if let Some((_, suffix)) = lower.split_once("last ") {
        let mut words = suffix.split_whitespace();
        let n: u64 = words
            .next()
            .unwrap_or("")
            .parse()
            .map_err(|_| "기간은 last N hours/minutes/days 또는 명시적 시각을 사용하세요")?;
        let unit = words.next().unwrap_or("");
        let multiplier = if unit.starts_with("hour") {
            3_600_000
        } else if unit.starts_with("minute") {
            60_000
        } else if unit.starts_with("day") {
            86_400_000
        } else {
            return Err("지원하지 않는 기간입니다. --from-ms/--to-ms를 지정하세요".into());
        };
        Some(
            n.checked_mul(multiplier)
                .filter(|v| *v > 0)
                .ok_or("조회 기간이 너무 크거나 0입니다")?,
        )
    } else {
        None
    };
    if [
        "어제",
        "오늘",
        "주간",
        "주일",
        "이번",
        "yesterday",
        "today",
        "since",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        return Err("달력 기준 기간은 --from-ms/--to-ms로 지정하세요".into());
    }
    if duration.is_none()
        && (compact.contains("시간")
            || compact.contains("지난")
            || compact.contains("최근")
            || lower.contains("hour")
            || lower.contains("minute")
            || lower.contains("days")
            || lower.contains("last"))
    {
        return Err("기간을 안전하게 해석할 수 없습니다. --from-ms/--to-ms를 지정하세요".into());
    }
    Ok((
        now.saturating_sub(duration.unwrap_or(86_400_000)),
        now,
        if duration.is_some() {
            "질문에서 해석한 구간"
        } else {
            "기본 최근 24시간"
        },
    ))
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn query(args: &Value) -> Result<EvidenceQuery, String> {
    let obj = args.as_object().ok_or("arguments는 객체여야 합니다")?;
    if obj
        .keys()
        .any(|k| !["from_ms", "to_ms", "pid", "limit"].contains(&k.as_str()))
    {
        return Err("알 수 없는 조회 인자입니다".into());
    }
    let from_ms = args
        .get("from_ms")
        .and_then(Value::as_u64)
        .ok_or("from_ms 필수")?;
    let to_ms = args
        .get("to_ms")
        .and_then(Value::as_u64)
        .ok_or("to_ms 필수")?;
    let pid = match args.get("pid") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            u32::try_from(v.as_u64().ok_or("pid는 정수여야 합니다")?)
                .map_err(|_| "pid 범위 초과")?,
        ),
    };
    let limit = match args.get("limit") {
        None => 200,
        Some(v) => usize::try_from(v.as_u64().ok_or("limit는 양의 정수여야 합니다")?)
            .map_err(|_| "limit 범위 초과")?,
    };
    Ok(EvidenceQuery {
        from_ms,
        to_ms,
        pid,
        limit,
    })
}

fn dispatch(store: &EventStore, request: Value, phase: &mut u8) -> Option<Value> {
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !request.get("method").is_some_and(Value::is_string)
    {
        return Some(error(
            request.get("id").cloned().unwrap_or(Value::Null),
            -32600,
            "Invalid Request",
        ));
    }
    let method = request["method"].as_str().unwrap();
    let Some(id) = request.get("id").cloned() else {
        if method == "notifications/initialized" && *phase == 1 {
            *phase = 2;
        }
        return None;
    };
    if !(id.is_string() || id.is_number()) {
        return Some(error(Value::Null, -32600, "잘못된 요청 ID"));
    }
    let result = match method {
        "initialize" => {
            if *phase != 0 {
                return Some(error(id, -32600, "이미 초기화되었습니다"));
            }
            if !request["params"]["protocolVersion"].is_string() {
                return Some(error(id, -32602, "protocolVersion 필수"));
            }
            *phase = 1;
            json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"argos-evidence","version":env!("CARGO_PKG_VERSION")},"instructions":"이 서버는 설정된 단일 호스트 DB만 조회합니다. 근거 ID와 truncation을 답변에 표시하세요. 조회 누락은 위협 없음의 근거가 아닙니다."})
        }
        "ping" => json!({}),
        _ if *phase != 2 => return Some(error(id, -32002, "초기화가 필요합니다")),
        "tools/list" => json!({"tools":[{
            "name":"query_evidence", "description":"로컬 호스트의 지정 기간 파일·탐지·프로세스 증거, 각 ID와 전체 건수/잘림 상태. DB 읽기 전용.",
            "inputSchema":{"type":"object","properties":{"from_ms":{"type":"integer","minimum":0},"to_ms":{"type":"integer","minimum":0},"pid":{"type":"integer","minimum":0,"maximum":4294967295u64},"limit":{"type":"integer","minimum":1,"maximum":10000,"default":200}},"required":["from_ms","to_ms"],"additionalProperties":false},
            "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}
        }]}),
        "tools/call" => {
            if request["params"]["name"] != "query_evidence" {
                return Some(error(id, -32602, "알 수 없는 도구"));
            }
            match query(&request["params"]["arguments"]) {
                Err(e) => return Some(error(id, -32602, &e)),
                Ok(q) => match store.query_evidence(&q) {
                    Ok(bundle) => match store.response_results(&q) {
                        Ok(responses) => {
                            let mut result = serde_json::to_value(bundle).unwrap();
                            result["response_results"] = serde_json::to_value(responses).unwrap();
                            json!({"content":[{"type":"text","text":result.to_string()}],"structuredContent":result,"isError":false})
                        }
                        Err(e) => {
                            json!({"content":[{"type":"text","text":e.to_string()}],"isError":true})
                        }
                    },
                    Err(e) => {
                        json!({"content":[{"type":"text","text":e.to_string()}],"isError":true})
                    }
                },
            }
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

pub fn serve_mcp(store: &EventStore) -> super::CmdResult {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut phase = 0;
    loop {
        let mut line = Vec::new();
        if (&mut input).take(1_048_577).read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.len() > 1_048_576 {
            return Err("MCP 요청은 1MiB 이하로 제한됩니다".into());
        }
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(request) => dispatch(store, request, &mut phase),
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            writeln!(output, "{response}")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requested_period_is_not_a_recent_row_sample() {
        assert_eq!(
            time_range("지난 24시간 위험했어?", None, None, 100_000_000)
                .unwrap()
                .0,
            13_600_000
        );
        assert_eq!(
            time_range("last 2 hours", None, None, 100_000_000)
                .unwrap()
                .0,
            92_800_000
        );
        assert!(time_range("어제", None, None, 100_000_000).is_err());
        assert!(time_range("지난 0시간", None, None, 100).is_err());
        assert!(time_range("", Some(10), None, 100).is_err());
        assert_eq!(
            time_range("어제", Some(10), Some(20), 100).unwrap(),
            (10, 20, "명시한 구간")
        );
    }
    #[test]
    fn ambiguous_periods_are_not_silently_narrowed() {
        assert_eq!(
            time_range("최근48시간", None, None, 200_000_000).unwrap().0,
            27_200_000
        );
        for question in [
            "지난2시간과 지난24시간",
            "last 2 hours yesterday",
            "48시간 위험",
            "last2 hours",
        ] {
            assert!(
                time_range(question, None, None, 200_000_000).is_err(),
                "{question}"
            );
        }
    }
    #[test]
    fn query_rejects_ignored_or_lossy_filters() {
        assert!(query(&json!({"from_ms":0,"to_ms":1,"pid":-1})).is_err());
        assert!(query(&json!({"from_ms":0,"to_ms":1,"server":"other"})).is_err());
        assert!(query(&json!({"from_ms":0,"to_ms":1,"limit":"5"})).is_err());
    }
}
