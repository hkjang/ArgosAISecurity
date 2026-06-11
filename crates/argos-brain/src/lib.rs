//! Argos Brain: AI 위협 분석 (요건서 5장 AI Threat Summary / Root Cause).
//!
//! Anthropic Messages API를 직접 HTTP로 호출한다 (Rust 공식 SDK 부재).
//! AI hallucination 리스크 대응(요건서 18장): 프롬프트에 실제 탐지 근거
//! (탐지 메타데이터 + 관련 파일 이벤트)만 제공하고, 근거 밖 추정은 금지시킨다.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";
const DEFAULT_MODEL: &str = "claude-opus-4-8";

#[derive(Debug, thiserror::Error)]
pub enum BrainError {
    #[error("ANTHROPIC_API_KEY 환경변수가 설정되어 있지 않습니다")]
    MissingApiKey,
    #[error("API 요청 실패: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API 오류 응답 ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("응답에 텍스트 블록이 없습니다")]
    EmptyResponse,
}

/// 탐지 1건에 대한 분석 입력 (storage에서 조회한 근거 데이터).
#[derive(Debug, Clone)]
pub struct DetectionContext {
    pub rule: String,
    pub score: f64,
    pub severity: String,
    pub summary: String,
    pub timestamp_ms: u64,
    pub pid: u32,
    /// 탐지 근거가 된 파일 경로들.
    pub paths: Vec<String>,
    /// 탐지 전후의 파일 이벤트 로그 라인 (ts, pid, action, path).
    pub recent_events: Vec<String>,
}

#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(Deserialize)]
struct ApiErrorBody {
    message: String,
}

const SYSTEM_PROMPT: &str = "\
당신은 Argos AI Security의 보안 분석가입니다. Linux 서버의 랜섬웨어/이상행위 탐지 결과를 분석합니다.

규칙:
- 제공된 탐지 데이터와 이벤트 로그에 있는 근거만 사용하세요. 로그에 없는 사실을 추정하지 마세요.
- 각 판단마다 근거가 된 이벤트(시각, 경로)를 명시하세요.
- 확신할 수 없는 부분은 '추가 확인 필요'로 표시하세요.

다음 형식으로 한국어로 답하세요:
## 사고 요약
(2-3문장, 비전문가도 이해 가능하게)
## 근거 분석
(어떤 이벤트 패턴이 탐지를 유발했는지)
## 오탐 가능성
(정상 배치 작업/백업/로그 로테이션일 가능성과 그 근거)
## 권장 조치
(우선순위 순서로, 각 조치의 이유 포함)";

pub struct ThreatExplainer {
    api_key: String,
    model: String,
    client: reqwest::blocking::Client,
}

impl ThreatExplainer {
    /// ANTHROPIC_API_KEY 환경변수에서 키를 읽는다.
    pub fn from_env() -> Result<Self, BrainError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .ok_or(BrainError::MissingApiKey)?;
        let model =
            std::env::var("ARGOS_AI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string());
        Ok(Self {
            api_key,
            model,
            client: reqwest::blocking::Client::new(),
        })
    }

    /// 탐지 1건을 사람이 읽을 수 있는 사고 분석으로 변환한다 (AI Threat Summary).
    pub fn explain(&self, ctx: &DetectionContext) -> Result<String, BrainError> {
        let request = MessagesRequest {
            model: &self.model,
            max_tokens: 2048,
            system: SYSTEM_PROMPT,
            messages: vec![Message {
                role: "user",
                content: build_prompt(ctx),
            }],
        };
        self.send(&request)
    }
}

/// Copilot 질의에 제공하는 서버 현황 근거 (요건서 5장 AI Query Copilot).
#[derive(Debug, Clone, Default)]
pub struct CopilotContext {
    /// 에이전트 상태 요약 (감시 경로, 누적 카운트 등).
    pub status_summary: String,
    /// 최근 탐지 로그 라인.
    pub recent_detections: Vec<String>,
    /// 최근 파일 이벤트 로그 라인.
    pub recent_events: Vec<String>,
    /// 최근 프로세스 실행 로그 라인.
    pub recent_processes: Vec<String>,
}

const COPILOT_SYSTEM: &str = "\
당신은 Argos AI Security의 보안 코파일럿입니다. 관리자의 자연어 질문에 한국어로 답합니다.

규칙:
- 제공된 서버 상태/탐지/이벤트/프로세스 데이터에 있는 근거만 사용하세요.
- 데이터에 없는 사실은 추정하지 말고 '제공된 로그에서 확인되지 않음'이라고 답하세요.
- 판단의 근거가 된 로그 라인(시각, 경로, pid)을 함께 제시하세요.
- 위험도 평가를 요청받으면 점수·심각도와 함께 그 이유를 설명하세요.
- 답변은 간결하게, 핵심부터.";

impl ThreatExplainer {
    /// 자연어 질문에 서버 데이터를 근거로 답한다 (argos ask).
    pub fn ask(&self, question: &str, ctx: &CopilotContext) -> Result<String, BrainError> {
        let mut content = String::new();
        content.push_str("[서버 상태]\n");
        content.push_str(&ctx.status_summary);
        content.push_str("\n\n[최근 탐지]\n");
        if ctx.recent_detections.is_empty() {
            content.push_str("(없음)\n");
        }
        for line in ctx.recent_detections.iter().take(30) {
            content.push_str(line);
            content.push('\n');
        }
        content.push_str("\n[최근 파일 이벤트]\n");
        for line in ctx.recent_events.iter().take(80) {
            content.push_str(line);
            content.push('\n');
        }
        content.push_str("\n[최근 프로세스 실행]\n");
        for line in ctx.recent_processes.iter().take(40) {
            content.push_str(line);
            content.push('\n');
        }
        content.push_str("\n[질문]\n");
        content.push_str(question);

        let request = MessagesRequest {
            model: &self.model,
            max_tokens: 1536,
            system: COPILOT_SYSTEM,
            messages: vec![Message {
                role: "user",
                content,
            }],
        };
        self.send(&request)
    }

    /// Messages API 공통 호출.
    fn send(&self, request: &MessagesRequest<'_>) -> Result<String, BrainError> {
        let resp = self
            .client
            .post(API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", API_VERSION)
            .header("content-type", "application/json")
            .json(request)
            .send()?;

        let status = resp.status();
        if !status.is_success() {
            let message = resp
                .json::<ApiErrorEnvelope>()
                .map(|e| e.error.message)
                .unwrap_or_else(|_| "응답 본문 해석 실패".to_string());
            return Err(BrainError::Api {
                status: status.as_u16(),
                message,
            });
        }

        let body: MessagesResponse = resp.json()?;
        body.content
            .into_iter()
            .find(|b| b.kind == "text")
            .map(|b| b.text)
            .ok_or(BrainError::EmptyResponse)
    }
}

fn build_prompt(ctx: &DetectionContext) -> String {
    let mut p = String::new();
    p.push_str("다음 탐지 이벤트를 분석해 주세요.\n\n[탐지 정보]\n");
    p.push_str(&format!(
        "- 룰: {}\n- 위험 점수: {:.0}/100 ({})\n- 시각(epoch ms): {}\n- pid: {}\n- 요약: {}\n",
        ctx.rule, ctx.score, ctx.severity, ctx.timestamp_ms, ctx.pid, ctx.summary
    ));
    p.push_str("\n[영향 파일]\n");
    for path in ctx.paths.iter().take(30) {
        p.push_str(&format!("- {path}\n"));
    }
    p.push_str("\n[탐지 전후 파일 이벤트 로그]\n");
    for line in ctx.recent_events.iter().take(100) {
        p.push_str(&format!("{line}\n"));
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_contains_evidence() {
        let ctx = DetectionContext {
            rule: "behavior.ransomware_pattern".into(),
            score: 87.0,
            severity: "critical".into(),
            summary: "10초 내 파일 42개 변경".into(),
            timestamp_ms: 1234,
            pid: 0,
            paths: vec!["/home/a.docx".into()],
            recent_events: vec!["1230 0 Modify /home/a.docx".into()],
        };
        let p = build_prompt(&ctx);
        assert!(p.contains("behavior.ransomware_pattern"));
        assert!(p.contains("/home/a.docx"));
        assert!(p.contains("87"));
    }
}
