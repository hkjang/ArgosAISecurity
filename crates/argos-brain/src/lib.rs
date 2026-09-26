//! Argos Brain: AI 위협 분석 (요건서 5장 AI Threat Summary / Root Cause).
//!
//! Anthropic/Ollama 응답을 구조화하고 제공한 근거의 인용·조회 범위를 검사한다.
//! 인용 검사는 모델 문장의 의미적 정확성이나 센서 수집의 완전성을 증명하지 않는다.

mod validation;

use std::io::Read;
use validation::Catalog;

const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

use argos_common::config::AiConfig;
use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.anthropic.com/v1/messages";
const API_VERSION: &str = "2023-06-01";

#[derive(Debug, thiserror::Error)]
pub enum BrainError {
    #[error("ANTHROPIC_API_KEY 환경변수가 설정되어 있지 않습니다")]
    MissingApiKey,
    #[error("AI 설정 오류: {0}")]
    Config(String),
    #[error("API 요청 실패: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API 오류 응답 ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("응답에 텍스트 블록이 없습니다")]
    EmptyResponse,
    #[error("AI 근거 검증 실패: {0}")]
    Validation(String),
    #[error("AI 데이터 크기 제한 초과: {0}")]
    SizeLimit(&'static str),
    #[error("AI 응답을 읽지 못했습니다: {0}")]
    Read(#[from] std::io::Error),
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

const SYSTEM_PROMPT: &str = validation::ANSWER_CONTRACT;

pub struct ThreatExplainer {
    api_key: String,
    model: String,
    client: reqwest::blocking::Client,
    provider: String,
    endpoint: String,
}

impl ThreatExplainer {
    /// ANTHROPIC_API_KEY와 ARGOS_AI_MODEL 환경변수를 사용한다.
    pub fn from_env() -> Result<Self, BrainError> {
        Self::from_config(&AiConfig::default())
    }

    pub fn from_config(config: &AiConfig) -> Result<Self, BrainError> {
        if !matches!(config.provider.as_str(), "anthropic" | "ollama") {
            return Err(BrainError::Config(
                "provider는 anthropic 또는 ollama여야 합니다".into(),
            ));
        }
        let model = if config.model.is_empty() {
            std::env::var("ARGOS_AI_MODEL").unwrap_or_default()
        } else {
            config.model.clone()
        };
        if model.trim().is_empty() {
            return Err(BrainError::Config(
                "ai.model 또는 ARGOS_AI_MODEL에 사용 가능한 모델을 지정하세요".into(),
            ));
        }
        if config.timeout_secs == 0 {
            return Err(BrainError::Config("timeout_secs는 양수여야 합니다".into()));
        }
        let key_env = if config.api_key_env.is_empty() && config.provider == "anthropic" {
            "ANTHROPIC_API_KEY"
        } else {
            &config.api_key_env
        };
        let api_key = if key_env.is_empty() {
            String::new()
        } else {
            std::env::var(key_env).unwrap_or_default()
        };
        if config.provider == "anthropic" && api_key.is_empty() {
            return Err(BrainError::MissingApiKey);
        }
        let endpoint = if config.endpoint.is_empty() {
            if config.provider == "ollama" {
                "http://127.0.0.1:11434/api/chat".into()
            } else {
                API_URL.into()
            }
        } else {
            config.endpoint.clone()
        };
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|_| BrainError::Config("잘못된 API URL".into()))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(BrainError::Config(
                "API URL은 사용자 인증정보가 없는 http(s) 주소여야 합니다".into(),
            ));
        }
        Ok(Self {
            api_key,
            model,
            provider: config.provider.clone(),
            endpoint,
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_secs))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
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
        self.send_validated(&request, &Catalog::legacy())
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

const COPILOT_SYSTEM: &str = validation::ANSWER_CONTRACT;

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
        for line in &ctx.recent_detections {
            content.push_str(line);
            content.push('\n');
        }
        content.push_str("\n[최근 파일 이벤트]\n");
        for line in &ctx.recent_events {
            content.push_str(line);
            content.push('\n');
        }
        content.push_str("\n[최근 프로세스 실행]\n");
        for line in &ctx.recent_processes {
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
        self.send_validated(&request, &Catalog::legacy())
    }

    /// 기간·PID로 조회한 전체 건수/누락 표시와 실제 근거 ID를 함께 전달한다.
    pub fn ask_evidence(
        &self,
        question: &str,
        evidence: &argos_storage::EvidenceBundle,
    ) -> Result<String, BrainError> {
        let catalog = Catalog::evidence(evidence, None)?;
        let request = MessagesRequest {
            model: &self.model,
            max_tokens: 2048,
            system: COPILOT_SYSTEM,
            messages: vec![Message {
                role: "user",
                content: format!(
                    "[조회 근거 JSON]\n{}\n[질문]\n{}",
                    serde_json::to_string(evidence)
                        .map_err(|e| BrainError::Config(e.to_string()))?,
                    question
                ),
            }],
        };
        self.send_validated(&request, &catalog)
    }

    /// 파일·탐지 근거와 대응 결과 감사를 함께 분석한다. 각 조회 범위/누락을 보존한다.
    pub fn ask_investigation(
        &self,
        question: &str,
        evidence: &argos_storage::EvidenceBundle,
        responses: &argos_storage::EvidencePage<argos_storage::ResponseAuditRow>,
    ) -> Result<String, BrainError> {
        let catalog = Catalog::evidence(evidence, Some(responses))?;
        let content = format!(
            "[조회 근거 JSON]\n{}\n[대응 결과 감사]\n{}\n[질문]\n{}",
            serde_json::to_string(evidence).map_err(|e| BrainError::Config(e.to_string()))?,
            serde_json::to_string(responses).map_err(|e| BrainError::Config(e.to_string()))?,
            question
        );
        let request = MessagesRequest {
            model: &self.model,
            max_tokens: 2048,
            system: COPILOT_SYSTEM,
            messages: vec![Message {
                role: "user",
                content,
            }],
        };
        self.send_validated(&request, &catalog)
    }

    fn send_validated(
        &self,
        request: &MessagesRequest<'_>,
        catalog: &Catalog,
    ) -> Result<String, BrainError> {
        let mut content = request
            .messages
            .iter()
            .map(|m| m.content.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        content.push_str("\n[앱이 검증한 인용 목록과 조회 범위]\n");
        content.push_str(&catalog.prompt()?);
        if content.len() > MAX_REQUEST_BYTES {
            return Err(BrainError::SizeLimit(
                "조회 범위를 줄이세요 (요청 최대 4MiB)",
            ));
        }
        let request = MessagesRequest {
            model: request.model,
            max_tokens: request.max_tokens,
            system: request.system,
            messages: vec![Message {
                role: "user",
                content,
            }],
        };
        catalog.validate_render(&self.send(&request)?)
    }

    /// 응답 본문 크기와 기존 전체 요청 timeout을 함께 제한한다.
    fn send(&self, request: &MessagesRequest<'_>) -> Result<String, BrainError> {
        let payload = if self.provider == "ollama" {
            let messages: Vec<_> =
                std::iter::once(serde_json::json!({"role":"system","content":request.system}))
                    .chain(
                        request
                            .messages
                            .iter()
                            .map(|m| serde_json::json!({"role":m.role,"content":m.content})),
                    )
                    .collect();
            serde_json::to_vec(&serde_json::json!({
                "model":self.model, "messages":messages, "stream":false,
                "options":{"num_predict":request.max_tokens}
            }))
        } else {
            serde_json::to_vec(request)
        }
        .map_err(|_| BrainError::Validation("요청 JSON을 구성하지 못했습니다".into()))?;
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(BrainError::SizeLimit(
                "조회 범위를 줄이세요 (요청 최대 4MiB)",
            ));
        }
        let mut req = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .body(payload);
        if self.provider == "ollama" {
            if !self.api_key.is_empty() {
                req = req.bearer_auth(&self.api_key);
            }
        } else {
            req = req
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", API_VERSION);
        }
        let resp = req.send()?;
        let status = resp.status();
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES)
        {
            return Err(BrainError::SizeLimit("응답 최대 1MiB"));
        }
        let mut bytes = Vec::new();
        resp.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(BrainError::SizeLimit("응답 최대 1MiB"));
        }
        if !status.is_success() {
            // 서버 본문에는 토큰/프롬프트가 반사될 수 있어 그대로 출력하지 않는다.
            return Err(BrainError::Api {
                status: status.as_u16(),
                message: "제공자가 요청을 거부했습니다".into(),
            });
        }
        let result = if self.provider == "ollama" {
            let body: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
                BrainError::Validation("제공자 응답 JSON을 해석하지 못했습니다".into())
            })?;
            body.get("message")
                .and_then(|m| m.get("content"))
                .and_then(|v| v.as_str())
                .map(String::from)
        } else {
            let body: MessagesResponse = serde_json::from_slice(&bytes).map_err(|_| {
                BrainError::Validation("제공자 응답 JSON을 해석하지 못했습니다".into())
            })?;
            let blocks: Vec<_> = body
                .content
                .into_iter()
                .filter(|b| b.kind == "text")
                .map(|b| b.text)
                .collect();
            if blocks.is_empty() {
                None
            } else {
                Some(blocks.join("\n"))
            }
        };
        result
            .filter(|s| !s.trim().is_empty())
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
mod tests;
