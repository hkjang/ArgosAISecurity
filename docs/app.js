/** v0.4.0 landing page copy and illustrative CLI workflows. No backend calls. */
const i18n = {
  "ko": {
    "nav_features": "핵심 기능",
    "nav_cli": "CLI 데모",
    "nav_architecture": "아키텍처",
    "nav_recovery": "복구 메커니즘",
    "nav_faq": "자주 묻는 질문",
    "hero_badge": "v0.4.0 · Linux 보안 플랫폼",
    "hero_title": "차단과 복구를 검증하는 Linux 보안<br><span class=\"text-gradient\">Argos AI Security</span>",
    "hero_subtitle": "통신이 끊겨도 등록한 파일을 이어 보내고, 보관 한도와 디스크 여유를 확인합니다. 복구 시험 결과가 현재 계획·백업에도 유효한지 다시 검증합니다.",
    "btn_quickstart": "빠른 시작 가이드",
    "btn_demo": "CLI 데모 체험",
    "metric_time": "v0.4.0",
    "metric_time_label": "공개 릴리즈",
    "metric_recovery": "SHA-256",
    "metric_recovery_label": "복구 객체 무결성 검증",
    "metric_policy": "Ed25519",
    "metric_policy_label": "서명·버전·기간 검증",
    "metric_ai": "Ollama",
    "metric_ai_label": "Anthropic·온프레미스 AI",
    "sec_features_title": "탐지부터 조사·복구까지",
    "sec_features_desc": "자동 차단은 기본 비활성입니다. 정책을 과거 이벤트로 비교하고 정상본을 검토한 뒤 운영 범위를 넓힐 수 있습니다.",
    "feat1_title": "행위·Linux 설정 분석",
    "feat1_desc": "notify/fanotify와 /proc 관측, 선택한 다중 시간 구간과 Linux 설정 의미를 분석합니다. 별도 경로·마운트 검사는 공백을 표시하고 시험 파일로 DB 수신을 확인합니다.",
    "feat2_title": "내용 표본과 엔트로피",
    "feat2_desc": "기본 앞부분 64 KiB를 분석하며, 선택 기능으로 읽기 예산을 앞·중간·끝에 나눕니다. 이전 관측과 파일 유형을 비교하지만 파일 전체 검사나 공격 판정을 보증하지는 않습니다.",
    "feat3_title": "정상본 복구·사건 보존",
    "feat3_desc": "정상본 미리보기와 사건 보존, SQLite·PostgreSQL 복구 시험을 지원합니다. 보고서의 계획·백업·필수 검사·나이를 대조하며, 무서명 보고서의 출처 인증과는 구별합니다.",
    "feat4_title": "서명 정책·사전 검증",
    "feat4_desc": "서명·버전·유효기간·대상·키 ID를 검사합니다. 저장 이벤트로 정책을 비교하고 승인 예외의 매칭·만료·범위와 예외 제거 영향을 확인합니다.",
    "feat5_title": "근거 기반 AI·증거 패키지",
    "feat5_desc": "AI 인용을 실제 근거와 대조합니다. 검증한 증거·정상본을 영속 대기열로 전송하고 서명 수신증명을 확인합니다. 서버는 전체·에이전트 한도와 디스크 여유를 검사합니다.",
    "feat6_title": "프로세스 차단·네트워크 격리",
    "feat6_desc": "자동 차단을 켠 Linux 호스트에서 PID·시작 시각·부팅 ID를 확인하고 종료 결과를 기록합니다. 별도 격리 명령은 IPv4/IPv6의 명시적 관리 연결만 허용합니다.",
    "sec_cli_title": "CLI 사용 흐름 살펴보기",
    "sec_cli_desc": "설명을 위한 가상 데이터와 요약 예시입니다. 실제 서버에 연결하거나 명령을 실행하지 않으며, 처리 시간·탐지율·복구율의 측정 결과가 아닙니다.",
    "sec_arch_title": "수집·판단·보존을 나눈 구조",
    "sec_arch_desc": "대응 판단과 알림 억제를 분리하고 백업·사건 보존·중앙 전송을 별도 작업으로 처리합니다. 실제 운영 처리량은 배포 환경에서 검증해야 합니다.",
    "arch_sensor": "argos-sensor",
    "arch_sensor_desc": "notify / fanotify 파일 이벤트와 /proc 신원·UID/GID·capability 관측",
    "arch_detect": "argos-detect",
    "arch_detect_desc": "센서별 점수·내용 표본·선택적 다중 시간창과 계보 집계",
    "arch_recovery": "argos-recovery",
    "arch_recovery_desc": "정상본 판정·미리보기·복구 시험·독립 사건 보존 참조",
    "arch_response": "argos-response",
    "arch_response_desc": "pidfd 신원 확인·종료 결과 감사와 IPv4/IPv6 격리",
    "arch_brain": "argos-brain",
    "arch_brain_desc": "Anthropic / Ollama 기반 기간별 근거 조회와 AI 설명",
    "arch_policy": "argos-policy",
    "arch_policy_desc": "서명·버전·기간·대상 검증, 승인 근거를 포함한 새 버전 롤백",
    "sec_faq_title": "자주 묻는 질문 (FAQ)",
    "sec_faq_desc": "Argos AI Security 도입 및 운용에 대한 주요 답변입니다.",
    "faq1_q": "Q1. 무엇을 검증할 수 있나요?",
    "faq1_a": "탐지·대응 결과와 정상본 무결성 외에 경로 공백, 시험 이벤트 수신, DB 복원 검사, 원격 보관 수신증명과 AI 인용을 확인합니다. 실제 시험 범위는 검증 문서에 기록합니다. 전체 서비스 복구, 운영 탐지율이나 AI 문장의 의미까지 보증하지는 않습니다.",
    "faq2_q": "Q2. 기본 설정에서 프로세스가 자동 차단되나요?",
    "faq2_a": "아니요. auto_block=false가 기본이며 notify 센서는 원인 PID를 제공하지 않습니다. 자동 차단은 명시적 활성화, 기본 80점 임계치와 규칙 조건, Linux 프로세스 신원 검증이 필요합니다. 오탐 위험이 있으므로 정책 재생과 관찰 모드로 먼저 확인하세요.",
    "faq3_q": "Q3. AI에 어떤 데이터가 전달되나요?",
    "faq3_a": "설정한 제공자에 저장된 이벤트·탐지·프로세스·대응 근거를 전달합니다. 파일 본문을 직접 보내지는 않지만 경로·명령행·계정 정보에도 민감한 값이 있을 수 있습니다. Anthropic은 외부 API이며, Ollama는 지정한 사내 주소로 구성할 수 있습니다. 모델 ID와 조회 범위를 확인하세요.",
    "faq4_q": "Q4. 어떤 환경에서 사용할 수 있나요?",
    "faq4_a": "v0.4.0 배포 바이너리는 GNU/Linux x86_64, glibc 2.39 이상용입니다. 소스 빌드 최소 Rust 버전은 1.86입니다. notify는 다른 OS 개발용 경로도 제공하지만 이번 릴리즈에서 Windows/macOS 바이너리와 실행 검증 결과는 제공하지 않습니다. fanotify·프로세스 대응·격리는 Linux 지원과 권한이 필요합니다.",
    "footer_tagline": "차단·정상본 복구·사건 근거를 검증하는 Linux 보안 플랫폼",
    "footer_quick_inquiry": "문의 요청:",
    "footer_rights": "© 2026 Argos AI Security. All rights reserved. Licensed under AGPL-3.0.",
    "nav_docs": "문서",
    "btn_download": "v0.4.0 다운로드"
  },
  "en": {
    "nav_features": "Features",
    "nav_cli": "CLI Demo",
    "nav_architecture": "Architecture",
    "nav_recovery": "Recovery",
    "nav_faq": "FAQ",
    "hero_badge": "v0.4.0 · Linux security platform",
    "hero_title": "Linux security with verifiable response and recovery<br><span class=\"text-gradient\">Argos AI Security</span>",
    "hero_subtitle": "Resume queued files after connection failures and check storage limits and free space. Revalidate recovery drill results against the current plan and backup.",
    "btn_quickstart": "Quick Start Guide",
    "btn_demo": "Interactive CLI Demo",
    "metric_time": "v0.4.0",
    "metric_time_label": "Published release",
    "metric_recovery": "SHA-256",
    "metric_recovery_label": "Recovery object integrity",
    "metric_policy": "Ed25519",
    "metric_policy_label": "Signature, version and time checks",
    "metric_ai": "Ollama",
    "metric_ai_label": "Anthropic or on-premises AI",
    "sec_features_title": "Detection, investigation and recovery",
    "sec_features_desc": "Automatic blocking is off by default. Compare policies against recorded events and review recovery points before expanding deployment.",
    "feat1_title": "Behavior and Linux configuration analysis",
    "feat1_desc": "Combine notify/fanotify and /proc observations with optional time windows and Linux configuration analysis. Check path and mount gaps separately, and confirm a probe event reaches the database.",
    "feat2_title": "Content samples and entropy",
    "feat2_desc": "The default reads up to 64 KiB from the beginning. Optional sampling divides a read budget across the beginning, middle and end and compares prior observations and file types. It does not inspect every byte.",
    "feat3_title": "Reviewed recovery and incident retention",
    "feat3_desc": "Preview reviewed backups, retain incident references and run SQLite/PostgreSQL recovery drills. Check report plans, backup bytes, required checks and age; unsigned report provenance is not authenticated.",
    "feat4_title": "Signed policies and preflight comparison",
    "feat4_desc": "Check signatures, versions, validity, targets and key IDs. Replay recorded events to compare policies and examine exception matches, expiry, scope and removal impact.",
    "feat5_title": "Evidence-based AI and export",
    "feat5_desc": "Match AI citations against real records. Queue verified packages and backups for delivery and validate signed receipts. The server checks global and per-agent limits and available disk space.",
    "feat6_title": "Process response and network isolation",
    "feat6_desc": "With blocking enabled on Linux, verify PID, start time and boot ID before termination and record the result. Separate IPv4/IPv6 isolation commands allow only explicit management connections.",
    "sec_cli_title": "Explore the CLI workflow",
    "sec_cli_desc": "Illustrative data and abbreviated explanations only. This page does not connect to a server or run commands. Outputs are not latency, detection-rate or recovery-rate measurements; English text translates the Korean CLI.",
    "sec_arch_title": "Separate collection, decisions and retention",
    "sec_arch_desc": "Response decisions are independent of alert suppression. Backup, incident retention and central delivery use separate workers. Production throughput needs validation in your deployment.",
    "arch_sensor": "argos-sensor",
    "arch_sensor_desc": "notify / fanotify file events and /proc identity, UID/GID and capability observations",
    "arch_detect": "argos-detect",
    "arch_detect_desc": "Sensor-aware scoring, content samples and optional time-window and ancestry aggregation",
    "arch_recovery": "argos-recovery",
    "arch_recovery_desc": "Known-good review, previews, recovery tests and independent incident retention",
    "arch_response": "argos-response",
    "arch_response_desc": "pidfd identity checks, termination audit and IPv4/IPv6 isolation",
    "arch_brain": "argos-brain",
    "arch_brain_desc": "Time-bounded evidence and AI explanations with Anthropic or Ollama",
    "arch_policy": "argos-policy",
    "arch_policy_desc": "Signature, version, validity and target checks; rollback as an approved new version",
    "sec_faq_title": "Frequently Asked Questions",
    "sec_faq_desc": "Key insights into deploying and operating Argos AI Security.",
    "faq1_q": "Q1. What can I verify?",
    "faq1_a": "Verify response results, reviewed backup integrity, path gaps, probe delivery, database restore checks, remote receipts and AI citations. Validation documents record the executed tests. These checks do not guarantee full service recovery, production detection rates or the semantic truth of AI statements.",
    "faq2_q": "Q2. Does the default configuration block processes?",
    "faq2_a": "No. auto_block=false is the default, and notify cannot attribute file events to a PID. Blocking requires explicit activation, the default score threshold of 80 plus rule conditions, and verified Linux process identity. Use policy replay and observation mode to assess false positives first.",
    "faq3_q": "Q3. Which data is sent to the AI provider?",
    "faq3_a": "Stored file, detection, process and response evidence goes to the configured provider. File bodies are not sent directly, but paths, command lines and account information can still contain sensitive values. Anthropic uses an external API; Ollama can use your on-premises endpoint. Configure the model ID and review the query scope.",
    "faq4_q": "Q4. Which environments are supported?",
    "faq4_a": "The v0.4.0 binaries target GNU/Linux x86_64 with glibc 2.39 or later. Source builds require Rust 1.86 or later. notify also provides a development path for other operating systems, but this release supplies no Windows/macOS binaries or execution validation. fanotify, process response and isolation need Linux support and permissions.",
    "footer_tagline": "A Linux platform for verifiable response, reviewed recovery and incident evidence",
    "footer_quick_inquiry": "Inquiry:",
    "footer_rights": "© 2026 Argos AI Security. All rights reserved. Licensed under AGPL-3.0.",
    "nav_docs": "Docs",
    "btn_download": "Download v0.4.0"
  }
};

const cliCommands = {
  "status": "argos --config argos.toml status",
  "policy": "argos --config argos.toml policy verify",
  "restore": "argos restore /srv/data/report.txt --list",
  "explain": "argos ask --from-ms 1790380800000 --to-ms 1790467200000 \"Review this period\"",
  "evidence": "argos evidence-export 42 --out /secure/incident-42"
};
const cliExamples = {
  "ko": {
    "status": "[예제 설정을 사용하는 상태 출력 발췌]\n센서        : Notify\n자동 차단   : 비활성 (탐지 전용)\n중앙 서버   : 미연동 (standalone)\n\n생존 신호와 보호 지표는 실제 에이전트 기록에서 확인합니다.\n탐지 없음과 감시 중단은 서로 다른 상태입니다.",
    "policy": "[신뢰 키·메타데이터를 설정한 정책의 검증 예시]\n서명·유효기간·대상·설정 검증 성공.\n영구 버전 검사/적용은 에이전트 시작 시 실행됩니다.\n\n$ argos --config argos.toml policy status\n마지막 수락 정책의 버전·해시와 감사 이력을 조회합니다.\nverify 명령은 정책을 활성화하지 않습니다.",
    "restore": "[가상 버전 목록 발췌]\nID   TRUST\n23   unverified\n19   known-good  (운영자 검토 근거가 있는 버전)\n\n$ argos restore /srv/data/report.txt --version 23 --preview /tmp/report-preview.txt\n미검토 버전은 새 경로에서 먼저 검토합니다.\n\n$ argos restore /srv/data/report.txt\n기본 복구는 최신 정상 판정 버전을 선택합니다.\n백업 시각이나 해시 일치만으로 정상본이 되지 않습니다.",
    "explain": "[기간을 명시한 AI 조사 흐름]\n설정한 Anthropic/Ollama 제공자와 명시한 모델 ID를 사용합니다.\n호스트 범위는 현재 설정의 로컬 이벤트 DB입니다.\n종류별 전체/조회 건수와 누락을 표시하고 근거 ID를 전달합니다.\n\n답변은 원본 근거와 대조해야 합니다.\n이 데모는 AI를 호출하지 않으며 실제 조사 결과를 표시하지 않습니다.",
    "evidence": "[새 디렉터리에 작성하는 증거 패키지]\nevidence.json  근거·대응 결과·조회 범위와 누락\npolicy.json    내보내기 시점의 마지막 수락 정책 또는 로컬 설정\nmanifest.json  파일 목록·크기·SHA-256·마스킹 범위\n\n$ argos evidence-verify /secure/incident-42\n파일과 manifest의 일치 여부를 검증합니다.\n기본값은 민감 필드를 가리며, 해시 검증은 발급자 진위 증명이 아닙니다."
  },
  "en": {
    "status": "[Translated excerpt using the example configuration]\nSensor        : Notify\nAuto-block    : Disabled (detection only)\nCentral       : Standalone\n\nCheck actual heartbeat and protection metrics from your agent.\nNo detections and interrupted monitoring are different states.",
    "policy": "[Example with trusted keys and policy metadata configured]\nSignature, time bounds, target and settings verified.\nPersistent version checks and activation occur at agent startup.\n\n$ argos --config argos.toml policy status\nRead the last accepted version, hash and audit history.\nThe verify command does not activate a policy.",
    "restore": "[Illustrative version list]\nID   TRUST\n23   unverified\n19   known-good  (explicitly reviewed by an operator)\n\n$ argos restore /srv/data/report.txt --version 23 --preview /tmp/report-preview.txt\nReview the unverified version in a new file first.\n\n$ argos restore /srv/data/report.txt\nDefault restore selects the latest known-good version.\nAn earlier timestamp or matching hash alone does not establish trust.",
    "explain": "[AI investigation with an explicit time range]\nUses the configured Anthropic/Ollama provider and explicit model ID.\nThe host scope is the local event DB in your configuration.\nIncludes per-source counts, missing coverage and evidence IDs.\n\nCompare the answer with the underlying evidence.\nThis demo makes no AI calls and displays no real incident findings.",
    "evidence": "[Evidence package in a new directory]\nevidence.json  Evidence, response records and query coverage\npolicy.json    Last accepted policy or local configuration at export\nmanifest.json  File list, sizes, SHA-256 and redaction scope\n\n$ argos evidence-verify /secure/incident-42\nChecks consistency between files and the manifest.\nSensitive fields are redacted by default; hashes do not authenticate origin."
  }
};

// The URL owns the locale; loading the English page must never replace it with Korean.
const currentLang = document.documentElement.lang === 'en' ? 'en' : 'ko';
function switchCliTab(key) {
  if (!Object.hasOwn(cliCommands, key)) return;
  document.querySelectorAll('.cli-tab').forEach(tab => {
    const active = tab.dataset.cli === key;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-pressed', String(active));
  });
  const body = document.getElementById('cli-output-container');
  if (!body) return;
  const command = document.createElement('div');
  const prompt = document.createElement('span');
  prompt.className = 'cli-prompt';
  prompt.textContent = 'demo@argos:~$ ';
  const text = document.createElement('span');
  text.className = 'cli-cmd';
  text.textContent = cliCommands[key];
  command.append(prompt, text);
  const output = document.createElement('div');
  output.className = 'cli-output';
  output.textContent = cliExamples[currentLang][key];
  body.replaceChildren(command, output);
}

document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-i18n]').forEach(element => {
    const value = i18n[currentLang][element.dataset.i18n];
    if (value) element.innerHTML = value; // Trusted static copy only; demo data uses textContent.
  });
  document.querySelectorAll('.cli-tab').forEach(tab => {
    tab.addEventListener('click', () => switchCliTab(tab.dataset.cli));
  });
  switchCliTab('status');
  const faqItems = document.querySelectorAll('.faq-item');
  faqItems.forEach(item => {
    const button = item.querySelector('.faq-question');
    if (!button) return;
    button.setAttribute('aria-expanded', String(item.classList.contains('active')));
    button.addEventListener('click', () => {
      const open = !item.classList.contains('active');
      faqItems.forEach(other => {
        other.classList.remove('active');
        other.querySelector('.faq-question')?.setAttribute('aria-expanded', 'false');
      });
      item.classList.toggle('active', open);
      button.setAttribute('aria-expanded', String(open));
    });
  });
  const mobileButton = document.getElementById('mobile-menu-btn');
  const navLinks = document.querySelector('.nav-links');
  if (mobileButton && navLinks) {
    mobileButton.setAttribute('aria-expanded', 'false');
    mobileButton.addEventListener('click', () => {
      mobileButton.setAttribute('aria-expanded', String(navLinks.classList.toggle('active')));
    });
    navLinks.querySelectorAll('a').forEach(link => link.addEventListener('click', () => {
      navLinks.classList.remove('active');
      mobileButton.setAttribute('aria-expanded', 'false');
    }));
  }
});
