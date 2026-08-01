/**
 * Argos AI Security - Interactive Landing Page Logic (i18n, CLI Simulator, FAQ Accordion)
 */

// Multilingual Dictionary (KO / EN)
const i18n = {
  ko: {
    nav_features: "핵심 기능",
    nav_cli: "CLI 데모",
    nav_architecture: "아키텍처",
    nav_recovery: "복구 메커니즘",
    nav_faq: "자주 묻는 질문",
    hero_badge: "AI 기반 Linux 서버 랜섬웨어 방어 플랫폼",
    hero_title: "Linux 서버 보안의 새로운 기준,<br><span class='text-gradient'>Argos AI Security</span>",
    hero_subtitle: "실시간 파일·프로세스 감시, Shannon 엔트로피 분석, 0초 차단, 해시 검증 복구 및 Claude AI Threat Copilot을 통한 완벽한 랜섬웨어 방어 체계",
    btn_quickstart: "빠른 시작 가이드",
    btn_demo: "CLI 데모 체험",
    metric_time: "0ms",
    metric_time_label: "탐지-차단 지연 시간",
    metric_recovery: "100%",
    metric_recovery_label: "해시 검증 복구율",
    metric_policy: "Ed25519",
    metric_policy_label: "위변조 방지 정책 서명",
    metric_ai: "24/7",
    metric_ai_label: "Claude AI 사고 분석",
    
    sec_features_title: "엔터프라이즈급 6대 핵심 보안 기능",
    sec_features_desc: "단순 로그 감시를 넘어 프로세스 차단, 복구, AI 분석까지 일체형으로 제공합니다.",
    feat1_title: "실시간 행위 탐지 (Behavior Scoring)",
    feat1_desc: "fanotify 및 notify 기반 파일/프로세스 감시. 슬라이딩 윈도우(10초) 내 변경·삭제·확장자 변경 행위를 0~100점 스케일로 실시간 평가합니다.",
    feat2_title: "Shannon 엔트로피 암호화 탐지",
    feat2_desc: "파일 수정 발생 시 상위 64KB의 엔트로피를 계산(암호화 데이터 ≈ 7.2+). 랜섬웨어가 파일 전체를 암호화하기 직전에 즉각 감지합니다.",
    feat3_title: "해시 검증 무결성 복구 (CAS)",
    feat3_desc: "SHA-256 내용 주소 백업 저장소(Content-Addressable Storage)를 운용하여, 변조 전 시점으로 100% 해시 검증 복구를 수행합니다.",
    feat4_title: "Ed25519 Cryptographic Policy",
    feat4_desc: "서명되지 않은 보안 정책은 즉시 거부됩니다. 공격자에 의한 보안 정책 우회 및 임의 변경을 원천 차단합니다.",
    feat5_title: "Claude AI Threat Copilot",
    feat5_desc: "argos-brain 크레이트를 통해 실제 SQLite Audit Log에만 기반한 AI 위협 분석 요건 보고서를 즉시 작성합니다 (Hallucination 방지).",
    feat6_title: "프로세스 차단 & 네트워크 격리",
    feat6_desc: "SIGKILL/SIGSTOP으로 위험 프로세스 즉각 사살 및 iptables 기반 ARGOS_ISOLATE 체인을 생성하여 2차 감염 확산을 방지합니다.",

    sec_cli_title: "강력한 CLI (Command Line Interface)",
    sec_cli_desc: "터미널에서 명령어 한 줄로 실시간 보안 상태 확인부터 AI 사고 분석, 파일 복구까지 제어합니다.",

    sec_arch_title: "단탄한 시스템 아키텍처",
    sec_arch_desc: "독립된 Rust 크레이트 모듈화 설계로 극대화된 성능과 안전성을 제공합니다.",
    arch_sensor: "argos-sensor",
    arch_sensor_desc: "notify / fanotify / procmon 파일 & 프로세스 이벤트 수집",
    arch_detect: "argos-detect",
    arch_detect_desc: "Shannon 엔트로피 + 행위 점수 산정 로직",
    arch_recovery: "argos-recovery",
    arch_recovery_desc: "SHA-256 CAS 버전 관리 백업 및 무결성 복구",
    arch_response: "argos-response",
    arch_response_desc: "SIGKILL 프로세스 차단 & iptables 네트워크 격리",
    arch_brain: "argos-brain",
    arch_brain_desc: "Claude API 기반 AI 사고 설명 및 자연어 질의응답",
    arch_policy: "argos-policy",
    arch_policy_desc: "Ed25519 비대칭키 정책 서명 및 무결성 검증",

    sec_faq_title: "자주 묻는 질문 (FAQ)",
    sec_faq_desc: "Argos AI Security 도입 및 운용에 대한 주요 답변입니다.",
    faq1_q: "Q1. 기존 EDR/백신 제품과 Argos AI Security의 핵심 차별점은 무엇인가요?",
    faq1_a: "Argos는 단순히 알려진 시그니처 패턴만 비교하는 것이 아니라, 실시간 행위 점수(Behavior Scoring)와 Shannon 엔트로피 분석을 결합하여 Zero-day 랜섬웨어도 즉각 감지합니다. 또한 공격으로 훼손된 파일은 SHA-256 기반 내용 주소 백업(CAS)을 통해 공격 이전 시점으로 100% 해시 검증 복구가 가능합니다.",
    faq2_q: "Q2. 오탐(False Positive)으로 인해 중요한 서비스 프로세스가 차단될 위험은 없나요?",
    faq2_a: "Argos는 안정성을 최우선으로 설계되었습니다. 기본 정책은 auto_block=false(Dry-run 모드)이며, 오탐 방지를 위해 위험 점수가 80점 이상이고 확실한 원인 pid가 식별된 경우에만 차단 조치를 수행합니다. 또한 시스템 핵심 프로세스(pid 0 등)에 대한 시그널 전송은 원천적으로 거부됩니다.",
    faq3_q: "Q3. AI 분석 기능 사용 시 기업 내 민감한 파일 내용이 외부로 유출되나요?",
    faq3_a: "전혀 유출되지 않습니다. argos-brain 크레이트는 실제 파일 내용이 아닌, SQLite 감사 로그에 기록된 파일 이벤트 유형, 변경 비율, 엔트로피 점수 등 메타데이터만을 요약하여 Claude API로 전달합니다 (Hallucination 방지 및 보안 준수).",
    faq4_q: "Q4. Linux 외에 Windows나 macOS 환경에서도 빌드 및 개발 테스트가 가능한가요?",
    faq4_a: "네, 전체 워크스페이스는 Windows/macOS 환경에서도 컴파일 및 테스트가 지원됩니다. 크로스 플랫폼 파일 센서(notify)가 제공되며, Linux 전용 기능(fanotify, process kill, iptables)은 #[cfg(target_os = \"linux\")]로 안전하게 격리되어 있습니다.",

    footer_tagline: "AI 기반 Linux 서버 실시간 탐지·차단·복구 보안 플랫폼",
    footer_quick_inquiry: "문의 요청:",
    footer_rights: "© 2026 Argos AI Security. All rights reserved. Licensed under AGPL-3.0."
  },
  en: {
    nav_features: "Features",
    nav_cli: "CLI Demo",
    nav_architecture: "Architecture",
    nav_recovery: "Recovery",
    nav_faq: "FAQ",
    hero_badge: "AI-Powered Linux Server Ransomware Defense Platform",
    hero_title: "The New Standard in Linux Security,<br><span class='text-gradient'>Argos AI Security</span>",
    hero_subtitle: "Complete ransomware defense featuring real-time file & process monitoring, Shannon entropy analysis, 0-second blocking, hash-verified recovery, and Claude AI Threat Copilot.",
    btn_quickstart: "Quick Start Guide",
    btn_demo: "Interactive CLI Demo",
    metric_time: "0ms",
    metric_time_label: "Detection-to-Block Latency",
    metric_recovery: "100%",
    metric_recovery_label: "Hash-Verified Recovery",
    metric_policy: "Ed25519",
    metric_policy_label: "Tamper-Proof Policy Signature",
    metric_ai: "24/7",
    metric_ai_label: "Claude AI Incident Analysis",
    
    sec_features_title: "Enterprise Security Pillars",
    sec_features_desc: "Going beyond traditional log auditing to deliver integrated process termination, recovery, and AI copilot response.",
    feat1_title: "Real-time Behavior Scoring",
    feat1_desc: "fanotify & notify based file/process auditing. Evaluates modification, deletion, and extension change rates on a 0-100 severity scale within a 10s sliding window.",
    feat2_title: "Shannon Entropy Detection",
    feat2_desc: "Calculates Shannon entropy on file headers (64KB) upon modification (encrypted data ≈ 7.2+), catching ransomware right before whole-file encryption.",
    feat3_title: "Hash-Verified Integrity Recovery",
    feat3_desc: "Operates a SHA-256 Content-Addressable Storage (CAS) backup engine to perform 100% hash-verified instant file restoration to pre-attack states.",
    feat4_title: "Ed25519 Cryptographic Policy",
    feat4_desc: "Unsigned security policies are strictly rejected, preventing attackers from bypassing or modifying security configurations.",
    feat5_title: "Claude AI Threat Copilot",
    feat5_desc: "Generates factual threat summaries grounded exclusively in SQLite WAL audit logs via the argos-brain crate (Hallucination-free).",
    feat6_title: "Process Kill & Network Isolation",
    feat6_desc: "Terminates malicious processes via SIGKILL/SIGSTOP and enforces iptables ARGOS_ISOLATE chains to stop lateral movement.",

    sec_cli_title: "Powerful Command Line Interface",
    sec_cli_desc: "Control everything from security auditing to AI incident explanations and file recovery right from your terminal.",

    sec_arch_title: "Robust Modular Architecture",
    sec_arch_desc: "Designed as decoupled Rust crates for maximum performance, memory safety, and high throughput.",
    arch_sensor: "argos-sensor",
    arch_sensor_desc: "notify / fanotify / procmon file & process telemetry collector",
    arch_detect: "argos-detect",
    arch_detect_desc: "Shannon entropy & sliding window behavior scoring engine",
    arch_recovery: "argos-recovery",
    arch_recovery_desc: "SHA-256 CAS versioned backup & hash verification recovery",
    arch_response: "argos-response",
    arch_response_desc: "SIGKILL process enforcement & iptables network isolation",
    arch_brain: "argos-brain",
    arch_brain_desc: "Claude API powered AI threat summary & natural language query",
    arch_policy: "argos-policy",
    arch_policy_desc: "Ed25519 asymmetric key policy signing & verification",

    sec_faq_title: "Frequently Asked Questions",
    sec_faq_desc: "Key insights into deploying and operating Argos AI Security.",
    faq1_q: "Q1. How does Argos AI Security differ from traditional EDR or antivirus software?",
    faq1_a: "Argos does not rely solely on static signatures. It combines real-time behavior scoring with Shannon entropy calculation to detect zero-day ransomware. Furthermore, files damaged by an attack can be restored with 100% hash verification via SHA-256 Content-Addressable Storage.",
    faq2_q: "Q2. Is there a risk of critical business processes being blocked by false positives?",
    faq2_a: "Argos prioritizes operational stability. By default, auto_block=false (dry-run mode). Automated process blocking requires a behavior score ≥ 80 and a verified target PID. Critical system PIDs (such as PID 0) are strictly protected from signal enforcement.",
    faq3_q: "Q3. Does the AI threat analysis export sensitive file contents offsite?",
    faq3_a: "No. The argos-brain crate extracts only audit event metadata—such as event types, modification counts, and entropy scores from the SQLite database—and sends strictly non-sensitive telemetry to the Claude API.",
    faq4_q: "Q4. Can Argos be compiled and tested on Windows or macOS?",
    faq4_a: "Yes. The entire workspace compiles and runs on Windows and macOS using the cross-platform notify sensor. Linux-specific modules (fanotify, process signals, iptables) are safely gated under #[cfg(target_os = \"linux\")].",

    footer_tagline: "AI-Powered Real-Time Linux Server Ransomware Defense Platform",
    footer_quick_inquiry: "Inquiry:",
    footer_rights: "© 2026 Argos AI Security. All rights reserved. Licensed under AGPL-3.0."
  }
};

// CLI Command Output Simulator Database
const cliSimulations = {
  status: {
    cmd: "argos status",
    out: `[Argos Agent System Status]
Daemon State: RUNNING (PID 4192)
Storage: SQLite WAL (/var/lib/argos/argos.db - 4.2 MB)
Active Sensor: fanotify (Linux Root Telemetry)
Monitored Path: /srv/app/data, /etc/nginx, /var/www
Policy Verification: PASSED (Ed25519 Signed by SecOps Key #1)
Auto-Block: ENABLED (Score Threshold >= 80)
Active Threats: 0 Critical | 1 Resolved`
  },
  threats: {
    cmd: "argos threats",
    out: `[Recent Threat Audit Logs - Last 24 Hours]
ID: 104 | Score: <span class="cli-highlight-critical">92/100 (CRITICAL)</span> | Timestamp: 2026-08-01 09:05:12 UTC
Process: pid=8412 (/tmp/.malware_exec)
Event Summary: 142 file edits in 3.2s, High Entropy Write (7.84/8.0)
Action Taken: <span class="cli-highlight-success">SIGKILL ENFORCED</span> -> PID 8412 Terminated | Backup Snapshots Created: 142 files`
  },
  restore: {
    cmd: "argos restore /srv/app/data/customer_db.sqlite --list",
    out: `[SHA-256 CAS Backup History for customer_db.sqlite]
Version 3: 2026-08-01 09:05:11 UTC (Hash: a7f8c2... | Size: 1.2 MB) <span class="cli-highlight-success">[PRE-ATTACK SAFE POINT]</span>
Version 2: 2026-08-01 08:00:00 UTC (Hash: b3d9e1... | Size: 1.1 MB)
Version 1: 2026-08-01 00:00:00 UTC (Hash: e81c4a... | Size: 1.0 MB)

<span class="cli-cmd">$ argos restore /srv/app/data/customer_db.sqlite</span>
[Argos Recovery Engine]
Verifying target hash: a7f8c2e91b...
Restoring file to /srv/app/data/customer_db.sqlite...
<span class="cli-highlight-success">[SUCCESS] File restored cleanly. Hash verification 100% matched!</span>`
  },
  explain: {
    cmd: "argos explain 104",
    out: `[Argos AI Copilot - Powered by Claude Messages API]
Analyzing Threat Record #104 from SQLite Audit Logs...

<span class="cli-highlight-info">[AI Incident Narrative Summary]</span>
At 09:05:12 UTC, binary '/tmp/.malware_exec' (PID 8412) attempted rapid bulk encryption across '/srv/app/data'. 
- Shannon entropy spiked from 4.1 to 7.84 across 142 files.
- Argos Scorer calculated severity score 92 (Critical).
- Automated response triggered SIGKILL within 45ms, isolating PID 8412.
- Recommended Action: Run 'argos restore /srv/app/data/ --before-ms 1760000000000' to restore all 142 files to safe versions.`
  },
  policy: {
    cmd: "argos policy verify",
    out: `[Ed25519 Security Policy Verification]
Policy File: /etc/argos/policy.toml
Public Key:  ed25519_pk_8f7a9d2c41e0...
Signature:   ed25519_sig_3b811a95c...

Result: <span class="cli-highlight-success">[VALID] Policy signature matches public key. Policy active.</span>
Active Rules:
 - auto_block = true
 - entropy_threshold = 7.0
 - sliding_window_sec = 10`
  }
};

let currentLang = 'ko';

// Function to update UI texts based on current language
function setLanguage(lang) {
  currentLang = lang;
  document.documentElement.lang = lang;
  
  const elements = document.querySelectorAll('[data-i18n]');
  elements.forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (i18n[lang] && i18n[lang][key]) {
      el.innerHTML = i18n[lang][key];
    }
  });

  const langBtnText = document.getElementById('lang-text');
  if (langBtnText) {
    langBtnText.textContent = lang === 'ko' ? 'EN' : 'KO';
  }

  localStorage.setItem('argos_lang', lang);
}

// Function to simulate CLI command switching
function switchCliTab(tabKey) {
  const tabs = document.querySelectorAll('.cli-tab');
  tabs.forEach(t => t.classList.remove('active'));

  const activeTab = document.querySelector(`.cli-tab[data-cli="${tabKey}"]`);
  if (activeTab) activeTab.classList.add('active');

  const cliBody = document.getElementById('cli-output-container');
  if (cliBody && cliSimulations[tabKey]) {
    const data = cliSimulations[tabKey];
    cliBody.innerHTML = `
      <div><span class="cli-prompt">gaga@argos-linux:~$</span> <span class="cli-cmd">${data.cmd}</span></div>
      <div class="cli-output">${data.out}</div>
    `;
  }
}

// FAQ Accordion Setup
function initFaqAccordion() {
  const faqItems = document.querySelectorAll('.faq-item');
  faqItems.forEach(item => {
    const btn = item.querySelector('.faq-question');
    if (btn) {
      btn.addEventListener('click', () => {
        const isActive = item.classList.contains('active');
        faqItems.forEach(i => i.classList.remove('active'));
        if (!isActive) {
          item.classList.add('active');
        }
      });
    }
  });
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  const savedLang = localStorage.getItem('argos_lang') || 'ko';
  setLanguage(savedLang);

  const langBtn = document.getElementById('btn-lang-toggle');
  if (langBtn) {
    langBtn.addEventListener('click', () => {
      const nextLang = currentLang === 'ko' ? 'en' : 'ko';
      setLanguage(nextLang);
    });
  }

  const cliTabs = document.querySelectorAll('.cli-tab');
  cliTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const key = tab.getAttribute('data-cli');
      switchCliTab(key);
    });
  });

  initFaqAccordion();
});
