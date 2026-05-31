import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clipboard,
  Download,
  FileJson,
  FileSearch,
  Loader2,
  Network,
  RefreshCw,
  ShieldAlert,
  Upload,
  X,
} from "lucide-react";
import {
  analyzeFile,
  checkHealth,
  getAnalysisResult,
  getSandboxStatus,
  runSandboxExecutable,
  uploadLogFile,
} from "./api.js";

const ACCEPTED_EXTENSIONS = [".json", ".jsonl", ".log", ".txt"];
const EXE_EXTENSION = ".exe";
const SANDBOX_TERMINAL_STATUSES = new Set(["terminated", "failed"]);

const STEP_LABELS = [
  { key: "upload", label: "파일 업로드" },
  { key: "analyze", label: "행위 분석" },
  { key: "report", label: "리포트 생성" },
];

const IOC_LABELS = {
  ips: "IP 주소",
  domains: "도메인",
  urls: "URL",
  hashes: "해시",
  file_paths: "파일 경로",
  registry_keys: "레지스트리 키",
  ransom_notes: "랜섬노트",
  encrypted_extensions: "암호화 확장자",
  suspicious_file_names: "의심 파일명",
  bitcoin_addresses: "비트코인 주소",
  email_addresses: "이메일 주소",
};

const MITRE_EVIDENCE_RULES = {
  "T1059.001": {
    keywords: ["powershell", "pwsh", "encodedcommand", "-enc ", "invoke-webrequest", "downloadstring", "iex "],
  },
  "T1059.003": {
    keywords: ["cmd.exe", "cmd /c", "cmd /k", "/c "],
  },
  T1105: {
    keywords: ["downloadfile", "downloadstring", "invoke-webrequest", "certutil", "bitsadmin", "curl ", "wget "],
  },
  T1112: {
    eventIds: ["12", "13", "14"],
    keywords: ["reg add", "reg delete", "regedit", "currentversion\\run", "currentversion\\runonce"],
  },
  T1218: {
    keywords: ["mshta", "rundll32", "regsvr32", "installutil", "msbuild", "wscript", "cscript"],
  },
  T1486: {
    keywords: [".locked", ".encrypted", ".crypted", ".crypt", ".enc", "how_to_decrypt", "recover_files"],
  },
  T1490: {
    keywords: ["vssadmin", "delete shadows", "shadowcopy", "wbadmin", "bcdedit", "wmic shadowcopy delete"],
  },
};

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function riskClass(riskLevel) {
  const value = String(riskLevel || "unknown").toLowerCase();
  if (value === "high") return "risk-high";
  if (value === "medium") return "risk-medium";
  if (value === "low") return "risk-low";
  return "risk-unknown";
}

function riskLabel(riskLevel) {
  const value = String(riskLevel || "unknown").toLowerCase();
  if (value === "high") return "높음";
  if (value === "medium") return "중간";
  if (value === "low") return "낮음";
  return "미확인";
}

function detectionLabel(label) {
  const value = String(label || "unknown").toLowerCase();
  if (value === "suspicious") return "의심";
  if (value === "benign") return "정상";
  return "미확인";
}

function confidenceLabel(confidence) {
  if (confidence === "high") return "높음";
  if (confidence === "medium") return "중간";
  if (confidence === "low") return "낮음";
  return "미확인";
}

function sandboxStatusLabel(status) {
  const labels = {
    queued: "대기 중",
    launching: "Windows EC2 생성 중",
    waiting_for_ssh: "SSH 연결 대기 중",
    transferring: "EXE 전송 중",
    running: "샘플 실행 중",
    terminating: "인스턴스 종료 중",
    analyzing_logs: "로그 분석 중",
    terminated: "실행 완료",
    failed: "실패",
  };
  return labels[status] || "상태 없음";
}

function sandboxStatusClass(status) {
  if (status === "failed") return "failed";
  if (status === "terminated") return "done";
  if (status) return "active";
  return "";
}

function pickResult(recordOrResponse) {
  return recordOrResponse?.result || recordOrResponse || null;
}

function countIocs(iocs = {}) {
  return Object.values(iocs).reduce(
    (total, values) => total + (Array.isArray(values) ? values.length : 0),
    0,
  );
}

function higherConfidence(left, right) {
  const order = { low: 0, medium: 1, high: 2 };
  const normalizedLeft = normalizeConfidence(left);
  const normalizedRight = normalizeConfidence(right);
  if (!normalizedLeft) return normalizedRight;
  if (!normalizedRight) return normalizedLeft;
  return order[normalizedLeft] >= order[normalizedRight] ? normalizedLeft : normalizedRight;
}

function normalizeConfidence(confidence) {
  return ["low", "medium", "high"].includes(confidence) ? confidence : null;
}

function inferTechniqueConfidence(technique) {
  const normalized = normalizeConfidence(technique.confidence);
  if (normalized) return normalized;
  if ((technique.evidence || []).length >= 2) return "medium";
  if ((technique.evidence || []).length === 1) return "low";
  return "low";
}

function uniqueMitreTechniques(result) {
  const techniqueMap = new Map();
  const sources = [
    ...(result?.llm_report?.mitre_attack || []),
    ...(result?.suspicious_results || []).flatMap((item) => item.mitre_attack || []),
    ...(result?.rule_results || []).flatMap((item) => item.mitre_attack || []),
  ];

  for (const technique of sources) {
    const key = `${technique.technique_id}:${technique.tactic}`;
    if (!techniqueMap.has(key)) {
      techniqueMap.set(key, {
        ...technique,
        evidence: technique.evidence || [],
        confidence: inferTechniqueConfidence(technique),
      });
      continue;
    }

    const existing = techniqueMap.get(key);
    existing.evidence = Array.from(new Set([
      ...(existing.evidence || []),
      ...(technique.evidence || []),
    ])).slice(0, 5);
    existing.confidence = higherConfidence(existing.confidence, inferTechniqueConfidence(technique));
  }

  for (const technique of techniqueMap.values()) {
    if ((technique.evidence || []).length) continue;

    const inferredEvidence = inferMitreEvidence(result, technique);
    technique.evidence = inferredEvidence;
    technique.confidence = higherConfidence(
      technique.confidence,
      inferredEvidence.length >= 2 ? "medium" : inferredEvidence.length === 1 ? "low" : null,
    );
  }

  return Array.from(techniqueMap.values());
}

function inferMitreEvidence(result, technique) {
  const rule = MITRE_EVIDENCE_RULES[technique.technique_id];
  if (!rule) return [];

  const chains = [
    ...(result?.rule_results || []),
    ...(result?.suspicious_results || []),
    ...(result?.attack_chains || []),
  ];
  const evidence = [];

  for (const chain of chains) {
    const actions = chain.actions?.length ? chain.actions : [chain];
    for (const action of actions) {
      const eventId = String(action.event_id || "");
      const combined = [
        action.image,
        action.command_line,
        action.parent_image,
        action.parent_command_line,
        action.target_filename,
        action.target_object,
        action.details,
        action.destination_ip,
        action.destination_hostname,
      ].filter(Boolean).join(" ").toLowerCase();

      const eventMatched = (rule.eventIds || []).includes(eventId);
      const keywordMatched = (rule.keywords || []).some((keyword) => combined.includes(keyword));

      if (!eventMatched && !keywordMatched) continue;

      const value = action.command_line || action.target_object || action.target_filename || action.details || action.image;
      if (value && !evidence.includes(value)) evidence.push(value);
      if (eventMatched && !evidence.includes(`Sysmon event ID ${eventId}`)) {
        evidence.push(`Sysmon event ID ${eventId}`);
      }
      if (evidence.length >= 5) return evidence.slice(0, 5);
    }
  }

  return evidence.slice(0, 5);
}

function buildNarrativeReport(result, mitreTechniques, iocs) {
  if (!result) return "아직 분석 결과가 없습니다.";

  const summary = result.summary || {};
  const risk = riskLabel(result.risk_level || summary.risk_level);
  const findings = result.key_findings || [];
  const topSuspicious = result.suspicious_results?.[0];
  const iocTotal = countIocs(iocs);
  const lines = [
    "랜섬웨어 행위 분석 보고서",
    "",
    `위험도: ${risk}`,
    `파싱 이벤트: ${summary.parsed_events ?? "-"}건`,
    `Sysmon 핵심 이벤트: ${summary.sysmon_core_events ?? "-"}건`,
    `공격 체인: ${summary.attack_chains ?? "-"}개`,
    `의심 체인: ${summary.suspicious_chains ?? "-"}개`,
    `IOC: ${iocTotal}개`,
    "",
    "주요 판단",
  ];

  if (findings.length) {
    findings.forEach((finding) => lines.push(`- ${translateFinding(finding)}`));
  } else {
    lines.push("- 주요 발견 사항이 없습니다.");
  }

  lines.push("", "가장 높은 의심 행위");
  if (topSuspicious) {
    lines.push(`- 프로세스: ${topSuspicious.image || "알 수 없음"}`);
    lines.push(`- 점수: ${topSuspicious.score ?? 0}`);
    lines.push(
      `- 근거: ${(topSuspicious.reasons || []).slice(0, 4).map(translateRuleReason).join("; ") || "근거 없음"}`,
    );
  } else {
    lines.push("- 의심으로 분류된 체인이 없습니다.");
  }

  lines.push("", "MITRE ATT&CK 관점");
  if (mitreTechniques.length) {
    mitreTechniques.slice(0, 8).forEach((technique) => {
      lines.push(
        `- ${technique.technique_id} ${technique.technique} (${technique.tactic}, 신뢰도 ${confidenceLabel(technique.confidence)})`,
      );
      if (technique.evidence?.length) {
        lines.push(`  근거: ${technique.evidence.slice(0, 2).join(" / ")}`);
      }
    });
  } else {
    lines.push("- 매핑된 ATT&CK 기법이 없습니다.");
  }

  lines.push("", "대응 권고");
  lines.push("- 의심 호스트를 네트워크에서 격리하고 추가 파일 변경 여부를 확인하세요.");
  lines.push("- IOC를 EDR/SIEM 차단 및 검색 조건에 반영하세요.");
  lines.push("- 백업과 섀도 복사본 삭제 흔적을 확인하고 복구 가능성을 점검하세요.");

  return lines.join("\n");
}

function translateFinding(finding) {
  const text = String(finding || "");
  const riskMatch = text.match(/^Overall risk level is (.+)\.$/);
  if (riskMatch) {
    return `전체 위험도는 ${riskLabel(riskMatch[1])}입니다.`;
  }

  const noSuspicious = "No suspicious attack chains exceeded the rule threshold.";
  if (text === noSuspicious) {
    return "룰 임계값을 넘은 의심 공격 체인은 없습니다.";
  }

  const iocMatch = text.match(/^Extracted (\d+) IOC values across (\d+) categories\.$/);
  if (iocMatch) {
    return `${iocMatch[2]}개 카테고리에서 IOC 값 ${iocMatch[1]}개를 추출했습니다.`;
  }

  const topMatch = text.match(/^Highest scoring suspicious chain: (.+) \(score (\d+)\)\.$/);
  if (topMatch) {
    return `가장 높은 점수의 의심 체인: ${topMatch[1]} (점수 ${topMatch[2]}).`;
  }

  return text;
}

function translateRuleReason(reason) {
  const text = String(reason || "");
  const translations = {
    "suspicious process used": "의심 프로세스가 실행됨",
    "suspicious command keyword found": "의심 명령어 키워드가 발견됨",
    "multiple file creation events": "파일 생성 이벤트가 다수 발생함",
    "multiple registry modification events": "레지스트리 변경 이벤트가 다수 발생함",
    "network connection observed": "네트워크 연결이 관찰됨",
    "multiple behavior categories observed": "여러 행위 유형이 함께 관찰됨",
    "high event count": "이벤트 수가 많음",
    "mass file creation activity observed": "대량 파일 생성 행위가 관찰됨",
    "encrypted-looking file extension observed": "암호화된 파일로 보이는 확장자가 관찰됨",
    "ransom note filename observed": "랜섬노트로 보이는 파일명이 관찰됨",
    "system recovery inhibition command observed": "시스템 복구 방해 명령이 관찰됨",
    "Run key persistence registry modification observed": "Run 키 지속성 레지스트리 변경이 관찰됨",
    "PowerShell download or obfuscation behavior observed": "PowerShell 다운로드 또는 난독화 행위가 관찰됨",
    "living-off-the-land binary execution observed": "LOLBins 실행이 관찰됨",
    "external network connection observed": "외부 네트워크 연결이 관찰됨",
    "high-confidence ransomware impact behavior combination observed": "랜섬웨어 영향 행위 조합이 높은 신뢰도로 관찰됨",
    "delivery and persistence behavior combination observed": "전달 및 지속성 행위 조합이 관찰됨",
  };

  return translations[text] || text;
}

function downloadText(filename, content, type = "text/plain") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function App() {
  const fileInputRef = useRef(null);
  const exeInputRef = useRef(null);
  const [health, setHealth] = useState(null);
  const [selectedExeFile, setSelectedExeFile] = useState(null);
  const [isExeDragging, setIsExeDragging] = useState(false);
  const [sandboxRuntimeSeconds, setSandboxRuntimeSeconds] = useState(300);
  const [sandboxSession, setSandboxSession] = useState(null);
  const [sandboxError, setSandboxError] = useState("");
  const [isSubmittingSandbox, setIsSubmittingSandbox] = useState(false);
  const [isRefreshingSandbox, setIsRefreshingSandbox] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [activeStep, setActiveStep] = useState(null);
  const [completedSteps, setCompletedSteps] = useState([]);
  const [error, setError] = useState("");
  const [analysisRecord, setAnalysisRecord] = useState(null);
  const [uploadMeta, setUploadMeta] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");

  const result = pickResult(analysisRecord);
  const summary = result?.summary || {};
  const iocs = result?.iocs || {};
  const mitreTechniques = useMemo(() => uniqueMitreTechniques(result), [result]);
  const riskLevel = result?.risk_level || summary.risk_level || "unknown";
  const analysisId = uploadMeta?.analysis_id || analysisRecord?.analysis_id || "analysis";
  const llmReportJson = useMemo(
    () => JSON.stringify(result?.llm_report || {}, null, 2),
    [result],
  );
  const fullResultJson = useMemo(
    () => JSON.stringify(result || {}, null, 2),
    [result],
  );
  const narrativeReport = useMemo(
    () => buildNarrativeReport(result, mitreTechniques, iocs),
    [result, mitreTechniques, iocs],
  );

  useEffect(() => {
    checkHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: "offline", service: "백엔드 연결 불가" }));
  }, []);

  useEffect(() => {
    if (!sandboxSession?.session_id || SANDBOX_TERMINAL_STATUSES.has(sandboxSession.status)) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      refreshSandboxStatus(sandboxSession.session_id);
    }, 5000);

    return () => window.clearTimeout(timer);
  }, [sandboxSession?.session_id, sandboxSession?.status]);

  function handleExeFile(file) {
    const isAccepted = file.name.toLowerCase().endsWith(EXE_EXTENSION);

    if (!isAccepted) {
      setSandboxError("EXE 파일만 업로드할 수 있습니다.");
      return;
    }

    setSandboxError("");
    setSelectedExeFile(file);
    setSandboxSession(null);
  }

  function removeSelectedExeFile() {
    setSelectedExeFile(null);
    setSandboxSession(null);
    setSandboxError("");
    if (exeInputRef.current) exeInputRef.current.value = "";
  }

  async function refreshSandboxStatus(sessionId = sandboxSession?.session_id) {
    if (!sessionId) return;

    setIsRefreshingSandbox(true);
    try {
      const nextSession = await getSandboxStatus(sessionId);
      applySandboxSession(nextSession);
      setSandboxError("");
    } catch (statusError) {
      setSandboxError(statusError.message || "샌드박스 상태 조회 중 오류가 발생했습니다.");
    } finally {
      setIsRefreshingSandbox(false);
    }
  }

  async function runSandbox() {
    if (!selectedExeFile) return;

    setSandboxError("");
    setIsSubmittingSandbox(true);
    setSandboxSession(null);
    resetResult();

    try {
      const session = await runSandboxExecutable(selectedExeFile, sandboxRuntimeSeconds);
      applySandboxSession(session);
    } catch (runError) {
      setSandboxError(runError.message || "샌드박스 실행 요청 중 오류가 발생했습니다.");
    } finally {
      setIsSubmittingSandbox(false);
    }
  }

  function applySandboxSession(nextSession) {
    setSandboxSession(nextSession);

    if (!nextSession?.analysis_result) return;

    setUploadMeta({
      analysis_id: nextSession.analysis_id,
      filename: nextSession.ingested_stream_id
        ? `${nextSession.ingested_stream_id}.jsonl`
        : nextSession.filename,
      saved_path: nextSession.ingested_log_path || "",
      sha256: nextSession.sha256,
      status: "completed",
    });
    setAnalysisRecord({
      analysis_id: nextSession.analysis_id,
      status: "completed",
      result: nextSession.analysis_result,
    });
    setCompletedSteps(["upload", "analyze", "report"]);
    setActiveStep(null);
    setActiveTab("overview");
  }

  function resetResult() {
    setAnalysisRecord(null);
    setUploadMeta(null);
    setActiveStep(null);
    setCompletedSteps([]);
    setActiveTab("overview");
  }

  function handleFile(file) {
    const lowerName = file.name.toLowerCase();
    const isAccepted = ACCEPTED_EXTENSIONS.some((extension) => lowerName.endsWith(extension));

    if (!isAccepted) {
      setError("JSON, JSONL, LOG, TXT 파일만 업로드할 수 있습니다.");
      return;
    }

    setError("");
    setSelectedFile(file);
    resetResult();
  }

  function removeSelectedFile() {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
    resetResult();
  }

  async function runAnalysis() {
    if (!selectedFile) return;

    setError("");
    resetResult();
    setActiveStep("upload");

    try {
      const uploadResponse = await uploadLogFile(selectedFile);
      setUploadMeta(uploadResponse);
      setCompletedSteps(["upload"]);
      setActiveStep("analyze");

      const analyzeResponse = await analyzeFile(uploadResponse.analysis_id);
      setCompletedSteps(["upload", "analyze"]);
      setActiveStep("report");

      const finalRecord = analyzeResponse.result
        ? analyzeResponse
        : await getAnalysisResult(uploadResponse.analysis_id);

      setAnalysisRecord(finalRecord);
      setCompletedSteps(["upload", "analyze", "report"]);
      setActiveStep(null);
    } catch (analysisError) {
      setError(analysisError.message || "분석 중 오류가 발생했습니다.");
      setActiveStep(null);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert size={28} aria-hidden="true" />
          <div>
            <strong>Hansung NetGuardian</strong>
            <span>랜섬웨어 분석 콘솔</span>
          </div>
        </div>

        <nav className="nav-list" aria-label="주요 메뉴">
          <a href="#sandbox">EXE 실행</a>
          <a href="#upload">로그 업로드</a>
          <a href="#analysis">분석 결과</a>
          <a href="#llm">LLM 전달 JSON</a>
        </nav>

        <div className={`health-pill ${health?.status === "ok" ? "online" : "offline"}`}>
          <Activity size={15} aria-hidden="true" />
          <span>{health?.status === "ok" ? "백엔드 연결됨" : "백엔드 연결 안 됨"}</span>
        </div>
      </aside>

      <main className="workspace">
        <section className="page-heading">
          <div>
            <p className="eyebrow">Sysmon / Winlogbeat JSON 분석 파이프라인</p>
            <h1>랜섬웨어 행위 분석 리포트</h1>
          </div>
          <div className="button-row">
            <button className="ghost-button" type="button" onClick={() => checkHealth().then(setHealth)}>
              <RefreshCw size={16} aria-hidden="true" />
              연결 확인
            </button>
            <button
              className="ghost-button"
              type="button"
              disabled={!result}
              onClick={() => downloadText(`${analysisId}_analysis_result.json`, fullResultJson, "application/json")}
            >
              <Download size={16} aria-hidden="true" />
              결과 JSON
            </button>
          </div>
        </section>

        <section className="sandbox-section" id="sandbox">
          <div className="panel sandbox-panel">
            <div className="panel-title split-title">
              <div>
                <h2>EXE 샌드박스 실행</h2>
                <span>실행 파일을 Windows EC2에 전송하고 일정 시간 실행한 뒤 Sysmon 로그를 수집합니다.</span>
              </div>
              <div className="runtime-control">
                <label htmlFor="sandbox-runtime">실행 시간</label>
                <input
                  id="sandbox-runtime"
                  type="number"
                  min="30"
                  step="30"
                  value={sandboxRuntimeSeconds}
                  onChange={(event) => setSandboxRuntimeSeconds(Number(event.target.value) || 300)}
                />
                <span>초</span>
              </div>
            </div>

            <div className="sandbox-grid">
              <div>
                <button
                  className={`drop-zone exe-drop-zone ${isExeDragging ? "dragging" : ""}`}
                  type="button"
                  onClick={() => exeInputRef.current?.click()}
                  onDragOver={(event) => {
                    event.preventDefault();
                    setIsExeDragging(true);
                  }}
                  onDragLeave={() => setIsExeDragging(false)}
                  onDrop={(event) => {
                    event.preventDefault();
                    setIsExeDragging(false);
                    const file = event.dataTransfer.files?.[0];
                    if (file) handleExeFile(file);
                  }}
                >
                  <ShieldAlert size={42} aria-hidden="true" />
                  <strong>분석할 EXE 파일을 올려주세요</strong>
                  <span>업로드 후 Windows 샌드박스 인스턴스에서 실행됩니다</span>
                </button>

                <input
                  ref={exeInputRef}
                  className="hidden-input"
                  type="file"
                  accept={EXE_EXTENSION}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) handleExeFile(file);
                  }}
                />

                {selectedExeFile && (
                  <div className="selected-file">
                    <FileSearch size={22} aria-hidden="true" />
                    <div>
                      <strong>{selectedExeFile.name}</strong>
                      <span>{formatBytes(selectedExeFile.size)}</span>
                    </div>
                    <button className="icon-button" type="button" onClick={removeSelectedExeFile} title="파일 제거">
                      <X size={17} aria-hidden="true" />
                    </button>
                  </div>
                )}

                {sandboxError && (
                  <div className="error-banner">
                    <AlertTriangle size={17} aria-hidden="true" />
                    <div>
                      <strong>샌드박스 요청 실패</strong>
                      <span>{sandboxError}</span>
                    </div>
                  </div>
                )}

                <button
                  className="primary-button"
                  type="button"
                  disabled={!selectedExeFile || isSubmittingSandbox}
                  onClick={runSandbox}
                >
                  {isSubmittingSandbox ? (
                    <Loader2 className="spin" size={18} aria-hidden="true" />
                  ) : (
                    <Upload size={18} aria-hidden="true" />
                  )}
                  샌드박스 실행
                </button>
              </div>

              <div className={`sandbox-status-card ${sandboxStatusClass(sandboxSession?.status)}`}>
                <div className="sandbox-status-header">
                  <div>
                    <span>현재 상태</span>
                    <strong>{sandboxStatusLabel(sandboxSession?.status)}</strong>
                  </div>
                  <button
                    className="ghost-button"
                    type="button"
                    disabled={!sandboxSession?.session_id || isRefreshingSandbox}
                    onClick={() => refreshSandboxStatus()}
                  >
                    {isRefreshingSandbox ? (
                      <Loader2 className="spin" size={16} aria-hidden="true" />
                    ) : (
                      <RefreshCw size={16} aria-hidden="true" />
                    )}
                    새로고침
                  </button>
                </div>

                {sandboxSession ? (
                  <dl className="meta-list">
                    <div>
                      <dt>세션 ID</dt>
                      <dd>{sandboxSession.session_id}</dd>
                    </div>
                    <div>
                      <dt>인스턴스 ID</dt>
                      <dd>{sandboxSession.instance_id || "-"}</dd>
                    </div>
                    <div>
                      <dt>원격 실행 경로</dt>
                      <dd>{sandboxSession.remote_path || "-"}</dd>
                    </div>
                    <div>
                      <dt>로그 분석 상태</dt>
                      <dd>{sandboxSession.analysis_status || "-"}</dd>
                    </div>
                    <div>
                      <dt>로그 분석 ID</dt>
                      <dd>{sandboxSession.analysis_id || "-"}</dd>
                    </div>
                    <div>
                      <dt>수집 로그</dt>
                      <dd>{sandboxSession.ingested_log_path || "-"}</dd>
                    </div>
                    <div>
                      <dt>수집 이벤트</dt>
                      <dd>{sandboxSession.ingested_event_count ?? "-"}</dd>
                    </div>
                    <div>
                      <dt>SHA-256</dt>
                      <dd>{sandboxSession.sha256}</dd>
                    </div>
                    {sandboxSession.analysis_result && (
                      <div>
                        <dt>결과 표시</dt>
                        <dd>아래 분석 대시보드에 자동 반영됨</dd>
                      </div>
                    )}
                    {sandboxSession.analysis_error && (
                      <div>
                        <dt>분석 오류</dt>
                        <dd>{sandboxSession.analysis_error}</dd>
                      </div>
                    )}
                    {sandboxSession.error && (
                      <div>
                        <dt>오류</dt>
                        <dd>{sandboxSession.error}</dd>
                      </div>
                    )}
                  </dl>
                ) : (
                  <p className="sandbox-empty">아직 실행된 샌드박스 세션이 없습니다.</p>
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="layout-grid" id="upload">
          <div className="panel upload-panel">
            <div className="panel-title">
              <Upload size={18} aria-hidden="true" />
              <h2>로그 파일 업로드</h2>
            </div>

            <button
              className={`drop-zone ${isDragging ? "dragging" : ""}`}
              type="button"
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(event) => {
                event.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(event) => {
                event.preventDefault();
                setIsDragging(false);
                const file = event.dataTransfer.files?.[0];
                if (file) handleFile(file);
              }}
            >
              <FileJson size={42} aria-hidden="true" />
              <strong>Winlogbeat JSON 파일을 끌어오거나 클릭하세요</strong>
              <span>.json, .jsonl, .log, .txt 파일을 지원합니다</span>
            </button>

            <input
              ref={fileInputRef}
              className="hidden-input"
              type="file"
              accept={ACCEPTED_EXTENSIONS.join(",")}
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) handleFile(file);
              }}
            />

            {selectedFile && (
              <div className="selected-file">
                <FileSearch size={22} aria-hidden="true" />
                <div>
                  <strong>{selectedFile.name}</strong>
                  <span>{formatBytes(selectedFile.size)}</span>
                </div>
                <button className="icon-button" type="button" onClick={removeSelectedFile} title="파일 제거">
                  <X size={17} aria-hidden="true" />
                </button>
              </div>
            )}

            {error && (
              <div className="error-banner">
                <AlertTriangle size={17} aria-hidden="true" />
                <div>
                  <strong>분석 요청 실패</strong>
                  <span>{error}</span>
                </div>
              </div>
            )}

            <button className="primary-button" type="button" disabled={!selectedFile || !!activeStep} onClick={runAnalysis}>
              {activeStep ? <Loader2 className="spin" size={18} aria-hidden="true" /> : <Upload size={18} aria-hidden="true" />}
              분석 시작
            </button>
          </div>

          <div className="panel progress-panel">
            <div className="panel-title">
              <Network size={18} aria-hidden="true" />
              <h2>분석 진행 상태</h2>
            </div>

            <div className="stepper">
              {STEP_LABELS.map((step, index) => {
                const isDone = completedSteps.includes(step.key);
                const isActive = activeStep === step.key;
                return (
                  <div className={`step ${isDone ? "done" : ""} ${isActive ? "active" : ""}`} key={step.key}>
                    <div className="step-marker">
                      {isDone ? <CheckCircle2 size={17} aria-hidden="true" /> : index + 1}
                    </div>
                    <div>
                      <strong>{step.label}</strong>
                      <span>{stepDescription(step.key, isDone, isActive)}</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {uploadMeta && (
              <dl className="meta-list">
                <div>
                  <dt>분석 ID</dt>
                  <dd>{uploadMeta.analysis_id}</dd>
                </div>
                <div>
                  <dt>SHA-256</dt>
                  <dd>{uploadMeta.sha256}</dd>
                </div>
              </dl>
            )}
          </div>
        </section>

        <section className="results-section" id="analysis">
          <div className="summary-band">
            <Metric label="위험도" value={riskLabel(riskLevel)} className={riskClass(riskLevel)} />
            <Metric label="파싱 이벤트" value={summary.parsed_events ?? "-"} />
            <Metric label="의심 체인" value={summary.suspicious_chains ?? "-"} />
            <Metric label="IOC 값" value={countIocs(iocs)} />
            <Metric label="MITRE 기법" value={mitreTechniques.length} />
          </div>

          <div className="tabs" role="tablist" aria-label="분석 결과 섹션">
            {[
              ["overview", "요약"],
              ["report", "자연어 보고서"],
              ["iocs", "IOCs"],
              ["mitre", "MITRE"],
              ["chains", "공격 체인"],
              ["rules", "탐지 룰"],
            ].map(([key, label]) => (
              <button
                className={activeTab === key ? "active" : ""}
                type="button"
                role="tab"
                aria-selected={activeTab === key}
                key={key}
                onClick={() => setActiveTab(key)}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="tab-surface">
            {!result && <EmptyState />}
            {result && activeTab === "overview" && <OverviewTab result={result} />}
            {result && activeTab === "report" && (
              <ReportTab
                report={narrativeReport}
                onCopy={() => navigator.clipboard.writeText(narrativeReport)}
                onDownload={() => downloadText(`${analysisId}_narrative_report.txt`, narrativeReport)}
              />
            )}
            {result && activeTab === "iocs" && <IocTab iocs={iocs} />}
            {result && activeTab === "mitre" && <MitreTab techniques={mitreTechniques} />}
            {result && activeTab === "chains" && (
              <ChainsTab
                chains={result.attack_chains || []}
                abstractedChains={result.abstracted_attack_chains || []}
              />
            )}
            {result && activeTab === "rules" && <RulesTab rules={result.rule_results || []} />}
          </div>
        </section>

        <section className="panel llm-panel" id="llm">
          <div className="panel-title split-title">
            <div>
              <h2>LLM 전달용 리포트 JSON</h2>
              <span>백엔드가 AI 리포트 생성 단계로 넘기기 위해 정리한 구조화 JSON입니다.</span>
            </div>
            <div className="button-row">
              <button
                className="ghost-button"
                type="button"
                onClick={() => navigator.clipboard.writeText(llmReportJson)}
                disabled={!result}
              >
                <Clipboard size={16} aria-hidden="true" />
                복사
              </button>
              <button
                className="ghost-button"
                type="button"
                onClick={() => downloadText(`${analysisId}_llm_report.json`, llmReportJson, "application/json")}
                disabled={!result}
              >
                <Download size={16} aria-hidden="true" />
                JSON 저장
              </button>
            </div>
          </div>
          <pre className="json-view">{result ? llmReportJson : "아직 분석 결과가 없습니다."}</pre>
        </section>
      </main>
    </div>
  );
}

function stepDescription(key, isDone, isActive) {
  if (isDone) return "완료됨";
  if (isActive && key === "upload") return "로그 파일을 백엔드로 전송하는 중";
  if (isActive && key === "analyze") return "파싱, 체인 구성, 탐지, MITRE 매핑 중";
  if (isActive && key === "report") return "리포트 JSON을 정리하는 중";
  if (key === "upload") return "파일 선택 대기 중";
  if (key === "analyze") return "업로드 후 실행";
  return "분석 완료 후 생성";
}

function Metric({ label, value, className = "" }) {
  return (
    <div className={`metric ${className}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      <FileSearch size={34} aria-hidden="true" />
      <strong>불러온 분석 결과가 없습니다</strong>
      <span>Winlogbeat JSON 또는 JSONL 파일을 업로드하면 결과 대시보드가 채워집니다.</span>
    </div>
  );
}

function OverviewTab({ result }) {
  return (
    <div className="content-grid">
      <section>
        <h3>주요 발견 사항</h3>
        <ul className="finding-list">
          {(result.key_findings || []).map((finding) => (
            <li key={finding}>{translateFinding(finding)}</li>
          ))}
        </ul>
      </section>
      <section>
        <h3>이벤트 분포</h3>
        <DataRows rows={Object.entries(result.summary?.events_by_type?.by_event_id || {})} />
      </section>
    </div>
  );
}

function ReportTab({ report, onCopy, onDownload }) {
  return (
    <section className="report-panel">
      <div className="panel-title split-title">
        <div>
          <h2>자연어 분석 보고서</h2>
          <span>현재 분석 JSON을 기반으로 생성한 요약 보고서입니다.</span>
        </div>
        <div className="button-row">
          <button className="ghost-button" type="button" onClick={onCopy}>
            <Clipboard size={16} aria-hidden="true" />
            복사
          </button>
          <button className="ghost-button" type="button" onClick={onDownload}>
            <Download size={16} aria-hidden="true" />
            TXT 저장
          </button>
        </div>
      </div>
      <pre className="report-text">{report}</pre>
    </section>
  );
}

function IocTab({ iocs }) {
  return (
    <div className="ioc-grid">
      {Object.entries(iocs).map(([key, values]) => (
        <section className="ioc-group" key={key}>
          <div className="ioc-header">
            <h3>{IOC_LABELS[key] || key}</h3>
            <button
              className="mini-button"
              type="button"
              disabled={!values.length}
              onClick={() => navigator.clipboard.writeText(values.join("\n"))}
            >
              <Clipboard size={13} aria-hidden="true" />
              복사
            </button>
          </div>
          {values.length ? (
            <ul>
              {values.map((value) => (
                <li key={value}>{value}</li>
              ))}
            </ul>
          ) : (
            <span className="muted">추출된 값 없음</span>
          )}
        </section>
      ))}
    </div>
  );
}

function MitreTab({ techniques }) {
  if (!techniques.length) return <EmptyInline message="매핑된 MITRE ATT&CK 기법이 없습니다." />;

  return (
    <div className="mitre-list">
      {techniques.map((technique) => (
        <article className="mitre-card" key={`${technique.technique_id}-${technique.tactic}`}>
          <div className="mitre-card-head">
            <div>
              <strong>{technique.technique_id} · {technique.technique}</strong>
              <span>{technique.tactic}</span>
            </div>
            <span className={`confidence-chip confidence-${technique.confidence || "unknown"}`}>
              {confidenceLabel(technique.confidence)}
            </span>
          </div>
          <ul className="evidence-list">
            {(technique.evidence || []).length ? (
              technique.evidence.map((item) => <li key={item}>{item}</li>)
            ) : (
              <li>근거 없음</li>
            )}
          </ul>
        </article>
      ))}
    </div>
  );
}

function ChainsTab({ chains, abstractedChains }) {
  if (!chains.length && !abstractedChains.length) {
    return <EmptyInline message="구성된 공격 체인이 없습니다." />;
  }

  const chainList = chains.length ? chains : abstractedChains;

  return (
    <div className="timeline">
      {chainList.slice(0, 10).map((chain, index) => (
        <article className="timeline-item" key={`${chain.process_guid || chain.image}-${index}`}>
          <div className="timeline-dot">{index + 1}</div>
          <div className="timeline-content">
            <div className="timeline-title">
              <strong>{chain.image || "알 수 없는 프로세스"}</strong>
              <span>{chain.start_time || "시간 정보 없음"} · 이벤트 {chain.event_count ?? chain.abstracted_actions?.length ?? 0}개</span>
            </div>
            <CommandBlock command={chain.command_line || "수집된 명령줄 없음"} />
            {chain.actions?.length > 0 && (
              <ul className="timeline-actions">
                {chain.actions.slice(0, 5).map((action, actionIndex) => (
                  <li key={`${action.timestamp || actionIndex}-${action.event_id}`}>
                    <span>{action.timestamp || "-"}</span>
                    <strong>{action.event_type || `Event ${action.event_id || "-"}`}</strong>
                    <em>{action.target_filename || action.target_object || action.destination_ip || ""}</em>
                  </li>
                ))}
              </ul>
            )}
            {chain.abstracted_actions?.length > 0 && (
              <ul className="timeline-actions">
                {chain.abstracted_actions.slice(0, 5).map((action, actionIndex) => (
                  <li key={`${action.timestamp || actionIndex}-${action.summary}`}>
                    <span>{action.timestamp || "-"}</span>
                    <strong>{action.summary}</strong>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

function RulesTab({ rules }) {
  if (!rules.length) return <EmptyInline message="룰 기반 탐지 결과가 없습니다." />;

  return (
    <div className="chain-list">
      {rules.slice(0, 10).map((rule, index) => (
        <article className="chain-item" key={`${rule.process_guid || rule.image}-${index}`}>
          <div>
            <strong>{rule.image || "알 수 없는 프로세스"}</strong>
            <span>{detectionLabel(rule.label)} · 점수 {rule.score ?? 0}</span>
          </div>
          <CommandBlock command={rule.command_line || "수집된 명령줄 없음"} />
          <ul className="reason-list">
            {(rule.reasons || []).slice(0, 6).map((reason) => (
              <li key={reason}>{translateRuleReason(reason)}</li>
            ))}
          </ul>
        </article>
      ))}
    </div>
  );
}

function CommandBlock({ command }) {
  const [expanded, setExpanded] = useState(false);
  const isLong = command.length > 140;
  const displayed = !isLong || expanded ? command : `${command.slice(0, 140)}...`;

  return (
    <div className="command-block">
      <code>{displayed}</code>
      {isLong && (
        <button className="mini-button" type="button" onClick={() => setExpanded((value) => !value)}>
          {expanded ? <ChevronDown size={13} aria-hidden="true" /> : <ChevronRight size={13} aria-hidden="true" />}
          {expanded ? "접기" : "펼치기"}
        </button>
      )}
    </div>
  );
}

function DataRows({ rows }) {
  if (!rows.length) return <EmptyInline message="이벤트 요약 정보가 없습니다." />;

  return (
    <dl className="data-rows">
      {rows.map(([key, value]) => (
        <div key={key}>
          <dt>이벤트 {key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function EmptyInline({ message }) {
  return <div className="empty-inline">{message}</div>;
}

export default App;
