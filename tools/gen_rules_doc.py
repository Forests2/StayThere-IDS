"""docs/DETECTION_RULES.md 다시 만들기 — 규칙을 바꾼 뒤 실행: python tools/gen_rules_doc.py"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from attack_taxonomy import BLOCK_RULES, INTRUSION_RULES, KILL_RULES, RULE_INFO, RULE_TAXONOMY  # noqa: E402

V1019 = {"artex_host_artifact", "artex_user_agent", "js_asset_burst", "ioc_domain_query", "agent_command_style",
         "retry_loop", "credential_dump", "privilege_escalation", "payload_staging", "distributed_ips",
         "dev_tool_inbound", "dev_tool_exposed", "local_agent_command", "baseline_anomaly"}
V11 = {"webshell_file_created", "object_enumeration", "log_theft", "llm_malware_pattern", "llm_then_exec",
       "autorun_change", "ransomware_prep", "mass_file_change", "git_spawned_unusual", "package_install_exec",
       "agent_secret_access"}


def main():
    c = json.load(open(os.path.join(BASE, "config.json"), encoding="utf-8"))
    out = ["# 탐지 규칙 목록", "",
           f"DDS 에 들어 있는 탐지 규칙 {len(RULE_INFO)}개입니다. (`attack_taxonomy.py` 의 `RULE_INFO`·`RULE_TAXONOMY` 에서 "
           "자동 생성 — `python tools/gen_rules_doc.py`)", "",
           "- **경보 화면**은 '외부 침입 흔적' 규칙(아래 ★)이 HIGH 로 걸릴 때만 뜹니다. PC 안에서 사용자가 쓰는 AI 프로그램 활동은 기록만 남깁니다.",
           "- **자동 대응**(켜져 있을 때): 🛡 = 출발지 IP 자동 차단, ⛔ = 해당 프로세스 자동 종료.",
           "- 🆕 = 2026-10-19 추가 (ARTEX 원본·한국어판 · AI 에이전트 행동 · 평소 패턴), "
           "🆕¹·¹ = v1.1 (2026-10-21, 금융권 공격 유형 · LLM 을 부르는 악성코드 · AI 코딩 도구 공격 · 랜섬웨어 · 공급망). "
           "근거: [CHANGELOG](../CHANGELOG.md) · [최신 위협 정보 정리](THREAT_NOTES_2026-10-19.md)",
           "- **공격 분류**는 [AIPFL-IDS](https://github.com/PrathamWankhade/AIPFL-IDS) 가 쓰는 데이터셋 라벨"
           "(NF-ToN-IoT-V2 / CICIoT2023)에 맞춰 붙였습니다. 데이터셋에 해당 개념이 없는 규칙은 `-` 로 표시합니다.", ""]
    groups = list(dict.fromkeys(g for g, _, _ in RULE_INFO.values()))
    for g in groups:
        out += [f"## {g}", "", "| 규칙 | 심각도 | 언제 걸리나 | 공격 분류 (NF-ToN-IoT-V2) | CICIoT2023 라벨 |", "|---|---|---|---|---|"]
        for r, (gg, sev, desc) in RULE_INFO.items():
            if gg != g:
                continue
            ko, nf, cic = RULE_TAXONOMY[r]
            mark = (" ★" if r in INTRUSION_RULES else "") + (" 🛡" if r in BLOCK_RULES else "") + \
                   (" ⛔" if r in KILL_RULES else "") + (" 🆕" if r in V1019 else "") + (" 🆕¹·¹" if r in V11 else "")
            out.append(f"| `{r}`{mark} | {sev} | {desc} | {f'{ko} · **{nf}**' if nf else ko} | {cic or '-'} |")
        out.append("")
    j = lambda k: ", ".join(map(str, c.get(k, [])))
    rows = [
        ("interval_sec", c["interval_sec"], "수집 주기(초)"),
        ("work_hours", f"{c['work_hours']['start']}–{c['work_hours']['end']}시", "이 시간 밖 로그인은 `off_hours_logon`"),
        ("scan_burst", f"{c['scan_burst']['window_sec']}초 · 포트 {c['scan_burst']['ports']}개", "`port_scan` 기준"),
        ("recon_burst", f"{c['recon_burst']['window_sec']}초 · 명령 {c['recon_burst']['count']}종", "`recon_burst` 기준"),
        ("shell_burst", f"{c['shell_burst']['window_sec']}초 · {c['shell_burst']['count']}회", "`shell_burst` 기준"),
        ("outbound_scan", f"{c['outbound_scan']['window_sec']}초 · IP {c['outbound_scan']['ips']}개", "`outbound_scan` 기준"),
        ("risky_inbound_ports", j("risky_inbound_ports"), "외부에서 들어오면 `risky_port_inbound`"),
        ("bad_outbound_ports", j("bad_outbound_ports"), "이 포트로 나가면 `odd_port_outbound`"),
        ("ioc_ips", f"{len(c['ioc_ips'])}개", "CrowdStrike ARTEX 보고서 공개 IP"),
        ("ioc_ports / ioc_domains", f"{c['ioc_ports']} / {c['ioc_domains']}", "같은 보고서"),
        ("artex_process_names", j("artex_process_names"), "🆕 ARTEX 원본·한국어판 실행 파일 이름 → `artex_host_artifact`"),
        ("artex_host_keywords", f"{len(c['artex_host_keywords'])}개 (artex_token, autumn27/artex, 콘솔 제목, cyberstrikeai 등)",
         "🆕 명령줄·경로에 있으면 `artex_host_artifact`"),
        ("artex_user_agents", " · ".join(c["artex_user_agents"]), "🆕 웹 로그에 있으면 `artex_user_agent`"),
        ("web_log_dirs", " · ".join(c["web_log_dirs"]), "🆕 있으면 읽는 웹 서버 로그 폴더 (IIS W3C · nginx/Apache combined)"),
        ("js_burst", f"{c['js_burst']['window_sec']}초 · JS {c['js_burst']['distinct_js']}개", "🆕 `js_asset_burst` 기준"),
        ("agent_burst", f"{c['agent_burst']['window_sec']}초 · {c['agent_burst']['count']}건 · 표시 {c['agent_burst']['min_markers']}개 이상",
         "🆕 `agent_command_style` 기준 (`agent_command_markers` 목록)"),
        ("retry_burst", f"{c['retry_burst']['window_sec']}초 · {c['retry_burst']['count']}번 · 유사도 {c['retry_burst']['similarity']}", "🆕 `retry_loop` 기준"),
        ("distributed_ips", f"{c['distributed_ips']['window_sec']}초 · IP {c['distributed_ips']['ips']}개", "🆕 `distributed_ips` 기준"),
        ("dev_tool_ports", ", ".join(f"{k}({v})" for k, v in c["dev_tool_ports"].items()), "🆕 `dev_tool_exposed` · `dev_tool_inbound`"),
        ("sysmon", str(c["sysmon"]["enabled"]).lower(), "Sysmon 이 있으면 이벤트 1·3·11·12·13·22 사용"),
        ("baseline", f"{c['baseline']['learn_days']}일 · 이벤트 {c['baseline']['min_events']:,}건 학습 뒤 · "
                     f"{c['baseline']['window_sec'] // 60}분 안에 {c['baseline']['burst']}가지", "🆕 `baseline_anomaly` 기준"),
        ("powershell_4104", str(c["powershell_4104"]["enabled"]).lower(), "🆕¹·¹ PowerShell 스크립트 블록 기록 읽기 (enable_cmdline_audit.bat 가 켬)"),
        ("web_root_dirs · web_root_markers · web_script_ext", f"{j('web_root_dirs')} · 확장자 {len(c['web_script_ext'])}종",
         "🆕¹·¹ `webshell_file_created` (Sysmon 없으면 웹 폴더를 30초마다 비교)"),
        ("enum_burst", f"{c['enum_burst']['window_sec']}초 · 값 {c['enum_burst']['distinct']}가지", "🆕¹·¹ `object_enumeration` 기준 (정적 파일 제외)"),
        ("log_markers · archive_markers", f"{len(c['log_markers'])} · {len(c['archive_markers'])}개", "🆕¹·¹ `log_theft` (웹 서버 아래에서만)"),
        ("script_hosts · office_processes", f"{j('script_hosts')} · Office {len(c['office_processes'])}종", "🆕¹·¹ `llm_malware_pattern`"),
        ("llm_exec_window_sec", c["llm_exec_window_sec"], "🆕¹·¹ `llm_then_exec` — LLM 접속 뒤 이 시간 안의 셸 실행"),
        ("autorun_markers · suspicious_autorun_values", f"{len(c['autorun_markers'])} · {len(c['suspicious_autorun_values'])}개",
         "🆕¹·¹ `autorun_change` (Sysmon 없으면 Run 키 · 시작프로그램 폴더를 30초마다 비교)"),
        ("ransomware_patterns", f"{len(c['ransomware_patterns'])}개 (vssadmin · wmic · wbadmin · bcdedit)", "🆕¹·¹ `ransomware_prep`"),
        ("mass_file · doc_ext", f"{c['mass_file']['window_sec']}초 · {c['mass_file']['files']}개 · 비율 {c['mass_file']['share']}",
         "🆕¹·¹ `mass_file_change` — 문서 확장자 뒤에 낯선 확장자가 붙은 파일만 셈"),
        ("package_install_markers · download_markers", f"{len(c['package_install_markers'])} · {len(c['download_markers'])}개", "🆕¹·¹ `package_install_exec`"),
        ("git_suspicious_children", j("git_suspicious_children"), "🆕¹·¹ `git_spawned_unusual`"),
        ("secret_markers · secret_readers_allow", f"{len(c['secret_markers'])} · {len(c['secret_readers_allow'])}개",
         "🆕¹·¹ `agent_secret_access` (4663 은 enable_secret_audit.ps1 로 켬)"),
        ("notify", "syslog · 웹훅 (기본 꺼짐)", "🆕¹·¹ 침입 알림을 PC 밖으로 전송 (Logpresso 등)"),
    ]
    out += ["## 기본 설정값 (config.json)", "", "| 항목 | 값 | 뜻 |", "|---|---|---|"]
    out += [f"| `{a}` | {b} | {d} |" for a, b, d in rows]
    out += ["", "> 기준값은 개발자가 정한 초기값입니다. 실제 PC 에서 며칠 돌려 보고 오탐에 맞춰 조정하세요."]
    with open(os.path.join(BASE, "docs", "DETECTION_RULES.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"docs/DETECTION_RULES.md — 규칙 {len(RULE_INFO)}개")


if __name__ == "__main__":
    main()
