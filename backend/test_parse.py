from app.services.winlogbeat_parser import (
    build_abstracted_attack_chains,
    build_attack_chain_candidates,
    filter_events,
    parse_winlogbeat_file,
    save_json,
)

from app.services.rule_detector import (
    detect_malicious_chains,
    filter_suspicious_results,
)

INPUT_FILE = "samples/winlogbeat_sample.json"

OUTPUT_ALL = "data/parsed_logs.json"
OUTPUT_SYSMON = "data/sysmon_only.json"
OUTPUT_SYSMON_CORE = "data/sysmon_core.json"
OUTPUT_ATTACK_CHAINS = "data/attack_chains.json"
OUTPUT_ABSTRACTED_CHAINS = "data/abstracted_attack_chains.json"
OUTPUT_RULE_RESULTS = "data/rule_detection_results.json"
OUTPUT_SUSPICIOUS_ONLY = "data/suspicious_only.json"


def main():
    # 1. 전체 파싱
    parsed = parse_winlogbeat_file(INPUT_FILE)
    save_json(parsed, OUTPUT_ALL)

    # 2. Sysmon만 추출
    sysmon_logs = filter_events(
        parsed,
        channel="Microsoft-Windows-Sysmon/Operational"
    )
    save_json(sysmon_logs, OUTPUT_SYSMON)

    # 3. Sysmon 핵심 이벤트만 추출
    core_event_ids = {"1", "3", "11", "12", "13", "14"}
    sysmon_core = [
        e for e in sysmon_logs
        if str(e.get("event_id")) in core_event_ids
    ]
    save_json(sysmon_core, OUTPUT_SYSMON_CORE)

    # 4. 공격 체인 후보 생성
    attack_chains = build_attack_chain_candidates(sysmon_core)
    save_json(attack_chains, OUTPUT_ATTACK_CHAINS)

    # 5. 추상화된 공격 체인 생성
    abstracted_attack_chains = build_abstracted_attack_chains(attack_chains)
    save_json(abstracted_attack_chains, OUTPUT_ABSTRACTED_CHAINS)

    # 6. 규칙 기반 탐지
    rule_results = detect_malicious_chains(attack_chains)
    save_json(rule_results, OUTPUT_RULE_RESULTS)

    suspicious_only = filter_suspicious_results(rule_results)
    save_json(suspicious_only, OUTPUT_SUSPICIOUS_ONLY)

    print(f"규칙 기반 분석 결과 개수: {len(rule_results)}")
    print(f"의심 체인 개수: {len(suspicious_only)}")
    print(f"저장 완료: {OUTPUT_RULE_RESULTS}")
    print(f"저장 완료: {OUTPUT_SUSPICIOUS_ONLY}")

    if rule_results:
        sample = rule_results[0]
        print("\n규칙 기반 탐지 샘플")
        print(f"process_guid: {sample.get('process_guid')}")
        print(f"image: {sample.get('image')}")
        print(f"score: {sample.get('score')}")
        print(f"label: {sample.get('label')}")
        print(f"reasons: {sample.get('reasons')}")

    # 7. 발표용 출력
    print("===== 로그 분석 MVP 실행 결과 =====")
    print(f"전체 로그 개수: {len(parsed)}")
    print(f"Sysmon 로그 개수: {len(sysmon_logs)}")
    print(f"Sysmon 핵심 이벤트 개수: {len(sysmon_core)}")
    print(f"공격 체인 후보 개수: {len(attack_chains)}")
    print(f"추상화된 체인 개수: {len(abstracted_attack_chains)}")
    print()

    print("생성된 결과 파일:")
    print(f"- {OUTPUT_ALL}")
    print(f"- {OUTPUT_SYSMON}")
    print(f"- {OUTPUT_SYSMON_CORE}")
    print(f"- {OUTPUT_ATTACK_CHAINS}")
    print(f"- {OUTPUT_ABSTRACTED_CHAINS}")
    print()

    if abstracted_attack_chains:
        sample = abstracted_attack_chains[0]
        print("첫 번째 체인 샘플:")
        print(f"process_guid: {sample.get('process_guid')}")
        print(f"image: {sample.get('image')}")
        print(f"event_count: {sample.get('event_count')}")
        if sample.get("abstracted_actions"):
            print(f"first_action: {sample['abstracted_actions'][0]['summary']}")


if __name__ == "__main__":
    main()