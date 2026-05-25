from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.attack_chain_builder import (  # noqa: E402
    build_attack_chain_candidates,
    filter_core_sysmon_events,
)
from app.services.feature_extractor import ML_FEATURE_COLUMNS, extract_chain_features  # noqa: E402
from app.services.normalizer import filter_events  # noqa: E402
from app.services.rule_detector import detect_malicious_chains  # noqa: E402
from app.services.winlogbeat_parser import parse_winlogbeat_file  # noqa: E402


ML_ROOT = Path(__file__).resolve().parents[1]
RAW_DATA_DIR = ML_ROOT / "data" / "raw"
RAW_DATA_PATH = RAW_DATA_DIR / "sample_logs.json"
PROCESSED_DIR = ML_ROOT / "data" / "processed"
MODELS_DIR = ML_ROOT / "models"
FEATURES_PATH = PROCESSED_DIR / "features.csv"
TRAIN_PATH = PROCESSED_DIR / "train.csv"
TEST_PATH = PROCESSED_DIR / "test.csv"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.pkl"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.json"

DEFAULT_LOG_PATHS = [
    RAW_DATA_PATH,
    PROJECT_ROOT / "collector" / "sample_inputs" / "winlogbeat_sample.json",
]
LABEL_BY_DIRECTORY = {
    "benign": "benign",
    "ransomware": "suspicious",
    "malware": "suspicious",
}


def preprocess_dataset(
    log_paths: list[str | Path] | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
    include_seed_rows: bool = True,
    csv_path: str | Path | None = None,
    label_column: str | None = None,
) -> dict[str, str | int | list[str]]:
    """Build a dynamic-analysis training set from Winlogbeat/Sysmon logs.

    csv_path and label_column are accepted for backward CLI compatibility, but
    this pipeline intentionally trains on behavior-chain features instead of PE
    static-analysis columns.
    """
    del label_column
    source_paths = resolve_log_paths(log_paths, csv_path)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    for path in source_paths:
        rows.extend(extract_labeled_chain_rows(path))

    if include_seed_rows:
        rows.extend(build_seed_rows())

    if not rows:
        raise ValueError("No attack-chain feature rows were extracted from log inputs.")

    features = pd.DataFrame(rows)
    features = features.reindex(columns=[*ML_FEATURE_COLUMNS, "label"], fill_value=0)
    features[ML_FEATURE_COLUMNS] = features[ML_FEATURE_COLUMNS].apply(pd.to_numeric).fillna(0)

    label_encoder = LabelEncoder()
    features["label"] = label_encoder.fit_transform(features["label"].astype(str))
    features.to_csv(FEATURES_PATH, index=False)

    stratify = features["label"] if features["label"].nunique() > 1 else None
    train, test = train_test_split(
        features,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    train.to_csv(TRAIN_PATH, index=False)
    test.to_csv(TEST_PATH, index=False)

    with open(LABEL_ENCODER_PATH, "wb") as f:
        pickle.dump(label_encoder, f)

    with open(FEATURE_COLUMNS_PATH, "w", encoding="utf-8") as f:
        json.dump(ML_FEATURE_COLUMNS, f, ensure_ascii=False, indent=2)

    return {
        "source_logs": [str(path) for path in source_paths],
        "rows": int(len(features)),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "feature_count": len(ML_FEATURE_COLUMNS),
        "feature_columns": ML_FEATURE_COLUMNS,
        "features_path": str(FEATURES_PATH),
        "train_path": str(TRAIN_PATH),
        "test_path": str(TEST_PATH),
        "label_encoder_path": str(LABEL_ENCODER_PATH),
        "feature_columns_path": str(FEATURE_COLUMNS_PATH),
    }


def resolve_log_paths(
    log_paths: list[str | Path] | None,
    csv_path: str | Path | None = None,
) -> list[Path]:
    candidates = [Path(path) for path in log_paths] if log_paths else []

    if csv_path:
        candidates.append(Path(csv_path))

    if not candidates:
        candidates = [path for path in DEFAULT_LOG_PATHS if path.exists()]
        candidates.extend(sorted((PROJECT_ROOT / "samples" / "benign").glob("*.json*")))
        candidates.extend(sorted((PROJECT_ROOT / "samples" / "ransomware").glob("*.json*")))

    existing = []
    for path in candidates:
        resolved = path if path.is_absolute() else PROJECT_ROOT / path
        if resolved.exists() and resolved.is_file():
            existing.append(resolved)

    if not existing:
        raise FileNotFoundError("No Winlogbeat log files were found for preprocessing.")

    return existing


def extract_labeled_chain_rows(log_path: str | Path) -> list[dict[str, Any]]:
    log_path = Path(log_path)
    parsed_events = parse_winlogbeat_file(str(log_path))
    sysmon_events = filter_events(
        parsed_events,
        channel="Microsoft-Windows-Sysmon/Operational",
    )
    attack_chains = build_attack_chain_candidates(filter_core_sysmon_events(sysmon_events))
    rule_results = detect_malicious_chains(attack_chains)
    rule_labels = {
        result.get("process_guid") or result.get("command_line") or result.get("image"): result.get("label", "benign")
        for result in rule_results
    }
    forced_label = infer_label_from_path(log_path)
    rows = []

    for chain in attack_chains:
        features = extract_chain_features(chain)
        rule_key = chain.get("process_guid") or chain.get("command_line") or chain.get("image")
        rule_label = rule_labels.get(rule_key, "benign")
        label = forced_label or ("suspicious" if rule_label == "suspicious" else "benign")
        rows.append({**features, "label": label})

    return rows


def infer_label_from_path(path: Path) -> str | None:
    parts = {part.lower() for part in path.parts}
    for directory_name, label in LABEL_BY_DIRECTORY.items():
        if directory_name in parts:
            return label
    return None


def build_seed_rows() -> list[dict[str, Any]]:
    rows = []

    for file_count in range(0, 3):
        for registry_count in range(0, 2):
            for network_count in range(0, 2):
                event_count = 1 + file_count + registry_count + network_count
                rows.append(
                    make_row(
                        event_count,
                        1,
                        file_count,
                        registry_count,
                        network_count,
                        0,
                        0,
                        int(sum([file_count > 0, registry_count > 0, network_count > 0]) >= 1),
                        "benign",
                    )
                )

    for file_count in range(3, 8):
        for registry_count in range(0, 3):
            for network_count in range(0, 2):
                event_count = 1 + file_count + registry_count + network_count
                rows.append(
                    make_row(
                        event_count,
                        1,
                        file_count,
                        registry_count,
                        network_count,
                        1,
                        1,
                        1,
                        "suspicious",
                    )
                )

    for event_count in range(5, 10):
        rows.append(make_row(event_count, 1, 2, 2, 0, 1, 1, 1, "suspicious"))
        rows.append(make_row(event_count, 1, 2, 0, 1, 1, 1, 1, "suspicious"))

    return rows


def make_row(
    event_count: int,
    process_create_count: int,
    file_create_count: int,
    registry_modify_count: int,
    network_connect_count: int,
    uses_suspicious_process: int,
    uses_suspicious_command: int,
    has_multiple_behaviors: int,
    label: str,
) -> dict[str, Any]:
    return {
        "event_count": event_count,
        "process_create_count": process_create_count,
        "file_create_count": file_create_count,
        "registry_modify_count": registry_modify_count,
        "network_connect_count": network_connect_count,
        "uses_suspicious_process": uses_suspicious_process,
        "uses_suspicious_command": uses_suspicious_command,
        "has_multiple_behaviors": has_multiple_behaviors,
        "label": label,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Preprocess Winlogbeat/Sysmon logs into dynamic chain features."
    )
    parser.add_argument(
        "--log-path",
        action="append",
        dest="log_paths",
        help="Winlogbeat JSON/JSONL file. Can be passed multiple times.",
    )
    parser.add_argument("--csv-path", default=None, help="Backward-compatible alias for one log path.")
    parser.add_argument("--label-column", default=None, help="Ignored in dynamic log mode.")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--no-seed-rows", action="store_true")
    args = parser.parse_args()

    result = preprocess_dataset(
        log_paths=args.log_paths,
        csv_path=args.csv_path,
        label_column=args.label_column,
        test_size=args.test_size,
        include_seed_rows=not args.no_seed_rows,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
