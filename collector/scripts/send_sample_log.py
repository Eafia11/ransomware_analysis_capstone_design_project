from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib import request


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE = PROJECT_ROOT / "collector" / "sample_inputs" / "winlogbeat_sample-20260415.jsonl"
DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"


def upload_file(sample_path: Path, backend_url: str) -> dict:
    boundary = "----collector-sample-boundary"
    content = sample_path.read_bytes()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{sample_path.name}"\r\n'
        "Content-Type: application/json\r\n\r\n"
    ).encode("utf-8") + content + f"\r\n--{boundary}--\r\n".encode("utf-8")

    upload_request = request.Request(
        f"{backend_url.rstrip('/')}/upload",
        data=body,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )

    with request.urlopen(upload_request) as response:
        return json.loads(response.read().decode("utf-8"))


def analyze_file(analysis_id: str, backend_url: str) -> dict:
    analyze_request = request.Request(
        f"{backend_url.rstrip('/')}/analyze/{analysis_id}",
        data=b"",
        method="POST",
    )

    with request.urlopen(analyze_request) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload a sample Winlogbeat log to the backend.")
    parser.add_argument("--sample", default=str(DEFAULT_SAMPLE))
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--analyze", action="store_true")
    args = parser.parse_args()

    sample_path = Path(args.sample)
    if not sample_path.exists():
        raise FileNotFoundError(f"sample file not found: {sample_path}")

    upload_result = upload_file(sample_path, args.backend_url)
    print(json.dumps(upload_result, ensure_ascii=False, indent=2))

    if args.analyze:
        analysis_result = analyze_file(upload_result["analysis_id"], args.backend_url)
        print(json.dumps(analysis_result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
