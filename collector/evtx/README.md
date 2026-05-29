# EVTX Log Collection

Place raw Windows Event Log `.evtx` files in this directory before converting
them into Winlogbeat/Sysmon JSON or JSONL inputs for backend analysis.

The current backend API analyzes normalized log files such as `.json`,
`.jsonl`, `.log`, and `.txt`. Raw `.evtx` files should be converted before
uploading them to `/upload`.
