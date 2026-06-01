#!/usr/bin/env sh
set -eu

LOG_PATH="${1:-collector/sample_inputs/winlogbeat_sample-20260415.jsonl}"
MODEL_PATH="${2:-}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

case "$LOG_PATH" in
  /*) ;;
  *) LOG_PATH="$PROJECT_DIR/$LOG_PATH" ;;
esac

if [ -n "$MODEL_PATH" ]; then
  case "$MODEL_PATH" in
    /*) ;;
    *) MODEL_PATH="$PROJECT_DIR/$MODEL_PATH" ;;
  esac
fi

cd "$PROJECT_DIR/ml/src"

if [ -n "$MODEL_PATH" ]; then
  python train_xgboost.py --log-path "$LOG_PATH" --model-path "$MODEL_PATH" --preprocess
else
  python train_xgboost.py --log-path "$LOG_PATH" --preprocess
fi
