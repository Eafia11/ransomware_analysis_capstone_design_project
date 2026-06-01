@echo off
setlocal

for %%I in ("%~dp0..") do set "PROJECT_DIR=%%~fI\"
set "LOG_PATH=%~1"
set "MODEL_PATH=%~2"

if "%LOG_PATH%"=="" (
    set "LOG_PATH=%PROJECT_DIR%collector\sample_inputs\winlogbeat_sample-20260415.jsonl"
) else (
    if exist "%PROJECT_DIR%%LOG_PATH%" (
        set "LOG_PATH=%PROJECT_DIR%%LOG_PATH%"
    )
)

if not "%MODEL_PATH%"=="" (
    if exist "%PROJECT_DIR%%MODEL_PATH%" (
        set "MODEL_PATH=%PROJECT_DIR%%MODEL_PATH%"
    )
)

cd /d "%PROJECT_DIR%ml\src"

if "%MODEL_PATH%"=="" (
    python train_xgboost.py --log-path "%LOG_PATH%" --preprocess
) else (
    python train_xgboost.py --log-path "%LOG_PATH%" --model-path "%MODEL_PATH%" --preprocess
)

endlocal
