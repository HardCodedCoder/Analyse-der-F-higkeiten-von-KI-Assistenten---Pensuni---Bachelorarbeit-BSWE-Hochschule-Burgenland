@echo off
setlocal enabledelayedexpansion

REM Pfad zum Intel Inspector (ggf. anpassen)
set INSPECTOR_PATH="C:\Program Files (x86)\Intel\oneAPI\inspector\latest\bin64\inspxe-cl.exe"

REM Pfad zur zu analysierenden Executable
set EXE_PATH="C:\Users\z0041eeu\Desktop\Testumgebung\build\Debug\BachelorThesisDemo.exe"

REM Arbeitsverzeichnis der Anwendung
set APP_DIR="C:\Users\z0041eeu\Desktop\Testumgebung\build\Debug"

REM Ausgabeordner für Ergebnisse
set OUTPUT_DIR="C:\Users\z0041eeu\Desktop\Testumgebung\inspector_results"

REM Projektname
set PROJECT_NAME=BachelorThesisMemoryCheck

REM Testfall-Schleife TC1_B bis TC15_B
for /L %%i in (1,1,15) do (
    set "TESTCASE=TC%%i_B"
    echo [INFO] Starte Analyse für !TESTCASE!

    %INSPECTOR_PATH% -collect mi3 ^
        -knob detect-invalid-accesses=true ^
        -knob analyze-stack=true ^
        -knob detect-leaks-on-exit=true ^
        -knob detect-resource-leaks=true ^
        -knob enable-memory-growth-detection=true ^
        -knob enable-on-demand-leak-detection=true ^
        -knob remove-duplicates=true ^
        -knob still-allocated-memory=true ^
        -knob stack-depth=32 ^
        -offload-target=default ^
        -module-filter-mode=include ^
        -app-working-dir %APP_DIR% ^
        --app-working-dir=%APP_DIR% ^
        -result-dir %OUTPUT_DIR%\!TESTCASE! ^
        -- %EXE_PATH% !TESTCASE!
)

echo [INFO] Alle Analysen abgeschlossen.
pause
