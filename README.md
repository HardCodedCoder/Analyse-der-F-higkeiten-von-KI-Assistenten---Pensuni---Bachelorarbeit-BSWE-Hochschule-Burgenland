# Speicherfehler-Erkennung in C/C++ mit KI und Analyse-Tools

Dieses Repository enthält den Quellcode, die Auswertungsberichte und Skripte zur experimentellen Durchführung der Bachelorarbeit **„Analyse der Fähigkeiten von KI-Assistenten zur Erkennung und Behebung von Speicherverwaltungsfehlern in C/C++“**.

## Projektübersicht

Ziel des Projekts ist es, die Fähigkeiten moderner KI-Assistenten (wie ChatGPT, Gemini, Claude etc.) bei der Erkennung und Behebung typischer sicherheitsrelevanter Speicherfehler in C/C++ zu evaluieren. Zusätzlich werden klassische Analysewerkzeuge (z. B. Intel Inspector, Clang Static Analyzer) eingesetzt, um die Ergebnisse zu vergleichen.

Untersuchte Fehlerarten:

- Buffer Overflow
- Use-after-Free
- Memory Leak

## Projektstruktur

```
├── .vscode/                  # VSCode Konfiguration
│   ├── settings.json
│   └── tasks.json
├── build/                    # CMake-Buildverzeichnis (nicht eingecheckt)
├── inspector_results/        # Ausgabeergebnisse vom Intel Inspector
├── src/                      # Alle Quellcodes der Testfälle (TC1_B.cpp bis TC15_B.cpp)
├── TC*_B_report.txt          # Auswertung pro Testfall (manuell oder durch Tools erzeugt)
├── inspector.bat             # Automatisiertes Batch-Skript zur Ausführung von Intel Inspector
├── CMakeLists.txt            # Projekt-Setup für CMake
├── .gitignore                # Ausgeschlossene Dateien und Ordner
├── README.md                 # Dieses Dokument
└── Bachelorarbeit_Pensum.txt# Notizen/Planung zur Arbeit
```

## Nutzung

### 1. Build (mit CMake)
Voraussetzung: CMake, ein C++ Compiler (z. B. MSVC), Ninja empfohlen.

```bash
cmake -S . -B build -G Ninja
cmake --build build
```

### 2. Ausführung der Testfälle

Die kompilierten Testfälle können manuell oder automatisch durch das Batch-Skript `inspector.bat` analysiert werden. Die Pfade im Skript müssen an die lokale Umgebung angepasst werden.

```bash
inspector.bat
```

## Weiterführende Informationen

Die Bachelorarbeit selbst beschreibt im Detail:

- Die Methodik der Testfallerstellung
- Das Bewertungsschema
- Die verwendeten Tools und Modelle
- Eine Diskussion der Ergebnisse und Implikationen

## Lizenz

Das Projekt steht nur zu Studienzwecken zur Verfügung. Keine kommerzielle Nutzung.
# Analyse-der-F-higkeiten-von-KI-Assistenten---Pensuni---Bachelorarbeit-BSWE-Hochschule-Burgenland
