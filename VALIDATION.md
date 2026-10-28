# Validierungsnachweis – 28. Oktober 2026

Geprüft in einer isolierten Linux-Umgebung mit Python 3.12.14 und Streamlit 1.66.1.
Keine Prüfung auf dem Mac der Nutzerin und keine Ausführung in einem Microsoft-Tenant.

| Prüfung | Ergebnis |
|---|---|
| Unit-Tests | 30 bestanden (v2-Tests plus Regel-Sync-Tests Python/KQL/Sigma) |
| Vollständiger synthetischer Batch | Bestanden; 14 Ereignisse, sieben Szenarien |
| Baseline | TP 3, FP 1, FN 0, TN 3 |
| Tuning bei gültiger Ausnahme | TP 3, FP 0, FN 0, TN 4 |
| Pipeline-Integration | Demo, Import ohne Labels, ungültiger Import und konkurrierender Lauf geprüft |
| Fehlerbehandlung | Ungültiger Import und konkurrierender Lauf lassen den letzten fertigen Lauf unverändert |
| Streamlit AppTest | Baseline und Tuning; getrennte Notizen/Bewertungen und deren Erhalt beim Befundwechsel bestanden |
| Shell-Syntax | Beide Bash-Startskripte mit bash -n geprüft |
| Python-Syntax | Module, Skripte und Tests kompiliert |
| pip-audit 2.10.1 | Keine bekannten Schwachstellen in den 34 aufgelösten Paketen des Runtime-Requirements-Satzes gemeldet |
| GitHub Actions | Workflow vorbereitet; keine Remote-Ausführung |
| macOS launchd | Generator vorbereitet; auf macOS nicht ausgeführt |
| Defender/KQL/Sigma | Quellen abgeglichen; keine Tenant-/Backend-Ausführung |

Referenzlauf: `20261028T063759844733Z-d164bb98`. Den zugehörigen Testbericht und das Manifest findest du unter `reports/runs/20261028T063759844733Z-d164bb98/`. Den vollständigen Paketprüfbericht findest du in `reports/dependency_audit.json`. Dieser Bericht ist eine Momentaufnahme des hier aufgelösten Abhängigkeitssatzes; bitte auf dem Mac erneut prüfen.

Reproduzieren im Projektordner, mit aktivierter .venv:

```bash
bash scripts/check.sh
python scripts/test_pipeline.py
python scripts/test_dashboard.py
python -m pip install -r requirements-audit.txt
python -m pip_audit -r requirements.txt
```

Die Benchmark-Werte gelten ausschließlich für die Demo. Die Backup-Ausnahme endet am 28. November 2026 um 00:00 UTC. Nach Ablauf ist der Backup-Treffer im aktuellen Prüflauf wieder sichtbar; der UI-Benchmark-Test benötigt dann eine überprüfte gültige Ausnahme. Die Unit-Tests nutzen eine feste Bewertungszeit.
