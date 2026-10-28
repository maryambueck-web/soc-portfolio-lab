# Incident Runbook – Tabletop / ausschließlich simuliert

## Alarmaufnahme
- Incident-ID / Zeit in UTC:
- Regel / Priorität / betroffene Geräte und Konten:
- Ereignis-IDs und Datenquellen:
- Gesicherte Fakten:
- Hypothese / Unsicherheiten:

## Untersuchung
- Prozesskette, Befehlszeile, Quell-IP und Ziel prüfen.
- Legitime Tätigkeit anhand genehmigter Änderungen validieren.
- Zeitlinie und Umfang über weitere Geräte/Konten prüfen.
- Kritikalität und mögliche Auswirkungen bewerten.

## Eindämmung – Maßnahmenvorschlag, keine automatische Ausführung
- Playbook und zuständige Entscheidungsbefugnis prüfen.
- Kompromittiertes Gerät via EDR isolieren; Wirksamkeit prüfen.
- Alternative: Netzwerkteam für Switch-/NAC-/WLAN-Isolation einschalten.
- Konten und Sitzungen bei Bedarf gesondert absichern.
- Bei Fileserver-Szenario Backups und andere Systeme schützen.
- Forensische Beweissicherung abstimmen; nicht unüberlegt neu starten.

## Wiederherstellung
- Ursache und Persistenz entfernen bzw. System kontrolliert neu aufsetzen.
- Betroffene Zugangsdaten von einem sauberen Gerät erneuern.
- Sauberes Backup verifizieren, Wiederanbindung freigeben lassen.
- Verstärkte Überwachung nach Wiederherstellung.

## Lessons Learned
- Was wurde erkannt und was fehlte?
- Welcher Schritt dauerte zu lange?
- Regel-/Playbook-Änderung, Verantwortliche, Frist und Nachtest:


## Nachweis aus v2 anfügen

- Lauf-ID und UTC-Zeit aus dem Dashboard:
- Alarm-ID und Regelversion:
- Ereignis-IDs und SHA-256 des Eingabedatensatzes:
- Unterdrückte Treffer und gültige Ausnahme geprüft:
- Entscheidungsverantwortlicher und Freigabe für vorgeschlagene Maßnahmen:
- Nächste Prüfschritte, Verantwortliche und Frist:

Bei FILE-001 beachten: Die Korrelation erfolgt auf Geräteebene. Verschiedene Konten können beteiligt sein; eine gemeinsame Prozesskette ist mit diesen zwei Ereignissen nicht bewiesen. Eine niedrige Priorität bei einem einzelnen Teilereignis schließt einen kritischen Gesamtfall nicht aus.

Der Befundexport dokumentiert `response_executed: false`. Tatsächliche Maßnahmen separat mit Ausführendem, Genehmigung, Zeit und Ergebnis dokumentieren; diese Lab-Notiz ist kein Nachweis einer Geräte-Isolation.
