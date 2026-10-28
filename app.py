"""Read-only local triage UI over completed batch snapshots."""
import hashlib
import json
import re
from datetime import datetime, timezone
import streamlit as st
from lab import ROOT
from safeio import MAX_BYTES, load_events, strict_json


def load_run():
    latest = strict_json((ROOT/'reports/latest.json').read_text(encoding='utf-8'))
    run_id = latest['run_id']
    if not isinstance(run_id, str) or not re.fullmatch(r'[0-9]{8}T[0-9]{12}Z-[a-f0-9]{8}', run_id):
        raise ValueError('invalid run identifier')
    folder = ROOT/'reports/runs'/run_id
    if not folder.resolve().is_relative_to((ROOT/'reports/runs').resolve()):
        raise ValueError('invalid run path')
    manifest = strict_json((folder/'manifest.json').read_text(encoding='utf-8'))
    required = ('events.jsonl', 'alerts_baseline.json', 'alerts_tuned.json', 'metrics.json', 'suppressed.json', 'exception_policy.json')
    for name in required:
        data = (folder/name).read_bytes()
        if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != manifest['files_sha256'][name]:
            raise ValueError('incomplete or modified run')
    def read(name):
        return strict_json((folder/name).read_text(encoding='utf-8'))
    return manifest, load_events(folder/'events.jsonl'), read('alerts_baseline.json'), read('alerts_tuned.json'), read('suppressed.json'), read('metrics.json')

st.set_page_config(page_title='SOC Portfolio Lab', layout='wide')
st.title('SOC Portfolio Lab · Detection & Triage')
st.warning('Lokales Batch-Lab – keine Live-Überwachung und keine automatische Reaktion an Geräten.')
try:
    manifest, events, baseline, tuned_alerts, suppressed, metrics = load_run()
except (OSError, ValueError, KeyError, TypeError):
    st.error('Kein vollständiger, gültiger Lauf. Im Projektordner ausführen: bash scripts/check.sh')
    st.stop()
st.caption(f"Lauf: {manifest['run_id']} · UTC: {manifest['created_at']} · Regeln: {manifest['rule_version']}")
if manifest['input_type'] == 'synthetic':
    st.info('Ausschließlich synthetische Testereignisse.')
else:
    st.info('Importierte normalisierte Daten. Herkunft und Vollständigkeit separat prüfen.')
if not manifest['exception_active']:
    st.warning('Backup-Ausnahme war beim Lauf abgelaufen. Treffer bleiben sichtbar; Ausnahme prüfen.')
tuned = st.toggle('Gezielte Backup-Ausnahme aktivieren', value=False)
alerts = tuned_alerts if tuned else baseline
m = metrics['tuned' if tuned else 'baseline']
if 'TP' in m:
    st.caption('Benchmark auf Szenarioebene; Aussagen gelten nur für die vorhandenen Testlabels.')
    for c, k in zip(st.columns(4), ['TP','FP','FN','TN']):
        c.metric(k, m[k])
    st.write('Precision:', m['precision'], 'Recall:', m['recall'])
else:
    st.info('Keine vollständigen Testlabels: Precision und Recall werden nicht berechnet.')
st.subheader('Befunde – Untersuchungshinweise')
st.dataframe(alerts)
if alerts:
    index = st.selectbox('Befund auswählen', range(len(alerts)), format_func=lambda i: f"{alerts[i]['rule']} – {alerts[i]['device']}")
    a = alerts[index]
    st.subheader('Technische Belege')
    st.json([e for e in events if e['event_id'] in a['evidence']])
    key = manifest['run_id'] + a['alert_id']
    drafts = st.session_state.setdefault('drafts', {})
    draft = drafts.get(key, {'verdict': 'Offen', 'notes': ''})
    for field in ('verdict', 'notes'):
        widget_key = field + '-' + key
        if widget_key not in st.session_state:
            st.session_state[widget_key] = draft[field]
    verdict = st.selectbox('Analystenbewertung', ['Offen','True Positive','False Positive','Weitere Untersuchung'], key='verdict-'+key)
    notes = st.text_area('Begründung und nächste Schritte', key='notes-'+key, max_chars=10000)
    drafts[key] = dict(verdict=verdict, notes=notes)
    record = dict(alert=a, verdict=verdict, notes=notes, run_id=manifest['run_id'],
                  exported_at=datetime.now(timezone.utc).isoformat(), input_type=manifest['input_type'],
                  events_sha256=manifest['files_sha256']['events.jsonl'], response_executed=False)
    st.download_button('Untersuchungsnotiz herunterladen', json.dumps(record, indent=2, ensure_ascii=False), file_name='investigation-'+a['alert_id']+'.json', mime='application/json')
    st.caption('Notizen gelten je Befund und Browser-Sitzung. Vor Sitzungsende exportieren.')
with st.expander('Unterdrückte Treffer und Ausnahmebegründung'):
    st.json(suppressed)
    st.caption('Auditliste des gespeicherten Laufs. Beim Ausschalten der Ausnahme sind diese Treffer in der Baseline sichtbar.')
with st.expander('Alle Ereignisse'):
    st.dataframe(events)
with st.expander('Laufnachweis'):
    st.json(manifest)
    st.caption('SHA-256 erkennt Abweichungen gegenüber diesem Manifest. Ohne externe Signatur ist dies kein manipulationssicherer Beweis.')
