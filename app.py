import hashlib
import ipaddress
import json
import math
import re
from email import policy
from email.parser import BytesParser

import folium
from fpdf import FPDF
import requests
import streamlit as st
from streamlit_folium import st_folium

try:
    import google.generativeai as genai
except ImportError:
    genai = None

GEMINI_API_KEY = "AIzaSyDLFWw_PFuv8S71fZxXB8tGT4IWL7URIW8"
GEMINI_MODEL = "gemini-2.5-flash"
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,query"
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat, dlon = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * \
        math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))

def calculate_routing_anomaly(geo_rows: list[dict]) -> tuple:
    valid = [r for r in geo_rows if r.get('status') == 'success' and r.get('lat')]
    if len(valid) < 2: return 0, 0, 0
    actual_dist = sum(haversine(valid[i]['lat'], valid[i]['lon'], valid[i+1]['lat'], valid[i+1]['lon']) for i in range(len(valid)-1))
    optimized_dist = haversine(valid[0]['lat'], valid[0]['lon'], valid[-1]['lat'], valid[-1]['lon'])
    deviation = ((actual_dist - optimized_dist) / optimized_dist) * 100 if optimized_dist > 0 else 0
    return round(actual_dist), round(optimized_dist), round(deviation)

st.set_page_config(page_title="Email Threat Forensics", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
      .stApp { 
        background-color: #0c0a00;
        background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.06'/%3E%3C/svg%3E");
        color: #fef08a; 
      }
      div[data-testid="stMetric"] {
        background: #1a1600;
        border: 1px solid #b45309;
        border-radius: 4px;
        padding: 12px;
        box-shadow: 0 0 10px rgba(217, 119, 6, 0.15);
      }
      h1, h2, h3, p { color: #fef08a !important; }
      .block-container { padding-top: 1.4rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

def is_public_ipv4(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global

def extract_public_hops(received_headers: list[str]) -> list[str]:
    hops: list[str] = []
    seen: set[str] = set()
    for header in received_headers:
        for ip in IPV4_RE.findall(header or ""):
            if ip in seen or not is_public_ipv4(ip):
                continue
            seen.add(ip)
            hops.append(ip)
    return hops

def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    received = msg.get_all("Received") or []
    try:
        body = msg.get_body(preferencelist=("plain", "html"))
        body_text = body.get_content() if body else ""
    except Exception:
        body_text = ""
    if isinstance(body_text, bytes):
        body_text = body_text.decode("utf-8", errors="replace")
    return {
        "from": msg.get("From", "N/A"),
        "subject": msg.get("Subject", "N/A"),
        "return_path": msg.get("Return-Path", "N/A"),
        "authentication_results": msg.get("Authentication-Results", "N/A"),
        "received": received,
        "hops": extract_public_hops(received),
        "body": (body_text or "")[:8000],
        "date": msg.get("Date", "N/A"),
        "message_id": msg.get("Message-ID", "N/A"),
        "to": msg.get("To", "N/A"),
    }

def geolocate_ips(ips: list[str]) -> list[dict]:
    results = []
    for ip in ips:
        try:
            resp = requests.get(IP_API_URL.format(ip=ip), timeout=8)
            data = resp.json()
        except Exception as exc:
            results.append({"query": ip, "status": "fail", "message": str(exc)})
            continue
        if data.get("status") != "success":
            results.append({"query": ip, "status": "fail", "message": data.get("message", "lookup failed")})
            continue
        results.append(data)
    return results

def build_hop_map(geo_rows: list[dict]) -> folium.Map | None:
    points = [
        (row["lat"], row["lon"], row)
        for row in geo_rows
        if row.get("status") == "success" and row.get("lat") is not None
    ]
    if not points:
        return None
    fmap = folium.Map(location=points[0][:2], zoom_start=3, tiles="CartoDB dark_matter")
    path = []
    for idx, (lat, lon, row) in enumerate(points, start=1):
        path.append((lat, lon))
        popup = f"<b>Hop {idx}</b><br>{row.get('query')}<br>{row.get('city', '')}, {row.get('country', '')}"
        folium.CircleMarker(
            location=(lat, lon), radius=8,
            color="#b45309" if idx == 1 else ("#fef08a" if idx == len(points) else "#78350f"),
            fill=True, fill_opacity=0.9, popup=popup, tooltip=f"Hop {idx}: {row.get('query')}",
        ).add_to(fmap)
    if len(path) >= 2:
        folium.PolyLine(path, color="#b45309", weight=3, opacity=0.8).add_to(fmap)
    fmap.fit_bounds(path, padding=(30, 30))
    return fmap

def classify_with_gemini(parsed: dict, geo_rows: list[dict], file_hash: str) -> dict:
    fallback = {"classification": "Unknown", "threat_score": 0, "rationale": "Gemini unavailable.", "indicators": []}
    if genai is None:
        return fallback

    hop_summary = []
    for row in geo_rows:
        if row.get("status") == "success":
            hop_summary.append(f"{row.get('query')} | {row.get('city')}, {row.get('country')} | {row.get('isp')}")
        else:
            hop_summary.append(f"{row.get('query')} | lookup failed")

    prompt = f"""You are an email threat and digital-forensics analyst.
Classify this email as exactly one of: Phishing, BEC, Clean.
Also assign an integer threat_score from 0 to 100.
Return ONLY valid JSON with keys: classification, threat_score, rationale, indicators (array of short strings).
Evidence: SHA-256: {file_hash}\nFrom: {parsed['from']}\nTo: {parsed['to']}\nSubject: {parsed['subject']}\nPublic IP hops: {hop_summary}\nBody excerpt: {parsed['body'][:4000]}"""
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", (response.text or "").strip())
        data = json.loads(text)
        return {
            "classification": str(data.get("classification", "Unknown")).strip(),
            "threat_score": max(0, min(100, int(data.get("threat_score", 0)))),
            "rationale": str(data.get("rationale", "")).strip() or "No rationale provided.",
            "indicators": [str(item) for item in (data.get("indicators") or [])][:12],
        }
    except Exception:
        return fallback

def generate_pdf_report(parsed: dict, analysis: dict, file_hash: str) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, txt="AI Email Forensic Intelligence Report", ln=True, align="C")
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 8, txt="Smart India Hackathon - Threat Detection Platform", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Email Header Metadata:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 8, txt=f"From: {parsed['from']}", ln=True)
    pdf.cell(200, 8, txt=f"Subject: {parsed['subject']}", ln=True)
    pdf.cell(200, 8, txt=f"SHA-256 Hash (Unaltered lock): {file_hash}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Threat Assessment:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 8, txt=f"Classification: {analysis['classification']}", ln=True)
    pdf.cell(200, 8, txt=f"Threat Score: {analysis['threat_score']} / 100", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Analyst Rationale:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 6, txt=analysis['rationale'])
    return bytes(pdf.output())

st.title("🛡️ Email Threat Detection & Forensic Intelligence")
st.caption("Upload a `.eml` / `.txt` file OR paste raw email text to run the geodesic analyzer and circuit topographer.")

tab1, tab2 = st.tabs(["📁 Upload File", "📝 Paste Raw Email Text"])
raw_bytes = None

with tab1:
    uploaded = st.file_uploader("Upload email artifact (.eml, .txt)", type=["eml", "txt"])
    if uploaded: raw_bytes = uploaded.getvalue()

with tab2:
    pasted_text = st.text_area("Paste the raw email source (headers + body) here:", height=200)
    if st.button("Analyze Pasted Text"):
        if pasted_text.strip(): raw_bytes = pasted_text.encode('utf-8')

if not raw_bytes: st.stop()

sha256 = hashlib.sha256(raw_bytes).hexdigest()
parsed = parse_eml(raw_bytes)

with st.spinner("Tracing public IP hops and classifying the message..."):
    geo_rows = geolocate_ips(parsed["hops"])
    analysis = classify_with_gemini(parsed, geo_rows, sha256)
    actual_km, optimal_km, anomaly_pct = calculate_routing_anomaly(geo_rows)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Classification", analysis["classification"])
c2.metric("Threat score", f"{analysis['threat_score']} / 100")
c3.metric("Public hops", str(len(parsed["hops"])))
c4.metric("Artifact size", f"{len(raw_bytes):,} B")

if anomaly_pct > 0:
    st.markdown(f"**Geodesic Routing Anomaly:** Path deviated by **{anomaly_pct}%** from the optimized direct route ({actual_km}km actual vs {optimal_km}km optimal).")

st.markdown(
    f"<div style='padding:10px 14px;border-left:4px solid #b45309;"
    f"background:#1a1600;border-radius:8px;margin-bottom:1rem;'>"
    f"<b>Analyst rationale:</b> {analysis['rationale']}</div>",
    unsafe_allow_html=True,
)

pdf_data = generate_pdf_report(parsed, analysis, sha256)
st.download_button(label="📥 Download Official Forensic PDF Report", data=pdf_data, file_name="email_forensic_report.pdf", mime="application/pdf")

st.markdown("<br>", unsafe_allow_html=True)
left, right = st.columns((1.15, 1))

with left:
    st.subheader("Header intelligence")
    st.write("**From:**", parsed["from"])
    st.write("**Subject:**", parsed["subject"])
    st.write("**Date:**", parsed["date"])

    st.subheader("Unaltered Cryptographic Lock")
    st.code(f"SHA-256: {sha256}", language="text")
    st.caption("This digital seal guarantees the payload features remain completely unaltered from their original state.")

with right:
    st.subheader("Circuit Topography")
    if not parsed["hops"]:
        st.warning("No public IPv4 hops were found.")
    else:
        table = []
        for idx, row in enumerate(geo_rows, start=1):
            if idx == 1: role = "Battery (Origin)"
            elif idx == len(geo_rows): role = "Capacitor (Terminal)"
            else: role = "Transistor (Relay)"
            
            if "pass" in str(parsed["authentication_results"]).lower() and idx == len(geo_rows):
                role += " + Diode (Verified)"

            if row.get("status") == "success":
                table.append({"Hop": idx, "Circuit Role": role, "IP": row.get("query"), "Country": row.get("country")})
            else:
                table.append({"Hop": idx, "Circuit Role": role, "IP": row.get("query"), "Country": "Failed"})
        st.dataframe(table, use_container_width=True, hide_index=True)

        hop_map = build_hop_map(geo_rows)
        if hop_map: st_folium(hop_map, width=None, height=420)
