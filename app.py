import hashlib
import ipaddress
import json
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

st.set_page_config(
    page_title="Email Threat Forensics",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
      .stApp { background: linear-gradient(180deg, #070b14 0%, #101827 100%); }
      div[data-testid="stMetric"] {
        background: #111827;
        border: 1px solid #1f2937;
        border-radius: 12px;
        padding: 12px;
      }
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
            results.append(
                {
                    "query": ip,
                    "status": "fail",
                    "message": data.get("message", "lookup failed"),
                }
            )
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
        popup = (
            f"<b>Hop {idx}</b><br>"
            f"{row.get('query')}<br>"
            f"{row.get('city', '')}, {row.get('regionName', '')}, {row.get('country', '')}<br>"
            f"ISP: {row.get('isp', 'N/A')}"
        )
        folium.CircleMarker(
            location=(lat, lon),
            radius=8,
            color="#22d3ee" if idx == 1 else ("#f97316" if idx == len(points) else "#a78bfa"),
            fill=True,
            fill_opacity=0.9,
            popup=popup,
            tooltip=f"Hop {idx}: {row.get('query')}",
        ).add_to(fmap)
    if len(path) >= 2:
        folium.PolyLine(path, color="#22d3ee", weight=3, opacity=0.8).add_to(fmap)
    fmap.fit_bounds(path, padding=(30, 30))
    return fmap


def classify_with_gemini(parsed: dict, geo_rows: list[dict], file_hash: str) -> dict:
    fallback = {
        "classification": "Unknown",
        "threat_score": 0,
        "rationale": "Gemini analysis unavailable.",
        "indicators": [],
    }
    if genai is None:
        fallback["rationale"] = "Install google-generativeai to enable classification."
        return fallback

    hop_summary = []
    for row in geo_rows:
        if row.get("status") == "success":
            hop_summary.append(
                f"{row.get('query')} | {row.get('city')}, {row.get('country')} | {row.get('isp')}"
            )
        else:
            hop_summary.append(f"{row.get('query')} | lookup failed")

    prompt = f"""You are an email threat and digital-forensics analyst.
Classify this email as exactly one of: Phishing, BEC, Clean.
Also assign an integer threat_score from 0 to 100.

Return ONLY valid JSON with keys:
classification, threat_score, rationale, indicators (array of short strings).

Evidence:
SHA-256: {file_hash}
From: {parsed['from']}
To: {parsed['to']}
Subject: {parsed['subject']}
Return-Path: {parsed['return_path']}
Authentication-Results: {parsed['authentication_results']}
Public IP hops: {hop_summary}
Body excerpt:
{parsed['body'][:4000]}
"""
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json"},
        )
        text = (response.text or "").strip()
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
        data = json.loads(text)
        classification = str(data.get("classification", "Unknown")).strip()
        if classification not in {"Phishing", "BEC", "Clean"}:
            classification = "Unknown"
        score = int(data.get("threat_score", 0))
        score = max(0, min(100, score))
        indicators = data.get("indicators") or []
        if not isinstance(indicators, list):
            indicators = [str(indicators)]
        return {
            "classification": classification,
            "threat_score": score,
            "rationale": str(data.get("rationale", "")).strip() or "No rationale provided.",
            "indicators": [str(item) for item in indicators][:12],
        }
    except Exception as exc:
        fallback["rationale"] = f"Gemini request failed: {exc}"
        return fallback


def generate_pdf_report(parsed: dict, analysis: dict, file_hash: str) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, txt="AI Email Forensic Intelligence Report", ln=True, align="C")
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 8, txt="Smart India Hackathon - Threat Detection Platform", ln=True, align="C")
    pdf.ln(10)
    
    # Metadata
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Email Header Metadata:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 8, txt=f"From: {parsed['from']}", ln=True)
    pdf.cell(200, 8, txt=f"To: {parsed['to']}", ln=True)
    pdf.cell(200, 8, txt=f"Subject: {parsed['subject']}", ln=True)
    pdf.cell(200, 8, txt=f"SHA-256 Hash: {file_hash}", ln=True)
    pdf.ln(5)
    
    # Threat Assessment
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Threat Assessment:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 8, txt=f"Classification: {analysis['classification']}", ln=True)
    pdf.cell(200, 8, txt=f"Threat Score: {analysis['threat_score']} / 100", ln=True)
    pdf.ln(5)
    
    # Analyst Rationale
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, txt="Analyst Rationale:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 6, txt=analysis['rationale'])
    pdf.ln(5)
    
    # Indicators
    if analysis['indicators']:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(200, 10, txt="Key Indicators:", ln=True)
        pdf.set_font("Arial", size=10)
        for ind in analysis['indicators']:
            pdf.cell(200, 6, txt=f"- {ind}", ln=True)
            
    return bytes(pdf.output())


def verdict_color(classification: str) -> str:
    return {
        "Phishing": "#ef4444",
        "BEC": "#f59e0b",
        "Clean": "#22c55e",
    }.get(classification, "#94a3b8")


st.title("🛡️ Email Threat Detection & Forensic Intelligence")
st.caption(
    "Upload a `.eml` / `.txt` file OR paste raw email text to extract headers, trace public hops, "
    "hash the artifact, and classify the message with Gemini."
)

tab1, tab2 = st.tabs(["📁 Upload File", "📝 Paste Raw Email Text"])

raw_bytes = None

with tab1:
    uploaded = st.file_uploader("Upload email artifact (.eml, .txt)", type=["eml", "txt"])
    if uploaded:
        raw_bytes = uploaded.getvalue()

with tab2:
    pasted_text = st.text_area("Paste the raw email source (headers + body) here:", height=200)
    if st.button("Analyze Pasted Text"):
        if pasted_text.strip():
            raw_bytes = pasted_text.encode('utf-8')
        else:
            st.warning("Please paste some email text first.")

if not raw_bytes:
    st.info("Drop a file or paste raw text above to begin the forensic analysis.")
    st.stop()

sha256 = hashlib.sha256(raw_bytes).hexdigest()
parsed = parse_eml(raw_bytes)

with st.spinner("Tracing public IP hops and classifying the message..."):
    geo_rows = geolocate_ips(parsed["hops"])
    analysis = classify_with_gemini(parsed, geo_rows, sha256)

color = verdict_color(analysis["classification"])
c1, c2, c3, c4 = st.columns(4)
c1.metric("Classification", analysis["classification"])
c2.metric("Threat score", f"{analysis['threat_score']} / 100")
c3.metric("Public hops", str(len(parsed["hops"])))
c4.metric("Artifact size", f"{len(raw_bytes):,} B")

st.markdown(
    f"<div style='padding:10px 14px;border-left:4px solid {color};"
    f"background:#111827;border-radius:8px;margin-bottom:1rem;'>"
    f"<b>Analyst rationale:</b> {analysis['rationale']}</div>",
    unsafe_allow_html=True,
)

pdf_data = generate_pdf_report(parsed, analysis, sha256)
st.download_button(
    label="📥 Download Official Forensic PDF Report",
    data=pdf_data,
    file_name="email_forensic_report.pdf",
    mime="application/pdf",
)

st.markdown("<br>", unsafe_allow_html=True)

left, right = st.columns((1.15, 1))

with left:
    st.subheader("Header intelligence")
    st.write("**From:**", parsed["from"])
    st.write("**To:**", parsed["to"])
    st.write("**Subject:**", parsed["subject"])
    st.write("**Return-Path:**", parsed["return_path"])
    st.write("**Date:**", parsed["date"])
    st.write("**Message-ID:**", parsed["message_id"])
    st.markdown("**Authentication-Results**")
    st.code(parsed["authentication_results"], language="text")

    st.subheader("Chain of custody")
    st.code(f"SHA-256: {sha256}", language="text")
    st.caption("Hash is computed over the exact uploaded bytes before parsing.")

    if analysis["indicators"]:
        st.subheader("Key indicators")
        for item in analysis["indicators"]:
            st.markdown(f"- {item}")

with right:
    st.subheader("Received hop geolocation")
    if not parsed["hops"]:
        st.warning("No public IPv4 hops were found in Received headers.")
    else:
        table = []
        for idx, row in enumerate(geo_rows, start=1):
            if row.get("status") == "success":
                table.append(
                    {
                        "Hop": idx,
                        "IP": row.get("query"),
                        "City": row.get("city"),
                        "Region": row.get("regionName"),
                        "Country": row.get("country"),
                        "ISP": row.get("isp"),
                    }
                )
            else:
                table.append(
                    {
                        "Hop": idx,
                        "IP": row.get("query"),
                        "City": "—",
                        "Region": "—",
                        "Country": row.get("message", "failed"),
                        "ISP": "—",
                    }
                )
        st.dataframe(table, use_container_width=True, hide_index=True)

        hop_map = build_hop_map(geo_rows)
        if hop_map:
            st_folium(hop_map, width=None, height=420)
        else:
            st.warning("Geolocation succeeded for no hops, so a map could not be drawn.")

with st.expander("Raw Received headers"):
    if parsed["received"]:
        st.code("\n\n".join(parsed["received"]), language="text")
    else:
        st.write("None")

with st.expander("Message body excerpt"):
    st.text(parsed["body"] or "(empty)")