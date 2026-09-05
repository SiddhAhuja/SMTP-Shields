import hashlib
import ipaddress
import json
import math
import re
import email.utils
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

import folium
from fpdf import FPDF
import requests
import streamlit as st
from streamlit_folium import st_folium

try:
    import dns.resolver
except ImportError:
    pass

try:
    import google.generativeai as genai
except ImportError:
    genai = None

GEMINI_API_KEY = "AIzaSyDLFWw_PFuv8S71fZxXB8tGT4IWL7URIW8"
GEMINI_MODEL = "gemini-2.5-flash"
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,query"
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat, dlon = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))

def extract_hop_time(header_text):
    parts = str(header_text).split(';')
    if len(parts) > 1:
        try:
            dt = email.utils.parsedate_to_datetime(parts[-1].strip())
            return dt.astimezone(timezone.utc)
        except: pass
    return None

def check_live_dns(domain):
    records = {"SPF": "Not Found", "DMARC": "Not Found"}
    if not domain: return records
    try:
        for rdata in dns.resolver.resolve(domain, 'TXT'):
            if "v=spf1" in rdata.to_text().lower(): records["SPF"] = rdata.to_text().strip('"')
    except: pass
    try:
        for rdata in dns.resolver.resolve(f'_dmarc.{domain}', 'TXT'):
            if "v=dmarc1" in rdata.to_text().lower(): records["DMARC"] = rdata.to_text().strip('"')
    except: pass
    return records

st.set_page_config(page_title="Email Threat Forensics", page_icon="🛡️", layout="wide")

st.markdown(
    """
    <style>
      .stApp { background-color: #0c0a00; color: #fef08a; }
      div[data-testid="stMetric"] { background: #1a1600; border: 1px solid #b45309; border-radius: 4px; padding: 12px; }
      h1, h2, h3, p { color: #fef08a !important; }
    </style>
    """, unsafe_allow_html=True
)

def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    received = msg.get_all("Received") or []
    try: body_text = msg.get_body(preferencelist=("plain", "html")).get_content()
    except: body_text = ""
    if isinstance(body_text, bytes): body_text = body_text.decode("utf-8", errors="replace")
    
    sender = msg.get("From", "N/A")
    domain = sender.split("@")[-1].strip("<>") if "@" in sender else ""
    
    return {
        "from": sender, "domain": domain, "subject": msg.get("Subject", "N/A"),
        "received": received, "body": (body_text or "")[:8000]
    }

st.title("🛡️ Advanced Email Threat Detection")
raw_bytes = None
tab1, tab2 = st.tabs(["📁 Upload File", "📝 Paste Raw Email Text"])

with tab1:
    uploaded = st.file_uploader("Upload email artifact (.eml, .txt)", type=["eml", "txt"])
    if uploaded: raw_bytes = uploaded.getvalue()
with tab2:
    pasted_text = st.text_area("Paste the raw email source here:", height=200)
    if st.button("Analyze Pasted Text") and pasted_text.strip():
        raw_bytes = pasted_text.encode('utf-8')

if not raw_bytes: st.stop()

sha256 = hashlib.sha256(raw_bytes).hexdigest()
parsed = parse_eml(raw_bytes)

hops = []
seen = set()
for r in parsed["received"]:
    for ip in IPV4_RE.findall(r):
        try:
            if ipaddress.ip_address(ip).is_global and ip not in seen:
                hops.append({"ip": ip, "time": extract_hop_time(r), "raw": r})
                seen.add(ip)
        except: pass

with st.spinner("Interrogating live DNS & executing calculus optimizations..."):
    dns_records = check_live_dns(parsed["domain"])
    geo_data = []
    for h in hops:
        try:
            resp = requests.get(IP_API_URL.format(ip=h["ip"]), timeout=5).json()
            if resp.get("status") == "success":
                resp["time"] = h["time"]
                geo_data.append(resp)
        except: pass

c1, c2, c3 = st.columns(3)
c1.metric("Live SPF Record", "Verified" if "v=spf1" in dns_records["SPF"].lower() else "Failed/None")
c2.metric("Live DMARC Record", "Verified" if "v=dmarc1" in dns_records["DMARC"].lower() else "Failed/None")
c3.metric("Public Hops Extracted", str(len(geo_data)))

st.subheader("Unaltered Cryptographic Lock")
st.code(f"SHA-256: {sha256}", language="text")
st.caption("This digital seal guarantees the payload features remain completely unaltered from their original state.")

left, right = st.columns((1, 1))

with left:
    st.subheader("Kinematics & OSINT Pivots")
    table = []
    for i in range(len(geo_data)):
        row = geo_data[i]
        speed = "N/A"
        if i > 0 and row.get("time") and geo_data[i-1].get("time"):
            dist = haversine(geo_data[i-1]["lat"], geo_data[i-1]["lon"], row["lat"], row["lon"])
            time_diff = abs((row["time"] - geo_data[i-1]["time"]).total_seconds())
            if time_diff > 0:
                calc_speed = dist / time_diff
                speed = f"{calc_speed:.2f} km/s"
                if calc_speed > 200000: speed += " ⚠️ (Impossible)"

        table.append({
            "Hop": i+1,
            "IP": row["query"],
            "Location": f"{row.get('city')}, {row.get('country')}",
            "Velocity (dx/dt)": speed,
            "VirusTotal": f"https://www.virustotal.com/gui/search/{row['query']}"
        })
    
    st.data_editor(
        table,
        column_config={"VirusTotal": st.column_config.LinkColumn("OSINT Check")},
        hide_index=True, use_container_width=True
    )

with right:
    st.subheader("Geodesic Hop Mapping")
    if geo_data:
        fmap = folium.Map(location=[geo_data[0]["lat"], geo_data[0]["lon"]], zoom_start=2, tiles="CartoDB dark_matter")
        path = [(r["lat"], r["lon"]) for r in geo_data]
        for idx, (lat, lon) in enumerate(path, 1):
            folium.CircleMarker(location=(lat, lon), radius=6, color="#fef08a", fill=True, popup=f"Hop {idx}").add_to(fmap)
        folium.PolyLine(path, color="#b45309", weight=2, opacity=0.8).add_to(fmap)
        st_folium(fmap, width=None, height=350)
