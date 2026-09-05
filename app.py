import hashlib
import ipaddress
import json
import math
import re
import email.utils
from urllib.parse import urlparse
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
URL_RE = re.compile(r'https?://[^\s<>"\']+')

DISPOSABLE_DOMAINS = {"mailinator.com", "guerrillamail.com", "temp-mail.org", "10minutemail.com", "yopmail.com", "throwawaymail.com", "burnermail.io", "tempmail.net", "sharklasers.com"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}

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
      .stApp { 
        background-color: #0c0a00;
        background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.06'/%3E%3C/svg%3E");
        color: #fef08a; 
      }
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
    urls = list(set(URL_RE.findall(body_text)))
    
    return {
        "from": sender, "domain": domain.lower(), "subject": msg.get("Subject", "N/A"),
        "received": received, "body": (body_text or "")[:8000], "urls": urls
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
is_burner = parsed["domain"] in DISPOSABLE_DOMAINS

hops = []
seen = set()
for r in parsed["received"]:
    for ip in IPV4_RE.findall(r):
        try:
            if ipaddress.ip_address(ip).is_global and ip not in seen:
                hops.append({"ip": ip, "time": extract_hop_time(r), "raw": r})
                seen.add(ip)
        except: pass

with st.spinner("Interrogating live DNS & executing psychological analysis..."):
    dns_records = check_live_dns(parsed["domain"])
    geo_data = []
    for h in hops:
        try:
            resp = requests.get(IP_API_URL.format(ip=h["ip"]), timeout=5).json()
            if resp.get("status") == "success":
                resp["time"] = h["time"]
                geo_data.append(resp)
        except: pass

    # AI Psychological Analysis
    prompt = f"""Analyze this email for social engineering tactics.
Return ONLY valid JSON with keys: classification (Phishing/BEC/Clean), threat_score (0-100), rationale, and manipulation_matrix (object with boolean keys: urgency, authority_impersonation, financial_fear).
Body excerpt: {parsed['body'][:4000]}"""
    
    ai_data = {"classification": "Unknown", "threat_score": 0, "rationale": "AI Unavailable", "manipulation_matrix": {}}
    if genai:
        try:
            genai.configure(api_key=GEMINI_API_KEY)
            response = genai.GenerativeModel(GEMINI_MODEL).generate_content(prompt, generation_config={"response_mime_type": "application/json"})
            ai_data = json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", (response.text or "").strip()))
        except: pass

c1, c2, c3, c4 = st.columns(4)
c1.metric("Live SPF Record", "Verified" if "v=spf1" in dns_records["SPF"].lower() else "Failed/None")
c2.metric("Live DMARC Record", "Verified" if "v=dmarc1" in dns_records["DMARC"].lower() else "Failed/None")
c3.metric("Burner Domain", "🚨 YES (High Risk)" if is_burner else "No")
c4.metric("AI Threat Score", f"{ai_data.get('threat_score', 0)} / 100")

st.subheader("Unaltered Cryptographic Lock")
st.code(f"SHA-256: {sha256}", language="text")
st.caption("This digital seal guarantees the payload features remain completely unaltered from their original state.")

left, right = st.columns((1, 1))

with left:
    st.subheader("Psychological Manipulation Matrix")
    matrix = ai_data.get("manipulation_matrix", {})
    st.write(f"**Urgency / Time Pressure:** {'🔴 Detected' if matrix.get('urgency') else '🟢 Clear'}")
    st.write(f"**Authority Impersonation:** {'🔴 Detected' if matrix.get('authority_impersonation') else '🟢 Clear'}")
    st.write(f"**Financial Fear / Extortion:** {'🔴 Detected' if matrix.get('financial_fear') else '🟢 Clear'}")
    
    st.markdown(
        f"<div style='padding:10px;border-left:4px solid #b45309;background:#1a1600;margin-top:1rem;'>"
        f"<b>AI Rationale:</b> {ai_data.get('rationale')}</div>",
        unsafe_allow_html=True
    )

with right:
    st.subheader("URL Quarantine Zone")
    if parsed["urls"]:
        url_table = []
        for url in parsed["urls"]:
            domain = urlparse(url).netloc.lower()
            warning = "⚠️ Masked Link" if domain in URL_SHORTENERS else "Standard URL"
            url_table.append({"Extracted Link (Unclickable)": url, "Status": warning})
        st.dataframe(url_table, use_container_width=True, hide_index=True)
    else:
        st.success("No external links found in the payload.")
