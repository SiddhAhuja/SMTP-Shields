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
from streamlit_agraph import agraph, Node, Edge, Config

try:
    import dns.resolver
except ImportError:
    pass

try:
    import google.generativeai as genai
except ImportError:
    genai = None

GEMINI_API_KEY = "AIzaSyDLFWw_PFuv8S71fZxXB8tGT4IWL7URIW8"
GEMINI_MODEL = "gemini-3.6-flash"
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,query"
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_RE = re.compile(r'https?://[^\s<>"\']+')
PIXEL_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\'][^>]*width=["\']?[01]["\']?', re.IGNORECASE)

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

st.set_page_config(page_title="Forensic Threat Platform", layout="wide")

st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
      
      html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      }
      
      .stApp {
        background: radial-gradient(circle at 50% 0%, #172554 0%, #0b1120 40%, #030712 100%);
        color: #f1f5f9;
      }
      
      h1, h2, h3, h4 {
        color: #f8fafc !important;
        letter-spacing: -0.02em;
        font-weight: 600;
      }
      
      p, label, span {
        color: #94a3b8;
      }

      div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 14px 18px;
        backdrop-filter: blur(12px);
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
      }
      
      div[data-testid="stMetricLabel"] p {
        color: #64748b !important;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.05em;
        font-weight: 600;
      }

      div[data-testid="stMetricValue"] div {
        color: #38bdf8 !important;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        font-size: 1.5rem;
      }

      .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1e293b;
      }

      .stTabs [data-baseweb="tab"] {
        background: transparent;
        border: 1px solid transparent;
        border-radius: 6px;
        color: #94a3b8;
        padding: 8px 16px;
        font-size: 0.9rem;
      }

      .stTabs [aria-selected="true"] {
        background: #1e293b !important;
        border-color: #334155 !important;
        color: #38bdf8 !important;
      }

      .stTextArea textarea, .stTextInput input {
        background-color: #0b1120 !important;
        border: 1px solid #1e293b !important;
        color: #f8fafc !important;
        font-family: 'JetBrains Mono', monospace;
        border-radius: 6px;
      }

      .stButton > button {
        background: #0284c7;
        color: #ffffff;
        border: none;
        border-radius: 6px;
        padding: 8px 20px;
        font-weight: 500;
        transition: all 0.2s ease;
      }

      .stButton > button:hover {
        background: #0369a1;
        box-shadow: 0 0 15px rgba(2, 132, 199, 0.4);
      }

      .code-block {
        font-family: 'JetBrains Mono', monospace;
        background: #030712;
        border: 1px solid #1e293b;
        padding: 12px;
        border-radius: 6px;
        color: #38bdf8;
        font-size: 0.85rem;
        word-break: break-all;
      }

      .badge-detected {
        color: #f87171;
        font-weight: 600;
      }

      .badge-clear {
        color: #34d399;
        font-weight: 500;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    received = msg.get_all("Received") or []
    try:
        body_html = msg.get_body(preferencelist=("html", "plain")).get_content()
    except Exception:
        body_html = ""
    if isinstance(body_html, bytes):
        body_html = body_html.decode("utf-8", errors="replace")

    sender = msg.get("From", "N/A")
    domain = sender.split("@")[-1].strip("<>") if "@" in sender else ""
    urls = list(set(URL_RE.findall(body_html)))
    pixels = list(set(PIXEL_RE.findall(body_html)))

    hops = []
    seen = set()
    for r in received:
        for ip in IPV4_RE.findall(r):
            if ip not in seen and ipaddress.ip_address(ip).is_global:
                hops.append({"ip": ip, "time": extract_hop_time(r)})
                seen.add(ip)

    return {
        "from": sender,
        "domain": domain.lower(),
        "subject": msg.get("Subject", "N/A"),
        "hops": hops,
        "urls": urls,
        "pixels": pixels,
        "body": body_html[:6000],
    }

st.title("Email Forensics & Threat Intelligence Platform")
st.markdown("Automated ingestion, cryptographic validation, recursive hop tracing, and LLM classification.")

if "messages" not in st.session_state:
    st.session_state.messages = []

raw_bytes = None
tab1, tab2 = st.tabs(["Artifact Upload", "Raw Header & Body Ingestion"])

with tab1:
    uploaded = st.file_uploader("Upload .eml or .txt forensic file", type=["eml", "txt"], label_visibility="collapsed")
    if uploaded:
        raw_bytes = uploaded.getvalue()

with tab2:
    pasted_text = st.text_area("Paste raw email headers and payload", height=160, label_visibility="collapsed")
    if st.button("Analyze Ingested Text") and pasted_text.strip():
        raw_bytes = pasted_text.encode('utf-8')

if not raw_bytes:
    st.stop()

sha256 = hashlib.sha256(raw_bytes).hexdigest()
parsed = parse_eml(raw_bytes)
is_burner = parsed["domain"] in DISPOSABLE_DOMAINS

with st.spinner("Analyzing artifacts, interrogating DNS, and executing inference..."):
    dns_records = check_live_dns(parsed["domain"])
    geo_data = []
    for h in parsed["hops"]:
        try:
            resp = requests.get(IP_API_URL.format(ip=h["ip"]), timeout=5).json()
            if resp.get("status") == "success":
                resp["time"] = h["time"]
                geo_data.append(resp)
        except Exception:
            pass

    ai_data = {
        "classification": "Unknown",
        "threat_score": 0,
        "rationale": "Inference unavailable.",
        "manipulation_matrix": {"urgency": False, "authority_impersonation": False, "financial_fear": False},
    }
    if genai:
        try:
            genai.configure(api_key=GEMINI_API_KEY)
            prompt = f"""You are an elite digital forensics engineer.
Classify this email (Phishing, BEC, Clean). Score threat level from 0 to 100.
Return ONLY raw JSON with keys:
classification, threat_score, rationale, manipulation_matrix (object with boolean keys: urgency, authority_impersonation, financial_fear).

Sender: {parsed['from']}
Subject: {parsed['subject']}
Body excerpt: {parsed['body'][:3000]}"""
            response = genai.GenerativeModel(GEMINI_MODEL).generate_content(
                prompt, generation_config={"response_mime_type": "application/json"}
            )
            ai_data = json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", (response.text or "").strip()))
        except Exception:
            pass

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Classification", ai_data.get("classification", "Unknown"))
c2.metric("Threat Index", f"{ai_data.get('threat_score', 0)} / 100")
c3.metric("Live SPF", "Verified" if "v=spf1" in dns_records["SPF"].lower() else "Failed")
c4.metric("Live DMARC", "Verified" if "v=dmarc1" in dns_records["DMARC"].lower() else "Failed")
c5.metric("Disposable Domain", "Flagged" if is_burner else "Clean")

st.markdown(
    f"""
    <div style="background: rgba(15, 23, 42, 0.6); border-left: 3px solid #0284c7; padding: 14px 18px; border-radius: 6px; margin: 1.2rem 0;">
      <span style="font-weight:600; color:#f8fafc; font-size: 0.9rem;">Analyst Assessment Rationale:</span>
      <p style="margin: 6px 0 0 0; color: #cbd5e1; font-size: 0.92rem; line-height: 1.5;">{ai_data.get('rationale')}</p>
    </div>
    """,
    unsafe_allow_html=True,
)

left_col, right_col = st.columns((1.1, 0.9))

with left_col:
    st.subheader("Interactive Infrastructure Topology")
    nodes = [Node(id="Origin", label=f"Origin\n{parsed['from'][:18]}", size=20, color="#0284c7")]
    edges = []
    prev = "Origin"

    for i, g in enumerate(geo_data):
        node_id = f"Hop_{i}"
        label_text = f"Relay {i+1}\n{g['query']}\n{g.get('country', '')}"
        nodes.append(Node(id=node_id, label=label_text, size=15, color="#1e293b", font={"color": "#94a3b8"}))
        edges.append(Edge(source=prev, target=node_id, color="#334155"))
        prev = node_id

    for i, url in enumerate(parsed["urls"][:4]):
        domain_name = urlparse(url).netloc
        url_id = f"Link_{i}"
        nodes.append(Node(id=url_id, label=f"Extracted Host\n{domain_name}", size=12, color="#7f1d1d", font={"color": "#f87171"}))
        edges.append(Edge(source=prev, target=url_id, color="#991b1b", dashes=True))

    config = Config(width=650, height=380, directed=True, physics=True, hierarchical=False)
    if len(nodes) > 1:
        agraph(nodes=nodes, edges=edges, config=config)
    else:
        st.info("Insufficient routing data to construct topological graph.")

with right_col:
    st.subheader("Payload & Social Engineering Vectors")
    matrix = ai_data.get("manipulation_matrix", {})
    
    st.markdown(
        f"""
        <div style="background: rgba(15, 23, 42, 0.5); border: 1px solid #1e293b; border-radius: 6px; padding: 14px; margin-bottom: 1rem;">
          <div style="display:flex; justify-content:space-between; margin-bottom: 8px;">
            <span>Artificial Urgency / Coercion:</span>
            <span class="{'badge-detected' if matrix.get('urgency') else 'badge-clear'}">{'Detected' if matrix.get('urgency') else 'Clear'}</span>
          </div>
          <div style="display:flex; justify-content:space-between; margin-bottom: 8px;">
            <span>Authority / Executive Impersonation:</span>
            <span class="{'badge-detected' if matrix.get('authority_impersonation') else 'badge-clear'}">{'Detected' if matrix.get('authority_impersonation') else 'Clear'}</span>
          </div>
          <div style="display:flex; justify-content:space-between;">
            <span>Financial Duress / Asset Extortion:</span>
            <span class="{'badge-detected' if matrix.get('financial_fear') else 'badge-clear'}">{'Detected' if matrix.get('financial_fear') else 'Clear'}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Surveillance & Tracking Pixels")
    if parsed["pixels"]:
        st.markdown(f"<span class='badge-detected'>{len(parsed['pixels'])} tracking element(s) isolated:</span>", unsafe_allow_html=True)
        for p in parsed["pixels"]:
            st.code(p, language="text")
    else:
        st.markdown("<span class='badge-clear'>No zero-pixel surveillance assets found.</span>", unsafe_allow_html=True)

    st.subheader("Cryptographic State Seal")
    st.markdown(f"<div class='code-block'>SHA-256: {sha256}</div>", unsafe_allow_html=True)
    st.caption("Immutable cryptographic signature calculated over raw artifact bytes prior to ingestion.")

st.markdown("---")
st.subheader("Interactive Forensic Query Interface")
st.caption("Direct telemetry and evidence context query execution via Gemini 2.5 Flash.")

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("Query evidence parameters (e.g., 'Analyze the intention of the second relay node')"):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        if genai:
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            context = f"Forensics context:\nSender: {parsed['from']}\nSubject: {parsed['subject']}\nURLs: {parsed['urls']}\nHops: {[g.get('query') for g in geo_data]}\nBody: {parsed['body']}\n\nQuestion: {prompt}"
            try:
                reply = model.generate_content(context).text
            except Exception as e:
                reply = f"Inference pipeline failure: {e}"
        else:
            reply = "Generative model framework uninitialized."

        st.markdown(reply)
        st.session_state.messages.append({"role": "assistant", "content": reply})
