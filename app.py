import hashlib
import ipaddress
import json
import re
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser

import requests
import streamlit as st
from streamlit_agraph import agraph, Node, Edge, Config

try:
    import google.generativeai as genai
except ImportError:
    genai = None

GEMINI_API_KEY = "AIzaSyDLFWw_PFuv8S71fZxXB8tGT4IWL7URIW8"
GEMINI_MODEL = "gemini-2.5-flash"
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_RE = re.compile(r'https?://[^\s<>"\']+')
PIXEL_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\'][^>]*width=["\']?[01]["\']?', re.IGNORECASE)

st.set_page_config(page_title="Interactive Email Forensics", page_icon="🕵️", layout="wide")

# Bright, warm, grainy cinematic aesthetic
st.markdown(
    """
    <style>
      .stApp { 
        background-color: #fcf8f2;
        background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.08'/%3E%3C/svg%3E");
        color: #451a03; 
      }
      div[data-testid="stMetric"] { background: #fef3c7; border: 1px solid #d97706; border-radius: 8px; padding: 12px; }
      h1, h2, h3, p, span { color: #451a03 !important; }
    </style>
    """, unsafe_allow_html=True
)

def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    received = msg.get_all("Received") or []
    try: 
        body_html = msg.get_body(preferencelist=("html", "plain")).get_content()
    except: 
        body_html = ""
    if isinstance(body_html, bytes): body_html = body_html.decode("utf-8", errors="replace")
    
    sender = msg.get("From", "N/A")
    urls = list(set(URL_RE.findall(body_html)))
    pixels = list(set(PIXEL_RE.findall(body_html)))
    
    hops = []
    seen = set()
    for r in received:
        for ip in IPV4_RE.findall(r):
            if ip not in seen and ipaddress.ip_address(ip).is_global:
                hops.append(ip)
                seen.add(ip)
                
    return {
        "from": sender, "subject": msg.get("Subject", "N/A"),
        "hops": hops, "urls": urls, "pixels": pixels, "body": body_html[:6000]
    }

st.title("🕵️ Interactive Threat Intelligence Dashboard")

if "messages" not in st.session_state:
    st.session_state.messages = []

raw_bytes = None
tab1, tab2 = st.tabs(["📁 Upload File", "📝 Paste Raw Email Text"])

with tab1:
    uploaded = st.file_uploader("Upload email artifact (.eml, .txt)", type=["eml", "txt"])
    if uploaded: raw_bytes = uploaded.getvalue()
with tab2:
    pasted_text = st.text_area("Paste the raw email source here:", height=150)
    if st.button("Analyze Pasted Text") and pasted_text.strip():
        raw_bytes = pasted_text.encode('utf-8')

if not raw_bytes: st.stop()

parsed = parse_eml(raw_bytes)
sha256 = hashlib.sha256(raw_bytes).hexdigest()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Routing Hops", str(len(parsed["hops"])))
c2.metric("Extracted Links", str(len(parsed["urls"])))
c3.metric("Surveillance Pixels", str(len(parsed["pixels"])))
c4.metric("Cryptographic State", "Unaltered")

left, right = st.columns((1, 1))

with left:
    st.subheader("Physics-Based Threat Graph")
    nodes = []
    edges = []
    
    # Origin Node
    nodes.append(Node(id="Sender", label="Origin\n" + parsed["from"][:15], size=25, color="#d97706"))
    
    # Hop Nodes
    prev = "Sender"
    for i, ip in enumerate(parsed["hops"]):
        node_id = f"Hop_{i}"
        nodes.append(Node(id=node_id, label=f"Relay Server\n{ip}", size=15, color="#fde68a"))
        edges.append(Edge(source=prev, target=node_id, color="#b45309"))
        prev = node_id
        
    # URL Nodes
    for i, url in enumerate(parsed["urls"][:5]):
        domain = urlparse(url).netloc
        url_id = f"URL_{i}"
        nodes.append(Node(id=url_id, label=f"Payload Link\n{domain}", size=15, color="#ef4444"))
        edges.append(Edge(source=prev, target=url_id, color="#ef4444", dashes=True))
        
    config = Config(width=600, height=400, directed=True, physics=True, hierarchical=False)
    if len(nodes) > 1:
        agraph(nodes=nodes, edges=edges, config=config)
    else:
        st.warning("Not enough data to construct a threat graph.")

with right:
    st.subheader("Surveillance & Tracking Intelligence")
    if parsed["pixels"]:
        st.error(f"🚨 **{len(parsed['pixels'])} Invisible Tracking Pixels Detected!**")
        st.write("These microscopic 1x1 images were hidden in the email to secretly track your IP address and open-times.")
        for p in parsed["pixels"]:
            st.code(p, language="text")
    else:
        st.success("🟢 No invisible tracking pixels detected in the payload.")
        
    st.subheader("Unaltered Evidence Lock")
    st.code(f"SHA-256:\n{sha256}", language="text")

st.write("---")
st.subheader("Interrogate the Evidence (Live AI)")
st.caption("Ask Gemini directly about this specific email's code, intent, or origins.")

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

if prompt := st.chat_input("E.g., 'What does the code in the first link do?'"):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)
        
    with st.chat_message("assistant"):
        if genai:
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel(GEMINI_MODEL)
            context = f"You are a cyber forensics AI. Answer the user's question based strictly on this email data: \nSender: {parsed['from']}\nLinks: {parsed['urls']}\nHops: {parsed['hops']}\nBody: {parsed['body']}\n\nUser Question: {prompt}"
            try:
                response = model.generate_content(context)
                reply = response.text
            except Exception as e:
                reply = f"AI Error: {e}"
        else:
            reply = "Google Generative AI library is not installed."
            
        st.markdown(reply)
        st.session_state.messages.append({"role": "assistant", "content": reply})
