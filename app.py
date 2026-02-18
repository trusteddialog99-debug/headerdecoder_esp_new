import streamlit as st
import pandas as pd
import tempfile
import os
import re
from email.utils import parseaddr
from email.header import decode_header
import olefile

st.set_page_config(page_title="MSG/EML Header Analyzer (final)", layout="wide")

st.title("MSG / EML Header Analyzer – final")
st.markdown("""
Extrahiert aus den Internet-Headern (MSG/EML):
- Bis zu zwei DKIM-Signaturen (d=, s=, i=)
- From-Domain
- Return-Path-Domain
- Authentication-Results (DKIM pass prüfen)
- Striktes DKIM-Alignment (Exact match zwischen d= und From/Return-Path)

Hinweis: Für MSG-Dateien lesen wir die OLE-Stream-Namen
`__substg1.0_007D001F` (Unicode) oder `__substg1.0_007D001E` (ASCII).
""")

def decode_mime_words(s):
    # decode RFC2047 encoded words, keep as string
    parts = decode_header(s)
    out = ""
    for bytes_part, encoding in parts:
        if isinstance(bytes_part, bytes):
            try:
                out += bytes_part.decode(encoding or "utf-8", errors="ignore")
            except:
                out += bytes_part.decode("latin1", errors="ignore")
        else:
            out += bytes_part
    return out

def extract_from_eml(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except:
        text = raw.decode("latin1", errors="ignore")
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    return parts[0] if parts else text

def extract_from_msg(path: str) -> str | None:
    try:
        ole = olefile.OleFileIO(path)
    except Exception:
        return None

    candidates = []
    for entry in ole.listdir(streams=True, storages=False):
        name = "/".join(entry)
        if "007D001F" in name.upper() or "007D001E" in name.upper():
            try:
                data = ole.openstream(entry).read()
                candidates.append((name, data))
            except Exception:
                continue

    for try_name in ("__substg1.0_007D001F", "__substg1.0_007D001E"):
        if ole.exists(try_name):
            try:
                data = ole.openstream(try_name).read()
                candidates.insert(0, (try_name, data))
            except Exception:
                pass

    ole.close()

    if not candidates:
        return None

    for name, data in candidates:
        if "001F" in name.upper():
            try:
                text = data.decode("utf-16-le", errors="ignore")
                return text
            except Exception:
                pass

    for name, data in candidates:
        for enc in ("utf-8", "latin1", "cp1252"):
            try:
                text = data.decode(enc, errors="ignore")
                return text
            except Exception:
                continue

    return None

def parse_headers(headers: str) -> dict:
    # Initialize defaults
    result = {
        "dkim_domain_1": "-",
        "dkim_selector_1": "-",
        "dkim_itag_1": "-",
        "dkim_domain_2": "-",
        "dkim_selector_2": "-",
        "dkim_itag_2": "-",
        "email_versandtool": "Unbekannt",
        "from_domain": "-",
        "returnpath_domain": "-",
        "dkim_auth_result": "nicht vorhanden",
        "dkim_alignment": "kein Alignment",
        "headers_found": "yes" if headers else "no"
    }
    if not headers:
        return result

    # unfold folded headers (replace CRLF + whitespace with single space)
    normalized = re.sub(r"(\r?\n)[ \t]+", " ", headers)

    # Extract all DKIM-Signature blocks (handles folded lines)
    dkim_blocks = re.findall(r"(?mi)^dkim-signature:\s*(.+?)(?=\r?\n[^ \t]|$)", normalized, flags=re.S)

    def extract_from_block(block):
        d = re.search(r"\bd=([^;\s]+)", block, flags=re.I)
        s = re.search(r"\bs=([^;\s]+)", block, flags=re.I)
        i = re.search(r"\bi=([^;\s]+)", block, flags=re.I)
        return (d.group(1).strip().strip('"') if d else "-",
                s.group(1).strip().strip('"') if s else "-",
                i.group(1).strip().strip('"') if i else "-")

    if dkim_blocks:
        ex1 = extract_from_block(dkim_blocks[0])
        result["dkim_domain_1"], result["dkim_selector_1"], result["dkim_itag_1"] = ex1
        if len(dkim_blocks) > 1:
            ex2 = extract_from_block(dkim_blocks[1])
            result["dkim_domain_2"], result["dkim_selector_2"], result["dkim_itag_2"] = ex2

    # Lookup email sending tool (DKIM selector -> provider)
    def lookup_dkim_selector(sel: str) -> str:
        if not sel or sel == "-":
            return "Unbekannt"
        s = sel.lower()
        # common known selectors / substrings mapped to providers
        mapping = {
            "amazonses": "Amazon SES",
            "ses": "Amazon SES",
            "sendgrid": "SendGrid",
            "sg": "SendGrid",
            "mailgun": "Mailgun",
            "mg": "Mailgun",
            "mandrill": "Mandrill (Mailchimp)",
            "mailchimp": "Mailchimp",
            "google": "Google Workspace / Gmail",
            "google._domainkey": "Google Workspace / Gmail",
            "selector1": "Microsoft / Office 365",
            "selector2": "Microsoft / Office 365",
            "selector3": "Microsoft / Office 365",
            "scph": "SparkPost",
            "sparkpost": "SparkPost",
            "smtpapi": "SparkPost",
            "postmark": "Postmark",
            "pm": "Postmark",
            "yandex": "Yandex.Mail",
            "zoho": "Zoho Mail",
            "sendinblue": "Sendinblue (Brevo)",
            "brevo": "Sendinblue (Brevo)",
            "postfix": "Postfix (generic)",
            "exclaimer": "Exclaimer",
            "mailjet": "Mailjet",
            "elasticemail": "Elastic Email",
            "mailerlite": "MailerLite",
            "smtp2go": "SMTP2GO",
            "sendpulse": "SendPulse",
            "mailerlite": "MailerLite",
            "mailpoet": "MailPoet",
            "mailrelay": "Mailrelay",
            "sendwithus": "SendWithUs",
            "constantcontact": "Constant Contact",
            "salesforce": "Salesforce",
            "pardot": "Pardot (Salesforce)",
            "infusionsoft": "Keap/Infusionsoft",
            "campaignmonitor": "Campaign Monitor",
            "dotmailer": "dotmailer",
            "rackspace": "Rackspace Email",
            "gandi": "Gandi Mail",
            "ovh": "OVH Mail",
            "mailhost": "Generic Mail Host",
            "smtp": "Generic SMTP",
            "spf": "(not a selector)",
        }
        for k, v in mapping.items():
            if k in s:
                return v
        # fallback heuristics: timestamps or hex-like selectors are not mapped
        return "Unbekannt"

    # prefer first DKIM selector that yields a known provider
    provider = "Unbekannt"
    for sel in (result["dkim_selector_1"], result["dkim_selector_2"]):
        if sel and sel != "-":
            found = lookup_dkim_selector(sel)
            if found != "Unbekannt":
                provider = found
                break
    result["email_versandtool"] = provider

    # Authentication-Results DKIM pass check
    auth = re.search(r"(?mi)^authentication-results:\s*(.+)$", normalized, flags=re.M)
    if auth:
        auth_block = auth.group(1)
        if re.search(r"dkim\s*=\s*pass", auth_block, flags=re.I):
            result["dkim_auth_result"] = "pass"
        else:
            if re.search(r"dkim\s*=", auth_block, flags=re.I):
                result["dkim_auth_result"] = "fail"
            else:
                result["dkim_auth_result"] = "nicht vorhanden"

    # From header (may contain encoded words)
    fm = re.search(r"(?mi)^from:\s*(.+)$", normalized, flags=re.M)
    if fm:
        raw_from = fm.group(1).strip()
        decoded_from = decode_mime_words(raw_from)
        _, addr = parseaddr(decoded_from)
        if "@" in addr:
            result["from_domain"] = addr.split("@",1)[1].lower()

    # Return-Path
    rp = re.search(r"(?mi)^return-path:\s*(.+)$", normalized, flags=re.M)
    if rp:
        rp_raw = rp.group(1).strip()
        m = re.search(r"<([^>]+)>", rp_raw)
        if m:
            addr = m.group(1)
        else:
            _, addr = parseaddr(rp_raw)
        if "@" in addr:
            result["returnpath_domain"] = addr.split("@",1)[1].lower()

    # DKIM Alignment (strict exact match)
    fd = result["from_domain"]
    rp = result["returnpath_domain"]
    dd1 = result["dkim_domain_1"]
    dd2 = result["dkim_domain_2"]
    for dd in (dd1, dd2):
        if dd and dd != "-" and (dd.lower() == fd.lower() or dd.lower() == rp.lower()):
            result["dkim_alignment"] = "ja"
            break

    return result

uploaded_files = st.file_uploader(
    "MSG- oder EML-Dateien hochladen",
    type=["msg", "eml"],
    accept_multiple_files=True
)

if uploaded_files:
    results = []
    for up in uploaded_files:
        if up.name.lower().endswith(".eml"):
            raw = up.read()
            headers = extract_from_eml(raw)
        else:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                tmp.write(up.read())
                tmp_path = tmp.name
            headers = extract_from_msg(tmp_path)
            try:
                os.remove(tmp_path)
            except Exception:
                pass

        parsed = parse_headers(headers or "")
        row = {"filename": up.name, **parsed}
        results.append(row)

    df = pd.DataFrame(results)
    cols = ["filename",
            "dkim_domain_1","dkim_selector_1","dkim_itag_1",
            "dkim_domain_2","dkim_selector_2","dkim_itag_2",
            "from_domain","returnpath_domain",
            "dkim_auth_result","dkim_alignment","email_versandtool","headers_found"]
    df = df.reindex(columns=[c for c in cols if c in df.columns])
    st.subheader("Analyse-Ergebnisse")
    st.dataframe(df)

    st.download_button(
        "CSV herunterladen",
        df.to_csv(index=False).encode("utf-8"),
        "header_analysis.csv",
        "text/csv"
    )
else:
    st.info("Bitte MSG- oder EML-Dateien hochladen…")
