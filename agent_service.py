# SSLAgent service
import os
import time
import json
import logging
import socket
import ssl
import tempfile
from datetime import datetime, timezone

import importlib.util

_HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None

if _HAS_CRYPTO:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import ExtensionOID, NameOID
import urllib.parse
from logging.handlers import TimedRotatingFileHandler

try:
    import requests
except Exception:
    requests = None

CFG_DIR = r"C:\ProgramData\SSLAgent"
CFG_PATH = os.path.join(CFG_DIR, "config.json")
LOG_DIR = os.path.join(CFG_DIR, "log")
CABUNDLE_PATH = os.path.join(CFG_DIR, "ca-bundle.pem")

# --- Agent configuration ---
# Change WP_BASE_URL if the WordPress domain is different.
WP_BASE_URL = "https://kb.macomp.co.il"
POLL_URL = WP_BASE_URL + "/wp-json/ssl-agent/v1/poll"
ACK_URL = WP_BASE_URL + "/wp-json/ssl-agent/v1/ack"
REPORT_URL = WP_BASE_URL + "/wp-json/ssl-agent/v1/report"

# Replace with the exact token from the WordPress plugin.
AGENT_TOKEN = "<PUT_AGENT_TOKEN_HERE>"

DEFAULT_HEADERS = {
    "X-Agent-Token": AGENT_TOKEN,
    "Content-Type": "application/json",
}


def log_setup():
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger("SSLAgent")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        h = TimedRotatingFileHandler(
            os.path.join(LOG_DIR, "agent.log"),
            when="midnight",
            interval=1,
            backupCount=14,
            encoding="utf-8",
        )
        h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(h)
        err_path = os.path.join(LOG_DIR, "service.err.log")
        err_handler = logging.FileHandler(err_path, encoding="utf-8")
        err_handler.setLevel(logging.ERROR)
        err_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(err_handler)
    return logger


log = log_setup()


def load_cfg():
    """Load config.json with UTF-8/BOM support."""
    with open(CFG_PATH, "r", encoding="utf-8-sig") as f:
        c = json.load(f)
    c["server_base"] = c["server_base"].strip().rstrip("/")
    c["token"] = c["token"].strip()
    return c


def sess():
    """Create a requests session, using local CA bundle if exists."""
    if requests is None:
        return None
    s = requests.Session()
    if os.path.isfile(CABUNDLE_PATH):
        s.verify = CABUNDLE_PATH
    return s


def build_api_url(base: str, action: str) -> str:
    """
    Build full API URL for a given action ("poll", "ack", "report")
    Supports:
      - https://example.com/wp-json/ssl-agent/v1
      - https://example.com/?rest_route=/ssl-agent/v1
    """
    if "rest_route=" in base:
        # example: base = "https://site/?rest_route=/ssl-agent/v1"
        before, after = base.split("rest_route=", 1)
        route = after.rstrip("/") + "/" + action
        return f"{before}rest_route={route}"
    # default wp-json style
    return f"{base}/{action}"


def _parse_target(task: dict):
    """
    Decide which host/port/scheme לבדוק.
    """
    ctx = task.get("context") or {}

    # context עשוי להגיע כמחרוזת (למשל 'manual') – להתעלם ולהשתמש ב-site_url
    if isinstance(ctx, str):
        try:
            ctx = json.loads(ctx)
        except Exception:
            ctx = {}
    elif not isinstance(ctx, dict):
        ctx = {}

    host = ctx.get("target_host")
    port = ctx.get("target_port")
    scheme = ctx.get("scheme") or "https"
    site_url = task.get("site_url") or ctx.get("site_url")

    # אם אין host בקונטקסט – נגזור אותו מה-URL
    if not host and site_url:
        u = urllib.parse.urlparse(site_url)
        host = u.hostname
        port = u.port
        if not port:
            port = 443 if (u.scheme or "https") == "https" else 80
        scheme = u.scheme or scheme

    if not host:
        raise ValueError("missing host")
    if not port:
        port = 443

    return host, int(port), scheme, site_url


def _fetch_cert(host: str, port: int, timeout: int = 15) -> dict:
    cert_dict = None
    cert_der = None

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_dict = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
    except ssl.SSLError as e:
        log.warning(
            "TLS verify failed for %s:%s (%s); retrying without certificate verification",
            host,
            port,
            e,
        )
        # ניסיון שני – בלי אימות CA, רק כדי לקרוא תעודה
        insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure_ctx.check_hostname = False
        insecure_ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with insecure_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_dict = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)

    if not isinstance(cert_dict, dict):
        cert_dict = {}

    parsed_cert = None
    parsed_not_after = None
    parsed_cn = ""
    parsed_issuer = ""
    parsed_san = []

    if _HAS_CRYPTO and cert_der:
        try:
            parsed_cert = x509.load_der_x509_certificate(cert_der, default_backend())
            parsed_not_after = parsed_cert.not_valid_after

            cn_attr = parsed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attr:
                parsed_cn = cn_attr[0].value or ""

            issuer_org_attr = parsed_cert.issuer.get_attributes_for_oid(
                NameOID.ORGANIZATION_NAME
            )
            issuer_cn_attr = parsed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if issuer_org_attr:
                parsed_issuer = issuer_org_attr[0].value or ""
            elif issuer_cn_attr:
                parsed_issuer = issuer_cn_attr[0].value or ""
            elif parsed_cert.issuer.rdns:
                # fallback to the first attribute value to avoid empty issuer on unusual certs
                first_attr = parsed_cert.issuer.rdns[0].get_attributes_for_oid(
                    parsed_cert.issuer.rdns[0][0].oid
                )[0].value
                parsed_issuer = first_attr or ""

            try:
                san_ext = parsed_cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                dns_names = san_ext.value.get_values_for_type(x509.DNSName)
                ip_names = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
                parsed_san = dns_names + ip_names
            except x509.ExtensionNotFound:
                parsed_san = []
        except Exception as e:  # pragma: no cover - best-effort parsing
            log.warning("Could not decode certificate for %s:%s (%s)", host, port, e)
    elif not _HAS_CRYPTO and cert_der:
        log.warning(
            "cryptography not installed; install it to enable full certificate parsing"
        )

    not_after = ""
    expiry_ts = 0
    if parsed_not_after:
        dt = parsed_not_after
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        not_after = dt.strftime("%b %d %H:%M:%S %Y %Z")
        expiry_ts = int(dt.timestamp())
    else:
        not_after = cert_dict.get("notAfter") or ""
        if not_after:
            try:
                dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                dt = dt.replace(tzinfo=timezone.utc)
                expiry_ts = int(dt.timestamp())
            except Exception:
                expiry_ts = 0

    def _first_match(seq, *keys):
        for item in seq or []:
            for key, val in item:
                if key in keys and val:
                    return val
        return ""

    cn = parsed_cn or _first_match(cert_dict.get("subject"), "commonName", "CN")
    issuer_name = parsed_issuer or _first_match(
        cert_dict.get("issuer"), "organizationName", "O", "commonName", "CN"
    )

    san = parsed_san
    if not san:
        for t in cert_dict.get("subjectAltName", []):
            if t and len(t) >= 2 and t[1]:
                san.append(t[1])

    return {
        "not_after": not_after,
        "common_name": cn,
        "issuer_name": issuer_name,
        "subject_alt_names": san,
        "expiry_ts": expiry_ts,
    }


def _report_url(base: str, task: dict) -> str:
    """
    קובע את כתובת ה-report.
    אם השרת החזיר callback במשימה – משתמשים בו.
    אחרת: בונים URL מה-base.
    """
    if isinstance(task, dict):
        cb = task.get("callback")
        if cb:
            return cb
    return build_api_url(base, "report")


def _decode_json_dict(response, context):
    try:
        payload = response.json() if response.content else {}
    except Exception as e:
        body_preview = response.text[:500] if hasattr(response, "text") else ""
        log.error("%s error: Could not decode JSON: %s | body=%s", context, e, body_preview)
        return None
    if not isinstance(payload, dict):
        log.error(
            "%s error: payload is not a dict: %r | body=%s",
            context,
            payload,
            response.text[:500] if hasattr(response, "text") else "",
        )
        return None
    return payload


def once():
    s = sess()
    if s is None:
        log.warning("requests module missing; skipping")
        return

    if not DEFAULT_HEADERS.get("X-Agent-Token"):
        log.error("AGENT_TOKEN is not configured; aborting poll cycle")
        return

    # PULL TASKS
    log.info("polling server: %s", POLL_URL)
    try:
        r = s.get(POLL_URL, headers=DEFAULT_HEADERS, params={"limit": 50}, timeout=20)
    except Exception as e:
        log.error("poll error: %s", e)
        return

    if r.status_code == 403:
        log.error("Agent auth failed (403) – לבדוק את AGENT_TOKEN או ה-URL")
        return
    try:
        r.raise_for_status()
    except Exception as e:
        log.warning("poll status=%s error=%s", r.status_code, e)
        return

    payload = _decode_json_dict(r, "poll")
    if payload is None:
        return

    jobs = payload.get("jobs") or payload.get("tasks") or []
    if not isinstance(jobs, list):
        log.warning("poll malformed payload, jobs is not a list: %r", jobs)
        return
    pending = payload.get("pending")
    log.info(
        "poll received jobs=%d pending=%s count=%s",
        len(jobs),
        pending,
        payload.get("count"),
    )
    if not jobs:
        log.info("no jobs returned from poll; pending=%s", pending)
        return

    results = []
    acks = []
    now_iso = datetime.utcnow().isoformat() + "Z"

    for job in jobs:
        if not isinstance(job, dict):
            log.warning("poll job is not a dict: %r", job)
            continue

        job_id = job.get("id") or job.get("post_id")
        post_id = job.get("post_id") or job_id
        queue_id = job.get("queue_id") or job.get("queue_key")
        request_id = job.get("request_id") or ""
        site_url = job.get("site_url") or ""

        if not job_id or not post_id:
            log.warning("job missing id/post_id: %r", job)
            continue

        try:
            host, port, scheme, site_url = _parse_target(job)
            cert = _fetch_cert(host, port)
            expiry_ts_val = cert.get("expiry_ts") or cert.get("expiryts")
            try:
                expiry_ts_val = int(expiry_ts_val)
            except Exception:
                expiry_ts_val = 0
            if expiry_ts_val < 1000000000:
                expiry_ts_val = 0

            status = "ok" if expiry_ts_val > 0 else "error"
            error_message = "" if status == "ok" else "missing expiry_ts"
            if status == "error":
                log.warning(
                    "job %s missing/invalid expiry (host=%s): %r",
                    job_id,
                    host,
                    cert,
                )

            res = {
                "id": job_id,
                "post_id": post_id,
                "queue_id": queue_id,
                "site_url": site_url,
                "client_name": job.get("client_name", ""),
                "request_id": request_id,
                "expiry_ts": expiry_ts_val if status == "ok" else None,
                "common_name": cert.get("common_name", ""),
                "issuer_name": cert.get("issuer_name", ""),
                "status": status,
                "error": error_message,
                "executed_at": now_iso,
                "source": "agent",
            }
            results.append(res)
        except Exception as e:
            log.exception("failed processing job id=%s", job_id)
            results.append(
                {
                    "id": job_id,
                    "post_id": post_id,
                    "queue_id": queue_id,
                    "site_url": site_url,
                    "client_name": job.get("client_name", ""),
                    "request_id": request_id,
                    "expiry_ts": None,
                    "common_name": "",
                    "issuer_name": "",
                    "status": "error",
                    "error": str(e),
                    "executed_at": now_iso,
                    "source": "agent",
                }
            )

        acks.append({"id": job_id, "request_id": request_id})

    if acks:
        try:
            ack_resp = s.post(
                ACK_URL,
                headers=DEFAULT_HEADERS,
                json={"tasks": acks},
                timeout=10,
            )
            if ack_resp.status_code == 403:
                log.error("Agent auth failed (403) – לבדוק את AGENT_TOKEN או ה-URL")
                return
            if ack_resp.status_code != 200:
                log.warning("ack status=%s body=%s", ack_resp.status_code, ack_resp.text[:500])
            else:
                log.info("acknowledged %d tasks", len(acks))
        except Exception as e:
            log.error("ack error: %s", e)

    if results:
        results_payload = {
            "results": [
                {
                    "id": r.get("id"),
                    "post_id": r.get("post_id"),
                    "queue_id": r.get("queue_id"),
                    "site_url": r.get("site_url"),
                    "client_name": r.get("client_name", ""),
                    "request_id": r.get("request_id", ""),
                    "expiry_ts": r.get("expiry_ts"),
                    "common_name": r.get("common_name", ""),
                    "issuer_name": r.get("issuer_name", ""),
                    "status": r.get("status"),
                    "error": r.get("error", ""),
                    "executed_at": r.get("executed_at"),
                    "source": "agent",
                    "queue_key": r.get("queue_id"),
                }
                for r in results
            ]
        }

        try:
            rr = s.post(
                REPORT_URL,
                headers=DEFAULT_HEADERS,
                json=results_payload,
                timeout=20,
            )
            if rr.status_code == 403:
                log.error("Agent auth failed (403) – לבדוק את AGENT_TOKEN או ה-URL")
                return
            if rr.status_code != 200:
                log.warning("report status=%s body=%s", rr.status_code, rr.text[:500])
            else:
                log.info("report succeeded with status=%s", rr.status_code)
        except Exception as e:
            log.error("report error: %s", e)


def main():
    log.info("SSLAgent service starting")
    while True:
        try:
            once()
        except Exception:
            log.exception("loop error")
        time.sleep(60)


if __name__ == "__main__":
    main()
