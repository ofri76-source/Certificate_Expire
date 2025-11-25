# SSLAgent service
import os
import time
import json
import logging
import socket
import ssl
from datetime import datetime, timezone
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
    cert = None

    # ניסיון ראשון – אימות מלא
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
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
                cert = ssock.getpeercert()

    if not isinstance(cert, dict):
        cert = {}

    not_after = cert.get("notAfter")

    # Subject (CN)
    subj_list = cert.get("subject") or []
    if subj_list:
        subj = dict(x for x in subj_list[0])
    else:
        subj = {}
    cn = subj.get("commonName") or subj.get("CN") or ""

    # Issuer
    issuer_list = cert.get("issuer") or []
    if issuer_list:
        iss = dict(x for x in issuer_list[0])
    else:
        iss = {}
    issuer_name = iss.get("organizationName") or iss.get("O") or ""

    # SAN
    san = []
    for t in cert.get("subjectAltName", []):
        if t and len(t) >= 2:
            san.append(t[1])

    # expiry
    expiry_ts = 0
    if not_after:
        try:
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            dt = dt.replace(tzinfo=timezone.utc)
            expiry_ts = int(dt.timestamp())
        except Exception:
            expiry_ts = 0

    return {
        "not_after": not_after or "",
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
    c = load_cfg()
    s = sess()
    if s is None:
        log.warning("requests module missing; skipping")
        return

    hdr = {"X-Agent-Token": c["token"], "Content-Type": "application/json"}

    # PULL TASKS
    poll_url = build_api_url(c["server_base"], "poll")
    log.info("polling server: %s", poll_url)
    try:
        r = s.get(poll_url, headers=hdr, timeout=20)
    except Exception as e:
        log.error("poll error: %s", e)
        return

    if r.status_code != 200:
        log.warning("poll status=%s", r.status_code)
        return

    payload = _decode_json_dict(r, "poll")
    if payload is None:
        return

    tasks = payload.get("tasks") or payload.get("jobs") or []
    if not isinstance(tasks, list):
        log.warning("poll malformed payload, tasks is not a list: %r", tasks)
        return
    pending = payload.get("pending")
    log.info(
        "poll received tasks=%d pending=%s count=%s",
        len(tasks),
        pending,
        payload.get("count"),
    )
    if not tasks:
        log.info("no tasks returned from poll; pending=%s", pending)
        return

    results = []
    acks = []
    now = datetime.now(timezone.utc)

    now_iso = now.isoformat() + "Z"

    for t in tasks:
        if not isinstance(t, dict):
            log.warning("poll task is not a dict: %r", t)
            continue
        queue_id = t.get("queue_id") or t.get("id")
        tid = t.get("post_id") or t.get("id")
        rid = t.get("request_id") or ""
        if not tid:
            continue

        try:
            host, port, scheme, site_url = _parse_target(t)
            if scheme.lower() != "https" and port != 443:
                raise ValueError(f"non-https port={port}")

            cert = _fetch_cert(host, port)
            log.info(
                "processing task id=%s queue_id=%s host=%s port=%s scheme=%s",
                tid,
                queue_id,
                host,
                port,
                scheme,
            )
            expiry_ts_val = cert.get("expiry_ts") or cert.get("expiryts") or cert.get("not_after")
            try:
                expiry_ts_val = int(expiry_ts_val)
            except Exception:
                expiry_ts_val = 0
            if expiry_ts_val < 1000000000:
                expiry_ts_val = 0
            status = "ok" if expiry_ts_val > 0 else "error"
            if status == "error":
                log.warning("task %s missing/invalid expiry (host=%s): %r", tid, host, cert)

            res = {
                "id": tid,
                "post_id": tid,
                "queue_id": queue_id,
                "request_id": rid,
                "site_url": site_url or "",
                "check_name": "tls_expiry",
                "status": status,
                "error": None if status == "ok" else "missing expiry_ts",
                "latency_ms": None,  # ניתן להוסיף מדידת זמן אם תרצה
                "executed_at": now_iso,
                "source": "agent",
                "initiator": "poll",
                "target_host": host,
                "target_port": port,
                "scheme": scheme,
                "expiryts": expiry_ts_val,
                "expiry_ts": expiry_ts_val,
                "expiry": expiry_ts_val,
                "notafter": cert.get("not_after") or "",
                **cert,
            }
            results.append(res)

        except Exception as e:
            ctx = t.get("context") or {}
            if isinstance(ctx, str):
                try:
                    ctx = json.loads(ctx)
                except Exception:
                    ctx = {}
            elif not isinstance(ctx, dict):
                ctx = {}

            res = {
                "id": tid,
                "post_id": tid,
                "queue_id": queue_id,
                "request_id": rid,
                "site_url": t.get("site_url") or "",
                "check_name": "tls_expiry",
                "status": "error",
                "error": str(e),
                "executed_at": now_iso,
                "source": "agent",
                "initiator": "poll",
                "target_host": ctx.get("target_host"),
                "target_port": ctx.get("target_port"),
                "scheme": ctx.get("scheme") or "https",
                "expiry_ts": 0,
                "not_after": "",
                "common_name": "",
                "issuer_name": "",
                "subject_alt_names": [],
            }
            results.append(res)

        acks.append({"id": tid, "request_id": rid})

    # ACK
    try:
        ack_url = build_api_url(c["server_base"], "ack")
        ack_resp = s.post(ack_url, headers=hdr, json={"tasks": acks}, timeout=20)
        if ack_resp.status_code != 200:
            log.warning("ack status=%s body=%s", ack_resp.status_code, ack_resp.text[:500])
        else:
            log.info("acknowledged %d tasks", len(acks))
    except Exception as e:
        log.error("ack error: %s", e)

    # REPORT
    try:
        report_task = next((t for t in tasks if isinstance(t, dict)), None)
        report_url = _report_url(c["server_base"], report_task)
        log.info("reporting to %s", report_url)
        log.info(
            "reporting %d results: %s",
            len(results),
            [
                {
                    "id": r.get("id"),
                    "expiryts": r.get("expiryts"),
                    "expiry": r.get("expiry"),
                    "status": r.get("status"),
                }
                for r in results
            ],
        )
        rr = s.post(report_url, headers=hdr, json={"results": results}, timeout=30)
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
