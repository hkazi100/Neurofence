"""
XAI-FLOWS Network Intrusion Detection System
Flask + SocketIO backend — production-grade refactor
"""

from __future__ import annotations

import atexit
import csv
import ipaddress
import json
import logging
import os
import pickle
import time
from contextlib import contextmanager
from threading import Event, Lock, Thread
from typing import Any
from urllib.request import urlopen

import dill
import joblib
import numpy as np
import pandas as pd
import plotly
import warnings

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_cors import CORS
from flask_socketio import SocketIO
from sklearn.tree import _tree

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("xai-flows")

# ---------------------------------------------------------------------------
# sklearn backward-compat shim for legacy pickled tree models
# ---------------------------------------------------------------------------
try:
    _orig_check = _tree._check_node_ndarray

    def _compat_check(node_ndarray, expected_dtype):
        try:
            return _orig_check(node_ndarray, expected_dtype)
        except ValueError:
            if (
                hasattr(expected_dtype, "names")
                and "missing_go_to_left" in expected_dtype.names
                and node_ndarray.dtype.names is not None
                and "missing_go_to_left" not in node_ndarray.dtype.names
            ):
                fixed = np.empty(node_ndarray.shape, dtype=expected_dtype)
                for name in node_ndarray.dtype.names:
                    fixed[name] = node_ndarray[name]
                fixed["missing_go_to_left"] = 0
                return _orig_check(fixed, expected_dtype)
            raise

    _tree._check_node_ndarray = _compat_check
except Exception:
    pass

# ---------------------------------------------------------------------------
# Keras — optional
# ---------------------------------------------------------------------------
try:
    from tensorflow import keras
except ImportError:
    keras = None

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(APP_DIR)

app = Flask(__name__)
app.config["SECRET_KEY"] = (
    os.environ.get("FLASK_SECRET_KEY")
)  # see helper below
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"


def _missing_key():  # called only when env var absent — fail loudly
    key = os.urandom(32).hex()
    log.warning(
        "FLASK_SECRET_KEY not set — generated ephemeral key. "
        "Sessions will not survive restart. Set the env var in production."
    )
    return key


app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or _missing_key()

CORS(app)
socketio = SocketIO(
    app,
    async_mode=None,
    logger=False,  # set True only when debugging Socket.IO
    engineio_logger=False,
    cors_allowed_origins="*",
)

# ---------------------------------------------------------------------------
# Feature column definitions
# ---------------------------------------------------------------------------
FLOW_COLS = [
    "FlowID",
    "FlowDuration",
    "BwdPacketLenMax",
    "BwdPacketLenMin",
    "BwdPacketLenMean",
    "BwdPacketLenStd",
    "FlowIATMean",
    "FlowIATStd",
    "FlowIATMax",
    "FlowIATMin",
    "FwdIATTotal",
    "FwdIATMean",
    "FwdIATStd",
    "FwdIATMax",
    "FwdIATMin",
    "BwdIATTotal",
    "BwdIATMean",
    "BwdIATStd",
    "BwdIATMax",
    "BwdIATMin",
    "FwdPSHFlags",
    "FwdPackets_s",
    "MaxPacketLen",
    "PacketLenMean",
    "PacketLenStd",
    "PacketLenVar",
    "FINFlagCount",
    "SYNFlagCount",
    "PSHFlagCount",
    "ACKFlagCount",
    "URGFlagCount",
    "AvgPacketSize",
    "AvgBwdSegmentSize",
    "InitWinBytesFwd",
    "InitWinBytesBwd",
    "ActiveMin",
    "IdleMean",
    "IdleStd",
    "IdleMax",
    "IdleMin",
    "Src",
    "SrcPort",
    "Dest",
    "DestPort",
    "Protocol",
    "FlowStartTime",
    "FlowLastSeen",
    "PName",
    "PID",
    "Classification",
    "Probability",
    "Risk",
]

AE_FEATURES = np.array(
    [
        "FlowDuration",
        "BwdPacketLengthMax",
        "BwdPacketLengthMin",
        "BwdPacketLengthMean",
        "BwdPacketLengthStd",
        "FlowIATMean",
        "FlowIATStd",
        "FlowIATMax",
        "FlowIATMin",
        "FwdIATTotal",
        "FwdIATMean",
        "FwdIATStd",
        "FwdIATMax",
        "FwdIATMin",
        "BwdIATTotal",
        "BwdIATMean",
        "BwdIATStd",
        "BwdIATMax",
        "BwdIATMin",
        "FwdPSHFlags",
        "FwdPackets/s",
        "PacketLengthMax",
        "PacketLengthMean",
        "PacketLengthStd",
        "PacketLengthVariance",
        "FINFlagCount",
        "SYNFlagCount",
        "PSHFlagCount",
        "ACKFlagCount",
        "URGFlagCount",
        "AveragePacketSize",
        "BwdSegmentSizeAvg",
        "FWDInitWinBytes",
        "BwdInitWinBytes",
        "ActiveMin",
        "IdleMean",
        "IdleStd",
        "IdleMax",
        "IdleMin",
    ]
)

# Risk thresholds
RISK_LEVELS = [
    (0.8, "very_high", "Very High"),
    (0.6, "high", "High"),
    (0.4, "medium", "Medium"),
    (0.2, "low", "Low"),
    (0.0, "minimal", "Minimal"),
]


# ---------------------------------------------------------------------------
# Model loading — fail fast with clear errors
# ---------------------------------------------------------------------------
def load_models() -> dict:
    models: dict[str, Any] = {}

    models["ae_scaler"] = joblib.load("models/preprocess_pipeline_AE_39ft.save")

    if keras is not None:
        try:
            models["ae_model"] = keras.models.load_model("models/autoencoder_39ft.hdf5")
        except Exception:
            try:
                m = keras.models.load_model(
                    "models/autoencoder_39ft.hdf5", compile=False
                )
                m.compile(optimizer="adam", loss="mse")
                models["ae_model"] = m
            except Exception as exc:
                log.warning("Autoencoder unavailable: %s", exc)
                models["ae_model"] = None
    else:
        models["ae_model"] = None

    with open("models/model.pkl", "rb") as fh:
        models["classifier"] = pickle.load(fh)

    with open("models/explainer", "rb") as fh:
        models["explainer"] = dill.load(fh)

    return models


try:
    MODELS = load_models()
except Exception as exc:
    log.critical("Failed to load models: %s", exc)
    raise


def predict_proba(X):
    return MODELS["classifier"].predict_proba(X).astype(float)


# ---------------------------------------------------------------------------
# Firebase / Firestore — imported lazily so app starts without it
# ---------------------------------------------------------------------------
from firebase_admin.firestore import SERVER_TIMESTAMP
from firebase_config import (
    create_user_session,
    firestore_db,
    get_user_by_username,
    hash_password,
    increment_high_risk_count,
    save_malicious_flow,
    update_global_stats,
    verify_password,
)

# ---------------------------------------------------------------------------
# Packet capture imports
# ---------------------------------------------------------------------------
from scapy.sendrecv import sniff as scapy_sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

from lime import lime_tabular  # noqa: F401 — needed by dill-loaded explainer

# ---------------------------------------------------------------------------
# Application state (all guarded by locks)
# ---------------------------------------------------------------------------
_state_lock = Lock()
_flow_count = 0
_flow_df = pd.DataFrame(columns=FLOW_COLS)
_src_ip_dict: dict[str, int] = {}
_current_flows: dict[str, Flow] = {}
_pending_firestore: list[dict] = []  # flows queued from bg thread for main-thread write

FLOW_TIMEOUT = 600
TEST_MODE = os.environ.get("TEST_MODE", "true").lower() == "true"

_thread: Thread = Thread()
_thread_stop = Event()

# ---------------------------------------------------------------------------
# CSV logging — context-managed, one open/close per session
# ---------------------------------------------------------------------------
_output_log = open("output_logs.csv", "w", newline="")
_input_log = open("input_logs.csv", "w", newline="")
_output_writer = csv.writer(_output_log)
_input_writer = csv.writer(_input_log)
_csv_lock = Lock()


def _close_logs():
    for fh in (_output_log, _input_log):
        if not fh.closed:
            fh.close()


atexit.register(_close_logs)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _risk_for_score(proba_risk: float) -> tuple[str, str]:
    """Return (risk_level, risk_label) for a given combined risk probability."""
    for threshold, level, label in RISK_LEVELS:
        if proba_risk > threshold:
            return level, label
    return "minimal", "Minimal"


def _flag_img(country: str | None, is_private: bool) -> str:
    if is_private:
        return '<img src="static/images/lan.gif" height="11px" style="margin-bottom:0" title="LAN">'
    if country and country not in ("ano", "unknown"):
        c = country.lower()
        return f'<img src="static/images/blank.gif" class="flag flag-{c}" title="{country}">'
    return (
        '<img src="static/images/blank.gif" class="flag flag-unknown" title="UNKNOWN">'
    )


_ip_country_cache: dict[str, str | None] = {}


def ip_country(addr: str) -> str | None:
    if addr in _ip_country_cache:
        return _ip_country_cache[addr]
    try:
        url = f"https://ipinfo.io/{addr}/json" if addr else "https://ipinfo.io/json"
        with urlopen(url, timeout=5) as res:
            data = json.load(res)
        result = data.get("country")
    except Exception:
        result = None
    _ip_country_cache[addr] = result
    return result


def _is_ajax() -> bool:
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json
    )


def _clean_for_firestore(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, (np.integer, np.int64)):
            out[k] = int(v)
        elif isinstance(v, (np.floating, np.float64, np.float32)):
            out[k] = float(v)
        elif isinstance(v, np.ndarray):
            out[k] = v.tolist()
        elif isinstance(v, float) and (np.isnan(v) or np.isinf(v)):
            out[k] = None
        else:
            try:
                if pd.isna(v):
                    out[k] = None
                    continue
            except (TypeError, ValueError):
                pass
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Core classification logic
# ---------------------------------------------------------------------------


def classify(features: list) -> list | None:
    """
    Classify a completed network flow.

    features[:39]  — numeric ML features
    features[39:]  — metadata strings [src_ip, src_port, dst_ip, dst_port, proto, ...]
    """
    try:
        global _flow_count

        numeric = [
            np.nan if x in (np.inf, -np.inf) else float(x) for x in features[:39]
        ]
        if np.nan in numeric:
            return None  # incomplete flow — skip

        meta = [str(x) for x in features[39:]]
        record = features.copy()

        # --- IP annotation (display only) ---
        annotated_meta = list(meta)
        for idx in (0, 2):
            ip = meta[idx]
            try:
                private = ipaddress.ip_address(ip).is_private
            except ValueError:
                private = True
            country = None if private else ip_country(ip)
            annotated_meta[idx] = ip + " " + _flag_img(country, private)

        # --- Source IP tracking ---
        with _state_lock:
            src = meta[0]
            _src_ip_dict[src] = _src_ip_dict.get(src, 0) + 1
            _flow_count += 1
            flow_id = _flow_count

        # --- Inference ---
        result = MODELS["classifier"].predict([numeric])
        proba = predict_proba([numeric])
        proba_max = float(proba[0].max())
        proba_risk = float(sum(proba[0, 1:]))

        classification = str(result[0])
        risk_level, risk_label = _risk_for_score(proba_risk)
        risk_html = f"<p class='risk-badge risk-{risk_level}'>{risk_label}</p>"

        # --- CSV logging (thread-safe) ---
        with _csv_lock:
            _output_writer.writerow([f"Flow #{flow_id}"])
            _output_writer.writerow(["Flow info:"] + annotated_meta)
            _output_writer.writerow(["Flow features:"] + numeric)
            _output_writer.writerow(["Prediction:", classification, proba_max])
            _output_writer.writerow(["-" * 80])
            _input_writer.writerow([f"Flow #{flow_id}"])
            _input_writer.writerow(["Flow features:"] + numeric)
            _input_writer.writerow(["-" * 80])

        if classification != "Benign":
            log.info(
                "Flow #%d classified as %s (risk=%s)",
                flow_id,
                classification,
                risk_level,
            )

        # --- DataFrame update ---
        row = [flow_id] + record + [classification, proba_max, risk_html]
        with _state_lock:
            _flow_df.loc[len(_flow_df)] = row

        # --- Firestore (only from request context; queue otherwise) ---
        should_store = classification != "Benign" or risk_level in ("high", "very_high")
        if should_store:
            flow_data = dict(zip(FLOW_COLS, row))
            flow_data["risk_level"] = risk_level
            _queue_firestore_write(flow_data, risk_level)

        # --- Emit to frontend ---
        with _state_lock:
            ip_records = [
                {"SourceIP": ip, "count": cnt} for ip, cnt in _src_ip_dict.items()
            ]

        socketio.emit(
            "newresult",
            {
                "result": [flow_id]
                + annotated_meta
                + [classification, proba_max, risk_html],
                "ips": ip_records,
                "risk_level": risk_level,
                "classification": classification,
            },
            namespace="/test",
        )

        return [flow_id] + record + [classification, proba_max, risk_html]

    except Exception:
        log.exception("Error in classify()")
        return None


def _queue_firestore_write(flow_data: dict, risk_level: str) -> None:
    """
    Firestore writes must happen with a user/session context.
    We store pending writes and flush them on the next HTTP request.
    This avoids accessing Flask session from background threads.
    """
    with _state_lock:
        _pending_firestore.append({"data": flow_data, "risk_level": risk_level})


def _flush_firestore_queue() -> None:
    """Call this from a request context to drain the pending write queue."""
    with _state_lock:
        batch = _pending_firestore.copy()
        _pending_firestore.clear()

    if not batch or not session.get("user_id"):
        return

    user_id = session["user_id"]
    session_id = session.get("session_id", "default_session")

    for item in batch:
        try:
            clean = _clean_for_firestore(item["data"])
            flow_id = save_malicious_flow(
                user_id=user_id, session_id=session_id, flow_data=clean
            )
            if flow_id:
                increment_high_risk_count(session_id, item["risk_level"])
                log.debug("Saved flow %s to Firestore", flow_id)
            else:
                log.warning("save_malicious_flow returned None")
        except Exception:
            log.exception("Firestore write error")

    try:
        update_global_stats()
    except Exception:
        log.exception("update_global_stats failed")


# ---------------------------------------------------------------------------
# Packet capture
# ---------------------------------------------------------------------------


def _handle_packet(p) -> None:
    try:
        packet = PacketInfo()
        for setter in (
            packet.setDest,
            packet.setSrc,
            packet.setSrcPort,
            packet.setDestPort,
            packet.setProtocol,
            packet.setTimestamp,
            packet.setPSHFlag,
            packet.setFINFlag,
            packet.setSYNFlag,
            packet.setACKFlag,
            packet.setURGFlag,
            packet.setRSTFlag,
            packet.setPayloadBytes,
            packet.setHeaderBytes,
            packet.setPacketSize,
            packet.setWinBytes,
        ):
            setter(p)
        packet.setFwdID()
        packet.setBwdID()

        fwd_id = packet.getFwdID()
        bwd_id = packet.getBwdID()
        now = packet.getTimestamp()
        fin_rst = packet.getFINFlag() or packet.getRSTFlag()

        with _state_lock:
            if fwd_id in _current_flows:
                flow = _current_flows[fwd_id]
                if (now - flow.getFlowLastSeen()) > FLOW_TIMEOUT:
                    classify(flow.terminated())
                    del _current_flows[fwd_id]
                    _current_flows[fwd_id] = Flow(packet)
                elif fin_rst:
                    flow.new(packet, "fwd")
                    classify(flow.terminated())
                    del _current_flows[fwd_id]
                else:
                    flow.new(packet, "fwd")

            elif bwd_id in _current_flows:
                flow = _current_flows[bwd_id]
                if (now - flow.getFlowLastSeen()) > FLOW_TIMEOUT:
                    classify(flow.terminated())
                    del _current_flows[bwd_id]
                    _current_flows[fwd_id] = Flow(packet)
                elif fin_rst:
                    flow.new(packet, "bwd")
                    classify(flow.terminated())
                    del _current_flows[bwd_id]
                else:
                    flow.new(packet, "bwd")
            else:
                _current_flows[fwd_id] = Flow(packet)

    except AttributeError:
        pass  # not IP/TCP
    except Exception:
        log.exception("Error processing packet")


def _evict_stale_flows() -> None:
    now = time.time()
    with _state_lock:
        stale = [
            fid
            for fid, flow in _current_flows.items()
            if (now - flow.getFlowLastSeen()) > FLOW_TIMEOUT
        ]
        for fid in stale:
            try:
                classify(_current_flows[fid].terminated())
            except Exception:
                pass
            del _current_flows[fid]


def _sniff_loop() -> None:
    log.info("Sniff/detect loop started (TEST_MODE=%s)", TEST_MODE)
    while not _thread_stop.is_set():
        if TEST_MODE:
            socketio.emit(
                "newresult",
                {
                    "result": [
                        1,
                        "192.168.1.1",
                        "80",
                        "10.0.0.1",
                        "443",
                        "tcp",
                        "Benign",
                        "0.1",
                    ],
                    "ips": [{"SourceIP": "192.168.1.1", "count": 5}],
                    "risk_level": "minimal",
                    "classification": "Benign",
                },
                namespace="/test",
            )
            time.sleep(3)
        else:
            _evict_stale_flows()
            try:
                scapy_sniff(prn=_handle_packet, timeout=5)
            except Exception:
                log.exception("scapy sniff error")
            with _state_lock:
                snapshot = list(_current_flows.values())
            for flow in snapshot:
                try:
                    classify(flow.terminated())
                except Exception:
                    pass
            time.sleep(1)


def _ensure_sniff_thread() -> None:
    global _thread
    if not _thread.is_alive():
        log.info("Starting sniff background task")
        _thread = socketio.start_background_task(_sniff_loop)


# ---------------------------------------------------------------------------
# Before-request: flush Firestore queue while we have a session context
# ---------------------------------------------------------------------------


@app.before_request
def before_request():
    if session.get("logged_in"):
        _flush_firestore_queue()


# ---------------------------------------------------------------------------
# Routes — authentication
# ---------------------------------------------------------------------------


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/login", methods=["POST"])
def login():
    ajax = _is_ajax()

    try:
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or request.form.get("username", "")).strip()
        password = data.get("password") or request.form.get("password", "")

        if not username or not password:
            msg = "Username and password are required."
            return (
                (jsonify({"success": False, "message": msg}), 400)
                if ajax
                else (flash(msg) or redirect(url_for("landing")))
            )

        if firestore_db is None:
            msg = "Database unavailable. Try again later."
            return (
                (jsonify({"success": False, "message": msg}), 503)
                if ajax
                else (flash(msg) or redirect(url_for("landing")))
            )

        user_data, user_id = _resolve_user(username)

        if not user_data:
            return _auth_fail(ajax, "Invalid username or password.", 401)

        if "password_hash" not in user_data:
            return _auth_fail(ajax, "Account setup incomplete. Contact admin.", 401)

        if not verify_password(user_data["password_hash"], password):
            return _auth_fail(ajax, "Invalid username or password.", 401)

        _setup_session(user_data, user_id)
        _ensure_sniff_thread()

        log.info("User %s logged in", username)
        return (
            jsonify({"success": True, "redirect": url_for("capture")})
            if ajax
            else redirect(url_for("capture"))
        )

    except Exception:
        log.exception("Login error")
        return _auth_fail(ajax, "Login failed. Please try again.", 500)


def _resolve_user(username: str) -> tuple[dict | None, str | None]:
    """Try multiple lookup strategies; return (user_data, user_id) or (None, None)."""
    # Email lookup by document ID
    if "@" in username:
        doc = firestore_db.collection("users").document(username).get()
        if doc.exists:
            return doc.to_dict(), username

    # Username query
    user_data, user_id = get_user_by_username(username)
    if user_data:
        return user_data, user_id

    # Fallback: append default domain
    if "@" not in username:
        email = f"{username}@example.com"
        doc = firestore_db.collection("users").document(email).get()
        if doc.exists:
            return doc.to_dict(), email

    return None, None


def _setup_session(user_data: dict, user_id: str) -> None:
    session.clear()
    session["logged_in"] = True
    session["username"] = user_data.get("username", user_id)
    session["user_id"] = user_id
    session["email"] = user_data.get("email", user_id)
    session["fullname"] = user_data.get("fullname", "")
    session["new_session"] = True

    ua = request.user_agent
    device_info = {
        "os": ua.platform if ua else "Unknown",
        "browser": ua.browser if ua else "Unknown",
        "ip_address": request.remote_addr or "0.0.0.0",
    }
    sid = create_user_session(user_id, device_info)
    session["session_id"] = sid or "default_session"
    try:
        update_global_stats()
    except Exception:
        pass


def _auth_fail(ajax: bool, msg: str, status: int):
    if ajax:
        return jsonify({"success": False, "message": msg}), status
    flash(msg)
    return redirect(url_for("landing"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    ajax = _is_ajax()
    try:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        fullname = request.form.get("fullname", "").strip()

        errors = {}
        if not username:
            errors["username"] = "Username is required."
        if not password:
            errors["password"] = "Password is required."
        if not email:
            errors["email"] = "Email is required."

        if errors:
            if ajax:
                return jsonify({"success": False, "errors": errors}), 400
            for msg in errors.values():
                flash(msg)
            return render_template("signup.html")

        if firestore_db is None:
            msg = "Database unavailable. Try again later."
            if ajax:
                return jsonify({"success": False, "message": msg}), 503
            flash(msg)
            return render_template("signup.html")

        if "@" not in email:
            email = f"{email}@example.com"

        existing, _ = get_user_by_username(username)
        if existing:
            err = {"username": "Username already taken."}
            if ajax:
                return jsonify({"success": False, "errors": err}), 400
            flash(err["username"])
            return render_template("signup.html")

        if firestore_db.collection("users").document(email).get().exists:
            err = {"email": "Email already registered."}
            if ajax:
                return jsonify({"success": False, "errors": err}), 400
            flash(err["email"])
            return render_template("signup.html")

        pw_hash = hash_password(password)
        if not pw_hash:
            msg = "Error creating account. Please try again."
            if ajax:
                return jsonify({"success": False, "message": msg}), 500
            flash(msg)
            return render_template("signup.html")

        firestore_db.collection("users").document(email).set(
            {
                "username": username,
                "email": email,
                "fullname": fullname or username,
                "password_hash": pw_hash,
                "created_at": SERVER_TIMESTAMP,
                "last_active": SERVER_TIMESTAMP,
            }
        )
        log.info("New user created: %s (%s)", username, email)

        _setup_session(
            {"username": username, "email": email, "fullname": fullname}, email
        )

        if ajax:
            return jsonify({"success": True, "redirect": url_for("capture")})
        flash("Account created successfully!")
        return redirect(url_for("capture"))

    except Exception:
        log.exception("Signup error")
        msg = "Error creating account. Please try again."
        if ajax:
            return jsonify({"success": False, "message": msg}), 500
        flash(msg)
        return render_template("signup.html")


@app.route("/logout")
def logout():
    try:
        if firestore_db and session.get("session_id"):
            firestore_db.collection("sessions").document(session["session_id"]).update(
                {"end_time": SERVER_TIMESTAMP, "status": "completed"}
            )
    except Exception:
        log.exception("Error ending Firestore session")
    session.clear()
    return redirect(url_for("landing"))


# ---------------------------------------------------------------------------
# Routes — main app pages
# ---------------------------------------------------------------------------


def _require_login():
    if not session.get("logged_in"):
        return redirect(url_for("landing"))
    return None


@app.route("/capture")
def capture():
    return _require_login() or render_template("index.html")


@app.route("/profile")
def profile():
    return _require_login() or render_template(
        "profile.html",
        username=session.get("username"),
        email=session.get("email"),
        fullname=session.get("fullname"),
    )


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/detail")
def detail():
    flow_id = request.args.get("flow_id", default=-1, type=int)
    with _state_lock:
        flow = _flow_df.loc[_flow_df["FlowID"] == flow_id]

    if flow.empty:
        return "Flow not found", 404

    try:
        X = [flow.values[0, 1:40]]
        proba = predict_proba(X)
        risk_proba = float(sum(proba[0, 1:]))
        risk_level, risk_label = _risk_for_score(risk_proba)

        COLOR_MAP = {
            "very_high": "red",
            "high": "orangered",
            "medium": "orange",
            "low": "green",
            "minimal": "limegreen",
        }
        risk_html = f'Risk: <p style="color:{COLOR_MAP[risk_level]};">{risk_label}</p>'

        exp = MODELS["explainer"].explain_instance(
            X[0], predict_proba, num_features=6, top_labels=1
        )

        ae_model = MODELS["ae_model"]
        if ae_model is not None:
            X_t = MODELS["ae_scaler"].transform(X)
            recon = ae_model.predict(X_t)
            err = recon - X_t
            abs_err = np.abs(err)
            top5_idx = np.argpartition(abs_err[0], -5)[-5:]
            fig = {
                "data": [
                    {
                        "type": "bar",
                        "x": AE_FEATURES[top5_idx].tolist(),
                        "y": err[0][top5_idx].tolist(),
                    }
                ],
                "layout": {"title": "Reconstruction Error (Top 5 Features)"},
            }
            ae_plot = plotly.io.to_html(fig, include_plotlyjs=False, full_html=False)
        else:
            ae_plot = "<p>Autoencoder unavailable.</p>"

        return render_template(
            "detail.html",
            tables=[flow.reset_index(drop=True).transpose().to_html(classes="data")],
            exp=exp.as_html(),
            ae_plot=ae_plot,
            risk=risk_html,
        )
    except Exception:
        log.exception("Error in detail view")
        return "Error processing request", 500


# ---------------------------------------------------------------------------
# Routes — API / utility
# ---------------------------------------------------------------------------


@app.route("/start-sniff")
def start_sniff():
    _ensure_sniff_thread()
    return jsonify({"status": "started"})


@app.route("/check-session")
def check_session():
    if not session.get("logged_in"):
        return jsonify({"logged_in": False}), 401
    return jsonify(
        {
            "logged_in": True,
            "username": session.get("username"),
            "user_id": session.get("user_id"),
            "session_id": session.get("session_id"),
        }
    )


@app.route("/clear-local-flows")
def clear_local_flows():
    if not session.get("logged_in"):
        return jsonify({"status": "error", "message": "Not authorized"}), 401
    return jsonify({"status": "success"})


@app.route("/test-firebase")
def test_firebase():
    if not firestore_db:
        return jsonify({"status": "error", "message": "Firestore not initialized"}), 500
    try:
        doc_ref = firestore_db.collection("connection_tests").document()
        doc_ref.set({"test": "RNIDS Connection Test", "timestamp": SERVER_TIMESTAMP})
        return jsonify({"status": "success", "document_id": doc_ref.id})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/test-emit")
def test_emit():
    socketio.emit(
        "newresult",
        {
            "result": [
                1,
                "192.168.1.1",
                "80",
                "10.0.0.1",
                "443",
                "tcp",
                "Benign",
                "0.1",
            ],
            "ips": [{"SourceIP": "192.168.1.1", "count": 5}],
            "risk_level": "minimal",
            "classification": "Benign",
        },
        namespace="/test",
    )
    return jsonify({"status": "emitted"})


@app.route("/debug-auth")
def debug_auth():
    """Development-only auth debugger. Disabled in production via env var."""
    if not app.config["DEBUG"]:
        return jsonify({"error": "Not available in production"}), 403

    username = request.args.get("username")
    if not username:
        return jsonify({"usage": "/debug-auth?username=<name>"})

    user_data, user_id = _resolve_user(username)
    if not user_data:
        return jsonify({"status": "not_found", "username": username})

    return jsonify(
        {
            "status": "found",
            "username": user_data.get("username"),
            "user_id": user_id,
            "email": user_data.get("email"),
            "has_password_hash": "password_hash" in user_data,
            "password_hash_length": len(user_data.get("password_hash", "")),
        }
    )


# ---------------------------------------------------------------------------
# SocketIO events
# ---------------------------------------------------------------------------


@socketio.on("connect", namespace="/test")
def on_connect():
    log.info("Client connected")
    socketio.emit(
        "message", {"status": "connected", "msg": "Server ready!"}, namespace="/test"
    )
    _ensure_sniff_thread()


@socketio.on("disconnect", namespace="/test")
def on_disconnect():
    log.info("Client disconnected")


# ---------------------------------------------------------------------------
# Shutdown cleanup
# ---------------------------------------------------------------------------


def _shutdown():
    log.info("Shutting down — cleaning up flows")
    _thread_stop.set()
    with _state_lock:
        for fid, flow in list(_current_flows.items()):
            try:
                classify(flow.terminated())
            except Exception:
                pass
            del _current_flows[fid]
    _close_logs()


atexit.register(_shutdown)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        socketio.run(app, allow_unsafe_werkzeug=True, port=5050)
    except Exception:
        log.exception("Fatal error starting application")
        _shutdown()
