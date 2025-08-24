                    # Toydatabase for Patterns Matter #
# ======= Imports ====== #

from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, session, current_app, abort, jsonify
import os
import pandas as pd
import numpy as np
import sqlite3
import secrets
import time


from werkzeug.utils import secure_filename
import datetime
from datetime import timedelta
import re
import csv
# Google Drive API imports
import io, base64, zipfile
from typing import List, Dict, Optional


# ========== SETTINGS (Drive-only materials; DB persisted on Fly volume) ==========
# Persist app state (SQLite DB, optional legacy uploads) on Fly's volume
DATA_DIR = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)

# SQLite DB lives on the volume so admin history / catalog survive deploys
DB_NAME = os.path.join(DATA_DIR, "patterns-matter.db")

# Local uploads folder (not used for Drive materials, but harmless to keep)
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_DATASET_EXTENSIONS = {"csv", "npy"}
ALLOWED_RESULTS_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "pdf", "docx"}
ALLOWED_MUSIC_EXTENSIONS   = {"mp3", "wav", "m4a", "ogg", "mp4"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.permanent_session_lifetime = timedelta(minutes=10)
IS_PROD = bool(os.getenv("FLY_APP_NAME"))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    )

# ---------- Secrets: require in prod, friendly defaults in dev ----------

def _require_env(name: str) -> str:
    val = os.getenv(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

if IS_PROD:
    # In production, these MUST be set via Fly secrets:
    #   fly secrets set ADMIN_PASSWORD='...' FLASK_SECRET_KEY='...'
    ADMIN_PASSWORD = _require_env("ADMIN_PASSWORD")
    app.secret_key = _require_env("FLASK_SECRET_KEY")
else:
    # Local dev fallbacks (or read from a local .env before this block)
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "devpassword")
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-keep-local")

# Google Drive scope for the Service Account (secrets provided via Fly)
GDRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]


# -------------------------- ----------------Utility Functions ---------------------------------------------------------------------------------------------------------------------

def allowed_dataset_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DATASET_EXTENSIONS

def allowed_results_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_RESULTS_EXTENSIONS

def allowed_music_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_MUSIC_EXTENSIONS

# ================================================================= Helper Functions ((8 helpers for drive-api))================================================== #

def get_drive_service():
    """
    Build a Drive v3 service from a Service Account.
    Reads either:
      - GDRIVE_SA_JSON: absolute path to JSON in the VM
      - GDRIVE_SA_JSON_BASE64: base64-encoded JSON content
    Requires env: GDRIVE_ROOT_FOLDER_ID (top folder shared with SA).
    """
    # Lazy imports so the app can boot even if libs aren't installed
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        import json, base64
    except Exception as ie:
        raise RuntimeError(
            "Google API libraries not installed. "
            "Add to requirements.txt: google-api-python-client google-auth google-auth-httplib2"
        ) from ie

    scopes = ["https://www.googleapis.com/auth/drive"]
    json_path = os.environ.get("GDRIVE_SA_JSON")
    json_b64  = os.environ.get("GDRIVE_SA_JSON_BASE64")

    if json_path and os.path.isfile(json_path):
        creds = service_account.Credentials.from_service_account_file(json_path, scopes=scopes)
    elif json_b64:
        try:
            info = json.loads(base64.b64decode(json_b64).decode("utf-8"))
        except Exception as e:
            raise RuntimeError("GDRIVE_SA_JSON_BASE64 is not valid base64 JSON.") from e
        creds = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    else:
        raise RuntimeError("Missing service account: set GDRIVE_SA_JSON or GDRIVE_SA_JSON_BASE64.")

    # Build the Drive client (handle older client versions without cache_discovery kw)
    try:
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except TypeError:
        return build("drive", "v3", credentials=creds)
    except Exception as e:
        raise RuntimeError(f"Failed to build Drive service: {e}")
#=======================================================================================================================================================================#

def _drive_extract_id(link_or_id: str) -> Optional[str]:
    """
    Accepts a full Drive URL (file or folder) or a raw ID and returns the ID.
    Handles:
      - https://drive.google.com/file/d/<ID>/view…
      - https://drive.google.com/drive/folders/<ID>
      - …?id=<ID>
      - raw <ID>
    """
    s = (link_or_id or "").strip()
    if not s:
        return None
    m = re.search(r"/file/d/([A-Za-z0-9_-]+)", s)
    if m: return m.group(1)
    m = re.search(r"/folders/([A-Za-z0-9_-]+)", s)
    if m: return m.group(1)
    m = re.search(r"[?&]id=([A-Za-z0-9_-]+)", s)
    if m: return m.group(1)
    # raw-ish ID
    if re.match(r"^[A-Za-z0-9_-]{10,}$", s):  # loose check
        return s
    return None
#=======================================================================================================================================================================#

def drive_find_or_create_folder(service, parent_id: str, name: str) -> str:
    """Find a folder by name under parent; create if missing. Returns folder ID."""
    # Escape single quotes for Drive query syntax: name = '...'
    safe_name = (name or "").replace("'", "\\'")

    q = (
        "mimeType='application/vnd.google-apps.folder' "
        f"and name='{safe_name}' "
        f"and '{parent_id}' in parents and trashed=false"
    )
    res = service.files().list(q=q, fields="files(id,name)", pageSize=1).execute()
    items = res.get("files", [])
    if items:
        return items[0]["id"]

    meta = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
        "parents": [parent_id],
    }
    created = service.files().create(body=meta, fields="id").execute()
    return created["id"]
#=======================================================================================================================================================================#

def drive_ensure_property_tab_folder(service, root_folder_id: str, prop: str, tab: str) -> str:
    """
    Ensures a structure: <root>/<prop>/<tab> exists, returns final folder ID.
    """
    prop_id = drive_find_or_create_folder(service, root_folder_id, prop)
    tab_id = drive_find_or_create_folder(service, prop_id, tab)
    return tab_id
#=======================================================================================================================================================================#

def drive_list_folder_files(service, folder_id: str, recursive: bool = False) -> List[Dict]:
    """
    List non-trashed files (id,name,mimeType) under folder_id.
    If recursive=True, include files in all subfolders depth-first.
    """
    items: List[Dict] = []
    stack = [folder_id]
    while stack:
        fid = stack.pop()
        page_token = None
        while True:
            res = service.files().list(
                q=f"'{fid}' in parents and trashed=false",
                fields="nextPageToken, files(id,name,mimeType)",
                pageSize=1000,
                pageToken=page_token
            ).execute()
            for f in res.get("files", []):
                mt = f.get("mimeType")
                if mt == "application/vnd.google-apps.folder":
                    if recursive:
                        stack.append(f["id"])
                else:
                    items.append(f)
            page_token = res.get("nextPageToken")
            if not page_token:
                break
    return items
#=======================================================================================================================================================================#

def drive_upload_bytes(service, folder_id: str, filename: str, data: bytes) -> str:
    """Upload a new file into folder_id. Returns file ID."""
    from googleapiclient.http import MediaIoBaseUpload
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/octet-stream", resumable=False)
    body = {"name": filename, "parents": [folder_id]}
    created = service.files().create(body=body, media_body=media, fields="id").execute()
    return created["id"]
#=======================================================================================================================================================================#

def _ext_ok_for_tab(filename: str, tab: str) -> bool:
    ext = (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    if tab == "dataset":
        return ext in ALLOWED_DATASET_EXTENSIONS
    return ext in ALLOWED_RESULTS_EXTENSIONS
#=======================================================================================================================================================================#

def _drive_urls(file_id: str) -> (str, str):
    preview = f"https://drive.google.com/file/d/{file_id}/preview"
    download = f"https://drive.google.com/uc?export=download&id={file_id}"
    return preview, download
#=======================================================================================================================================================================#

_SQLITE_RESERVED_PREFIXES = ("sqlite_",)

def tableize_basename(name: str) -> str:
    """
    Convert a *basename only* (e.g., 'Featurized Band Gap Data.csv') into a
    safe SQLite table name. Preserves case (to match your existing tables).
    Ensures:
      - No path separators
      - Allowed chars: [A-Za-z0-9_]
      - No leading 'sqlite_' prefix
      - Not empty; if empty, returns 't_unnamed'
      - Collapses multiple underscores
      - Appends an extension suffix (_csv/_npy) if the original had one
    """

    base = os.path.basename(name or "").strip()
    if not base:
        return "t_unnamed"

    # Split extension (if any) for suffixing
    stem, ext = os.path.splitext(base)
    ext_suffix = ""
    if ext:
        e = ext.lstrip(".").lower()
        if e in ("csv", "npy"):
            ext_suffix = f"_{e}"
        else:
            # Non-dataset extension: still keep it to avoid collisions
            ext_suffix = f"_{e}"

    # Replace separators and disallowed chars with underscores
    s = stem.replace(".", "_").replace("-", "_").replace(" ", "_")
    s = re.sub(r"[^0-9A-Za-z_]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")

    if not s:
        s = "t_unnamed"

    # Avoid reserved internal prefix
    lowered = s.lower()
    if any(lowered.startswith(p) for p in _SQLITE_RESERVED_PREFIXES):
        s = "t_" + s

    # names  in reasonable length
    if len(s) > 120:
        s = s[:120].rstrip("_")

    return f"{s}{ext_suffix}"
#=======================================================================================================================================================================#

def file_to_table_name(filename: str) -> str:
    """
    Small wrapper that ensures we only pass a basename to the canonical function.
    Use this everywhere you need to turn a filename into a table name.
    """
    import os
    return tableize_basename(os.path.basename(filename or ""))
#=======================================================================================================================================================================#

# def make_file_public(file_id: str):
#     """Ensure the file is readable by 'anyone with the link'."""
#     svc = get_drive_service()
#     try:
#         svc.permissions().create(
#             fileId=file_id,
#             body={"role": "reader", "type": "anyone"},
#             fields="id",
#         ).execute()
#     except Exception:
#         pass  # ignore if permission already exists
#=======================================================================================================================================================================#

def ensure_uploads_log_columns():
    """Backfill Drive-era columns if missing on older DBs."""
    need = {"storage", "drive_id", "preview_url", "download_url", "source", "description"}
    have = set()
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        try:
            c.execute("PRAGMA table_info(uploads_log)")
            for _cid, name, *_rest in c.fetchall():
                have.add(name)
        except Exception:
            return  # table might not exist yet; schema helper below will create it

        missing = list(need - have)
        for col in missing:
            if col in ("storage", "drive_id", "preview_url", "download_url", "source", "description"):
                c.execute(f"ALTER TABLE uploads_log ADD COLUMN {col} TEXT")
        conn.commit()
#=======================================================================================================================================================================#

def ensure_uploads_log_schema():
    """
    Create the catalog (uploads_log) + audit history (uploads_audit) + triggers.
    Unique index creation is best-effort so audit never gets blocked by dupes.
    """
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()

        # Catalog (public pages read this)
        c.execute("""
        CREATE TABLE IF NOT EXISTS uploads_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            property     TEXT NOT NULL,
            tab          TEXT NOT NULL,      -- 'dataset' | 'results'
            filename     TEXT NOT NULL,      -- display label (basename)
            uploaded_at  TEXT,               -- first/last touch; app-maintained
            -- Drive-first metadata (may be NULL on old/local rows)
            storage      TEXT,               -- 'drive' | 'local'
            drive_id     TEXT,
            preview_url  TEXT,
            download_url TEXT,
            source       TEXT,
            description  TEXT
        )
        """)

        # Make sure Drive-era columns exist on older DBs
        ensure_uploads_log_columns()

        # Audit table (history for /admin)
        c.execute("""
        CREATE TABLE IF NOT EXISTS uploads_audit (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            property  TEXT NOT NULL,
            tab       TEXT NOT NULL,
            filename  TEXT NOT NULL,
            action    TEXT NOT NULL,   -- add | update | delete
            at        TEXT NOT NULL
        )
        """)

        # Triggers (idempotent creation)
        def ensure_trigger(name, ddl):
            c.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?", (name,))
            if not c.fetchone():
                c.execute(ddl)

        ensure_trigger("trg_ul_insert_audit", """
        CREATE TRIGGER trg_ul_insert_audit
        AFTER INSERT ON uploads_log
        BEGIN
          INSERT INTO uploads_audit(property, tab, filename, action, at)
          VALUES (NEW.property, NEW.tab, NEW.filename, 'add',
                  COALESCE(NEW.uploaded_at, CURRENT_TIMESTAMP));
        END;""")

        ensure_trigger("trg_ul_update_audit", """
        CREATE TRIGGER trg_ul_update_audit
        AFTER UPDATE ON uploads_log
        BEGIN
          INSERT INTO uploads_audit(property, tab, filename, action, at)
          VALUES (NEW.property, NEW.tab, NEW.filename, 'update',
                  COALESCE(NEW.uploaded_at, CURRENT_TIMESTAMP));
        END;""")

        ensure_trigger("trg_ul_delete_audit", """
        CREATE TRIGGER trg_ul_delete_audit
        AFTER DELETE ON uploads_log
        BEGIN
          INSERT INTO uploads_audit(property, tab, filename, action, at)
          VALUES (OLD.property, OLD.tab, OLD.filename, 'delete', CURRENT_TIMESTAMP);
        END;""")

        # Best-effort unique index enabling UPSERTs; don't block audit on failure
        try:
            c.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
                ON uploads_log(property, tab, filename)
            """)
        except Exception as e:
            app.logger.warning("ensure_uploads_log_schema: unique index creation skipped: %s", e)

        conn.commit()
#=======================================================================================================================================================================#

def dedupe_uploads_log():
    """Remove duplicate (property,tab,filename) rows and enforce unique index."""
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # Try best: keep by uploaded_at desc, then rowid desc (needs window functions)
        try:
            c.executescript("""
                WITH ranked AS (
                  SELECT rowid,
                         property, tab, filename,
                         COALESCE(uploaded_at,'') AS ts,
                         ROW_NUMBER() OVER (
                           PARTITION BY property, tab, filename
                           ORDER BY ts DESC, rowid DESC
                         ) AS rn
                  FROM uploads_log
                )
                DELETE FROM uploads_log
                 WHERE rowid IN (SELECT rowid FROM ranked WHERE rn > 1);
            """)
        except sqlite3.OperationalError:
            # Fallback for older SQLite: keep MAX(rowid)
            c.execute("""
                DELETE FROM uploads_log
                 WHERE rowid NOT IN (
                   SELECT MAX(rowid)
                     FROM uploads_log
                    GROUP BY property, tab, filename
                 );
            """)
        # Enforce uniqueness
        try:
            c.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
                ON uploads_log(property, tab, filename)
            """)
        except sqlite3.OperationalError as e:
            # If this fails, we’ll at least not crash the app
            current_app.logger.warning("unique index create failed: %s", e)
        conn.commit()
#=======================================================================================================================================================================#

def auto_log_material_files():
    """
    Walk UPLOAD_FOLDER and upsert one row per (property, tab, filename).
    Idempotent and uses SQLite CURRENT_TIMESTAMP (no Python datetime).
    """
    ensure_uploads_log_schema()

    root_dir = UPLOAD_FOLDER
    if not os.path.exists(root_dir):
        return {"status": "skip", "reason": "UPLOAD_FOLDER missing", "added_or_updated": 0}

    allowed_exts = (ALLOWED_DATASET_EXTENSIONS | ALLOWED_RESULTS_EXTENSIONS)
    rows = []  # (property, tab, filename)

    for root, _dirs, files in os.walk(root_dir):
        for fname in files:
            ext = fname.rsplit('.', 1)[-1].lower() if '.' in fname else ''
            if ext not in allowed_exts:
                continue

            full = os.path.join(root, fname)
            rel_path = os.path.relpath(full, root_dir)  # e.g. bandgap/dataset/foo.csv
            parts = rel_path.split(os.sep)

            # Skip music under uploads/clips/
            if parts and parts[0] == 'clips':
                continue

            if len(parts) >= 3:
                prop, tab, filename = parts[0], parts[1], parts[2]
                if tab in ("dataset", "results"):
                    rows.append((prop, tab, filename))

    if not rows:
        return {"status": "ok", "added_or_updated": 0}

    added_or_updated = 0
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        upsert = """
        INSERT INTO uploads_log (property, tab, filename, uploaded_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(property, tab, filename)
        DO UPDATE SET uploaded_at = CURRENT_TIMESTAMP
        """
        for r in rows:
            c.execute(upsert, r)
            added_or_updated += 1
        conn.commit()

    return {"status": "ok", "added_or_updated": added_or_updated}
#=======================================================================================================================================================================#
              
# Automation of import to sqlite3 database
def auto_import_uploads():
    """
    Import CSV/NPY datasets from uploads/<property>/<dataset>/ into SQLite tables.
    - Skips music under uploads/clips/
    - Does NOT write to uploads_log (logging handled elsewhere)
    - Re-imports only when source file mtime changed (tracked in import_etag)
    """
    if not os.path.exists(UPLOAD_FOLDER):
        print("auto_import_uploads: uploads/ folder not found, skipping.")
        return 0

    ALLOWED_IMPORT_EXTS = {'csv', 'npy'}
    imported = 0

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # Track file mtimes to avoid unnecessary re-imports
        c.execute("""
            CREATE TABLE IF NOT EXISTS import_etag (
                relpath TEXT PRIMARY KEY,
                mtime REAL NOT NULL
            )
        """)
        conn.commit()

        for root, _, files in os.walk(UPLOAD_FOLDER):
            # Skip music tree
            rel_root = os.path.relpath(root, UPLOAD_FOLDER)
            if rel_root.split(os.sep)[0] == 'clips':
                continue

            for filename in files:
                if filename.startswith('.'):
                    continue
                ext = filename.rsplit('.', 1)[-1].lower()
                if ext not in ALLOWED_IMPORT_EXTS:
                    continue

                filepath = os.path.join(root, filename)
                relpath = os.path.relpath(filepath, UPLOAD_FOLDER)
                mtime = os.path.getmtime(filepath)
                table_name = file_to_table_name(filename)

                # Check etag (mtime)
                c.execute("SELECT mtime FROM import_etag WHERE relpath=?", (relpath,))
                row = c.fetchone()
                if row and float(row[0]) == float(mtime):
                    # up-to-date, skip
                    continue

                # Load into DataFrame
                try:
                    if ext == 'csv':
                        df = pd.read_csv(filepath)
                    else:  # npy
                        arr = np.load(filepath, allow_pickle=True)
                        if isinstance(arr, np.ndarray):
                            if arr.ndim == 2:
                                df = pd.DataFrame(arr)
                            elif arr.ndim == 1 and hasattr(arr.dtype, 'names') and arr.dtype.names:
                                # structured array -> DataFrame with named columns
                                df = pd.DataFrame(arr.tolist(), columns=list(arr.dtype.names))
                            else:
                                df = pd.DataFrame(arr)
                        else:
                            print(f"auto_import_uploads: unsupported NPY structure for {relpath}, skipping.")
                            continue
                except Exception as e:
                    print(f"auto_import_uploads: failed to read {relpath}: {e}")
                    continue

                # Import into SQLite (replace whole table)
                try:
                    df.to_sql(table_name, conn, if_exists='replace', index=False)
                    c.execute("REPLACE INTO import_etag (relpath, mtime) VALUES (?, ?)", (relpath, mtime))
                    conn.commit()
                    imported += 1
                    print(f"auto_import_uploads: imported {relpath} -> table '{table_name}'")
                except Exception as e:
                    print(f"auto_import_uploads: failed to import {relpath} to '{table_name}': {e}")

    print(f"auto_import_uploads: done, {imported} table(s) updated.")
    return imported
#=======================================================================================================================================================================#

# Run-once warm-up
import threading

_startup_done = False
_startup_lock = threading.Lock()

def _run_startup_tasks():
    """Idempotent, best-effort startup initialization."""
    global _startup_done
    with _startup_lock:
        if _startup_done:
            return
        try:
            try:
                ensure_uploads_log_schema()
            except Exception as e:
                app.logger.warning("ensure_uploads_log_schema at startup: %s", e)

            try:
                ensure_uploads_log_columns()
            except Exception as e:
                app.logger.warning("ensure_uploads_log_columns at startup: %s", e)

            # (Optional) If >> to clean up old local rows or dedupe:
            # try:
            #     dedupe_uploads_log()
            # except Exception as e:
            #     app.logger.warning("dedupe_uploads_log at startup: %s", e)

        finally:
            _startup_done = True
#=======================================================================================================================================================================#

@app.before_request
def _startup_once():
    # Keep health checks and static super fast
    if request.endpoint in ("healthz", "static"):
        return
    if not _startup_done:
        _run_startup_tasks()
#=======================================================================================================================================================================#

# --- Admin inactivity guard: auto-logout after 10 minutes of inactivity ---
@app.before_request
def enforce_admin_idle_timeout():
    safe_endpoints = {'login', 'healthz', 'static'}
    if session.get('admin'):
        now  = int(time.time())
        last = session.get('last_seen', now)
        if (now - last) > IDLE_TIMEOUT_SECONDS:
            flash("You were logged out for security reasons. Please, log in again to edit!")
            session.pop('admin', None)
            session.pop('last_seen', None)
            if request.endpoint not in safe_endpoints:
                return redirect(url_for('login'))
        else:
            session['last_seen'] = now

        
###################################################################################========== ROUTES ==========############################################################
###########################################################################################################################################################################

# Public home used by multiple templates (and health check lands here )
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def public_home():
    #tables = _list_user_tables()
    return render_template("landing.html")

##############################################################################################################################################################

@app.route("/materials", methods=["GET"])
def materials_portal():
    # Uses your templates/materials_portal.html
    return render_template("materials_portal.html")

##############################################################################################################################################################

# SQL Query Tool (admin only, CRUD, multi-statement)
DESTRUCTIVE_REGEX = re.compile(r"\b(drop|delete|update|alter|truncate)\b", re.IGNORECASE)

def _list_user_tables():
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT name
              FROM sqlite_master
             WHERE type='table'
               AND name NOT LIKE 'sqlite_%'
             ORDER BY 1
        """)
        return [r[0] for r in cur.fetchall()]

def _strip_sql_comments(sql: str) -> str:
    # -- inline comments
    sql = re.sub(r"--.*?$", "", sql, flags=re.MULTILINE)
    # /* block comments */
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return sql

def _is_destructive(sql: str) -> bool:
    plain = _strip_sql_comments(sql)
    return bool(DESTRUCTIVE_REGEX.search(plain))

@app.route("/admin/sql", methods=["GET", "POST"])
@app.route("/query_sql", methods=["GET", "POST"])
def query_sql():
    if not session.get("admin"):
        return redirect(url_for("login"))

    tables = _list_user_tables()
    sql = ""
    result_html = ""
    error_msg = ""
    needs_confirm = False

    if request.method == "POST":
        sql = (request.form.get("sql") or "").strip()
        user_confirmed = (request.form.get("confirm") in ("on", "1", "true", "yes"))

        if not sql:
            error_msg = "Please enter SQL."
        elif re.search(r"\bsqlite_\w+", sql, re.IGNORECASE):
            error_msg = "Queries that reference internal tables (sqlite_*) are blocked."
        else:
            try:
                # If destructive, require explicit confirmation
                if _is_destructive(sql) and not user_confirmed:
                    needs_confirm = True
                    error_msg = (
                        "This query contains destructive statements "
                        "(DROP/DELETE/UPDATE/ALTER/TRUNCATE). Check the box below to confirm and resubmit."
                    )
                else:
                    statements = [s.strip() for s in sql.split(";") if s.strip()]
                    total_changed = 0
                    last_select_html = None

                    with sqlite3.connect(DB_NAME) as conn:
                        conn.execute("PRAGMA foreign_keys=ON;")
                        cur = conn.cursor()

                        for stmt in statements:
                            if re.match(r"^\s*(with\s+.*?select|select)\b", stmt, re.IGNORECASE | re.DOTALL):
                                cur.execute(stmt)
                                rows = cur.fetchall()
                                cols = [d[0] for d in cur.description] if cur.description else []
                                df = pd.DataFrame(rows, columns=cols)
                                last_select_html = df.to_html(classes="data", index=False)
                            else:
                                cur.execute(stmt)
                                total_changed = conn.total_changes

                        conn.commit()

                    result_html = (
                        last_select_html
                        if last_select_html is not None
                        else f"<p><b>OK.</b> Executed {len(statements)} statement(s). "
                             f"Total changed rows: {total_changed}.</p>"
                    )

            except Exception as e:
                error_msg = str(e)

    return render_template(
        "sql_query.html",   # <-- matches your existing template filename
        tables=tables,
        sql=sql,
        result_html=result_html,
        error_msg=error_msg,
        needs_confirm=needs_confirm,
    )
##############################################################################################################################################################

# Admin only rescanning for duplicates and re-importing
@app.route('/admin/rescan_uploads')
def rescan_uploads():
    """
    Re-scan the UPLOAD_FOLDER and upsert entries into uploads_log.
    Returns JSON with counts. Uses CURRENT_TIMESTAMP in SQL.
    """
    try:
        # observe before/after for quick sanity checks
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM uploads_log")
            before = cur.fetchone()[0]

        result = auto_log_material_files()

        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM uploads_log")
            after = cur.fetchone()[0]

        return jsonify({
            "status": result.get("status", "ok"),
            "added_or_updated": result.get("added_or_updated", 0),
            "rows_before": before,
            "rows_after": after
        })
    except Exception as e:
        return jsonify({"status": f"auto_log_material_files failed: {e}"}), 500
    
##############################################################################################################################################################

IDLE_TIMEOUT_SECONDS = 10 * 60  # 10 minutes

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        pw = (request.form.get('password') or '').strip()
        if pw == ADMIN_PASSWORD:
            # mark session as admin and start idle timer
            session['admin'] = True
            session['last_seen'] = int(time.time())
            session.permanent = True  # respects app.permanent_session_lifetime if you set it
            flash("Logged in as admin.")
            return redirect(url_for('public_home'))
        else:
            flash("Incorrect password.")
            return redirect(url_for('login'))
    # GET
    return render_template('login.html')
##############################################################################################################################################################

@app.route('/logout')
def logout():
    # clear admin markers
    session.pop('admin', None)
    session.pop('last_seen', None)
    flash("Logged out.")
    return redirect(url_for('public_home'))
##############################################################################################################################################################

# --- Admin Dashboard (history-only) ---
@app.route('/admin', methods=['GET'])
def admin_home():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Make sure catalog + audit schema exist (triggers are created here too)
    ensure_uploads_log_schema()
    try:
        ensure_uploads_log_columns()
    except Exception as e:
        app.logger.warning("ensure_uploads_log_columns : %s", e)

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # If audit table is still empty, show an empty page gracefully
        c.execute("""
        SELECT name FROM sqlite_master
        WHERE type='table' AND name='uploads_audit'
        """)
        if not c.fetchone():
            audit_rows = []
        else:
            c.execute("""
            WITH hist AS (
              SELECT property, tab, filename,
                     MIN(CASE WHEN action='add' THEN at END) AS first_added,
                     MAX(at) AS last_event
                FROM uploads_audit
            GROUP BY property, tab, filename
            )
            SELECT
              h.filename AS file_name,
              COALESCE(h.first_added, h.last_event) AS uploaded_at,
              CASE WHEN u.rowid IS NULL THEN 'Absent' ELSE 'Present' END AS public_view_status
            FROM hist h
            LEFT JOIN uploads_log u
                   ON u.property=h.property AND u.tab=h.tab AND u.filename=h.filename
            ORDER BY uploaded_at DESC, h.filename;
            """)
            audit_rows = c.fetchall()

    return render_template('admin_home.html', audit_rows=audit_rows)
##############################################################################################################################################################

@app.route("/admin/repair_uploads")
def admin_repair_uploads():
    if not session.get("admin"):
        abort(403)

    stats = {}
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()

        # remove local rows (catalog is Drive-only)
        c.execute("SELECT COUNT(*) FROM uploads_log WHERE storage IS NULL OR storage!='drive'")
        stats["deleted_non_drive_rows"] = c.fetchone()[0]
        c.execute("DELETE FROM uploads_log WHERE storage IS NULL OR storage!='drive'")

        # dedupe on (property,tab,filename)
        deleted = 0
        used_window = False
        try:
            c.execute("""
                WITH ranked AS (
                  SELECT rowid,
                         property, tab, filename,
                         COALESCE(uploaded_at,'') AS ts,
                         ROW_NUMBER() OVER (
                           PARTITION BY property, tab, filename
                           ORDER BY ts DESC, rowid DESC
                         ) AS rn
                  FROM uploads_log
                )
                DELETE FROM uploads_log
                 WHERE rowid IN (SELECT rowid FROM ranked WHERE rn > 1);
            """)
            deleted = conn.total_changes
            used_window = True
        except sqlite3.OperationalError:
            c.execute("""
                DELETE FROM uploads_log
                 WHERE rowid NOT IN (
                   SELECT MAX(rowid)
                     FROM uploads_log
                    GROUP BY property, tab, filename
                 );
            """)
            deleted = conn.total_changes

        stats["duplicates_deleted"] = deleted
        stats["used_window_fn"] = used_window

        # unique index (best effort)
        try:
            c.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
                ON uploads_log(property, tab, filename)
            """)
            stats["unique_index"] = "ok"
        except Exception as e:
            stats["unique_index"] = f"failed: {e}"

        conn.commit()

    return jsonify(stats)   
##############################################################################################################################################################

@app.route("/healthz")
def healthz():
    # Must be super fast and always 200 so Fly can mark the machine healthy
    return "ok", 200
##############################################################################################################################################################

@app.route("/diag/routes")
def diag_routes():
    # Lets you confirm which routes are actually registered in prod
    if not session.get("admin"):
        abort(403)
    rules = sorted([str(r) for r in app.url_map.iter_rules()])
    return jsonify({"routes": rules})
##############################################################################################################################################################

@app.route('/materials/<property_name>/<tab>', methods=['GET', 'POST'])
def property_detail(property_name, tab):
    # ---- titles / guards ----
    pretty_titles = {
        'bandgap': 'Band Gap',
        'formation_energy': 'Formation Energy',
        'melting_point': 'Melting Point',
        'oxidation_state': 'Oxidation State',
    }
    if property_name not in pretty_titles or tab not in ('dataset', 'results'):
        return "Not found.", 404

    upload_message = ""
    edit_message = ""
    is_admin = bool(session.get('admin'))

    # Ensure schema/columns exist
    try:
        ensure_uploads_log_schema()
    except Exception as e:
        app.logger.warning("ensure_uploads_log_schema: %s", e)
    try:
        ensure_uploads_log_columns()
    except Exception as e:
        app.logger.warning("ensure_uploads_log_columns: %s", e)

    # ---- admin POST handlers (Drive-first only) ----
    if is_admin and request.method == 'POST':
        try:
            # 1) Add a single Drive file by link/ID
            if request.form.get('add_drive'):
                drive_link = (request.form.get('drive_link') or '').strip()
                label = (request.form.get('label') or '').strip()
                new_source = (request.form.get('row_source') or '').strip() if tab == 'dataset' else None
                new_desc = (request.form.get('row_description') or '').strip()

                if not _ext_ok_for_tab(label, tab):
                    if tab == 'dataset':
                        upload_message = "Label must end with .csv or .npy for datasets."
                    else:
                        upload_message = f"Label must end with one of: {', '.join(sorted(ALLOWED_RESULTS_EXTENSIONS))}."
                else:
                    file_id = _drive_extract_id(drive_link)
                    if not file_id:
                        upload_message = "Invalid Google Drive link or ID."
                    else:
                        preview_url, download_url = _drive_urls(file_id)
                        # Best effort: ensure public permission
                        try:
                            svc = get_drive_service()
                            svc.permissions().create(
                                fileId=file_id,
                                body={"role": "reader", "type": "anyone"},
                                fields="id"
                            ).execute()
                        except Exception:
                            pass
                        with sqlite3.connect(DB_NAME) as conn:
                            c = conn.cursor()
                            c.execute(
                                """
                                INSERT INTO uploads_log
                                   (property, tab, filename, uploaded_at,
                                    storage, drive_id, preview_url, download_url, source, description)
                                VALUES (?, ?, ?, CURRENT_TIMESTAMP,
                                        'drive', ?, ?, ?, ?, ?)
                                ON CONFLICT(property, tab, filename)
                                DO UPDATE SET
                                   uploaded_at = CURRENT_TIMESTAMP,
                                   storage     = 'drive',
                                   drive_id    = excluded.drive_id,
                                   preview_url = excluded.preview_url,
                                   download_url= excluded.download_url,
                                   source      = COALESCE(excluded.source, uploads_log.source),
                                   description = COALESCE(excluded.description, uploads_log.description)
                                """,
                                (property_name, tab, label, file_id, preview_url, download_url, new_source, new_desc),
                            )
                            conn.commit()
                        upload_message = f"Added Drive item '{label}'."

            # 2) Link a Drive FOLDER → import all allowed files (recursive)
            elif request.form.get('link_folder'):
                folder_link = (request.form.get('drive_folder_link') or '').strip()
                folder_id = _drive_extract_id(folder_link)
                if not folder_id:
                    upload_message = "Invalid Drive folder link or ID."
                else:
                    service = get_drive_service()
                    files = drive_list_folder_files(service, folder_id, recursive=True)
                    imported = 0
                    with sqlite3.connect(DB_NAME) as conn:
                        c = conn.cursor()
                        for f in files:
                            name = (f.get("name") or "").strip()
                            if not _ext_ok_for_tab(name, tab):
                                continue
                            fid = f["id"]
                            preview_url, download_url = _drive_urls(fid)
                            # Make public best-effort
                            try:
                                service.permissions().create(
                                    fileId=fid,
                                    body={"role": "reader", "type": "anyone"},
                                    fields="id"
                                ).execute()
                            except Exception:
                                pass
                            c.execute(
                                """
                                INSERT INTO uploads_log
                                   (property, tab, filename, uploaded_at,
                                    storage, drive_id, preview_url, download_url)
                                VALUES (?, ?, ?, CURRENT_TIMESTAMP,
                                        'drive', ?, ?, ?)
                                ON CONFLICT(property, tab, filename)
                                DO UPDATE SET
                                   uploaded_at = CURRENT_TIMESTAMP,
                                   storage     = 'drive',
                                   drive_id    = excluded.drive_id,
                                   preview_url = excluded.preview_url,
                                   download_url= excluded.download_url
                                """,
                                (property_name, tab, name, fid, preview_url, download_url),
                            )
                            imported += 1
                        conn.commit()
                    upload_message = f"Linked folder: imported {imported} item(s)."

            # 3) Upload a ZIP → push contents to Drive <root>/<property>/<tab> → import
            elif request.form.get('zip_upload'):
                if 'zipfile' not in request.files or request.files['zipfile'].filename == '':
                    upload_message = "No ZIP file selected."
                else:
                    zf = request.files['zipfile']
                    try:
                        root_id = (os.environ.get("GDRIVE_ROOT_FOLDER_ID") or "").strip()
                        if not root_id:
                            raise RuntimeError("GDRIVE_ROOT_FOLDER_ID not set.")
                        service = get_drive_service()
                        target_folder_id = drive_ensure_property_tab_folder(service, root_id, property_name, tab)

                        # Hard guard so we never upload into Drive 'root'
                        if not target_folder_id or target_folder_id in ("root", "", None):
                            raise RuntimeError("Refusing to upload: invalid Drive parent (would create in root).")

                        data = zf.read()
                        z = zipfile.ZipFile(io.BytesIO(data))
                        uploaded = 0
                        with sqlite3.connect(DB_NAME) as conn:
                            c = conn.cursor()
                            for info in z.infolist():
                                if info.is_dir():
                                    continue
                                base = os.path.basename(info.filename)
                                if not base or not _ext_ok_for_tab(base, tab):
                                    continue
                                file_bytes = z.read(info)
                                fid = drive_upload_bytes(service, target_folder_id, base, file_bytes)
                                preview_url, download_url = _drive_urls(fid)
                                # Make public best-effort
                                try:
                                    service.permissions().create(
                                        fileId=fid,
                                        body={"role": "reader", "type": "anyone"},
                                        fields="id"
                                    ).execute()
                                except Exception:
                                    pass
                                c.execute(
                                    """
                                    INSERT INTO uploads_log
                                       (property, tab, filename, uploaded_at,
                                        storage, drive_id, preview_url, download_url)
                                    VALUES (?, ?, ?, CURRENT_TIMESTAMP,
                                            'drive', ?, ?, ?)
                                    ON CONFLICT(property, tab, filename)
                                    DO UPDATE SET
                                       uploaded_at = CURRENT_TIMESTAMP,
                                       storage     = 'drive',
                                       drive_id    = excluded.drive_id,
                                       preview_url = excluded.preview_url,
                                       download_url= excluded.download_url
                                    """,
                                    (property_name, tab, base, fid, preview_url, download_url),
                                )
                                uploaded += 1
                            conn.commit()
                        upload_message = f"Uploaded {uploaded} file(s) from ZIP to Drive."
                    except Exception as e:
                        upload_message = f"ZIP upload failed: {e}"

            # 4) Inline edit (source/description)
            elif 'edit_row' in request.form:
                row_filename = (request.form.get('row_filename') or '').strip()
                new_desc = (request.form.get('row_description') or '').strip()
                with sqlite3.connect(DB_NAME) as conn:
                    c = conn.cursor()
                    if tab == 'dataset':
                        new_source = (request.form.get('row_source') or '').strip()
                        c.execute(
                            """
                            UPDATE uploads_log
                               SET source = ?, description = ?
                             WHERE property = ? AND tab = ? AND filename = ?
                            """,
                            (new_source, new_desc, property_name, tab, row_filename),
                        )
                    else:
                        c.execute(
                            """
                            UPDATE uploads_log
                               SET description = ?
                             WHERE property = ? AND tab = ? AND filename = ?
                            """,
                            (new_desc, property_name, tab, row_filename),
                        )
                    conn.commit()
                # AJAX? return JSON so the page doesn't reload
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"ok": True, "filename": row_filename})
                # Non-AJAX fallback
                edit_message = f"Updated info for {row_filename}."

        except Exception as e:
            # AJAX error?
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"ok": False, "error": str(e)}), 400
            upload_message = f"Error: {e}"

    # ---- fetch current uploads (Drive-only for property pages) ----
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """
            SELECT filename,
                   COALESCE(source,'')        AS source,
                   COALESCE(description,'')   AS description,
                   uploaded_at,
                   COALESCE(storage,'local')  AS storage,
                   COALESCE(preview_url,'')   AS preview_url,
                   COALESCE(download_url,'')  AS download_url
              FROM uploads_log
             WHERE property = ? AND tab = ?
               AND storage = 'drive'
          ORDER BY uploaded_at DESC, filename
            """,
            (property_name, tab),
        )
        uploads = c.fetchall()

    # No local datasets shown anymore; keep for template compatibility
    table_map = {}

    return render_template(
        'property_detail.html',
        property_name=property_name,
        pretty_title=pretty_titles[property_name],
        tab=tab,
        uploads=uploads,
        upload_message=upload_message,
        edit_message=edit_message,
        admin=is_admin,
        table_map=table_map,
    )    
##############################################################################################################################################################

# NEW: JSON endpoint to save one row without full-page reload
@app.route('/materials/<property_name>/<tab>/edit', methods=['POST'])
def materials_edit_row(property_name, tab):
    if not session.get('admin'):
        return jsonify({"ok": False, "error": "not_authorized"}), 403
    if tab not in ('dataset', 'results'):
        return jsonify({"ok": False, "error": "bad_tab"}), 400

    row_filename = (request.form.get('row_filename') or '').strip()
    if not row_filename:
        return jsonify({"ok": False, "error": "missing_filename"}), 400

    new_desc = (request.form.get('row_description') or '').strip()

    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            if tab == 'dataset':
                new_source = (request.form.get('row_source') or '').strip()
                c.execute("""
                    UPDATE uploads_log
                       SET source = ?, description = ?
                     WHERE property=? AND tab=? AND filename=? AND storage='drive'
                """, (new_source, new_desc, property_name, tab, row_filename))
            else:
                c.execute("""
                    UPDATE uploads_log
                       SET description = ?
                     WHERE property=? AND tab=? AND filename=? AND storage='drive'
                """, (new_desc, property_name, tab, row_filename))
            conn.commit()
        return jsonify({"ok": True, "message": f"Saved: {row_filename}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
##############################################################################################################################################################

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print('Serving file:', full_path)
    if not os.path.isfile(full_path):
        print('File not found:', full_path)
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
##############################################################################################################################################################

@app.route('/view_result/<property_name>/<tab>/<path:filename>')
def view_result_file(property_name, tab, filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], property_name, tab, filename)
    if not os.path.isfile(filepath):
        return "File not found.", 404

    ext = filename.rsplit('.', 1)[-1].lower()
    return render_template("view_result.html", filename=filename, property_name=property_name, tab=tab, ext=ext)


def extract_drive_id(link):
    match = re.search(r'/d/([a-zA-Z0-9_-]+)', link)
    if match:
        return match.group(1)
    match = re.search(r'id=([a-zA-Z0-9_-]+)', link)
    if match:
        return match.group(1)
    raise ValueError("Invalid Drive link")
##############################################################################################################################################################

@app.route('/clips')
def public_clips():
    import os

    admin = session.get('admin', False)
    clips = []

    # -- 1. Try to load from CSV (Drive-backed music list)
    csv_path = '/data/drive_music.csv'
    #csv_path = '/data/drive_music.csv' if os.path.exists('/data/drive_music.csv') else 'drive_music.csv'

    try:
        with open(csv_path, encoding='utf-8') as f:
            reader = csv.DictReader(f)
            required_headers = {'title', 'description', 'preview_url', 'download_url'}
            if reader.fieldnames and required_headers.issubset(set(reader.fieldnames)):
                for row in reader:
                    title = row.get('title', '').strip()
                    description = row.get('description', '').strip()
                    preview = row.get('preview_url', '').strip()
                    download = row.get('download_url', '').strip()
                    if preview and download:
                        clips.append((preview, download, title, description))
            else:
                print("⚠️ CSV is missing required headers:", reader.fieldnames)
    except Exception as e:
        print("🚫 Error reading CSV:", e)


    pass

    return render_template('clips.html', clips=clips, admin=admin)
##############################################################################################################################################################

@app.route('/view_table/<path:filename>', methods=['GET'])
def view_table(filename):
    """
    Used by the 'View' link in property_detail.html.
    Accepts 'property/tab/file.csv' and renders the dataset:
    - Prefer reading the imported SQLite table (created by auto_import_uploads()).
    - If missing, fall back to reading the file from uploads/ directly.
    """
    admin = bool(session.get('admin'))
    safe_name = os.path.basename(filename)
    table = tableize_basename(safe_name)

    df = None

    # Try SQLite first
    try:
        with sqlite3.connect(DB_NAME) as conn:
            df = pd.read_sql_query(f'SELECT * FROM "{table}"', conn)
    except Exception:
        # Fallback: read the source file
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.isfile(path):
            abort(404)
        ext = (safe_name.rsplit('.', 1)[-1] if '.' in safe_name else '').lower()
        try:
            if ext == 'csv':
                df = pd.read_csv(path)
            elif ext == 'npy':
                arr = np.load(path, allow_pickle=True)
                if isinstance(arr, np.ndarray):
                    if arr.ndim == 2:
                        df = pd.DataFrame(arr)
                    elif arr.ndim == 1 and hasattr(arr.dtype, 'names') and arr.dtype.names:
                        df = pd.DataFrame(arr.tolist(), columns=list(arr.dtype.names))
                    else:
                        df = pd.DataFrame(arr)
                else:
                    return "Unsupported NPY structure.", 415
            else:
                return f"Unsupported dataset type: {ext}", 415
        except Exception as e:
            return f"Failed to open dataset: {e}", 500

    return render_template(
        'view_table.html',
        tables=[df.to_html(classes='data', index=False)],
        titles=getattr(df, 'columns', []),
        filename=safe_name,
        imported_table=table,
        admin=admin
    )
##############################################################################################################################################################

@app.route('/dataset/<table>')
def public_view(table):
    # allow only simple identifiers
    if not re.match(r'^[A-Za-z0-9_]+$', table or ''):
        abort(404)

    try:
        with sqlite3.connect(DB_NAME) as conn:
            # verify table exists
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
            if not cur.fetchone():
                abort(404)

            # quote identifier to avoid issues with reserved words/case
            df = pd.read_sql_query(f'SELECT * FROM "{table}"', conn)

        return render_template(
            'view_table.html',
            tables=[df.to_html(classes='data', index=False)],
            titles=df.columns.values,
            filename=table,
            imported_table=table,
            admin=False
        )
    except Exception as e:
        # don’t 500 the whole app; show a friendly message
        return render_template(
            'view_table.html',
            tables=[f"<p><b>Error loading table '{table}':</b> {e}</p>"],
            titles=[],
            filename=table,
            imported_table=table,
            admin=False
        ), 200
##############################################################################################################################################################

@app.route('/download/<table>')
def download(table):
    # allow only simple identifiers and quote it
    if not re.match(r'^[A-Za-z0-9_]+$', table or ''):
        abort(404)
    with sqlite3.connect(DB_NAME) as conn:
        df = pd.read_sql_query(f'SELECT * FROM "{table}"', conn)
    csv_path = os.path.join(UPLOAD_FOLDER, f"{table}.csv")
    df.to_csv(csv_path, index=False)
    return send_from_directory(UPLOAD_FOLDER, f"{table}.csv", as_attachment=True)
##############################################################################################################################################################

@app.route('/migrate_csv_to_db')
def migrate_csv_to_db():
    if not session.get('admin'):
        return "❌ Admin login required", 403

    import os
    csv_path = '/data/drive_music.csv' if os.path.exists('/data/drive_music.csv') else 'drive_music.csv'

    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()

            # Step 1: Drop and recreate table
            c.execute("DROP TABLE IF EXISTS music_clips")
            c.execute('''
                CREATE TABLE music_clips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT,
                    title TEXT,
                    description TEXT
                )
            ''')

            # Step 2: Insert from CSV
            with open(csv_path, encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    title = row.get('title', '').strip()
                    description = row.get('description', '').strip()
                    preview = row.get('preview_url', '').strip()
                    download = row.get('download_url', '').strip()
                    if preview and download:
                        db_value = f"{preview}||{download}"
                        c.execute(
                            "INSERT INTO music_clips (filename, title, description) VALUES (?, ?, ?)",
                            (db_value, title, description)
                        )

            conn.commit()
        return "✅ Table recreated and data loaded from CSV!"
    except Exception as e:
        return f"❌ Error: {e}"
##############################################################################################################################################################

# SEARCH ROUTE
@app.route('/search')
def search():
    query = request.args.get('q', '').strip().lower()
    materials = []
    clips = []
    if query:
        # Search materials database datasets/results
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT property, tab, filename, description
                FROM uploads_log
                WHERE lower(property) LIKE ? OR lower(tab) LIKE ? OR lower(filename) LIKE ? OR lower(description) LIKE ?
                ORDER BY uploaded_at DESC
            """, (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
            materials = c.fetchall()
        # Search music clips
        try:
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT id, filename, title, description
                    FROM music_clips
                    WHERE lower(title) LIKE ? OR lower(description) LIKE ? OR lower(filename) LIKE ?
                    ORDER BY id DESC
                """, (f'%{query}%', f'%{query}%', f'%{query}%'))
                clips = [
                    (id, filename.replace('\\', '/'), title, description)
                    for (id, filename, title, description) in c.fetchall()
                ]
        except Exception:
            clips = []
    return render_template('search_results.html', query=query, materials=materials, clips=clips)
##############################################################################################################################################################

# DELETE CLIP
@app.route('/delete_clip/<int:clip_id>', methods=['POST'])
def delete_clip(clip_id):
    if not session.get('admin'):
        return redirect(url_for('login'))
    # Find filename to delete from disk
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT filename FROM music_clips WHERE id = ?", (clip_id,))
        row = c.fetchone()
        if row:
            filename = row[0].replace('\\','/')
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(full_path):
                os.remove(full_path)
            c.execute("DELETE FROM music_clips WHERE id = ?", (clip_id,))
            conn.commit()
    return redirect(url_for('public_clips'))
##############################################################################################################################################################

@app.route('/delete_dataset_file/<property_name>/<tab>/<path:filename>', methods=['POST'])
def delete_dataset_file(property_name, tab, filename):
    if not session.get('admin'):
        return redirect(url_for('login'))

    # 1) Remove local file if it exists (we rarely use this now, but harmless)
    try:
        uploads_root = current_app.config.get("UPLOAD_FOLDER", UPLOAD_FOLDER)
        base_dir = os.path.join(uploads_root, property_name, tab)
        # Only sanitize for the filesystem path:
        safe_fs_name = secure_filename(os.path.basename(filename))
        target_path = os.path.realpath(os.path.join(base_dir, safe_fs_name))
        base_dir_real = os.path.realpath(base_dir)
        if target_path.startswith(base_dir_real + os.sep) and os.path.isfile(target_path):
            os.remove(target_path)
    except Exception as e:
        current_app.logger.warning("File delete warning for %s: %s", filename, e)

    # 2) Delete the catalog row by the *original* filename exactly
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            "DELETE FROM uploads_log WHERE property=? AND tab=? AND filename=?",
            (property_name, tab, filename)   # <- original, NOT secure_filename
        )
        conn.commit()

    # Optional: flash a message (you’re already showing flashes site-wide)
    flash(f"Deleted entry: {filename}")

    return redirect(url_for('property_detail', property_name=property_name, tab=tab))

##############################################################################################################################################################

@app.route('/add_drive_clip', methods=['GET', 'POST'])
def add_drive_clip():
    if not session.get('admin'):
        return redirect(url_for('login'))

    message = ""
    if request.method == 'POST':
        link = request.form.get('link', '').strip()
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        def extract_drive_id(link):
            # Accept both full share URLs and raw file IDs
            match = re.search(r'/d/([a-zA-Z0-9_-]+)', link)
            if match:
                return match.group(1)
            match = re.search(r'id=([a-zA-Z0-9_-]+)', link)
            if match:
                return match.group(1)
            # Fallback: raw ID
            if re.match(r'^[a-zA-Z0-9_-]{10,}$', link):
                return link
            return None

        file_id = extract_drive_id(link)
        if file_id and title:
            preview_url = f"https://drive.google.com/file/d/{file_id}/preview"
            download_url = f"https://drive.google.com/uc?export=download&id={file_id}"
            try:
                with open('/data/drive_music.csv', 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([title, description, preview_url, download_url])
                message = "✅ Clip added successfully!"
            except Exception as e:
                message = f"❌ Error writing to CSV: {e}"
        else:
            message = "❌ Invalid link or missing title."

    return render_template('add_drive_clip.html', message=message)
##############################################################################################################################################################

            # ========== MAIN ==========
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)