                    # Toydatabase for Patterns Matter #
# ======= Imports ====== #

from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, session, current_app, abort, jsonify
import os
import pandas as pd
import numpy as np
import sqlite3
from werkzeug.utils import secure_filename
import datetime
import re
import csv
<<<<<<< HEAD
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
import io, base64, zipfile
from typing import List, Dict, Optional

=======
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc

# ========== SETTINGS ==========

UPLOAD_FOLDER = 'uploads'
DB_NAME = 'patterns-matter.db' # SQLite database file
ADMIN_PASSWORD = 'IronMa1deN!'

ALLOWED_DATASET_EXTENSIONS = {'csv', 'npy'}
ALLOWED_RESULTS_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'docx'}
ALLOWED_MUSIC_EXTENSIONS = {'mp3', 'wav', 'm4a', 'ogg', 'mp4'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'IronMa1deN!'

<<<<<<< HEAD
GDRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]

=======
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
# ---------- Utility Functions ----------

def allowed_dataset_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DATASET_EXTENSIONS

def allowed_results_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_RESULTS_EXTENSIONS

def allowed_music_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_MUSIC_EXTENSIONS

# ========== Helper Functions ========== #

<<<<<<< HEAD
def get_drive_service():
    """
    Build a Drive v3 service from a Service Account.
    Reads either:
      - GDRIVE_SA_JSON: absolute path to JSON in the VM
      - GDRIVE_SA_JSON_BASE64: base64-encoded JSON content
    Requires env: GDRIVE_ROOT_FOLDER_ID (top folder shared with SA).
    """
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
    except Exception as ie:
        raise RuntimeError(
            "Google API libraries not installed. "
            "Add to requirements.txt: google-api-python-client google-auth google-auth-httplib2"
        ) from ie

    scopes = ["https://www.googleapis.com/auth/drive"]
    json_path = os.environ.get("GDRIVE_SA_JSON")
    json_b64 = os.environ.get("GDRIVE_SA_JSON_BASE64")

    if json_path and os.path.isfile(json_path):
        creds = service_account.Credentials.from_service_account_file(json_path, scopes=scopes)
    elif json_b64:
        info = json.loads(base64.b64decode(json_b64).decode("utf-8"))
        creds = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    else:
        raise RuntimeError("Missing service account: set GDRIVE_SA_JSON or GDRIVE_SA_JSON_BASE64.")

    try:
        service = build("drive", "v3", credentials=creds, cache_discovery=False)
        return service
    except Exception as e:
        raise RuntimeError(f"Failed to build Drive service: {e}")

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

def drive_find_or_create_folder(service, parent_id: str, name: str) -> str:
    """Find a folder by name under parent; create if missing. Returns folder ID."""
    q = (
        f"mimeType='application/vnd.google-apps.folder' "
        f"and name='{name.replace(\"'\", \"\\'\")}' "
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

def drive_ensure_property_tab_folder(service, root_folder_id: str, prop: str, tab: str) -> str:
    """
    Ensures a structure: <root>/<prop>/<tab> exists, returns final folder ID.
    """
    prop_id = drive_find_or_create_folder(service, root_folder_id, prop)
    tab_id = drive_find_or_create_folder(service, prop_id, tab)
    return tab_id

def drive_list_folder_files(service, folder_id: str) -> List[Dict]:
    """
    List non-trashed files (id,name,mimeType) directly under folder_id.
    We rely on filename extension for filtering by tab.
    """
    items = []
    page_token = None
    while True:
        res = service.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            fields="nextPageToken, files(id,name,mimeType)",
            pageSize=1000,
            pageToken=page_token
        ).execute()
        items.extend(res.get("files", []))
        page_token = res.get("nextPageToken")
        if not page_token:
            break
    return items

def drive_upload_bytes(service, folder_id: str, filename: str, data: bytes) -> str:
    """Upload a new file into folder_id. Returns file ID."""
    from googleapiclient.http import MediaIoBaseUpload
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/octet-stream", resumable=False)
    body = {"name": filename, "parents": [folder_id]}
    created = service.files().create(body=body, media_body=media, fields="id").execute()
    return created["id"]

def _ext_ok_for_tab(filename: str, tab: str) -> bool:
    ext = (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    if tab == "dataset":
        return ext in ALLOWED_DATASET_EXTENSIONS
    return ext in ALLOWED_RESULTS_EXTENSIONS

def _drive_urls(file_id: str) -> (str, str):
    preview = f"https://drive.google.com/file/d/{file_id}/preview"
    download = f"https://drive.google.com/uc?export=download&id={file_id}"
    return preview, download

#==================================================#

=======
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
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

def file_to_table_name(filename: str) -> str:
    """
    Small wrapper that ensures we only pass a basename to the canonical function.
    Use this everywhere you need to turn a filename into a table name.
    """
    import os
    return tableize_basename(os.path.basename(filename or ""))

#==================================================#

<<<<<<< HEAD
# Google Drive integration using service account creds

def drive():
    """Build a Drive service using service-account creds from env."""
    sa_path = os.environ.get("GDRIVE_SA_JSON", "").strip()
    sa_b64 = os.environ.get("GDRIVE_SA_JSON_BASE64", "").strip()
    if sa_path and os.path.isfile(sa_path):
        creds = Credentials.from_service_account_file(sa_path, scopes=GDRIVE_SCOPES)
    elif sa_b64:
        import base64, json, tempfile
        data = json.loads(base64.b64decode(sa_b64).decode("utf-8"))
        creds = Credentials.from_service_account_info(data, scopes=GDRIVE_SCOPES)
    else:
        raise RuntimeError("No service account credentials provided (GDRIVE_SA_JSON or GDRIVE_SA_JSON_BASE64).")
    return build("drive", "v3", credentials=creds, cache_discovery=False)

def make_file_public(file_id: str):
    """Ensure the file is readable by 'anyone with the link'."""
    svc = drive()
    try:
        svc.permissions().create(
            fileId=file_id,
            body={"role": "reader", "type": "anyone"},
            fields="id",
        ).execute()
    except Exception:
        # If permission already exists, ignore.
        pass

def drive_links(file_id: str):
    """Return (preview_url, download_url)."""
    return (f"https://drive.google.com/file/d/{file_id}/preview",
            f"https://drive.google.com/uc?export=download&id={file_id}")

def _is_folder(item): 
    return item.get("mimeType") == "application/vnd.google-apps.folder"

def _drive_list_children(parent_id: str):
    """Yield children of a Drive folder."""
    svc = drive()
    q = f"'{parent_id}' in parents and trashed=false"
    token = None
    while True:
        resp = svc.files().list(
            q=q, spaces="drive",
            fields="nextPageToken, files(id,name,mimeType,modifiedTime)",
            pageToken=token, pageSize=1000).execute()
        for f in resp.get("files", []):
            yield f
        token = resp.get("nextPageToken")
        if not token:
            break

def _find_child_by_name(parent_id: str, name: str):
    for f in _drive_list_children(parent_id):
        if f.get("name") == name:
            return f
    return None

def _ensure_folder(parent_id: str, name: str):
    """Find or create a subfolder."""
    svc = drive()
    existing = _find_child_by_name(parent_id, name)
    if existing and _is_folder(existing):
        return existing["id"]
    meta = {"name": name, "mimeType": "application/vnd.google-apps.folder", "parents": [parent_id]}
    created = svc.files().create(body=meta, fields="id").execute()
    return created["id"]

#==================================================#

=======
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
def ensure_uploads_log_schema():
    """Public catalog (uploads_log) + audit history (uploads_audit) with triggers."""
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()

        # Public catalog (what public pages read)
        c.execute("""
        CREATE TABLE IF NOT EXISTS uploads_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            property    TEXT NOT NULL,
            tab         TEXT NOT NULL,      -- 'dataset' | 'results'
            filename    TEXT NOT NULL,      -- human-visible label
            uploaded_at TEXT,               -- first/last touch, maintained by app
            -- Drive-first metadata
            storage     TEXT,               -- 'drive' | 'local' (legacy)
            drive_id    TEXT,
            preview_url TEXT,
            download_url TEXT,
            source      TEXT,
            description TEXT,
            UNIQUE(property, tab, filename)
        )
        """)

        # Ensure index exists even on old DBs
        c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
        ON uploads_log(property, tab, filename)
        """)

        # ---- Audit table
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

        # Helper to create triggers idempotently
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

        conn.commit()

#==================================================#

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

#==================================================#
              
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

#==================================================#

# Run-once warm-up
from threading import Lock

_startup_done = False
_startup_lock = Lock()

def _run_startup_tasks():
    global _startup_done
    with _startup_lock:
        if _startup_done:
            return
        try:
            ensure_uploads_log_schema()   # if you have this helper; otherwise drop it
        except Exception as e:
            app.logger.warning("ensure_uploads_log_schema skipped: %s", e)
<<<<<<< HEAD
        # try:
        #     auto_import_uploads()
        # except Exception as e:
        #     app.logger.warning("auto_import_uploads skipped: %s", e)
        # try:
        #     auto_log_material_files()
        # except Exception as e:
        #     app.logger.warning("auto_log_material_files skipped: %s", e)
            
=======
        try:
            auto_import_uploads()
        except Exception as e:
            app.logger.warning("auto_import_uploads skipped: %s", e)
        try:
            auto_log_material_files()
        except Exception as e:
            app.logger.warning("auto_log_material_files skipped: %s", e)
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
        _startup_done = True

@app.before_request
def _startup_once():
    if not _startup_done:
        _run_startup_tasks()
        

####################################### ========== ROUTES ==========#####################################

#########################################################

# --- Public home + Admin SQL Query Tool (CRUD, multi-statement) ---
def _list_user_tables():
    """List non-internal SQLite tables for display in the SQL tool and home page."""
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

#########################################################

# Public home used by multiple templates (and health check lands here )
@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def public_home():
    #tables = _list_user_tables()
    return render_template("landing.html")

#########################################################

@app.route("/materials", methods=["GET"])
def materials_portal():
    # Uses your templates/materials_portal.html
    return render_template("materials_portal.html")

#########################################################

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

#########################################################

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
    
#########################################################

# -- Admin login/logout --
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session['admin'] = True
            flash("Logged in as admin.")
            return redirect(url_for('public_home'))
        else:
            flash("Incorrect password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('admin', None)
    flash("Logged out.")
    return redirect(url_for('public_home'))

#########################################################

# --- Admin Dashboard (history-only) ---
@app.route('/admin', methods=['GET'])
def admin_home():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Make sure catalog + audit schema exist (triggers are created here too)
    ensure_uploads_log_schema()

    # Build the history table: when first added, and whether still present publicly
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
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

#########################################################

@app.route("/admin/fix_uploads_uniqueness", methods=["GET", "POST"])
def fix_uploads_uniqueness():
    if not session.get("admin"):
        abort(403)

    stats = {}
    try:
        # The schema helper may fail while dups exist; ignore and continue.
        try:
            ensure_uploads_log_schema()
        except Exception as e:
            app.logger.warning("ensure_uploads_log_schema raised (continuing): %s", e)

        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()

            rows_before = c.execute("SELECT COUNT(*) FROM uploads_log").fetchone()[0]
            dup_groups_before = c.execute("""
                SELECT COUNT(*)
                  FROM (
                    SELECT property, tab, filename, COUNT(*) c
                      FROM uploads_log
                     GROUP BY property, tab, filename
                    HAVING c > 1
                  )
            """).fetchone()[0]

            deleted = 0
            used_window = False

            if dup_groups_before > 0:
                # Prefer window-function method (keeps newest by uploaded_at, then highest rowid)
                try:
                    c.execute("""
                        WITH ranked AS (
                          SELECT rowid,
                                 property, tab, filename,
                                 COALESCE(uploaded_at, '') AS ts,
                                 ROW_NUMBER() OVER (
                                   PARTITION BY property, tab, filename
                                   ORDER BY ts DESC, rowid DESC
                                 ) AS rn
                          FROM uploads_log
                        )
                        DELETE FROM uploads_log
                         WHERE rowid IN (SELECT rowid FROM ranked WHERE rn > 1);
                    """)
                    used_window = True
                    deleted = conn.total_changes
                except sqlite3.OperationalError:
                    # Fallback for older SQLite (no window functions):
                    # keep the earliest row per key (good enough to enforce uniqueness)
                    c.execute("""
                        DELETE FROM uploads_log
                         WHERE rowid NOT IN (
                           SELECT MIN(rowid)
                             FROM uploads_log
                            GROUP BY property, tab, filename
                         );
                    """)
                    deleted = conn.total_changes

            # Now enforce uniqueness with an index.
            # If dups remain for any reason, this will raise; we’ll report below.
            try:
                c.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
                    ON uploads_log(property, tab, filename)
                """)
            except sqlite3.OperationalError as e:
                app.logger.warning("creating unique index failed: %s", e)

            conn.commit()

            rows_after = c.execute("SELECT COUNT(*) FROM uploads_log").fetchone()[0]
            dup_groups_after = c.execute("""
                SELECT COUNT(*)
                  FROM (
                    SELECT property, tab, filename, COUNT(*) c
                      FROM uploads_log
                     GROUP BY property, tab, filename
                    HAVING c > 1
                  )
            """).fetchone()[0]

        stats.update({
            "rows_before": rows_before,
            "duplicate_groups_before": dup_groups_before,
            "deleted_rows": deleted,
            "used_window_delete": used_window,
            "rows_after": rows_after,
            "duplicate_groups_after": dup_groups_after,
            "status": "ok" if dup_groups_after == 0 else "still_has_duplicates"
        })
        return jsonify(stats)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500    
    
#########################################################

@app.route("/healthz")
def healthz():
    # Must be super fast and always 200 so Fly can mark the machine healthy
    return "ok", 200

#########################################################

@app.route("/diag/routes")
def diag_routes():
    # Lets you confirm which routes are actually registered in prod
    if not session.get("admin"):
        abort(403)
    rules = sorted([str(r) for r in app.url_map.iter_rules()])
    return jsonify({"routes": rules})

#########################################################

<<<<<<< HEAD
# -- View and import (admin + public, Drive-only adds) --
=======
# -- View and import (admin + Public) --
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
# -- View and import (admin + Public) --
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

<<<<<<< HEAD
    # ---- admin POST handlers ----
    if is_admin and request.method == 'POST':
        try:
            # 0) Ensure storage columns exist (for upgraded DBs)
            try:
                with sqlite3.connect(DB_NAME) as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT storage, drive_id, preview_url, download_url FROM uploads_log LIMIT 1")
            except Exception:
                with sqlite3.connect(DB_NAME) as conn:
                    cur = conn.cursor()
                    cur.execute("ALTER TABLE uploads_log ADD COLUMN storage TEXT")
                    cur.execute("ALTER TABLE uploads_log ADD COLUMN drive_id TEXT")
                    cur.execute("ALTER TABLE uploads_log ADD COLUMN preview_url TEXT")
                    cur.execute("ALTER TABLE uploads_log ADD COLUMN download_url TEXT")
                    conn.commit()

            # 1) Add a single Drive file by link/ID
            if request.form.get('add_drive'):
                drive_link = request.form.get('drive_link', '').strip()
                label = request.form.get('label', '').strip()
                new_source = (request.form.get('row_source') or '').strip() if tab == 'dataset' else None
                new_desc = (request.form.get('row_description') or '').strip()

                ext = (label.rsplit('.', 1)[-1].lower() if '.' in label else '')
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
                        with sqlite3.connect(DB_NAME) as conn:
                            c = conn.cursor()
                            c.execute(
                                """
                                INSERT INTO uploads_log
                                   (property, tab, filename, uploaded_at, storage, drive_id, preview_url, download_url, source, description)
                                VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'drive', ?, ?, ?, ?, ?)
                                ON CONFLICT(property, tab, filename)
                                DO UPDATE SET
                                   uploaded_at = CURRENT_TIMESTAMP,
                                   storage = 'drive',
                                   drive_id = excluded.drive_id,
                                   preview_url = excluded.preview_url,
                                   download_url = excluded.download_url,
                                   source = COALESCE(excluded.source, uploads_log.source),
                                   description = COALESCE(excluded.description, uploads_log.description)
                                """,
                                (property_name, tab, label, file_id, preview_url, download_url, new_source, new_desc),
                            )
                            conn.commit()
                        upload_message = f"Added Drive item '{label}'."

            # 2) Link a Drive FOLDER → import all allowed files
            elif request.form.get('link_folder'):
                folder_link = request.form.get('drive_folder_link', '').strip()
                folder_id = _drive_extract_id(folder_link)
                if not folder_id:
                    upload_message = "Invalid Drive folder link or ID."
                else:
                    service = get_drive_service()
                    # list files and import those with allowed extensions for this tab
                    files = drive_list_folder_files(service, folder_id)
                    imported = 0
                    with sqlite3.connect(DB_NAME) as conn:
                        c = conn.cursor()
                        for f in files:
                            name = f.get("name") or ""
                            if not _ext_ok_for_tab(name, tab):
                                continue
                            fid = f["id"]
                            preview_url, download_url = _drive_urls(fid)
                            c.execute(
                                """
                                INSERT INTO uploads_log
                                   (property, tab, filename, uploaded_at, storage, drive_id, preview_url, download_url)
                                VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'drive', ?, ?, ?)
                                ON CONFLICT(property, tab, filename)
                                DO UPDATE SET
                                   uploaded_at = CURRENT_TIMESTAMP,
                                   storage = 'drive',
                                   drive_id = excluded.drive_id,
                                   preview_url = excluded.preview_url,
                                   download_url = excluded.download_url
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
                        root_id = os.environ.get("GDRIVE_ROOT_FOLDER_ID", "").strip()
                        if not root_id:
                            raise RuntimeError("GDRIVE_ROOT_FOLDER_ID not set.")
                        service = get_drive_service()
                        target_folder_id = drive_ensure_property_tab_folder(service, root_id, property_name, tab)

                        data = zf.read()
                        z = zipfile.ZipFile(io.BytesIO(data))
                        uploaded = 0

                        # Upload allowed files only
                        with sqlite3.connect(DB_NAME) as conn:
                            c = conn.cursor()
                            for info in z.infolist():
                                if info.is_dir():
                                    continue
                                # we only want the basename to be the label/filename
                                base = os.path.basename(info.filename)
                                if not base:
                                    continue
                                if not _ext_ok_for_tab(base, tab):
                                    continue
                                file_bytes = z.read(info)
                                fid = drive_upload_bytes(service, target_folder_id, base, file_bytes)
                                preview_url, download_url = _drive_urls(fid)
                                c.execute(
                                    """
                                    INSERT INTO uploads_log
                                       (property, tab, filename, uploaded_at, storage, drive_id, preview_url, download_url)
                                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'drive', ?, ?, ?)
                                    ON CONFLICT(property, tab, filename)
                                    DO UPDATE SET
                                       uploaded_at = CURRENT_TIMESTAMP,
                                       storage = 'drive',
                                       drive_id = excluded.drive_id,
                                       preview_url = excluded.preview_url,
                                       download_url = excluded.download_url
                                    """,
                                    (property_name, tab, base, fid, preview_url, download_url),
                                )
                                uploaded += 1
                            conn.commit()

                        upload_message = f"Uploaded {uploaded} file(s) from ZIP to Drive."
                    except Exception as e:
                        upload_message = f"ZIP upload failed: {e}"

            # 4) Inline edit (source/description) – unchanged
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
                edit_message = f"Updated info for {row_filename}."

        except Exception as e:
            upload_message = f"Error: {e}"

    # ---- fetch current uploads (public catalog) ----
=======
    # Helper: parse Google Drive link or raw id
    def _extract_drive_id(link_or_id: str):
        s = (link_or_id or "").strip()
        m = re.search(r"/d/([a-zA-Z0-9_-]+)", s)
        if m: return m.group(1)
        m = re.search(r"[?&]id=([a-zA-Z0-9_-]+)", s)
        if m: return m.group(1)
        if re.match(r"^[a-zA-Z0-9_-]{10,}$", s):
            return s
        return None

    # Make sure schema exists (columns like storage/preview_url/etc.)
    try:
        ensure_uploads_log_schema()
    except Exception as e:
        app.logger.warning("ensure_uploads_log_schema: %s", e)

    # ---- admin POST handlers ----
    if is_admin and request.method == 'POST':
        # 1) Add Drive entry
        if request.form.get('add_drive'):
            drive_link = request.form.get('drive_link', '').strip()
            label = request.form.get('label', '').strip()
            new_source = (request.form.get('row_source') or '').strip() if tab == 'dataset' else None
            new_desc = (request.form.get('row_description') or '').strip()

            # Basic ext check from label to keep tabs consistent
            ext = (label.rsplit('.', 1)[-1].lower() if '.' in label else '')
            if tab == 'dataset' and ext not in ALLOWED_DATASET_EXTENSIONS:
                upload_message = "Label must end with .csv or .npy for datasets."
            elif tab == 'results' and ext not in ALLOWED_RESULTS_EXTENSIONS:
                upload_message = f"Label must be one of: {', '.join(sorted(ALLOWED_RESULTS_EXTENSIONS))}."
            else:
                file_id = _extract_drive_id(drive_link)
                if not file_id:
                    upload_message = "Invalid Google Drive link or ID."
                else:
                    preview_url = f"https://drive.google.com/file/d/{file_id}/preview"
                    download_url = f"https://drive.google.com/uc?export=download&id={file_id}"
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

        # 2) Inline edit (source/description)
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
            edit_message = f"Updated info for {row_filename}."

    # ---- fetch current uploads as plain dicts (so Jinja `row.filename` works) ----
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """
<<<<<<< HEAD
            SELECT filename,
                   COALESCE(source,'')      AS source,
                   COALESCE(description,'') AS description,
                   uploaded_at,
                   COALESCE(storage,'local') AS storage,
                   preview_url,
                   download_url
=======
            SELECT
                filename,
                COALESCE(source,'')        AS source,
                COALESCE(description,'')   AS description,
                uploaded_at,
                COALESCE(storage,'local')  AS storage,
                COALESCE(preview_url,'')   AS preview_url,
                COALESCE(download_url,'')  AS download_url
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
              FROM uploads_log
             WHERE property = ? AND tab = ?
          ORDER BY uploaded_at DESC, filename
            """,
            (property_name, tab),
        )
<<<<<<< HEAD
        uploads = c.fetchall()

    # Map local dataset filenames to SQL table names (for old/local files)
    table_map = {}
    if tab == 'dataset':
        for row in uploads:
            if (row['storage'] or 'local') != 'drive':
                fname = row['filename']
                if fname and (fname.endswith('.csv') or fname.endswith('.npy')):
=======
        uploads = [dict(r) for r in c.fetchall()]

    # Map local dataset filenames to SQL table names (for potential view links)
    table_map = {}
    if tab == 'dataset':
        for row in uploads:
            if row.get('storage') != 'drive':
                fname = row.get('filename', '')
                if fname.endswith('.csv') or fname.endswith('.npy'):
>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
                    table_map[fname] = file_to_table_name(fname)

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
<<<<<<< HEAD
=======

>>>>>>> de853a6ad379935603467611a67615b2f6aed6dc
    
#########################################################

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print('Serving file:', full_path)
    if not os.path.isfile(full_path):
        print('File not found:', full_path)
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

#########################################################

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

#########################################################

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

#########################################################

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

#########################################################

@app.route('/dataset/<table>')
def public_view(table):
    # Anyone can view any table
    with sqlite3.connect(DB_NAME) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
    return render_template('view_table.html',
                           tables=[df.to_html(classes='data')],
                           titles=df.columns.values,
                           filename=table,
                           imported_table=table,
                           admin=False)
    
#########################################################

@app.route('/download/<table>')
def download(table):
    with sqlite3.connect(DB_NAME) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
    csv_path = os.path.join(UPLOAD_FOLDER, f"{table}.csv")
    df.to_csv(csv_path, index=False)
    return send_from_directory(UPLOAD_FOLDER, f"{table}.csv", as_attachment=True)

#########################################################

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
    
#########################################################

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

#########################################################

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

#########################################################

# DELETE DATASET/RESULT FILE
from urllib.parse import unquote

@app.route('/delete_dataset_file/<property_name>/<tab>/<path:filename>', methods=['POST'])
def delete_dataset_file(property_name, tab, filename):
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Build and validate the target path
    uploads_root = current_app.config.get("UPLOAD_FOLDER", UPLOAD_FOLDER)
    base_dir = os.path.join(uploads_root, property_name, tab)
    safe_name = secure_filename(os.path.basename(filename))
    target_path = os.path.realpath(os.path.join(base_dir, safe_name))
    base_dir_real = os.path.realpath(base_dir)
    if not (target_path == base_dir_real or target_path.startswith(base_dir_real + os.sep)):
        abort(400, description="Invalid file path")

    # Remove file if present
    try:
        if os.path.isfile(target_path):
            os.remove(target_path)
    except Exception as e:
        print(f"File delete warning: {e}")

    # Remove exactly one row by composite key
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            "DELETE FROM uploads_log WHERE property=? AND tab=? AND filename=?",
            (property_name, tab, safe_name)
        )
        conn.commit()

    return redirect(url_for('property_detail', property_name=property_name, tab=tab))

#########################################################

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

#########################################################

            # ========== MAIN ==========
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)