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

# ---------- Utility Functions ----------

def allowed_dataset_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DATASET_EXTENSIONS

def allowed_results_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_RESULTS_EXTENSIONS

def allowed_music_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_MUSIC_EXTENSIONS

# ========== Helper Functions ========== #

def ensure_uploads_log_schema():
    """Create/upgrade uploads_log to the expected schema; ensure uniqueness."""
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # Create table if missing (includes UNIQUE on the key)
        c.execute("""
        CREATE TABLE IF NOT EXISTS uploads_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property   TEXT NOT NULL,
            tab        TEXT NOT NULL,
            filename   TEXT NOT NULL,
            uploaded_at TEXT,
            UNIQUE(property, tab, filename)
        )
        """)
        # Ensure uploaded_at column exists (for older DBs)
        cols = {row[1] for row in c.execute("PRAGMA table_info(uploads_log)").fetchall()}
        if "uploaded_at" not in cols:
            c.execute("ALTER TABLE uploads_log ADD COLUMN uploaded_at TEXT")
            # Try to migrate from legacy logged_at if it exists
            try:
                c.execute("UPDATE uploads_log SET uploaded_at = COALESCE(uploaded_at, logged_at) WHERE uploaded_at IS NULL")
            except sqlite3.OperationalError:
                pass  # logged_at may not exist; ignore

        # Ensure a unique index exists even if the table was created long ago
        c.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
        ON uploads_log(property, tab, filename)
        """)
        conn.commit()

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

    def tableize(name: str) -> str:
        # Stable, safe table name from filename only (not full path)
        # e.g. "bandgap.csv" -> "bandgap_csv"
        t = name.replace('.', '_').replace('-', '_').replace(' ', '_')
        return re.sub(r'[^0-9a-zA-Z_]', '_', t)

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
                table_name = tableize(filename)

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
        try:
            auto_import_uploads()
        except Exception as e:
            app.logger.warning("auto_import_uploads skipped: %s", e)
        try:
            auto_log_material_files()
        except Exception as e:
            app.logger.warning("auto_log_material_files skipped: %s", e)
        _startup_done = True

@app.before_request
def _startup_once():
    if not _startup_done:
        _run_startup_tasks()
        

                    # ========== ROUTES ==========

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

# -- Admin-only home page (upload/import/query) --
@app.route('/admin', methods=['GET', 'POST'])
def admin_home():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # Get all uploads (materials) from uploads_log
    uploads = []
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT property, tab, filename, uploaded_at
            FROM uploads_log
            ORDER BY uploaded_at DESC
        """)
        uploads = c.fetchall()

    # Get all music clips from the music_clips table
    music_clips = []
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT filename, title, description FROM music_clips ORDER BY rowid DESC")
            music_clips = c.fetchall()
    except Exception:
        music_clips = []

    return render_template(
        'admin_home.html',
        uploads=uploads,
        music_clips=music_clips
    )

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

# -- View and import (admin only) --
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

    # ---- admin POST handlers ----
    if is_admin and request.method == 'POST':
        # Inline row edit
        if 'edit_row' in request.form:
            row_filename = request.form.get('row_filename') or ''
            safe_row_filename = secure_filename(os.path.basename(row_filename))
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
                        (new_source, new_desc, property_name, tab, safe_row_filename),
                    )
                else:
                    c.execute(
                        """
                        UPDATE uploads_log
                           SET description = ?
                         WHERE property = ? AND tab = ? AND filename = ?
                        """,
                        (new_desc, property_name, tab, safe_row_filename),
                    )
                conn.commit()

            edit_message = f"Updated info for {safe_row_filename}."

        # New file upload
        elif 'file' in request.files:
            f = request.files['file']
            if not f or f.filename == '':
                upload_message = "No file selected."
            else:
                # Validate extension by tab
                if tab == 'dataset':
                    is_allowed = allowed_dataset_file(f.filename)
                    allowed_types = "CSV or NPY"
                else:  # results
                    is_allowed = allowed_results_file(f.filename)
                    allowed_types = "JPG, PNG, GIF, PDF, or DOCX"

                if not is_allowed:
                    upload_message = f"File type not allowed. Only {allowed_types} supported."
                else:
                    # Save to disk (under /uploads/<property>/<tab>/)
                    property_folder = os.path.join(app.config['UPLOAD_FOLDER'], property_name, tab)
                    os.makedirs(property_folder, exist_ok=True)
                    safe_filename = secure_filename(os.path.basename(f.filename))
                    filepath = os.path.join(property_folder, safe_filename)
                    f.save(filepath)

                    # Log to DB (idempotent; no Python datetime)
                    with sqlite3.connect(DB_NAME) as conn:
                        c = conn.cursor()
                        c.execute(
                            """
                            INSERT INTO uploads_log (property, tab, filename, uploaded_at)
                            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                            ON CONFLICT(property, tab, filename)
                            DO UPDATE SET uploaded_at = CURRENT_TIMESTAMP
                            """,
                            (property_name, tab, safe_filename),
                        )
                        conn.commit()

                    upload_message = f"File {safe_filename} uploaded for {pretty_titles[property_name]} {tab.title()}!"

    # ---- fetch current uploads (unique per key thanks to UNIQUE index) ----
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute(
            """
            SELECT filename,
                   COALESCE(source, '')      AS source,
                   COALESCE(description, '') AS description,
                   uploaded_at
              FROM uploads_log
             WHERE property = ? AND tab = ?
          ORDER BY uploaded_at DESC, filename
            """,
            (property_name, tab),
        )
        uploads = c.fetchall()

    return render_template(
        'property_detail.html',
        property_name=property_name,
        pretty_title=pretty_titles[property_name],
        tab=tab,
        uploads=uploads,
        upload_message=upload_message,
        edit_message=edit_message,
        admin=is_admin,
    )
    
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