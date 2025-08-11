# Test deploy via GitHub Actions. This app will temporarily run on a public IP.
# It is a Flask web application that allows users to upload datasets, view results, and manage
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

# the  current auto_log_material_files() ---
def ensure_uploads_log_schema():
    # Creates the table and backfills missing columns so existing DBs keep working
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS uploads_log (
                property     TEXT NOT NULL,
                tab          TEXT NOT NULL,
                filename     TEXT NOT NULL,
                uploaded_at  TEXT,
                source       TEXT,
                description  TEXT
            )
        """)
        # Backfill columns if the table already existed without them
        existing = {row[1] for row in c.execute("PRAGMA table_info(uploads_log)")}
        for col, ddl in [
            ("uploaded_at", "ALTER TABLE uploads_log ADD COLUMN uploaded_at TEXT"),
            ("source",      "ALTER TABLE uploads_log ADD COLUMN source TEXT"),
            ("description", "ALTER TABLE uploads_log ADD COLUMN description TEXT"),
        ]:
            if col not in existing:
                c.execute(ddl)

        c.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_unique
            ON uploads_log(property, tab, filename)
        """)
        conn.commit()


def auto_log_material_files():
    ensure_uploads_log_schema()

    # Avoid relying on current_app when we can read from app.config directly
    upload_root = app.config.get("UPLOAD_FOLDER", UPLOAD_FOLDER)
    if not os.path.exists(upload_root):
        return

    all_allowed_exts = ALLOWED_DATASET_EXTENSIONS | ALLOWED_RESULTS_EXTENSIONS
    to_insert = []

    for root, _, files in os.walk(upload_root):
        rel_root = os.path.relpath(root, upload_root)
        if rel_root.split(os.sep)[0] == "clips":
            continue

        for fname in files:
            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
            if ext not in all_allowed_exts:
                continue

            rel_path = os.path.relpath(os.path.join(root, fname), upload_root)
            parts = rel_path.split(os.sep)
            if len(parts) >= 3:
                property_name, tab, file_name = parts[0], parts[1], parts[2]
                to_insert.append((property_name, tab, file_name))

    if not to_insert:
        return

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        # Upsert: if the file is already logged, refresh uploaded_at
        c.executemany("""
            INSERT INTO uploads_log (property, tab, filename, uploaded_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(property, tab, filename)
            DO UPDATE SET uploaded_at=excluded.uploaded_at
        """, to_insert)
        conn.commit()


# ========== FLASK APP ==========

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'IronMa1deN!'

@app.before_first_request
def _warm_up():
    try:
        auto_import_uploads()
    except Exception as e:
        app.logger.warning("auto_import_uploads skipped: %s", e)
    try:
        auto_log_material_files()
    except Exception as e:
        app.logger.warning("auto_log_material_files skipped: %s", e)


# ---------- Utility Functions ----------
def allowed_dataset_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DATASET_EXTENSIONS

def allowed_results_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_RESULTS_EXTENSIONS

def allowed_music_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_MUSIC_EXTENSIONS

# ========== ROUTES ==========

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

# -- View and import (admin only) --
@app.route('/view/<path:filename>', methods=['GET', 'POST'])
def view_table(filename):
    admin = session.get('admin', False)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    ext = filename.rsplit('.', 1)[1].lower()
    table_name = filename.replace('.', '_').replace('-', '_').replace('/', '_').replace('\\', '_')

    try:
        if ext == 'csv':
            df = pd.read_csv(filepath)
        elif ext == 'npy':
            arr = np.load(filepath, allow_pickle=True)
            if isinstance(arr, np.ndarray):
                if arr.ndim == 2:
                    df = pd.DataFrame(arr)
                elif arr.ndim == 1 and hasattr(arr[0], 'dtype') and arr[0].dtype.names:
                    df = pd.DataFrame(arr)
                else:
                    df = pd.DataFrame(arr)
            else:
                return "Unsupported NPY format for display."
        else:
            return "Unsupported file type."
    except Exception as e:
        return f"Could not read file: {e}"

    # Only allow import if admin
    if admin and request.method == 'POST' and 'import_sql' in request.form:
        with sqlite3.connect(DB_NAME) as conn:
            df.to_sql(table_name, conn, if_exists='replace', index=False)
        flash(f"Table '{table_name}' imported to SQLite.")

    return render_template('view_table.html',
                           tables=[df.to_html(classes='data')],
                           titles=df.columns.values,
                           filename=filename,
                           imported_table=table_name,
                           admin=admin)


# -- SQL query tool (admin only) --
@app.route('/query', methods=['GET', 'POST'])
def query_sql():
    if not session.get('admin'):
        return redirect(url_for('login'))

    # List all tables for dropdown or info
    tables = []
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in c.fetchall()]

    sql = ""
    result_html = ""
    error_msg = ""

    if request.method == 'POST':  
        sql = request.form['sql']
        try:
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute(sql)
                # Try to fetch rows, if any
                try:
                    rows = c.fetchall()
                    if rows:
                        # Get column names
                        columns = [desc[0] for desc in c.description]
                        import pandas as pd
                        df = pd.DataFrame(rows, columns=columns)
                        result_html = df.to_html(classes='data')
                    else:
                        result_html = "<p><b>Query executed successfully.</b></p>"
                except Exception:
                    result_html = "<p><b>Query executed successfully.</b></p>"
                conn.commit()
        except Exception as e:
            error_msg = str(e)
    return render_template(
        'sql_query.html',
        tables=tables,
        sql=sql,
        result_html=result_html,
        error_msg=error_msg,
        admin=True
    )

# ========== PUBLIC ROUTES (view/download only) ==========

@app.route('/')
def public_home():
    return render_template('landing.html')

@app.route('/materials')
def materials_portal():
    return render_template('materials_portal.html')

@app.route('/materials/<property_name>/<tab>', methods=['GET', 'POST'])
def property_detail(property_name, tab):
    pretty_titles = {
        'bandgap': 'Band Gap',
        'formation_energy': 'Formation Energy',
        'melting_point': 'Melting Point',
        'oxidation_state': 'Oxidation State'
    }
    if property_name not in pretty_titles or tab not in ['dataset', 'results']:
        return "Not found.", 404

    upload_message = ""
    edit_message = ""
    is_admin = session.get('admin', False)

    if is_admin and request.method == 'POST':
        # Inline edit form (from table row)
        if 'edit_row' in request.form:
            row_filename = request.form.get('row_filename')
            new_source = request.form.get('row_source', '').strip() if tab == 'dataset' else None
            new_desc = request.form.get('row_description', '').strip()
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                if tab == 'dataset':
                    c.execute("""
                        UPDATE uploads_log
                        SET source=?, description=?
                        WHERE property=? AND tab=? AND filename=?
                    """, (new_source, new_desc, property_name, tab, row_filename))
                else:
                    c.execute("""
                        UPDATE uploads_log
                        SET description=?
                        WHERE property=? AND tab=? AND filename=?
                    """, (new_desc, property_name, tab, row_filename))
                conn.commit()
            edit_message = f"Updated info for {row_filename}."
        # Upload form
        elif 'file' in request.files:
            if request.files['file'].filename == '':
                upload_message = "No file selected."
            else:
                file = request.files['file']
                # Set allowed extensions logic
                if tab == 'dataset':
                    is_allowed = allowed_dataset_file(file.filename)
                    allowed_types = "CSV or NPY"
                elif tab == 'results':
                    is_allowed = allowed_results_file(file.filename)
                    allowed_types = "JPG, PNG, GIF, PDF, or DOCX"
                else:
                    is_allowed = False
                    allowed_types = ""

                if file and is_allowed:
                    property_folder = os.path.join(app.config['UPLOAD_FOLDER'], property_name, tab)
                    os.makedirs(property_folder, exist_ok=True)
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(property_folder, filename)
                    file.save(filepath)
                    # LOG THE UPLOAD!
                    with sqlite3.connect(DB_NAME) as conn:
                        c = conn.cursor()
                        c.execute(
                            "INSERT INTO uploads_log (property, tab, filename, uploaded_at) VALUES (?, ?, ?, ?)",
                            (property_name, tab, filename, datetime.datetime.now().isoformat())
                        )
                        conn.commit()
                    upload_message = f"File {filename} uploaded for {pretty_titles[property_name]} {tab.title()}!"
                else:
                    upload_message = f"File type not allowed. Only {allowed_types} supported."

    # Always fetch current uploads after handling POSTs
    uploads = []
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT filename, source, description, uploaded_at
            FROM uploads_log
            WHERE property=? AND tab=?
            ORDER BY uploaded_at DESC
        """, (property_name, tab))
        uploads = c.fetchall()
    uploads = [
        (fname, source, description, uploaded_at)
        for (fname, source, description, uploaded_at) in uploads
    ]

    return render_template(
        'property_detail.html',
        property_name=property_name,
        pretty_title=pretty_titles[property_name],
        tab=tab,
        uploads=uploads,
        upload_message=upload_message,
        edit_message=edit_message,
        admin=is_admin
    )


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print('Serving file:', full_path)
    if not os.path.isfile(full_path):
        print('File not found:', full_path)
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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

@app.route('/download/<table>')
def download(table):
    with sqlite3.connect(DB_NAME) as conn:
        df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
    csv_path = os.path.join(UPLOAD_FOLDER, f"{table}.csv")
    df.to_csv(csv_path, index=False)
    return send_from_directory(UPLOAD_FOLDER, f"{table}.csv", as_attachment=True)

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



# ========== MAIN ==========
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)