from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, session
import os
import pandas as pd
import numpy as np
import sqlite3
from werkzeug.utils import secure_filename
import datetime

# ========== SETTINGS ==========
UPLOAD_FOLDER = 'uploads'
DB_NAME = 'patterns-matter.db'
ADMIN_PASSWORD = 'IronMa1deN!'

ALLOWED_DATASET_EXTENSIONS = {'csv', 'npy'}
ALLOWED_RESULTS_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'docx'}
ALLOWED_MUSIC_EXTENSIONS = {'mp3', 'wav', 'm4a', 'ogg', 'mp4'}

# ========== FLASK APP ==========
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'IronMa1deN!'

# Create folders if missing
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

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
        if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], property_name, tab, fname))
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


from flask import abort

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print('Serving file:', full_path)
    if not os.path.isfile(full_path):
        print('File not found:', full_path)
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/clips', methods=['GET', 'POST'])
def public_clips():
    admin = session.get('admin', False)
    message = ""
    # Handle upload if admin and POST
    if admin and request.method == 'POST':
        file = request.files.get('file')
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        if not file or not allowed_music_file(file.filename):
            message = "Please upload a valid music or video file."
        elif not title:
            message = "Title is required."
        else:
            filename = secure_filename(file.filename)
            upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'clips')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            # Store path as forward slash for web
            db_filename = 'clips/' + filename
            try:
                with sqlite3.connect(DB_NAME) as conn:
                    c = conn.cursor()
                    c.execute(
                        "INSERT INTO music_clips (filename, title, description) VALUES (?, ?, ?)",
                        (db_filename, title, description)
                    )
                    conn.commit()
                message = "Clip uploaded!"
            except sqlite3.OperationalError:
                message = "Database table not ready. Use SQL tool to create it first!"

    # Get clips (or show empty list if table missing)
    try:
        with sqlite3.connect(DB_NAME) as conn:
            c = conn.cursor()
            c.execute("SELECT id, filename, title, description FROM music_clips")
            # Always fix: use forward slashes in filename
            clips = [
                (id, filename.replace('\\', '/'), title, description)
                for (id, filename, title, description) in c.fetchall()
            ]
    except sqlite3.OperationalError:
        clips = []
    return render_template('clips.html', clips=clips, admin=admin, message=message)

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
    safe_filename = secure_filename(os.path.basename(filename))
    # Remove from disk
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], property_name, tab, safe_filename)
    if os.path.isfile(file_path):
        os.remove(file_path)
    # Remove from DB
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM uploads_log WHERE property=? AND tab=? AND filename=?", (property_name, tab, safe_filename))
        conn.commit()
    return redirect(url_for('property_detail', property_name=property_name, tab=tab))

# --- Print routes for debugging (optional, can comment out) ---
for rule in app.url_map.iter_rules():
    print(rule.endpoint, rule)

# ========== MAIN ==========
if __name__ == '__main__':
    app.run(debug=True)