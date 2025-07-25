**Relational Database Management Systems (RDBMS):**
Designing relational data models: Used SQLite with tables for datasets and music clips.

Normalizing data: Structured uploads by property/tab, logging all uploads (with filename, property, tab, upload date, etc.).

CRUD operations: Created, read, updated, and deleted records using SQL and Python.

Foreign keys (conceptual): Related dataset files to material properties, and music clips to metadata.

SQL querying: Built custom queries, a SQL query tool, and explored database introspection (SELECT name FROM sqlite_master).

**Web Development (Full Stack):**
Backend: Flask routes, session management, file upload/download, dynamic rendering with Jinja2 templates.

Frontend: HTML5 structure, CSS for layout/design, responsive tables, and forms for admin and user actions.

RESTful patterns: Used logical URLs for resources (/clips, /materials/bandgap/dataset, etc.).

Security: Used admin sessions, upload validation, and login/logout flows.

**Data Management & User Experience:**
Search: Built a global search bar, retrieving results from SQL for both datasets and clips.

File organization: Uploaded files stored in structured subfolders, linked in the database for easy lookup.

Inline editing: Allowed admins to update dataset “source” and “description” directly in the web table.

Robust error handling: Clear messages for missing files, bad uploads, or DB errors.

Version control: Managed project with Git/GitHub.

## Quick Start

1. Install requirements: pip install -r requirements.txt
2. Run the app:
3. Open [http://localhost:5000](http://localhost:5000)

## Project Structure
app.py
static/
templates/
uploads/ # (excluded from repo)
patterns-matter.db # (excluded from repo)

## License

MIT 

## Contact

Sayeed Shahriar  
sayeed.shahriar@gmail.com

