from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import json
import os
import math
from datetime import datetime, timedelta

app = FastAPI(title="Cyber Vault API")

# Cấu hình CORS để FE gọi được BE
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "/root/cyber_vault/cyber_vault.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.on_event("startup")
def init_db():
    try:
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS vault_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT,
                cwe TEXT,
                cve TEXT,
                severity TEXT,
                language TEXT NOT NULL,
                format TEXT NOT NULL,
                file_path TEXT NOT NULL UNIQUE,
                date_added DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip_address TEXT PRIMARY KEY,
                banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error initializing database: {e}")

@app.get("/api/vault")
def get_vault_items(search: str = None, severity: str = None, lang: str = 'vi', page: int = Query(1, ge=1)):
    limit = 20
    conn = get_db_connection()
    
    base_query = "FROM vault_index WHERE format = 'json' AND language = ?"
    params = [lang]

    if search:
        base_query += " AND (title LIKE ? OR category LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if severity:
        if severity == "Medium to High":
            base_query += " AND (severity LIKE '%Medium to High%' OR severity LIKE '%Trung bình đến Cao%' OR severity LIKE '%Trung binh den Cao%')"
        elif severity == "High to Critical":
            base_query += " AND (severity LIKE '%High to Critical%' OR severity LIKE '%Cao đến Nghiêm trọng%' OR severity LIKE '%Cao den Nghiem trong%')"
        elif severity == "Critical":
            base_query += " AND (severity LIKE '%Critical%' OR severity LIKE '%Nghiêm trọng%' OR severity LIKE '%Nghiem trong%') AND severity NOT LIKE '%High to Critical%' AND severity NOT LIKE '%Cao đến Nghiêm trọng%' AND severity NOT LIKE '%Cao den Nghiem trong%'"
        elif severity == "High":
            base_query += " AND (severity LIKE '%High%' OR severity LIKE '%Cao%') AND severity NOT LIKE '%Medium to High%' AND severity NOT LIKE '%High to Critical%' AND severity NOT LIKE '%Trung bình đến Cao%' AND severity NOT LIKE '%Trung binh den Cao%' AND severity NOT LIKE '%Cao đến Nghiêm trọng%' AND severity NOT LIKE '%Cao den Nghiem trong%'"
        elif severity == "Medium":
            base_query += " AND (severity LIKE '%Medium%' OR severity LIKE '%Trung bình%' OR severity LIKE '%Trung binh%') AND severity NOT LIKE '%Medium to High%' AND severity NOT LIKE '%Trung bình đến Cao%' AND severity NOT LIKE '%Trung binh den Cao%'"
        elif severity == "Low":
            base_query += " AND (severity LIKE '%Low%' OR severity LIKE '%Thấp%') AND severity NOT LIKE '%Medium%' AND severity NOT LIKE '%Trung bình%' AND severity NOT LIKE '%Trung binh%' AND severity NOT LIKE '%Medium to High%' AND severity NOT LIKE '%Trung bình đến Cao%' AND severity NOT LIKE '%Trung binh den Cao%'"

    # Count total items
    count_query = f"SELECT COUNT(*) as total {base_query}"
    total_count = conn.execute(count_query, params).fetchone()['total']
    total_pages = math.ceil(total_count / limit) if limit > 0 else 1

    # Fetch paginated items
    offset = (page - 1) * limit
    items_query = f"SELECT * {base_query} ORDER BY date_added DESC LIMIT ? OFFSET ?"
    items_params = params + [limit, offset]

    items = conn.execute(items_query, items_params).fetchall()
    conn.close()
    
    result_items = []
    for ix in items:
        item_dict = dict(ix)
        file_path = item_dict.get('file_path', '')
        if file_path:
            filename = os.path.basename(file_path)
            slug = filename.replace('_en.json', '').replace('_vi.json', '')
            item_dict['slug'] = slug
        item_dict.pop('file_path', None)
        item_dict.pop('format', None)
        result_items.append(item_dict)

    return {
        "items": result_items,
        "total_count": total_count,
        "total_pages": total_pages,
        "page": page,
        "limit": limit
    }

@app.get("/api/vault/search")
def search_vault_items(q: str = Query(..., min_length=1), lang: str = 'vi'):
    conn = get_db_connection()
    query = "SELECT id, title, category, severity, date_added, file_path FROM vault_index WHERE format = 'json' AND language = ? AND title LIKE ? ORDER BY date_added DESC LIMIT 10"
    params = [lang, f"%{q}%"]
    items = conn.execute(query, params).fetchall()
    conn.close()
    
    result_items = []
    for ix in items:
        item_dict = dict(ix)
        file_path = item_dict.get('file_path', '')
        if file_path:
            filename = os.path.basename(file_path)
            slug = filename.replace('_en.json', '').replace('_vi.json', '')
            item_dict['slug'] = slug
        item_dict.pop('file_path', None)
        result_items.append(item_dict)
    return result_items

@app.get("/api/vault/share/{slug}")
def get_vault_content_by_slug(slug: str, lang: str = 'en'):
    if lang not in ['vi', 'en']:
        lang = 'en'
    conn = get_db_connection()
    query = "SELECT id, file_path FROM vault_index WHERE format = 'json' AND language = ? AND file_path LIKE ?"
    item = conn.execute(query, (lang, f"%/{slug}_{lang}.json")).fetchone()
    conn.close()

    if not item or not os.path.exists(item['file_path']):
        raise HTTPException(status_code=404, detail="Không tìm thấy file")

    with open(item['file_path'], 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    return {"id": item['id'], "content": data}

@app.get("/api/vault/{item_id}/content")
def get_vault_content(item_id: int):
    conn = get_db_connection()
    item = conn.execute("SELECT file_path FROM vault_index WHERE id = ?", (item_id,)).fetchone()
    conn.close()

    if not item or not os.path.exists(item['file_path']):
        raise HTTPException(status_code=404, detail="Không tìm thấy file")

    with open(item['file_path'], 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

@app.get("/api/vault/{item_id}/download")
def download_file(item_id: int, format: str = Query("json", regex="^(json|md)$")):
    conn = get_db_connection()
    # Lấy file gốc trước
    item = conn.execute("SELECT file_path, title FROM vault_index WHERE id = ?", (item_id,)).fetchone()
    conn.close()

    if not item:
        raise HTTPException(status_code=404, detail="Không tìm thấy bản ghi")

    file_path = item['file_path']
    
    # Logic suy luận file MD từ file JSON (vì cấu trúc thư mục của bạn rất chuẩn)
    if format == 'md':
        file_path = file_path.replace('/json/', '/markdown/').replace('.json', '.md')

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"File {format.upper()} chưa được tạo trên server")

    return FileResponse(path=file_path, filename=os.path.basename(file_path))

class FeedbackSubmit(BaseModel):
    title: str
    content: str
    lang: str = 'vi'

@app.get("/api/doc")
def get_doc(lang: str = 'vi'):
    if lang not in ['vi', 'en']:
        lang = 'vi'
    file_path = f"/root/cyber_vault/doc_{lang}.json"
    if not os.path.exists(file_path):
        # Fallback local path for dev/test
        local_path = os.path.join(os.path.dirname(__file__), f"doc_{lang}.json")
        if os.path.exists(local_path):
            file_path = local_path
        else:
            return {
              "project": {"name": "Cyber Vault", "description": "Documentation not found"},
              "last_updated": "",
              "messages": {"title": "Error", "content": ["File not found on server."]}
            }
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

@app.post("/api/feedback")
def submit_feedback(request: Request, feedback: FeedbackSubmit):
    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = request.headers.get("X-Real-IP")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif real_ip:
        client_ip = real_ip
    else:
        client_ip = request.client.host
        
    if not client_ip:
        client_ip = "unknown"
        
    conn = get_db_connection()
    
    banned = conn.execute("SELECT ip_address FROM banned_ips WHERE ip_address = ?", (client_ip,)).fetchone()
    if banned:
        conn.close()
        msg = "Đã thực hiện quá nhiều, vui lòng thử lại sau." if feedback.lang == 'vi' else "Too many requests, please try again later."
        return {"status": "success", "message": msg}
        
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    count = conn.execute("SELECT COUNT(*) as c FROM feedback WHERE ip_address = ? AND created_at >= ?", (client_ip, one_hour_ago.strftime('%Y-%m-%d %H:%M:%S'))).fetchone()['c']
    
    if count >= 3:
        conn.execute("INSERT INTO banned_ips (ip_address) VALUES (?)", (client_ip,))
        conn.commit()
        conn.close()
        msg = "Đã thực hiện quá nhiều, vui lòng thử lại sau." if feedback.lang == 'vi' else "Too many requests, please try again later."
        return {"status": "success", "message": msg}
        
    conn.execute("INSERT INTO feedback (ip_address, title, content) VALUES (?, ?, ?)", (client_ip, feedback.title, feedback.content))
    conn.commit()
    conn.close()
    
    msg = "Cảm ơn bạn đã đóng góp ý kiến." if feedback.lang == 'vi' else "Thank you for your feedback."
    return {"status": "success", "message": msg}