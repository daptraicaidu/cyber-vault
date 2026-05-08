from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import json
import os
import math

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

@app.get("/api/vault")
def get_vault_items(search: str = None, severity: str = None, lang: str = 'vi', page: int = Query(1, ge=1), limit: int = Query(20, ge=1)):
    conn = get_db_connection()
    
    base_query = "FROM vault_index WHERE format = 'json' AND language = ?"
    params = [lang]

    if search:
        base_query += " AND (title LIKE ? OR category LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if severity:
        base_query += " AND severity LIKE ?"
        params.append(f"%{severity}%")

    # Count total items
    count_query = f"SELECT COUNT(*) as total {base_query}"
    total_count = conn.execute(count_query, params).fetchone()['total']
    total_pages = math.ceil(total_count / limit) if limit > 0 else 1

    # Fetch paginated items
    offset = (page - 1) * limit
    items_query = f"SELECT * {base_query} LIMIT ? OFFSET ?"
    items_params = params + [limit, offset]

    items = conn.execute(items_query, items_params).fetchall()
    conn.close()
    
    return {
        "items": [dict(ix) for ix in items],
        "total_count": total_count,
        "total_pages": total_pages,
        "page": page,
        "limit": limit
    }

@app.get("/api/vault/search")
def search_vault_items(q: str = Query(..., min_length=1), lang: str = 'vi'):
    conn = get_db_connection()
    query = "SELECT id, title FROM vault_index WHERE format = 'json' AND language = ? AND title LIKE ? LIMIT 10"
    params = [lang, f"%{q}%"]
    items = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(ix) for ix in items]

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