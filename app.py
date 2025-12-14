import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from html import escape

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jose import jwt, JWTError

# ========================= CONFIG =========================
SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-change-in-production-2025")
ALGORITHM = "HS256"
SESSION_EXPIRE_MINUTES = 30
TRIAL_DAYS = 14

# Frontend URL - update this to your IONOS domain
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://citycites.io")
# Ensure FRONTEND_URL has proper protocol
if FRONTEND_URL and not FRONTEND_URL.startswith(("http://", "https://")):
    FRONTEND_URL = "https://" + FRONTEND_URL
# Remove trailing slash if present
FRONTEND_URL = FRONTEND_URL.rstrip("/")

# Log the frontend URL for debugging
print(f"[CONFIG] FRONTEND_URL set to: {FRONTEND_URL}")

# =========================================================
app = FastAPI()

# Add CORS middleware to allow requests from frontend
# Support both HTTP and HTTPS versions of the frontend URL
frontend_origins = set([
    FRONTEND_URL,
    "http://localhost:8000",  # For local testing
    "http://127.0.0.1:8000",  # For local testing
])

# Add HTTP version if FRONTEND_URL is HTTPS
if FRONTEND_URL.startswith("https://"):
    http_version = FRONTEND_URL.replace("https://", "http://")
    frontend_origins.add(http_version)
# Add HTTPS version if FRONTEND_URL is HTTP
elif FRONTEND_URL.startswith("http://"):
    https_version = FRONTEND_URL.replace("http://", "https://")
    frontend_origins.add(https_version)

# Also add common variations
frontend_origins.update([
    "http://citycites.io",
    "https://citycites.io",
    "http://www.citycites.io",
    "https://www.citycites.io",
])

# Convert back to list for CORS middleware
frontend_origins_list = list(frontend_origins)
print(f"[CORS] Allowing origins: {frontend_origins_list}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=frontend_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Try to use bcrypt, fallback to plaintext (NOT SECURE - for testing only)
try:
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    # Test if bcrypt works
    test_hash = pwd_context.hash("test")
    BCRYPT_AVAILABLE = True
except Exception as e:
    print(f"WARNING: bcrypt not available: {e}")
    print("Falling back to plaintext passwords (NOT SECURE - for development only)")
    print("Install bcrypt: pip install bcrypt")
    # Fallback to plaintext (ONLY FOR DEVELOPMENT)
    pwd_context = None
    BCRYPT_AVAILABLE = False

# Use local database path (works for both local and production)
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "app.db")

# ======================= DB INIT =======================
def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        first_name TEXT,
        last_name TEXT,
        created_at TEXT,
        trial_start TEXT,
        trial_end TEXT,
        is_active INTEGER DEFAULT 1,
        is_admin INTEGER DEFAULT 0,
        is_approved INTEGER DEFAULT 0,
        last_activity TEXT
    )""")
    # Add is_approved column if it doesn't exist (for existing databases)
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_approved INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    c.execute("""CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT, email TEXT, message TEXT, role TEXT, city_name TEXT, county_name TEXT, created_at TEXT
    )""")
    # Default admin – CHANGE PASSWORD ASAP
    # Only create admin if it doesn't exist
    try:
        existing = c.execute("SELECT id FROM users WHERE email = ?", ("admin@example.com",)).fetchone()
        if not existing:
            if BCRYPT_AVAILABLE:
                hashed = pwd_context.hash("admin123")
            else:
                # Fallback: plaintext (NOT SECURE - development only)
                print("WARNING: Creating admin with plaintext password (NOT SECURE)")
                hashed = "admin123"
            c.execute("""INSERT INTO users
                         (email,password_hash,first_name,is_admin,created_at,last_activity,is_active,is_approved)
                         VALUES (?,?,?,?,?,?,?,?)""",
                      ("admin@example.com", hashed, "Admin", 1,
                       datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), 1, 1))
    except Exception as e:
        # If something fails, we'll create admin on first login attempt
        print(f"Warning: Could not create admin user: {e}")
    conn.commit()
    conn.close()

# ======================= AUTH =======================
def create_token(email: str):
    expire = datetime.now(timezone.utc) + timedelta(days=30)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, ALGORITHM)

def get_current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
    except JWTError:
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if not user or not user["is_active"]:
        return None
    
    # Convert Row to dict for easier access
    user_dict = dict(user)
    # Note: We don't check is_approved here because admins need to see unapproved users
    # The approval check is done in individual endpoints that need it

    # Inactivity timeout
    if user_dict.get("last_activity"):
        try:
            last = datetime.fromisoformat(user_dict["last_activity"])
            if datetime.now(timezone.utc) - last > timedelta(minutes=SESSION_EXPIRE_MINUTES):
                return None
        except Exception:
            pass  # If date parsing fails, allow the session

    # Refresh activity
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET last_activity = ? WHERE id = ?",
                 (datetime.utcnow().isoformat(), user_dict["id"]))
    conn.commit()
    conn.close()

    return user_dict

def is_trial_active(user: dict) -> bool:
    if user.get("is_admin"):
        return True
    if not user.get("trial_end"):
        return False
    trial_end = datetime.fromisoformat(user["trial_end"])
    return datetime.now(timezone.utc) <= trial_end

# ======================= ROUTES =======================
# Initialize database on startup (with error handling)
try:
    init_db()
except Exception as e:
    print(f"Warning: Database initialization had issues: {e}")
    print("The app will continue, but some features may not work.")
    print("Try installing bcrypt: pip install bcrypt")

# Define routes BEFORE mounting static files to ensure they take precedence
@app.post("/signup")
async def signup(email: str = Form(), password: str = Form(),
                 first_name: str = Form(""), last_name: str = Form("")):
    try:
        # Try to hash the password
        if not BCRYPT_AVAILABLE:
            # Fallback: store password as plaintext (NOT SECURE - development only)
            print("WARNING: Using plaintext password storage (NOT SECURE)")
            hashed = password
        else:
            try:
                hashed = pwd_context.hash(password)
            except Exception as e:
                print(f"Error hashing password: {e}")
                return HTMLResponse(
                    f"<h1>Server Error</h1><p>Password hashing failed. Please ensure bcrypt is installed: pip install bcrypt</p><p>Error: {str(e)}</p>",
                    status_code=500
                )
        
        now = datetime.utcnow()
        trial_end = now + timedelta(days=TRIAL_DAYS)

        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute("""INSERT INTO users
                (email,password_hash,first_name,last_name,created_at,trial_start,trial_end,last_activity,is_approved)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (email, hashed, first_name, last_name, now.isoformat(),
                 now.isoformat(), trial_end.isoformat(), now.isoformat(), 0))
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.close()
            print(f"[SIGNUP] Email already registered: {email}")
            return HTMLResponse("Email already registered. Please use a different email or try logging in.", status_code=400)
        except Exception as e:
            conn.close()
            print(f"Database error during signup: {e}")
            return HTMLResponse(f"<h1>Database Error</h1><p>{str(e)}</p>", status_code=500)
        conn.close()

        # Redirect to pending approval page instead of dashboard
        redirect_url = f"{FRONTEND_URL}/signup.html?pending=1"
        
        # Validate redirect URL
        if not redirect_url.startswith(("http://", "https://")):
            print(f"[ERROR] Invalid redirect URL: {redirect_url}, FRONTEND_URL was: {FRONTEND_URL}")
            redirect_url = "https://citycites.io/signup.html?pending=1"
            print(f"[FIX] Using fallback URL: {redirect_url}")
        
        print(f"[SIGNUP] Redirecting to: {redirect_url}")
        response = RedirectResponse(url=redirect_url, status_code=303)
        return response
    except Exception as e:
        print(f"Unexpected error in signup: {e}")
        import traceback
        traceback.print_exc()
        return HTMLResponse(f"<h1>Internal Server Error</h1><p>{str(e)}</p>", status_code=500)

@app.post("/login")
async def login(email: str = Form(), password: str = Form()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    # Verify password
    if not user or not user["is_active"]:
        return HTMLResponse("Invalid credentials", status_code=401)
    
    if not BCRYPT_AVAILABLE:
        # Fallback: plaintext comparison (NOT SECURE)
        if user["password_hash"] != password:
            return HTMLResponse("Invalid credentials", status_code=401)
    else:
        if not pwd_context.verify(password, user["password_hash"]):
            return HTMLResponse("Invalid credentials", status_code=401)
    
    # Check if user is approved (admins are always approved)
    # Convert Row to dict for easier access
    user_dict = dict(user)
    if not user_dict.get("is_admin") and not user_dict.get("is_approved", 0):
        return HTMLResponse("Your account is pending admin approval. Please wait for an administrator to approve your account.", status_code=403)

    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET last_activity = ? WHERE id = ?",
                 (datetime.utcnow().isoformat(), user["id"]))
    conn.commit()
    conn.close()

    # Redirect admins to admin page, regular users to dashboard
    redirect_path = "/admin.html" if user_dict.get("is_admin") else "/dashboard.html"
    redirect_url = f"{FRONTEND_URL}{redirect_path}"
    
    # Validate redirect URL
    if not redirect_url.startswith(("http://", "https://")):
        print(f"[ERROR] Invalid redirect URL: {redirect_url}, FRONTEND_URL was: {FRONTEND_URL}")
        redirect_url = f"https://citycites.io{redirect_path}"
        print(f"[FIX] Using fallback URL: {redirect_url}")
    
    print(f"[LOGIN] User {email} logged in, redirecting to: {redirect_url}")
    
    # Create redirect response with cookie
    is_secure = FRONTEND_URL.startswith("https://")
    response = RedirectResponse(url=redirect_url, status_code=303)
    # Set cookie with proper settings for cross-origin requests
    # Use "None" for SameSite when using HTTPS to allow cross-site cookies
    samesite_value = "none" if is_secure else "lax"
    response.set_cookie(
        "session", 
        create_token(user["email"]),
        httponly=True, 
        secure=is_secure, 
        samesite=samesite_value, 
        max_age=30*24*60*60,
        path="/"  # Make sure cookie is available for all paths
    )
    
    # Set redirect URL in custom header (Location header is automatically set by RedirectResponse)
    # X-Redirect-To is for JavaScript to read when Location might be blocked by CORS
    response.headers["X-Redirect-To"] = redirect_url
    response.headers["Access-Control-Expose-Headers"] = "X-Redirect-To, Location"
    
    return response

@app.get("/logout")
async def logout():
    redirect_url = f"{FRONTEND_URL}/"
    if not redirect_url.startswith(("http://", "https://")):
        redirect_url = "https://citycites.io/"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.delete_cookie("session")
    return response

@app.post("/contact")
async def contact(name: str = Form(), email: str = Form(), message: str = Form(),
                  role: str = Form(""), city_name: str = Form(""), county_name: str = Form("")):
    # Ensure database has the new columns (for backward compatibility)
    conn = sqlite3.connect(DB_PATH)
    try:
        # Check if columns exist, if not add them
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(contact_messages)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if "role" not in columns:
            conn.execute("ALTER TABLE contact_messages ADD COLUMN role TEXT")
        if "city_name" not in columns:
            conn.execute("ALTER TABLE contact_messages ADD COLUMN city_name TEXT")
        if "county_name" not in columns:
            conn.execute("ALTER TABLE contact_messages ADD COLUMN county_name TEXT")
        conn.commit()
        
        # Insert the message with new fields
        conn.execute("INSERT INTO contact_messages (name,email,message,role,city_name,county_name,created_at) VALUES (?,?,?,?,?,?,?)",
                     (name, email, message, role or None, city_name or None, county_name or None, datetime.utcnow().isoformat()))
        conn.commit()
    except Exception as e:
        print(f"[CONTACT] Database error: {e}")
    finally:
        conn.close()
    
    redirect_url = f"{FRONTEND_URL}/contact.html?sent=1"
    
    # Validate redirect URL
    if not redirect_url.startswith(("http://", "https://")):
        print(f"[ERROR] Invalid redirect URL: {redirect_url}, FRONTEND_URL was: {FRONTEND_URL}")
        redirect_url = "https://citycites.io/contact.html?sent=1"
        print(f"[FIX] Using fallback URL: {redirect_url}")
    
    print(f"[CONTACT] Message received from {email}, redirecting to: {redirect_url}")
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.headers["X-Redirect-To"] = redirect_url
    response.headers["Access-Control-Expose-Headers"] = "X-Redirect-To, Location"
    return response

# Admin routes
# API endpoint to get users for admin page
@app.get("/api/admin/users")
async def get_admin_users(user: dict = Depends(get_current_user)):
    """API endpoint to fetch all users for admin page"""
    try:
        if not user:
            raise HTTPException(status_code=403, detail="Authentication required")
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT id, email, first_name, last_name, created_at, trial_end, last_activity, is_admin, is_active, is_approved FROM users ORDER BY created_at DESC").fetchall()
        conn.close()
        
        # Convert to list of dicts
        users_list = []
        for u in users:
            u_dict = dict(u)
            users_list.append({
                "id": u_dict["id"],
                "email": u_dict.get("email", ""),
                "first_name": u_dict.get("first_name", ""),
                "last_name": u_dict.get("last_name", ""),
                "full_name": f"{u_dict.get('first_name', '')} {u_dict.get('last_name', '')}".strip() or "N/A",
                "created_at": u_dict.get("created_at", ""),
                "trial_end": u_dict.get("trial_end", ""),
                "last_activity": u_dict.get("last_activity", ""),
                "is_admin": bool(u_dict.get("is_admin", 0)),
                "is_active": bool(u_dict.get("is_active", 1)),
                "is_approved": bool(u_dict.get("is_approved", 0))
            })
        
        return {"users": users_list}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API] Error fetching users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# API endpoint to get contact messages for admin page
@app.get("/api/admin/messages")
async def get_admin_messages(user: dict = Depends(get_current_user)):
    """API endpoint to fetch all contact messages for admin page"""
    try:
        if not user:
            raise HTTPException(status_code=403, detail="Authentication required")
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        messages = conn.execute("SELECT name, email, message, role, city_name, county_name, created_at FROM contact_messages ORDER BY created_at DESC").fetchall()
        conn.close()
        
        # Convert to list of dicts
        messages_list = []
        for m in messages:
            m_dict = dict(m)
            messages_list.append({
                "name": m_dict.get("name", ""),
                "email": m_dict.get("email", ""),
                "message": m_dict.get("message", ""),
                "role": m_dict.get("role", ""),
                "city_name": m_dict.get("city_name", ""),
                "county_name": m_dict.get("county_name", ""),
                "created_at": m_dict.get("created_at", "")
            })
        
        return {"messages": messages_list}
    except HTTPException:
        raise
    except Exception as e:
        print(f"[API] Error fetching messages: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin.html")
async def admin_page(request: Request, user: dict = Depends(get_current_user)):
    try:
        if not user:
            raise HTTPException(status_code=403, detail="Authentication required")
        if not user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        messages = conn.execute("SELECT * FROM contact_messages ORDER BY created_at DESC").fetchall()
        conn.close()
        
        # Return the admin.html file with data injected
        admin_html_path = os.path.join(os.path.dirname(__file__), "admin.html")
        if not os.path.exists(admin_html_path):
            raise HTTPException(status_code=500, detail="Admin page template not found")
        with open(admin_html_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Inject users data with approval buttons
        users_html = []
        for u in users:
            # Convert Row to dict for easier access
            u_dict = dict(u)
            
            # Build name display
            first_name = escape(str(u_dict.get('first_name', '') or ''))
            last_name = escape(str(u_dict.get('last_name', '') or ''))
            full_name = f"{first_name} {last_name}".strip() or 'N/A'
            
            # Build status badge
            status_badge = ""
            if u_dict.get('is_admin'):
                status_badge = '<span class="badge bg-primary">Admin</span>'
            elif not u_dict.get('is_active', 1):
                status_badge = '<span class="badge bg-danger">Blocked</span>'
            elif u_dict.get('is_approved', 0):
                status_badge = '<span class="badge bg-success">Approved</span>'
            else:
                status_badge = '<span class="badge bg-warning text-dark">Pending</span>'
            
            # Build actions
            actions = []
            if not u_dict.get('is_admin'):
                if not u_dict.get('is_approved', 0):
                    actions.append(f'<button class="btn btn-sm btn-primary" onclick="approveUser({u_dict["id"]})" title="Approve user">Approve</button>')
                    actions.append(f'<button class="btn btn-sm btn-danger" onclick="rejectUser({u_dict["id"]})" title="Reject user">Reject</button>')
                elif u_dict.get('is_active', 1):
                    actions.append(f'<button class="btn btn-sm btn-warning" onclick="blockUser({u_dict["id"]})" title="Block user">Block</button>')
                    actions.append(f'<button class="btn btn-sm btn-outline-danger" onclick="deleteUser({u_dict["id"]})" title="Delete user">Delete</button>')
                else:
                    actions.append(f'<button class="btn btn-sm btn-success" onclick="unblockUser({u_dict["id"]})" title="Unblock user">Unblock</button>')
                    actions.append(f'<button class="btn btn-sm btn-outline-danger" onclick="deleteUser({u_dict["id"]})" title="Delete user">Delete</button>')
            else:
                actions.append(f'<span class="text-muted small">Admin Account</span>')
            
            actions_html = '<div class="d-flex gap-2">' + ''.join(actions) + '</div>' if actions else ''
            
            # Format dates
            created_at_str = u_dict.get('created_at', '')
            if created_at_str and len(created_at_str) >= 10:
                created_at = created_at_str[:10]
            else:
                created_at = 'N/A'
            
            trial_end_str = u_dict.get('trial_end', '')
            if trial_end_str and len(trial_end_str) >= 10:
                trial_end = trial_end_str[:10]
            else:
                trial_end = 'N/A'
            
            last_activity = u_dict.get('last_activity', '')
            if last_activity:
                try:
                    last_activity_dt = datetime.fromisoformat(last_activity)
                    last_activity_str = last_activity_dt.strftime('%Y-%m-%d %H:%M')
                except Exception:
                    last_activity_str = last_activity[:16] if len(last_activity) > 16 else last_activity
            else:
                last_activity_str = 'Never'
            
            users_html.append(
                f"<tr>"
                f"<td>{full_name}</td>"
                f"<td class=\"email-cell\">{escape(str(u_dict.get('email', '')))}</td>"
                f"<td>{status_badge}</td>"
                f"<td>{escape(str(created_at))}</td>"
                f"<td>{escape(str(trial_end))}</td>"
                f"<td><small>{escape(str(last_activity_str))}</small></td>"
                f"<td class=\"actions-cell\">{actions_html}</td>"
                f"</tr>"
            )
        
        users_html = ''.join(users_html)
        
        # Calculate user statistics
        total_users = len(users)
        pending_users = sum(1 for u in users if not dict(u).get('is_admin') and not dict(u).get('is_approved', 0))
        approved_users = sum(1 for u in users if not dict(u).get('is_admin') and dict(u).get('is_approved', 0) and dict(u).get('is_active', 1))
        blocked_users = sum(1 for u in users if not dict(u).get('is_active', 1))
        
        # Update welcome message with stats
        welcome_text = f"Managing {total_users} total users: {approved_users} approved, {pending_users} pending approval, {blocked_users} blocked"
        # Use a more flexible replacement that handles whitespace variations
        content = re.sub(
            r'<p id="admin-welcome">\s*Loading admin data…\s*</p>',
            f'<p id="admin-welcome">{welcome_text}</p>',
            content,
            flags=re.DOTALL
        )
        
        # Inject statistics into stat cards
        content = re.sub(
            r'<p class="stat-value" id="stat-total">-</p>',
            f'<p class="stat-value" id="stat-total">{total_users}</p>',
            content
        )
        content = re.sub(
            r'<p class="stat-value" id="stat-pending">-</p>',
            f'<p class="stat-value" id="stat-pending">{pending_users}</p>',
            content
        )
        content = re.sub(
            r'<p class="stat-value" id="stat-active">-</p>',
            f'<p class="stat-value" id="stat-active">{approved_users}</p>',
            content
        )
        content = re.sub(
            r'<p class="stat-value" id="stat-blocked">-</p>',
            f'<p class="stat-value" id="stat-blocked">{blocked_users}</p>',
            content
        )
        
        # Inject messages data
        messages_html = []
        for m in messages:
            m_dict = dict(m)
            msg_text = str(m_dict.get('message', ''))
            msg_display = escape(msg_text[:100] + ('...' if len(msg_text) > 100 else ''))
            created_at_msg = m_dict.get('created_at', '')
            created_at_display = escape(created_at_msg[:10] if created_at_msg and len(created_at_msg) >= 10 else 'N/A')
            messages_html.append(
                f"<tr><td>{escape(str(m_dict.get('name', 'N/A')))}</td><td class=\"email-cell\">{escape(str(m_dict.get('email', 'N/A')))}</td>"
                f"<td class=\"message-cell\">{msg_display}</td><td>{created_at_display}</td></tr>"
            )
        messages_html = ''.join(messages_html)
        
        # Replace the loading messages with actual data
        if users_html:
            content = content.replace(
                '<tr><td colspan="7">Loading users…</td></tr>',
                users_html
            )
            # Also replace if it's in tbody with id
            content = content.replace(
                '<tbody id="users-tbody">\n            <tr><td colspan="7">Loading users…</td></tr>\n          </tbody>',
                f'<tbody id="users-tbody">\n            {users_html}\n          </tbody>'
            )
        else:
            content = content.replace(
                '<tr><td colspan="7">Loading users…</td></tr>',
                '<tr><td colspan="7" class="text-center muted">No users found</td></tr>'
            )
        
        if messages_html:
            content = content.replace(
                '<tr><td colspan="4">Loading messages…</td></tr>',
                messages_html
            )
            # Also replace if it's in tbody with id
            content = content.replace(
                '<tbody id="messages-tbody">\n            <tr><td colspan="4">Loading messages…</td></tr>\n          </tbody>',
                f'<tbody id="messages-tbody">\n            {messages_html}\n          </tbody>'
            )
        else:
            content = content.replace(
                '<tr><td colspan="4">Loading messages…</td></tr>',
                '<tr><td colspan="4" class="text-center muted">No messages found</td></tr>'
            )
        
        return HTMLResponse(content)
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print(f"Error in admin_page: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/admin/block/{user_id}")
async def admin_block(user_id: int, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"{FRONTEND_URL}/admin.html", status_code=303)

@app.post("/admin/unblock/{user_id}")
async def admin_unblock(user_id: int, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"{FRONTEND_URL}/admin.html", status_code=303)

@app.post("/admin/approve/{user_id}")
async def admin_approve(user_id: int, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET is_approved = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"{FRONTEND_URL}/admin.html", status_code=303)

@app.post("/admin/reject/{user_id}")
async def admin_reject(user_id: int, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE users SET is_active = 0, is_approved = 0 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"{FRONTEND_URL}/admin.html", status_code=303)

# Dashboard route - inject product links for approved users
@app.get("/dashboard.html")
async def dashboard_page(request: Request, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url=f"{FRONTEND_URL}/login.html", status_code=303)
    if not user.get("is_admin") and not user.get("is_approved", 0):
        return HTMLResponse(
            "<h1>Account Pending Approval</h1><p>Your account is pending admin approval. Please wait for an administrator to approve your account.</p><a href='/logout'>Logout</a>",
            status_code=403
        )
    
    # Product links - only visible to approved users
    product_links = {
        "insites": "https://8c885017-a295-452f-9584-be9a12b1db6e-00-11241i54nt487.riker.replit.dev/",
        "sense": "https://fe5883fe-667f-4650-9e81-114aec5939c2-00-2kmfcqpudtsji.riker.replit.dev/"
    }
    
    # Read dashboard.html
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if not os.path.exists(dashboard_path):
        raise HTTPException(status_code=500, detail="Dashboard template not found")
    
    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Replace product card links with actual product URLs
    # City InSites link - add badge and external link icon
    insites_replacement = f'''<div class="mb-2"><span class="badge bg-success">Live Product</span></div>
          <a href="{product_links["insites"]}" target="_blank" rel="noopener noreferrer" class="btn btn-cta w-100">Open InSites <i class="bi bi-box-arrow-up-right ms-1"></i></a>'''
    content = re.sub(
        r'<a href="products\.html#insites" class="btn btn-cta w-100">Open InSites</a>',
        insites_replacement,
        content
    )
    
    # City Sense link - add badge and external link icon
    sense_replacement = f'''<div class="mb-2"><span class="badge bg-success">Live Product</span></div>
          <a href="{product_links["sense"]}" target="_blank" rel="noopener noreferrer" class="btn btn-cta w-100">Open Sense <i class="bi bi-box-arrow-up-right ms-1"></i></a>'''
    content = re.sub(
        r'<a href="products\.html#sense" class="btn btn-cta w-100">Open Sense</a>',
        sense_replacement,
        content
    )
    
    # Update welcome message with user's name
    user_name = user.get("first_name", "") or user.get("email", "User")
    if user.get("first_name") and user.get("last_name"):
        user_name = f"{user.get('first_name')} {user.get('last_name')}"
    elif user.get("first_name"):
        user_name = user.get("first_name")
    
    content = re.sub(
        r'<h1 class="display-5 mb-3">Your CityCites Dashboard</h1>',
        f'<h1 class="display-5 mb-3">Welcome, {escape(user_name)}</h1>',
        content
    )
    
    # Calculate trial days remaining
    trial_end_str = user.get("trial_end", "")
    if trial_end_str:
        try:
            trial_end = datetime.fromisoformat(trial_end_str)
            days_remaining = (trial_end - datetime.now(timezone.utc)).days
            if days_remaining < 0:
                days_remaining = 0
            content = re.sub(
                r'<div class="value">14</div>',
                f'<div class="value">{days_remaining}</div>',
                content
            )
        except Exception:
            pass
    
    return HTMLResponse(content)

@app.post("/admin/delete/{user_id}")
async def admin_delete(user_id: int, user: dict = Depends(get_current_user)):
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403)
    # Prevent deleting admin accounts
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    target_user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if target_user and dict(target_user).get('is_admin'):
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot delete admin accounts")
    # Delete the user
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"{FRONTEND_URL}/admin.html", status_code=303)

# Test endpoint to verify backend is running
@app.get("/test")
async def test():
    return {
        "status": "ok",
        "message": "Backend is running",
        "frontend_url": FRONTEND_URL,
        "cors_configured": True
    }

# Mount static files AFTER route definitions
# This ensures POST routes are handled before static file serving
app.mount("/", StaticFiles(directory=".", html=True), name="static")
