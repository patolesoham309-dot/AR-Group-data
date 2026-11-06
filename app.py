import os
import uuid
from pathlib import Path
from datetime import datetime, timedelta, date
from contextlib import contextmanager
from typing import Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------
APP_DIR = Path(__file__).parent
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Add your PostgreSQL connection string in Render Environment.")

UPLOAD_DIR = Path(os.getenv("FLEET_UPLOAD_DIR", str(APP_DIR / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("FLEET_SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError("Set FLEET_SECRET_KEY to a random secret of at least 32 characters in Render Environment.")

ALGORITHM = "HS256"
TOKEN_MINUTES = 720
MAX_PHOTO_BYTES = 8 * 1024 * 1024
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

app = FastAPI(title="AR Group Diesel Fleet Management API", version="1.0.0")


@contextmanager
def db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('super_admin','staff','driver')),
        fixed_bus_id BIGINT,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS buses (
        id BIGSERIAL PRIMARY KEY,
        bus_number TEXT UNIQUE NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS routes (
        id BIGSERIAL PRIMARY KEY,
        route_name TEXT UNIQUE NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS diesel_entries (
        id BIGSERIAL PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        entry_date DATE NOT NULL,
        driver_id BIGINT NOT NULL REFERENCES users(id),
        bus_id BIGINT NOT NULL REFERENCES buses(id),
        route_id BIGINT NOT NULL REFERENCES routes(id),
        meter_km NUMERIC(12,2) NOT NULL CHECK (meter_km > 0),
        litres NUMERIC(12,2) NOT NULL CHECK (litres > 0),
        rate_per_litre NUMERIC(12,2) NOT NULL CHECK (rate_per_litre > 0),
        full_tank BOOLEAN NOT NULL DEFAULT TRUE,
        meter_photo TEXT NOT NULL,
        pump_photo TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending','approved','rejected')),
        reviewed_by BIGINT REFERENCES users(id),
        review_note TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_entries_date ON diesel_entries(entry_date);
    CREATE INDEX IF NOT EXISTS idx_entries_bus ON diesel_entries(bus_id);
    CREATE INDEX IF NOT EXISTS idx_entries_driver ON diesel_entries(driver_id);
    CREATE INDEX IF NOT EXISTS idx_entries_status ON diesel_entries(status);
    """
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(schema)
            cur.execute("SELECT COUNT(*) AS n FROM users")
            if cur.fetchone()["n"] == 0:
                admin_user = os.getenv("FLEET_ADMIN_USER", "admin")
                admin_password = os.getenv("FLEET_ADMIN_PASSWORD", "")
                if len(admin_password) < 10:
                    raise RuntimeError(
                        "No users exist. Set FLEET_ADMIN_PASSWORD (minimum 10 characters) before first deployment."
                    )
                cur.execute(
                    """INSERT INTO users(username,full_name,password_hash,role)
                       VALUES(%s,%s,%s,'super_admin')""",
                    (admin_user, "System Administrator", pwd_context.hash(admin_password))
                )

            cur.execute("SELECT COUNT(*) AS n FROM buses")
            if cur.fetchone()["n"] == 0:
                cur.executemany(
                    "INSERT INTO buses(bus_number) VALUES(%s)",
                    [(f"BUS-{i:02d}",) for i in range(1, 31)]
                )

            cur.execute("SELECT COUNT(*) AS n FROM routes")
            if cur.fetchone()["n"] == 0:
                cur.executemany(
                    "INSERT INTO routes(route_name) VALUES(%s)",
                    [(x,) for x in [
                        "Pune-Goa", "Goa-Pune", "Hyderabad-Goa",
                        "Pune-Nagpur", "Karad-Vijayawada"
                    ]]
                )


@app.on_event("startup")
def startup():
    init_db()


# ------------------------------------------------------------
# Authentication and permissions
# ------------------------------------------------------------
def current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired login")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id,username,full_name,role,fixed_bus_id,active FROM users WHERE id=%s",
                (user_id,)
            )
            user = cur.fetchone()

    if not user or not user["active"]:
        raise HTTPException(status_code=401, detail="User is inactive or does not exist")
    return dict(user)


def require_office(user=Depends(current_user)):
    if user["role"] not in ("super_admin", "staff"):
        raise HTTPException(status_code=403, detail="Office access required")
    return user


def require_super_admin(user=Depends(current_user)):
    if user["role"] != "super_admin":
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return user


def make_token(user):
    return jwt.encode(
        {
            "sub": str(user["id"]),
            "exp": datetime.utcnow() + timedelta(minutes=TOKEN_MINUTES)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def save_image(upload: UploadFile) -> str:
    allowed = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp"
    }
    if upload.content_type not in allowed:
        raise HTTPException(status_code=400, detail="Only JPG, PNG or WEBP photos are accepted")

    filename = uuid.uuid4().hex + allowed[upload.content_type]
    path = UPLOAD_DIR / filename
    size = 0

    try:
        with path.open("wb") as output:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_PHOTO_BYTES:
                    raise HTTPException(status_code=413, detail="Each photo must be 8 MB or smaller")
                output.write(chunk)
    except Exception:
        path.unlink(missing_ok=True)
        raise

    return filename


def date_range(year: int, month: Optional[int] = None):
    if month is not None:
        if month < 1 or month > 12:
            raise HTTPException(status_code=400, detail="Month must be from 1 to 12")
        start = date(year, month, 1)
        end = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    else:
        start = date(year, 1, 1)
        end = date(year + 1, 1, 1)
    return start, end


# ------------------------------------------------------------
# Health and login
# ------------------------------------------------------------
@app.get("/health")
def health():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            cur.fetchone()
    return {"ok": True, "database": "connected"}


@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id,username,full_name,password_hash,role,fixed_bus_id,active FROM users WHERE username=%s",
                (username.strip(),)
            )
            user = cur.fetchone()

    if not user or not user["active"] or not pwd_context.verify(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Username or password is incorrect")

    return {
        "access_token": make_token(user),
        "token_type": "bearer",
        "role": user["role"],
        "full_name": user["full_name"]
    }


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "fixed_bus_id": user["fixed_bus_id"]
    }


# ------------------------------------------------------------
# Master data
# ------------------------------------------------------------
@app.get("/api/buses")
def list_buses(user=Depends(current_user)):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,bus_number FROM buses WHERE active=TRUE ORDER BY bus_number")
            return [dict(row) for row in cur.fetchall()]


@app.get("/api/routes")
def list_routes(user=Depends(current_user)):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,route_name FROM routes WHERE active=TRUE ORDER BY route_name")
            return [dict(row) for row in cur.fetchall()]


@app.post("/api/admin/buses")
def create_bus(bus_number: str = Form(...), admin=Depends(require_super_admin)):
    bus_number = bus_number.strip().upper()
    if not bus_number:
        raise HTTPException(status_code=400, detail="Bus number is required")
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO buses(bus_number) VALUES(%s) RETURNING id", (bus_number,))
                new_id = cur.fetchone()["id"]
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Bus number already exists")
    return {"ok": True, "id": new_id}


@app.post("/api/admin/routes")
def create_route(route_name: str = Form(...), admin=Depends(require_super_admin)):
    route_name = route_name.strip()
    if not route_name:
        raise HTTPException(status_code=400, detail="Route name is required")
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO routes(route_name) VALUES(%s) RETURNING id", (route_name,))
                new_id = cur.fetchone()["id"]
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Route already exists")
    return {"ok": True, "id": new_id}


# ------------------------------------------------------------
# User administration - Super Admin only
# ------------------------------------------------------------
@app.post("/api/admin/users")
def create_user(
    username: str = Form(...),
    full_name: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    fixed_bus_id: Optional[str] = Form(None),
    admin=Depends(require_super_admin)
):
    username = username.strip()
    full_name = full_name.strip()

    if not username or not full_name:
        raise HTTPException(status_code=400, detail="Username and full name are required")
    if role not in ("staff", "driver"):
        raise HTTPException(status_code=400, detail="Only Staff or Driver accounts can be created")
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters")

    bus_id = None
    if fixed_bus_id and fixed_bus_id.strip():
        try:
            bus_id = int(fixed_bus_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid fixed bus")
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM buses WHERE id=%s AND active=TRUE", (bus_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=400, detail="Selected bus does not exist")

    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO users(username,full_name,password_hash,role,fixed_bus_id)
                       VALUES(%s,%s,%s,%s,%s) RETURNING id""",
                    (username, full_name, pwd_context.hash(password), role, bus_id)
                )
                user_id = cur.fetchone()["id"]
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Username already exists")

    return {"ok": True, "id": user_id, "message": "Account created"}


@app.get("/api/admin/users")
def list_users(admin=Depends(require_super_admin)):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.id,u.username,u.full_name,u.role,u.fixed_bus_id,u.active,
                       b.bus_number
                FROM users u LEFT JOIN buses b ON b.id=u.fixed_bus_id
                ORDER BY u.id
            """)
            return [dict(row) for row in cur.fetchall()]


@app.post("/api/admin/users/{user_id}/active")
def set_user_active(
    user_id: int,
    active: bool = Form(...),
    admin=Depends(require_super_admin)
):
    if user_id == admin["id"] and not active:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET active=%s WHERE id=%s", (active, user_id))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/password")
def reset_user_password(
    user_id: int,
    password: str = Form(...),
    admin=Depends(require_super_admin)
):
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters")
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (pwd_context.hash(password), user_id)
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


# ------------------------------------------------------------
# Driver diesel entries
# ------------------------------------------------------------
@app.post("/api/diesel-entries")
def create_diesel_entry(
    entry_date: date = Form(...),
    bus_id: int = Form(...),
    route_id: int = Form(...),
    meter_km: float = Form(...),
    litres: float = Form(...),
    rate_per_litre: float = Form(...),
    full_tank: bool = Form(True),
    meter_photo: UploadFile = File(...),
    pump_photo: UploadFile = File(...),
    user=Depends(current_user)
):
    if user["role"] != "driver":
        raise HTTPException(status_code=403, detail="Only drivers can submit diesel entries")
    if min(meter_km, litres, rate_per_litre) <= 0:
        raise HTTPException(status_code=400, detail="KM, litres and rate must be greater than zero")
    if user["fixed_bus_id"] and user["fixed_bus_id"] != bus_id:
        raise HTTPException(status_code=403, detail="This driver is assigned to a different fixed bus")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM buses WHERE id=%s AND active=TRUE", (bus_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=400, detail="Select a valid bus")
            cur.execute("SELECT id FROM routes WHERE id=%s AND active=TRUE", (route_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=400, detail="Select a valid route")

    meter_name = save_image(meter_photo)
    try:
        pump_name = save_image(pump_photo)
    except Exception:
        (UPLOAD_DIR / meter_name).unlink(missing_ok=True)
        raise

    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO diesel_entries
                    (entry_date,driver_id,bus_id,route_id,meter_km,litres,
                     rate_per_litre,full_tank,meter_photo,pump_photo)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING id
                """, (
                    entry_date, user["id"], bus_id, route_id, meter_km,
                    litres, rate_per_litre, full_tank, meter_name, pump_name
                ))
                entry_id = cur.fetchone()["id"]
    except Exception:
        (UPLOAD_DIR / meter_name).unlink(missing_ok=True)
        (UPLOAD_DIR / pump_name).unlink(missing_ok=True)
        raise

    return {"ok": True, "id": entry_id, "status": "pending", "message": "Entry submitted for office approval"}


@app.get("/api/driver/entries")
def driver_entries(user=Depends(current_user)):
    if user["role"] != "driver":
        raise HTTPException(status_code=403, detail="Driver access required")
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.id,e.entry_date,e.meter_km,e.litres,e.rate_per_litre,
                       e.status,e.review_note,b.bus_number,r.route_name
                FROM diesel_entries e
                JOIN buses b ON b.id=e.bus_id
                JOIN routes r ON r.id=e.route_id
                WHERE e.driver_id=%s
                ORDER BY e.id DESC
            """, (user["id"],))
            return [dict(row) for row in cur.fetchall()]


# ------------------------------------------------------------
# Office review and reporting - Staff + Super Admin
# ------------------------------------------------------------
@app.get("/api/admin/entries")
def list_entries(status: Optional[str] = None, admin=Depends(require_office)):
    query = """
        SELECT e.*,u.full_name AS driver_name,b.bus_number,r.route_name,
               reviewer.full_name AS reviewer_name
        FROM diesel_entries e
        JOIN users u ON u.id=e.driver_id
        JOIN buses b ON b.id=e.bus_id
        JOIN routes r ON r.id=e.route_id
        LEFT JOIN users reviewer ON reviewer.id=e.reviewed_by
    """
    params = ()
    if status in ("pending", "approved", "rejected"):
        query += " WHERE e.status=%s"
        params = (status,)
    query += " ORDER BY e.id DESC"

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]


@app.post("/api/admin/entries/{entry_id}/review")
def review_entry(
    entry_id: int,
    decision: str = Form(...),
    note: str = Form(""),
    admin=Depends(require_office)
):
    if decision not in ("approved", "rejected"):
        raise HTTPException(status_code=400, detail="Decision must be approved or rejected")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE diesel_entries
                SET status=%s,reviewed_by=%s,review_note=%s
                WHERE id=%s AND status='pending'
            """, (decision, admin["id"], note.strip(), entry_id))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Pending entry not found")

    return {"ok": True, "status": decision}


@app.get("/api/admin/summary")
def summary(admin=Depends(require_office)):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT status,COUNT(*) AS n,
                       COALESCE(SUM(litres),0) AS litres,
                       COALESCE(SUM(litres*rate_per_litre),0) AS cost
                FROM diesel_entries GROUP BY status ORDER BY status
            """)
            status_rows = [dict(row) for row in cur.fetchall()]

            cur.execute("""
                SELECT b.bus_number,COUNT(e.id) AS entries,
                       COALESCE(SUM(e.litres),0) AS litres,
                       COALESCE(SUM(e.litres*e.rate_per_litre),0) AS cost
                FROM buses b
                LEFT JOIN diesel_entries e ON e.bus_id=b.id AND e.status='approved'
                WHERE b.active=TRUE
                GROUP BY b.id,b.bus_number ORDER BY b.bus_number
            """)
            bus_rows = [dict(row) for row in cur.fetchall()]

            cur.execute("""
                SELECT r.route_name,COUNT(e.id) AS entries,
                       COALESCE(SUM(e.litres),0) AS litres,
                       COALESCE(SUM(e.litres*e.rate_per_litre),0) AS cost
                FROM routes r
                LEFT JOIN diesel_entries e ON e.route_id=r.id AND e.status='approved'
                WHERE r.active=TRUE
                GROUP BY r.id,r.route_name ORDER BY r.route_name
            """)
            route_rows = [dict(row) for row in cur.fetchall()]

    return {
        "status_totals": status_rows,
        "bus_totals": bus_rows,
        "route_totals": route_rows,
        "note": "KM/L average needs verified full-to-full or trip-wise fuel-consumption readings."
    }


@app.get("/api/admin/reports/period")
def period_report(
    year: int,
    month: Optional[int] = None,
    admin=Depends(require_office)
):
    start, end = date_range(year, month)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT e.status,COUNT(*) AS entries,
                       COALESCE(SUM(e.litres),0) AS litres,
                       COALESCE(SUM(e.litres*e.rate_per_litre),0) AS cost
                FROM diesel_entries e
                WHERE e.entry_date >= %s AND e.entry_date < %s
                GROUP BY e.status ORDER BY e.status
            """, (start, end))
            totals = [dict(row) for row in cur.fetchall()]

            cur.execute("""
                SELECT b.bus_number,COUNT(e.id) AS entries,
                       COALESCE(SUM(e.litres),0) AS litres,
                       COALESCE(SUM(e.litres*e.rate_per_litre),0) AS cost
                FROM diesel_entries e JOIN buses b ON b.id=e.bus_id
                WHERE e.entry_date >= %s AND e.entry_date < %s
                  AND e.status='approved'
                GROUP BY b.bus_number ORDER BY b.bus_number
            """, (start, end))
            by_bus = [dict(row) for row in cur.fetchall()]

            cur.execute("""
                SELECT r.route_name,COUNT(e.id) AS entries,
                       COALESCE(SUM(e.litres),0) AS litres,
                       COALESCE(SUM(e.litres*e.rate_per_litre),0) AS cost
                FROM diesel_entries e JOIN routes r ON r.id=e.route_id
                WHERE e.entry_date >= %s AND e.entry_date < %s
                  AND e.status='approved'
                GROUP BY r.route_name ORDER BY r.route_name
            """, (start, end))
            by_route = [dict(row) for row in cur.fetchall()]

    return {
        "from_date": start,
        "to_date_exclusive": end,
        "status_totals": totals,
        "bus_totals": by_bus,
        "route_totals": by_route
    }


# ------------------------------------------------------------
# Authenticated photo access
# ------------------------------------------------------------
@app.get("/uploads/{filename}")
def get_upload(filename: str, token: str):
    # Photo links open in a new browser tab, so authenticate using the short-lived JWT query token.
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid or expired photo link")

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id,role,active FROM users WHERE id=%s",
                (user_id,)
            )
            user = cur.fetchone()
            safe_name = Path(filename).name
            if safe_name != filename:
                raise HTTPException(status_code=400, detail="Invalid filename")
            cur.execute("""
                SELECT driver_id FROM diesel_entries
                WHERE meter_photo=%s OR pump_photo=%s
                LIMIT 1
            """, (safe_name, safe_name))
            photo = cur.fetchone()

    if not user or not user["active"]:
        raise HTTPException(status_code=401, detail="User is inactive")
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")
    if user["role"] == "driver" and photo["driver_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="You cannot view another driver's photo")

    path = UPLOAD_DIR / safe_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Photo file not found")
    return FileResponse(path)


@app.get("/")
def home():
    return FileResponse(APP_DIR / "index.html")
