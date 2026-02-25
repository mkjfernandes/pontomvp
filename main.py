import os
from datetime import datetime, timedelta, date
from zoneinfo import ZoneInfo
from typing import Optional, List, Literal, Dict, Any

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from jose import jwt, JWTError
from passlib.context import CryptContext

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session


# -----------------------------
# Config
# -----------------------------
APP_TZ = ZoneInfo("America/Sao_Paulo")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_SUPER_SECRET")
JWT_ALG = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "12"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ponto_mvp.sqlite3")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

Base = declarative_base()

def now_sp() -> datetime:
    return datetime.now(tz=APP_TZ)

def utc_iso(dt: datetime) -> str:
    # Store timezone-aware; for display use local
    return dt.astimezone(APP_TZ).isoformat(timespec="seconds")

def client_ip(req: Request) -> str:
    # If behind proxy later, you can trust X-Forwarded-For carefully
    xf = req.headers.get("x-forwarded-for")
    if xf:
        return xf.split(",")[0].strip()
    return req.client.host if req.client else "unknown"


# -----------------------------
# DB
# -----------------------------
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)  # lower-case
    display_name = Column(String(80), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # "ADMIN" or "EMPLOYEE"
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_sp, nullable=False)

    punches = relationship("Punch", back_populates="user")

class Punch(Base):
    __tablename__ = "punches"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    type = Column(String(20), nullable=False)  # IN, OUT, LUNCH_START, LUNCH_END
    punched_at = Column(DateTime(timezone=True), nullable=False)
    ip = Column(String(80), nullable=False)
    user_agent = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=now_sp, nullable=False)

    user = relationship("User", back_populates="punches")

class Adjustment(Base):
    __tablename__ = "adjustments"
    id = Column(Integer, primary_key=True)
    admin_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    day = Column(String(10), nullable=False)  # YYYY-MM-DD
    reason = Column(Text, nullable=False)
    before_json = Column(Text, nullable=False)
    after_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=now_sp, nullable=False)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------
# Auth (JWT)
# -----------------------------
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)

def create_token(user: User) -> str:
    exp = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {
        "sub": str(user.id),
        "role": user.role,
        "username": user.username,
        "exp": exp
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(req: Request, db: Session = Depends(get_db)) -> User:
    token = req.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = int(payload.get("sub"))
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id, User.active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin required")
    return user


# -----------------------------
# App
# -----------------------------
app = FastAPI(title="Ponto MVP", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 24px auto; padding: 0 16px; }}
    .row {{ display:flex; gap:16px; flex-wrap:wrap; }}
    .card {{ border:1px solid #ddd; border-radius:10px; padding:16px; flex:1; min-width: 260px; }}
    button {{ padding:12px 14px; border-radius:10px; border:1px solid #333; background:#111; color:#fff; cursor:pointer; }}
    button.secondary {{ background:#fff; color:#111; }}
    table {{ width:100%; border-collapse: collapse; }}
    th, td {{ border-bottom:1px solid #eee; padding:10px; text-align:left; font-size: 14px; }}
    .muted {{ color:#666; font-size: 12px; }}
    .warn {{ background:#fff3cd; padding:10px; border-radius:10px; border:1px solid #ffeeba; }}
    input, select, textarea {{ width: 100%; padding:10px; border-radius:10px; border:1px solid #ccc; }}
    a {{ color:#0b5ed7; text-decoration:none; }}
    .top {{ display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }}
    .pill {{ font-size:12px; padding:6px 10px; background:#f3f3f3; border-radius:999px; }}
  </style>
</head>
<body>
  {body}
</body>
</html>"""

PUNCH_TYPES = ["IN", "OUT", "LUNCH_START", "LUNCH_END"]

def punch_label(t: str) -> str:
    return {
        "IN": "Entrada",
        "OUT": "Saída",
        "LUNCH_START": "Início almoço",
        "LUNCH_END": "Fim almoço",
    }.get(t, t)

def is_today(dt: datetime) -> bool:
    d = dt.astimezone(APP_TZ).date()
    return d == now_sp().date()

def get_today_punches(db: Session, user_id: int) -> List[Punch]:
    # SQLite friendly filtering: pull recent and filter; for Postgres use date trunc in SQL
    punches = db.query(Punch).filter(Punch.user_id == user_id).order_by(Punch.punched_at.asc()).all()
    return [p for p in punches if is_today(p.punched_at)]

def compute_alerts(punches: List[Punch]) -> List[str]:
    alerts = []
    types = [p.type for p in punches]

    # Simple sequence checks (alerts only)
    for i in range(1, len(types)):
        if types[i] == types[i-1]:
            alerts.append(f"Batida repetida: {punch_label(types[i])} duas vezes seguidas.")

    if "IN" not in types:
        alerts.append("Sem Entrada registrada hoje.")
    if "IN" in types and "OUT" not in types and now_sp().hour >= 18:
        alerts.append("Entrada registrada, mas sem Saída (após 18h).")

    if "LUNCH_START" in types and "LUNCH_END" not in types and now_sp().hour >= 14:
        alerts.append("Almoço iniciado, mas sem Fim almoço (após 14h).")

    # Lunch duration alert if both exist (use first pair)
    try:
        ls = next(p for p in punches if p.type == "LUNCH_START")
        le = next(p for p in punches if p.type == "LUNCH_END")
        dur = (le.punched_at - ls.punched_at).total_seconds() / 60.0
        if dur < 30:
            alerts.append(f"Almoço muito curto: {int(dur)} min.")
        if dur > 120:
            alerts.append(f"Almoço muito longo: {int(dur)} min.")
    except StopIteration:
        pass

    return alerts

def seed_users(db: Session) -> Dict[str, str]:
    existing = db.query(User).count()
    if existing > 0:
        return {}

    def gen_pw():
        return "Ponto@1234"

    users = [
        ("aline", "Aline", "EMPLOYEE"),
        ("caroline", "Caroline", "EMPLOYEE"),
        ("inglid", "Inglid", "EMPLOYEE"),
        ("marcus", "Marcus", "ADMIN"),
        ("william", "William", "ADMIN"),
    ]

    pw_map = {}
    for username, display, role in users:
        pw = gen_pw()
        pw_map[username] = pw
        db.add(
            User(
                username=username,
                display_name=display,
                password_hash=hash_password(pw),
                role=role,
                active=True,
            )
        )

    db.commit()
    return pw_map




@app.on_event("startup")
def on_startup():
    init_db()
    # Seed once
    db = SessionLocal()
    try:
        pw_map = seed_users(db)
        if pw_map:
            # Print passwords in server console once
            print("\n=== SENHAS TEMPORÁRIAS (APENAS NA PRIMEIRA EXECUÇÃO) ===")
            for u, p in pw_map.items():
                print(f"{u}: {p}")
            print("=======================================================\n")
    finally:
        db.close()


# -----------------------------
# Routes: Auth
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def root(req: Request):
    token = req.cookies.get("token")
    if token:
        return RedirectResponse("/ponto")
    return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(msg: Optional[str] = None):
    message = f"<p class='warn'>{msg}</p>" if msg else ""
    body = f"""
    <div class="top">
      <h2>Login - Ponto MVP</h2>
      <span class="pill">Fuso: America/Sao_Paulo</span>
    </div>
    {message}
    <div class="card">
      <form method="post" action="/auth/login">
        <label>Usuário</label>
        <input name="username" placeholder="ex.: aline" required />
        <div style="height:10px"></div>
        <label>Senha</label>
        <input name="password" type="password" required />
        <div style="height:14px"></div>
        <button type="submit">Entrar</button>
      </form>
      <p class="muted">As senhas temporárias são exibidas apenas no console do servidor na primeira execução.</p>
    </div>
    """
    return page("Login", body)

@app.post("/auth/login")
def auth_login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    u = db.query(User).filter(User.username == username.strip().lower(), User.active == True).first()
    if not u or not verify_password(password, u.password_hash):
        return RedirectResponse("/login?msg=Usuário%20ou%20senha%20inválidos", status_code=303)

    token = create_token(u)
    resp = RedirectResponse("/ponto", status_code=303)
    resp.set_cookie("token", token, httponly=True, samesite="lax")
    return resp

@app.post("/auth/logout")
def logout():
    resp = RedirectResponse("/login?msg=Logout%20feito", status_code=303)
    resp.delete_cookie("token")
    return resp


# -----------------------------
# Routes: Employee
# -----------------------------
@app.get("/ponto", response_class=HTMLResponse)
def ponto_page(req: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    punches = get_today_punches(db, user.id)
    alerts = compute_alerts(punches)

    rows = ""
    for p in punches:
        rows += f"<tr><td>{punch_label(p.type)}</td><td>{utc_iso(p.punched_at)}</td><td class='muted'>{p.ip}</td></tr>"

    alerts_html = ""
    if alerts:
        alerts_html = "<div class='warn'><b>Alertas:</b><ul>" + "".join([f"<li>{a}</li>" for a in alerts]) + "</ul></div>"

    admin_link = ""
    if user.role == "ADMIN":
        admin_link = """<a href="/admin">Ir para Admin</a>"""

    body = f"""
    <div class="top">
      <div>
        <h2>Ponto - {user.display_name}</h2>
        <div class="muted">Usuário: {user.username} • Perfil: {user.role} • Hoje: {now_sp().date().isoformat()}</div>
      </div>
      <div class="row" style="align-items:center">
        {admin_link}
        <form method="post" action="/auth/logout" style="margin:0">
          <button class="secondary" type="submit">Sair</button>
        </form>
      </div>
    </div>

    <div class="row">
      <div class="card">
        <h3>Bater ponto</h3>
        <div class="row">
          <form method="post" action="/punch" style="margin:0">
            <input type="hidden" name="type" value="IN" />
            <button type="submit">Entrada</button>
          </form>
          <form method="post" action="/punch" style="margin:0">
            <input type="hidden" name="type" value="OUT" />
            <button type="submit">Saída</button>
          </form>
          <form method="post" action="/punch" style="margin:0">
            <input type="hidden" name="type" value="LUNCH_START" />
            <button type="submit">Início almoço</button>
          </form>
          <form method="post" action="/punch" style="margin:0">
            <input type="hidden" name="type" value="LUNCH_END" />
            <button type="submit">Fim almoço</button>
          </form>
        </div>
        <p class="muted">O sistema registra horário + IP + user-agent para auditoria básica.</p>
      </div>

      <div class="card">
        <h3>Registros de hoje</h3>
        {alerts_html}
        <table>
          <thead><tr><th>Tipo</th><th>Data/Hora</th><th>IP</th></tr></thead>
          <tbody>{rows if rows else "<tr><td colspan='3' class='muted'>Sem registros hoje.</td></tr>"}</tbody>
        </table>
      </div>
    </div>
    """
    return page("Ponto", body)

@app.post("/punch")
def create_punch(
    req: Request,
    type: str = Form(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    t = type.strip().upper()
    if t not in PUNCH_TYPES:
        return RedirectResponse("/ponto", status_code=303)

    p = Punch(
        user_id=user.id,
        type=t,
        punched_at=now_sp(),
        ip=client_ip(req),
        user_agent=req.headers.get("user-agent", "")
    )
    db.add(p)
    db.commit()
    return RedirectResponse("/ponto", status_code=303)


# -----------------------------
# Routes: Admin
# -----------------------------
@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    req: Request,
    day: Optional[str] = None,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    if not day:
        day = now_sp().date().isoformat()

    # Load users
    users = db.query(User).filter(User.active == True).order_by(User.role.desc(), User.display_name.asc()).all()

    # Load punches and filter by day (simple approach)
    all_p = db.query(Punch).order_by(Punch.punched_at.asc()).all()
    target_day = date.fromisoformat(day)
    punches = [p for p in all_p if p.punched_at.astimezone(APP_TZ).date() == target_day]

    # Group
    by_user: Dict[int, List[Punch]] = {}
    for p in punches:
        by_user.setdefault(p.user_id, []).append(p)

    # Render table
    table = ""
    alerts_block = ""
    for u in users:
        if u.role != "EMPLOYEE":
            continue
        ups = by_user.get(u.id, [])
        alerts = compute_alerts(ups)
        ahtml = ""
        if alerts:
            ahtml = "<div class='warn'>" + "<br/>".join(alerts) + "</div>"

        rows = ""
        for p in ups:
            rows += f"<tr><td>{punch_label(p.type)}</td><td>{utc_iso(p.punched_at)}</td><td class='muted'>{p.ip}</td></tr>"

        table += f"""
        <div class="card">
          <h3>{u.display_name} <span class="muted">({u.username})</span></h3>
          {ahtml}
          <table>
            <thead><tr><th>Tipo</th><th>Data/Hora</th><th>IP</th></tr></thead>
            <tbody>{rows if rows else "<tr><td colspan='3' class='muted'>Sem registros.</td></tr>"}</tbody>
          </table>

          <details style="margin-top:10px">
            <summary>Ajustar (admin)</summary>
            <form method="post" action="/admin/adjust">
              <input type="hidden" name="target_username" value="{u.username}" />
              <input type="hidden" name="day" value="{day}" />
              <div style="height:8px"></div>
              <label>Novo conjunto de batidas (um por linha: IN, OUT, LUNCH_START, LUNCH_END com horário HH:MM)</label>
              <textarea name="new_punches" rows="5" placeholder="IN 08:02&#10;LUNCH_START 12:05&#10;LUNCH_END 13:07&#10;OUT 18:01" required></textarea>
              <div style="height:8px"></div>
              <label>Motivo</label>
              <input name="reason" placeholder="Ex.: Esqueceu de registrar retorno do almoço" required />
              <div style="height:10px"></div>
              <button type="submit">Salvar ajuste</button>
              <p class="muted">O ajuste substitui todas as batidas daquele dia para a pessoa (MVP).</p>
            </form>
          </details>
        </div>
        """

    body = f"""
    <div class="top">
      <div>
        <h2>Admin - {admin.display_name}</h2>
        <div class="muted">Data selecionada: {day}</div>
      </div>
      <div class="row" style="align-items:center">
        <a href="/ponto">Voltar ao Ponto</a>
        <form method="post" action="/auth/logout" style="margin:0">
          <button class="secondary" type="submit">Sair</button>
        </form>
      </div>
    </div>

    <div class="card">
      <form method="get" action="/admin">
        <label>Ver data</label>
        <input name="day" value="{day}" type="date" />
        <div style="height:10px"></div>
        <button class="secondary" type="submit">Atualizar</button>
      </form>
      <p class="muted">Alertas são informativos (não bloqueiam). Ajustes ficam auditados.</p>
    </div>

    <div class="row">
      {table}
    </div>
    """
    return page("Admin", body)

@app.post("/admin/adjust")
def admin_adjust(
    req: Request,
    target_username: str = Form(...),
    day: str = Form(...),
    new_punches: str = Form(...),
    reason: str = Form(...),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    target = db.query(User).filter(User.username == target_username.strip().lower(), User.active == True).first()
    if not target:
        return RedirectResponse(f"/admin?day={day}", status_code=303)

    target_day = date.fromisoformat(day)

    # Load existing punches for that day
    all_p = db.query(Punch).filter(Punch.user_id == target.id).order_by(Punch.punched_at.asc()).all()
    existing = [p for p in all_p if p.punched_at.astimezone(APP_TZ).date() == target_day]

    before = [{"type": p.type, "at": utc_iso(p.punched_at), "ip": p.ip} for p in existing]

    # Delete existing
    for p in existing:
        db.delete(p)

    # Parse new punches
    parsed = []
    for line in new_punches.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        t, hhmm = parts[0].upper(), parts[1]
        if t not in PUNCH_TYPES:
            continue
        try:
            hh, mm = hhmm.split(":")
            hh, mm = int(hh), int(mm)
            dt = datetime(target_day.year, target_day.month, target_day.day, hh, mm, tzinfo=APP_TZ)
        except Exception:
            continue
        parsed.append((t, dt))

    parsed.sort(key=lambda x: x[1])

    # Insert
    after = []
    for t, dt in parsed:
        p = Punch(
            user_id=target.id,
            type=t,
            punched_at=dt,
            ip=f"ADJUSTED_BY_{admin.username}",
            user_agent="ADMIN_ADJUSTMENT"
        )
        db.add(p)
        after.append({"type": t, "at": utc_iso(dt), "ip": p.ip})

    # Log adjustment
    adj = Adjustment(
        admin_user_id=admin.id,
        target_user_id=target.id,
        day=day,
        reason=reason,
        before_json=str(before),
        after_json=str(after),
    )
    db.add(adj)
    db.commit()

    return RedirectResponse(f"/admin?day={day}", status_code=303)


# -----------------------------
# Utility: show whoami (debug)
# -----------------------------
@app.get("/whoami")
def whoami(user: User = Depends(get_current_user)):
    return {"username": user.username, "display_name": user.display_name, "role": user.role}
