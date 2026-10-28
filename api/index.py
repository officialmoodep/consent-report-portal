import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from supabase import create_client, Client
from passlib.context import CryptContext

load_dotenv()

BASE = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="Consent Report Portal")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "CHANGE_ME"),
    https_only=True,
    same_site="lax",
)

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
sb: Client | None = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

def now():
    return datetime.now(timezone.utc)

def require_db():
    if not sb:
        raise RuntimeError("Supabase environment variables are not configured.")

def current_user(request: Request):
    return request.session.get("user")

def render(request: Request, name: str, **ctx):
    return templates.TemplateResponse(name, {"request": request, **ctx})

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render(request, "home.html", user=current_user(request))

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render(request, "auth.html", mode="register", error=None)

@app.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    require_db()
    email = email.strip().lower()
    if len(password) < 8:
        return render(request, "auth.html", mode="register", error="رمز عبور باید حداقل ۸ کاراکتر باشد.")
    existing = sb.table("users").select("id").eq("email", email).limit(1).execute()
    if existing.data:
        return render(request, "auth.html", mode="register", error="این ایمیل قبلاً ثبت شده است.")
    row = sb.table("users").insert({
        "email": email,
        "password_hash": pwd.hash(password)
    }).execute().data[0]
    request.session["user"] = {"id": row["id"], "email": email}
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "auth.html", mode="login", error=None)

@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    require_db()
    email = email.strip().lower()
    rows = sb.table("users").select("*").eq("email", email).limit(1).execute().data
    if not rows or not pwd.verify(password, rows[0]["password_hash"]):
        return render(request, "auth.html", mode="login", error="ایمیل یا رمز عبور اشتباه است.")
    request.session["user"] = {"id": rows[0]["id"], "email": rows[0]["email"]}
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    require_db()
    cases = sb.table("cases").select("*").eq("owner_id", user["id"]).order("created_at", desc=True).execute().data
    return render(request, "dashboard.html", user=user, cases=cases)

@app.post("/cases")
def create_case(request: Request, title: str = Form(...), expires_days: int = Form(7)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    require_db()
    expires_days = max(1, min(expires_days, 30))
    token = secrets.token_urlsafe(32)
    expires = now() + timedelta(days=expires_days)
    row = sb.table("cases").insert({
        "owner_id": user["id"],
        "title": title.strip()[:160],
        "token": token,
        "expires_at": expires.isoformat(),
        "status": "open"
    }).execute().data[0]
    return RedirectResponse(f"/case/{row['id']}", status_code=303)

@app.get("/case/{case_id}", response_class=HTMLResponse)
def case_page(request: Request, case_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    require_db()
    rows = sb.table("cases").select("*").eq("id", case_id).eq("owner_id", user["id"]).limit(1).execute().data
    if not rows:
        return HTMLResponse("پرونده پیدا نشد.", status_code=404)
    case = rows[0]
    submissions = sb.table("submissions").select("*").eq("case_id", case_id).order("created_at", desc=True).execute().data
    return render(request, "case.html", user=user, case=case, submissions=submissions)

@app.get("/share/{token}", response_class=HTMLResponse)
def share_page(request: Request, token: str):
    require_db()
    rows = sb.table("cases").select("id,title,token,expires_at,status").eq("token", token).limit(1).execute().data
    if not rows:
        return HTMLResponse("این لینک معتبر نیست.", status_code=404)
    case = rows[0]
    if case["status"] != "open" or datetime.fromisoformat(case["expires_at"].replace("Z","+00:00")) < now():
        return HTMLResponse("این لینک منقضی یا بسته شده است.", status_code=410)
    return render(request, "consent.html", case=case)

@app.post("/share/{token}")
async def submit_consent(
    request: Request,
    token: str,
    consent_location: str = Form("no"),
    consent_phone: str = Form("no"),
    consent_photo: str = Form("no"),
    phone: str = Form(""),
    latitude: str = Form(""),
    longitude: str = Form(""),
    photo: UploadFile | None = File(None),
):
    require_db()
    rows = sb.table("cases").select("*").eq("token", token).eq("status", "open").limit(1).execute().data
    if not rows:
        return HTMLResponse("این لینک معتبر نیست یا منقضی شده است.", status_code=410)
    case = rows[0]
    expires = datetime.fromisoformat(case["expires_at"].replace("Z","+00:00"))
    if expires < now():
        return HTMLResponse("این لینک منقضی شده است.", status_code=410)

    # Store only fields for which the visitor explicitly granted consent.
    data = {
        "case_id": case["id"],
        "consent_location": consent_location == "yes",
        "consent_phone": consent_phone == "yes",
        "consent_photo": consent_photo == "yes",
        "phone": phone.strip() if consent_phone == "yes" else None,
        "latitude": float(latitude) if consent_location == "yes" and latitude else None,
        "longitude": float(longitude) if consent_location == "yes" and longitude else None,
    }

    if consent_photo == "yes" and photo and photo.filename:
        content = await photo.read()
        if len(content) > 5 * 1024 * 1024:
            return HTMLResponse("حجم عکس بیشتر از ۵ مگابایت است.", status_code=413)
        safe_name = secrets.token_hex(16) + Path(photo.filename).suffix.lower()
        path = f"{case['id']}/{safe_name}"
        sb.storage.from_("consent-photos").upload(path, content, {"content-type": photo.content_type or "image/jpeg"})
        data["photo_path"] = path

    sb.table("submissions").insert(data).execute()
    return render(request, "thanks.html")

@app.post("/case/{case_id}/close")
def close_case(request: Request, case_id: str):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    require_db()
    sb.table("cases").update({"status": "closed"}).eq("id", case_id).eq("owner_id", user["id"]).execute()
    return RedirectResponse(f"/case/{case_id}", status_code=303)

@app.get("/health")
def health():
    return JSONResponse({"ok": True})
