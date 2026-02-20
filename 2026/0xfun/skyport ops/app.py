import os, secrets, shutil
from typing import Optional, List
from dataclasses import dataclass
from pathlib import Path

import strawberry
import strawberry.fastapi
from strawberry.relay import Node, NodeID
from strawberry.types import Info
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jose import jwt as jose_jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

_rsa_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
RSA_PRIVATE_PEM = _rsa_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
)
RSA_PUBLIC_DER = _rsa_key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

UPLOAD_DIR = Path("/tmp/skyport_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

JWKS_PATH = "/api/" + secrets.token_hex(8)

_STAFF_JWT = jose_jwt.encode(
    {"sub": "officer_chen", "role": "staff", "jwks_uri": JWKS_PATH},
    RSA_PRIVATE_PEM, algorithm="RS256",
)


@dataclass
class UserModel:
    pk: int
    username: str
    role: str
    full_name: str
    email: str
    flight: Optional[str] = None
    seat: Optional[str] = None
    terminal: Optional[str] = None
    badge_id: Optional[str] = None
    department: Optional[str] = None
    access_token: Optional[str] = None


USERS: dict[int, UserModel] = {
    1: UserModel(
        pk=1, username="james_porter", role="passenger",
        full_name="James Porter", email="j.porter@gmail.com",
        flight="SK291", seat="14C", terminal="Terminal A",
    ),
    2: UserModel(
        pk=2, username="officer_chen", role="staff",
        full_name="Lin Chen", email="l.chen@skyport.local",
        badge_id="SEC-0042", department="Security Operations",
        access_token=_STAFF_JWT,
    ),
    3: UserModel(
        pk=3, username="maria_santos", role="passenger",
        full_name="Maria Santos", email="m.santos@hotmail.com",
        flight="LH507", seat="32A", terminal="Terminal B",
    ),
    4: UserModel(
        pk=4, username="gate_miller", role="staff",
        full_name="Tom Miller", email="t.miller@skyport.local",
        badge_id="GATE-117", department="Gate Operations",
    ),
}


class UserRepository:

    @staticmethod
    def get_passenger(user_id: int) -> Optional[UserModel]:
        user = USERS.get(user_id)
        if user and user.role == "passenger":
            return user
        return None

    @staticmethod
    def get_staff(user_id: int) -> Optional[UserModel]:
        user = USERS.get(user_id)
        if user and user.role == "staff":
            return user
        return None


@dataclass
class FlightModel:
    flight_number: str
    destination: str
    gate: str
    scheduled: str
    status: str

FLIGHTS = [
    FlightModel("SK291", "Frankfurt (FRA)", "A14", "08:35", "Boarding"),
    FlightModel("LH507", "London Heathrow (LHR)", "B03", "09:10", "On Time"),
    FlightModel("EK881", "Dubai (DXB)", "C22", "09:45", "On Time"),
    FlightModel("TK044", "Istanbul (IST)", "A07", "10:20", "Delayed"),
    FlightModel("QR572", "Doha (DOH)", "B18", "11:00", "On Time"),
    FlightModel("UA190", "New York (JFK)", "C09", "11:55", "Departed"),
]


@strawberry.type
class PassengerNode(Node):
    id: NodeID[int]
    username: str
    full_name: str
    flight: Optional[str]
    seat: Optional[str]
    terminal: Optional[str]

    @classmethod
    def resolve_node(cls, node_id: str, *, info: Info, **kwargs):
        return USERS.get(int(node_id))

    @classmethod
    def resolve_nodes(cls, *, info: Info, node_ids, required=False):
        return [USERS.get(int(nid)) for nid in node_ids]

    @classmethod
    def is_type_of(cls, obj, info: Info) -> bool:
        return isinstance(obj, UserModel) and obj.role == "passenger"


@strawberry.type
class StaffSummary:
    username: str
    full_name: str
    badge_id: Optional[str]
    department: Optional[str]


@strawberry.type
class StaffNode(Node):
    id: NodeID[int]
    username: str
    full_name: str
    badge_id: Optional[str]
    department: Optional[str]
    access_token: Optional[str]

    @classmethod
    def resolve_node(cls, node_id: str, *, info: Info, **kwargs):
        return USERS.get(int(node_id))

    @classmethod
    def resolve_nodes(cls, *, info: Info, node_ids, required=False):
        return [USERS.get(int(nid)) for nid in node_ids]

    @classmethod
    def is_type_of(cls, obj, info: Info) -> bool:
        return isinstance(obj, UserModel) and obj.role == "staff"


@strawberry.type
class Flight:
    flight_number: str
    destination: str
    gate: str
    scheduled: str
    status: str


@strawberry.type
class GQLQuery:
    node: Node = strawberry.relay.node()

    @strawberry.field
    def passengers(self) -> List[PassengerNode]:
        return [u for u in USERS.values() if u.role == "passenger"]

    @strawberry.field
    def staff(self) -> List[StaffSummary]:
        return [
            StaffSummary(
                username=u.username,
                full_name=u.full_name,
                badge_id=u.badge_id,
                department=u.department,
            )
            for u in USERS.values() if u.role == "staff"
        ]

    @strawberry.field
    def flights(self) -> List[Flight]:
        return [
            Flight(
                flight_number=f.flight_number,
                destination=f.destination,
                gate=f.gate,
                scheduled=f.scheduled,
                status=f.status,
            )
            for f in FLIGHTS
        ]


def resolve_id(root, info) -> int:
    return root.pk if isinstance(root, UserModel) else root.id

def resolve_username(root, info) -> str:
    return root.username

def resolve_full_name(root, info) -> str:
    return root.full_name

def resolve_flight(root, info) -> Optional[str]:
    return root.flight if isinstance(root, UserModel) else None

def resolve_seat(root, info) -> Optional[str]:
    return root.seat if isinstance(root, UserModel) else None

def resolve_terminal(root, info) -> Optional[str]:
    return root.terminal if isinstance(root, UserModel) else None

def resolve_badge_id(root, info) -> Optional[str]:
    return root.badge_id if isinstance(root, UserModel) else None

def resolve_department(root, info) -> Optional[str]:
    return root.department if isinstance(root, UserModel) else None

def resolve_access_token(root, info) -> Optional[str]:
    return root.access_token if isinstance(root, UserModel) else None

PassengerNode.__strawberry_definition__.fields[0].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_id)
PassengerNode.__strawberry_definition__.fields[1].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_username)
PassengerNode.__strawberry_definition__.fields[2].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_full_name)
PassengerNode.__strawberry_definition__.fields[3].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_flight)
PassengerNode.__strawberry_definition__.fields[4].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_seat)
PassengerNode.__strawberry_definition__.fields[5].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_terminal)

StaffNode.__strawberry_definition__.fields[0].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_id)
StaffNode.__strawberry_definition__.fields[1].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_username)
StaffNode.__strawberry_definition__.fields[2].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_full_name)
StaffNode.__strawberry_definition__.fields[3].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_badge_id)
StaffNode.__strawberry_definition__.fields[4].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_department)
StaffNode.__strawberry_definition__.fields[5].base_resolver = strawberry.types.fields.resolver.StrawberryResolver(resolve_access_token)

schema = strawberry.Schema(query=GQLQuery, types=[PassengerNode, StaffNode])
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

graphql_router = strawberry.fastapi.GraphQLRouter(schema, graphql_ide=None)
app.include_router(graphql_router, prefix="/graphql")


_CSS = '''*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;color:#1a202c}
header{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:0 32px;
  display:flex;align-items:center;justify-content:space-between;height:62px;
  box-shadow:0 2px 10px rgba(0,0,0,.3)}
header .logo{font-size:1.15em;font-weight:700;letter-spacing:2px;display:flex;align-items:center;gap:10px}
header .logo .tag{font-size:.65em;background:#3b82f6;color:#fff;padding:2px 8px;
  border-radius:4px;letter-spacing:1px;font-weight:600}
nav a{color:#94a3b8;text-decoration:none;margin-left:24px;font-size:.88em;transition:color .2s}
nav a:hover{color:#fff}
.main{max-width:1020px;margin:36px auto;padding:0 24px}
.card{background:#fff;border-radius:10px;padding:28px;margin-bottom:22px;
  box-shadow:0 1px 6px rgba(0,0,0,.08)}
.card h2{font-size:1.05em;color:#1e3a5f;margin-bottom:14px;
  padding-bottom:10px;border-bottom:1px solid #e2e8f0;font-weight:700;letter-spacing:.3px}
table{width:100%;border-collapse:collapse;font-size:.9em}
th{background:#f7f9fc;color:#4a5568;font-weight:600;padding:10px 14px;
  text-align:left;border-bottom:2px solid #e2e8f0}
td{padding:10px 14px;border-bottom:1px solid #f0f4f8}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8faff}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.76em;font-weight:700;letter-spacing:.3px}
.badge-on-time{background:#dcfce7;color:#15803d}
.badge-delayed{background:#fef9c3;color:#a16207}
.badge-boarding{background:#dbeafe;color:#1d4ed8}
.badge-departed{background:#f3f4f6;color:#6b7280}
.alert{padding:12px 16px;border-radius:6px;margin-bottom:16px;font-size:.9em}
.alert-info{background:#eff6ff;border-left:4px solid #3b82f6;color:#1e40af}
.divider{height:1px;background:#e2e8f0;margin:20px 0}
a{color:#1d4ed8}'''

_HEADER = '''<header>
  <div class="logo">
    ✈ SKYPORT <span class="tag">OPS</span>
  </div>
  <nav>
    <a href="/">Home</a>
    <a href="/departures">Departures</a>
    <a href="/contact">Contact</a>
  </nav>
</header>'''

def _page(title, body):
    return HTMLResponse(f'''<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — SkyPort Operations</title>
<style>{_CSS}</style></head>
<body>{_HEADER}<div class="main">{body}</div></body></html>''')

@app.get("/")
def home():
    return _page("Home", '''
<div class="card">
  <h2>SkyPort Internal Operations Portal</h2>
  <div class="alert alert-info">
    Restricted access — authorised airport staff only.
    All activity is monitored and recorded.
  </div>
  <p style="color:#4a5568;font-size:.93em;line-height:1.75;margin-top:4px">
    Welcome to the SkyPort internal operations platform. This portal provides
    authorised staff with access to flight operations, passenger manifests, and
    ground services coordination. For system access or credential issues,
    contact the operations desk.
  </p>
</div>''')

@app.get("/departures")
def departures():
    return _page("Departures", '''
<div class="card">
  <h2>Live Departure Board</h2>
  <table id="departures"><thead><tr>
    <th>Flight</th><th>Destination</th><th>Gate</th><th>Scheduled</th><th>Status</th>
  </tr></thead><tbody></tbody></table>
</div>
<script>
fetch("/graphql",{method:"POST",headers:{"Content-Type":"application/json"},
body:JSON.stringify({query:"{flights{flightNumber destination gate scheduled status}}"})})
.then(r=>r.json()).then(d=>{
  if(!d.data||!d.data.flights)return;
  let t=document.querySelector("#departures tbody");
  d.data.flights.forEach(f=>{
    let st=f.status.toLowerCase().replace(" ","");
    t.innerHTML+=`<tr><td><strong>${f.flightNumber}</strong></td><td>${f.destination}</td>
    <td>${f.gate}</td><td>${f.scheduled}</td>
    <td><span class="badge badge-${st.replace("ontime","on-time")}">${f.status}</span></td></tr>`;
  });
});
</script>''')

@app.get("/contact")
def contact():
    return _page("Contact", '''
<div class="card">
  <h2>Operations Contact</h2>
  <p style="margin:12px 0">For system access, technical support, or operational inquiries:</p>
  <p><strong>Email:</strong> ops@skyport.local<br>
  <strong>Hotline:</strong> +1 (555) 0199<br>
  <strong>Hours:</strong> 24/7 Operations Desk</p>
</div>''')


@app.get(JWKS_PATH)
def jwks():
    pem_key = _rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return JSONResponse({
        "algorithm": "RS256",
        "public_key": pem_key.decode()
    })


def _decode_admin_jwt(token: str) -> Optional[dict]:
    if not token:
        return None
    try:
        payload = jose_jwt.decode(token, RSA_PUBLIC_DER, algorithms=None)
        return payload if payload.get("role") == "admin" else None
    except Exception:
        return None


def _require_admin(request: Request) -> bool:
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else None
    return _decode_admin_jwt(token) is not None


@app.get("/internal/manifests")
def manifests():
    return JSONResponse({
        "classified": True,
        "manifests": [
            {"flight": "SK291", "passengers": 187, "cargo_kg": 4200, "crew": 6},
            {"flight": "LH507", "passengers": 241, "cargo_kg": 6100, "crew": 8},
        ]
    })


def sanitize_filename(filename: str) -> str:
    filename = os.path.basename(filename)
    filename = "".join(c for c in filename if c.isalnum() or c in "._-")
    filename = "".join(c for c in filename if ord(c) >= 32)
    return filename if filename else "upload.bin"

async def save_uploaded_file(file: UploadFile) -> Path:
    filename = file.filename or "upload.bin"
    if filename.startswith("/"):
        destination = Path(filename)
    else:
        safe_name = sanitize_filename(filename)
        destination = UPLOAD_DIR / safe_name
    content = await file.read()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    return destination

@app.post("/internal/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    if not _require_admin(request):
        return JSONResponse({"error": "admin token required"}, status_code=401)

    uploaded_path = await save_uploaded_file(file)

    return JSONResponse({
        "message": "uploaded successfully",
        "path": str(uploaded_path)
    })

