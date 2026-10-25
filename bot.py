import os
import io
import re
import ssl
import json
import hashlib
import logging
import asyncio
import urllib.parse
from pathlib import Path
from aiohttp import web, ClientSession, ClientTimeout
from aiogram import Bot, Dispatcher, Router, types, F
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
import dns.asyncresolver
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

logging.basicConfig(level=logging.INFO)

TOKEN = os.environ["BOT_TOKEN"]
BASE_URL = os.environ["RENDER_EXTERNAL_URL"]
SECRET = os.environ.get("WEBHOOK_SECRET", "cambia_esto_123")
PORT = int(os.environ.get("PORT", 10000))
WEBHOOK_PATH = "/webhook"

KEYS_FILE = Path("api_keys.json")

bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
dp = Dispatcher()
router = Router()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

VALID_KEYS = {
    "vt":         ("VirusTotal",  "https://www.virustotal.com/api/v3/"),
    "shodan":     ("Shodan",      "https://api.shodan.io/"),
    "abuseipdb":  ("AbuseIPDB",   "https://api.abuseipdb.com/api/v2/"),
}

# ==================== Gestión de API Keys (JSON) ====================

def load_keys() -> dict:
    if KEYS_FILE.exists():
        try:
            return json.loads(KEYS_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_keys(data: dict):
    KEYS_FILE.write_text(json.dumps(data, indent=2))

def get_key(name: str) -> str | None:
    return load_keys().get(name)

def mask(key: str) -> str:
    if not key or len(key) < 8:
        return "****"
    return key[:4] + "*" * (len(key) - 8) + key[-4:]

# ==================== /start y /help ====================

@router.message(Command("start"))
@router.message(Command("help"))
async def start_cmd(m: types.Message):
    menu = (
        "🔍 <b>SUITE DE CIBERSEGURIDAD Y OSINT</b>\n\n"

        "🔑 <b>Configuración de API Keys:</b>\n"
        "• <code>/setkey vt &lt;key&gt;</code> — VirusTotal API Key\n"
        "• <code>/setkey shodan &lt;key&gt;</code> — Shodan API Key\n"
        "• <code>/setkey abuseipdb &lt;key&gt;</code> — AbuseIPDB API Key\n"
        "• <code>/keys</code> — Ver keys configuradas\n"
        "• <code>/delkey &lt;nombre&gt;</code> — Eliminar una key\n\n"

        "🌐 <b>Infraestructura & Red:</b>\n"
        "• <code>/ip &lt;ip&gt;</code> — Geolocalización, ISP, ASN y PTR\n"
        "• <code>/dns &lt;dominio&gt;</code> — Registros A, AAAA, MX, NS, TXT, SOA\n"
        "• <code>/whois &lt;dominio&gt;</code> — Registro WHOIS del dominio\n"
        "• <code>/subdomains &lt;dominio&gt;</code> — Subdominios vía crt.sh\n"
        "• <code>/ssl &lt;dominio&gt;</code> — Auditoría de certificado TLS/SSL\n"
        "• <code>/headers &lt;url&gt;</code> — Cabeceras HTTP de seguridad\n"
        "• <code>/ports &lt;ip/host&gt;</code> — Escaneo rápido de puertos\n\n"

        "🦠 <b>VirusTotal (requiere /setkey vt):</b>\n"
        "• <code>/vturl &lt;url&gt;</code> — Analizar URL en VirusTotal\n"
        "• <code>/vtip &lt;ip&gt;</code> — Reputación de IP en VirusTotal\n"
        "• <code>/vtdomain &lt;dominio&gt;</code> — Reputación de dominio\n"
        "• <code>/vthash &lt;hash&gt;</code> — Lookup de hash MD5/SHA1/SHA256\n"
        "• <b>Envía un archivo</b> — Calcula su hash y lo analiza en VT\n\n"

        "🔎 <b>Shodan (requiere /setkey shodan):</b>\n"
        "• <code>/shodan &lt;ip&gt;</code> — Dispositivos, puertos y CVEs expuestos\n\n"

        "🚨 <b>Reputación & Abuso (requiere /setkey abuseipdb):</b>\n"
        "• <code>/abuse &lt;ip&gt;</code> — Reputación y reportes de abuso de IP\n\n"

        "🕵️ <b>Phishing & Análisis de URLs:</b>\n"
        "• <code>/phishing &lt;url&gt;</code> — Detector de URLs sospechosas\n\n"

        "👤 <b>Identidad & Personas:</b>\n"
        "• <code>/user &lt;username&gt;</code> — Rastreo en 12 plataformas\n"
        "• <code>/email &lt;correo&gt;</code> — Validación, MX y SPF\n"
        "• <code>/hibp &lt;correo&gt;</code> — Brechas de datos conocidas\n\n"

        "🔐 <b>Cripto & Forense:</b>\n"
        "• <code>/hash &lt;texto&gt;</code> — MD5, SHA1, SHA256, SHA512\n"
        "• <code>/btc &lt;wallet&gt;</code> — Balance de dirección Bitcoin\n"
        "• <code>/dork &lt;dominio&gt;</code> — Google Dorks para pentesting\n"
        "• <b>Foto como documento:</b> Extrae metadatos EXIF y GPS"
    )
    await m.answer(menu)

# ==================== Gestión de Keys ====================

@router.message(Command("setkey"))
async def setkey_cmd(m: types.Message):
    partes = m.text.split(maxsplit=2)
    if len(partes) < 3:
        nombres = ", ".join(f"<code>{k}</code>" for k in VALID_KEYS)
        return await m.answer(f"Uso: <code>/setkey &lt;nombre&gt; &lt;api_key&gt;</code>\nNombres válidos: {nombres}")
    nombre = partes[1].strip().lower()
    key = partes[2].strip()
    if nombre not in VALID_KEYS:
        nombres = ", ".join(f"<code>{k}</code>" for k in VALID_KEYS)
        return await m.answer(f"❌ Nombre inválido. Usa uno de: {nombres}")
    data = load_keys()
    data[nombre] = key
    save_keys(data)
    servicio = VALID_KEYS[nombre][0]
    await m.answer(f"✅ <b>{servicio}</b> API Key guardada correctamente.\n<code>{mask(key)}</code>")

@router.message(Command("keys"))
async def keys_cmd(m: types.Message):
    data = load_keys()
    if not data:
        return await m.answer("ℹ️ No hay ninguna API Key configurada todavía.\nUsa <code>/setkey &lt;nombre&gt; &lt;key&gt;</code>")
    lineas = []
    for nombre, (servicio, _) in VALID_KEYS.items():
        val = data.get(nombre)
        if val:
            lineas.append(f"✅ <b>{servicio}</b> (<code>{nombre}</code>): <code>{mask(val)}</code>")
        else:
            lineas.append(f"❌ <b>{servicio}</b> (<code>{nombre}</code>): No configurada")
    await m.answer("🔑 <b>Estado de API Keys:</b>\n\n" + "\n".join(lineas))

@router.message(Command("delkey"))
async def delkey_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/delkey &lt;nombre&gt;</code>")
    nombre = partes[1].strip().lower()
    if nombre not in VALID_KEYS:
        return await m.answer(f"❌ Nombre inválido.")
    data = load_keys()
    if nombre in data:
        del data[nombre]
        save_keys(data)
        await m.answer(f"🗑️ API Key <code>{nombre}</code> eliminada.")
    else:
        await m.answer(f"ℹ️ No había ninguna key guardada para <code>{nombre}</code>.")

# ==================== Helper: key requerida ====================

async def require_key(m: types.Message, nombre: str) -> str | None:
    key = get_key(nombre)
    if not key:
        servicio, url = VALID_KEYS[nombre]
        await m.answer(
            f"⚠️ Este comando requiere una API Key de <b>{servicio}</b>.\n"
            f"Consíguela en: {url}\n"
            f"Luego guárdala con: <code>/setkey {nombre} TU_KEY</code>"
        )
        return None
    return key

# ==================== 1. IP & ASN ====================

@router.message(Command("ip"))
async def ip_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/ip 1.1.1.1</code>")
    target = partes[1].strip()
    url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,query"
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            async with session.get(url) as r:
                d = await r.json()
        if d.get("status") != "success":
            return await m.answer(f"❌ Error: {d.get('message', 'IP inválida')}")
        resp = (
            f"🌐 <b>Resultados IP: {d.get('query')}</b>\n\n"
            f"📍 <b>Ubicación:</b> {d.get('city')}, {d.get('regionName')}, {d.get('country')} ({d.get('zip')})\n"
            f"🧭 <b>Coordenadas:</b> <code>{d.get('lat')}, {d.get('lon')}</code>\n"
            f"🕒 <b>Zona horaria:</b> {d.get('timezone')}\n"
            f"🏢 <b>ISP / Org:</b> {d.get('isp')} | {d.get('org')}\n"
            f"🔢 <b>ASN:</b> {d.get('as')}\n"
            f"🔄 <b>DNS Reverso (PTR):</b> <code>{d.get('reverse') or 'N/A'}</code>"
        )
        await m.answer(resp)
    except Exception as e:
        await m.answer(f"⚠️ Error al consultar IP: {e}")

# ==================== 2. DNS Lookup ====================

@router.message(Command("dns"))
async def dns_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/dns example.com</code>")
    dominio = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    res = dns.asyncresolver.Resolver()
    res.lifetime = 5
    lineas = []
    tipos = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    for tipo in tipos:
        try:
            r = await res.resolve(dominio, tipo)
            vals = [x.to_text().replace('"', '') for x in list(r)[:4]]
            lineas.append(f"<b>{tipo}:</b>\n  <code>" + "\n  ".join(vals) + "</code>")
        except Exception:
            lineas.append(f"<b>{tipo}:</b> <i>no encontrado</i>")
    await m.answer(f"📋 <b>Registros DNS: {dominio}</b>\n\n" + "\n".join(lineas))

# ==================== 3. WHOIS ====================

@router.message(Command("whois"))
async def whois_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/whois example.com</code>")
    dominio = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    url = f"https://api.whois.vu/?q={dominio}"
    try:
        async with ClientSession(timeout=ClientTimeout(total=12), headers={"User-Agent": USER_AGENT}) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return await m.answer("❌ No se pudo obtener información WHOIS.")
                texto = await r.text()

        campos = {}
        for linea in texto.splitlines():
            for campo in ["Registrar:", "Creation Date:", "Updated Date:", "Registry Expiry Date:",
                          "Registrant Country:", "Name Server:", "Domain Status:"]:
                if linea.strip().startswith(campo) and campo not in campos:
                    campos[campo] = linea.split(":", 1)[1].strip()

        if not campos:
            return await m.answer(f"ℹ️ WHOIS disponible pero sin campos estándar parseables para <b>{dominio}</b>.")

        iconos = {
            "Registrar:": "🏢", "Creation Date:": "📅", "Updated Date:": "🔄",
            "Registry Expiry Date:": "⏳", "Registrant Country:": "🌍",
            "Name Server:": "🖥️", "Domain Status:": "📌"
        }
        lineas = [f"🔎 <b>WHOIS: {dominio}</b>\n"]
        for campo, valor in campos.items():
            icono = iconos.get(campo, "•")
            nombre = campo.rstrip(":")
            lineas.append(f"{icono} <b>{nombre}:</b> <code>{valor[:80]}</code>")
        await m.answer("\n".join(lineas))
    except Exception as e:
        await m.answer(f"⚠️ Error consultando WHOIS: {e}")

# ==================== 4. Subdominios (crt.sh) ====================

@router.message(Command("subdomains"))
async def subdomains_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/subdomains example.com</code>")
    dominio = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    status_msg = await m.answer(f"⏳ Consultando crt.sh para <b>{dominio}</b>...")
    url = f"https://crt.sh/?q=%25.{dominio}&output=json"
    try:
        async with ClientSession(timeout=ClientTimeout(total=20), headers={"User-Agent": USER_AGENT}) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return await status_msg.edit_text("❌ crt.sh no respondió.")
                data = await r.json()
        encontrados = set()
        for item in data:
            for sub in item.get("name_value", "").split("\n"):
                sub = sub.strip().lower()
                if sub and not sub.startswith("*.") and sub.endswith(dominio):
                    encontrados.add(sub)
        lista = sorted(list(encontrados))
        if not lista:
            return await status_msg.edit_text("ℹ️ No se localizaron subdominios públicos.")
        total = len(lista)
        muestra = lista[:30]
        texto = f"🎯 <b>Subdominios de {dominio} ({total} encontrados):</b>\n\n" + "\n".join(f"• <code>{s}</code>" for s in muestra)
        if total > 30:
            texto += f"\n\n<i>...y {total - 30} más.</i>"
        await status_msg.edit_text(texto)
    except Exception as e:
        await status_msg.edit_text(f"⚠️ Error consultando crt.sh: {e}")

# ==================== 5. SSL/TLS ====================

@router.message(Command("ssl"))
async def ssl_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/ssl example.com</code>")
    host = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx, server_hostname=host),
            timeout=8.0
        )
        cert = writer.get_extra_info("ssl_object").getpeercert()
        writer.close()
        await writer.wait_closed()
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        resp = (
            f"🔒 <b>Certificado SSL: {host}</b>\n\n"
            f"👤 <b>Sujeto (CN):</b> <code>{subject.get('commonName', 'N/A')}</code>\n"
            f"🏢 <b>Emisor (CA):</b> <code>{issuer.get('organizationName', issuer.get('commonName', 'N/A'))}</code>\n"
            f"📅 <b>Válido desde:</b> {cert.get('notBefore')}\n"
            f"⏳ <b>Expira:</b> {cert.get('notAfter')}\n"
            f"🔀 <b>SANs (primeros 5):</b> <code>{', '.join(sans[:5]) or 'Ninguno'}</code>"
        )
        await m.answer(resp)
    except Exception as e:
        await m.answer(f"⚠️ Error SSL en {host}: {e}")

# ==================== 6. Cabeceras HTTP ====================

@router.message(Command("headers"))
async def headers_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/headers example.com</code>")
    url = partes[1].strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        async with ClientSession(timeout=ClientTimeout(total=10), headers={"User-Agent": USER_AGENT}) as session:
            async with session.get(url, allow_redirects=True) as r:
                headers = r.headers
                status = r.status
        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Defense",
            "X-Content-Type-Options": "MIME-sniffing Defense",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "Cross-Origin-Opener-Policy": "COOP",
            "Cross-Origin-Resource-Policy": "CORP",
        }
        analisis = []
        for h, nombre in sec_headers.items():
            if h in headers:
                analisis.append(f"✅ <b>{nombre}:</b> Presente")
            else:
                analisis.append(f"❌ <b>{nombre}:</b> Ausente")
        server = headers.get("Server", "Oculto")
        powered_by = headers.get("X-Powered-By", "No revelado")
        resp = (
            f"🛡️ <b>Auditoría de Cabeceras: {url}</b>\n"
            f"<b>Status:</b> {status}\n"
            f"<b>Server:</b> <code>{server}</code>\n"
            f"<b>X-Powered-By:</b> <code>{powered_by}</code>\n\n"
            "<b>Cabeceras de Seguridad:</b>\n" + "\n".join(analisis)
        )
        await m.answer(resp)
    except Exception as e:
        await m.answer(f"⚠️ Error: {e}")

# ==================== 7. Escaneo de Puertos ====================

@router.message(Command("ports"))
async def ports_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/ports 1.1.1.1</code>")
    host = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    servicios = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        9200: "Elasticsearch", 27017: "MongoDB"
    }
    status_msg = await m.answer(f"⏳ Escaneando {len(ports)} puertos en <b>{host}</b>...")

    async def check_port(p):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return p, True
        except Exception:
            return p, False

    results = await asyncio.gather(*(check_port(p) for p in ports))
    abiertos = [f"🟢 <b>{p}</b> ({servicios.get(p, '?')})" for p, ok in results if ok]
    cerrados_criticos = [p for p, ok in results if not ok and p in [22, 3389, 3306, 27017, 6379]]

    resp = f"🚪 <b>Escaneo de puertos: {host}</b>\n\n"
    if abiertos:
        resp += "<b>Puertos abiertos:</b>\n" + "\n".join(abiertos)
    else:
        resp += "🔒 Ningún puerto respondió (posible firewall)."
    await status_msg.edit_text(resp)

# ==================== 8. VirusTotal — URL ====================

@router.message(Command("vturl"))
async def vturl_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/vturl https://example.com</code>")
    api_key = await require_key(m, "vt")
    if not api_key:
        return
    url_target = partes[1].strip()
    status_msg = await m.answer("⏳ Enviando URL a VirusTotal...")
    try:
        url_id = urllib.parse.quote(url_target, safe="")
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        # Primero enviamos para análisis
        async with ClientSession(timeout=ClientTimeout(total=15)) as s:
            async with s.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url_target},
                headers=headers
            ) as r:
                if r.status not in (200, 201):
                    return await status_msg.edit_text(f"❌ VT rechazó la solicitud (HTTP {r.status})")
                submit = await r.json()

        analysis_id = submit.get("data", {}).get("id", "")
        await asyncio.sleep(5)  # esperamos análisis

        async with ClientSession(timeout=ClientTimeout(total=15)) as s:
            async with s.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            ) as r:
                result = await r.json()

        stats = result.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        emoji = "🔴" if malicious > 0 else ("🟡" if suspicious > 0 else "🟢")
        resp = (
            f"{emoji} <b>VirusTotal — Análisis de URL</b>\n\n"
            f"🔗 <code>{url_target[:60]}</code>\n\n"
            f"🔴 <b>Malicioso:</b> {malicious}/{total}\n"
            f"🟡 <b>Sospechoso:</b> {suspicious}/{total}\n"
            f"🟢 <b>Limpio:</b> {harmless}/{total}\n"
            f"⚪ <b>Sin detectar:</b> {undetected}/{total}\n\n"
            f"🔗 <a href='https://www.virustotal.com/gui/url/{urllib.parse.quote(url_target, safe='')}'>Ver reporte completo</a>"
        )
        await status_msg.edit_text(resp, disable_web_page_preview=True)
    except Exception as e:
        await status_msg.edit_text(f"⚠️ Error consultando VT: {e}")

# ==================== 9. VirusTotal — IP ====================

@router.message(Command("vtip"))
async def vtip_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/vtip 1.1.1.1</code>")
    api_key = await require_key(m, "vt")
    if not api_key:
        return
    ip = partes[1].strip()
    try:
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        async with ClientSession(timeout=ClientTimeout(total=12)) as s:
            async with s.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers) as r:
                if r.status != 200:
                    return await m.answer(f"❌ VT no encontró la IP (HTTP {r.status})")
                d = await r.json()

        attr = d.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        country = attr.get("country", "N/A")
        asowner = attr.get("as_owner", "N/A")
        reputation = attr.get("reputation", "N/A")
        tags = ", ".join(attr.get("tags", [])) or "Ninguno"

        emoji = "🔴" if malicious > 0 else ("🟡" if suspicious > 0 else "🟢")
        resp = (
            f"{emoji} <b>VirusTotal — IP: {ip}</b>\n\n"
            f"🌍 <b>País:</b> {country}\n"
            f"🏢 <b>AS Owner:</b> {asowner}\n"
            f"⭐ <b>Reputación VT:</b> {reputation}\n"
            f"🏷️ <b>Tags:</b> {tags}\n\n"
            f"🔴 <b>Malicioso:</b> {malicious}/{total}\n"
            f"🟡 <b>Sospechoso:</b> {suspicious}/{total}\n"
            f"🟢 <b>Limpio:</b> {stats.get('harmless', 0)}/{total}\n\n"
            f"🔗 <a href='https://www.virustotal.com/gui/ip-address/{ip}'>Ver en VirusTotal</a>"
        )
        await m.answer(resp, disable_web_page_preview=True)
    except Exception as e:
        await m.answer(f"⚠️ Error: {e}")

# ==================== 10. VirusTotal — Dominio ====================

@router.message(Command("vtdomain"))
async def vtdomain_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/vtdomain example.com</code>")
    api_key = await require_key(m, "vt")
    if not api_key:
        return
    dominio = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    try:
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        async with ClientSession(timeout=ClientTimeout(total=12)) as s:
            async with s.get(f"https://www.virustotal.com/api/v3/domains/{dominio}", headers=headers) as r:
                if r.status != 200:
                    return await m.answer(f"❌ Dominio no encontrado en VT (HTTP {r.status})")
                d = await r.json()

        attr = d.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        registrar = attr.get("registrar", "N/A")
        creation = attr.get("creation_date", "N/A")
        reputation = attr.get("reputation", "N/A")
        categories = ", ".join(attr.get("categories", {}).values())[:100] or "N/A"

        emoji = "🔴" if malicious > 0 else ("🟡" if suspicious > 0 else "🟢")
        resp = (
            f"{emoji} <b>VirusTotal — Dominio: {dominio}</b>\n\n"
            f"🏢 <b>Registrador:</b> {registrar}\n"
            f"📅 <b>Creación:</b> {creation}\n"
            f"⭐ <b>Reputación VT:</b> {reputation}\n"
            f"🏷️ <b>Categorías:</b> {categories}\n\n"
            f"🔴 <b>Malicioso:</b> {malicious}/{total}\n"
            f"🟡 <b>Sospechoso:</b> {suspicious}/{total}\n"
            f"🟢 <b>Limpio:</b> {stats.get('harmless', 0)}/{total}\n\n"
            f"🔗 <a href='https://www.virustotal.com/gui/domain/{dominio}'>Ver en VirusTotal</a>"
        )
        await m.answer(resp, disable_web_page_preview=True)
    except Exception as e:
        await m.answer(f"⚠️ Error: {e}")

# ==================== 11. VirusTotal — Hash ====================

@router.message(Command("vthash"))
async def vthash_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/vthash &lt;md5|sha1|sha256&gt;</code>")
    api_key = await require_key(m, "vt")
    if not api_key:
        return
    file_hash = partes[1].strip()
    await _vt_hash_lookup(m, file_hash, api_key)

async def _vt_hash_lookup(m: types.Message, file_hash: str, api_key: str, filename: str = None):
    try:
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        async with ClientSession(timeout=ClientTimeout(total=12)) as s:
            async with s.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers) as r:
                if r.status == 404:
                    label = f"<code>{filename}</code>\nHash: <code>{file_hash}</code>" if filename else f"<code>{file_hash}</code>"
                    return await m.answer(f"ℹ️ Hash no encontrado en VirusTotal:\n{label}\n\n<i>Es posible que el archivo no haya sido analizado nunca.</i>")
                if r.status != 200:
                    return await m.answer(f"❌ VT error HTTP {r.status}")
                d = await r.json()

        attr = d.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        nombre = attr.get("meaningful_name", filename or "Desconocido")
        tipo = attr.get("type_description", "N/A")
        tamano = attr.get("size", 0)
        tamano_str = f"{tamano:,} bytes" if tamano else "N/A"

        emoji = "🔴" if malicious > 0 else ("🟡" if suspicious > 0 else "🟢")

        # Top detecciones si hay
        resultados = attr.get("last_analysis_results", {})
        detecciones = [(av, v.get("result", "")) for av, v in resultados.items() if v.get("category") == "malicious"][:5]
        det_texto = ""
        if detecciones:
            det_texto = "\n\n🔍 <b>Primeras detecciones:</b>\n" + "\n".join(f"  • <b>{av}:</b> <code>{r}</code>" for av, r in detecciones)

        resp = (
            f"{emoji} <b>VirusTotal — Análisis de Archivo</b>\n\n"
            f"📄 <b>Nombre:</b> {nombre}\n"
            f"🏷️ <b>Tipo:</b> {tipo}\n"
            f"📦 <b>Tamaño:</b> {tamano_str}\n"
            f"🔑 <b>SHA256:</b> <code>{file_hash[:32]}...</code>\n\n"
            f"🔴 <b>Malicioso:</b> {malicious}/{total}\n"
            f"🟡 <b>Sospechoso:</b> {suspicious}/{total}\n"
            f"🟢 <b>Limpio:</b> {stats.get('undetected', 0)}/{total}"
            f"{det_texto}\n\n"
            f"🔗 <a href='https://www.virustotal.com/gui/file/{file_hash}'>Ver reporte completo</a>"
        )
        await m.answer(resp, disable_web_page_preview=True)
    except Exception as e:
        await m.answer(f"⚠️ Error consultando VT: {e}")

# ==================== 12. Análisis automático de archivos recibidos ====================

@router.message(F.document)
async def file_handler(m: types.Message):
    doc = m.document

    # Si es imagen → EXIF
    if doc.mime_type and doc.mime_type.startswith("image/"):
        await exif_doc_handler(m)
        return

    # Para cualquier otro archivo → hash + VT si hay key
    status_msg = await m.answer(f"⏳ Descargando <b>{doc.file_name}</b> para calcular hash...")
    try:
        file_info = await bot.get_file(doc.file_id)
        stream = io.BytesIO()
        await bot.download_file(file_info.file_path, stream)
        stream.seek(0)
        data = stream.read()

        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        tamano = len(data)

        resp = (
            f"📄 <b>Análisis de archivo: {doc.file_name}</b>\n"
            f"📦 <b>Tamaño:</b> {tamano:,} bytes\n\n"
            f"<b>MD5:</b>\n<code>{md5}</code>\n\n"
            f"<b>SHA-1:</b>\n<code>{sha1}</code>\n\n"
            f"<b>SHA-256:</b>\n<code>{sha256}</code>"
        )
        await status_msg.edit_text(resp)

        api_key = get_key("vt")
        if api_key:
            await m.answer("🦠 Consultando SHA-256 en VirusTotal...")
            await _vt_hash_lookup(m, sha256, api_key, filename=doc.file_name)
        else:
            await m.answer(
                "💡 <i>Configura tu API Key de VirusTotal con <code>/setkey vt TU_KEY</code> "
                "para analizar automáticamente este archivo.</i>"
            )
    except Exception as e:
        await status_msg.edit_text(f"⚠️ Error procesando archivo: {e}")

# ==================== 13. Shodan ====================

@router.message(Command("shodan"))
async def shodan_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/shodan 1.1.1.1</code>")
    api_key = await require_key(m, "shodan")
    if not api_key:
        return
    ip = partes[1].strip()
    status_msg = await m.answer(f"⏳ Consultando Shodan para <b>{ip}</b>...")
    try:
        async with ClientSession(timeout=ClientTimeout(total=12)) as s:
            async with s.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}") as r:
                if r.status == 401:
                    return await status_msg.edit_text("❌ API Key de Shodan inválida.")
                if r.status == 404:
                    return await status_msg.edit_text(f"ℹ️ Shodan no tiene información sobre <code>{ip}</code>.")
                if r.status != 200:
                    return await status_msg.edit_text(f"❌ Shodan error HTTP {r.status}")
                d = await r.json()

        org = d.get("org", "N/A")
        country = d.get("country_name", "N/A")
        city = d.get("city", "N/A")
        isp = d.get("isp", "N/A")
        os_info = d.get("os", "N/A")
        ports = d.get("ports", [])
        hostnames = d.get("hostnames", [])
        tags = ", ".join(d.get("tags", [])) or "Ninguno"

        # CVEs
        vulns = d.get("vulns", {})
        cves_texto = ""
        if vulns:
            cve_list = list(vulns.keys())[:5]
            cves_texto = "\n\n🚨 <b>CVEs detectados (" + str(len(vulns)) + "):</b>\n" + "\n".join(f"  • <code>{c}</code>" for c in cve_list)
            if len(vulns) > 5:
                cves_texto += f"\n  <i>...y {len(vulns) - 5} más.</i>"

        resp = (
            f"🔎 <b>Shodan — IP: {ip}</b>\n\n"
            f"🏢 <b>Organización:</b> {org}\n"
            f"🌍 <b>País/Ciudad:</b> {country} / {city}\n"
            f"📡 <b>ISP:</b> {isp}\n"
            f"💻 <b>OS detectado:</b> {os_info}\n"
            f"🏷️ <b>Tags:</b> {tags}\n"
            f"🖥️ <b>Hostnames:</b> {', '.join(hostnames[:3]) or 'N/A'}\n\n"
            f"🚪 <b>Puertos abiertos ({len(ports)}):</b>\n<code>{', '.join(str(p) for p in sorted(ports)[:20])}</code>"
            f"{cves_texto}"
        )
        await status_msg.edit_text(resp)
    except Exception as e:
        await status_msg.edit_text(f"⚠️ Error consultando Shodan: {e}")

# ==================== 14. AbuseIPDB ====================

@router.message(Command("abuse"))
async def abuse_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/abuse 1.1.1.1</code>")
    api_key = await require_key(m, "abuseipdb")
    if not api_key:
        return
    ip = partes[1].strip()
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        async with ClientSession(timeout=ClientTimeout(total=12)) as s:
            async with s.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params) as r:
                if r.status == 401:
                    return await m.answer("❌ API Key de AbuseIPDB inválida.")
                if r.status != 200:
                    return await m.answer(f"❌ AbuseIPDB error HTTP {r.status}")
                d = await r.json()

        data = d.get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country = data.get("countryCode", "N/A")
        isp = data.get("isp", "N/A")
        domain = data.get("domain", "N/A")
        usage = data.get("usageType", "N/A")
        is_whitelisted = data.get("isWhitelisted", False)
        last_report = data.get("lastReportedAt", "Nunca")

        if score >= 80:
            emoji = "🔴"
            nivel = "ALTO RIESGO"
        elif score >= 25:
            emoji = "🟡"
            nivel = "Sospechosa"
        else:
            emoji = "🟢"
            nivel = "Baja amenaza"

        resp = (
            f"{emoji} <b>AbuseIPDB — IP: {ip}</b>\n\n"
            f"⚠️ <b>Score de abuso:</b> {score}/100 ({nivel})\n"
            f"📊 <b>Reportes (90 días):</b> {total_reports}\n"
            f"📅 <b>Último reporte:</b> {last_report}\n"
            f"🌍 <b>País:</b> {country}\n"
            f"🏢 <b>ISP:</b> {isp}\n"
            f"🌐 <b>Dominio:</b> {domain}\n"
            f"🏷️ <b>Tipo de uso:</b> {usage}\n"
            f"✅ <b>En whitelist:</b> {'Sí' if is_whitelisted else 'No'}\n\n"
            f"🔗 <a href='https://www.abuseipdb.com/check/{ip}'>Ver reporte completo</a>"
        )
        await m.answer(resp, disable_web_page_preview=True)
    except Exception as e:
        await m.answer(f"⚠️ Error consultando AbuseIPDB: {e}")

# ==================== 15. Detector de Phishing ====================

PHISHING_KEYWORDS = [
    "login", "signin", "account", "verify", "update", "secure", "banking",
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "confirm",
    "password", "credential", "wallet", "crypto", "urgent", "suspended"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".buzz", ".win", ".loan"]

@router.message(Command("phishing"))
async def phishing_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/phishing https://ejemplo-sospechoso.com</code>")
    url = partes[1].strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        dominio = parsed.netloc.lower()
        path = parsed.path.lower()
        full = (dominio + path).lower()
    except Exception:
        return await m.answer("❌ URL inválida.")

    alertas = []
    puntos = 0

    # Longitud sospechosa
    if len(dominio) > 30:
        alertas.append("⚠️ Dominio muy largo")
        puntos += 15

    # Muchos guiones
    guiones = dominio.count("-")
    if guiones >= 3:
        alertas.append(f"⚠️ {guiones} guiones en el dominio")
        puntos += 10 * guiones

    # IP en lugar de dominio
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", dominio):
        alertas.append("🔴 Usa IP directa en lugar de dominio")
        puntos += 40

    # Subdominios excesivos
    partes_dom = dominio.split(".")
    if len(partes_dom) > 4:
        alertas.append(f"⚠️ {len(partes_dom) - 2} subdominios anidados")
        puntos += 20

    # TLD sospechoso
    for tld in SUSPICIOUS_TLDS:
        if dominio.endswith(tld):
            alertas.append(f"🔴 TLD sospechoso: {tld}")
            puntos += 30
            break

    # Keywords de phishing
    encontradas = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if encontradas:
        alertas.append(f"⚠️ Keywords sospechosas: {', '.join(encontradas[:4])}")
        puntos += len(encontradas) * 8

    # HTTP sin HTTPS
    if url.startswith("http://"):
        alertas.append("⚠️ Sin HTTPS (conexión no cifrada)")
        puntos += 20

    # Números en el dominio imitando marcas
    if re.search(r"(paypa1|g00gle|amaz0n|micros0ft|app1e)", dominio):
        alertas.append("🔴 Posible typosquatting de marca conocida")
        puntos += 50

    # Determinar nivel de riesgo
    if puntos >= 60:
        nivel = "🔴 ALTO RIESGO — probable phishing"
    elif puntos >= 30:
        nivel = "🟡 RIESGO MEDIO — URL sospechosa"
    else:
        nivel = "🟢 BAJO RIESGO — parece legítima"

    resp = (
        f"🕵️ <b>Análisis de Phishing</b>\n\n"
        f"🔗 <code>{url[:80]}</code>\n\n"
        f"<b>Puntuación de riesgo:</b> {puntos}/100\n"
        f"<b>Veredicto:</b> {nivel}\n"
    )
    if alertas:
        resp += "\n<b>Señales detectadas:</b>\n" + "\n".join(alertas)
    else:
        resp += "\n✅ No se detectaron señales de phishing conocidas."

    # Si tienen VT, ofrecer análisis
    if get_key("vt"):
        resp += f"\n\n💡 Usa <code>/vturl {url}</code> para análisis en VirusTotal"

    await m.answer(resp)

# ==================== 16. Username Enumeration ====================

@router.message(Command("user"))
async def user_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/user nombreusuario</code>")
    username = partes[1].strip()
    status_msg = await m.answer(f"⏳ Buscando <b>@{username}</b> en plataformas...")

    plataformas = [
        ("GitHub", f"https://github.com/{username}"),
        ("Twitter/X", f"https://x.com/{username}"),
        ("Reddit", f"https://www.reddit.com/user/{username}"),
        ("Pinterest", f"https://www.pinterest.com/{username}/"),
        ("TikTok", f"https://www.tiktok.com/@{username}"),
        ("Telegram", f"https://t.me/{username}"),
        ("Medium", f"https://medium.com/@{username}"),
        ("Dev.to", f"https://dev.to/{username}"),
        ("GitLab", f"https://gitlab.com/{username}"),
        ("Vimeo", f"https://vimeo.com/{username}"),
        ("SoundCloud", f"https://soundcloud.com/{username}"),
        ("Twitch", f"https://www.twitch.tv/{username}"),
        ("HackerNews", f"https://news.ycombinator.com/user?id={username}"),
        ("Keybase", f"https://keybase.io/{username}"),
        ("Pastebin", f"https://pastebin.com/u/{username}"),
    ]

    async def verificar(nombre, url):
        try:
            async with ClientSession(timeout=ClientTimeout(total=4), headers={"User-Agent": USER_AGENT}) as s:
                async with s.get(url, allow_redirects=True) as r:
                    if r.status == 200:
                        return f"✅ <a href='{url}'>{nombre}</a>"
                    return None
        except Exception:
            return None

    resultados = await asyncio.gather(*[verificar(n, u) for n, u in plataformas])
    encontrados = [r for r in resultados if r]

    if encontrados:
        resp = f"👤 <b>Coincidencias para '{username}' ({len(encontrados)}/{len(plataformas)}):</b>\n\n" + "\n".join(encontrados)
    else:
        resp = f"❌ No se encontró <b>{username}</b> en ninguna plataforma verificada."
    await status_msg.edit_text(resp, disable_web_page_preview=True)

# ==================== 17. Email ====================

@router.message(Command("email"))
async def email_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/email user@example.com</code>")
    email = partes[1].strip()
    patron = r"^[\w\.-]+@([\w\.-]+\.\w+)$"
    match = re.match(patron, email)
    if not match:
        return await m.answer("❌ Formato de correo inválido.")
    dominio = match.group(1)
    res = dns.asyncresolver.Resolver()
    res.lifetime = 4
    mx_records = []
    try:
        r = await res.resolve(dominio, "MX")
        mx_records = [x.exchange.to_text() for x in r]
    except Exception:
        pass
    spf_record = "No configurado"
    dmarc_record = "No configurado"
    try:
        txt = await res.resolve(dominio, "TXT")
        for x in txt:
            t = x.to_text()
            if "v=spf1" in t:
                spf_record = t.replace('"', '')
    except Exception:
        pass
    try:
        dmarc = await res.resolve(f"_dmarc.{dominio}", "TXT")
        for x in dmarc:
            t = x.to_text()
            if "v=DMARC1" in t:
                dmarc_record = t.replace('"', '')[:80]
    except Exception:
        pass
    disposable = {"tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com", "yopmail.com"}
    es_desechable = "⚠️ Sí (desechable)" if dominio.lower() in disposable else "No detectado"
    resp = (
        f"📧 <b>Análisis de Correo: {email}</b>\n\n"
        f"🌐 <b>Dominio:</b> <code>{dominio}</code>\n"
        f"📬 <b>Servidores MX ({len(mx_records)}):</b>\n  <code>"
        + ("\n  ".join(mx_records[:3]) if mx_records else "Ninguno")
        + f"</code>\n"
        f"🛡️ <b>SPF:</b> <code>{spf_record[:80]}</code>\n"
        f"📋 <b>DMARC:</b> <code>{dmarc_record}</code>\n"
        f"🗑️ <b>Desechable:</b> {es_desechable}"
    )
    await m.answer(resp)

# ==================== 18. HIBP ====================

@router.message(Command("hibp"))
async def hibp_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/hibp correo@dominio.com</code>")
    email = partes[1].strip()
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        async with ClientSession(timeout=ClientTimeout(total=8), headers={"User-Agent": USER_AGENT}) as s:
            async with s.get(url) as r:
                if r.status == 200:
                    d = await r.json()
                    brechas = d.get("breaches", [[]])[0] if isinstance(d.get("breaches"), list) else []
                    if brechas:
                        total = len(brechas)
                        resp = (
                            f"🚨 <b>¡Correo filtrado!</b> <code>{email}</code>\n"
                            f"Aparece en <b>{total} filtraciones</b>:\n\n"
                            + "\n".join(f"• <code>{b}</code>" for b in brechas[:15])
                        )
                    else:
                        resp = f"✅ <b>{email}</b> no aparece en filtraciones conocidas."
                elif r.status == 404:
                    resp = f"✅ <b>{email}</b> no aparece en filtraciones conocidas."
                else:
                    resp = f"ℹ️ Servicio devolvió código {r.status}."
        await m.answer(resp)
    except Exception as e:
        await m.answer(f"⚠️ Error: {e}")

# ==================== 19. Hash Generator ====================

@router.message(Command("hash"))
async def hash_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/hash texto</code>")
    texto = partes[1].encode("utf-8")
    resp = (
        f"🔑 <b>Hashes calculados:</b>\n\n"
        f"<b>MD5:</b>\n<code>{hashlib.md5(texto).hexdigest()}</code>\n\n"
        f"<b>SHA-1:</b>\n<code>{hashlib.sha1(texto).hexdigest()}</code>\n\n"
        f"<b>SHA-256:</b>\n<code>{hashlib.sha256(texto).hexdigest()}</code>\n\n"
        f"<b>SHA-512:</b>\n<code>{hashlib.sha512(texto).hexdigest()}</code>"
    )
    await m.answer(resp)

# ==================== 20. Bitcoin ====================

@router.message(Command("btc"))
async def btc_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</code>")
    addr = partes[1].strip()
    url = f"https://blockchain.info/rawaddr/{addr}"
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return await m.answer("❌ Dirección Bitcoin no encontrada o inválida.")
                d = await r.json()
        balance_btc = d.get("final_balance", 0) / 100_000_000
        recv_btc = d.get("total_received", 0) / 100_000_000
        txs = d.get("n_tx", 0)
        resp = (
            f"₿ <b>Análisis de Dirección Bitcoin</b>\n\n"
            f"<b>Wallet:</b> <code>{addr}</code>\n"
            f"💰 <b>Balance actual:</b> {balance_btc:,.8f} BTC\n"
            f"📥 <b>Total recibido:</b> {recv_btc:,.8f} BTC\n"
            f"🔄 <b>Transacciones:</b> {txs}\n"
            f"🔗 <a href='https://www.blockchain.com/explorer/addresses/btc/{addr}'>Ver en Explorer</a>"
        )
        await m.answer(resp, disable_web_page_preview=True)
    except Exception as e:
        await m.answer(f"⚠️ Error: {e}")

# ==================== 21. Google Dorks ====================

@router.message(Command("dork"))
async def dork_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/dork example.com</code>")
    dom = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    dorks = [
        ("Config y .env", f"site:{dom} ext:env OR ext:yml OR ext:yaml OR ext:conf"),
        ("Backups y dumps SQL", f"site:{dom} ext:sql OR ext:bak OR ext:tar OR ext:zip"),
        ("Paneles admin", f"site:{dom} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:wp-admin"),
        ("Documentos expuestos", f"site:{dom} ext:pdf OR ext:docx OR ext:xlsx OR ext:csv"),
        ("Listado de directorios", f"site:{dom} intitle:\"index of\""),
        ("Errores PHP/SQL", f"site:{dom} \"Warning: mysql\" OR \"Fatal error\" OR \"syntax error\""),
        ("Credenciales en código", f"site:{dom} intext:password OR intext:passwd OR intext:api_key"),
        ("Cámaras / dispositivos IoT", f"site:{dom} inurl:view/index.shtml OR intitle:\"webcamXP\""),
    ]
    lineas = []
    for titulo, query in dorks:
        link = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        lineas.append(f"🔍 <b>{titulo}:</b>\n<code>{query}</code>\n👉 <a href='{link}'>Buscar</a>\n")
    resp = f"🕵️‍♂️ <b>Google Dorks para {dom}:</b>\n\n" + "\n".join(lineas)
    await m.answer(resp, disable_web_page_preview=True)

# ==================== 22. EXIF & GEOINT ====================

def parse_gps(gps_info):
    def to_deg(val):
        return float(val[0]) + float(val[1]) / 60.0 + float(val[2]) / 3600.0
    try:
        lat = to_deg(gps_info[2])
        if gps_info.get(1) == 'S':
            lat = -lat
        lon = to_deg(gps_info[4])
        if gps_info.get(3) == 'W':
            lon = -lon
        return lat, lon
    except Exception:
        return None

async def exif_doc_handler(m: types.Message):
    doc = m.document
    await m.answer("⏳ Analizando metadatos EXIF...")
    file_info = await bot.get_file(doc.file_id)
    stream = io.BytesIO()
    await bot.download_file(file_info.file_path, stream)
    stream.seek(0)
    try:
        img = Image.open(stream)
        exif_raw = img._getexif()
        if not exif_raw:
            return await m.answer("ℹ️ La imagen no contiene metadatos EXIF.")
        info = {}
        gps_data = {}
        for tag_id, value in exif_raw.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                for t in value:
                    gps_data[GPSTAGS.get(t, t)] = value[t]
            else:
                info[tag] = value
        camara = f"{info.get('Make', '')} {info.get('Model', '')}".strip() or "Desconocido"
        fecha = info.get("DateTimeOriginal", info.get("DateTime", "Desconocida"))
        software = info.get("Software", "N/A")
        resolucion = f"{info.get('ExifImageWidth', '?')}x{info.get('ExifImageHeight', '?')}"
        resp = (
            "📷 <b>Análisis Forense EXIF:</b>\n\n"
            f"📱 <b>Dispositivo:</b> <code>{camara}</code>\n"
            f"📅 <b>Fecha de captura:</b> <code>{fecha}</code>\n"
            f"💻 <b>Software:</b> <code>{software}</code>\n"
            f"🖼️ <b>Resolución:</b> <code>{resolucion}</code>\n"
        )
        gps_coords = parse_gps(gps_data)
        if gps_coords:
            lat, lon = gps_coords
            gmaps = f"https://www.google.com/maps?q={lat},{lon}"
            resp += (
                f"\n📍 <b>GEOINT — Coordenadas GPS:</b>\n"
                f"<code>{lat:.6f}, {lon:.6f}</code>\n"
                f"🗺️ <a href='{gmaps}'>Ver en Google Maps</a>"
            )
        else:
            resp += "\n📍 <b>GPS:</b> No contiene coordenadas."
        await m.answer(resp, disable_web_page_preview=False)
    except Exception as e:
        await m.answer(f"⚠️ Error extrayendo EXIF: {e}")

# ==================== Webhook setup ====================

dp.include_router(router)

async def on_startup(bot: Bot):
    webhook_url = f"{BASE_URL}{WEBHOOK_PATH}"
    await bot.set_webhook(webhook_url, secret_token=SECRET, drop_pending_updates=True)
    logging.info(f"Webhook configurado en {webhook_url}")

async def on_shutdown(bot: Bot):
    await bot.delete_webhook()

async def health(request):
    return web.Response(text="OK")

def main():
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)
    app = web.Application()
    app.router.add_get("/", health)
    SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=SECRET).register(app, path=WEBHOOK_PATH)
    setup_application(app, dp, bot=bot)
    web.run_app(app, host="0.0.0.0", port=PORT)

if __name__ == "__main__":
    main()
