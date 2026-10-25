import os
import io
import re
import ssl
import hashlib
import logging
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

bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
dp = Dispatcher()
router = Router()

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ==================== /start y /help ====================
@router.message(Command("start"))
@router.message(Command("help"))
async def start_cmd(m: types.Message):
    menu = (
        "🔍 <b>SUITE DE CIBERSEGURIDAD Y OSINT</b>\n\n"
        "🌐 <b>Infraestructura & Red:</b>\n"
        "• <code>/ip &lt;ip&gt;</code> — Geolocalización, ISP, ASN y PTR\n"
        "• <code>/dns &lt;dominio&gt;</code> — Registros A, AAAA, MX, NS, TXT, SOA\n"
        "• <code>/subdomains &lt;dominio&gt;</code> — Subdominios vía crt.sh (certificados)\n"
        "• <code>/ssl &lt;dominio&gt;</code> — Auditoría de certificado TLS/SSL y emisor\n"
        "• <code>/headers &lt;url&gt;</code> — Análisis de cabeceras HTTP de seguridad\n"
        "• <code>/ports &lt;ip/host&gt;</code> — Escaneo rápido de puertos comunes\n\n"
        "👤 <b>Identidad & Personas:</b>\n"
        "• <code>/user &lt;username&gt;</code> — Rastreo en 12 plataformas populares\n"
        "• <code>/email &lt;correo&gt;</code> — Formato, dominio, registros MX y SPF\n"
        "• <code>/hibp &lt;correo&gt;</code> — Comprobación de brechas (HIBP público)\n\n"
        "🔐 <b>Cripto & Forense:</b>\n"
        "• <code>/hash &lt;texto&gt;</code> — Generación MD5, SHA1, SHA256, SHA512\n"
        "• <code>/btc &lt;wallet&gt;</code> — Balance y transacciones de dirección Bitcoin\n"
        "• <code>/dork &lt;dominio&gt;</code> — Generador de Google Dorks para pentesting\n"
        "• <b>Foto con EXIF:</b> Envía cualquier foto como <u>documento</u> (sin comprimir) para extraer metadatos y coordenadas GPS"
    )
    await m.answer(menu)

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
            lineas.append(f"<b>{tipo}:</b>\n  <code>" + "\n  ".join(vals) + "<​/code>")
        except Exception:
            lineas.append(f"<b>{tipo}:</b> <i>no encontrado</i>")
    await m.answer(f"📋 <b>Registros DNS: {dominio}</b>\n\n" + "\n".join(lineas))

# ==================== 3. Subdominios (crt.sh) ====================
@router.message(Command("subdomains"))
async def subdomains_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/subdomains example.com</code>")
    dominio = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    status_msg = await m.answer(f"⏳ Consultando certificados de transparencia (crt.sh) para <b>{dominio}</b>...")
    url = f"https://crt.sh/?q=%25.{dominio}&output=json"
    try:
        async with ClientSession(timeout=ClientTimeout(total=20), headers={"User-Agent": USER_AGENT}) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return await status_msg.edit_text("❌ crt.sh no respondió con éxito.")
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

# ==================== 4. Auditoría SSL/TLS ====================
@router.message(Command("ssl"))
async def ssl_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/ssl example.com</code>")
    host = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    ctx = ssl.create_default_context()
    try:
        import asyncio
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
        await m.answer(f"⚠️ Error conectando por SSL a {host}: {e}")

# ==================== 5. Cabeceras HTTP de Seguridad ====================
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
            "Permissions-Policy": "Permissions-Policy"
        }
        analisis = []
        for h, nombre in sec_headers.items():
            if h in headers:
                analisis.append(f"✅ <b>{nombre}:</b> Presente")
            else:
                analisis.append(f"❌ <b>{nombre}:</b> Ausente")

        server = headers.get("Server", "Oculto / No revelado")
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
        await m.answer(f"⚠️ Error al conectar: {e}")

# ==================== 6. Escaneo Rápido de Puertos ====================
@router.message(Command("ports"))
async def ports_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/ports 1.1.1.1</code> o <code>/ports example.com</code>")
    host = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]
    servicios = {
        21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }

    import asyncio
    status_msg = await m.answer(f"⏳ Escaneando puertos comunes en <b>{host}</b>...")

    async def check_port(p):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return p, True
        except Exception:
            return p, False

    results = await asyncio.gather(*(check_port(p) for p in ports))
    abiertos = [f"🟢 <b>{p}</b> ({servicios.get(p, 'Desconocido')})" for p, ok in results if ok]

    if abiertos:
        resp = f"🚪 <b>Puertos abiertos en {host}:</b>\n\n" + "\n".join(abiertos)
    else:
        resp = f"🔒 Ninguno de los 12 puertos comunes respondió como abierto en <b>{host}</b> (posible firewall o filtrado)."
    await status_msg.edit_text(resp)

# ==================== 7. Username Enumeration ====================
@router.message(Command("user"))
async def user_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/user nombreusuario</code>")
    username = partes[1].strip()
    status_msg = await m.answer(f"⏳ Buscando <b>@{username}</b> en 12 plataformas...")

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
        ("Twitch", f"https://www.twitch.org/{username}")
    ]

    import asyncio
    async def verificar(nombre, url):
        try:
            async with ClientSession(timeout=ClientTimeout(total=4), headers={"User-Agent": USER_AGENT}) as s:
                async with s.get(url, allow_redirects=True) as r:
                    if r.status == 200:
                        return f"✅ <a href='{url}'>{nombre}</a>"
                    return None
        except Exception:
            return None

    tareas = [verificar(nombre, url) for nombre, url in plataformas]
    resultados = await asyncio.gather(*tareas)
    encontrados = [r for r in resultados if r]

    if encontrados:
        resp = f"👤 <b>Coincidencias para '{username}':</b>\n\n" + "\n".join(encontrados)
    else:
        resp = f"❌ No se encontró el perfil de <b>{username}</b> en las plataformas verificadas."
    await status_msg.edit_text(resp, disable_web_page_preview=True)

# ==================== 8. Email Validator & MX ====================
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
    try:
        txt_records = await res.resolve(dominio, "TXT")
        for x in txt_records:
            t = x.to_text()
            if "v=spf1" in t:
                spf_record = t.replace('"', '')
                break
    except Exception:
        pass

    disposable_domains = {"tempmail.com", "guerrillamail.com", "10minutemail.com", "mailinator.com", "yopmail.com"}
    es_desechable = "⚠️ Sí (desechable)" if dominio.lower() in disposable_domains else "No detectado como desechable"

    resp = (
        f"📧 <b>Análisis de Correo: {email}</b>\n\n"
        f"🌐 <b>Dominio:</b> <code>{dominio}</code>\n"
        f"📬 <b>Servidores MX ({len(mx_records)}):</b>\n  <code>" +
        ("\n  ".join(mx_records[:3]) if mx_records else "Ninguno (no puede recibir correo)") +
        f"</code>\n🛡️ <b>Registro SPF:</b> <code>{spf_record}</code>\n"
        f"🗑️ <b>Proveedor temporal:</b> {es_desechable}"
    )
    await m.answer(resp)

# ==================== 9. Brechas HIBP ====================
@router.message(Command("hibp"))
async def hibp_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/hibp correo@dominio.com</code>")
    email = partes[1].strip()
    url = f"https://leak-lookup.com/api/search"  # API alternativa abierta o endpoint libre
    # Empleamos el servicio público de HaveIBeenPwned con header adecuado si está disponible
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        async with ClientSession(timeout=ClientTimeout(total=8), headers={"User-Agent": USER_AGENT}) as s:
            async with s.get(url) as r:
                if r.status == 200:
                    d = await r.json()
                    brechas = d.get("breaches", [[]])[0] if isinstance(d.get("breaches"), list) else []
                    if brechas:
                        total = len(brechas)
                        muestra = brechas[:15]
                        resp = (
                            f"🚨 <b>¡ALERTA! Correo filtrado:</b> <code>{email}</code>\n"
                            f"Aparece en <b>{total} filtraciones</b> conocidas:\n\n" +
                            "\n".join(f"• <code>{b}</code>" for b in muestra)
                        )
                    else:
                        resp = f"✅ <b>{email}</b> no aparece en la base de datos de filtraciones analizada."
                elif r.status == 404:
                    resp = f"✅ <b>{email}</b> no aparece en filtraciones conocidas."
                else:
                    resp = f"ℹ️ Servicio de filtraciones devolvió código {r.status}."
        await m.answer(resp)
    except Exception as e:
        await m.answer(f"⚠️ Error al consultar filtraciones: {e}")

# ==================== 10. Hash Generator ====================
@router.message(Command("hash"))
async def hash_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/hash texto_a_hashear</code>")
    texto = partes[1].encode("utf-8")
    resp = (
        f"🔑 <b>Hashes calculados:</b>\n\n"
        f"<b>MD5:</b>\n<code>{hashlib.md5(texto).hexdigest()}</code>\n\n"
        f"<b>SHA-1:</b>\n<code>{hashlib.sha1(texto).hexdigest()}</code>\n\n"
        f"<b>SHA-256:</b>\n<code>{hashlib.sha256(texto).hexdigest()}</code>\n\n"
        f"<b>SHA-512:</b>\n<code>{hashlib.sha512(texto).hexdigest()}</code>"
    )
    await m.answer(resp)

# ==================== 11. Bitcoin Wallet OSINT ====================
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
        satoshis_balance = d.get("final_balance", 0)
        satoshis_recv = d.get("total_received", 0)
        balance_btc = satoshis_balance / 100_000_000
        recv_btc = satoshis_recv / 100_000_000
        txs = d.get("n_tx", 0)
        resp = (
            f"₿ <b>Análisis de Dirección Bitcoin</b>\n\n"
            f"<b>Wallet:</b> <code>{addr}</code>\n"
            f"💰 <b>Balance actual:</b> {balance_btc:,.8f} BTC\n"
            f"📥 <b>Total recibido:</b> {recv_btc:,.8f} BTC\n"
            f"🔄 <b>Transacciones totales:</b> {txs}\n"
            f"🔗 <a href='https://www.blockchain.com/explorer/addresses/btc/{addr}'>Ver en Blockchain Explorer</a>"
        )
        await m.answer(resp, disable_web_page_preview=True)
    except Exception as e:
        await m.answer(f"⚠️ Error consultando la blockchain: {e}")

# ==================== 12. Google Dorks Generator ====================
@router.message(Command("dork"))
async def dork_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: <code>/dork example.com</code>")
    dom = partes[1].strip().replace("http://", "").replace("https://", "").split("/")[0]
    import urllib.parse
    dorks = [
        ("Ficheros de configuración y .env", f"site:{dom} ext:env OR ext:yml OR ext:yaml OR ext:conf"),
        ("Backups y dumps SQL", f"site:{dom} ext:sql OR ext:bak OR ext:tar OR ext:zip"),
        ("Paneles de administración", f"site:{dom} inurl:admin OR inurl:login OR inurl:dashboard"),
        ("Documentos expuestos", f"site:{dom} ext:pdf OR ext:docx OR ext:xlsx OR ext:csv"),
        ("Listado de directorios", f"site:{dom} intitle:\"index of\"")
    ]
    lineas = []
    for titulo, query in dorks:
        link = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        lineas.append(f"🔍 <b>{titulo}:</b>\n<code>{query}</code>\n👉 <a href='{link}'>Buscar en Google</a>\n")
    resp = f"🕵️‍♂️ <b>Google Dorks para {dom}:</b>\n\n" + "\n".join(lineas)
    await m.answer(resp, disable_web_page_preview=True)

# ==================== 13. Forense EXIF & GEOINT ====================
def parse_gps(gps_info):
    def to_deg(val):
        d = float(val[0])
        m = float(val[1])
        s = float(val[2])
        return d + (m / 60.0) + (s / 3600.0)
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

@router.message(F.document)
async def exif_doc(m: types.Message):
    doc = m.document
    if not (doc.mime_type and doc.mime_type.startswith("image/")):
        return
    await m.answer("⏳ Descargando imagen sin comprimir para análisis EXIF...")
    file_info = await bot.get_file(doc.file_id)
    stream = io.BytesIO()
    await bot.download_file(file_info.file_path, stream)
    stream.seek(0)

    try:
        img = Image.open(stream)
        exif_raw = img._getexif()
        if not exif_raw:
            return await m.answer("ℹ️ La imagen no contiene metadatos EXIF (fueron eliminados o no se grabaron).")
        
        info = {}
        gps_data = {}
        for tag_id, value in exif_raw.items():
            tag = TAGS.get(tag_id, tag_id)
            if tag == "GPSInfo":
                for t in value:
                    sub_tag = GPSTAGS.get(t, t)
                    gps_data[sub_tag] = value[t]
            else:
                info[tag] = value

        camara = f"{info.get('Make', '')} {info.get('Model', '')}".strip() or "Desconocido"
        fecha = info.get("DateTimeOriginal", info.get("DateTime", "Desconocida"))
        software = info.get("Software", "N/A")

        resp = (
            "📷 <b>Análisis Forense de Imagen:</b>\n\n"
            f"📱 <b>Dispositivo:</b> <code>{camara}</code>\n"
            f"📅 <b>Fecha de captura:</b> <code>{fecha}</code>\n"
            f"💻 <b>Software/Editor:</b> <code>{software}</code>\n"
        )

        gps_coords = parse_gps(gps_data)
        if gps_coords:
            lat, lon = gps_coords
            gmaps = f"https://www.google.com/maps?q={lat},{lon}"
            resp += (
                f"\n📍 <b>GEOINT / Coordenadas GPS:</b>\n"
                f"<code>{lat:.6f}, {lon:.6f}</code>\n"
                f"🗺️ <a href='{gmaps}'>Ver ubicación en Google Maps</a>"
            )
        else:
            resp += "\n📍 <b>GPS:</b> No contiene coordenadas geográficas."

        await m.answer(resp, disable_web_page_preview=False)
    except Exception as e:
        await m.answer(f"⚠️ Error extrayendo EXIF: {e}")

# ==================== Configuración del Webhook ====================
dp.include_router(router)

async def on_startup(bot: Bot):
    webhook_url = f"{BASE_URL}{WEBHOOK_PATH}"
    await bot.set_webhook(
        webhook_url,
        secret_token=SECRET,
        drop_pending_updates=True
    )
    logging.info(f"Webhook configurado en {webhook_url}")

async def on_shutdown(bot: Bot):
    await bot.delete_webhook()

def main():
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)
    app = web.Application()
    webhook_requests_handler = SimpleRequestHandler(
        dispatcher=dp,
        bot=bot,
        secret_token=SECRET,
    )
    webhook_requests_handler.register(app, path=WEBHOOK_PATH)
    setup_application(app, dp, bot=bot)
    web.run_app(app, host="0.0.0.0", port=PORT)

if __name__ == "__main__":
    main()
