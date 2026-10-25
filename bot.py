import os
import logging
from aiohttp import web, ClientSession, ClientTimeout
from aiogram import Bot, Dispatcher, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
import dns.asyncresolver

logging.basicConfig(level=logging.INFO)

TOKEN = os.environ["BOT_TOKEN"]
BASE_URL = os.environ["RENDER_EXTERNAL_URL"]   # Render la crea automáticamente
SECRET = os.environ.get("WEBHOOK_SECRET", "cambia_esto_123")
PORT = int(os.environ.get("PORT", 10000))
WEBHOOK_PATH = "/webhook"

bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode="HTML"))
dp = Dispatcher()
router = Router()

@router.message(Command("start"))
async def start(m: types.Message):
    await m.answer(
        "🤖 <b>Bot OSINT</b>\n\n"
        "/ip &lt;ip&gt; - Info de una IP\n"
        "/dns &lt;dominio&gt; - Registros DNS"
    )

@router.message(Command("ip"))
async def ip(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: /ip 8.8.8.8")
    url = f"http://ip-api.com/json/{partes[1].strip()}?fields=status,message,country,city,isp,org,as,query"
    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as s:
            async with s.get(url) as r:
                d = await r.json()
        if d.get("status") != "success":
            return await m.answer(f"❌ {d.get('message', 'Error')}")
        await m.answer(
            f"🌐 <b>{d['query']}</b>\n"
            f"País: {d.get('country')}\nCiudad: {d.get('city')}\n"
            f"ISP: {d.get('isp')}\nOrg: {d.get('org')}\nAS: {d.get('as')}"
        )
    except Exception as e:
        await m.answer(f"⚠️ Error: {e}")

@router.message(Command("dns"))
async def dns_cmd(m: types.Message):
    partes = m.text.split(maxsplit=1)
    if len(partes) < 2:
        return await m.answer("Uso: /dns ejemplo.com")
    dominio = partes[1].strip()
    res = dns.asyncresolver.Resolver()
    res.lifetime = 5
    lineas = []
    for tipo in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            r = await res.resolve(dominio, tipo)
            lineas.append(f"<b>{tipo}:</b> " + ", ".join(x.to_text() for x in list(r)[:3]))
        except Exception:
            lineas.append(f"<b>{tipo}:</b> —")
    await m.answer(f"📋 <b>{dominio}</b>\n\n" + "\n".join(lineas))

dp.include_router(router)

async def on_startup(bot: Bot):
    await bot.set_webhook(f"{BASE_URL}{WEBHOOK_PATH}", secret_token=SECRET)

async def health(request):
    return web.Response(text="OK")

def main():
    dp.startup.register(on_startup)
    app = web.Application()
    app.router.add_get("/", health)
    SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=SECRET).register(app, path=WEBHOOK_PATH)
    setup_application(app, dp, bot=bot)
    web.run_app(app, host="0.0.0.0", port=PORT)

if __name__ == "__main__":
    main()
  
