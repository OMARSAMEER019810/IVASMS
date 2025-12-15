#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IVASMS -> Telegram forwarder using cookies provided via ENV (preferred) or cookies.txt fallback.
Supports:
 - COOKIES_NT   : Netscape cookies.txt content (multiline string)
 - COOKIES_JSON : Playwright storage_state JSON (string) OR JSON array of cookies
If both are empty, falls back to loading cookies.txt file if present.
"""
import os
import re
import json
import time
import asyncio
import traceback
from io import BytesIO
from hashlib import sha1
from datetime import datetime, timedelta
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

import cloudscraper
from pymongo import MongoClient
from pymongo.errors import PyMongoError

# ----------------------------
# Configuration (ENV)
# ----------------------------
YOUR_BOT_TOKEN = os.getenv("YOUR_BOT_TOKEN")  # Telegram bot token
CHAT_IDS_FILE = os.getenv("CHAT_IDS_FILE", "chat_ids.json")
INITIAL_CHAT_IDS = ["-1003073839183", "-1002907713631"]
ADMIN_CHAT_IDS = [s.strip() for s in os.getenv("ADMIN_CHAT_IDS", "").split(",") if s.strip()]

# Cookie input options (choose one)
COOKIES_NT = os.getenv("COOKIES_NT", "").strip()       # Netscape cookies.txt content (multiline)
COOKIES_JSON = os.getenv("COOKIES_JSON", "").strip()   # Playwright storage_state JSON or cookies array
COOKIES_FILE = os.getenv("COOKIES_FILE", "cookies.txt")  # fallback file path if env not provided

# IVASMS endpoints
LOGIN_CHECK_URL = "https://www.ivasms.com/"
LOGIN_URL = "https://www.ivasms.com/login"
BASE_URL = "https://www.ivasms.com/"
SMS_API_ENDPOINT = "https://www.ivasms.com/portal/sms/received/getsms"

# Polling interval
POLLING_INTERVAL_SECONDS = int(os.getenv("POLLING_INTERVAL_SECONDS", "5"))

# Processed IDs store
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")

# MongoDB (optional)
MONGO_URI = os.getenv("MONGO_URI", "")
DB_NAME = os.getenv("DB_NAME", "ivasms_bot")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "processed_sms")

# Minimal keyword lists (extend if you want)
SERVICE_KEYWORDS = {"Facebook":["facebook"], "Google":["google","gmail"], "WhatsApp":["whatsapp"], "Telegram":["telegram"], "Instagram":["instagram"], "Unknown":["unknown"]}
SERVICE_EMOJIS = {"Telegram":"📩","WhatsApp":"🟢","Facebook":"📘","Instagram":"📸","Unknown":"❓"}
COUNTRY_FLAGS = {"India":"🇮🇳","Unknown Country":"🏴‍☠️"}

# ----------------------------
# MongoDB init
# ----------------------------
mongo_client = None
mongo_collection = None
if MONGO_URI:
    try:
        mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        mongo_client.server_info()
        mongo_collection = mongo_client[DB_NAME][COLLECTION_NAME]
        print("✅ MongoDB connected successfully.")
    except PyMongoError as e:
        print("⚠️ MongoDB connect failed; falling back to JSON. Error:", e)
        mongo_collection = None
else:
    print("⚠️ MONGO_URI not provided — using JSON fallback for processed IDs.")
    mongo_collection = None

# ----------------------------
# Cookie loaders (env or file)
# ----------------------------
def parse_netscape_from_string(s: str):
    """Parse a netscape-format cookies string and return dict {name: value}"""
    cook = {}
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            name = parts[5].strip()
            value = parts[6].strip()
            if name:
                cook[name] = value
    return cook

def load_netscape_from_file(path: str):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
        return parse_netscape_from_string(data)
    except Exception as e:
        print("❌ Failed to read cookies file:", e)
        return {}

def parse_cookies_from_playwright_json(s: str):
    """
    Accept either:
      - full storage_state JSON (object with "cookies" key)
      - or a JSON array of cookie objects
    Returns dict {name: value}
    """
    try:
        data = json.loads(s)
        if isinstance(data, dict) and "cookies" in data and isinstance(data["cookies"], list):
            arr = data["cookies"]
        elif isinstance(data, list):
            arr = data
        else:
            return {}
        cookie_dict = {}
        for c in arr:
            if isinstance(c, dict) and "name" in c and "value" in c:
                cookie_dict[c["name"]] = c["value"]
        return cookie_dict
    except Exception as e:
        print("❌ Failed to parse COOKIES_JSON:", e)
        return {}

def load_cookies_from_env_or_file():
    # Priority: COOKIES_NT (netscape multiline) -> COOKIES_JSON -> cookies file fallback
    if COOKIES_NT:
        d = parse_netscape_from_string(COOKIES_NT)
        if d:
            print(f"✅ Loaded {len(d)} cookies from COOKIES_NT env var.")
            return d
    if COOKIES_JSON:
        d = parse_cookies_from_playwright_json(COOKIES_JSON)
        if d:
            print(f"✅ Loaded {len(d)} cookies from COOKIES_JSON env var.")
            return d
    # fallback to file
    d = load_netscape_from_file(COOKIES_FILE)
    if d:
        print(f"✅ Loaded {len(d)} cookies from file {COOKIES_FILE}.")
        return d
    print("⚠️ No cookies found in COOKIES_NT / COOKIES_JSON / cookies.txt")
    return {}

# ----------------------------
# Safe decompression
# ----------------------------
def safe_decompress(resp):
    try:
        enc = (resp.headers.get("Content-Encoding") or "").lower()
        if "br" in enc:
            try:
                import brotli
                return brotli.decompress(resp.content).decode(errors="replace")
            except Exception:
                pass
        if "gzip" in enc or "deflate" in enc:
            try:
                import gzip
                with BytesIO(resp.content) as bio:
                    return gzip.GzipFile(fileobj=bio).read().decode(errors="replace")
            except Exception:
                pass
        return resp.text
    except Exception:
        return getattr(resp, "text", "")

# ----------------------------
# Create cloudscraper session and inject cookies
# ----------------------------
def create_scraper_with_env_cookies():
    s = cloudscraper.create_scraper(allow_brotli=True)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": LOGIN_URL
    })
    cookie_dict = load_cookies_from_env_or_file()
    if cookie_dict:
        s.cookies.update(cookie_dict)
    return s

# ----------------------------
# Chat IDs persistence & processed ids (same as before)
# ----------------------------
def load_chat_ids():
    if not os.path.exists(CHAT_IDS_FILE):
        with open(CHAT_IDS_FILE, "w") as f:
            json.dump(INITIAL_CHAT_IDS, f)
        return INITIAL_CHAT_IDS.copy()
    try:
        with open(CHAT_IDS_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else INITIAL_CHAT_IDS.copy()
    except Exception:
        return INITIAL_CHAT_IDS.copy()

def save_chat_ids(chat_ids):
    try:
        with open(CHAT_IDS_FILE, "w") as f:
            json.dump(chat_ids, f, indent=2)
    except Exception as e:
        print("❌ Failed to save chat ids:", e)

def load_processed_ids():
    if mongo_collection:
        try:
            return {doc["_id"] for doc in mongo_collection.find({}, {"_id": 1})}
        except PyMongoError as e:
            print("⚠️ Mongo read error:", e)
            return set()
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_processed_id(sms_id: str):
    if mongo_collection:
        try:
            mongo_collection.update_one({"_id": sms_id}, {"$set": {"processed_at": datetime.utcnow()}}, upsert=True)
            return
        except PyMongoError as e:
            print("⚠️ Mongo write error:", e)
    try:
        s = load_processed_ids()
        s.add(sms_id)
        with open(STATE_FILE, "w") as f:
            json.dump(list(s), f)
    except Exception as e:
        print("❌ Failed to save processed id to file:", e)

# ----------------------------
# Telegram helpers & handlers
# ----------------------------
def escape_markdown(text: str) -> str:
    esc = r'\_*[]()~`>#+-=|{}.!'
    return re.sub(f'([{re.escape(esc)}])', r'\\\1', str(text))

async def send_telegram_message(context: ContextTypes.DEFAULT_TYPE, chat_id: str, message_data: dict):
    try:
        time_str = message_data.get("time", "N/A")
        number_str = message_data.get("number", "N/A")
        country_name = message_data.get("country", "N/A")
        flag_emoji = message_data.get("flag", "🏴‍☠️")
        service_name = message_data.get("service", "N/A")
        code_str = message_data.get("code", "N/A")
        full_sms_text = message_data.get("full_sms", "N/A")
        service_emoji = SERVICE_EMOJIS.get(service_name, "❓")
        full_message = (
            f"🔔 *You have successfully received OTP*\n\n"
            f"📞 *Number:* `{escape_markdown(number_str)}`\n"
            f"🔑 *Code:* `{escape_markdown(code_str)}`\n"
            f"🏆 *Service:* {service_emoji} {escape_markdown(service_name)}\n"
            f"🌎 *Country:* {escape_markdown(country_name)} {flag_emoji}\n"
            f"⏳ *Time:* `{escape_markdown(time_str)}`\n\n"
            f"💬 *Message:*\n```\n{full_sms_text}\n```"
        )
        await context.bot.send_message(chat_id=chat_id, text=full_message, parse_mode='MarkdownV2')
    except Exception as e:
        print("❌ Telegram send error:", e)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if str(uid) in ADMIN_CHAT_IDS:
        await update.message.reply_text("Welcome Admin!\nCommands: /add_chat <id>, /remove_chat <id>, /list_chats")
    else:
        await update.message.reply_text("You are not authorized.")

async def add_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if str(uid) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    try:
        new_id = context.args[0]
        chat_ids = load_chat_ids()
        if new_id not in chat_ids:
            chat_ids.append(new_id)
            save_chat_ids(chat_ids)
            await update.message.reply_text(f"Added {new_id}")
        else:
            await update.message.reply_text("Already present.")
    except Exception:
        await update.message.reply_text("Usage: /add_chat <chat_id>")

async def remove_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if str(uid) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    try:
        rid = context.args[0]
        chat_ids = load_chat_ids()
        if rid in chat_ids:
            chat_ids.remove(rid)
            save_chat_ids(chat_ids)
            await update.message.reply_text(f"Removed {rid}")
        else:
            await update.message.reply_text("Not found.")
    except Exception:
        await update.message.reply_text("Usage: /remove_chat <chat_id>")

async def list_chats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if str(uid) not in ADMIN_CHAT_IDS:
        await update.message.reply_text("Only admins can use this.")
        return
    chat_ids = load_chat_ids()
    if chat_ids:
        try:
            msg = "Registered chat IDs:\n" + "\n".join(f"- `{escape_markdown(str(c))}`" for c in chat_ids)
            await update.message.reply_text(msg, parse_mode='MarkdownV2')
        except Exception:
            await update.message.reply_text("Registered chat IDs:\n" + "\n".join(chat_ids))
    else:
        await update.message.reply_text("No chat IDs registered.")

# ----------------------------
# Blocking functions (scraper + SMS fetch)
# ----------------------------
def blocking_check_cookies_and_get_html(scraper):
    try:
        r = scraper.get(LOGIN_CHECK_URL, timeout=30, allow_redirects=True)
        text = safe_decompress(r)
        low = (text or "").lower()
        if any(k in low for k in ("dashboard","logout","/logout")):
            return True, text, scraper
        return False, text, scraper
    except Exception as e:
        return False, f"exception: {e}", None

def blocking_fetch_sms(scraper, csrf_token):
    try:
        messages = []
        today = datetime.utcnow()
        start_date = today - timedelta(days=1)
        from_date_str, to_date_str = start_date.strftime('%m/%d/%Y'), today.strftime('%m/%d/%Y')
        first_payload = {'from': from_date_str, 'to': to_date_str, '_token': csrf_token}
        summary_res = scraper.post(SMS_API_ENDPOINT, data=first_payload, timeout=30)
        summary_html = safe_decompress(summary_res) or ""
        soup = BeautifulSoup(summary_html, "html.parser")
        group_divs = soup.find_all('div', {'class': 'pointer'})
        if not group_divs:
            return []

        group_ids = []
        for div in group_divs:
            onclick = div.get('onclick','')
            m = re.search(r"getDetials\('(.+?)'\)", onclick)
            if m:
                group_ids.append(m.group(1))

        numbers_url = urljoin(BASE_URL, "portal/sms/received/getsms/number")
        sms_url = urljoin(BASE_URL, "portal/sms/received/getsms/number/sms")

        for group_id in group_ids:
            numbers_payload = {'start': from_date_str, 'end': to_date_str, 'range': group_id, '_token': csrf_token}
            numbers_res = scraper.post(numbers_url, data=numbers_payload, timeout=30)
            numbers_html = safe_decompress(numbers_res) or ""
            nsoup = BeautifulSoup(numbers_html, "html.parser")
            number_divs = nsoup.select("div[onclick*='getDetialsNumber']")
            if not number_divs:
                continue
            phone_numbers = [div.text.strip() for div in number_divs]

            for phone_number in phone_numbers:
                sms_payload = {'start': from_date_str, 'end': to_date_str, 'Number': phone_number, 'Range': group_id, '_token': csrf_token}
                sms_res = scraper.post(sms_url, data=sms_payload, timeout=30)
                sms_html = safe_decompress(sms_res) or ""
                ssoup = BeautifulSoup(sms_html, "html.parser")
                final_sms_cards = ssoup.find_all('div', class_='card-body')
                for card in final_sms_cards:
                    sms_text_p = card.find('p', class_='mb-0')
                    if sms_text_p:
                        sms_text = sms_text_p.get_text(separator='\n').strip()
                        date_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                        country_name_match = re.match(r'([a-zA-Z\s]+)', group_id)
                        country_name = country_name_match.group(1).strip() if country_name_match else group_id.strip()
                        service = "Unknown"
                        lower_sms_text = sms_text.lower()
                        for sname, keywords in SERVICE_KEYWORDS.items():
                            if any(k in lower_sms_text for k in keywords):
                                service = sname
                                break
                        code_match = re.search(r'(\d{3}-\d{3})', sms_text) or re.search(r'\b(\d{4,8})\b', sms_text)
                        code = code_match.group(1) if code_match else "N/A"
                        unique_id = sha1(f"{phone_number}|{sms_text}".encode()).hexdigest()
                        flag = COUNTRY_FLAGS.get(country_name, "🏴‍☠️")
                        messages.append({
                            "id": unique_id, "time": date_str, "number": phone_number,
                            "country": country_name, "flag": flag, "service": service,
                            "code": code, "full_sms": sms_text
                        })
        return messages
    except Exception as e:
        print("❌ blocking_fetch_sms error:", e)
        traceback.print_exc()
        return []

# ----------------------------
# Async wrappers and job
# ----------------------------
async def check_cookies_threaded(scraper):
    return await asyncio.to_thread(blocking_check_cookies_and_get_html, scraper)

async def fetch_sms_threaded(scraper, csrf_token):
    return await asyncio.to_thread(blocking_fetch_sms, scraper, csrf_token)

async def check_sms_job(context: ContextTypes.DEFAULT_TYPE):
    print(f"\n--- [{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Checking for new messages ---")
    try:
        scraper = create_scraper_with_env_cookies()
        ok, html_text, session = await asyncio.to_thread(blocking_check_cookies_and_get_html, scraper)
        if not ok:
            print("❌ Cookies not authenticated or server returned challenge.")
            snippet = (html_text or "")[:1200].replace("\n", " ")
            print("Response snippet (truncated):", snippet)
            return

        # extract CSRF token if present
        soup = BeautifulSoup(html_text or "", "html.parser")
        csrf = None
        meta = soup.find("meta", {"name":"csrf-token"})
        if meta and meta.get("content"):
            csrf = meta.get("content")
        else:
            hid = soup.find("input", {"name":"_token"}) or soup.find("input", {"name":"csrf_token"})
            if hid and hid.get("value"):
                csrf = hid.get("value")
        if not csrf:
            csrf = ""

        messages = await fetch_sms_threaded(session, csrf)
        if not messages:
            print("✔️ No new messages found.")
            return

        processed_ids = load_processed_ids()
        chat_ids = load_chat_ids()
        new_found = 0
        for msg in reversed(messages):
            if msg["id"] not in processed_ids:
                new_found += 1
                print(f"✔️ New message from {msg['number']}. Sending...")
                for cid in chat_ids:
                    await send_telegram_message(context, cid, msg)
                save_processed_id(msg["id"])
        if new_found > 0:
            print(f"✅ Sent {new_found} new messages.")
    except Exception as e:
        print("❌ Error in check_sms_job:", e)
        traceback.print_exc()

# ----------------------------
# Start / main
# ----------------------------
def main():
    if not YOUR_BOT_TOKEN:
        print("❌ Set YOUR_BOT_TOKEN env var and restart.")
        return

    application = Application.builder().token(YOUR_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("add_chat", add_chat_command))
    application.add_handler(CommandHandler("remove_chat", remove_chat_command))
    application.add_handler(CommandHandler("list_chats", list_chats_command))

    job_queue = application.job_queue
    job_queue.run_repeating(check_sms_job, interval=POLLING_INTERVAL_SECONDS, first=1)

    print("🚀 Bot started. Polling every", POLLING_INTERVAL_SECONDS, "seconds.")
    application.run_polling()

if __name__ == "__main__":
    main()
