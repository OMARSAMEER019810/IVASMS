import aiohttp
import telegram
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
import asyncio
import time
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta
import json
import logging
import os
import pytz
import hashlib
from io import StringIO
import firebase_admin
from firebase_admin import credentials, db
import shutil

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Firebase setup
cred = credentials.Certificate("smsotp-f8aa7-firebase-adminsdk-fbsvc-edf7c62e28.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://smsotp-f8aa7-default-rtdb.firebaseio.com'
})
numbers_ranges_ref = db.reference('numbers_ranges')
seen_sms_ref = db.reference('seen_sms')

# Telegram bot setup
BOT_TOKEN = "8362712826:AAFF5R1h0NuKJVEI8Qc9fhr5W2R4Lqji6-0"
CHAT_ID = "-1003053441379"
ADMIN_CHAT_ID = "-1003053441379"
ADMIN_USER_IDS = [6524840104]
ADMINS_FILE = "admins.json"
bot = telegram.Bot(token=BOT_TOKEN)

# SMS service configuration
LOGIN_URL = "https://www.ivasms.com/login"
SMS_LIST_URL = "https://www.ivasms.com/portal/sms/received/getsms/number"
SMS_DETAILS_URL = "https://www.ivasms.com/portal/sms/received/getsms/number/sms"
RETURN_ALL_URL = "https://www.ivasms.com/portal/numbers/return/allnumber/bluck"
EMAIL = "tawandamahachi07@gmail.com"
PASSWORD = "mahachi2007"

# SMS headers
SMS_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.ivasms.com/portal/sms/received",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept": "text/html, */*; q=0.01",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# Track processed SMS
seen_sms = set()
TIME_THRESHOLD = timedelta(minutes=60)

# Pending ranges for /add_range
pending_ranges = {}  # {chat_id: {"range": str, "numbers": list}}

# Debug log directory
DEBUG_LOG_DIR = "debug_logs"
if not os.path.exists(DEBUG_LOG_DIR):
    os.makedirs(DEBUG_LOG_DIR)

# Bot state
bot_running = True

# Admin persistence
def load_admins():
    global ADMIN_USER_IDS
    if os.path.exists(ADMINS_FILE):
        try:
            with open(ADMINS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                ADMIN_USER_IDS = data.get("admin_ids", ADMIN_USER_IDS)
            logger.info(f"Loaded admin IDs: {ADMIN_USER_IDS}")
        except Exception as e:
            logger.error(f"Error loading admins file: {e}")
    else:
        logger.info("Admins file not found, using default admins")

def save_admins():
    try:
        with open(ADMINS_FILE, "w", encoding="utf-8") as f:
            json.dump({"admin_ids": ADMIN_USER_IDS}, f, ensure_ascii=False, indent=4)
        logger.info("Admin IDs saved")
    except Exception as e:
        logger.error(f"Error saving admins file: {e}")

load_admins()

# Auto-clean bot.log and debug_logs
async def auto_clean_log():
    while True:
        try:
            # Clean bot.log
            if os.path.exists('bot.log'):
                with open('bot.log', 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                if len(lines) > 1000:
                    with open('bot.log', 'w', encoding='utf-8') as f:
                        f.writelines(lines[-1000:])
                    logger.info("Truncated bot.log to last 1000 lines")
                else:
                    logger.debug("bot.log under 1000 lines, no truncation needed")

            # Clean debug_logs directory
            if os.path.exists(DEBUG_LOG_DIR):
                current_time = time.time()
                for filename in os.listdir(DEBUG_LOG_DIR):
                    file_path = os.path.join(DEBUG_LOG_DIR, filename)
                    try:
                        file_mtime = os.path.getmtime(file_path)
                        # Delete files older than 1 hour (3600 seconds)
                        if current_time - file_mtime > 3600:
                            os.remove(file_path)
                            logger.info(f"Deleted old debug log: {file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting debug log {file_path}: {str(e)}")
                # Remove directory if empty
                try:
                    os.rmdir(DEBUG_LOG_DIR)
                    logger.info("Removed empty debug_logs directory")
                    os.makedirs(DEBUG_LOG_DIR)  # Recreate directory
                except OSError:
                    pass  # Directory not empty
            else:
                os.makedirs(DEBUG_LOG_DIR)
                logger.info("Recreated debug_logs directory")

            await asyncio.sleep(120)  # Run every 2 minutes
        except Exception as e:
            logger.error(f"Error in auto_clean_log: {str(e)}")
            await asyncio.sleep(120)

async def send_startup_alert(chat_id=CHAT_ID):
    try:
        current_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d-%m-%Y %H:%M:%S")
        startup_msg = (
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "🌟 **BOT INITIALIZED** 🌟\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕒 **Started At**: {current_time} (Asia/Dhaka)\n"
            "📡 **Status**: Operational\n"
            "🔧 **Service Provider**: Seven1Tel / IVASMS\n"
            "🔑 **Functionality**: OTP Detection Active\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "👨‍💻 **Developed by**: BAPPY KHAN\n"
            "━━━━━━━━━━━━━━━━━━━━━"
        )
        keyboard = [
            [InlineKeyboardButton("📞 Contact Owner", url="https://t.me/jadenafrix")],
            [InlineKeyboardButton("📢 Join Backup Channel", url="https://t.me/mrafrix")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await bot.send_message(
            chat_id=chat_id,
            text=startup_msg,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
        logger.info("Startup alert sent")
    except Exception as e:
        logger.error(f"Error sending startup alert: {str(e)}")
        await send_telegram_message(f"❌ Error sending startup alert: {str(e)}", chat_id)

def initialize_firebase_data():
    try:
        if not numbers_ranges_ref.get():
            numbers_ranges_ref.set({"ranges": []})
            logger.info("Initialized numbers_ranges in Firebase")
        if not seen_sms_ref.get():
            seen_sms_ref.set({"sms_ids": [], "last_updated": datetime.now().isoformat()})
            logger.info("Initialized seen_sms in Firebase")
    except Exception as e:
        logger.error(f"Error initializing Firebase data: {str(e)}")
        asyncio.create_task(send_telegram_message(f"❌ Error initializing Firebase data: {str(e)}", CHAT_ID))

def load_seen_sms():
    global seen_sms
    initialize_firebase_data()
    try:
        data = seen_sms_ref.get() or {"sms_ids": []}
        seen_sms = set(data.get("sms_ids", []))
        logger.info(f"Loaded {len(seen_sms)} SMS IDs from Firebase")
    except Exception as e:
        logger.error(f"Error loading seen_sms from Firebase: {str(e)}")
        seen_sms = set()

def save_seen_sms():
    try:
        seen_sms_ref.set({
            "sms_ids": list(seen_sms),
            "last_updated": datetime.now().isoformat()
        })
        logger.info("Saved SMS IDs to Firebase")
    except Exception as e:
        error_msg = f"❌ Error saving seen_sms to Firebase: {str(e)}"
        logger.error(error_msg)
        asyncio.create_task(send_telegram_message(error_msg, CHAT_ID))

def load_numbers_ranges():
    initialize_firebase_data()
    try:
        data = numbers_ranges_ref.get() or {"ranges": []}
        numbers = []
        ranges = []
        for range_item in data.get("ranges", []):
            range_value = str(range_item.get("range", "")).strip()
            range_numbers = range_item.get("numbers", [])
            if range_value and range_value not in ranges:
                ranges.append(range_value)
            for num in range_numbers:
                if num not in numbers:
                    numbers.append(str(num))
        logger.info(f"Loaded {len(numbers)} numbers and {len(ranges)} ranges from Firebase")
        return numbers, ranges
    except Exception as e:
        error_msg = f"❌ Error loading from Firebase: {str(e)}"
        logger.error(error_msg)
        asyncio.create_task(send_telegram_message(error_msg, CHAT_ID))
        return [], []

def save_numbers_ranges(ranges_data):
    try:
        if not isinstance(ranges_data, list):
            logger.error(f"Invalid ranges_data type: {type(ranges_data)}")
            raise ValueError("ranges_data must be a list")
        
        cleaned_ranges = []
        seen_ranges = set()
        for range_item in ranges_data:
            if not isinstance(range_item, dict) or "range" not in range_item or "numbers" not in range_item:
                logger.warning(f"Skipping invalid range item: {range_item}")
                continue
            range_value = str(range_item["range"]).strip()
            if range_value in seen_ranges:
                logger.warning(f"Duplicate range {range_value}, skipping")
                continue
            seen_ranges.add(range_value)
            numbers = [str(num).strip() for num in set(range_item.get("numbers", []))]
            cleaned_ranges.append({"range": range_value, "numbers": numbers})
        
        numbers_ranges_ref.set({"ranges": cleaned_ranges})
        logger.info(f"Saved {len(cleaned_ranges)} ranges to Firebase")
    except Exception as e:
        error_msg = f"❌ Error saving to Firebase: {str(e)}"
        logger.error(error_msg)
        asyncio.create_task(send_telegram_message(error_msg, CHAT_ID))

async def return_numbers(session, csrf_token, range_value=None):
    try:
        headers = SMS_HEADERS.copy()
        headers["x-csrf-token"] = csrf_token
        headers["Accept"] = "application/json"
        
        if range_value:
            url = f"https://www.ivasms.com/portal/numbers/return/range/{range_value}"
            payload = {"range": range_value}
            log_msg = f"Returning numbers for range: {range_value}"
        else:
            url = RETURN_ALL_URL
            payload = {}
            log_msg = "Returning all numbers"
        
        logger.info(f"{log_msg} | URL: {url}")
        async with session.post(url, headers=headers, data=payload, timeout=10) as response:
            logger.info(f"Return API response status code: {response.status}")
            text = await response.text()
            logger.debug(f"Return API response text: {text[:1000]}...")
            
            if response.status == 200:
                try:
                    response_data = await response.json()
                    logger.info(f"Return API response: {json.dumps(response_data, indent=2)[:500]}...")
                    if response_data.get("success", False) or (response_data.get("NumberDoneRemove") and len(response_data["NumberDoneRemove"]) > 0):
                        logger.info(f"{log_msg} successful")
                        return True
                    else:
                        logger.error(f"{log_msg} failed: {response_data.get('message', 'Unknown error')}")
                        return False
                except ValueError:
                    logger.error(f"Failed to parse return API response as JSON: {text[:500]}...")
                    return "success" in text.lower()
            elif response.status in [401, 403]:
                logger.error(f"{log_msg} failed due to authentication error (status code: {response.status})")
                return "SESSION_EXPIRED"
            else:
                logger.error(f"{log_msg} failed with status code: {response.status}, Response: {text[:500]}...")
                return False
    except Exception as e:
        logger.error(f"Error returning numbers: {str(e)}")
        return False

async def send_telegram_message(message, chat_id=CHAT_ID, reply_markup=None, auto_delete_seconds=None):
    logger.info(f"Sending Telegram message to chat_id {chat_id}: {message[:100]}...")
    try:
        sent_message = await bot.send_message(
            chat_id=chat_id,
            text=message,
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )
        logger.info(f"Message sent: Message ID {sent_message.message_id}")
        
        if auto_delete_seconds:
            await asyncio.sleep(auto_delete_seconds)
            try:
                await bot.delete_message(
                    chat_id=chat_id,
                    message_id=sent_message.message_id
                )
                logger.info(f"Message deleted: Message ID {sent_message.message_id}")
            except telegram.error.TelegramError as e:
                logger.error(f"Error deleting message: Message ID {sent_message.message_id}, Error: {str(e)}")
        return sent_message
    except telegram.error.BadRequest as e:
        logger.error(f"Telegram Bad Request error: {str(e)}")
        try:
            sent_message = await bot.send_message(
                chat_id=chat_id,
                text=message,
                reply_markup=reply_markup,
                parse_mode=None
            )
            logger.info(f"Message sent without Markdown: {message[:100]}...")
            if auto_delete_seconds:
                await asyncio.sleep(auto_delete_seconds)
                try:
                    await bot.delete_message(
                        chat_id=chat_id,
                        message_id=sent_message.message_id
                    )
                    logger.info(f"Message deleted: Message ID {sent_message.message_id}")
                except telegram.error.TelegramError as e:
                    logger.error(f"Error deleting message: Message ID {sent_message.message_id}, Error: {str(e)}")
            return sent_message
        except Exception as e2:
            logger.error(f"Retry Telegram message error: {str(e2)}")
    except telegram.error.InvalidToken:
        logger.error("Invalid Telegram bot token. Check with BotFather.")
    except telegram.error.NetworkError as e:
        logger.error(f"Telegram network error: {str(e)}")
    except Exception as e:
        logger.error(f"Error sending Telegram message: {str(e)}")
    return None

async def login_and_get_csrf(session, max_retries=3):
    for attempt in range(max_retries):
        try:
            logger.info(f"Login attempt {attempt + 1}/{max_retries}...")
            async with session.get(LOGIN_URL, headers=SMS_HEADERS, timeout=10) as response:
                logger.info(f"Login page status code: {response.status}")
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                csrf_input = soup.find('input', {'name': '_token'})
                if not csrf_input:
                    logger.error("CSRF token not found!")
                    return None, None
                csrf_token = csrf_input['value']
                logger.info(f"CSRF token: {csrf_token}")
                
                payload = {
                    "_token": csrf_token,
                    "email": EMAIL,
                    "password": PASSWORD
                }
                logger.info("Sending login request...")
                async with session.post(LOGIN_URL, data=payload, headers=SMS_HEADERS, timeout=10) as login_response:
                    logger.info(f"Login response status code: {login_response.status}")
                    text = await login_response.text()
                    if login_response.status != 200 or "Dashboard" not in text:
                        error_msg = f"❌ Login failed! Attempt {attempt + 1}/{max_retries}"
                        logger.error(error_msg)
                        await send_telegram_message(error_msg, CHAT_ID)
                        if attempt < max_retries - 1:
                            await asyncio.sleep(5)
                        continue
                    logger.info("Login successful!")
                    return session, csrf_token
        except Exception as e:
            error_msg = f"❌ Login error (attempt {attempt + 1}/{max_retries}): {str(e)}"
            logger.error(error_msg)
            await send_telegram_message(error_msg, CHAT_ID)
            if attempt < max_retries - 1:
                await asyncio.sleep(5)
    return None, None

async def sync_numbers_from_api(session, csrf_token, chat_id=CHAT_ID):
    try:
        start_time = time.time()
        logger.info("Starting API synchronization for numbers and ranges...")

        base_url = "https://www.ivasms.com/portal/numbers"
        page_size = 1000
        start = 0
        all_ranges_data = {}
        headers = SMS_HEADERS.copy()
        headers.update({
            "x-csrf-token": csrf_token,
            "Accept": "application/json",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-ch-ua": "\"Chromium\";v=\"136\", \"Android WebView\";v=\"136\", \"Not.A/Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?1",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "accept-language": "en-US,en;q=0.9",
            "priority": "u=1, i"
        })

        while True:
            params = {
                "draw": 2,
                "columns[0][data]": "number_id",
                "columns[0][name]": "id",
                "columns[0][orderable]": "false",
                "columns[1][data]": "Number",
                "columns[2][data]": "range",
                "columns[3][data]": "A2P",
                "columns[4][data]": "P2P",
                "columns[5][data]": "LimitA2P",
                "columns[6][data]": "limit_cli_a2p",
                "columns[7][data]": "limit_did_a2p",
                "columns[8][data]": "limit_cli_did_a2p",
                "columns[9][data]": "LimitP2P",
                "columns[10][data]": "limit_cli_p2p",
                "columns[11][data]": "limit_did_p2p",
                "columns[12][data]": "limit_cli_did_p2p",
                "columns[13][data]": "action",
                "columns[13][searchable]": "false",
                "columns[13][orderable]": "false",
                "order[0][column]": 1,
                "order[0][dir]": "desc",
                "start": start,
                "length": page_size,
                "search[value]": "",
                "_": int(time.time() * 1000)
            }

            api_start = time.time()
            logger.info(f"Fetching page: start={start}, page_size={page_size}")
            async with session.get(base_url, headers=headers, params=params, timeout=15) as response:
                api_time = time.time() - api_start
                logger.info(f"API response status code: {response.status}, took {api_time:.2f} seconds")

                if response.status in [401, 403]:
                    logger.info("Session expired during sync, re-logging in...")
                    session, new_csrf_token = await login_and_get_csrf(session)
                    if not session or not new_csrf_token:
                        error_msg = "❌ Failed to re-login during sync!"
                        logger.error(error_msg)
                        await send_telegram_message(error_msg, chat_id)
                        return False
                    headers["x-csrf-token"] = new_csrf_token
                    csrf_token = new_csrf_token
                    async with session.get(base_url, headers=headers, params=params, timeout=15) as response:
                        if not response.ok:
                            error_msg = f"❌ API sync retry failed! Status code: {response.status}"
                            logger.error(error_msg)
                            await send_telegram_message(error_msg, chat_id)
                            return False
                        text = await response.text()
                else:
                    if not response.ok:
                        error_msg = f"❌ API sync failed! Status code: {response.status}"
                        logger.error(error_msg)
                        await send_telegram_message(error_msg, chat_id)
                        return False
                    text = await response.text()

            try:
                data = json.loads(text)
                records_total = data.get("recordsTotal", 0)
                records_filtered = data.get("recordsFiltered", 0)
                logger.info(f"Records: total={records_total}, filtered={records_filtered}, received={len(data.get('data', []))}")
            except ValueError as e:
                error_msg = f"❌ Failed to parse API response as JSON: {str(e)}, Response: {text[:1000]}..."
                logger.error(error_msg)
                await send_telegram_message(error_msg, chat_id)
                return False

            if not data.get("data"):
                logger.warning(f"No data in page: start={start}")
                break

            for record in data.get("data", []):
                range_value = str(record.get("range", "")).strip() if record.get("range") is not None else ""
                number = str(record.get("Number", "")).strip() if record.get("Number") is not None else ""
                if not range_value or not number:
                    logger.warning(f"Skipping record with empty range or number: range={range_value}, number={number}")
                    continue
                if not validate_phone_number(number):
                    logger.warning(f"Invalid number format: {number}, range={range_value}")
                    continue
                if range_value not in all_ranges_data:
                    all_ranges_data[range_value] = {"range": range_value, "numbers": []}
                if number not in all_ranges_data[range_value]["numbers"]:
                    all_ranges_data[range_value]["numbers"].append(number)

            if len(data["data"]) < page_size or start + page_size >= records_total:
                logger.info("Reached end of records")
                break
            start += page_size
            await asyncio.sleep(1)

        ranges_data = list(all_ranges_data.values())
        logger.info(f"Found {len(ranges_data)} ranges: {[r['range'] for r in ranges_data]}")
        if len(ranges_data) < 3:
            logger.warning(f"Expected at least 3 ranges, found {len(ranges_data)}. Check API response or additional endpoints.")

        if not ranges_data:
            error_msg = "⚠️ No valid numbers or ranges found in API response!"
            logger.warning(error_msg)
            await send_telegram_message(error_msg, chat_id)
            return False

        existing_data = numbers_ranges_ref.get() or {"ranges": []}
        existing_data = existing_data.get("ranges", [])

        merged_data = []
        api_range_values = {r["range"] for r in ranges_data}
        for api_range in ranges_data:
            range_value = api_range["range"]
            numbers = api_range["numbers"]
            existing_range = next((item for item in existing_data if item["range"] == range_value), None)
            if existing_range:
                merged_numbers = list(set(existing_range["numbers"] + numbers))
                merged_data.append({"range": range_value, "numbers": merged_numbers})
            else:
                merged_data.append(api_range)
        for fb_range in existing_data:
            if fb_range["range"] not in api_range_values:
                merged_data.append(fb_range)

        save_numbers_ranges(merged_data)

        total_ranges = len(merged_data)
        total_numbers = sum(len(r["numbers"]) for r in merged_data)
        total_time = time.time() - start_time
        success_msg = f"✅ Synced numbers and ranges from API! Total ranges: {total_ranges}, Total numbers: {total_numbers}, Time: {total_time:.2f} seconds"
        logger.info(success_msg)
        keyboard = []
        if str(chat_id) == str(ADMIN_CHAT_ID):
            keyboard.append([InlineKeyboardButton("Sync Now", callback_data="sync_now")])
        keyboard.append([InlineKeyboardButton("Return All", callback_data="confirm_delete_all")])
        reply_markup = InlineKeyboardMarkup(keyboard) if keyboard else None

        await send_telegram_message(success_msg, chat_id, reply_markup=reply_markup, auto_delete_seconds=30)
        return True

    except Exception as e:
        error_msg = f"❌ API sync error: {str(e)}"
        logger.error(error_msg)
        await send_telegram_message(error_msg, chat_id)
        return False

async def fetch_number_list(session, csrf_token, range_value):
    post_data = {
        "_token": csrf_token,
        "start": (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"),
        "end": datetime.now().strftime("%Y-%m-%d"),
        "range": range_value,
        "draw": 1,
        "length": 100
    }
    
    headers = SMS_HEADERS.copy()
    headers["x-csrf-token"] = csrf_token
    
    max_retries = 3
    page = 0
    numbers = []
    
    while True:
        post_data["start"] = page * post_data["length"]
        for attempt in range(max_retries):
            try:
                logger.info(f"Fetching number list (page {page}, attempt {attempt + 1}/{max_retries}): range={range_value}")
                async with session.post(SMS_LIST_URL, headers=headers, data=post_data, timeout=10) as response:
                    logger.info(f"Number list response status code: {response.status}")
                    
                    if not response.ok:
                        error_msg = f"❌ Number list fetch failed! Range={range_value}, Status code: {response.status}"
                        logger.error(error_msg)
                        if response.status in [401, 403]:
                            return "SESSION_EXPIRED", []
                        if attempt < max_retries - 1:
                            await asyncio.sleep(5)
                            continue
                        return None, []
                    
                    text = await response.text()
                    soup = BeautifulSoup(text, "html.parser")
                    number_cards = soup.find_all("div", class_="card card-body border-bottom bg-100 p-2 rounded-0")
                    logger.info(f"Found {len(number_cards)} number cards for range {range_value}")
                    
                    if not number_cards:
                        debug_file = os.path.join(DEBUG_LOG_DIR, f"empty_number_list_{range_value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
                        with open(debug_file, "w", encoding="utf-8") as f:
                            f.write(text)
                        logger.error(f"Response saved: {debug_file}")
                    
                    for card in number_cards:
                        number_div = card.find("div", class_="col-sm-4 border-bottom border-sm-bottom-0 pb-2 pb-sm-0 mb-2 mb-sm-0")
                        if number_div:
                            number = str(number_div.get_text(strip=True))
                            logger.info(f"Extracted number: {number}")
                            onclick = number_div.get("onclick", "")
                            id_number_match = re.search(r"'(\d+)','(\d+)'", onclick)
                            id_number = id_number_match.group(2) if id_number_match else ""
                            numbers.append({"number": number, "id_number": id_number})
                    
                    if len(number_cards) < post_data["length"]:
                        break
                    
                    page += 1
                    break
                
            except Exception as e:
                error_msg = f"❌ Error fetching number list: Range={range_value}, Error: {str(e)}"
                logger.error(error_msg)
                if attempt < max_retries - 1:
                    await asyncio.sleep(5)
                continue
        
        if len(number_cards) < post_data["length"]:
            break
    
    if numbers:
        logger.info(f"Number list fetch successful: {len(numbers)} numbers found")
        return text, numbers
    else:
        error_msg = f"❌ No numbers found! Range={range_value}"
        logger.error(error_msg)
        return None, []

async def fetch_sms_details(session, csrf_token, number, range_value, id_number):
    post_data = {
        "_token": csrf_token,
        "Number": str(number),
        "Range": str(range_value),
        "id_number": id_number
    }
    
    headers = SMS_HEADERS.copy()
    headers["x-csrf-token"] = csrf_token
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Fetching SMS details (attempt {attempt + 1}/{max_retries}): Number={number}, Range={range_value}, id_number={id_number}")
            async with session.post(SMS_DETAILS_URL, headers=headers, data=post_data, timeout=10) as response:
                logger.info(f"SMS details response status code: {response.status}")
                
                debug_file = os.path.join(DEBUG_LOG_DIR, f"sms_raw_{number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
                with open(debug_file, "w", encoding="utf-8") as f:
                    text = await response.text()
                    f.write(text)
                logger.info(f"Raw response saved: {debug_file}")
                
                if not response.ok:
                    error_msg = f"❌ SMS details fetch failed! Number={number}, Range={range_value}, Status code: {response.status}"
                    logger.error(error_msg)
                    if response.status in [401, 403]:
                        return "SESSION_EXPIRED"
                    if attempt < max_retries - 1:
                        await asyncio.sleep(5)
                        continue
                    return None
                
                soup = BeautifulSoup(text, "html.parser")
                sms_content = soup.find("div", class_="card card-body border-bottom bg-soft-dark p-2 rounded-0")
                if not sms_content or not sms_content.get_text(strip=True):
                    sms_content = soup.find("div", class_="card-body") or soup.find("div", class_="sms-content")
                    if not sms_content or not sms_content.get_text(strip=True):
                        error_msg = f"❌ Empty SMS content found! Number={number}, Range={range_value}"
                        logger.error(error_msg)
                        debug_file = os.path.join(DEBUG_LOG_DIR, f"empty_sms_{number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
                        with open(debug_file, "w", encoding="utf-8") as f:
                            f.write(text)
                        logger.error(f"Response saved: {debug_file}")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(5)
                            continue
                        return None
                
                logger.info(f"SMS details fetch successful: Number={number}")
                return text
        except Exception as e:
            error_msg = f"❌ Error fetching SMS details: Number={number}, Range={range_value}, Error: {str(e)}"
            logger.error(error_msg)
            if attempt < max_retries - 1:
                await asyncio.sleep(5)
            continue
    return None

async def process_sms(sms_html, number, range_value):
    try:
        soup = BeautifulSoup(sms_html, "html.parser")
        sms_cards = soup.find_all("div", class_="card card-body border-bottom bg-soft-dark p-2 rounded-0")
        logger.info(f"Found {len(sms_cards)} SMS cards")
        
        if not sms_cards:
            logger.info(f"No SMS cards found! Range={range_value}, Number={number}")
            return
        
        dhaka_tz = pytz.timezone('Asia/Dhaka')
        current_time = datetime.now(dhaka_tz)
        
        for card in sms_cards:
            try:
                sms_text = card.find("p").get_text(strip=True) if card.find("p") else card.get_text(strip=True)
                logger.info(f"SMS text: {sms_text}")
                if not sms_text:
                    logger.info("Empty SMS text, skipping...")
                    continue
                
                sms_timestamp = card.find("span", class_="sms-date")
                timestamp_str = sms_timestamp.get_text(strip=True) if sms_timestamp else current_time.isoformat()
                try:
                    sms_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    sms_time = sms_time.astimezone(dhaka_tz)
                except ValueError:
                    try:
                        sms_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        sms_time = dhaka_tz.localize(sms_time)
                    except ValueError:
                        logger.warning(f"Failed to parse timestamp: {timestamp_str}, using current time")
                        sms_time = current_time
                
                if current_time - sms_time > TIME_THRESHOLD:
                    logger.info(f"Old SMS (timestamp: {timestamp_str}), skipping...")
                    continue
                
                sms_id = hashlib.sha256(f"{number}{sms_text}".encode()).hexdigest()
                if sms_id in seen_sms:
                    logger.info(f"Duplicate SMS (ID: {sms_id}), skipping...")
                    continue
                
                phone_number = mask_phone_number(number)
                logger.info(f"Final phone number for message: {phone_number}")
                
                code_match = re.search(r"(\d{6}|\d{5}|\d{4}|\d{3}[- ]?\d{3})", sms_text)
                if code_match:
                    otp_code = code_match.group(0).replace("-", "").replace(" ", "")
                    if "WhatsApp" in sms_text:
                        service = "WhatsApp"
                    elif "Facebook" in sms_text or "FB-" in sms_text:
                        service = "Facebook"
                    else:
                        service = "Unknown"
                    
                    country = str(range_value).split()[0] if range_value else "Unknown"
                    formatted_time = current_time.strftime("%d %b %Y, %I:%M %p")
                    
                    message = (
                        "━━━━━━━━━━━━━━━━━━━━━\n"
                        f"🔐 **{service} OTP Notification** 🔐\n"
                        "━━━━━━━━━━━━━━━━━━━━━\n"
                        f"🌍 **Country**: {country}\n"
                        f"⚙️ **Service**: {service}\n"
                        f"📱 **Number**: {phone_number}\n"
                        f"🔑 **OTP Code**: `{otp_code}`\n"
                        f"📜 **Message Content**:\n```\n{sms_text}\n```\n"
                        f"🕒 **Received At**: {formatted_time} (Asia/Dhaka)\n"
                        "━━━━━━━━━━━━━━━━━━━━━\n"
                        "🚀 **Status**: Awaiting Action\n"
                        "👨‍💻 **Powered by**: AFRIX DEVS\n"
                        "━━━━━━━━━━━━━━━━━━━━━"
                    )
                    
                    logger.info(f"Message to be sent: {message}")
                    await send_telegram_message(message, CHAT_ID, reply_markup=None)
                    seen_sms.add(sms_id)
                    save_seen_sms()
                    logger.info(f"OTP found: {otp_code}, Service: {service}, SMS ID: {sms_id}")
                else:
                    logger.info("No OTP found")
            except Exception as e:
                error_msg = f"❌ Error processing SMS: Range={range_value}, Number={number}, Error: {str(e)}"
                logger.error(error_msg)
                await send_telegram_message(error_msg, CHAT_ID)
    except Exception as e:
        error_msg = f"❌ Error parsing SMS: Range={range_value}, Number={number}, Error: {str(e)}"
        logger.error(error_msg)
        await send_telegram_message(error_msg, CHAT_ID)

async def wait_for_sms(session, csrf_token):
    global bot_running
    last_no_range_message = 0
    message_interval = 300
    
    while True:
        if not bot_running:
            logger.info("Bot is off, suspending SMS checking loop...")
            await asyncio.sleep(5)
            continue
        
        logger.info("Checking for new SMS...")
        try:
            data = numbers_ranges_ref.get() or {"ranges": []}
        except Exception as e:
            logger.error(f"Error loading ranges from Firebase: {str(e)}")
            data = {"ranges": []}
        
        ranges = data.get("ranges", [])
        if not ranges:
            current_time = time.time()
            if current_time - last_no_range_message > message_interval:
                logger.info("No ranges found, sending message...")
                await send_telegram_message("⚠️ No ranges found. Use /add_range or /sync.", CHAT_ID)
                last_no_range_message = current_time
            else:
                logger.info("No ranges found, but message not sent due to time interval")
            await asyncio.sleep(2)
            continue
        
        total_numbers_processed = 0
        for range_item in ranges:
            range_value = str(range_item.get("range", ""))
            range_numbers = range_item.get("numbers", [])
            if not range_numbers:
                logger.info(f"No numbers for range {range_value}, skipping...")
                continue
            
            number_list_html, numbers = await fetch_number_list(session, csrf_token, range_value)
            if number_list_html == "SESSION_EXPIRED":
                logger.info("Session expired, re-logging in...")
                session, csrf_token = await login_and_get_csrf(session)
                if not session or not csrf_token:
                    logger.error("Re-login failed, waiting 5 seconds...")
                    await asyncio.sleep(5)
                    continue
                number_list_html, numbers = await fetch_number_list(session, csrf_token, range_value)
            
            if not numbers:
                logger.info(f"No numbers found for range {range_value}, moving to next range...")
                continue
            
            for number_info in numbers:
                number = str(number_info["number"])
                id_number = str(number_info["id_number"])
                sms_html = await fetch_sms_details(session, csrf_token, number, range_value, id_number)
                if sms_html == "SESSION_EXPIRED":
                    logger.info("Session expired, re-logging in...")
                    session, csrf_token = await login_and_get_csrf(session)
                    if not session or not csrf_token:
                        logger.error("Re-login failed, waiting 5 seconds...")
                        await asyncio.sleep(5)
                        continue
                    sms_html = await fetch_sms_details(session, csrf_token, number, range_value, id_number)
                
                if sms_html:
                    await process_sms(sms_html, number, range_value)
                else:
                    logger.info(f"SMS fetch failed for number {number}, moving to next number...")
                
                total_numbers_processed += 1
        
        logger.info(f"Total numbers processed: {total_numbers_processed}")
        logger.info("Waiting 2 seconds...")
        await asyncio.sleep(2)

async def auto_sync(session, csrf_token, chat_id=CHAT_ID):
    while True:
        try:
            logger.info("Starting auto-sync...")
            await send_telegram_message(
                "🔄 Syncing numbers and ranges from API...",
                chat_id,
                auto_delete_seconds=30
            )
            await sync_numbers_from_api(session, csrf_token, chat_id)
            logger.info("Auto-sync completed, waiting 1 minute...")
            await asyncio.sleep(60)
        except Exception as e:
            error_msg = f"❌ Auto-sync error: {str(e)}"
            logger.error(error_msg)
            await send_telegram_message(error_msg, chat_id)
            await asyncio.sleep(60)

def validate_phone_number(number):
    pattern = r"^\+?\d{7,15}$"
    return bool(re.match(pattern, str(number)))

def mask_phone_number(number):
    logger.info(f"Original number input: '{number}'")
    cleaned_number = ''.join(c for c in str(number) if c.isdigit() or c == '+')
    has_plus = cleaned_number.startswith('+')
    cleaned_number = cleaned_number.lstrip('+')
    logger.info(f"Cleaned number: '{cleaned_number}'")
    
    if len(cleaned_number) >= 8:
        if len(cleaned_number) >= 7:
            masked = f"{cleaned_number[:5]}**{cleaned_number[7:]}"
        else:
            masked = f"{cleaned_number[:5]}**"
        if has_plus:
            masked = f"+{masked}"
        logger.info(f"Masked number: '{masked}'")
        return masked
    elif len(cleaned_number) > 0:
        masked = f"+{cleaned_number}" if has_plus else cleaned_number
        logger.info(f"Number too short, returning: '{masked}'")
        return masked
    else:
        logger.warning("Empty number after cleaning, returning '+Unknown'")
        return "+Unknown"

async def handle_bot_updates(update, session, csrf_token):
    global bot_running
    try:
        if update.message:
            message = update.message
            chat_id = message.chat.id
            user_id = message.from_user.id
            username = message.from_user.username or "Unknown"
            text = message.text or ""
            logger.info(f"Message received: {text} | Chat ID: {chat_id} | User ID: {user_id} | Username: @{username}")
            
            try:
                data = numbers_ranges_ref.get() or {"ranges": []}
            except Exception as e:
                logger.error(f"Error loading ranges from Firebase: {str(e)}")
                data = {"ranges": []}
            
            ranges = data.get("ranges", [])
            
            def is_admin(chat_id, user_id):
                return str(chat_id) == str(ADMIN_CHAT_ID) and user_id in ADMIN_USER_IDS
            
            if text.startswith(("/add_admin", "/add_admin@afrixivas_otpbot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ This command is only for admins!"
                    )
                    logger.warning(f"Non-admin attempted /add_admin: User ID: {user_id}, Username: @{username}")
                    return
                parts = text.split()
                if len(parts) != 2:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="⚠️ Provide a valid user ID. Example: /add_admin 123456789"
                    )
                    return
                new_admin_id = parts[1].strip()
                if not re.match(r"^\d+$", new_admin_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ User ID must be a positive number."
                    )
                    return
                new_admin_id = int(new_admin_id)
                if new_admin_id in ADMIN_USER_IDS:
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"ℹ️ User ID {new_admin_id} is already an admin."
                    )
                    return
                ADMIN_USER_IDS.append(new_admin_id)
                save_admins()
                logger.info(f"New admin added: {new_admin_id}, Added by: {user_id} (@{username})")
                formatted_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d %b %Y, %I:%M %p")
                await bot.send_message(
                    chat_id=chat_id,
                    text=(
                        f"✅ New admin added: User ID `{new_admin_id}`\n"
                        f"🕒 Time: {formatted_time}\n"
                        f"🚀 They can now use admin commands.\n\n"
                        f"~ BAPPY KHAN"
                    ),
                    parse_mode="Markdown"
                )
                return
            
            if text.startswith(("/remove_admin", "/remove_admin@dxsmsreceiver_bot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ This command is only for admins!"
                    )
                    logger.warning(f"Non-admin attempted /remove_admin: User ID: {user_id}, Username: @{username}")
                    return
                parts = text.split()
                if len(parts) != 2:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="⚠️ Provide a valid user ID. Example: /remove_admin 123456789"
                    )
                    return
                admin_id_to_remove = parts[1].strip()
                if not re.match(r"^\d+$", admin_id_to_remove):
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ User ID must be a positive number."
                    )
                    return
                admin_id_to_remove = int(admin_id_to_remove)
                if admin_id_to_remove not in ADMIN_USER_IDS:
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"ℹ️ User ID {admin_id_to_remove} is not an admin."
                    )
                    return
                if len(ADMIN_USER_IDS) <= 1:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ Cannot remove the last admin. At least one admin is required."
                    )
                    return
                ADMIN_USER_IDS.remove(admin_id_to_remove)
                save_admins()
                logger.info(f"Admin removed: {admin_id_to_remove}, Removed by: {user_id} (@{username})")
                formatted_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d %b %Y, %I:%M %p")
                await bot.send_message(
                    chat_id=chat_id,
                    text=(
                        f"✅ Admin removed: User ID `{admin_id_to_remove}`\n"
                        f"🕒 Time: {formatted_time}\n"
                        f"🚀 They can no longer use admin commands.\n\n"
                        f"~ BAPPY KHAN"
                    ),
                    parse_mode="Markdown"
                )
                return
            
            if text.startswith(("/check_id", "/check_id@dxsmsreceiver_bot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /check_id: User ID: {user_id}, Username: @{username}")
                    return
                parts = text.split()
                if len(parts) < 2:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="⚠️ Provide an ID. Example: /check_id -1003053441379"
                    )
                    return
                input_id = parts[1].strip()
                if input_id == str(ADMIN_CHAT_ID):
                    msg = f"✅ This is the admin chat ID: {input_id}\nAdmin commands can be used."
                else:
                    msg = f"ℹ️ This is a non-admin chat ID: {input_id}\nAdmin commands cannot be used."
                await bot.send_message(
                    chat_id=chat_id,
                    text=msg
                )
                logger.info(f"Checked ID: {input_id} | User ID: {user_id} | Chat ID: {chat_id}")
                return
            
            elif text.startswith(("/sync", "/sync@dxsmsreceiver_bot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /sync: User ID: {user_id}, Username: @{username}")
                    return
                await send_telegram_message(
                    "🔄 Syncing numbers and ranges from API...",
                    chat_id,
                    auto_delete_seconds=30
                )
                success = await sync_numbers_from_api(session, csrf_token, chat_id)
                if not success:
                    await bot.sendBackspace
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ Synchronization failed! Check logs for details."
                    )
            
            elif text.startswith(("/bot_on", "/bot_on@dxsmsreceiver_bot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /bot_on: User ID: {user_id}, Username: @{username}")
                    return
                if bot_running:
                    await send_telegram_message(
                        "ℹ️ Bot is already ON!",
                        chat_id,
                        auto_delete_seconds=30
                    )
                else:
                    bot_running = True
                    await send_telegram_message(
                        "✅ Bot is ON!",
                        chat_id,
                        auto_delete_seconds=30
                    )
                    logger.info(f"Bot turned ON: User ID: {user_id}, Username: @{username}")
            
            elif text.startswith(("/bot_off", "/bot_off@afrixivas_otpbot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /bot_off: User ID: {user_id}, Username: @{username}")
                    return
                if not bot_running:
                    await send_telegram_message(
                        "ℹ️ Bot is already OFF!",
                        chat_id,
                        auto_delete_seconds=30
                    )
                else:
                    bot_running = False
                    await send_telegram_message(
                        "❌ Bot is OFF!",
                        chat_id,
                        auto_delete_seconds=30
                    )
                    logger.info(f"Bot turned OFF: User ID: {user_id}, Username: @{username}")
            
            elif text.startswith(("/delete_all", "/delete_all@afrixivas_otpbot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /delete_all: User ID: {user_id}, Username: @{username}")
                    return
                keyboard = [
                    [InlineKeyboardButton("Yes, Return All", callback_data="delete_all")],
                    [InlineKeyboardButton("No, Cancel", callback_data="cancel_delete")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await bot.send_message(
                    chat_id=chat_id,
                    text="Are you sure you want to return all numbers?",
                    reply_markup=reply_markup
                )
            
            elif text.startswith(("/remove_range", "/remove_range@afrixivas_otpbot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /remove_range: User ID: {user_id}, Username: @{username}")
                    return
                numbers, ranges_list = load_numbers_ranges()
                if ranges_list:
                    keyboard = [[InlineKeyboardButton(range_val, callback_data=f"remove_{range_val}")] for range_val in ranges_list]
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    await bot.send_message(
                        chat_id=chat_id,
                        text="Select a range to return:",
                        reply_markup=reply_markup
                    )
                else:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="No ranges have been added."
                    )
            
            elif text.startswith(("/start", "/start@afrixivas_otpbot")):
                await bot.send_message(
                    chat_id=chat_id,
                    text=f"👋 Welcome, @{username}! (User ID: {user_id})\nUse /add_range to add ranges and numbers, /sync to sync from API (admin only), or /delete_all to return all numbers (admin only)."
                )
            
            elif text.startswith(("/list_ranges", "/list_ranges@afrixivas_otpbot")):
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This command is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted /list_ranges: User ID: {user_id}, Username: @{username}")
                    return
                if ranges:
                    keyboard = []
                    for r in ranges:
                        range_name = r["range"]
                        num_count = len(r["numbers"])
                        keyboard.append([InlineKeyboardButton(f"{range_name}: {num_count} numbers", callback_data=f"select_range_{range_name}")])
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    sent_message = await bot.send_message(
                        chat_id=chat_id,
                        text="📋 **Select a Range:**\nChoose from the ranges below.",
                        parse_mode="Markdown",
                        reply_markup=reply_markup
                    )
                    asyncio.create_task(auto_delete_message(chat_id, sent_message.message_id, 120))
                else:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="⚠️ No ranges found. Use /add_range or /sync."
                    )
            
            elif chat_id in pending_ranges and pending_ranges[chat_id].get("range") is not None:
                if not text:
                    logger.info("Empty message, skipping...")
                    return
                logger.info(f"Received text: '{text}' (length: {len(text)})")
                cleaned_text = text.strip()
                if cleaned_text in ["/add_range", "/add_range@afrixivas_otpbot"]:
                    if not is_admin(chat_id, user_id):
                        await bot.send_message(
                            chat_id=chat_id,
                            text=f"❌ This command is only for admins! (User ID: {user_id})"
                        )
                        logger.warning(f"Non-admin attempted /add_range in pending range: User ID: {user_id}, Username: @{username}")
                        return
                    logger.info(f"Resetting pending_ranges for chat_id {chat_id}: {pending_ranges[chat_id]}")
                    pending_ranges[chat_id] = {"range": None, "numbers": []}
                    await bot.send_message(
                        chat_id=chat_id,
                        text="Provide a range (e.g., BOLIVIA 1926)."
                    )
                    return
                numbers_input = text.split("\n")
                range_value = pending_ranges[chat_id]["range"]
                valid_numbers = []
                invalid_numbers = []
                for number in numbers_input:
                    number = str(number).strip()
                    if not number:
                        continue
                    if validate_phone_number(number):
                        valid_numbers.append(number)
                        pending_ranges[chat_id]["numbers"].append(number)
                        logger.info(f"Number added: {number}, Total numbers: {len(pending_ranges[chat_id]['numbers'])}")
                    else:
                        invalid_numbers.append(number)
                if valid_numbers:
                    existing_range = next((item for item in ranges if item["range"] == range_value), None)
                    if existing_range:
                        existing_range["numbers"].extend([num for num in valid_numbers if num not in existing_range["numbers"]])
                    else:
                        ranges.append({"range": range_value, "numbers": valid_numbers})
                    save_numbers_ranges(ranges)
                    valid_msg = f"✅ Numbers accepted: {', '.join(valid_numbers)}\nRange and numbers saved: {range_value} ({len(pending_ranges[chat_id]['numbers'])} numbers)\nProvide more numbers, or use /add_range for a new range."
                    await bot.send_message(chat_id=chat_id, text=valid_msg)
                if invalid_numbers:
                    invalid_msg = f"⚠️ Invalid numbers! Provide 7-15 digit numbers, optionally with '+'. Invalid: {', '.join(invalid_numbers)}"
                    await bot.send_message(chat_id=chat_id, text=invalid_msg)
                return
            elif chat_id in pending_ranges and pending_ranges[chat_id]["range"] is None:
                if not is_admin(chat_id, user_id):
                    await bot.send_message(
                        chat_id=chat_id,
                        text=f"❌ This action is only for admins! (User ID: {user_id})"
                    )
                    logger.warning(f"Non-admin attempted to set range: User ID: {user_id}, Username: @{username}")
                    return
                range_value = text.strip()
                if not range_value:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="⚠️ Range cannot be empty. Provide a valid range (e.g., KENYA 5544)."
                    )
                    return
                pending_ranges[chat_id]["range"] = range_value
                await bot.send_message(
                    chat_id=chat_id,
                    text=f"Range set: {range_value}\nNow provide numbers (one per line), or use /add_range for a new range."
                )
                logger.info(f"Range set for chat_id {chat_id}: {range_value}")

        elif update.callback_query:
            query = update.callback_query
            chat_id = query.message.chat.id
            user_id = query.from_user.id
            username = query.from_user.username or "Unknown"
            data = query.data
            logger.info(f"Callback query received: {data} | Chat ID: {chat_id} | User ID: {user_id} | Username: @{username} | Message ID: {query.message.message_id}")

            def is_admin(chat_id, user_id):
                return str(chat_id) == str(ADMIN_CHAT_ID) and user_id in ADMIN_USER_IDS

            if not is_admin(chat_id, user_id):
                await query.answer("❌ This action is only for admins!")
                logger.warning(f"Non-admin attempted callback: {data}, User ID: {user_id}, Username: @{username}")
                return

            try:
                ranges_data = numbers_ranges_ref.get() or {"ranges": []}
                ranges_data = ranges_data.get("ranges", [])
            except Exception as e:
                logger.error(f"Error loading ranges from Firebase: {str(e)}")
                ranges_data = []
                await query.answer("⚠️ No ranges found.")

            if data.startswith("select_range_"):
                range_name = data[len("select_range_"):]
                range_item = next((r for r in ranges_data if r["range"] == range_name), None)
                if not range_item:
                    await query.answer("⚠️ Range not found!")
                    return
                numbers = range_item["numbers"]
                num_count = len(numbers)
                formatted_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d %b %Y, %I:%M %p")
                
                message = (
                    f"📋 *Range Details*\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"🌍 *Range*: {range_name}\n"
                    f"🔢 *Total Numbers*: {num_count}\n"
                    f"🕒 *Updated*: {formatted_time}\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"Select an action below:"
                )
                
                keyboard = [
                    [
                        InlineKeyboardButton("📄 Copy Numbers", callback_data=f"copy_range_{range_name}"),
                        InlineKeyboardButton("📥 Download TXT", callback_data=f"download_range_{range_name}")
                    ],
                    [InlineKeyboardButton("⬅️ Back to Ranges", callback_data="back_to_ranges")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.message.edit_text(
                    text=message,
                    parse_mode="Markdown",
                    reply_markup=reply_markup
                )
                asyncio.create_task(auto_delete_message(chat_id, query.message.message_id, 120))
                await query.answer()
                logger.info(f"Range selected: {range_name}, Numbers: {num_count}")

            elif data.startswith("copy_range_"):
                range_name = data[len("copy_range_"):]
                range_item = next((r for r in ranges_data if r["range"] == range_name), None)
                if not range_item or not range_item["numbers"]:
                    await query.answer("⚠️ No numbers found!")
                    return
                numbers = range_item["numbers"]
                numbers_text = "\n".join(numbers)
                formatted_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d %b %Y, %I:%M %p")
                if len(numbers_text) > 4000:
                    numbers_text = numbers_text[:4000] + "\n...More numbers available for download"
                
                message = (
                    f"📄 *Copied Numbers*\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"🌍 *Range*: {range_name}\n"
                    f"🔢 *Total Numbers*: {len(numbers)}\n"
                    f"🕒 *Time*: {formatted_time}\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"```\n{numbers_text}\n```"
                )
                
                keyboard = [
                    [InlineKeyboardButton("⬅️ Back to Ranges", callback_data="back_to_ranges")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                sent_message = await bot.send_message(
                    chat_id=chat_id,
                    text=message,
                    parse_mode="Markdown",
                    reply_markup=reply_markup
                )
                asyncio.create_task(auto_delete_message(chat_id, sent_message.message_id, 120))
                await query.answer("✅ Numbers copied!")
                logger.info(f"Copied numbers for range: {range_name}, Count: {len(numbers)}")

            elif data.startswith("download_range_"):
                range_name = data[len("download_range_"):]
                range_item = next((r for r in ranges_data if r["range"] == range_name), None)
                if not range_item or not range_item["numbers"]:
                    await query.answer("⚠️ No numbers found!")
                    return
                numbers = range_item["numbers"]
                file_content = "\n".join(numbers)
                file_name = f"{range_name.replace(' ', '_')}_numbers.txt"
                file_io = StringIO(file_content)
                file_io.name = file_name
                formatted_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d %b %Y, %I:%M %p")
                
                try:
                    await bot.delete_message(
                        chat_id=chat_id,
                        message_id=query.message.message_id
                    )
                    logger.info(f"Deleted range message for download: Message ID {query.message.message_id}")
                except telegram.error.TelegramError as e:
                    logger.error(f"Error deleting range message: {str(e)}")
                
                caption = (
                    f"📥 *Downloaded Numbers*\n"
                    f"━━━━━━━━━━━━━━━\n"
                    f"🌍 *Range*: {range_name}\n"
                    f"🔢 *Total Numbers*: {len(numbers)}\n"
                    f"🕒 *Time*: {formatted_time}\n"
                    f"━━━━━━━━━━━━━━━"
                )
                
                sent_message = await bot.send_document(
                    chat_id=chat_id,
                    document=file_io,
                    caption=caption,
                    parse_mode="Markdown"
                )
                asyncio.create_task(auto_delete_message(chat_id, sent_message.message_id, 18000))
                await query.answer("✅ TXT file downloaded!")
                logger.info(f"Sent TXT file for range: {range_name}, Count: {len(numbers)}")

            elif data == "back_to_ranges":
                formatted_time = datetime.now(pytz.timezone('Asia/Dhaka')).strftime("%d %b %Y, %I:%M %p")
                if ranges_data:
                    keyboard = []
                    for r in ranges_data:
                        range_name = r["range"]
                        num_count = len(r["numbers"])
                        keyboard.append([InlineKeyboardButton(f"🌍 {range_name} ({num_count} numbers)", callback_data=f"select_range_{range_name}")])
                    reply_markup = InlineKeyboardMarkup(keyboard)
                    message = (
                        f"📋 *Range Selection*\n"
                        f"━━━━━━━━━━━━━━━\n"
                        f"🔢 *Total Ranges*: {len(ranges_data)}\n"
                        f"🕒 *Updated*: {formatted_time}\n"
                        f"━━━━━━━━━━━━━━━\n"
                        f"Select a range below:"
                    )
                    await query.message.edit_text(
                        text=message,
                        parse_mode="Markdown",
                        reply_markup=reply_markup
                    )
                    asyncio.create_task(auto_delete_message(chat_id, query.message.message_id, 120))
                else:
                    message = (
                        f"⚠️ *No Ranges Available*\n"
                        f"━━━━━━━━━━━━━━━\n"
                        f"ℹ️ Use /add_range or /sync to add ranges.\n"
                        f"🕒 *Time*: {formatted_time}\n"
                        f"━━━━━━━━━━━━━━━"
                    )
                    await query.message.edit_text(
                        text=message,
                        parse_mode="Markdown"
                    )
                await query.answer()

            elif data == "sync_now":
                logger.info(f"Sync Now callback triggered by User ID: {user_id}, Username: @{username}, Message ID: {query.message.message_id}")
                await bot.send_message(
                    chat_id=chat_id,
                    text="🔄 Syncing numbers and ranges from API..."
                )
                success = await sync_numbers_from_api(session, csrf_token, chat_id)
                if not success:
                    await bot.send_message(
                        chat_id=chat_id,
                        text="❌ Synchronization failed! Check logs for details."
                    )
                await query.answer()

            elif data == "delete_all":
                success = await return_numbers(session, csrf_token)
                if success == "SESSION_EXPIRED":
                    logger.info("Session expired during delete_all, re-logging in...")
                    session, csrf_token = await login_and_get_csrf(session)
                    if not session or not csrf_token:
                        await query.message.edit_text("❌ Failed to re-login! Check logs for details.")
                        await query.answer()
                        return
                    success = await return_numbers(session, csrf_token)
                if success:
                    numbers_ranges_ref.set({"ranges": []})
                    await query.message.edit_text("✅ All numbers returned and cleared from database!")
                    logger.info(f"All numbers returned by User ID: {user_id}, Username: @{username}")
                else:
                    await query.message.edit_text("❌ Failed to return all numbers! Check logs for details.")
                await query.answer()

            elif data == "cancel_delete":
                await query.message.edit_text("❌ Action cancelled.")
                await query.answer()

            elif data.startswith("remove_"):
                range_value = data[len("remove_"):]
                keyboard = [
                    [InlineKeyboardButton("Yes, Return Range", callback_data=f"confirm_delete_range_{range_value}")],
                    [InlineKeyboardButton("No, Cancel", callback_data="cancel_delete")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.message.edit_text(
                    text=f"Are you sure you want to return the range '{range_value}'?",
                    reply_markup=reply_markup
                )
                await query.answer()

            elif data.startswith("confirm_delete_range_"):
                range_value = data[len("confirm_delete_range_"):]
                success = await return_numbers(session, csrf_token, range_value)
                if success == "SESSION_EXPIRED":
                    logger.info("Session expired during range delete, re-logging in...")
                    session, csrf_token = await login_and_get_csrf(session)
                    if not session or not csrf_token:
                        await query.message.edit_text("❌ Failed to re-login! Check logs for details.")
                        await query.answer()
                        return
                    success = await return_numbers(session, csrf_token, range_value)
                if success:
                    ranges_data = [r for r in ranges_data if r["range"] != range_value]
                    save_numbers_ranges(ranges_data)
                    await query.message.edit_text(f"✅ Range '{range_value}' returned and deleted!")
                    logger.info(f"Range {range_value} returned by User ID: {user_id}, Username: @{username}")
                else:
                    await query.message.edit_text(f"❌ Failed to return range '{range_value}'! Check logs for details.")
                await query.answer()

    except Exception as e:
        error_msg = f"❌ Error processing bot update: {str(e)}"
        logger.error(error_msg)
        await send_telegram_message(error_msg, chat_id)

async def auto_delete_message(chat_id, message_id, delay):
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(
            chat_id=chat_id,
            message_id=message_id
        )
        logger.info(f"Auto-deleted message: Chat ID {chat_id}, Message ID {message_id}")
    except telegram.error.TelegramError as e:
        logger.error(f"Error auto-deleting message: Chat ID {chat_id}, Message ID {message_id}, Error: {str(e)}")

async def main():
    logger.info("Starting bot main loop...")
    async with aiohttp.ClientSession() as session:
        try:
            session, csrf_token = await login_and_get_csrf(session)
            if not session or not csrf_token:
                logger.error("Login failed, stopping bot...")
                return
            
            await send_startup_alert()
            load_seen_sms()
            
            asyncio.create_task(auto_clean_log())
            asyncio.create_task(auto_sync(session, csrf_token))
            asyncio.create_task(wait_for_sms(session, csrf_token))
            
            last_update_id = None
            while True:
                try:
                    updates = await bot.get_updates(offset=last_update_id, timeout=30)
                    for update in updates:
                        last_update_id = update.update_id + 1
                        await handle_bot_updates(update, session, csrf_token)
                    await asyncio.sleep(1)
                except telegram.error.NetworkError as e:
                    logger.error(f"Telegram network error: {str(e)}")
                    await asyncio.sleep(5)
                except Exception as e:
                    logger.error(f"Main loop error: {str(e)}")
                    await send_telegram_message(f"❌ Main loop error: {str(e)}", CHAT_ID)
                    await asyncio.sleep(5)
                    
        except Exception as e:
            logger.error(f"Error starting bot: {str(e)}")
            await send_telegram_message(f"❌ Error starting bot: {str(e)}", CHAT_ID)

if __name__ == "__main__":
    asyncio.run(main())
