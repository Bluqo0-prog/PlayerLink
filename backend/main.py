
import os
import re
import secrets
import hashlib
import hmac
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import escape
from urllib.parse import urlencode

import asyncpg
import httpx

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from starlette.middleware.sessions import SessionMiddleware


# ============================================================
# PLAYERLINK v0.9
# Discord login + protected Minecraft lookup + Postgres cache
# ============================================================

VERSION = "0.9"

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

DISCORD_API = "https://discord.com/api/v10"

REDIRECT_URI = (
    "https://playerlink.onrender.com/api/auth/discord/callback"
)

WEBSITE = "https://bluqo0-prog.github.io/PlayerLink/web/"

DISCORD_SCOPES = "identify guilds guilds.members.read"

SEARCH_COOLDOWN_SECONDS = 30
SEARCHES_PER_HOUR = 20
PROFILE_CACHE_HOURS = 24
NOT_FOUND_CACHE_MINUTES = 5

MINECRAFT_NAME = re.compile(r"^[A-Za-z0-9_]{3,16}$")
MINECRAFT_UUID = re.compile(r"^[0-9a-fA-F]{32}$")

USER_AGENT = "PlayerLink/0.9"


if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "SESSION_SECRET must be at least 32 characters."
    )

if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is missing from Render Environment."
    )


def utcnow():
    return datetime.now(timezone.utc)


def visitor_key(request: Request):
    # Hash the network address instead of saving it directly.
    # People on the same network may share a search limit.
    address = request.client.host if request.client else "unknown"

    return hmac.new(
        SESSION_SECRET.encode(),
        address.encode(),
        hashlib.sha256,
    ).hexdigest()


def avatar_url(uuid):
    return f"https://mc-heads.net/avatar/{uuid}/100"


# ============================================================
# DATABASE SETUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    pool = await asyncpg.create_pool(
        dsn=DATABASE_URL,
        min_size=1,
        max_size=3,
        command_timeout=15,
    )

    app.state.db = pool

    try:
        async with pool.acquire() as conn:

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS minecraft_cache (
                    lookup_name TEXT PRIMARY KEY,
                    username TEXT,
                    uuid TEXT,
                    found BOOLEAN NOT NULL,
                    source TEXT,
                    checked_at TIMESTAMPTZ NOT NULL
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS search_limits (
                    visitor_key TEXT PRIMARY KEY,
                    window_start TIMESTAMPTZ NOT NULL,
                    search_count INTEGER NOT NULL,
                    last_search TIMESTAMPTZ NOT NULL
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS provider_cooldowns (
                    provider TEXT PRIMARY KEY,
                    retry_after TIMESTAMPTZ NOT NULL
                )
            """)

        yield

    finally:
        await pool.close()


app = FastAPI(
    title="PlayerLink API",
    version=VERSION,
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://bluqo0-prog.github.io"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="playerlink_session",
    https_only=True,
    same_site="lax",
    max_age=86400,
)


# ============================================================
# HEALTH CHECKS
# ============================================================

@app.get("/")
async def home():
    return {
        "name": "PlayerLink",
        "version": VERSION,
        "status": "online",
        "discord_configured": bool(
            DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET
        ),
        "minecraft_lookup": "enabled",
    }


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": VERSION,
    }


@app.get("/api/database/health")
async def database_health(request: Request):

    try:
        async with request.app.state.db.acquire() as conn:
            value = await conn.fetchval("SELECT 1")

        return {
            "database": "connected" if value == 1 else "error",
            "version": VERSION,
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database connection unavailable.",
        )


# ============================================================
# SEARCH COOLDOWN
# ============================================================

async def enforce_search_limit(request: Request):

    key = visitor_key(request)
    now = utcnow()

    async with request.app.state.db.acquire() as conn:
        async with conn.transaction():

            await conn.execute("""
                INSERT INTO search_limits (
                    visitor_key,
                    window_start,
                    search_count,
                    last_search
                )
                VALUES ($1, $2, 0, $2)
                ON CONFLICT (visitor_key) DO NOTHING
            """, key, now)

            row = await conn.fetchrow("""
                SELECT *
                FROM search_limits
                WHERE visitor_key = $1
                FOR UPDATE
            """, key)

            if now - row["window_start"] >= timedelta(hours=1):
                count = 0
                window_start = now
            else:
                count = row["search_count"]
                window_start = row["window_start"]

            if count > 0:

                elapsed = (
                    now - row["last_search"]
                ).total_seconds()

                if elapsed < SEARCH_COOLDOWN_SECONDS:

                    remaining = max(
                        1,
                        int(SEARCH_COOLDOWN_SECONDS - elapsed) + 1,
                    )

                    raise HTTPException(
                        status_code=429,
                        detail="Please wait before searching again.",
                        headers={"Retry-After": str(remaining)},
                    )

            if count >= SEARCHES_PER_HOUR:

                remaining = max(
                    1,
                    int(
                        (
                            row["window_start"] + timedelta(hours=1)
                            - now
                        ).total_seconds()
                    ) + 1,
                )

                raise HTTPException(
                    status_code=429,
                    detail="Hourly search limit reached.",
                    headers={"Retry-After": str(remaining)},
                )

            await conn.execute("""
                UPDATE search_limits
                SET window_start = $2,
                    search_count = $3,
                    last_search = $4
                WHERE visitor_key = $1
            """, key, window_start, count + 1, now)


# ============================================================
# CACHE
# ============================================================

async def get_cached(conn, lookup_name):

    return await conn.fetchrow("""
        SELECT *
        FROM minecraft_cache
        WHERE lookup_name = $1
    """, lookup_name)


def cache_is_fresh(row):

    if not row:
        return False

    duration = (
        timedelta(hours=PROFILE_CACHE_HOURS)
        if row["found"]
        else timedelta(minutes=NOT_FOUND_CACHE_MINUTES)
    )

    return utcnow() - row["checked_at"] < duration


def format_cached(row, stale=False):

    if not row["found"]:
        return JSONResponse(
            status_code=404,
            content={
                "detail": "Minecraft username not found."
            },
        )

    return {
        "username": row["username"],
        "uuid": row["uuid"],
        "avatar_url": avatar_url(row["uuid"]),
        "source": row["source"],
        "cached": True,
        "stale": stale,
    }


async def save_cache(
    conn,
    lookup_name,
    username=None,
    uuid=None,
    source=None,
    found=True,
):

    await conn.execute("""
        INSERT INTO minecraft_cache (
            lookup_name,
            username,
            uuid,
            found,
            source,
            checked_at
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (lookup_name)
        DO UPDATE SET
            username = EXCLUDED.username,
            uuid = EXCLUDED.uuid,
            found = EXCLUDED.found,
            source = EXCLUDED.source,
            checked_at = EXCLUDED.checked_at
    """,
        lookup_name,
        username,
        uuid,
        found,
        source,
        utcnow(),
    )


# ============================================================
# EXTERNAL PROVIDER COOLDOWNS
# ============================================================

async def provider_is_available(conn, provider):

    retry_after = await conn.fetchval("""
        SELECT retry_after
        FROM provider_cooldowns
        WHERE provider = $1
    """, provider)

    return retry_after is None or retry_after <= utcnow()


async def pause_provider(conn, provider, response):

    raw = response.headers.get("Retry-After", "60")

    try:
        wait_seconds = int(raw)
    except ValueError:
        try:
            retry_date = parsedate_to_datetime(raw)
            wait_seconds = int(
                (retry_date - utcnow()).total_seconds()
            ) + 1
        except (TypeError, ValueError, OverflowError):
            wait_seconds = 60

    wait_seconds = max(30, min(wait_seconds, 3600))

    await conn.execute("""
        INSERT INTO provider_cooldowns (
            provider,
            retry_after
        )
        VALUES ($1, $2)
        ON CONFLICT (provider)
        DO UPDATE SET retry_after = EXCLUDED.retry_after
    """,
        provider,
        utcnow() + timedelta(seconds=wait_seconds),
    )


# ============================================================
# OFFICIAL MINECRAFT LOOKUP + PLAYERDB BACKUP
# ============================================================

async def lookup_minecraft(conn, username):

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    async with httpx.AsyncClient(
        timeout=8.0,
        headers=headers,
    ) as client:

        # PRIMARY: Official Minecraft Services

        if await provider_is_available(conn, "minecraft"):

            try:
                response = await client.get(
                    "https://api.minecraftservices.com"
                    "/minecraft/profile/lookup/name/"
                    + username
                )

                if response.status_code == 200:

                    data = response.json()

                    name = data.get("name")
                    uuid = str(data.get("id", "")).replace("-", "")

                    if (
                        isinstance(name, str)
                        and MINECRAFT_NAME.fullmatch(name)
                        and MINECRAFT_UUID.fullmatch(uuid)
                    ):
                        return {
                            "username": name,
                            "uuid": uuid.lower(),
                            "source": "minecraft",
                        }

                elif response.status_code == 404:
                    return {"not_found": True}

                elif response.status_code == 429:
                    await pause_provider(
                        conn,
                        "minecraft",
                        response,
                    )

            except (httpx.RequestError, ValueError, AttributeError):
                pass

        # BACKUP: PlayerDB

        if await provider_is_available(conn, "playerdb"):

            try:
                response = await client.get(
                    "https://playerdb.co/api/player/minecraft/"
                    + username
                )

                if response.status_code == 429:

                    await pause_provider(
                        conn,
                        "playerdb",
                        response,
                    )

                elif response.status_code == 200:

                    data = response.json()

                    if data.get("code") == "player.found":

                        player = data.get(
                            "data", {}
                        ).get("player", {})

                        name = player.get("username")

                        uuid = str(
                            player.get("raw_id")
                            or player.get("id", "")
                        ).replace("-", "")

                        if (
                            isinstance(name, str)
                            and MINECRAFT_NAME.fullmatch(name)
                            and MINECRAFT_UUID.fullmatch(uuid)
                        ):
                            return {
                                "username": name,
                                "uuid": uuid.lower(),
                                "source": "playerdb",
                            }

                    elif data.get("success") is False:
                        return {"not_found": True}

            except (httpx.RequestError, ValueError, AttributeError):
                pass

    return {"unavailable": True}


# ============================================================
# MINECRAFT SEARCH API
# ============================================================

@app.get("/api/minecraft/player/{username}")
async def minecraft_player(
    username: str,
    request: Request,
):

    username = username.strip()

    if not MINECRAFT_NAME.fullmatch(username):
        raise HTTPException(
            status_code=400,
            detail=(
                "Enter a valid Minecraft Java username "
                "(3–16 letters, numbers, or underscores)."
            ),
        )

    await enforce_search_limit(request)

    lookup_name = username.lower()

    async with request.app.state.db.acquire() as conn:

        row = await get_cached(conn, lookup_name)

        if cache_is_fresh(row):
            return format_cached(row)

        # Only one lookup for a particular username at a time.
        async with conn.transaction():

            await conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext($1))",
                lookup_name,
            )

            row = await get_cached(conn, lookup_name)

            if cache_is_fresh(row):
                return format_cached(row)

            result = await lookup_minecraft(conn, username)

            if result.get("not_found"):

                await save_cache(
                    conn,
                    lookup_name,
                    found=False,
                    source="minecraft",
                )

                return JSONResponse(
                    status_code=404,
                    content={
                        "detail": "Minecraft username not found."
                    },
                )

            if result.get("unavailable"):

                if row and row["found"]:
                    return format_cached(row, stale=True)

                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": (
                            "Minecraft lookup is temporarily "
                            "unavailable. Please try again later."
                        )
                    },
                )

            await save_cache(
                conn,
                lookup_name,
                username=result["username"],
                uuid=result["uuid"],
                source=result["source"],
                found=True,
            )

            return {
                "username": result["username"],
                "uuid": result["uuid"],
                "avatar_url": avatar_url(result["uuid"]),
                "source": result["source"],
                "cached": False,
                "stale": False,
            }


# ============================================================
# DISCORD LOGIN — EXISTING WORKING FLOW
# ============================================================

@app.get("/api/auth/discord/login")
async def discord_login(request: Request):

    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Discord login is not configured.",
        )

    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": DISCORD_SCOPES,
        "state": state,
        "prompt": "consent",
    }

    return RedirectResponse(
        "https://discord.com/oauth2/authorize?"
        + urlencode(params),
        status_code=302,
    )


@app.get("/api/auth/discord/callback")
async def discord_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
):

    if error:
        raise HTTPException(
            status_code=400,
            detail="Discord authorization was canceled or denied.",
        )

    expected_state = request.session.pop(
        "oauth_state",
        None,
    )

    if (
        not expected_state
        or not state
        or not secrets.compare_digest(
            expected_state,
            state,
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid Discord login state.",
        )

    if not code:
        raise HTTPException(
            status_code=400,
            detail="Discord did not return an authorization code.",
        )

    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Discord login is not configured.",
        )

    token_payload = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:

            token_response = await client.post(
                f"{DISCORD_API}/oauth2/token",
                data=token_payload,
                headers={
                    "Content-Type":
                        "application/x-www-form-urlencoded"
                },
            )

            if token_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail="Discord authorization failed.",
                )

            token_data = token_response.json()
            access_token = token_data.get("access_token")

            if not access_token:
                raise HTTPException(
                    status_code=502,
                    detail="Discord did not return an access token.",
                )

            headers = {
                "Authorization": f"Bearer {access_token}"
            }

            user_response = await client.get(
                f"{DISCORD_API}/users/@me",
                headers=headers,
            )

            guild_response = await client.get(
                f"{DISCORD_API}/users/@me/guilds",
                headers=headers,
            )

            if (
                user_response.status_code != 200
                or guild_response.status_code != 200
            ):
                raise HTTPException(
                    status_code=502,
                    detail="Could not retrieve Discord account.",
                )

            user = user_response.json()
            guilds = guild_response.json()

            if not isinstance(guilds, list):
                raise HTTPException(
                    status_code=502,
                    detail="Invalid Discord server response.",
                )

    except httpx.RequestError:
        raise HTTPException(
            status_code=502,
            detail="Discord is temporarily unreachable.",
        )

    # Keep OAuth tokens out of browser cookies.
    request.session["user"] = {
        "id": str(user.get("id", "")),
        "username": str(user.get("username", "")),
        "avatar": user.get("avatar"),
        "guild_count": len(guilds),
    }

    return RedirectResponse(
        "/api/auth/discord/profile",
        status_code=302,
    )


# ============================================================
# DISCORD PROFILE
# ============================================================

@app.get(
    "/api/auth/discord/profile",
    response_class=HTMLResponse,
)
async def discord_profile(request: Request):

    user = request.session.get("user")

    if not user:

        return HTMLResponse("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1">
                <title>PlayerLink — Sign In</title>
                <style>
                    body {
                        background: #0b1020;
                        color: white;
                        font-family: Arial, sans-serif;
                        text-align: center;
                        padding: 70px 20px;
                    }
                    a {
                        display: inline-block;
                        padding: 14px 20px;
                        background: #5865f2;
                        color: white;
                        border-radius: 10px;
                        text-decoration: none;
                    }
                </style>
            </head>
            <body>
                <h1>PlayerLink 💜</h1>
                <p>Connect your Discord account.</p>
                <a href="/api/auth/discord/login">
                    Connect Discord
                </a>
            </body>
            </html>
        """)

    username = escape(str(user.get("username", "")))
    discord_id = escape(str(user.get("id", "")))
    guild_count = escape(str(user.get("guild_count", 0)))

    return HTMLResponse(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">
            <title>PlayerLink — Profile</title>
            <style>
                * {{ box-sizing: border-box; }}
                body {{
                    background: #0b1020;
                    color: white;
                    font-family: Arial, sans-serif;
                    padding: 60px 20px;
                }}
                .card {{
                    max-width: 580px;
                    margin: auto;
                    padding: 35px;
                    background: #172236;
                    border: 1px solid #34445e;
                    border-radius: 16px;
                }}
                h1 {{ color: #a5b4ff; }}
                .success {{ color: #4ade80; }}
                .row {{
                    padding: 15px 0;
                    border-bottom: 1px solid #34445e;
                    overflow-wrap: anywhere;
                }}
                .label {{
                    color: #a5b4cc;
                    font-size: 12px;
                    display: block;
                    margin-bottom: 7px;
                }}
                p {{
                    color: #a5b4cc;
                    line-height: 1.7;
                }}
                a {{
                    display: inline-block;
                    padding: 13px 18px;
                    margin: 10px 8px 0 0;
                    background: #5865f2;
                    color: white;
                    text-decoration: none;
                    border-radius: 10px;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <h1>PlayerLink 💜</h1>
                <p class="success">✓ Discord Connected!</p>
                <h2>{username}</h2>

                <div class="row">
                    <span class="label">Discord ID</span>
                    {discord_id}
                </div>

                <div class="row">
                    <span class="label">Authorized servers</span>
                    {guild_count}
                </div>

                <p>
                    Your Discord login is working.
                    PlayerLink v0.9 also includes protected
                    Minecraft search and a shared database cache.
                </p>

                <a href="{WEBSITE}">Back to PlayerLink</a>
                <a href="/api/auth/logout">Sign Out</a>
            </div>
        </body>
        </html>
    """)


@app.get("/api/auth/me")
async def auth_me(request: Request):

    user = request.session.get("user")

    if not user:
        return {
            "authenticated": False,
            "user": None,
        }

    return {
        "authenticated": True,
        "user": user,
    }


@app.get("/api/auth/logout")
async def auth_logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        WEBSITE,
        status_code=302,
    )
