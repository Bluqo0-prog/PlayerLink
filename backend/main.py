
import os
import secrets
from html import escape
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware


# ============================================================
# PLAYERLINK v0.8
# Discord OAuth + future server role support
# ============================================================

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET", "")

DISCORD_API = "https://discord.com/api/v10"

REDIRECT_URI = (
    "https://playerlink.onrender.com/api/auth/discord/callback"
)

WEBSITE = "https://bluqo0-prog.github.io/PlayerLink/web/"

# Updated authorization permissions:
# identify = identify the signed-in Discord user
# guilds = retrieve their authorized server list
# guilds.members.read = access their own server membership data

DISCORD_SCOPES = "identify guilds guilds.members.read"


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "SESSION_SECRET is missing or too short. "
        "Set a random value of at least 32 characters "
        "in Render Environment."
    )


app = FastAPI(
    title="PlayerLink API",
    version="0.8",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bluqo0-prog.github.io",
    ],
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
# HOME / HEALTH
# ============================================================

@app.get("/")
async def home():
    return {
        "name": "PlayerLink",
        "version": "0.8",
        "status": "online",
        "discord_configured": bool(
            DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET
        ),
    }


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "0.8",
    }


# ============================================================
# DISCORD LOGIN
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

    parameters = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": DISCORD_SCOPES,
        "state": state,
        "prompt": "consent",
    }

    authorization_url = (
        "https://discord.com/oauth2/authorize?"
        + urlencode(parameters)
    )

    return RedirectResponse(
        url=authorization_url,
        status_code=302,
    )


# ============================================================
# DISCORD CALLBACK
# ============================================================

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
            detail="Invalid Discord login state. Please try again.",
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
        async with httpx.AsyncClient(
            timeout=15.0
        ) as client:

            # Exchange the authorization code for a token.
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
                    detail=(
                        "Discord could not complete authorization. "
                        "Please try connecting again."
                    ),
                )

            token_data = token_response.json()

            access_token = token_data.get(
                "access_token"
            )

            if not access_token:
                raise HTTPException(
                    status_code=502,
                    detail="Discord did not return an access token.",
                )

            headers = {
                "Authorization": f"Bearer {access_token}"
            }

            # Retrieve the signed-in Discord user.
            user_response = await client.get(
                f"{DISCORD_API}/users/@me",
                headers=headers,
            )

            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail="Could not retrieve Discord account.",
                )

            user = user_response.json()

            # Retrieve their authorized server list.
            guild_response = await client.get(
                f"{DISCORD_API}/users/@me/guilds",
                headers=headers,
            )

            if guild_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail="Could not retrieve authorized servers.",
                )

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

    # Store only a small amount of account information
    # in the signed session cookie.
    #
    # Never store OAuth access tokens or refresh tokens
    # in the browser cookie.
    #
    # Protected server-side storage will be added later
    # for the verified player directory and role lookup.

    request.session["user"] = {
        "id": str(user.get("id", "")),
        "username": str(user.get("username", "")),
        "avatar": user.get("avatar"),
        "guild_count": len(guilds),
    }

    return RedirectResponse(
        url="/api/auth/discord/profile",
        status_code=302,
    )


# ============================================================
# DISCORD PROFILE PAGE
# ============================================================

@app.get(
    "/api/auth/discord/profile",
    response_class=HTMLResponse,
)
async def discord_profile(request: Request):

    user = request.session.get("user")

    if not user:
        return HTMLResponse(
            content="""
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

                    .card {
                        max-width: 500px;
                        margin: auto;
                        padding: 35px;
                        border-radius: 16px;
                        background: #172236;
                        border: 1px solid #34445e;
                    }

                    a {
                        display: inline-block;
                        margin-top: 15px;
                        padding: 13px 20px;
                        border-radius: 10px;
                        background: #5865f2;
                        color: white;
                        text-decoration: none;
                        font-weight: bold;
                    }

                    p {
                        color: #a5b4cc;
                    }
                </style>
            </head>

            <body>
                <div class="card">
                    <h1>PlayerLink 💜</h1>

                    <h2>Connect your Discord</h2>

                    <p>
                        Sign in to view your Discord account.
                    </p>

                    <a href="/api/auth/discord/login">
                        Connect Discord
                    </a>
                </div>
            </body>

            </html>
            """,
            status_code=200,
        )

    username = escape(
        str(user.get("username", ""))
    )

    discord_id = escape(
        str(user.get("id", ""))
    )

    guild_count = escape(
        str(user.get("guild_count", 0))
    )

    return HTMLResponse(
        content=f"""
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1">

            <title>PlayerLink — Discord Profile</title>

            <style>
                * {{
                    box-sizing: border-box;
                }}

                body {{
                    margin: 0;
                    background: #0b1020;
                    color: white;
                    font-family: Arial, sans-serif;
                    padding: 65px 20px;
                }}

                .card {{
                    max-width: 580px;
                    margin: auto;
                    padding: 35px;
                    border-radius: 17px;
                    background: #172236;
                    border: 1px solid #34445e;
                }}

                h1 {{
                    margin-top: 0;
                    color: #a5b4ff;
                }}

                h2 {{
                    overflow-wrap: anywhere;
                }}

                .success {{
                    color: #4ade80;
                    font-weight: bold;
                }}

                .row {{
                    padding: 15px 0;
                    border-bottom: 1px solid #34445e;
                    overflow-wrap: anywhere;
                }}

                .label {{
                    display: block;
                    color: #a5b4cc;
                    font-size: 12px;
                    margin-bottom: 7px;
                }}

                .notice {{
                    color: #a5b4cc;
                    font-size: 13px;
                    line-height: 1.7;
                    margin-top: 22px;
                }}

                a {{
                    display: inline-block;
                    margin: 15px 10px 0 0;
                    padding: 13px 17px;
                    border-radius: 10px;
                    background: #5865f2;
                    color: white;
                    text-decoration: none;
                    font-weight: bold;
                    font-size: 14px;
                }}

                a.secondary {{
                    background: #27344c;
                }}
            </style>
        </head>

        <body>
            <div class="card">

                <h1>PlayerLink 💜</h1>

                <p class="success">
                    ✓ Discord Connected!
                </p>

                <h2>{username}</h2>

                <div class="row">
                    <span class="label">
                        Discord username
                    </span>

                    <strong>{username}</strong>
                </div>

                <div class="row">
                    <span class="label">
                        Discord ID
                    </span>

                    <strong>{discord_id}</strong>
                </div>

                <div class="row">
                    <span class="label">
                        Authorized servers
                    </span>

                    <strong>{guild_count}</strong>
                </div>

                <p class="notice">
                    Your Discord account is connected.

                    PlayerLink now requests permission to read
                    your own server membership information.

                    Live role lookup, Minecraft verification,
                    and Friends in Server are coming in
                    future backend updates.
                </p>

                <a href="{WEBSITE}">
                    Back to PlayerLink
                </a>

                <a
                    class="secondary"
                    href="/api/auth/logout"
                >
                    Sign Out
                </a>

            </div>
        </body>

        </html>
        """
    )


# ============================================================
# SESSION STATUS
# ============================================================

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


# ============================================================
# LOGOUT
# ============================================================

@app.get("/api/auth/logout")
async def auth_logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        url=WEBSITE,
        status_code=302,
    )
