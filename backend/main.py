
import os
import secrets
from html import escape
from urllib.parse import urlencode

import httpx

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware


# ==========================================
# PLAYERLINK CONFIGURATION
# ==========================================

CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")

DISCORD_API = "https://discord.com/api/v10"

REDIRECT_URI = (
    "https://playerlink.onrender.com"
    "/api/auth/discord/callback"
)

WEBSITE = (
    "https://bluqo0-prog.github.io"
    "/PlayerLink/web/"
)

if not SESSION_SECRET or len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "Set a secure SESSION_SECRET in Render."
    )


# ==========================================
# CREATE API
# ==========================================

app = FastAPI(
    title="PlayerLink API",
    version="0.7.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bluqo0-prog.github.io"
    ],
    allow_methods=["GET"],
    allow_headers=["*"]
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="playerlink_session",
    https_only=True,
    same_site="lax",
    max_age=86400
)


# ==========================================
# HEALTH ENDPOINTS
# ==========================================

@app.get("/")
def home():

    return {
        "name": "PlayerLink",
        "version": "0.7",
        "status": "online",
        "discord_configured": bool(
            CLIENT_ID and CLIENT_SECRET
        )
    }


@app.get("/api/health")
def health():

    return {
        "status": "healthy"
    }


# ==========================================
# DISCORD LOGIN
# ==========================================

@app.get("/api/auth/discord/login")
def discord_login(request: Request):

    if not CLIENT_ID or not CLIENT_SECRET:

        raise HTTPException(
            status_code=503,
            detail="Discord OAuth is not configured."
        )

    state = secrets.token_urlsafe(32)

    request.session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state
    }

    authorization_url = (
        "https://discord.com/oauth2/authorize?"
        + urlencode(params)
    )

    return RedirectResponse(
        authorization_url,
        status_code=302
    )


# ==========================================
# DISCORD CALLBACK
# ==========================================

@app.get("/api/auth/discord/callback")
async def discord_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = ""
):

    expected_state = request.session.pop(
        "oauth_state",
        None
    )

    if error:

        raise HTTPException(
            status_code=400,
            detail="Discord authorization was cancelled."
        )

    if (
        not code
        or not state
        or not expected_state
        or not secrets.compare_digest(
            state,
            expected_state
        )
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid Discord login state."
        )

    async with httpx.AsyncClient(
        timeout=15
    ) as client:

        # Exchange authorization code for token.

        token_response = await client.post(
            DISCORD_API + "/oauth2/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI
            },
            headers={
                "Content-Type":
                "application/x-www-form-urlencoded"
            }
        )

        if token_response.status_code != 200:

            raise HTTPException(
                status_code=502,
                detail="Discord token exchange failed."
            )

        token_data = token_response.json()

        access_token = token_data["access_token"]

        authorization_headers = {
            "Authorization":
            f"Bearer {access_token}"
        }

        # Get the signed-in Discord user.

        user_response = await client.get(
            DISCORD_API + "/users/@me",
            headers=authorization_headers
        )

        if user_response.status_code != 200:

            raise HTTPException(
                status_code=502,
                detail="Could not retrieve Discord profile."
            )

        # Get their authorized Discord servers.

        guild_response = await client.get(
            DISCORD_API + "/users/@me/guilds",
            headers=authorization_headers
        )

        if guild_response.status_code != 200:

            raise HTTPException(
                status_code=502,
                detail="Could not retrieve Discord servers."
            )

        user = user_response.json()

        guilds = guild_response.json()

    # Store basic user information.
    # Never store the OAuth access token in the cookie.

    request.session.clear()

    request.session["user"] = {
        "id": user["id"],
        "username": user["username"],
        "avatar": user.get("avatar"),
        "guild_count": len(guilds)
    }

    return RedirectResponse(
        "/api/auth/discord/profile",
        status_code=303
    )


# ==========================================
# CURRENT USER
# ==========================================

@app.get("/api/auth/me")
def current_user(request: Request):

    user = request.session.get("user")

    if not user:

        return {
            "authenticated": False,
            "user": None
        }

    return {
        "authenticated": True,
        "user": user
    }


# ==========================================
# DISCORD PROFILE PAGE
# ==========================================

@app.get(
    "/api/auth/discord/profile",
    response_class=HTMLResponse
)
def discord_profile(request: Request):

    user = request.session.get("user")

    if not user:

        return RedirectResponse(
            "/api/auth/discord/login"
        )

    username = escape(user["username"])

    user_id = escape(user["id"])

    guild_count = int(user["guild_count"])

    return HTMLResponse(f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1">

<title>PlayerLink | Discord Connected</title>

<style>

body {{
    background: #0b1020;
    color: white;
    font-family: Arial, sans-serif;
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
}}

.card {{
    width: min(420px, 90%);
    background: #182235;
    border: 1px solid #34445e;
    border-radius: 18px;
    padding: 35px;
    text-align: center;
}}

h1 {{
    color: #818cf8;
}}

p {{
    color: #a5b4cc;
}}

a {{
    display: block;
    margin-top: 15px;
    padding: 14px;
    background: #5865f2;
    border-radius: 9px;
    color: white;
    text-decoration: none;
    font-weight: bold;
}}

.logout {{
    background: #34445e;
}}

</style>

</head>

<body>

<div class="card">

<h1>PlayerLink</h1>

<h2>Discord Connected!</h2>

<p>Signed in as</p>

<h2>{username}</h2>

<p>Discord ID: {user_id}</p>

<p>Authorized servers: {guild_count}</p>

<p>Your Discord account is connected for this session.</p>

<a href="{WEBSITE}">
Return to PlayerLink
</a>

<a class="logout" href="/api/auth/logout">
Sign Out
</a>

</div>

</body>
</html>
""")


# ==========================================
# LOGOUT
# ==========================================

@app.get("/api/auth/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        WEBSITE,
        status_code=303
    )
