
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="PlayerLink API",
    version="0.6.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bluqo0-prog.github.io"
    ],
    allow_methods=["GET"],
    allow_headers=["*"]
)

@app.get("/")
def home():
    return {
        "name": "PlayerLink",
        "version": "0.6",
        "status": "online",
        "message": "PlayerLink backend is running!"
    }

@app.get("/api/health")
def health():
    return {"status": "healthy"}


# PLAYERLINK TEST 123
