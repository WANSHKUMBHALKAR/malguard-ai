import os
from pathlib import Path
from dotenv import load_dotenv
from supabase import create_client, Client

# Load .env from the project root
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

supabase_url = os.getenv("NEXT_PUBLIC_SUPABASE_URL")

# Prefer Service Role key for backend operations
supabase_key = (
    os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
)

db_client: Client | None = None

if not supabase_url or not supabase_key:
    print("CRITICAL DATABASE INITIALIZATION ERROR: Supabase environment variables are missing.")
else:
    try:
        db_client = create_client(supabase_url, supabase_key)
        print("[SUCCESS] Successfully initialized Supabase PostgreSQL database connection.")
    except Exception as e:
        print(f"[ERROR] Failed to connect to Supabase: {e}")

def get_db() -> Client:
    if db_client is None:
        raise RuntimeError("Supabase database connection is unconfigured.")
    return db_client