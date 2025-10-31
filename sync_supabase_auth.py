# from supabase import create_client
# import psycopg2
# import os

# # --- Configure Supabase ---
# SUPABASE_URL = "https://njoqbuhrvdbcpmwcmyyu.supabase.co"
# SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5qb3FidWhydmRiY3Btd2NteXl1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc1ODg1MzcxNCwiZXhwIjoyMDc0NDI5NzE0fQ.nHMnXDydggYgKJUXQQc1okTbdSGLMBCSJW5Z7RapkNY"  # 🔥 not the anon key!

# supabase = create_client(SUPABASE_URL, SERVICE_ROLE_KEY)

# # --- Connect directly to Supabase database (your users table) ---
# conn = psycopg2.connect(
#     host="aws-1-ap-southeast-1.pooler.supabase.com",
#     port="5432",
#     dbname="postgres",
#     user="postgres.njoqbuhrvdbcpmwcmyyu",
#     password="Ed!fy1Mpr0j3ct",  # use .env ideally
#     sslmode="require"
# )

# cur = conn.cursor()
# cur.execute("SELECT email, password FROM users;")  # adjust column names as needed
# users = cur.fetchall()

# print(f"Found {len(users)} users to sync...")

# for email, password in users:
#     try:
#         response = supabase.auth.admin.create_user({
#             "email": email,
#             "password": password,
#             "email_confirm": True  # mark as verified
#         })
#         print(f"✅ Synced user: {email}")
#     except Exception as e:
#         print(f"❌ Failed to sync {email}: {e}")

# cur.close()
# conn.close()
