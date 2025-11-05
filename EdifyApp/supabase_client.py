from supabase import create_client
from django.conf import settings

# ✅ Use Django settings (already loaded from your .env)
supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
