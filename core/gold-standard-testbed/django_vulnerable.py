import os
from django import forms
from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt

# Vulnerable: DJA-003 (DEBUG in production)
DEBUG = True
# Vulnerable: DJA-005 (Insecure ALLOWED_HOSTS)
ALLOWED_HOSTS = ["*"]
# Vulnerable: DJA-007 (Insecure cookie flags)
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
# Vulnerable: DJA-008 (Hardcoded secret key)
SECRET_KEY = "django-insecure-hardcoded-secret"
# Vulnerable: DJA-012 (Unsafe session serializer)
SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"
# Vulnerable: DJA-014 (Weak password hasher)
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


# Vulnerable: DJA-001 (CSRF disabled)
@csrf_exempt
def update_profile(request):
    # Vulnerable: DJA-002 (Raw SQL injection)
    email = request.GET.get("email", "")
    q = "SELECT * FROM users WHERE email = '" + email + "'"
    User.objects.raw(q)
    # Vulnerable: DJA-006 (Open redirect)
    if request.GET.get("next"):
        return redirect(request.GET.get("next"))
    # Vulnerable: DJA-010 (Sensitive error leak)
    try:
        raise RuntimeError("db password leaked")
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"ok": True})


# Vulnerable: DJA-004 (ModelForm mass assignment)
class UserForm(forms.ModelForm):
    class Meta:
        model = User


class AdminForm(forms.ModelForm):
    # Vulnerable: DJA-017 (ModelForm exclude abuse)
    class Meta:
        model = User
        exclude = []


def render_html(user_input):
    # Vulnerable: DJA-011 (XSS via mark_safe)
    html = mark_safe(user_input)
    return html


def query_user(user_id):
    # Vulnerable: DJA-013 (Insecure .extra where clause)
    qs = User.objects.extra(where=["id=%s" % user_id])
    return qs


def logout_redirect(request):
    # Vulnerable: DJA-015 (Unsafe logout redirect)
    LOGOUT_REDIRECT_URL = request.GET.get("next")
    return LOGOUT_REDIRECT_URL


# Vulnerable: DJA-016 (ReDoS in URL patterns)
urlpatterns = [
    re_path(r"^(a+)+$", view),
]


# Vulnerable: DJA-018 (Missing LoginRequiredMixin on CBV)
class PaymentsView(View):
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


def upload_file(upload):
    # Vulnerable: DJA-009 (Unsafe upload path)
    path = os.path.join("/data/uploads", upload.name)
    with open(path, "wb") as f:
        pass
    return path


def upload_file_raw(upload):
    # Vulnerable: DJA-009 (Unsafe upload path)
    path = os.path.join("/data/uploads", upload.name)
    with open(path, "wb") as f:
        f.write(upload.read())
    return path
