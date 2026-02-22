import secrets
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect


def home(request):
    """
    Simple page showing:
      - 'Login with Google' if not logged in
      - email + logout link if logged in
    """
    user = request.session.get("user")
    if not user:
        return HttpResponse('<a href="/login/">Login with Google</a>')
    return HttpResponse(
        f"Hello {user['email']} "
        f'(<a href="/logout/">logout</a>)'
    )


def google_login(request):
    """
    Redirects the user to Google's OAuth 2.0 authorization endpoint.
    """
    # --- demo check for placeholder client ID/secret ---
    cid = settings.GOOGLE_CLIENT_ID
    csecret = settings.GOOGLE_CLIENT_SECRET
    if "REPLACE WITH YOUR GOOGLE CLIENT ID" in cid or "REPLACE WITH YOUR GOOGLE CLIENT SECRET" in csecret:
        return HttpResponse(
            "<h1 style='color:red; font-size:2rem;'>"
            "Google OAuth is NOT configured"
            "</h1>"
            "<p>Set real GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in settings.py.</p>"
            f"<pre style='background:#222;color:#ff0000;padding:1rem;'>"
            f"GOOGLE_CLIENT_ID    = {cid!r}\n"
            f"GOOGLE_CLIENT_SECRET = {csecret!r}"
            "</pre>"
        )
    # --- end demo check ---




    # Random string to protect against CSRF
    state = secrets.token_urlsafe(16)
    request.session["oauth_state"] = state

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
    }

    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(url)


def google_callback(request):
    """
    Handles Google's redirect back:
      - checks 'state'
      - exchanges 'code' for an access token
      - fetches user info
      - stores email in the session
    """
    if request.GET.get("state") != request.session.get("oauth_state"):
        return HttpResponseBadRequest("Invalid state")

    code = request.GET.get("code")
    if not code:
        return HttpResponseBadRequest("Missing code")

    # Exchange code for tokens
    token_res = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        },
    )
    if not token_res.ok:
        return HttpResponseBadRequest("Token request failed")

    access_token = token_res.json().get("access_token")
    if not access_token:
        return HttpResponseBadRequest("No access token")

    # Fetch basic user info
    userinfo_res = requests.get(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if not userinfo_res.ok:
        return HttpResponseBadRequest("Userinfo request failed")

    userinfo = userinfo_res.json()

    # Store just the email in the session for this demo
    request.session["user"] = {"email": userinfo.get("email")}
    request.session.pop("oauth_state", None)

    return redirect("/")


def logout_view(request):
    """Clear the session and go back to home."""
    request.session.pop("user", None)
    request.session.pop("oauth_state", None)
    return redirect("/")