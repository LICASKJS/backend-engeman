from pathlib import Path
path = Path('back-end/app.py')
text = path.read_text(encoding='latin-1')
old = "    identidade = get_jwt_identity()\r\n\r\n\r\n    if identidade is None:\r\n\r\n\r\n        return False\r\n\r\n\r\n    if isinstance(identidade, dict):\r\n\r\n\r\n        email = identidade.get('email', '')\r\n\r\n\r\n        role = identidade.get('role')\r\n\r\n\r\n    else:\r\n\r\n\r\n        email = identidade\r\n\r\n\r\n        role = None\r\n\r\n\r\n    email = (email or '').strip().lower()\r\n\r\n\r\n    if email not in ADMIN_ALLOWED_EMAILS:\r\n\r\n\r\n        return False\r\n\r\n\r\n    if role is not None and role != 'admin':\r\n\r\n\r\n        return False\r\n\r\n\r\n    return True"
new = "    identidade = get_jwt_identity()\r\n    claims = get_jwt()\r\n\r\n    if identidade is None:\r\n        return False\r\n\r\n    email = (identidade or '').strip().lower()\r\n    if email not in ADMIN_ALLOWED_EMAILS:\r\n        return False\r\n\r\n    role = claims.get('role') if isinstance(claims, dict) else None\r\n    if role is not None and role != 'admin':\r\n        return False\r\n\r\n    return True"
if old not in text:
    raise SystemExit('old admin auth block not found')
path.write_text(text.replace(old, new), encoding='latin-1')
