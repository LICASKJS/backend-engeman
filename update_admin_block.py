from pathlib import Path
path = Path('back-end/app.py')
text = path.read_text(encoding='latin-1')
old = "        if email in ADMIN_ALLOWED_EMAILS and senha == ADMIN_PASSWORD:\r\n\r\n\r\n\r\n            token = create_access_token(identity={'role': 'admin', 'email': email})\r\n\r\n\r\n\r\n            return jsonify(access_token=token, email=email), 200"
new = "        if email in ADMIN_ALLOWED_EMAILS and senha == ADMIN_PASSWORD:\r\n            token = create_access_token(identity=email, additional_claims={'role': 'admin'})\r\n            return jsonify(access_token=token, email=email), 200"
if old not in text:
    raise SystemExit('old chunk not found')
path.write_text(text.replace(old, new), encoding='latin-1')
