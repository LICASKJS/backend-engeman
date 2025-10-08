from pathlib import Path
path = Path('back-end/app.py')
text = path.read_text(encoding='latin-1')
marker = "def painel_admin_dashboard():"
new_block = "@app.route('/api/admin/login', methods=['POST'])\ndef admin_login():\n    try:\n        data = request.get_json() or {}\n        email = (data.get('email') or '').strip().lower()\n        senha = data.get('senha') or ''\n        if email in ADMIN_ALLOWED_EMAILS and senha == ADMIN_PASSWORD:\n            token = create_access_token(identity=email, additional_claims={'role': 'admin'})\n            return jsonify(access_token=token, email=email), 200\n        return jsonify(message='Credenciais invalidas'), 401\n    except Exception as exc:\n        print(f'Erro no login admin: {exc}')\n        return jsonify(message='Erro ao autenticar administrador'), 500\n\n\n"
if marker not in text:
    raise SystemExit('marker not found')
text = text.replace(marker, new_block + marker)
path.write_text(text, encoding='latin-1')
