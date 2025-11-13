from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_mail import Mail, Message
from config import Config
from models import db, Fornecedor, Documento, Homologacao, NotaFornecedor
from werkzeug.security import generate_password_hash, check_password_hash
import random
import base64
import os
import pandas as pd
import math
import unicodedata
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from sqlalchemy import or_, inspect, text

mail = Mail()
app = Flask(__name__)

UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ADMIN_ALLOWED_EMAILS = {
    'pedro.vilaca@engeman.net',
    'sofia.beltrao@engeman.net',
    'lucas.mateus@engeman.net'
}

ADMIN_PASSWORD = 'admin123'
ALLOWED_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "https://portalengeman-front.vercel.app",
    "https://portalengeman.vercel.app",
]
CORS(app, resources={r"/api/*": {"origins": ALLOWED_CORS_ORIGINS}})
app.config.from_object(Config)
db.init_app(app)

jwt = JWTManager(app)
mail.init_app(app)
migrate = Migrate(app, db)

def _ensure_nota_fornecedor_schema():
    try:
        inspector = inspect(db.engine)
    except Exception as exc:
        print(f'Nao foi possivel inspecionar o banco para atualizar notas_fornecedores: {exc}')
        return
    if 'notas_fornecedores' not in inspector.get_table_names():
        return
    existing_columns = {col['name'] for col in inspector.get_columns('notas_fornecedores')}
    alter_statements = []

    def schedule(column_name, ddl):
        if column_name not in existing_columns:
            alter_statements.append((column_name, ddl))

    schedule('status_decisao', 'VARCHAR(20)')
    schedule('observacao_admin', 'TEXT')
    schedule('nota_referencia', 'FLOAT')
    schedule('email_enviado', 'INTEGER DEFAULT 0')
    schedule('decisao_atualizada_em', 'DATETIME')

    if not alter_statements:
        return

    try:
        with db.engine.begin() as connection:
            for column_name, ddl in alter_statements:
                connection.execute(text(f'ALTER TABLE notas_fornecedores ADD COLUMN {column_name} {ddl}'))
                print(f'Coluna {column_name} adicionada a notas_fornecedores')
    except Exception as exc:
        print(f'Erro ao ajustar schema de notas_fornecedores: {exc}')


with app.app_context():
    db.create_all()
    _ensure_nota_fornecedor_schema()

    
@app.route('/')
def home():
    return "Bem-vindo ao Portal de Fornecedores!"


@app.route('/api/cadastro', methods=['POST'])
def cadastrar_fornecedor():
    try:
        data = request.get_json() or {}
        print(data)
        if not all(key in data for key in ('email', 'cnpj', 'nome', 'senha')):
            return jsonify(message="Dados incompletos, verifique os campos."), 400
        hashed_password = generate_password_hash(data['senha'], method='pbkdf2:sha256')
        fornecedor = Fornecedor(
            nome=data['nome'],
            email=data['email'],
            cnpj=data['cnpj'],
            senha=hashed_password
        )
        db.session.add(fornecedor)
        db.session.commit()
        return jsonify(message="Fornecedor cadastrado com sucesso"), 201
    except Exception as e:
        print(str(e))
        return jsonify(message="Erro ao cadastrar fornecedor: " + str(e)), 500
    
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        senha = data.get("senha")
        if not email or not senha:
            app.logger.error(f"Login falhou, email ou senha não fornecidos: {data}")
            return jsonify(message="Email e senha são obrigatórios."), 400
        fornecedor = Fornecedor.query.filter(Fornecedor.email.ilike(email)).first()
        if fornecedor:
            app.logger.info(f"Fornecedor encontrado: {fornecedor.email}")
            if check_password_hash(fornecedor.senha, senha):
                access_token = create_access_token(identity=str(fornecedor.id))
                app.logger.info(f"Token gerado para o fornecedor {fornecedor.email}")
                return jsonify(access_token=access_token), 200
            else:
                app.logger.error(f"Senha incorreta para o fornecedor: {fornecedor.email}")
        else:
            app.logger.error(f"Fornecedor não encontrado: {email}")
            return jsonify(message="Credenciais inválidas"), 401
    except Exception as e:
        app.logger.error(f"Erro no login: {str(e)}")
        return jsonify(message="Erro ao autenticar, tente novamente mais tarde."), 500
    
@app.route('/api/recuperar-senha', methods=['POST'])
def recuperar_senha():
    try:
        data = request.get_json()
        fornecedor = Fornecedor.query.filter_by(email=data['email']).first()
        if not fornecedor:
            return jsonify(message="Fornecedor não encontrado"), 404
        token = str(random.randint(100000, 999999))
        fornecedor.token_recuperacao = token
        fornecedor.token_expira = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()
        corpo_email = f"""
  <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Recuperação de Senha - Engeman</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Inter', Arial, sans-serif; background-color: #f8fafc;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="background: white; border-radius: 12px; padding: 40px 30px; text-align: center; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); margin-bottom: 20px;">
                    <img src="cid:engeman_logo" alt="Engeman Logo" style="max-width: 200px; height: auto; margin-bottom: 20px;">
                    <h1 style="margin: 0; font-size: 28px; font-weight: 600; color: #f97316;">
                        RECUPERAÇÃO DE SENHA</h1><br>
                    <h2 style="margin: 0 0 20px 0; font-size: 20px; font-weight: 600; color: #696969;">
                        Olá, {fornecedor.nome}!
                    </h2>
                    <p style="margin: 0 0 30px 0; color: #64748b; font-size: 16px; line-height: 1.6;">
                        Recebemos uma solicitação para redefinir a senha da sua conta. Use o token abaixo para criar uma nova senha:
                    </p>
                    <div style="background: #fef3c7; border: 2px solid #f97316; border-radius: 8px; padding: 25px; margin: 30px 0; text-align: center;">
                        <p style="margin: 0 0 15px 0; font-size: 16px; font-weight: 600; color: #92400e;">
                            Seu Token de Recuperação:
                        </p>
                        <div style="font-size: 32px; font-weight: 600; color: #f97316; letter-spacing: 4px; font-family: 'Courier New', monospace; margin: 15px 0;">
                            {token}
                        </div>
                        <p style="margin: 15px 0 0 0; color: #92400e; font-size: 14px;">
                            Este token expira em 10 minutos
                        </p>
                    </div>
                    <div style="background: #f1f5f9; border-radius: 8px; padding: 20px; margin: 30px 0;">
                        <h4 style="margin: 0 0 15px 0; font-size: 16px; font-weight: 600; color: #1e293b;">
                            Como usar:
                        </h4>
                        <ol style="margin: 0; color: #64748b; font-size: 14px; line-height: 1.6; padding-left: 20px;">
                            <li>Acesse a página de recuperação de senha</li>
                            <li>Digite o token no campo solicitado</li>
                            <li>Defina sua nova senha</li>
                        </ol>
                    </div>
                    <p style="margin: 30px 0 0 0; color: #94a3b8; font-size: 14px; text-align: center;">
                        Se você não solicitou esta recuperação, ignore este e-mail.
                    </p>
                    <!-- Simplified footer -->
                    <div style="text-align: center; padding-top: 20px; border-top: 1px solid #e2e8f0; margin-top: 30px;">
                        <p style="margin: 0; color: #94a3b8; font-size: 12px;">
                            © 2025 Engeman - Portal de Fornecedores
                        </p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        imagem_path = os.path.join(os.path.dirname(app.root_path), 'static', 'colorida.png')
        enviar_email(fornecedor.email, "Recuperação de Senha", corpo_email, imagem_path)
        return jsonify(message="Token de recuperação enviado por e-mail"), 200
    except Exception as e:
        return jsonify(message="Erro ao recuperar senha: " + str(e)), 500
    
@app.route("/api/validar-token", methods=["POST"])
def validar_token():
    try:
        data = request.get_json()
        token = data.get("token")
        if not token:
            return jsonify(message="Token é obrigatório"), 400
        fornecedor = Fornecedor.query.filter_by(token_recuperacao=token).first()
        if not fornecedor:
            return jsonify(message="Token inválido ou fornecedor não encontrado"), 404
        if fornecedor.token_expira < datetime.utcnow():
            return jsonify(message="Token expirado"), 400
        return jsonify(message="Token válido"), 200
    except Exception as e:
        print(f"Erro ao validar token: {e}")
        return jsonify(message="Erro ao validar token"), 500
    
@app.route("/api/redefinir-senha", methods=["POST"])
def redefinir_senha():
    data = request.get_json()
    token = data.get("token")
    nova_senha = data.get("nova_senha")
    if not token or not nova_senha:
        return jsonify(message="Token e nova senha são obrigatórios"), 400
    fornecedor = Fornecedor.query.filter_by(token_recuperacao=token).first()
    if not fornecedor:
        return jsonify(message="Token inválido ou fornecedor não encontrado"), 404
    if fornecedor.token_expira < datetime.utcnow():
        return jsonify(message="Token expirado"), 400
    fornecedor.senha = generate_password_hash(nova_senha, method="pbkdf2:sha256")
    fornecedor.token_recuperacao = None
    fornecedor.token_expira = None
    db.session.commit()
    return jsonify(message="Senha redefinida com sucesso"), 200

@app.route('/api/contato', methods=['POST'])
def contato():
    try:
        data = request.get_json()
        nome = data.get("nome")
        email = data.get("email")
        assunto = data.get("assunto")
        mensagem = data.get("mensagem")
        if not nome or not email or not assunto or not mensagem:
            return jsonify(message="Todos os campos são obrigatórios."), 400
        corpo_email = f"""
<!DOCTYPE html>

<html lang="pt-BR">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MENSAGEM DO PORTAL DE FORNECEDORES</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }}
        .header {{
            background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
            padding: 40px 30px;
            text-align: center;
            position: relative;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
        }}
        .logo {{
            width: 150px;
            height: auto;
            margin-bottom: 20px;
            position: relative;
            z-index: 1;
        }}
        .header-title {{
            color: #f97316;
            font-size: 24px;
            font-weight: 700;
            margin: 0;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            position: relative;
            z-index: 1;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .message-card {{
            background: #f8fafc;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border-left: 4px solid #f97316;
        }}
        .field {{
            margin-bottom: 20px;
        }}
        .field-label {{
            display: inline-flex;
            align-items: center;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        .field-icon {{
            width: 16px;
            height: 16px;
            margin-right: 8px;
            color: #f97316;
        }}
        .field-value {{
            color: #475569;
            font-size: 15px;
            line-height: 1.6;
            background: #ffffff;
            padding: 12px 16px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}
        .message-text {{
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .footer {{
            background: #f1f5f9;
            padding: 24px 30px;
            text-align: center;
            border-top: 1px solid #e2e8f0;
        }}
        .footer-text {{
            color: #64748b;
            font-size: 13px;
            line-height: 1.5;
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
            color: #000000;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 21px;
            font-weight: 600;
            margin-bottom: 16px;
        }}
        @media (max-width: 600px) {{
            .container {{
                margin: 10px;
                border-radius: 12px;
            }}
            .header, .content, .footer {{
                padding-left: 20px;
                padding-right: 20px;
            }}
            .header-title {{
                font-size: 20px;
            }}
        }}
    </style>
</head>

<body>

    <div class="container">
        <div class="header">
            <img src="cid:engeman_logo" alt="Engeman Logo" class="logo">
            <h1 class="header-title">PORTAL DE FORNECEDORES</h1>
            <p>Abaixo tem algumas dúvidas do fornecedor, favor analise o quanto antes</p>
        </div>
        <div class="content">
            <div class="badge">
                📧 Nova Mensagem Recebida
            </div>
            <div class="message-card">
                <div class="field">
                    <div class="field-label">
                        <svg class="field-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"/>
                        </svg>
                        Nome do Remetente
                    </div>
                    <div class="field-value">{nome}</div>
                </div>
                <div class="field">
                    <div class="field-label">
                        <svg class="field-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z"/>
                            <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z"/>
                        </svg>
                        E-mail de Contato
                    </div>
                    <div class="field-value">{email}</div>
                </div>
                <div class="field">
                    <div class="field-label">
                        <svg class="field-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 101 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
                        </svg>
                        Assunto
                    </div>
                    <div class="field-value">{assunto}</div>
                </div>
                <div class="field">
                    <div class="field-label">
                        <svg class="field-icon" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M18 13V5a2 2 0 00-2-2H4a2 2 0 00-2 2v8a2 2 0 002 2h3l3 3 3-3h3a2 2 0 002-2zM5 7a1 1 0 011-1h8a1 1 0 110 2H6a1 1 0 01-1-1zm1 3a1 1 0 100 2h3a1 1 0 100-2H6z" clip-rule="evenodd"/>
                        </svg>
                        Mensagem
                    </div>
                    <div class="field-value message-text">{mensagem}</div>
                </div>
            </div>
        </div>
        <div class="footer">
            <p class="footer-text">
                <strong>Portal de Fornecedores</strong><br>
                Este é um e-mail automático gerado pelo sistema. Por favor, não responda diretamente a esta mensagem.
            </p>
        </div>
    </div>
</body>

</html>

"""

        imagem_path = os.path.join(os.path.dirname(app.root_path), 'static', 'colorida.png')
        enviar_email(
            destinatario="lucas.mateus@engeman.net",
            assunto=f"MENSAGEM DO PORTAL: {assunto}",
            corpo=corpo_email,
            imagem_path=imagem_path
        )
        return jsonify(message="Mensagem enviada com sucesso!"), 200
    except Exception as e:
        print(f"Erro ao enviar mensagem: {e}")
        return jsonify(message="Erro ao enviar a mensagem."), 500
def allowed_file(filename):
    allowed_extensions = ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'xlsx', 'csv']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def _obter_caminho_claf():
    candidatos = [
        os.path.join(app.root_path, 'uploads', 'CLAF.xlsx'),
        os.path.join(app.root_path, '..', 'uploads', 'CLAF.xlsx'),
        os.path.join(app.root_path, '..', 'static', 'CLAF.xlsx'),
        os.path.join(app.root_path, '..', 'public', 'docs', 'CLAF.xlsx'),
        os.path.join(app.root_path, 'static', 'CLAF.xlsx'),
    ]
    for caminho in candidatos:
        caminho_abs = os.path.abspath(caminho)
        if os.path.exists(caminho_abs):
            return caminho_abs
    raise FileNotFoundError('Planilha CLAF.xlsx nao encontrada.')


def _resolver_planilha(nome_arquivo):
    candidatos = [
        os.path.join(app.root_path, 'uploads', nome_arquivo),
        os.path.join(app.root_path, '..', 'static', nome_arquivo),
        os.path.join(app.root_path, '..', 'uploads', nome_arquivo),
        os.path.join(app.root_path, '..', 'public', 'docs', nome_arquivo),
        os.path.join(app.root_path, 'static', nome_arquivo),
    ]
    for caminho in candidatos:
        caminho_abs = os.path.abspath(caminho)
        if os.path.exists(caminho_abs):
            return caminho_abs
    return None


def _normalizar_texto(valor):
    if valor is None:
        return ''
    if isinstance(valor, str):
        texto = valor
    else:
        try:
            if pd.isna(valor):
                return ''
        except Exception:
            pass
        texto = str(valor)
    texto = unicodedata.normalize('NFKD', texto)
    texto = ''.join(ch for ch in texto if not unicodedata.combining(ch))
    texto = ' '.join(texto.split())
    return texto.upper().strip()


def _normalizar_chave(valor):
    texto = _normalizar_texto(valor)
    return ''.join(ch for ch in texto if ch.isalnum())


def _contar_valores_textuais(serie):
    contador = 0
    for valor in serie.dropna():
        if isinstance(valor, str) and valor.strip():
            contador += 1
        elif not isinstance(valor, str):
            texto = str(valor).strip()
            if texto:
                contador += 1
    return contador


def _colunas_por_candidatos(df, candidatos, fallback_indices=None, max_count=None):
    encontrados = []
    mapa = {}
    for idx, coluna in enumerate(df.columns):
        chave = _normalizar_chave(coluna)
        if chave and chave not in mapa:
            mapa[chave] = coluna
    for candidato in candidatos:
        chave_candidato = _normalizar_chave(candidato)
        coluna = mapa.get(chave_candidato)
        if coluna and coluna not in encontrados:
            encontrados.append(coluna)
            if max_count and len(encontrados) >= max_count:
                return encontrados
    if fallback_indices:
        for indice in fallback_indices:
            if 0 <= indice < len(df.columns):
                coluna = df.columns[indice]
                if coluna not in encontrados:
                    conteudo = _contar_valores_textuais(df[coluna])
                    if conteudo == 0:
                        continue
                    encontrados.append(coluna)
                    if max_count and len(encontrados) >= max_count:
                        return encontrados
    if not encontrados:
        melhor_coluna = None
        melhor_contagem = 0
        for coluna in df.columns:
            contagem = _contar_valores_textuais(df[coluna])
            if contagem > melhor_contagem:
                melhor_coluna = coluna
                melhor_contagem = contagem
        if melhor_coluna is not None:
            encontrados.append(melhor_coluna)
    if max_count:
        return encontrados[:max_count]
    return encontrados


CLAF_VALORES_IGNORADOS = {
    'MATERIAL / SERVICO',
    'MATERIAL/SERVICO',
    'MATERIAIS',
    'CATEGORIA',
    'GRUPO',
    'FAMILIA',
    'REQUISITOS LEGAIS',
    'REQUISITOS ESTABELECIDOS PELA ENGEMAN',
    'CRITERIOS DE QUALIFICACAO',
    'GRAUS DE RISCO COMPLIANCE',
}


@app.route('/api/envio-documento', methods=['POST'])
def enviar_documento():
    try:
        fornecedor_id = request.form.get('fornecedor_id')
        categoria = request.form.get('categoria')
        arquivos = request.files.getlist('arquivos')
        fornecedor = Fornecedor.query.get(fornecedor_id)
        if not fornecedor:
            return jsonify(message="Fornecedor não encontrado"), 404
        if not categoria or not arquivos:
            return jsonify(message="Categoria ou arquivos não fornecidos"), 400
        lista_arquivos = []
        arquivos_paths = []
        pasta_fornecedor = os.path.join(UPLOAD_FOLDER, str(fornecedor_id))
        os.makedirs(pasta_fornecedor, exist_ok=True)
        for arquivo in arquivos:
            if not allowed_file(arquivo.filename):
                return jsonify(message=f"Extensão do arquivo não permitida: {arquivo.filename}"), 400
            filename = secure_filename(arquivo.filename)
            caminho_arquivo = os.path.join(pasta_fornecedor, filename)
            arquivo.save(caminho_arquivo)
            documento = Documento(
                nome_documento=filename,
                categoria=categoria,
                fornecedor_id=fornecedor.id
            )
            db.session.add(documento)
            lista_arquivos.append(filename)
            arquivos_paths.append(caminho_arquivo)
        db.session.commit()
        link_documentos = [f"/uploads/{fornecedor_id}/{a}" for a in lista_arquivos]
        enviar_email_documento(
            fornecedor_nome=fornecedor.nome,
            documento_nome=", ".join(lista_arquivos),
            categoria=categoria,
            destinatario='lucas.mateus@engeman.net',
            link_documento=", ".join(link_documentos),
            arquivos_paths=arquivos_paths
        )
        return jsonify(message="Documentos enviados com sucesso", enviados=lista_arquivos), 200
    except Exception as e:
        return jsonify(message="Erro ao enviar documentos: " + str(e)), 500
    
@app.route('/api/documentos-necessarios', methods=['POST'])
def documentos_necessarios():
    try:
        data = request.get_json() or {}
        categoria = (data.get('categoria') or '').strip()
        if not categoria:
            return jsonify(message="Categoria nao fornecida"), 400
        claf_path = _obter_caminho_claf()
        df = pd.read_excel(claf_path, header=0)
        df.columns = [str(col).strip() for col in df.columns]
        coluna_material_lista = _colunas_por_candidatos(
            df,
            ('material', 'materiais', 'material/servico', 'categoria', 'grupo', 'familia'),
            fallback_indices=[0],
            max_count=1,
        )
        if not coluna_material_lista:
            return jsonify(message="Coluna de materiais nao encontrada na planilha"), 500
        coluna_material = coluna_material_lista[0]
        colunas_documentos = _colunas_por_candidatos(
            df,
            (
                'requisitos legais',
                'requisitos_estabelecidos_pela_engeman',
                'requisitos estabelecidos pela engeman',
                'criterios de qualificacao',
            ),
            fallback_indices=[1, 2],
        )
        if not colunas_documentos:
            return jsonify(message="Colunas de documentos nao encontradas na planilha"), 500
        categoria_normalizada = _normalizar_texto(categoria)
        serie_categorias = df[coluna_material].apply(_normalizar_texto)
        mask = serie_categorias.apply(
            lambda valor: bool(valor) and (
                categoria_normalizada in valor or valor in categoria_normalizada
            )
        )
        df_filtrado = df[mask]
        documentos = []
        vistos = set()
        for _, row in df_filtrado.iterrows():
            for coluna_doc in colunas_documentos:
                valor = row.get(coluna_doc)
                if pd.isna(valor):
                    continue
                texto = str(valor).strip()
                if not texto:
                    continue
                texto_normalizado = _normalizar_texto(texto)
                if not texto_normalizado or texto_normalizado in CLAF_VALORES_IGNORADOS:
                    continue
                if texto_normalizado in vistos:
                    continue
                vistos.add(texto_normalizado)
                documentos.append(texto)
        return jsonify(documentos=documentos), 200
    except FileNotFoundError as exc:
        return jsonify(message=str(exc)), 500
    except Exception as e:
        return jsonify(message="Erro ao consultar documentos: " + str(e)), 500


@app.route('/api/categorias', methods=['GET'])
def listar_categorias():
    try:
        claf_path = _obter_caminho_claf()
        df = pd.read_excel(claf_path, header=0)
        df.columns = [str(col).strip() for col in df.columns]
        coluna_material_lista = _colunas_por_candidatos(
            df,
            ('material', 'materiais', 'material/servico', 'categoria', 'grupo', 'familia'),
            fallback_indices=[0],
            max_count=1,
        )
        if not coluna_material_lista:
            return jsonify(message="Coluna de materiais nao encontrada na planilha"), 500
        coluna_material = coluna_material_lista[0]
        serie = df[coluna_material]
        vistos = set()
        materiais = []
        for valor in serie:
            if pd.isna(valor):
                continue
            nome = str(valor).strip()
            if not nome:
                continue
            chave = _normalizar_texto(nome)
            if not chave or chave in CLAF_VALORES_IGNORADOS:
                continue
            if chave in vistos:
                continue
            vistos.add(chave)
            materiais.append(nome)
        materiais.sort(key=_normalizar_texto)
        return jsonify(materiais=materiais, total=len(materiais)), 200
    except FileNotFoundError as exc:
        return jsonify(message=str(exc)), 500
    except Exception as exc:
        return jsonify(message="Erro ao listar categorias: " + str(exc)), 500

@app.route('/api/dados-homologacao', methods=['GET'])
def consultar_dados_homologacao():
    try:
        fornecedor_nome = request.args.get('fornecedor_nome', type=str)

        print(f"Buscando dados para o fornecedor com nome: {fornecedor_nome}")

        if not fornecedor_nome:

            return jsonify(message="Parâmetro 'fornecedor_nome' é obrigatório."), 400
        
        path_homologados = os.path.abspath(
            os.path.join(app.root_path, '..', 'uploads', 'fornecedores_homologados.xlsx')
        )
        path_controle = os.path.abspath(
            os.path.join(app.root_path, '..', 'uploads', 'atendimento controle_qualidade.xlsx')
        )
        print(f"Caminho do arquivo de homologados: {path_homologados}")

        print(f"Caminho do arquivo de controle de qualidade: {path_controle}")

        if not os.path.exists(path_homologados) or not os.path.exists(path_controle):
            return jsonify(
                message="Um ou mais arquivos de planilha não foram encontrados. Verifique os caminhos dos arquivos."
            ), 500
        df_homologacao = pd.read_excel(path_homologados)

        df_controle_qualidade = pd.read_excel(path_controle)

        df_homologacao.columns = (
            df_homologacao.columns.str.strip().str.lower().str.replace(" ", "_")
        )

        df_controle_qualidade.columns = (
            df_controle_qualidade.columns.str.strip().str.lower().str.replace(" ", "_")
        )
        filtro_homologados = df_homologacao[
            df_homologacao['agente'].str.contains(fornecedor_nome, case=False, na=False)
        ]
        if filtro_homologados.empty:
            return jsonify(message="Fornecedor não encontrado na planilha de homologados."), 404
        
        fornecedor_h = filtro_homologados.iloc[0]

        print(f"Fornecedor encontrado: {fornecedor_h}")

        fornecedor_id_raw = fornecedor_h.get('codigo')
        fornecedor_id = int(fornecedor_id_raw) if pd.notna(fornecedor_id_raw) else None
        nota_homologacao_raw = fornecedor_h.get('nota_homologacao')
        nota_homologacao = float(nota_homologacao_raw) if nota_homologacao_raw is not None and not pd.isna(nota_homologacao_raw) else None
        iqf_raw = fornecedor_h.get('iqf')
        iqf = float(iqf_raw) if iqf_raw is not None and not pd.isna(iqf_raw) else None
        aprovado_raw = fornecedor_h.get('aprovado')
        aprovado_valor = ''

        if aprovado_raw is not None and not pd.isna(aprovado_raw):

            aprovado_valor = str(aprovado_raw).strip()
        status_homologacao = 'APROVADO' if aprovado_valor.upper() == 'S' else 'EM_ANALISE'
        filtro_ocorrencias = df_controle_qualidade[
            df_controle_qualidade['nome_agente'].str.strip().str.lower()
            == fornecedor_h['agente'].strip().lower()
        ] if 'nome_agente' in df_controle_qualidade.columns else df_controle_qualidade.iloc[0:0]

        if filtro_ocorrencias.empty and 'nome_agente' in df_controle_qualidade.columns and fornecedor_nome:
            filtro_ocorrencias = df_controle_qualidade[
                df_controle_qualidade['nome_agente'].str.contains(fornecedor_nome, case=False, na=False)
            ]
        media_iqf_controle = None
        total_notas_controle = 0
        if not filtro_ocorrencias.empty and 'nota' in filtro_ocorrencias.columns:
            notas_validas = pd.to_numeric(filtro_ocorrencias['nota'], errors='coerce').dropna()
            total_notas_controle = len(notas_validas)
            if total_notas_controle:
                media_iqf_controle = float(notas_validas.mean())
                print(f"Total de notas encontradas no controle de qualidade: {total_notas_controle}")
                print(f"IQF calculada a partir do controle de qualidade: {media_iqf_controle}")
        observacoes_lista = []
        observacao_resumo = ''
        if 'observacao' in filtro_ocorrencias.columns:
            observacoes_series = (
                filtro_ocorrencias['observacao']
                .fillna('')
                .astype(str)
                .str.strip()
            )
            observacoes_filtradas = []
            for obs in observacoes_series.tolist():
                obs_limpo = obs.strip()
                if not obs_limpo:
                    continue
                obs_normalizado = ''.join(
                    ch for ch in unicodedata.normalize('NFD', obs_limpo.lower())
                    if unicodedata.category(ch) != 'Mn'
                )
                obs_normalizado = ''.join(ch for ch in obs_normalizado if ch.isalnum() or ch.isspace())
                obs_normalizado = ' '.join(obs_normalizado.split())
                if obs_normalizado == 'sem comentarios':
                    continue
                observacoes_filtradas.append(obs_limpo)
            observacoes_lista = observacoes_filtradas
            if observacoes_filtradas:
                observacao_resumo = '; '.join(observacoes_filtradas)
        iqf_final = media_iqf_controle if media_iqf_controle is not None else iqf
        status_homologacao = _determinar_status_final(aprovado_valor, nota_homologacao, iqf_final, iqf)
        return jsonify(
            id=fornecedor_id,
            nome=str(fornecedor_h.get('agente', '')),
            iqf=iqf_final,
            status=status_homologacao,
            homologacao=nota_homologacao,
            aprovado=aprovado_valor,
            ocorrencias=observacoes_lista,
            observacao=observacao_resumo,
            iqf_homologados=iqf,
            total_notas_iqf=total_notas_controle
        ), 200
    except FileNotFoundError as fnf:
        return jsonify(message=f"Arquivo de planilha não encontrado: {str(fnf)}"), 500
    except Exception as e:
        print(f"Erro inesperado ao consultar dados de homologação: {str(e)}")
        return jsonify(message="Erro ao consultar dados de homologação", error_details=str(e)), 500


@app.route('/api/portal/resumo', methods=['GET'])
@jwt_required()
def portal_resumo():
    identidade = get_jwt_identity()
    try:
        fornecedor_id = int(identidade)
    except (TypeError, ValueError):
        return jsonify(message="Identidade do fornecedor invalida."), 400
    fornecedor = Fornecedor.query.get(fornecedor_id)
    if fornecedor is None:
        return jsonify(message="Fornecedor nao encontrado."), 404
    df_homologados = None
    df_controle = None
    try:
        df_homologados, df_controle = _carregar_planilhas_homologacao()
    except FileNotFoundError as exc:
        print(f'Planilhas de homologacao nao encontradas para resumo do portal: {exc}')
    except Exception as exc:
        print(f'Erro ao carregar planilhas para resumo do portal: {exc}')
    resumo = _montar_resumo_portal(fornecedor, df_homologados, df_controle)
    return jsonify(resumo=resumo), 200

def _normalize_text(value):
    if value is None:
        return ''
    normalized = ''.join(
        ch for ch in unicodedata.normalize('NFD', str(value).lower())
        if unicodedata.category(ch) != 'Mn'
    )
    normalized = ''.join(ch for ch in normalized if ch.isalnum() or ch.isspace())
    return ' '.join(normalized.split())

def _carregar_planilhas_homologacao():
    path_homologados = _resolver_planilha('fornecedores_homologados.xlsx')
    path_controle = _resolver_planilha('atendimento controle_qualidade.xlsx')
    if not path_homologados or not path_controle:
        print('Planilhas de homologacao nao encontradas. Continuando sem dados de planilha.')
        return None, None
    try:
        df_homologados = pd.read_excel(path_homologados)
        df_controle = pd.read_excel(path_controle)
        df_homologados.columns = (
            df_homologados.columns.str.strip().str.lower().str.replace(' ', '_')
        )
        df_controle.columns = (
            df_controle.columns.str.strip().str.lower().str.replace(' ', '_')
        )
        return df_homologados, df_controle
    except Exception as exc:
        print(f'Erro ao carregar planilhas de homologacao: {exc}')
        return None, None

def _to_float(value):
    try:
        if value in (None, '', 'nan'):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None
def _calcular_media_iqf_controle(fornecedor_nome_planilha, fornecedor_nome_busca, df_controle):
    if df_controle is None or df_controle.empty:
        return None, 0, []
    if 'nome_agente' not in df_controle.columns:
        return None, 0, []
    nomes_series = df_controle['nome_agente'].astype(str)
    normalizados = nomes_series.apply(_normalize_text).astype(str)
    alvo_normalizado = _normalize_text(fornecedor_nome_planilha or fornecedor_nome_busca)
    mask = normalizados == alvo_normalizado
    if not mask.any():
        mask = normalizados.str.contains(_normalize_text(fornecedor_nome_busca), regex=False)
    subset = df_controle[mask]
    if subset.empty:
        return None, 0, []
    notas_validas = pd.to_numeric(subset.get('nota'), errors='coerce').dropna()
    total = len(notas_validas)
    media = float(notas_validas.mean()) if total else None
    observacoes = []
    if 'observacao' in subset.columns:
        observacoes = subset['observacao'].dropna().astype(str).tolist()
    return media, total, observacoes

def _determinar_status_final(aprovado_valor, nota_homologacao, iqf_calculada, nota_iqf_planilha):
    for valor in (iqf_calculada, nota_iqf_planilha, nota_homologacao):
        valor_float = _to_float(valor)
        if valor_float is not None and valor_float < 70:
            return 'REPROVADO'
    aprovado_valor = (aprovado_valor or '').strip().upper()
    if aprovado_valor == 'N':
        return 'REPROVADO'
    if aprovado_valor == 'S':
        return 'APROVADO'
    return 'EM_ANALISE'

def _montar_registro_admin(fornecedor, df_homologados, df_controle):
    nota_homologacao = None
    nota_manual = getattr(fornecedor, 'nota_admin', None)
    status_manual = None
    observacao_admin = None
    decisao_atualizada_em = None
    nota_referencia_manual = None
    if nota_manual:
        if nota_manual.nota_homologacao is not None:
            try:
                nota_homologacao = float(nota_manual.nota_homologacao)
            except (TypeError, ValueError):
                nota_homologacao = None
        status_manual_raw = (nota_manual.status_decisao or '').strip().upper() if nota_manual.status_decisao else ''
        if status_manual_raw in {'APROVADO', 'REPROVADO', 'EM_ANALISE'}:
            status_manual = status_manual_raw
        observacao_admin = nota_manual.observacao_admin
        nota_referencia_manual = nota_manual.nota_referencia
        decisao_atualizada_em = nota_manual.decisao_atualizada_em
    nota_iqf_planilha = None
    fornecedor_nome_planilha = fornecedor.nome
    aprovado_valor = ''
    registros_compativeis = pd.DataFrame()
    if df_homologados is not None and not df_homologados.empty:
        candidatos = []
        for coluna in ['agente', 'nome_fantasia']:
            if coluna in df_homologados.columns:
                candidatos.append(
                    df_homologados[coluna].apply(_normalize_text) == _normalize_text(fornecedor.nome)
                )
        if candidatos:
            mask = candidatos[0]
            for extra in candidatos[1:]:
                mask = mask | extra
            registros_compativeis = df_homologados[mask]
        if registros_compativeis.empty and 'cnpj' in df_homologados.columns:
            registros_compativeis = df_homologados[
                df_homologados['cnpj'].astype(str)
                .str.replace('\r', '')
                .str.replace('\n', '')
                .str.strip()
                == fornecedor.cnpj.strip()
            ]
    if not registros_compativeis.empty:
        registro = registros_compativeis.iloc[0]
        fornecedor_nome_planilha = str(registro.get('agente', fornecedor.nome))
        aprovado_valor = str(registro.get('aprovado', '')).strip().upper()
        if nota_homologacao is None:
            nota_homologacao = _to_float(registro.get('nota homologacao'))
        nota_iqf_planilha = _to_float(registro.get('iqf'))
    media_iqf_controle, total_notas_controle, observacoes_lista = _calcular_media_iqf_controle(
        fornecedor_nome_planilha, fornecedor.nome, df_controle
    )
    iqf_final = media_iqf_controle if media_iqf_controle is not None else nota_iqf_planilha
    status_final = _determinar_status_final(aprovado_valor, nota_homologacao, iqf_final, nota_iqf_planilha)
    if status_manual:
        status_final = status_manual
    documentos = [
        {
            'id': doc.id,
            'nome': doc.nome_documento,
            'categoria': doc.categoria,
            'data_upload': doc.data_upload.isoformat() if doc.data_upload else None
        }
        for doc in fornecedor.documentos
    ]
    ultima_doc = max(
        [doc.data_upload for doc in fornecedor.documentos if doc.data_upload],
        default=None
    )
    ultima_atividade = max(
        [valor for valor in [fornecedor.data_cadastro, ultima_doc] if valor],
        default=None
    )
    return {
        'id': fornecedor.id,
        'nome': fornecedor.nome,
        'email': fornecedor.email,
        'cnpj': fornecedor.cnpj,
        'categoria': fornecedor.categoria,
        'status': status_final,
        'aprovado': status_final == 'APROVADO',
        'nota_homologacao': nota_homologacao,
        'nota_iqf': iqf_final,
        'nota_iqf_planilha': nota_iqf_planilha,
        'nota_iqf_media': media_iqf_controle,
        'total_notas_iqf': total_notas_controle,
        'observacoes': observacoes_lista,
        'observacao_admin': observacao_admin,
        'nota_referencia_admin': nota_referencia_manual,
        'decisao_atualizada_em': decisao_atualizada_em.isoformat() if decisao_atualizada_em else None,
        'documentos': documentos,
        'total_documentos': len(documentos),
        'ultima_atividade': ultima_atividade.isoformat() if ultima_atividade else None,
        'data_cadastro': fornecedor.data_cadastro.isoformat() if fornecedor.data_cadastro else None
    }


def _montar_resumo_portal(fornecedor, df_homologados, df_controle):
    info_admin = _montar_registro_admin(fornecedor, df_homologados, df_controle)
    ocorrencias = [
        str(item).strip()
        for item in info_admin.get('observacoes', []) or []
        if str(item).strip()
    ]
    ultima_atividade = info_admin.get('ultima_atividade')
    if not ultima_atividade and fornecedor.data_cadastro:
        ultima_atividade = fornecedor.data_cadastro.isoformat()
    proxima_reavaliacao = None
    if ultima_atividade:
        try:
            data_base = datetime.fromisoformat(ultima_atividade)
            proxima_reavaliacao = (data_base + timedelta(days=365)).isoformat()
        except ValueError:
            proxima_reavaliacao = None
    nota_homologacao = info_admin.get('nota_homologacao')
    media_iqf = info_admin.get('nota_iqf') or info_admin.get('nota_iqf_media') or info_admin.get('nota_iqf_planilha')
    media_iqf = _to_float(media_iqf) or 0.0
    total_avaliacoes = info_admin.get('total_notas_iqf') or 1
    try:
        total_avaliacoes = max(int(total_avaliacoes), 1)
    except (TypeError, ValueError):
        total_avaliacoes = 1
    status = (info_admin.get('status') or 'EM_ANALISE').strip().upper()
    status_legivel = status.replace('_', ' ').title()
    feedback = '; '.join(ocorrencias) if ocorrencias else 'Aguardando analise dos documentos enviados.'
    nota_homologacao_texto = ''
    if isinstance(nota_homologacao, (int, float)):
        nota_homologacao_texto = f'{nota_homologacao:.2f}'.replace('.', ',')
    resumo = {
        'id': fornecedor.id,
        'nome': fornecedor.nome,
        'email': fornecedor.email,
        'cnpj': fornecedor.cnpj,
        'telefone': getattr(fornecedor, 'telefone', None),
        'categoria': fornecedor.categoria,
        'status': status,
        'statusLegivel': status_legivel,
        'mediaIQF': media_iqf,
        'media_iqf': media_iqf,
        'notaIQF': media_iqf,
        'nota_iqf': media_iqf,
        'mediaHomologacao': nota_homologacao or 0,
        'nota_homologacao': nota_homologacao or 0,
        'totalAvaliacoes': total_avaliacoes,
        'total_notas_iqf': total_avaliacoes,
        'ocorrencias': ocorrencias,
        'feedback': feedback,
        'observacao': feedback,
        'ultimaAtualizacao': ultima_atividade,
        'ultimaAvaliacao': ultima_atividade,
        'proximaReavaliacao': proxima_reavaliacao,
        'notaHomologacaoTexto': nota_homologacao_texto,
    }
    return resumo
def _admin_usuario_autorizado():
    identidade = get_jwt_identity()
    claims = get_jwt()
    if identidade is None:
        return False
    email = (identidade or '').strip().lower()
    if email not in ADMIN_ALLOWED_EMAILS:
        return False
    role = claims.get('role') if isinstance(claims, dict) else None
    if role is not None and role != 'admin':
        return False
    return True


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json() or {}
        email = (data.get('email') or '').strip().lower()
        senha = data.get('senha') or ''
        if email in ADMIN_ALLOWED_EMAILS and senha == ADMIN_PASSWORD:
            token = create_access_token(identity=email, additional_claims={'role': 'admin'})
            return jsonify(access_token=token, email=email), 200
        return jsonify(message='Credenciais inválidas'), 401
    except Exception as exc:
        print(f'Erro no login admin: {exc}')
        return jsonify(message='Erro ao autenticar administrador'), 500
    
@app.route('/api/admin/dashboard', methods=['GET'])
@jwt_required()
def painel_admin_dashboard():
    if not _admin_usuario_autorizado():
        return jsonify(message='Acesso nao autorizado.'), 403
    try:
        fornecedores_db = Fornecedor.query.all()
        total_cadastrados = len(fornecedores_db)
        total_documentos = Documento.query.count()
        df_homologados, df_controle = _carregar_planilhas_homologacao()
        status_counts = {'APROVADO': 0, 'REPROVADO': 0, 'EM_ANALISE': 0}
        for fornecedor in fornecedores_db:
            info = _montar_registro_admin(fornecedor, df_homologados, df_controle)
            status_counts[info['status']] = status_counts.get(info['status'], 0) + 1
        return jsonify(
            total_cadastrados=total_cadastrados,
            total_aprovados=status_counts.get('APROVADO', 0),
            total_em_analise=status_counts.get('EM_ANALISE', 0),
            total_reprovados=status_counts.get('REPROVADO', 0),
            total_documentos=total_documentos
        ), 200
    except FileNotFoundError as e:
        return jsonify(message=str(e)), 500
    except Exception as exc:
        print(f'Erro no dashboard admin: {exc}')
        return jsonify(message='Erro ao gerar dashboard administrativo'), 500
    


@app.route('/api/admin/fornecedores', methods=['GET'])
@jwt_required()
def painel_admin_fornecedores():
    if not _admin_usuario_autorizado():
        return jsonify(message='Acesso nao autorizado.'), 403
    try:
        search_term = request.args.get('search', '', type=str).strip()
        query = Fornecedor.query
        if search_term:
            like_term = f"%{search_term}%"
            query = query.filter(
                or_(
                    Fornecedor.nome.ilike(like_term),
                    Fornecedor.cnpj.ilike(like_term)
                )
            )
        fornecedores = query.order_by(Fornecedor.nome.asc()).all()
        df_homologados, df_controle = _carregar_planilhas_homologacao()
        resultados = [
            _montar_registro_admin(fornecedor, df_homologados, df_controle)
            for fornecedor in fornecedores
        ]
        return jsonify(resultados), 200
    except FileNotFoundError as e:
        return jsonify(message=str(e)), 500
    except Exception as exc:
        print(f'Erro ao listar fornecedores admin: {exc}')
        return jsonify(message='Erro ao listar fornecedores'), 500


@app.route('/api/admin/fornecedores/<int:fornecedor_id>/notas', methods=['PATCH', 'POST', 'OPTIONS'])
@jwt_required()
def atualizar_nota_fornecedor(fornecedor_id):
    if request.method == 'OPTIONS':
        return '', 204
    if not _admin_usuario_autorizado():
        return jsonify(message='Acesso nao autorizado.'), 403

    fornecedor = Fornecedor.query.get(fornecedor_id)
    if fornecedor is None:
        return jsonify(message='Fornecedor nao encontrado.'), 404

    payload = request.get_json() or {}
    nota_valor = payload.get('notaHomologacao')
    if nota_valor is None:
        nota_valor = payload.get('nota_homologacao')
    if nota_valor is None:
        return jsonify(message='O campo notaHomologacao é obrigatório.'), 400
    try:
        nota_float = float(str(nota_valor).replace(',', '.'))
    except (TypeError, ValueError):
        return jsonify(message='Nota de homologacao invalida.'), 400
    if not math.isfinite(nota_float):
        return jsonify(message='Nota de homologacao invalida.'), 400

    try:
        registro_manual = NotaFornecedor.query.filter_by(fornecedor_id=fornecedor.id).first()
        if registro_manual is None:
            registro_manual = NotaFornecedor(fornecedor_id=fornecedor.id)
            db.session.add(registro_manual)
        registro_manual.nota_homologacao = nota_float
        registro_manual.atualizado_em = datetime.utcnow()
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        print(f'Erro ao atualizar nota de homologacao: {exc}')
        return jsonify(message='Erro ao atualizar nota de homologacao.'), 500

    df_homologados = None
    df_controle = None
    try:
        df_homologados, df_controle = _carregar_planilhas_homologacao()
    except FileNotFoundError:
        df_homologados = None
        df_controle = None
    except Exception as exc:
        print(f'Erro ao carregar planilhas apos atualizar nota: {exc}')
        df_homologados = None
        df_controle = None

    fornecedor_payload = _montar_registro_admin(fornecedor, df_homologados, df_controle)
    fornecedor_payload['nota_homologacao'] = nota_float
    return jsonify(
        message='Nota de homologacao atualizada com sucesso.',
        fornecedor=fornecedor_payload
    ), 200


@app.route('/api/admin/fornecedores/<int:fornecedor_id>/decisao', methods=['POST', 'OPTIONS'])
@jwt_required()
def registrar_decisao_fornecedor(fornecedor_id):
    if request.method == 'OPTIONS':
        return '', 204
    if not _admin_usuario_autorizado():
        return jsonify(message='Acesso nao autorizado.'), 403

    fornecedor = Fornecedor.query.get(fornecedor_id)
    if fornecedor is None:
        return jsonify(message='Fornecedor nao encontrado.'), 404

    payload = request.get_json() or {}
    status_informado = (payload.get('status') or '').strip().upper()
    status_validos = {'APROVADO', 'REPROVADO', 'EM_ANALISE'}
    if status_informado not in status_validos:
        return jsonify(message='Status informado invalido.'), 400

    observacao = (payload.get('observacao') or '').strip()
    nota_referencia_valor = payload.get('notaReferencia')
    nota_referencia = None
    if nota_referencia_valor is not None:
        try:
            nota_referencia = float(str(nota_referencia_valor).replace(',', '.'))
        except (TypeError, ValueError):
            nota_referencia = None

    enviar_email_flag = bool(payload.get('enviarEmail'))

    registro_manual = NotaFornecedor.query.filter_by(fornecedor_id=fornecedor.id).first()
    if registro_manual is None:
        registro_manual = NotaFornecedor(fornecedor_id=fornecedor.id)
        db.session.add(registro_manual)

    registro_manual.status_decisao = status_informado
    registro_manual.observacao_admin = observacao or None
    registro_manual.nota_referencia = nota_referencia
    registro_manual.decisao_atualizada_em = datetime.utcnow()

    email_enviado = False
    if enviar_email_flag:
        email_enviado = _enviar_email_decisao(fornecedor, status_informado, observacao)
    registro_manual.email_enviado = email_enviado

    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        print(f'Erro ao registrar decisao: {exc}')
        return jsonify(message='Erro ao registrar decisao do fornecedor.'), 500

    df_homologados = None
    df_controle = None
    try:
        df_homologados, df_controle = _carregar_planilhas_homologacao()
    except FileNotFoundError:
        pass
    except Exception as exc:
        print(f'Erro ao carregar planilhas apos decisao: {exc}')

    fornecedor_payload = _montar_registro_admin(fornecedor, df_homologados, df_controle)
    return jsonify(
        message='Decisao registrada com sucesso.',
        emailEnviado=email_enviado,
        fornecedor=fornecedor_payload
    ), 200
@app.route('/api/admin/notificacoes', methods=['GET'])
@jwt_required()
def painel_admin_notificacoes():
    if not _admin_usuario_autorizado():
        return jsonify(message='Acesso não autorizado.'), 403
    try:
        limite = request.args.get('limit', 20, type=int)
        eventos = []
        fornecedores = Fornecedor.query.order_by(Fornecedor.data_cadastro.desc()).limit(limite).all()
        for fornecedor in fornecedores:
            if not fornecedor.data_cadastro:
                continue
            eventos.append({
                'id': f"cadastro-{fornecedor.id}",
                'tipo': 'cadastro',
                'titulo': 'Novo fornecedor cadastrado',
                'descricao': fornecedor.nome,
                'timestamp': fornecedor.data_cadastro.isoformat(),
                'detalhes': {
                    'email': fornecedor.email,
                    'cnpj': fornecedor.cnpj
                }
            })
        documentos = Documento.query.order_by(Documento.data_upload.desc()).limit(limite).all()
        for doc in documentos:
            fornecedor = doc.fornecedor
            if not doc.data_upload or not fornecedor:
                continue
            eventos.append({
                'id': f"documento-{doc.id}",
                'tipo': 'documento',
                'titulo': 'Documento enviado',
                'descricao': f"{fornecedor.nome} anexou {doc.nome_documento}",
                'timestamp': doc.data_upload.isoformat(),
                'detalhes': {
                    'fornecedor': fornecedor.nome,
                    'documento': doc.nome_documento,
                    'categoria': doc.categoria
                }
            })
        eventos.sort(key=lambda item: item['timestamp'], reverse=True)
        eventos = eventos[:limite]
        return jsonify(eventos), 200
    except Exception as exc:
        print(f'Erro ao obter notificações admin: {exc}')
        return jsonify(message='Erro ao listar notificações'), 500
    

@app.route('/api/fornecedores', methods=['GET'])
def listar_fornecedores():
    nome = request.args.get('nome', '')
    print(f"Buscando fornecedores com nome: {nome}")
    if nome:
        fornecedores = Fornecedor.query.filter(Fornecedor.nome.ilike(f'%{nome}%')).all()
    else:
        fornecedores = Fornecedor.query.all()
    print(f"Fornecedores encontrados: {len(fornecedores)}")
    lista = [{"id": f.id, "nome": f.nome, "email": f.email, "cnpj": f.cnpj} for f in fornecedores]
    return jsonify(lista)
def enviar_email_documento(fornecedor_nome, documento_nome, categoria, destinatario, link_documento, arquivos_paths=None):
    corpo = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MENSAGEM DO PORTAL DE FORNECEDORES</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background: #ffffff;
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            }}
            .header {{
                background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
                padding: 40px 30px;
                text-align: center;
                position: relative;
            }}
            .header::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            }}
            .logo {{
                width: 150px;
                height: auto;
                margin-bottom: 20px;
                position: relative;
                z-index: 1;
                filter: brightness(0) invert(1);
            }}
            .header-title {{
                color: #f97316;
                font-size: 24px;
                font-weight: 700;
                margin: 0;
                text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                position: relative;
                z-index: 1;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .badge {{
                display: inline-flex;
                align-items: center;
                background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
                color: #000000;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
                margin-bottom: 16px;
            }}
            .message-card {{
                background: #f8fafc;
                border-radius: 12px;
                padding: 24px;
                margin-bottom: 24px;
                border-left: 4px solid #f97316;
            }}
            .message-title {{
                font-size: 20px;
                font-weight: 700;
                color: #1e293b;
                margin-bottom: 16px;
            }}
            .message-text {{
                color: #475569;
                font-size: 15px;
                line-height: 1.6;
                margin-bottom: 20px;
            }}
            .field {{
                margin-bottom: 20px;
            }}
            .field-label {{
                display: inline-flex;
                align-items: center;
                font-weight: 600;
                color: #1e293b;
                margin-bottom: 8px;
                font-size: 14px;
            }}
            .field-icon {{
                width: 16px;
                height: 16px;
                margin-right: 8px;
                color: #f97316;
            }}
            .field-value {{
                color: #475569;
                font-size: 15px;
                line-height: 1.6;
                background: #ffffff;
                padding: 12px 16px;
                border-radius: 8px;
                border: 1px solid #e2e8f0;
                font-weight: 500;
            }}
            .cta-section {{
                text-align: center;
                margin: 32px 0;
                padding: 24px;
                background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
                border-radius: 12px;
                border: 1px solid #f59e0b;
            }}
            .cta-text {{
                font-size: 16px;
                color: #92400e;
                margin-bottom: 16px;
                font-weight: 500;
            }}
            .cta-button {{
                display: inline-flex;
                align-items: center;
                background: linear-gradient(135deg, #f97316 0%, #ef4444 100%);
                color: #ffffff;
                padding: 12px 24px;
                text-decoration: none;
                border-radius: 25px;
                font-weight: 600;
                font-size: 15px;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(249, 115, 22, 0.3);
            }}
            .cta-button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 25px rgba(249, 115, 22, 0.4);
            }}
            .footer {{
                background: #f1f5f9;
                padding: 24px 30px;
                text-align: center;
                border-top: 1px solid #e2e8f0;
            }}
            .footer-text {{
                color: #64748b;
                font-size: 13px;
                line-height: 1.5;
                margin-bottom: 8px;
            }}
            .company-info {{
                color: #94a3b8;
                font-size: 12px;
                font-weight: 500;
                margin-top: 16px;
            }}
            /* Dark mode support for better readability */
            @media (prefers-color-scheme: dark) {{
                .container {{
                    background: #1e293b;
                    color: #f1f5f9;
                }}
                .message-card {{
                    background: #334155;
                    border-left-color: #f97316;
                }}
                .message-title {{
                    color: #f1f5f9;
                }}
                .message-text {{
                    color: #cbd5e1;
                }}
                .field-label {{
                    color: #f1f5f9;
                }}
                .field-value {{
                    background: #475569;
                    color: #f1f5f9;
                    border-color: #64748b;
                }}
                .footer {{
                    background: #334155;
                    border-top-color: #475569;
                }}
                .footer-text {{
                    color: #94a3b8;
                }}
                .company-info {{
                    color: #64748b;
                }}
            }}
            @media (max-width: 600px) {{
                .container {{
                    margin: 10px;
                    border-radius: 12px;
                }}
                .header, .content, .footer {{
                    padding-left: 20px;
                    padding-right: 20px;
                }}
                .header-title {{
                    font-size: 20px;
                }}
                .cta-section {{
                    padding: 20px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="header-title"> DOCUMENTAÇÕES DO FORNECEDOR </h1>
            </div>
            <div class="content">
                <div class="badge">
                    📄 Novas Documentações Recebidas
                </div>
                <div class="message-card">
                    <h2 class="message-title">Documentação de Fornecedor</h2>
                    <p class="message-text">
                        O fornecedor <strong>{fornecedor_nome}</strong> enviou os documentos necessários para cadastro e homologação no sistema.
                    </p>
                    <div class="field">
                        <div class="field-label">
                            <span class="field-icon">📋</span>
                            DOCUMENTO
                        </div>
                        <div class="field-value">{documento_nome}</div>
                    </div>
                    <div class="field">
                        <div class="field-label">
                            <span class="field-icon">🏷️</span>
                            CATEGORIA
                        </div>
                        <div class="field-value">{categoria}</div>
                    </div>
                </div>
                <div class="cta-section">
                    <p class="cta-text">
                        <strong>⚠️ Ação Necessária:</strong> <br> Caso tenha documentos vencidos, alertar ao fornecedor.
                    </p>
                </div>
            </div>
            <div class="footer">
                <p class="footer-text">
                    Se você não esperava por este e-mail, favor desconsiderar esta mensagem.
                </p>
                <p class="company-info">
                    Sistema Engeman - Gestão de Fornecedores<br>
                    Este é um e-mail automático, não responda.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    try:
        msg = Message(
            f'DOCUMENTAÇÕES RECEBIDAS - {fornecedor_nome}',
            recipients=[destinatario],
            html=corpo,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        if arquivos_paths:
            for arquivo_path in arquivos_paths:
                with app.open_resource(arquivo_path) as fp:
                    msg.attach(arquivo_path, "application/octet-stream", fp.read())
        mail.send(msg)
        print(f'E-mail enviado para {destinatario}')
    except Exception as e:
        print(f"Erro ao enviar e-mail para {destinatario}: {e}")
        return None


def _enviar_email_decisao(fornecedor, status_informado, observacao):
    try:
        assunto = (
            "Portal Engeman - Homologacao aprovada"
            if status_informado == 'APROVADO'
            else "Portal Engeman - Homologacao reprovada"
        )
        status_legivel = "aprovado" if status_informado == 'APROVADO' else "reprovado"
        corpo = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resultado da Homologacao</title>
</head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Inter',Arial,sans-serif;color:#0f172a;">
    <table role="presentation" cellspacing="0" cellpadding="0" width="100%">
        <tr>
            <td align="center" style="padding:32px;">
                <table role="presentation" cellspacing="0" cellpadding="0" width="100%" style="max-width:600px;background:#ffffff;border-radius:16px;padding:32px;border:1px solid #e2e8f0;">
                    <tr>
                        <td style="text-align:center;padding-bottom:16px;">
                            <h1 style="margin:0;font-size:22px;color:oklch(0.646 0.222 41.116);">Decisão sobre sua homologação</h1>
                            <p style="margin:8px 0 0;color:#475569;font-size:14px;">Fornecedor: <strong>{fornecedor.nome}</strong></p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:16px;background:#f8fafc;border-radius:12px;border:1px solid #e2e8f0;color:#0f172a;">
                            Informamos que o processo foi <strong>{status_legivel}</strong>.
                            {f"<p style='margin-top:12px;color:#475569;'>Observação: {observacao}</p>" if observacao else ""}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding-top:20px;color:#475569;font-size:13px;">
                            Em caso de dúvidas, nossa equipe está a disposição pelo Portal Engeman.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
        imagem_path = os.path.join(os.path.dirname(app.root_path), 'static', 'colorida.png')
        enviar_email(fornecedor.email, assunto, corpo, imagem_path)
        return True
    except Exception as exc:
        print(f'Erro ao enviar e-mail de decisao: {exc}')
        return False
def enviar_email(destinatario, assunto, corpo, imagem_path):
    try:
        msg = Message(assunto, recipients=[destinatario], html=corpo)
        with open(imagem_path, "rb") as img:
            img_data = img.read()
            encoded_img = base64.b64encode(img_data).decode('utf-8')
        corpo_com_imagem = corpo.replace("cid:engeman_logo", f"data:image/png;base64,{encoded_img}")
        msg.html = corpo_com_imagem
        mail.send(msg)
    except Exception as e:
        print(f"Erro ao enviar e-mail: {e}")
        raise e
def gerar_token_recuperacao():
    return random.randint(100000, 999999)
if __name__ == '__main__':
    app.run(debug=True)

