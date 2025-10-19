from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


"""Tabela de fornecedores"""

class Fornecedor(db.Model):
    __tablename__ = 'fornecedores'

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    cnpj = db.Column(db.String(18), unique=True, nullable=False)
    senha = db.Column(db.String(256), nullable=False)

    token_recuperacao = db.Column(db.String(6), nullable=True)
    token_expira = db.Column(db.DateTime, nullable=True)

    categoria = db.Column(db.String(100), nullable=True)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    documentos = db.relationship('Documento', backref='fornecedor', lazy=True)
    dados_homologacao = db.relationship('Homologacao', backref='fornecedor', lazy=True)

    def __init__(self, nome, email, cnpj, senha, **kwargs):
        super().__init__(**kwargs)
        self.nome = nome
        self.email = email
        self.cnpj = cnpj
        self.senha = senha


"""Tabela de documentos"""

class Documento(db.Model):
    __tablename__ = 'documentos'

    id = db.Column(db.Integer, primary_key=True)
    nome_documento = db.Column(db.String(100), nullable=False)
    categoria = db.Column(db.String(50), nullable=False)
    data_upload = db.Column(db.DateTime, default=datetime.utcnow)

    fornecedor_id = db.Column(db.Integer, db.ForeignKey('fornecedores.id'), nullable=False)


"""Tabela de Homologação"""

class Homologacao(db.Model):
    __tablename__ = 'homologacoes'

    id = db.Column(db.Integer, primary_key=True)
    iqf = db.Column(db.Float, nullable=False)
    homologacao = db.Column(db.String(50), nullable=False)
    observacoes = db.Column(db.Text, nullable=True)

    fornecedor_id = db.Column(db.Integer, db.ForeignKey('fornecedores.id'), nullable=False)


"""Decisão administrativa do fornecedor"""

class DecisaoFornecedor(db.Model):
    __tablename__ = 'decisoes_fornecedor'

    id = db.Column(db.Integer, primary_key=True)
    fornecedor_id = db.Column(db.Integer, db.ForeignKey('fornecedores.id'), unique=True, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    nota_referencia = db.Column(db.Float, nullable=True)
    observacao = db.Column(db.Text, nullable=True)
    avaliador_email = db.Column(db.String(120), nullable=True)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    email_enviado_em = db.Column(db.DateTime, nullable=True)

    fornecedor = db.relationship(
        'Fornecedor',
        backref=db.backref('decisao_admin', uselist=False, cascade="all, delete"),
    )
