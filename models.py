from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


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

    documentos = db.relationship(
        'Documento',
        backref='fornecedor',
        lazy=True,
        cascade='all, delete-orphan'
    )
    dados_homologacao = db.relationship(
        'Homologacao',
        backref='fornecedor',
        lazy=True,
        cascade='all, delete-orphan'
    )
    nota_admin = db.relationship(
        'NotaFornecedor',
        backref='fornecedor',
        uselist=False,
        cascade='all, delete-orphan'
    )

    def __init__(self, nome, email, cnpj, senha, **kwargs):
        super().__init__(**kwargs)
        self.nome = nome
        self.email = email
        self.cnpj = cnpj
        self.senha = senha


class Documento(db.Model):
    __tablename__ = 'documentos'

    id = db.Column(db.Integer, primary_key=True)
    nome_documento = db.Column(db.String(100), nullable=False)
    categoria = db.Column(db.String(50), nullable=False)
    data_upload = db.Column(db.DateTime, default=datetime.utcnow)
    mime_type = db.Column(db.String(255), nullable=True)
    dados_arquivo = db.Column(db.LargeBinary, nullable=True)

    fornecedor_id = db.Column(db.Integer, db.ForeignKey('fornecedores.id'), nullable=False)


class Homologacao(db.Model):
    __tablename__ = 'homologacoes'

    id = db.Column(db.Integer, primary_key=True)
    iqf = db.Column(db.Float, nullable=False)
    homologacao = db.Column(db.String(50), nullable=False)
    observacoes = db.Column(db.Text, nullable=True)

    fornecedor_id = db.Column(db.Integer, db.ForeignKey('fornecedores.id'), nullable=False)


class NotaFornecedor(db.Model):
    __tablename__ = 'notas_fornecedores'

    id = db.Column(db.Integer, primary_key=True)
    fornecedor_id = db.Column(
        db.Integer,
        db.ForeignKey('fornecedores.id'),
        nullable=False,
        unique=True
    )
    nota_homologacao = db.Column(db.Float, nullable=True)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    status_decisao = db.Column(db.String(20), nullable=True)
    observacao_admin = db.Column(db.Text, nullable=True)
    nota_referencia = db.Column(db.Float, nullable=True)
    email_enviado = db.Column(db.Boolean, default=False, nullable=False)
    decisao_atualizada_em = db.Column(db.DateTime, nullable=True)
