import os
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'secret-key-here')

    _database_url = os.environ.get('DATABASE_URL', 'sqlite:///fornecedores.db')
    if _database_url.startswith('postgres://'):
        _database_url = _database_url.replace('postgres://', 'postgresql+psycopg2://', 1)
    if _database_url.startswith('postgresql'):
        parsed_url = urlparse(_database_url)
        query_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
        if 'sslmode' not in query_params:
            query_params['sslmode'] = 'require'
        updated_query = urlencode(query_params)
        parsed_url = parsed_url._replace(query=updated_query)
        _database_url = urlunparse(parsed_url)
    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    _pool_recycle = int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 280))
    SQLALCHEMY_POOL_RECYCLE = _pool_recycle
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': _pool_recycle,
    }

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.office365.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in {'true', '1', 'yes'}
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'notificacaosuprimentos@engeman.net')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '02082023Ll*')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
