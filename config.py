import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'secret-key-here')

    _database_url = os.environ.get('DATABASE_URL', 'sqlite:///fornecedores.db')
    if _database_url.startswith('postgres://'):
        _database_url = _database_url.replace('postgres://', 'postgresql+psycopg2://', 1)
    SQLALCHEMY_DATABASE_URI = _database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.office365.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in {'true', '1', 'yes'}
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'notificacaosuprimentos@engeman.net')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '02082023Ll*')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
