from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def enviar_email(destinatario, assunto, corpo):
    msg = Message(assunto, recipients=[destinatario])
    msg.body = corpo
    mail.send(msg)
    
import random

def gerar_token_recuperacao():
    return ''.join([str(random.randint(0, 9)) for _ in range(4)])
