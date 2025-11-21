import pandas as pd
import os

STATIC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'static'))

homologados_file = os.path.join(STATIC_PATH, 'fornecedores_homologados.xlsx')
controle_file = os.path.join(STATIC_PATH, 'atendimento controle_qualidade.xlsx')

df_homologados = pd.read_excel(homologados_file)
df_controle = pd.read_excel(controle_file)

print("=== Homologados ===")
print(df_homologados.head())

print("\n=== Controle de Qualidade ===")
print(df_controle.head())

nome = "ENGEMAN"
print("\nFiltrando fornecedor na planilha de homologados:")
print(df_homologados[df_homologados['agente'].str.contains(nome, case=False, na=False)])

print("\nFiltrando fornecedor na planilha de controle de qualidade:")
print(df_controle[df_controle['nome_agente'].str.contains(nome, case=False, na=False)])
