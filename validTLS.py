#!/usr/bin/python3
import re
import argparse
import socket
import ssl
import warnings
from tabulate import tabulate
from colorama import init, Fore, Style
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def check_tls13_support(dominio):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as secure_sock:
                cipher = secure_sock.cipher()
                if cipher and cipher[1] == "TLSv1.3":
                    return cipher
    except (ssl.SSLError, socket.error):
        pass
    return False

def get_certificate_issuer(dominio):
    try:
        context = ssl.create_default_context()
        clave = 'organizationName'
        with socket.create_connection((dominio, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as secure_sock:
                cert = secure_sock.getpeercert()
                cert2 = secure_sock.getpeercert(binary_form=True)
                issuer = cert['issuer']

                for tupla in issuer:
                    if tupla[0][0] == clave:
                        issuer = tupla[0][1]
                        return issuer
    except (ssl.SSLError, socket.error):
        return None

def get_certificate_key(dominio):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as secure_sock:
                cert = secure_sock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                public_key = x509_cert.public_key()
                key_size = public_key.key_size
                key_algorithm = public_key.__class__.__name__

                if key_size and key_algorithm:
                    key_value = str(key_size) + " " + str(key_algorithm)
                    return key_value

    except (ssl.SSLError, socket.error):
        return None

def get_certificate_expiry(dominio):
    fecha_actual = datetime.now()
    fecha_actual_formateada = fecha_actual.strftime("%Y-%m-%d")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as secure_sock:
                cert = secure_sock.getpeercert()
                fecha_objeto = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                fecha_formateada = fecha_objeto.strftime("%Y-%m-%d")

                diferencia = fecha_objeto - fecha_actual
                dias_diferencia = diferencia.days

                if dias_diferencia > 30:
                    fecha_pintada = Fore.GREEN + fecha_formateada + Fore.WHITE  # verde
                else:
                    fecha_pintada = Fore.RED + fecha_formateada + Fore.WHITE  # rojo

                return fecha_pintada
    except (ssl.SSLError, socket.error):
        return None

def check_tls_support(dominio):
    tls_versions = {}
    for protocol in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]:
        try:
            context = ssl.SSLContext(protocol)
            with socket.create_connection((dominio, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as secure_sock:
                    version = secure_sock.version()
                    tls_versions[protocol] = version
        except (ssl.SSLError, socket.error):
            pass
    return tls_versions

def is_port_open(host, port, timeout=5):
    try:
        socket.setdefaulttimeout(timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def main():
    parser = argparse.ArgumentParser(description='Validación de datos de TLS')
    parser.add_argument('dominio', nargs='?', help='Archivo de dominios')
    parser.add_argument('--archivo', required=False, help='Archivo de dominios')
    parser.add_argument('--output', required=False, help='Archivo de salida')

    args = parser.parse_args()
    dominio = args.dominio
    archivo_dominios = args.archivo
    archivo_salida = args.output

    warnings.filterwarnings("ignore")

    if dominio:
        dominios = [dominio]
    else:
        if not archivo_dominios:
            print("Debe agregar un archivo con dominios o un dominio individual")
            return
        with open(archivo_dominios, 'r') as archivo:
            dominios = archivo.readlines()

    table_data = []

    for dominio in dominios:
        dominio = dominio.strip()  # Eliminar caracteres de nueva línea u otros espacios en blanco

        try:
            socket.gethostbyname(dominio)  # Verificar si el dominio es válido
        except socket.gaierror:
            print(f"Dominio inválido: {dominio}")
            continue

        if not is_port_open(dominio, 443):
            print(f"Puerto 443 cerrado para el dominio: {dominio}")
            continue

        row = []
        row.append(Fore.WHITE + dominio)

        issuer = get_certificate_issuer(dominio)
        if issuer:
            row.append(Fore.GREEN + issuer + Fore.WHITE)
        else:
            row.append(Fore.RED + "Autofirmado" + Fore.WHITE)

        expiry_date = get_certificate_expiry(dominio)
        if expiry_date:
            row.append(expiry_date)
        else:
            row.append(Fore.RED + "No disponible" + Fore.WHITE)

        key_value = get_certificate_key(dominio)
        if key_value:
            row.append(Fore.GREEN + key_value + Fore.WHITE)
        else:
            row.append(Fore.RED + "No disponible" + Fore.WHITE)

        tls_versions = check_tls_support(dominio)
        if tls_versions:
            tls_versions = [tls_versions.get(protocol, Fore.GREEN + "-" + Fore.WHITE) for protocol in [ssl.PROTOCOL_TLSv1, ssl.PROTOCO
            row.extend(tls_versions)
        else:
            row.extend(["No se pudo obtener información"] * 3)

        tlsv13_support = check_tls13_support(dominio)
        if tlsv13_support:
            row.append(Fore.GREEN + "TLSv1.3" + Fore.WHITE)
            row.append(Fore.GREEN + tlsv13_support[0] + Fore.WHITE)
        else:
            row.append(Fore.RED + "No" + Fore.WHITE)
            row.append(Fore.RED + "-" + Fore.WHITE)

        table_data.append(row)

    headers = ["Dominio", "Emisor", "Validez Certificado", "Llave Pública","TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "Cipher"]
    for i in range(len(table_data)):
        for j in range(len(table_data[i])):
            if table_data[i][j] == "TLSv1.1":
                table_data[i][j] = Fore.RED + "TLSv1.1" + Fore.WHITE
            if table_data[i][j] == "TLSv1":
                table_data[i][j] = Fore.RED + "TLSv1" + Fore.WHITE
            if table_data[i][j] == "TLSv1.2":
                table_data[i][j] = Fore.LIGHTYELLOW_EX + "TLSv1.2" + Fore.WHITE

    table = tabulate(table_data, headers=headers, tablefmt="grid")

    if archivo_salida:
        with open(archivo_salida, 'w') as salida:
            salida.write(Fore.WHITE + table)
        print(table)
    else:
        print(table)


if __name__ == '__main__':
    main()
    init()
