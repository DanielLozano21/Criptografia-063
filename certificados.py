import binascii
import base64
import getpass
import os
import time
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError, InvalidkeyError, CryptoError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

"""El programa se realizo con dos clases una contiene el funcionamiento
y la otra contiene las funciones del menu. Utilizamos tres metodos criptograficos
el primero seria asimetrico con el certificado y la llave privada, el segundo seria simetrico 
cifrando la llave y firmando el certificado con fernet y el tercero seria simetrico para encriptar
el mensaje que guardaremos en un txt"""


class Chida:

    """Primero definimos el constructor y asignamos los objetos que creimos necesarios
    self.genkeypair obtiene la llave que vamos a utilizar en mas funciones, self.usuario
    y self.passwd obtienen el usuario y contraseña"""

    def __init__(self, ):
        self.genkeypair = SigningKey.generate()
        self.usuario = str(input("Ingresa el usuario: \n"))
        self.passwd = str(input("Ingresa la contraseña: \n "))

    """Despues definimos cuatro funciones para manipular archivos y la informacion del programa"""

    @staticmethod
    def stringtobytes(data):
        return base64.decodebytes(data.encode("utf-8"))

    @staticmethod
    def bytestostring(data):
        return base64.encodebytes(data).decode("utf-8")

    @staticmethod
    def read(path):
        with open(path, 'rb') as file:
            return file.read()

    @staticmethod
    def write(data, path):
        with open(path, "wb") as file:
            file.write(data)

    """La funcion criptokey lo que hace es objeto que utilizaremos para poder ejecutar los metodos de 
    encriptado y desencriptado, el cual vendria siendo la llave"""

    def criptokey(self):
        passwd = self.passwd.encode('utf-8')
        salt = b'cdfgtrnhyuioplkj'
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(passwd))
        return key

    """Una vez que tenemos la llave ya la podemos utilizar en las funciones para cifrar/decifrar con fernet """

    def encriptar(self, mensaje):
        key = self.criptokey()
        f = Fernet(key)
        token = f.encrypt(mensaje)
        return token

    def desencriptar(self, mensaje):
        key = self.criptokey()
        f2 = Fernet(key)
        token = f2.decrypt(mensaje)
        return token

    """Esta funcion sing creara el contenido del certificado para que se lo podamos brindar, aqui hicimos uso
    de los constructores para facilitar el codigo"""

    def sing(self):
        singi = SigningKey(self.genkeypair._seed)
        signed = singi.sign(self.usuario.encode('utf-8'))
        return signed

    """Esta funcion login sirve para validar el certificado y la llave del usuario, primero obtnemos el la
     path de ambos archivos desde el usuario con el que hizo login, leemos ambos archivos y almacenamos
     su contenido en una variable, desencriptamos la llave privada y con esa misma verificamos si la firma del
     certificado coincide, en caso de que no coincida nos dara una excepcion porque los parametros seran incorrectos"""

    def login(self):
        try:
            pathk = self.usuario + ".key"
            pathc = self.usuario + ".cer"
            seed = self.read(pathk)
            signed = self.read(pathc)
            keydes = self.desencriptar(seed)
            verkey = SigningKey(keydes).verify_key
            try:
                verkey.verify(signed)
                return True
            except BadSignatureError:
                return False
        except Exception:
            print("Parametros de login invalidos!")
            time.sleep(2)

    """Para el registro del certificado y llave utilizaremos el nombre del usuario que se registros
    y con ese crearemos el path, despues encriptaremos la llave y por ultimo escribiremos ambos archivos
    con la funcion write dandole la informacion y el path"""

    def registro(self):
        pathk = self.usuario + ".key"
        pathc = self.usuario + ".cer"
        self.write(self.encriptar(self.genkeypair._seed), pathk)
        self.write(self.sing(), pathc)

    """Las ultimas dos funciones son para cifrar/decifrar la informacion que se escribira/leera de un archivo txt
    es decir la informacion que cifremos se guaradara en un archivo y para decifrala la leeremos."""

    def rot(self, data):
        password = self.passwd.encode('utf-8')
        encrypted_array = []
        i = 0
        for d in data:
            encrypted_array.append(((d + password[i]) % 256).to_bytes(1, "big"))
            i += 1
            if i >= len(password):
                i = 0
        encriptado = b''.join(encrypted_array)
        path = self.usuario + ".txt"
        self.write(encriptado, path)

    def drot(self):
        try:
            path = self.usuario + '.txt'
            data = self.read(path)
            decrypted_array = []
            i = 0
            password = self.passwd.encode('utf-8')
            for d in data:
                decrypted_array.append(((d - password[i]) % 256).to_bytes(1, "big"))
                i += 1
                if i >= len(password):
                    i = 0
            msgd = ''
            for i in decrypted_array:
                msgd += i.decode('utf-8')
            return msgd
        except Exception:
            print("\nNo se encontro ningun archivo con tu nombre de usuario")


""""En la clase del menu estan las funciones que imprimen distintos menus y la funcion para limpiar la pantalla"""


class Menu:

    @staticmethod
    def cls(tim):
        os.system('cls' if os.name == 'nt' else 'clear')
        time.sleep(tim)

    @staticmethod
    def menu1():
        print("""
▄█▄    █▄▄▄▄ ▄█ █ ▄▄     ▄▄▄▄▀ ████▄   ▄▀  █▄▄▄▄ ██   ▄████  ▄█ ██   
█▀ ▀▄  █  ▄▀ ██ █   █ ▀▀▀ █    █   █ ▄▀    █  ▄▀ █ █  █▀   ▀ ██ █ █  
█   ▀  █▀▀▌  ██ █▀▀▀      █    █   █ █ ▀▄  █▀▀▌  █▄▄█ █▀▀    ██ █▄▄█ 
█▄  ▄▀ █  █  ▐█ █        █     ▀████ █   █ █  █  █  █ █      ▐█ █  █ 
▀███▀    █    ▐  █      ▀             ███    █      █  █      ▐    █ 
         ▀         ▀                         ▀      █    ▀         █ 

                         """)
        print('Elige una opcion')
        print('1--Registrarse')
        print('2--Login')
        print('3--Salir')

    @staticmethod
    def menu2():
        print("""
▄█▄    █▄▄▄▄ ▄█ █ ▄▄     ▄▄▄▄▀ ████▄   ▄▀  █▄▄▄▄ ██   ▄████  ▄█ ██   
█▀ ▀▄  █  ▄▀ ██ █   █ ▀▀▀ █    █   █ ▄▀    █  ▄▀ █ █  █▀   ▀ ██ █ █  
█   ▀  █▀▀▌  ██ █▀▀▀      █    █   █ █ ▀▄  █▀▀▌  █▄▄█ █▀▀    ██ █▄▄█ 
█▄  ▄▀ █  █  ▐█ █        █     ▀████ █   █ █  █  █  █ █      ▐█ █  █ 
▀███▀    █    ▐  █      ▀             ███    █      █  █      ▐    █ 
         ▀         ▀                         ▀      █    ▀         █ 

                 """)
        print("Elige una opcion")
        print("1--Guardar mensaje encriptado")
        print("2--Desencriptar mensaje guardado")
        print("3--Salir")

    @staticmethod
    def menu3():
        print("""
▄█▄    █▄▄▄▄ ▄█ █ ▄▄     ▄▄▄▄▀ ████▄   ▄▀  █▄▄▄▄ ██   ▄████  ▄█ ██   
█▀ ▀▄  █  ▄▀ ██ █   █ ▀▀▀ █    █   █ ▄▀    █  ▄▀ █ █  █▀   ▀ ██ █ █  
█   ▀  █▀▀▌  ██ █▀▀▀      █    █   █ █ ▀▄  █▀▀▌  █▄▄█ █▀▀    ██ █▄▄█ 
█▄  ▄▀ █  █  ▐█ █        █     ▀████ █   █ █  █  █  █ █      ▐█ █  █ 
▀███▀    █    ▐  █      ▀             ███    █      █  █      ▐    █ 
         ▀         ▀                         ▀      █    ▀         █ 

                 """)
        print("Escribe el mensaje que se encriptara")

    @staticmethod
    def menu4():
        print("""
▄█▄    █▄▄▄▄ ▄█ █ ▄▄     ▄▄▄▄▀ ████▄   ▄▀  █▄▄▄▄ ██   ▄████  ▄█ ██   
█▀ ▀▄  █  ▄▀ ██ █   █ ▀▀▀ █    █   █ ▄▀    █  ▄▀ █ █  █▀   ▀ ██ █ █  
█   ▀  █▀▀▌  ██ █▀▀▀      █    █   █ █ ▀▄  █▀▀▌  █▄▄█ █▀▀    ██ █▄▄█ 
█▄  ▄▀ █  █  ▐█ █        █     ▀████ █   █ █  █  █  █ █      ▐█ █  █ 
▀███▀    █    ▐  █      ▀             ███    █      █  █      ▐    █ 
         ▀         ▀                         ▀      █    ▀         █ 

                 """)
        print("Escribe el mensaje que se desencriptara")


"""Por ultimo creamos un menu ciclico donde llamamos las funciones de las clases para que pueda funcionar"""


if __name__ == '__main__':

    menu = Menu()

    while True:
        menu.cls(0)
        menu.menu1()
        opc = str(input(">"))
        if opc == '3':
            break

        chida = Chida()

        if opc == '1':
            chida.registro()

        elif opc == '2':
            if chida.login():
                while True:
                    menu.cls(.5)
                    menu.menu2()
                    opc2 = str(input(">"))
                    if opc2 == '1':
                        menu.cls(.1)
                        menu.menu3()
                        mssg = str(input(">"))
                        chida.rot(mssg.encode('utf-8'))
                        input("Presiona enter para continuar")
                    elif opc2 == '2':
                        menu.cls(.1)
                        menu.menu4()
                        print("\nEl mensaje contenido es --> ", chida.drot(), "\n")
                        input("Presiona enter para continuar")
                    elif opc2 == '3':
                        break
