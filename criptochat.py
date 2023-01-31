#!/usr/bin/env python3
"""
Chat encriptado entre usuarios locales en el dispositivo.
"""
from typing import *
import datetime
import pickle
import rsa
import sys

PADDING_DIGITS = 10
USER_FILE = "data/users.dat"
USERS = {}      # user dictionary


class UserKey(object):
    """
    Esta clase define la clave RSA de un usuario. Sus dos atributos son su clave pública compuesta por el módulo y
    exponente público, y su clave privada compuesta a su vez por el módulo público y el exponente privado. Ambos
    atributos son tuplas de enteros (Tuple[int, int]).
    """
    def __init__(self, n: int, e: int, d: int):
        """
        __init__ de la clase UserKey.
        :param n: int. Módulo público
        :param e: int. Exponente público
        :param d: int. Exponente privado
        """
        self.public_key = n, e
        self.private_key = n, d

    def get_all_keys(self) -> Tuple[int, int, int]:
        """
        Esta función toma las claves pública y privada de la clave RSA y devuelve una tupla con el módulo, exponente
        público y exponente privado, en dicho orden.
        :return: Tuple[int, int, int]. Tupla parámetros clave.
        """
        return self.public_key[0], self.public_key[1], self.private_key[1]


def get_rand_user_key():
    """
    Esta función genera un objeto clave RSA aleatoria. Los primos generados automáticamente son primos de entre 64 y
    128 bits.
    :return: UserKey. Clave aleatoria.
    """
    n, e, d = rsa.generar_claves(18446744073709551616, 340282366920938463463374607431768211456)
    return UserKey(n, e, d)


def valid(n: int, e: int, d: int) -> bool:
    """
    Dados un módulo, un exponente público y uno privado, esta función realiza un test del cifrado y descifrado con
    dichas claves. Si el resultado es erróneo o existe algún fallo, las claves son erróneas. Las claves son válidas
    en caso contrario.
    :param n: int. Módulo público
    :param e: int. Exponente público
    :param d: int. Exponente privado
    :return: bool. True en caso de ser la clave válida, False en caso contrario.
    """
    try:
        return True if "test-message" == rsa.descifrar_cadena_rsa(rsa.cifrar_cadena_rsa("test-message", n, e,
                                                                                        PADDING_DIGITS), n, d,
                                                                  PADDING_DIGITS) else False
    except OverflowError:
        return False


class User(object):
    """
    Esta clase define un usuario del programa. Cada usuario dispone de un nombre de usuario, una clave RSA, un
    identificador distintivo y un inbox en el que se almacenan los mensajes cifrados que este recibe. Dos usuarios
    pueden tener el mismo número pero no el mismo identificador. Los identificadores son enteros enumerados del 0 hasta
    "n", siendo "n" el número de usuarios menos uno.
    """
    def __init__(self, username: str, user_key: UserKey = None, user_id: int = None,
                 inbox: List[Tuple[int, str, List[int] or None]] = None):
        """
        __init__ de la clase User.
        :param username: str. Nombre del usuario.
        :param user_key: UserKey. Clave RSA del usuario. default: genera una clave aleatoria.
        :param user_id: int. Id de usuario. default: "numero de usuarios" en USERS (previo a ser añadido a esta lista).
        :param inbox: List[Tuple[int, str, List[int] or None]]. Inbox del usuario. Incluye None si el mensaje se ha
                      corrompido en algún momento.
        """
        global USERS
        self.username = username
        self.user_key = user_key
        print(f"Tu clave es: n = {user_key.public_key[0]}, e = {user_key.public_key[1]}, d = {user_key.private_key[1]}")
        print()
        self.inbox = inbox
        if not user_id:
            self.id = len(USERS)
        else:
            self.id = user_id

        USERS[self.id] = self

    def change_user_keys(self, n: int, e: int, d: int, checked: bool = False) -> UserKey:
        """
        Esta función cambia los parámetros de la clave de su usuario por los dados. No realiza ninguna comprobación
        de dichos parámetros si se especifica así.
        :param n: int. Módulo público.
        :param e: int. Exponente público.
        :param d: int. Exponente privado.
        :param checked: bool. Indica si se ejecuta o no la verificación de la nueva clave.
        :return: UserKey. Nueva clave de usuario.
        """
        global USERS
        if not checked:
            assert valid(n, e, d), "Clave RSA inválida."
            print("Cambiando claves...")

        # Saving previous keys to change inbox
        prev_n, prev_d = self.user_key.private_key
        self.change_inbox_key(prev_n, prev_d, n, e)
        self.user_key = UserKey(n, e, d)
        # update user on user list
        USERS[self.id] = self
        print(f"Tu nueva clave es: n = {n}, e = {e}, d = {d}")
        return self.user_key

    def check_inbox(self) -> List[Tuple[str, str, str]] or None:
        """
        Descifra los mensajes del inbox y devuelve una lista con los contenedores de mensajes descifrados.
        :return: List[Tuple[str, str, str]]. Contenedor compuesto por nombre emisor, fecha y mensaje descifrado.
                 None. En caso de que el inbox estuviese vacío.
        """
        if self.inbox is None:
            return None
        print("Descifrando mensajes inbox...")
        decrypted_messages = []
        for container in self.inbox:
            username_id, date, message = container
            user = find_user(username_id)

            if message is None:
                decrypted_messages.append((user.username, str(date), "MENSAJE CORRUPTO"))
                continue

            n, d = self.user_key.private_key
            try:
                decrypted_messages.append((user.username, str(date),
                                           rsa.descifrar_cadena_rsa(message, n, d, digitos_padding=PADDING_DIGITS)))
            except ValueError:
                decrypted_messages.append((user.username, str(date), "MENSAJE CORRUPTO"))
        return decrypted_messages

    def change_inbox_key(self, prev_n: int, prev_d: int, new_n: int, new_e: int) -> None:
        """
        Esta función se ejecuta cuando se cambia la clave del usuario. Descifra y cifra los mensajes del inbox con la
        nueva clave para poder ser descifrados a posteriori. En caso de haber un error (con la clave y el padding
        establecido por ejemplo), el mensaje del contenedor se corrompería y no podría volver a recuperarse. Entonces
        el contenedor tiene un None por mensaje.
        :param prev_n: int. Antiguo módulo público.
        :param prev_d: int. Antiguo exponente privado.
        :param new_n: int. Nuevo módulo público.
        :param new_e: int. Nuevo exponente público.
        :return: None.
        """
        if self.inbox:
            temp_inbox = [(container[0], container[1], catch(rsa.descifrar_cadena_rsa, lambda message: None,
                                                             container[2], prev_n, prev_d, PADDING_DIGITS)
                          if container[2] is not None else None) for container in self.inbox]
            self.inbox = []
            for container in temp_inbox:
                try:
                    self.inbox.append((container[0], container[1], rsa.cifrar_cadena_rsa(container[2], new_n, new_e,
                                                                                         PADDING_DIGITS)
                                      if container[2] is not None else None))
                except AssertionError as error_message:
                    print("Assertion:", error_message)
                    self.inbox.append((container[0], container[1], None))
        return None

    def change_inbox_padding(self, padding_digits: int) -> None:
        """
        Esta función se ejecuta cuando se cambia el número de digitos padding del chat. Descifra y cifra los mensajes
        del inbox con el nuevo padding para poder ser descifrados a posteriori. En caso de haber un error (con la clave
        y el padding establecido por ejemplo), el mensaje del contenedor se corrompería y no podría volver a
        recuperarse. Entonces el contenedor tiene un None por mensaje.
        :param padding_digits: int. Nuevo número de dígitos padding.
        :return: None.
        """
        if self.inbox:
            n, e, d = self.user_key.get_all_keys()
            temp_inbox = [(container[0], container[1], catch(rsa.descifrar_cadena_rsa, lambda message: None,
                                                             container[2], n, d, PADDING_DIGITS)
                          if container[2] is not None else None) for container in self.inbox]
            self.inbox = []
            for container in temp_inbox:
                try:
                    self.inbox.append((container[0], container[1], rsa.cifrar_cadena_rsa(container[2], n, e,
                                                                                         padding_digits)
                                       if container[2] is not None else None))
                except ValueError as error_message:
                    print('ValueError:', error_message)
                    self.inbox.append((container[0], container[1], None))

                except AssertionError as error_message:
                    print('AssertionError:', error_message)
                    self.inbox.append((container[0], container[1], None))

            USERS[self.id] = self
        return None


def catch(func, handle=lambda e: None, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as e:
        print(e)
        return handle(e)


class UserNotFound(Exception):
    """
    Excepción personalizada que se eleva siempre y cuando el id de un usuario no se encuentra en el diccionario de
    usuarios registrados.
    """
    def __init__(self, message):
        super().__init__(message)


def create_user(username: str, user_key: UserKey = get_rand_user_key()):
    """
    Función que crea un usuario dados un nombre y una clave (opcional).
    :param username: str. Nombre del nuevo usuario.
    :param user_key: UserKey. Clave RSA del usuario. default: genera una clave aleatoria.
    :return:
    """
    return User(username, user_key)


def find_user(username_id: int) -> User:
    """
    Dado un identificador de usuario, busca y devuelve este en caso de encontrarse en el diccionario de usuarios
    registrados.
    :param username_id: int. Identificador de usuario.
    :return: User. Usuario.
    """
    if username_id in USERS:
        return USERS[username_id]
    raise UserNotFound('El id introducido no se corresponde al de ninguno de los usuarios registrados.')


def send_message(shipper_user: User, receiver_user: User, message: str) -> None:
    """
    Esta función manda un contenedor con un mensaje dado, cifrado con las claves públicas del receptor, conociendo el
    emisor y el receptor.
    :param shipper_user: User. Emisor mensaje.
    :param receiver_user: User. Receptor mensaje.
    :param message: str. Mensaje.
    :return:
    """
    n, e = receiver_user.user_key.public_key
    print("Cifrando mensaje...")
    try:
        encrypted_message = rsa.cifrar_cadena_rsa(message, n, e, digitos_padding=PADDING_DIGITS)
        print("El mensaje ha sido cifrado y enviado.")
        print("Mensaje cifrado:", " ".join(list(map(str, encrypted_message))))
        date = str(datetime.date.today().strftime("%d/%m/%Y"))
        if receiver_user.inbox is None:
            receiver_user.inbox = []
        receiver_user.inbox.append((shipper_user.id, date, encrypted_message))
    except ValueError as error_message:
        print('ValueError:', error_message)
    except AssertionError as error_message:
        print('AssertionError:', error_message)
    finally:
        return None


class Menu:
    """
    Esta clase define el menu/interfaz que se le mostrará al utilizar el programa.
    """
    def __init__(self):
        self.logged_user = None

    def menu(self) -> None or bool:
        exit_menu = False
        while not exit_menu:
            if self.logged_user is None:
                try:
                    print("************Bienvenido a criptochat.py**************")
                    print()

                    choice = input("A: Registre un nuevo usuario\nB: Inicie sesión\nC: Cambiar padding\nD: Mostrar "
                                   "usuarios\nQ: Salir\n\nPor favor elija una opción: ")

                    if choice == "A" or choice == "a":
                        register()
                    elif choice == "B" or choice == "b":
                        self.login()
                        exit_menu = self.menu()
                        print()
                    elif choice == "C" or choice == "c":
                        change_padding()
                    elif choice == "D" or choice == "d":
                        print_users()
                    elif choice == "Q" or choice == "q":
                        exit_menu = True
                    else:
                        raise ValueError('Entrada incorrecta. Debe seleccionar "A", "B", "C", "D" o "Q". Otros valores'
                                         ' no son validos')

                except ValueError as error_message:
                    print('ValueError:', error_message)

            else:
                try:
                    print()
                    print("************Bienvenido a criptochat.py**************")
                    print("Ha iniciado sesión como", self.logged_user.username)

                    choice = input("A: Mirar inbox\nB: Mandar mensaje\nC: Mostrar claves\nD: Cambiar claves\nE:"
                                   " Descifrar mensaje encriptado\nF: Cerrar sesión\nQ: Salir\n\nPor favor elija"
                                   " una opción: ")

                    if choice == "A" or choice == "a":
                        self.check_inbox_menu()
                    elif choice == "B" or choice == "b":
                        self.send_message_menu()
                    elif choice == "C" or choice == "c":
                        user_key = self.logged_user.user_key
                        public_key = user_key.public_key
                        private_key = user_key.private_key
                        print(f"Tu clave pública es: (n, e) = {public_key} y la privada (n, d) = {private_key}.")
                    elif choice == "D" or choice == "d":
                        self.change_keys_menu()
                    elif choice == "E" or choice == "e":
                        self.descifrar_mensaje()
                    elif choice == "F" or choice == "f":
                        self.logged_user = None
                        return False
                    elif choice == "Q" or choice == "q":
                        exit_menu = True
                        return True
                    else:
                        raise ValueError('Entrada incorrecta. Debe seleccionar "A", "B", "C", "D", "E" o "Q". Otros'
                                         ' valores no son validos')

                except ValueError as error_message:
                    print('ValueError:', error_message, 'Inténtalo de nuevo.')
        return None

    def login(self) -> User or None:
        """
        Esta función inicia sesión a un usuario registrado.
        :return: None
        """
        valid_input = False
        user_id = None
        while not valid_input:
            try:
                user_id = input("Seleccione el id de un usuario existente: ")
                if not user_id.isdigit():
                    raise ValueError('Entrada incorrecta. El id de un usuario es un número entero.')
                user_id = int(user_id)
                valid_input = True
            except ValueError as error_message:
                print('ValueError:', error_message)
                print()

        try:
            self.logged_user = find_user(user_id)
            return self.logged_user
        except UserNotFound as error_message:
            print('UserNotFound:', error_message)
            print()

    def check_inbox_menu(self) -> None:
        """
        Esta función imprime en pantalla los mensajes que han sido enviados al usuario que ha iniciado sesión y sus
        detalles (como emisor y fecha).
        :return: None.
        """
        if (inbox := self.logged_user.check_inbox()) is None:
            return print('No has recibido ningún mensaje.')

        count = 0
        for container in inbox:
            count += 1
            print(f'{count} | {container[0]} ({container[1]}): {container[2]}')
        return None

    def send_message_menu(self) -> None:
        """
        Esta función crea el menú que se le presenta al usuario que quiere enviar un mensaje.
        :return: None.
        """
        valid_input = False
        receiver_user_id = None
        while not valid_input:
            try:
                receiver_user_id = input("Seleccione el id de un usuario existente: ")
                if not receiver_user_id.isdigit():
                    raise ValueError('Entrada incorrecta. El id de un usuario es un número entero.')
                receiver_user_id = int(receiver_user_id)
                valid_input = True
            except ValueError as error_message:
                print('ValueError:', error_message)

        try:
            receiver_user = find_user(receiver_user_id)
        except UserNotFound as error_message:
            print('UserNotFound:', error_message)
            return

        message = ""
        while message == "":
            try:
                message = input('Escribe un mensaje de al menos un carácter: ')
                if message == "":
                    raise ValueError('Por favor, escriba un mensaje de al menos un carácter.')
            except ValueError as error_message:
                print(error_message)
        return send_message(self.logged_user, receiver_user, message)

    def change_keys_menu(self) -> None:
        """
        Esta función crea el menú que se le presenta al usuario que quiere cambiar sus claves.
        :return: None.
        """
        try:
            key = input("Claves RSA de usuario (presiona enter para obtener nuevas claves aleatorias): ")
            if not key:
                print("Cambiando claves...")
                n, e, d = rsa.generar_claves(18446744073709551616, 340282366920938463463374607431768211456)
                self.logged_user.change_user_keys(n, e, d, True)

            else:
                key = tuple(key.split(" "))
                for number in key:
                    if not number.isdigit():
                        raise ValueError('Claves incorrectas. Las claves del usuario deben ser 3 enteros positivos'
                                         ' separados por espacios.')

                if 0 < len(key) > 3:
                    raise ValueError('Demasiadas claves. Las claves del usuario deben ser 3 enteros positivos separados'
                                     ' por espacios.')
                n, e, d = tuple(map(int, key))
                self.logged_user.change_user_keys(n, e, d)
                print("Claves modificadas satisfactoriamente.")
            return None

        except ValueError as error_message:
            print('ValueError:', error_message)

        except AssertionError as error_message:
            print('AssertionError:', error_message)

    def descifrar_mensaje(self) -> str:
        """
        Esta función descifra un mensaje cifrado separado por espacios introducido manualmente por el usuario y
        devuelve una string con el mensaje descifrado. Este mensaje es volátil, una vez descifrado, no se guarda.
        :return: None.
        """
        try:
            mensaje = list(input("Introduzca un mensaje cifrado: ").split(" "))
            mensaje = list(map(int, mensaje))
            print(mensaje)
            n, d = self.logged_user.user_key.private_key
            print(n, d)
            print(mensaje_descifrado := rsa.descifrar_cadena_rsa(mensaje, n, d, PADDING_DIGITS))
            return mensaje_descifrado
        except ValueError:
            print('ValueError: El mensaje introducido es incorrecto. Se precisa de una serie de enteros positivos'
                  ' separados por espacios cifrados con la clave pública del usuario y con el padding especificado.')
        except OverflowError as error_message:
            print('OverflowError:', error_message)


def register() -> User:
    """
    Esta función registra un nuevo usuario con los parámetros introducidos por el usuario. Una vez empieza el registro
    debe acabarse para continuar el uso del programa. Presione enter para que el programa introduzca claves aleatorias
    por el usuario.
    :return: User.
    """
    username = ""
    while username == "":
        try:
            username = input("Seleccione un nombre de usuario: ")
            if username == "":
                raise ValueError("Entrada incorrecta. Por favor introduzca un nombre de usuario.")
        except ValueError as error_message:
            print(error_message)

    while True:
        try:
            key = input("Claves RSA de usuario (no obligatorio): ")

            if not key:
                return create_user(username)

            key = tuple(key.split(" "))
            if 0 < len(key) > 3:
                raise ValueError('Demasiadas claves. Las claves del usuario deben ser 3 enteros positivos separados por'
                                 ' espacios.')

            for number in key:
                if not number.isdigit():
                    raise ValueError('Claves incorrectas. Las claves del usuario deben ser 3 enteros positivos'
                                     ' separados por espacios.')

            n, e, d = tuple(map(int, key))
            assert valid(n, e, d), "Clave RSA inválida. Por favor introduzca otra clave."
            user_key = UserKey(n, e, d)
            return create_user(username, user_key)

        except ValueError as error_message:
            print('ValueError:', error_message)

        except AssertionError as error_message:
            print('AssertionError:', error_message)


def print_users() -> None:
    """
    Esta función imprime los identificadores y nombres de todos los usuarios registrados.
    :return: None.
    """
    if not USERS:
        print('\tNo se ha registrado ningún usuario.')
    for user in USERS.values():
        print('\tID:', user.id, 'USERNAME:', user.username)
    print()
    return None


def change_padding() -> None:
    """
    Esta función cambia el número de dígitos de padding de la aplicación. Este retoma su valor predeterminado (10)
    tras reiniciar el programa.
    :return: None.
    """
    global PADDING_DIGITS

    padding_digits = ""
    while not padding_digits.isdigit():
        try:
            padding_digits = input("Introduzca un nuevo número de dígitos de padding: ")
            if not padding_digits.isdigit():
                raise ValueError("Entrada incorrecta El número de dígitos de padding debe ser un entero mayor o igual"
                                 "que 0.")
        except ValueError as error_message:
            print(error_message)

    print("Cambiando padding...")
    padding_digits = int(padding_digits)
    for user in USERS.values():
        user.change_inbox_padding(padding_digits)
    PADDING_DIGITS = padding_digits
    print("Padding modificado satisfactoriamente.")
    print()
    return None


def main():
    try:
        global USERS
        try:
            with open(USER_FILE, 'rb') as file:
                USERS = pickle.load(file)
        except (FileNotFoundError, OSError, IOError):
            print("WARNING: Es posible que los cambios realizados no se graben.")
        except EOFError:
            pass

        menu = Menu()
        return menu.menu()

    except KeyboardInterrupt:
        print("Se ha forzado el fin de la ejecución de criptochat.py. Guardando cambios...")

    finally:
        try:
            with open(USER_FILE, "wb") as file:
                print("Guardando cambios...")
                pickle.dump(USERS, file)
        except (FileNotFoundError, OSError, IOError, EOFError):
            print("Archivo de guardado no encontrado. No se puede grabar los cambios.")


if __name__ == '__main__':
    sys.exit(main())
