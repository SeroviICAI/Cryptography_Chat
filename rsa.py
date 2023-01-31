"""
Librería principal de criptografía RSA que define las funciones principales del
programa criptochat.py.
"""
from math import log10
from typing import *
import modular
import random


def generar_claves(min_primo: int, max_primo: int) -> Tuple[int, int, int]:
    """
    Esta función, dados un intervalo en el que se generen los números primos factores del módulo n, devuelve una tupla
    de enteros en el que el primer y segundo índice representan la clave pública "n" y "e", y el tercero la privada "d".
    :param min_primo: Cota inferior para generación de primos.
    :param max_primo: Cota superior para generación de primos (no incluida).
    :return: Tuple[int, int, int]. Los elementos representan respectivamente: n, e y d; siendo n y e la clave pública y
             d la privada.
    """
    primo_1, primo_2 = generar_numeros_primos(min_primo, max_primo, 2)
    n = primo_1 * primo_2
    phi = (primo_1 - 1) * (primo_2 - 1)
    while True:
        e = random.randrange(1, phi, 2)
        if modular.coprimos(phi, e):
            break
    d = modular.inversa_mod_p(e, phi)
    return n, e, d


def generar_numeros_primos(min_primo: int, max_primo: int, numero: int) -> int or Tuple[int, ...]:
    """
    Esta función devuelve tantos primos aleatorios en el intervalo [min_primo, max_primo) como se hayan especificado.
    :param min_primo: Cota inferior entera.
    :param max_primo: Cota superior entera (no incluida).
    :param numero: Número de primos a generar.
    :return: int. Entero primo generado (si numero = 1). Tuple[int, ...]. Tupla de enteros primos generados (si numero >
             1).
    """
    if numero < 1:
        raise ValueError("El número de primos debe ser un entero mayor a 0")

    if min_primo > max_primo:
        raise ValueError("El min_primo no puede ser mayor a max_primo")

    output_primos = []
    lista_aleatorios = [random.randint(min_primo - 1, max_primo) for __ in range(numero)]
    for n in lista_aleatorios:
        p = siguiente_primo(n)
        while p in output_primos:
            p = siguiente_primo(p)

        if p >= max_primo:
            p = anterior_primo(max_primo)
            while p in output_primos:
                p = anterior_primo(p)

        if p < min_primo or isinstance(p, float):
            raise ValueError("no existen tantos primos en el intervalo especificado")
        output_primos.append(p)
    return output_primos[0] if len(output_primos) == 1 else tuple(output_primos)


def siguiente_primo(n: int) -> int:
    """
    Esta función dado un entero, devuelve el siguiente número mayor al dado que sea primo.
    :param n: int. Número del que se quiere conocer su siguiente primo.
    :return: int. Número primo.
    """
    n += 1
    while not modular.es_primo(n):
        n += 1
    return n


def anterior_primo(n: int) -> int or modular.NE:
    """
    Esta función dado un entero, devuelve el anterior número menor al dado que sea primo.
    :param n: int. Número del que se quiere conocer su anterior primo.
    :return: int. Número primo. NE. Si el número dado no tiene primos anteriores.
    """
    try:
        assert n > 2, 'No existen números primos menores a 2'
        n -= 1
        while not modular.es_primo(n):
            n -= 1
        return n
    except AssertionError:
        return modular.NE


def aplicar_padding(m: int, digitos_padding: int) -> int:
    if digitos_padding < 0 or m < 0:
        raise ValueError('Entrada incorrecta. Las entradas deben ser enteros positivos.')
    return int(str(m) + "".join(str(random.randint(0, 9)) for __ in range(0, digitos_padding)))


def eliminar_padding(m: int, digitos_padding: int) -> int:
    if not 0 <= digitos_padding < (int(log10(m)) + 1):
        raise ValueError('Los dígitos padding deben ser menores al número de cifras del mensaje y mayores que 0')
    return m // (10 ** digitos_padding)


def cifrar_rsa(m: int, n: int, e: int, digitos_padding: int) -> int:
    """
    Esta función, dado un mensaje (número entero) y una clave púbica, lo cifra mediante RSA aplicando padding de "n"
    dígitos, dado un "n" entero. Los dígitos padding deben ser menores al número de cifras del módulo menos el de las
    cifras del mensaje.
    :param m: int. Mensaje a cifrar.
    :param n: int. Módulo público.
    :param e: int. Exponente público.
    :param digitos_padding: int. Número dígitos de padding
    :return: int. Mensaje cifrado.
    """
    if m < 0 or n < 0 or e < 0 or digitos_padding < 0:
        raise ValueError('Entrada incorrecta. Las entradas deben ser enteros positivos.')
    assert (int(log10(m)) + 1 + digitos_padding) < (int(log10(n)) + 1), 'Los dígitos padding deben ser ' \
                                                                        'menores al número de cifras ' \
                                                                        'del módulo menos el del mensaje'
    m = aplicar_padding(m, digitos_padding)
    return modular.potencia_mod_p(m, e, n)


def descifrar_rsa(c: int, n: int, d: int, digitos_padding: int) -> int:
    """
    Esta función toma un mensaje entero cifrado c y una clave privada de dos enteros n y d, y devuelve el mensaje plano
    usando RSA con dicha clave y eliminando digitos padding cifras de padding.
    :param c: int. Mensaje cifrado.
    :param n: int. Módulo público.
    :param d: int. Clave privada.
    :param digitos_padding: int. Número dígitos de padding.
    :return: int. Mensaje plano.
    """
    c = modular.potencia_mod_p(c, d, n)
    return eliminar_padding(c, digitos_padding)


def cifrar_cadena_rsa(s: str, n: int, e: int, digitos_padding: int) -> List[int]:
    """
    Esta función convierte una string en código unicode y devuelve una lista de enteros que representan cada carácter
    cifrado con RSA, dadas una clave pública y un número entero de dígitos de padding.
    :param s: int. str. String a cifrar.
    :param n: int. Módulo público.
    :param e: int. Exponente público.
    :param digitos_padding: int. Número dígitos de padding.
    :return: List[int]. Lista de caracteres cifrados.
    """
    return [cifrar_rsa(ord(char), n, e, digitos_padding) for char in s]


def descifrar_cadena_rsa(clist: List[int], n: int, d: int, digitos_padding: int) -> str:
    """
    Esta función dado una lista de caracteres cifrados mediante RSA los descifra convirtiéndolos a una string plana.
    :param clist: List[int]. Lista de caracteres cifrados.
    :param n: int. Módulo público.
    :param d: int. Clave privada.
    :param digitos_padding: int. Número dígitos de padding.
    :return: str. String plana.
    """
    return "".join(chr(descifrar_rsa(c, n, d, digitos_padding)) for c in clist)


def romper_clave(n: int, e: int) -> int:
    """
    Esta función devuelve la clave privada dada una clave RSA pública.
    :param n: Módulo público.
    :param e: Exponente público.
    :return: int. Clave privada.
    """
    assert 1 < e < (phi := modular.euler(n)) and modular.coprimos(phi, e), "Clave pública no es válida."
    return modular.inversa_mod_p(e, phi)


def ataque_texto_plano(clist: List[int], n: int, e: int) -> str:
    """
    Esta función devuelve una string descifrada dada una clave pública y una lista de caracteres cifrados.
    :param clist: List[int]. Lista de caracteres cifrados.
    :param n: int. Módulo público
    :param e: int. Exponente público.
    :return: str. String descifrada.
    """
    d = romper_clave(n, e)
    return descifrar_cadena_rsa(clist, n, d, digitos_padding=0)
