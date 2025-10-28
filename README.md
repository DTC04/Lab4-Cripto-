# Cifrado Simétrico en Python (DES, 3DES y AES)

Este proyecto implementa un sistema de cifrado y descifrado en **Python** utilizando los algoritmos simétricos **DES**, **3DES** y **AES-256** en modo **CBC (Cipher Block Chaining)**.  

El programa solicita al usuario un mensaje, una clave y un vector de inicialización (IV) para cada algoritmo, ajusta las claves a la longitud requerida y muestra los resultados del texto cifrado y descifrado.

---

## 🚀 Características

- Soporta **DES (56 bits efectivos)**, **3DES (168 bits efectivos)** y **AES-256 (256 bits)**.
- Ajusta automáticamente la longitud de claves e IV:
  - Trunca si son demasiado largas.
  - Completa con bytes aleatorios si son demasiado cortas.
- Utiliza **padding PKCS#7** para mensajes que no coinciden con el tamaño de bloque.
- Imprime:
  - La clave final usada (en hexadecimal).
  - El texto cifrado (en hexadecimal).
  - El texto descifrado (para verificar que coincide con el original).
- Arquitectura orientada a objetos:
  - **ProcesadorBytes**: ajusta cadenas y genera bytes aleatorios.
  - **ValidadorClaves**: valida y ajusta claves según algoritmo.
  - **AlgoritmoCifrado**: clase abstracta para DES, 3DES y AES.
  - **FabricaAlgoritmos**: patrón fábrica para crear instancias de algoritmos.
  - **InterfazUsuario**: maneja entradas desde la terminal.
  - **ControladorPrincipal**: orquesta todo el flujo del programa:contentReference[oaicite:0]{index=0}.

---

## 📦 Requisitos

- Python 3.8+
- Librería [PyCryptodome](https://www.pycryptodome.org/)

Instalación de dependencias:

```bash
pip install pycryptodome
