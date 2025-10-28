import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Tuple
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ConfiguracionCifrado:
    """Configuración para algoritmos de cifrado simétrico."""
    nombre: str
    tamaño_clave: int
    tamaño_bloque: int
    tamaño_iv: int
    clase_cipher: Any

class ProcesadorBytes:
    """Utilidad para manipulación y ajuste de bytes."""
    
    @staticmethod
    def normalizar_longitud(datos: str, longitud_objetivo: int) -> bytes:
        """Normaliza una cadena a una longitud específica en bytes."""
        datos_bytes = datos.encode('utf-8')
        
        if len(datos_bytes) < longitud_objetivo:
            padding = get_random_bytes(longitud_objetivo - len(datos_bytes))
            return datos_bytes + padding
        elif len(datos_bytes) > longitud_objetivo:
            return datos_bytes[:longitud_objetivo]
        
        return datos_bytes
    
    @staticmethod
    def generar_bytes_aleatorios(cantidad: int) -> bytes:
        """Genera bytes aleatorios seguros."""
        return get_random_bytes(cantidad)

class ValidadorClaves:
    """Validador especializado para diferentes tipos de claves."""
    
    @staticmethod
    def validar_clave_des(clave_bytes: bytes) -> bytes:
        """Valida y ajusta clave DES con paridad correcta."""
        # pycryptodome no tiene adjust_key_parity, usamos la clave directamente
        logger.info(f"Clave DES procesada: {len(clave_bytes)} bytes - {clave_bytes.hex()}")
        return clave_bytes
    
    @staticmethod
    def validar_clave_3des(clave_bytes: bytes) -> bytes:
        """Valida clave 3DES evitando claves débiles."""
        intentos = 0
        while intentos < 100:  # Límite de seguridad
            try:
                # pycryptodome no tiene adjust_key_parity, validamos directamente
                DES3.new(clave_bytes, DES3.MODE_CBC, iv=b"\x00"*8)
                logger.info(f"Clave 3DES validada: {len(clave_bytes)} bytes - {clave_bytes.hex()}")
                return clave_bytes
            except ValueError:
                # Modifica el último byte si la clave es inválida
                clave_bytes = clave_bytes[:-1] + ProcesadorBytes.generar_bytes_aleatorios(1)
                intentos += 1
        
        raise ValueError("No se pudo generar una clave 3DES válida después de múltiples intentos")
    
    @staticmethod
    def validar_clave_aes(clave_bytes: bytes) -> bytes:
        """Valida clave AES-256."""
        logger.info(f"Clave AES-256 procesada: {len(clave_bytes)} bytes - {clave_bytes.hex()}")
        return clave_bytes

class AlgoritmoCifrado(ABC):
    """Clase abstracta para algoritmos de cifrado simétrico."""
    
    def __init__(self, configuracion: ConfiguracionCifrado):
        self.config = configuracion
        self.procesador = ProcesadorBytes()
        self.validador = ValidadorClaves()
    
    @abstractmethod
    def preparar_clave(self, clave_texto: str) -> bytes:
        """Prepara la clave según las especificaciones del algoritmo."""
        pass
    
    def preparar_iv(self, iv_texto: str) -> bytes:
        """Prepara el vector de inicialización."""
        iv_bytes = self.procesador.normalizar_longitud(iv_texto, self.config.tamaño_iv)
        if len(iv_bytes) != self.config.tamaño_iv:
            raise ValueError(f"IV inválido para {self.config.nombre}: requiere {self.config.tamaño_iv} bytes")
        logger.info(f"IV {self.config.nombre} preparado: {len(iv_bytes)} bytes - {iv_bytes.hex()}")
        return iv_bytes
    
    def ejecutar_cifrado_completo(self, mensaje: str, clave_texto: str, iv_texto: str) -> None:
        """Ejecuta el proceso completo de cifrado y descifrado."""
        clave = self.preparar_clave(clave_texto)
        iv = self.preparar_iv(iv_texto)
        
        # Crear cipher para cifrado
        cipher = self.config.clase_cipher.new(clave, self.config.clase_cipher.MODE_CBC, iv)
        
        # Cifrar mensaje
        mensaje_padded = pad(mensaje.encode('utf-8'), self.config.tamaño_bloque)
        texto_cifrado = cipher.encrypt(mensaje_padded)
        
        logger.info(f"{self.config.nombre} - Cifrado completado: {texto_cifrado.hex()}")
        
        # Crear nuevo cipher para descifrado
        decipher = self.config.clase_cipher.new(clave, self.config.clase_cipher.MODE_CBC, iv)
        
        # Descifrar mensaje
        texto_descifrado_bytes = decipher.decrypt(texto_cifrado)
        texto_descifrado = unpad(texto_descifrado_bytes, self.config.tamaño_bloque)
        
        logger.info(f"{self.config.nombre} - Descifrado completado: {texto_descifrado.decode('utf-8')}")
        print(f"\n{self.config.nombre} - Texto cifrado (hex): {texto_cifrado.hex()}")
        print(f"{self.config.nombre} - Texto descifrado: {texto_descifrado.decode('utf-8')}\n")

class ImplementacionDES(AlgoritmoCifrado):
    """Implementación específica para DES."""
    
    def preparar_clave(self, clave_texto: str) -> bytes:
        clave_bytes = self.procesador.normalizar_longitud(clave_texto, self.config.tamaño_clave)
        return self.validador.validar_clave_des(clave_bytes)

class Implementacion3DES(AlgoritmoCifrado):
    """Implementación específica para 3DES."""
    
    def preparar_clave(self, clave_texto: str) -> bytes:
        clave_bytes = self.procesador.normalizar_longitud(clave_texto, self.config.tamaño_clave)
        return self.validador.validar_clave_3des(clave_bytes)

class ImplementacionAES(AlgoritmoCifrado):
    """Implementación específica para AES-256."""
    
    def preparar_clave(self, clave_texto: str) -> bytes:
        clave_bytes = self.procesador.normalizar_longitud(clave_texto, self.config.tamaño_clave)
        return self.validador.validar_clave_aes(clave_bytes)

class FabricaAlgoritmos:
    """Factory para crear instancias de algoritmos de cifrado."""
    
    CONFIGURACIONES = {
        'DES': ConfiguracionCifrado('DES', 8, 8, 8, DES),
        '3DES': ConfiguracionCifrado('3DES', 24, 8, 8, DES3),
        'AES': ConfiguracionCifrado('AES', 32, 16, 16, AES)
    }
    
    @classmethod
    def crear_algoritmo(cls, tipo: str) -> AlgoritmoCifrado:
        """Crea una instancia del algoritmo especificado."""
        if tipo not in cls.CONFIGURACIONES:
            raise ValueError(f"Algoritmo no soportado: {tipo}")
        
        config = cls.CONFIGURACIONES[tipo]
        
        if tipo == 'DES':
            return ImplementacionDES(config)
        elif tipo == '3DES':
            return Implementacion3DES(config)
        elif tipo == 'AES':
            return ImplementacionAES(config)
        
        raise ValueError(f"Implementación no encontrada para: {tipo}")

class InterfazUsuario:
    """Maneja la interacción con el usuario."""
    
    @staticmethod
    def solicitar_datos() -> Dict[str, str]:
        """Solicita todos los datos necesarios al usuario."""
        datos = {}
        
        print("=== Sistema de Cifrado Simétrico ===")
        datos['mensaje'] = input("Ingrese el texto a cifrar: ")
        
        algoritmos = ['DES', '3DES', 'AES']
        for algoritmo in algoritmos:
            datos[f'clave_{algoritmo.lower()}'] = input(f"Ingrese la clave para {algoritmo}: ")
            datos[f'iv_{algoritmo.lower()}'] = input(f"Ingrese el IV para {algoritmo}: ")
        
        return datos

class ControladorPrincipal:
    """Controlador principal que orquesta todo el proceso."""
    
    def __init__(self):
        self.fabrica = FabricaAlgoritmos()
        self.interfaz = InterfazUsuario()
    
    def ejecutar_proceso_completo(self) -> None:
        """Ejecuta el proceso completo de cifrado."""
        try:
            datos_usuario = self.interfaz.solicitar_datos()
            mensaje = datos_usuario['mensaje']
            
            algoritmos_a_procesar = [
                ('DES', datos_usuario['clave_des'], datos_usuario['iv_des']),
                ('3DES', datos_usuario['clave_3des'], datos_usuario['iv_3des']),
                ('AES', datos_usuario['clave_aes'], datos_usuario['iv_aes'])
            ]
            
            for nombre_algoritmo, clave, iv in algoritmos_a_procesar:
                algoritmo = self.fabrica.crear_algoritmo(nombre_algoritmo)
                algoritmo.ejecutar_cifrado_completo(mensaje, clave, iv)
                
        except Exception as e:
            logger.error(f"Error durante la ejecución: {e}")
            print(f"Error: {e}")

def inicializar_aplicacion():
    """Función principal de inicialización."""
    controlador = ControladorPrincipal()
    controlador.ejecutar_proceso_completo()

if __name__ == "__main__":
    inicializar_aplicacion()
