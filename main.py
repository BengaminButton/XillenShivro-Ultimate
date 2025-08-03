import os
import sys
import hashlib
import hmac
import ctypes
import struct
import tempfile
import time
import platform
import threading
import random
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext, font, simpledialog
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Protocol.KDF import scrypt, HKDF, PBKDF2
import psutil
import zstandard as zstd
import lzma
import json
from datetime import datetime, timedelta
import zipfile
import io
import string
import argparse
import binascii


# ============= НАСТРОЙКИ БЕЗОПАСНОСТИ =============
class SecurityConfig:
    # Алгоритмы шифрования
    SYMMETRIC_ALGORITHMS = {
        'AES-256': {'key_size': 32, 'iv_size': 16},
        'ChaCha20': {'key_size': 32, 'iv_size': 12}
    }

    ASYMMETRIC_ALGORITHMS = {
        'RSA': {'key_size': 2048},
        'ECC': {'curve': 'P-256'}
    }

    HASH_ALGORITHMS = {
        'SHA3-256': {'output_size': 32},
        'SHA-256': {'output_size': 32},
        'BLAKE2b': {'output_size': 64}
    }

    # Алгоритмы сжатия
    COMPRESSION_ALGORITHMS = {
        'Zstandard': {'level': 3},
        'LZMA': {'level': 6},
        'Нет': {}
    }

    # Функции получения ключа
    KDF_ALGORITHMS = {
        'PBKDF2': {'iterations': 100000},
        'scrypt': {'N': 2 ** 14, 'r': 8, 'p': 1},
        'HKDF': {}
    }

    # Настройки по умолчанию
    DEFAULT_SYMMETRIC = 'AES-256'
    DEFAULT_ASYMMETRIC = 'RSA'
    DEFAULT_HASH = 'SHA3-256'
    DEFAULT_COMPRESSION = 'Zstandard'
    DEFAULT_KDF = 'scrypt'

    # Другие настройки
    MAX_PASSWORD_ATTEMPTS = 3
    SELF_DESTRUCT_DELAY = 5  # секунд
    DEFAULT_EXPIRATION_DAYS = 7
    METADATA_ENCRYPTION = True
    FILE_CHUNK_SIZE = 64 * 1024  # 64KB


# ============= ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ =============
class SecurityUtils:
    @staticmethod
    def secure_erase(data: bytes or str) -> None:
        """Безопасное удаление данных из памяти"""
        if isinstance(data, bytes):
            buffer = (ctypes.c_byte * len(data))()
            ctypes.memmove(buffer, data, len(data))
            for i in range(3):  # Тройная перезапись
                ctypes.memset(buffer, i, len(data))
        elif isinstance(data, str):
            encoded = data.encode('utf-8')
            buffer = (ctypes.c_byte * len(encoded))()
            ctypes.memmove(buffer, encoded, len(encoded))
            for i in range(3):
                ctypes.memset(buffer, i, len(encoded))

    @staticmethod
    def generate_key_pair(algorithm: str = 'RSA') -> tuple:
        """Генерация асимметричной пары ключей"""
        if algorithm == 'RSA':
            key = RSA.generate(SecurityConfig.ASYMMETRIC_ALGORITHMS['RSA']['key_size'])
            return key.export_key(), key.publickey().export_key()
        elif algorithm == 'ECC':
            key = ECC.generate(curve=SecurityConfig.ASYMMETRIC_ALGORITHMS['ECC']['curve'])
            return key.export_key(format='DER'), key.public_key().export_key(format='DER')
        else:
            raise ValueError("Неподдерживаемый асимметричный алгоритм")

    @staticmethod
    def derive_key(password: str, salt: bytes, algorithm: str = 'scrypt') -> bytes:
        """Получение криптографического ключа из пароля"""
        if algorithm == 'scrypt':
            params = SecurityConfig.KDF_ALGORITHMS['scrypt']
            return scrypt(password.encode(), salt,
                          key_len=32,
                          N=params['N'],
                          r=params['r'],
                          p=params['p'])
        elif algorithm == 'PBKDF2':
            params = SecurityConfig.KDF_ALGORITHMS['PBKDF2']
            return PBKDF2(password.encode(), salt, dkLen=32,
                          count=params['iterations'],
                          hmac_hash_module=SHA256)
        elif algorithm == 'HKDF':
            return HKDF(password.encode(), 32, salt, SHA3_256, context=b"XillenShivro")
        else:
            raise ValueError(f"Неподдерживаемый алгоритм получения ключа: {algorithm}")

    @staticmethod
    def compress_data(data: bytes, algorithm: str = 'Zstandard') -> bytes:
        """Сжатие данных перед шифрованием"""
        if algorithm == 'Zstandard':
            cctx = zstd.ZstdCompressor(level=SecurityConfig.COMPRESSION_ALGORITHMS['Zstandard']['level'])
            return cctx.compress(data)
        elif algorithm == 'LZMA':
            return lzma.compress(data, preset=SecurityConfig.COMPRESSION_ALGORITHMS['LZMA']['level'])
        elif algorithm == 'Нет':
            return data
        else:
            raise ValueError("Неподдерживаемый алгоритм сжатия")

    @staticmethod
    def decompress_data(data: bytes, algorithm: str = 'Zstandard') -> bytes:
        """Распаковка данных после дешифрования"""
        if algorithm == 'Zstandard':
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        elif algorithm == 'LZMA':
            return lzma.decompress(data)
        elif algorithm == 'Нет':
            return data
        else:
            raise ValueError("Неподдерживаемый алгоритм сжатия")

    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Генерация безопасного случайного пароля"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

    @staticmethod
    def secure_delete(filepath: str) -> None:
        """Безопасное удаление файла с многократной перезаписью"""
        try:
            with open(filepath, 'ba+') as f:
                length = f.tell()
                f.seek(0)
                for _ in range(3):  # Тройная перезапись
                    f.write(os.urandom(length))
                    f.flush()
                os.fsync(f.fileno())
            os.remove(filepath)
        except Exception as e:
            print(f"Ошибка безопасного удаления: {str(e)}")

    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str = 'SHA3-256') -> str:
        """Вычисление криптографического хеша файла"""
        hash_func = {
            'SHA3-256': hashlib.sha3_256,
            'SHA-256': hashlib.sha256,
            'BLAKE2b': lambda: hashlib.blake2b(digest_size=64)
        }.get(algorithm, hashlib.sha3_256)

        h = hash_func()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()


# ============= ЯДРО ШИФРОВАНИЯ =============
class EncryptionEngine:
    def __init__(self):
        self.attempts = 0
        self.last_attempt = 0
        self.current_settings = {
            'symmetric': SecurityConfig.DEFAULT_SYMMETRIC,
            'asymmetric': SecurityConfig.DEFAULT_ASYMMETRIC,
            'hash_algorithm': SecurityConfig.DEFAULT_HASH,
            'compression': SecurityConfig.DEFAULT_COMPRESSION,
            'kdf': SecurityConfig.DEFAULT_KDF,
            'expiration_days': SecurityConfig.DEFAULT_EXPIRATION_DAYS
        }

    def encrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        """Шифрование файла выбранными алгоритмами"""
        try:
            # Генерация случайной соли и IV
            salt = get_random_bytes(32)
            iv = get_random_bytes(
                SecurityConfig.SYMMETRIC_ALGORITHMS[self.current_settings['symmetric']]['iv_size']
            )

            # Получение ключа шифрования
            key = SecurityUtils.derive_key(password, salt, self.current_settings['kdf'])

            # Чтение файла
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            # Сжатие данных
            compressed = SecurityUtils.compress_data(
                plaintext,
                self.current_settings['compression']
            )

            # Шифрование данных
            ciphertext = self._symmetric_encrypt(
                compressed,
                key,
                iv,
                self.current_settings['symmetric']
            )

            # Подготовка метаданных
            metadata = {
                'original_size': len(plaintext),
                'compressed_size': len(compressed),
                'algorithm': self.current_settings['symmetric'],
                'compression': self.current_settings['compression'],
                'kdf': self.current_settings['kdf'],
                'timestamp': int(time.time()),
                'expiration': int(time.time()) + self.current_settings['expiration_days'] * 86400,
                'filename': os.path.basename(input_path),
                'file_hash_algorithm': self.current_settings['hash_algorithm'],
                'file_hash': SecurityUtils.calculate_file_hash(input_path, self.current_settings['hash_algorithm'])
            }

            if SecurityConfig.METADATA_ENCRYPTION:
                metadata_iv = get_random_bytes(16)
                metadata_encrypted = self._symmetric_encrypt(
                    json.dumps(metadata).encode(),
                    key,
                    metadata_iv,
                    'AES-256'
                )
                metadata_data = metadata_iv + metadata_encrypted
            else:
                metadata_data = json.dumps(metadata).encode()

            # Запись выходного файла
            with open(output_path, 'wb') as f:
                f.write(salt)
                f.write(iv)
                f.write(struct.pack('I', len(metadata_data)))
                f.write(metadata_data)
                f.write(ciphertext)

            return True

        except Exception as e:
            print(f"Ошибка шифрования: {str(e)}")
            return False

    def decrypt_file(self, input_path: str, output_path: str, password: str) -> bool:
        """Дешифрование файла с помощью пароля"""
        try:
            with open(input_path, 'rb') as f:
                salt = f.read(32)
                iv = f.read(
                    SecurityConfig.SYMMETRIC_ALGORITHMS[self.current_settings['symmetric']]['iv_size']
                )
                metadata_size = struct.unpack('I', f.read(4))[0]
                metadata_data = f.read(metadata_size)
                ciphertext = f.read()

            # Получение ключа
            key = SecurityUtils.derive_key(password, salt, self.current_settings['kdf'])

            # Дешифрование метаданных
            if SecurityConfig.METADATA_ENCRYPTION:
                metadata_iv = metadata_data[:16]
                metadata_encrypted = metadata_data[16:]
                metadata_json = self._symmetric_decrypt(
                    metadata_encrypted,
                    key,
                    metadata_iv,
                    'AES-256'
                ).decode()
                metadata = json.loads(metadata_json)
            else:
                metadata = json.loads(metadata_data.decode())

            # Обновление настроек из метаданных
            self.current_settings['symmetric'] = metadata['algorithm']
            self.current_settings['compression'] = metadata['compression']
            self.current_settings['kdf'] = metadata.get('kdf', SecurityConfig.DEFAULT_KDF)
            self.current_settings['hash_algorithm'] = metadata.get('file_hash_algorithm', SecurityConfig.DEFAULT_HASH)

            # Проверка срока действия
            if time.time() > metadata['expiration']:
                SecurityUtils.secure_delete(input_path)
                raise ValueError("Файл просрочен и был безопасно удален")

            # Дешифрование данных
            compressed = self._symmetric_decrypt(
                ciphertext,
                key,
                iv,
                metadata['algorithm']
            )

            # Распаковка
            plaintext = SecurityUtils.decompress_data(
                compressed,
                metadata['compression']
            )

            # Проверка целостности файла
            temp_file = tempfile.mktemp()
            with open(temp_file, 'wb') as f:
                f.write(plaintext)

            hash_algorithm = metadata.get('file_hash_algorithm', SecurityConfig.DEFAULT_HASH)
            current_hash = SecurityUtils.calculate_file_hash(temp_file, hash_algorithm)
            if current_hash != metadata.get('file_hash'):
                os.remove(temp_file)
                raise ValueError("Проверка целостности не удалась - обнаружено возможное вмешательство")

            # Сохранение в конечное расположение
            os.rename(temp_file, output_path)

            return True

        except Exception as e:
            self.attempts += 1
            if self.attempts >= SecurityConfig.MAX_PASSWORD_ATTEMPTS:
                SecurityUtils.secure_delete(input_path)
                raise ValueError("Слишком много неудачных попыток - файл безопасно уничтожен")
            raise ValueError(f"Ошибка дешифрования: {str(e)}")

    def _symmetric_encrypt(self, data: bytes, key: bytes, iv: bytes, algorithm: str) -> bytes:
        """Внутреннее симметричное шифрование"""
        if algorithm == 'AES-256':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(data, AES.block_size))
        elif algorithm == 'ChaCha20':
            cipher = ChaCha20.new(key=key, nonce=iv)
            return cipher.encrypt(data)
        else:
            raise ValueError(f"Неподдерживаемый симметричный алгоритм: {algorithm}")

    def _symmetric_decrypt(self, data: bytes, key: bytes, iv: bytes, algorithm: str) -> bytes:
        """Внутреннее симметричное дешифрование"""
        if algorithm == 'AES-256':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(data), AES.block_size)
        elif algorithm == 'ChaCha20':
            cipher = ChaCha20.new(key=key, nonce=iv)
            return cipher.decrypt(data)
        else:
            raise ValueError(f"Неподдерживаемый симметричный алгоритм: {algorithm}")

    def encrypt_folder(self, folder_path: str, output_path: str, password: str) -> bool:
        """Шифрование всей папки в контейнерный файл"""
        try:
            # Создание временного архива
            temp_archive = tempfile.mktemp(suffix='.zip')

            # Создание zip-архива
            with zipfile.ZipFile(temp_archive, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)

            # Шифрование архива
            result = self.encrypt_file(temp_archive, output_path, password)

            # Очистка
            os.remove(temp_archive)
            return result

        except Exception as e:
            print(f"Ошибка шифрования папки: {str(e)}")
            return False

    def decrypt_folder(self, input_path: str, output_path: str, password: str) -> bool:
        """Дешифрование контейнера папки"""
        try:
            # Сначала дешифрование во временный файл
            temp_archive = tempfile.mktemp(suffix='.zip')
            if not self.decrypt_file(input_path, temp_archive, password):
                return False

            # Создание выходной директории, если её нет
            os.makedirs(output_path, exist_ok=True)

            # Распаковка архива
            with zipfile.ZipFile(temp_archive, 'r') as zipf:
                zipf.extractall(output_path)

            # Очистка
            os.remove(temp_archive)
            return True

        except Exception as e:
            print(f"Ошибка дешифрования папки: {str(e)}")
            return False

    def hybrid_encrypt(self, input_path: str, output_path: str, public_key: bytes) -> bool:
        """Гибридное шифрование с использованием симметричной и асимметричной криптографии"""
        try:
            # Генерация случайного симметричного ключа
            sym_key = get_random_bytes(32)
            iv = get_random_bytes(16)

            # Шифрование файла симметричным ключом
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            cipher = AES.new(sym_key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

            # Шифрование симметричного ключа открытым ключом
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            enc_sym_key = cipher_rsa.encrypt(sym_key)

            # Запись выходного файла
            with open(output_path, 'wb') as f:
                f.write(iv)
                f.write(struct.pack('I', len(enc_sym_key)))
                f.write(enc_sym_key)
                f.write(ciphertext)

            return True

        except Exception as e:
            print(f"Ошибка гибридного шифрования: {str(e)}")
            return False


# ============= ПОЛЬЗОВАТЕЛЬСКИЙ ИНТЕРФЕЙС =============
class XillenShivroUI:
    def __init__(self, root):
        self.root = root
        self.engine = EncryptionEngine()
        self.setup_ui()
        self.setup_security()

    def setup_security(self):
        """Инициализация функций безопасности"""
        # Анти-отладка
        if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
            self.self_destruct("Обнаружен отладчик")

        # Защита памяти
        self.secure_memory = ctypes.create_string_buffer(4096)
        ctypes.memset(self.secure_memory, 0, 4096)

        # Мониторинг потока
        self.monitor_thread = threading.Thread(target=self.security_monitor, daemon=True)
        self.monitor_thread.start()

    def security_monitor(self):
        """Фоновый мониторинг безопасности"""
        while True:
            time.sleep(2)
            # Проверка отладчиков
            if platform.system() == 'Windows':
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    self.self_destruct("Обнаружен отладчик")

            # Очистка защищенной памяти
            ctypes.memset(self.secure_memory, random.randint(0, 255), 4096)

            # Проверка системной безопасности
            self.check_system_security()

    def check_system_security(self):
        """Проверка угроз безопасности"""
        # Проверка известных хакерских инструментов
        blacklist = ['wireshark', 'ollydbg', 'idaq', 'cain']
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in blacklist:
                self.self_destruct(f"Обнаружена угроза безопасности: {proc.info['name']}")

    def self_destruct(self, reason: str):
        """Аварийное самоуничтожение"""
        self.log_message(f"КРИТИЧЕСКАЯ УГРОЗА БЕЗОПАСНОСТИ: {reason}")
        self.log_message(f"САМОУНИЧТОЖЕНИЕ ЧЕРЕЗ {SecurityConfig.SELF_DESTRUCT_DELAY} СЕКУНД")

        # Безопасное удаление конфиденциальных данных
        if hasattr(self, 'pass_entry'):
            SecurityUtils.secure_erase(self.pass_entry.get())
            SecurityUtils.secure_erase(self.confirm_entry.get())

        # Обратный отсчет
        for i in range(SecurityConfig.SELF_DESTRUCT_DELAY, 0, -1):
            self.log_message(f"{i}...")
            time.sleep(1)

        # Завершение приложения
        os._exit(1)

    def setup_ui(self):
        self.root.title("XillenShivro Ultimate - Профессиональное шифрование")
        self.root.geometry("1000x800")
        self.root.configure(bg='#121212')

        # Установка иконки приложения
        try:
            self.root.iconbitmap(default='icon.ico')
        except:
            pass

        # Основной контейнер
        main_frame = tk.Frame(self.root, bg='#121212')
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Заголовок
        header_frame = tk.Frame(main_frame, bg='#121212')
        header_frame.pack(fill='x', pady=(0, 20))

        tk.Label(header_frame,
                 text="XILLENSHIVRO ULTIMATE",
                 font=("Arial", 24, "bold"),
                 fg="#00ffaa",
                 bg='#121212').pack()

        # Информация об авторах
        author_frame = tk.Frame(header_frame, bg='#121212')
        author_frame.pack(pady=5)

        tk.Label(author_frame,
                 text="Автор: @gazprombankrussla | Помощник: @Bengamin_Button",
                 font=("Arial", 10),
                 fg="#aaaaaa",
                 bg='#121212').pack()

        # Выбор операции
        self.operation = tk.StringVar(value="encrypt")

        op_frame = tk.Frame(main_frame, bg='#121212')
        op_frame.pack(fill='x', pady=10)

        tk.Radiobutton(op_frame,
                       text="Шифровать файл",
                       variable=self.operation,
                       value="encrypt",
                       font=("Arial", 10),
                       fg="white",
                       bg='#121212',
                       selectcolor='#121212').pack(side='left', padx=10)

        tk.Radiobutton(op_frame,
                       text="Дешифровать файл",
                       variable=self.operation,
                       value="decrypt",
                       font=("Arial", 10),
                       fg="white",
                       bg='#121212',
                       selectcolor='#121212').pack(side='left', padx=10)

        tk.Radiobutton(op_frame,
                       text="Шифровать папку",
                       variable=self.operation,
                       value="encrypt_folder",
                       font=("Arial", 10),
                       fg="white",
                       bg='#121212',
                       selectcolor='#121212').pack(side='left', padx=10)

        tk.Radiobutton(op_frame,
                       text="Дешифровать папку",
                       variable=self.operation,
                       value="decrypt_folder",
                       font=("Arial", 10),
                       fg="white",
                       bg='#121212',
                       selectcolor='#121212').pack(side='left', padx=10)

        # Выбор файла
        file_frame = tk.LabelFrame(main_frame,
                                   text="Операции с файлами",
                                   font=("Arial", 10, "bold"),
                                   fg="#00ffaa",
                                   bg='#121212',
                                   relief='flat')
        file_frame.pack(fill='x', padx=10, pady=10)

        # Исходный файл
        tk.Label(file_frame,
                 text="Источник:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=0, column=0, sticky='e', padx=5, pady=5)

        self.source_entry = tk.Entry(file_frame,
                                     width=60,
                                     font=("Arial", 10),
                                     bg='#222222',
                                     fg="white",
                                     insertbackground='white',
                                     relief='flat')
        self.source_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(file_frame,
                  text="Обзор",
                  command=self.browse_source,
                  bg='#333333',
                  fg="white",
                  activebackground='#444444',
                  activeforeground="white",
                  relief='flat').grid(row=0, column=2, padx=5, pady=5)

        # Целевой файл
        tk.Label(file_frame,
                 text="Цель:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=1, column=0, sticky='e', padx=5, pady=5)

        self.target_entry = tk.Entry(file_frame,
                                     width=60,
                                     font=("Arial", 10),
                                     bg='#222222',
                                     fg="white",
                                     insertbackground='white',
                                     relief='flat')
        self.target_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(file_frame,
                  text="Обзор",
                  command=self.browse_target,
                  bg='#333333',
                  fg="white",
                  activebackground='#444444',
                  activeforeground="white",
                  relief='flat').grid(row=1, column=2, padx=5, pady=5)

        # Раздел пароля
        pass_frame = tk.LabelFrame(main_frame,
                                   text="Параметры безопасности",
                                   font=("Arial", 10, "bold"),
                                   fg="#00ffaa",
                                   bg='#121212',
                                   relief='flat')
        pass_frame.pack(fill='x', padx=10, pady=10)

        # Пароль
        tk.Label(pass_frame,
                 text="Пароль:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=0, column=0, sticky='e', padx=5, pady=5)

        self.pass_entry = tk.Entry(pass_frame,
                                   show="•",
                                   width=40,
                                   font=("Arial", 12),
                                   bg='#222222',
                                   fg="white",
                                   insertbackground='white',
                                   relief='flat')
        self.pass_entry.grid(row=0, column=1, padx=5, pady=5)

        # Кнопка генерации пароля
        tk.Button(pass_frame,
                  text="Сгенерировать",
                  command=self.generate_password,
                  bg='#444444',
                  fg="white",
                  activebackground='#555555',
                  activeforeground="white",
                  relief='flat').grid(row=0, column=2, padx=5, pady=5)

        # Подтверждение пароля
        tk.Label(pass_frame,
                 text="Подтверждение:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=1, column=0, sticky='e', padx=5, pady=5)

        self.confirm_entry = tk.Entry(pass_frame,
                                      show="•",
                                      width=40,
                                      font=("Arial", 12),
                                      bg='#222222',
                                      fg="white",
                                      insertbackground='white',
                                      relief='flat')
        self.confirm_entry.grid(row=1, column=1, padx=5, pady=5)

        # Индикатор сложности пароля
        self.strength_var = tk.StringVar(value="")
        self.strength_label = tk.Label(pass_frame,
                                       textvariable=self.strength_var,
                                       font=("Arial", 9),
                                       fg="#ff5555",
                                       bg='#121212')
        self.strength_label.grid(row=1, column=2, sticky='w', padx=5)

        # Привязка проверки пароля
        self.pass_entry.bind("<KeyRelease>", self.check_password_strength)
        self.confirm_entry.bind("<KeyRelease>", self.check_password_match)

        # Выбор алгоритма
        algo_frame = tk.LabelFrame(main_frame,
                                   text="Настройки шифрования",
                                   font=("Arial", 10, "bold"),
                                   fg="#00ffaa",
                                   bg='#121212',
                                   relief='flat')
        algo_frame.pack(fill='x', padx=10, pady=10)

        # Симметричный алгоритм
        tk.Label(algo_frame,
                 text="Симметричный:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=0, column=0, sticky='e', padx=5, pady=5)

        self.sym_algo = tk.StringVar(value=SecurityConfig.DEFAULT_SYMMETRIC)
        sym_menu = ttk.Combobox(algo_frame, textvariable=self.sym_algo,
                                values=list(SecurityConfig.SYMMETRIC_ALGORITHMS.keys()),
                                state="readonly",
                                width=15)
        sym_menu.grid(row=0, column=1, sticky='w', padx=5, pady=5)

        # Функция получения ключа
        tk.Label(algo_frame,
                 text="Функция ключа:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=0, column=2, sticky='e', padx=5, pady=5)

        self.kdf_algo = tk.StringVar(value=SecurityConfig.DEFAULT_KDF)
        kdf_menu = ttk.Combobox(algo_frame, textvariable=self.kdf_algo,
                                values=list(SecurityConfig.KDF_ALGORITHMS.keys()),
                                state="readonly",
                                width=10)
        kdf_menu.grid(row=0, column=3, sticky='w', padx=5, pady=5)

        # Алгоритм сжатия
        tk.Label(algo_frame,
                 text="Сжатие:",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=1, column=0, sticky='e', padx=5, pady=5)

        self.comp_algo = tk.StringVar(value=SecurityConfig.DEFAULT_COMPRESSION)
        comp_menu = ttk.Combobox(algo_frame, textvariable=self.comp_algo,
                                 values=list(SecurityConfig.COMPRESSION_ALGORITHMS.keys()),
                                 state="readonly",
                                 width=10)
        comp_menu.grid(row=1, column=1, sticky='w', padx=5, pady=5)

        # Срок действия
        tk.Label(algo_frame,
                 text="Срок действия (дни):",
                 font=("Arial", 10),
                 fg="white",
                 bg='#121212').grid(row=1, column=2, sticky='e', padx=5, pady=5)

        self.exp_days = tk.StringVar(value=str(SecurityConfig.DEFAULT_EXPIRATION_DAYS))
        tk.Entry(algo_frame,
                 textvariable=self.exp_days,
                 width=5,
                 font=("Arial", 10),
                 bg='#222222',
                 fg="white",
                 insertbackground='white',
                 relief='flat').grid(row=1, column=3, sticky='w', padx=5, pady=5)

        # Кнопка выполнения
        self.execute_btn = tk.Button(main_frame,
                                     text="Выполнить операцию",
                                     command=self.execute_operation,
                                     font=("Arial", 12, "bold"),
                                     bg='#00aa77',
                                     fg="white",
                                     activebackground='#008855',
                                     activeforeground="white",
                                     relief='flat',
                                     padx=20,
                                     pady=10)
        self.execute_btn.pack(pady=20)

        # Строка состояния
        self.status_var = tk.StringVar(value="Готов")
        status_bar = tk.Label(main_frame,
                              textvariable=self.status_var,
                              font=("Arial", 9),
                              fg="#aaaaaa",
                              bg='#121212',
                              anchor='w')
        status_bar.pack(side='bottom', fill='x', padx=10, pady=5)

        # Панель журнала
        log_frame = tk.LabelFrame(main_frame,
                                  text="Журнал операций",
                                  font=("Arial", 10, "bold"),
                                  fg="#00ffaa",
                                  bg='#121212',
                                  relief='flat')
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.log = scrolledtext.ScrolledText(log_frame,
                                             bg='#0a0a0a',
                                             fg="#00ffaa",
                                             insertbackground='#00ffaa',
                                             font=("Consolas", 10),
                                             relief='flat')
        self.log.pack(fill='both', expand=True, padx=5, pady=5)
        self.log.insert('end', ">>> XillenShivro Ultimate инициализирован\n")
        self.log.insert('end', ">>> Профессиональное шифрование готово к работе\n")
        self.log.configure(state='disabled')

    def browse_source(self):
        """Выбор исходного файла/папки"""
        if self.operation.get() in ("encrypt_folder", "decrypt_folder"):
            path = filedialog.askdirectory()
        else:
            path = filedialog.askopenfilename()

        if path:
            self.source_entry.delete(0, 'end')
            self.source_entry.insert(0, path)

            # Предложение целевого пути
            if not self.target_entry.get():
                if self.operation.get() in ("encrypt", "encrypt_folder"):
                    self.target_entry.insert(0, path + ".xsec")
                else:
                    if path.endswith(".xsec"):
                        self.target_entry.insert(0, path[:-5])
                    else:
                        self.target_entry.insert(0, path + ".dec")

    def browse_target(self):
        """Выбор целевого расположения"""
        if self.operation.get() in ("encrypt_folder", "decrypt_folder"):
            path = filedialog.askdirectory()
        else:
            path = filedialog.asksaveasfilename()

        if path:
            self.target_entry.delete(0, 'end')
            self.target_entry.insert(0, path)

    def generate_password(self):
        """Генерация и отображение безопасного пароля"""
        password = SecurityUtils.generate_password()
        self.pass_entry.delete(0, 'end')
        self.pass_entry.insert(0, password)
        self.confirm_entry.delete(0, 'end')
        self.confirm_entry.insert(0, password)
        self.log_message(f"Сгенерирован пароль: {password}")
        self.strength_var.set("Сложность: Отличная")
        self.strength_label.config(fg="#00ff00")

    def check_password_strength(self, event=None):
        """Проверка и отображение сложности пароля"""
        password = self.pass_entry.get()
        if len(password) == 0:
            self.strength_var.set("")
            return

        strength = 0
        # Проверка длины
        if len(password) >= 12:
            strength += 1
        if len(password) >= 16:
            strength += 1

        # Разнообразие символов
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()" for c in password)

        if has_upper and has_lower:
            strength += 1
        if has_digit:
            strength += 1
        if has_special:
            strength += 1

        # Обратная связь
        if strength < 3:
            text, color = "Очень слабый", "#ff0000"
        elif strength < 5:
            text, color = "Слабый", "#ff5555"
        elif strength < 7:
            text, color = "Хороший", "#ffff00"
        else:
            text, color = "Отличный", "#00ff00"

        self.strength_var.set(f"Сложность: {text}")
        self.strength_label.config(fg=color)

    def check_password_match(self, event=None):
        """Проверка совпадения паролей"""
        password = self.pass_entry.get()
        confirm = self.confirm_entry.get()

        if password and confirm:
            if password == confirm:
                self.strength_var.set("Пароли совпадают")
                self.strength_label.config(fg="#00ff00")
            else:
                self.strength_var.set("Пароли не совпадают")
                self.strength_label.config(fg="#ff0000")
        else:
            self.strength_var.set("")

    def execute_operation(self):
        """Выполнение выбранной операции"""
        source = self.source_entry.get()
        target = self.target_entry.get()
        password = self.pass_entry.get()
        confirm = self.confirm_entry.get()

        # Проверка входных данных
        if not source or not target:
            messagebox.showerror("Ошибка", "Укажите исходный и целевой пути")
            return

        if password != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return

        if len(password) < 12:
            messagebox.showerror("Ошибка", "Пароль должен содержать не менее 12 символов")
            return

        # Обновление настроек движка
        self.engine.current_settings = {
            'symmetric': self.sym_algo.get(),
            'compression': self.comp_algo.get(),
            'kdf': self.kdf_algo.get(),
            'expiration_days': int(self.exp_days.get()),
            'hash_algorithm': SecurityConfig.DEFAULT_HASH
        }

        try:
            self.execute_btn.config(state='disabled')
            self.status_var.set("Обработка...")
            self.log_message(f"Начало операции: {self.operation.get()}...")
            self.log_message(f"Алгоритм: {self.sym_algo.get()}, KDF: {self.kdf_algo.get()}")

            start_time = time.time()

            if self.operation.get() == "encrypt":
                success = self.engine.encrypt_file(source, target, password)
            elif self.operation.get() == "decrypt":
                success = self.engine.decrypt_file(source, target, password)
            elif self.operation.get() == "encrypt_folder":
                success = self.engine.encrypt_folder(source, target, password)
            elif self.operation.get() == "decrypt_folder":
                success = self.engine.decrypt_folder(source, target, password)
            else:
                raise ValueError("Недопустимая операция")

            elapsed = time.time() - start_time

            if success:
                self.log_message(f"Операция успешно завершена за {elapsed:.2f} секунд")
                self.log_message(f"Результат сохранен в: {target}")
                messagebox.showinfo("Успех", "Операция успешно завершена")
                self.status_var.set("Операция завершена")
            else:
                self.log_message("Ошибка операции")
                messagebox.showerror("Ошибка", "Ошибка выполнения операции")
                self.status_var.set("Ошибка операции")

        except Exception as e:
            self.log_message(f"ОШИБКА: {str(e)}")
            messagebox.showerror("Ошибка", str(e))
            self.status_var.set("Произошла ошибка")

        finally:
            self.execute_btn.config(state='normal')
            self.pass_entry.delete(0, 'end')
            self.confirm_entry.delete(0, 'end')
            self.strength_var.set("")

    def log_message(self, message):
        """Добавление сообщения в журнал"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log.configure(state='normal')
        self.log.insert('end', f"[{timestamp}] {message}\n")
        self.log.see('end')
        self.log.configure(state='disabled')
        self.root.update()


# ============= КОМАНДНАЯ СТРОКА =============
def cli_main():
    parser = argparse.ArgumentParser(description="XillenShivro - Набор шифрования")
    parser.add_argument('operation', choices=['encrypt', 'decrypt', 'encrypt-folder', 'decrypt-folder'],
                        help="Операция для выполнения")
    parser.add_argument('input', help="Путь к исходному файлу или папке")
    parser.add_argument('output', help="Путь к целевому файлу")
    parser.add_argument('--password', help="Пароль шифрования/дешифрования")
    parser.add_argument('--algorithm', default='AES-256', choices=SecurityConfig.SYMMETRIC_ALGORITHMS.keys(),
                        help="Алгоритм шифрования")
    parser.add_argument('--kdf', default='scrypt', choices=SecurityConfig.KDF_ALGORITHMS.keys(),
                        help="Функция получения ключа")
    parser.add_argument('--compression', default='Zstandard', choices=SecurityConfig.COMPRESSION_ALGORITHMS.keys(),
                        help="Алгоритм сжатия")
    parser.add_argument('--expire-days', type=int, default=7, help="Дней до самоуничтожения файла")

    args = parser.parse_args()

    engine = EncryptionEngine()
    engine.current_settings = {
        'symmetric': args.algorithm,
        'compression': args.compression,
        'kdf': args.kdf,
        'expiration_days': args.expire_days,
        'hash_algorithm': SecurityConfig.DEFAULT_HASH
    }

    if not args.password:
        args.password = simpledialog.askstring("Пароль", "Введите пароль:", show='*')
        if not args.password:
            print("Требуется пароль")
            return

    try:
        start_time = time.time()

        if args.operation == 'encrypt':
            success = engine.encrypt_file(args.input, args.output, args.password)
        elif args.operation == 'decrypt':
            success = engine.decrypt_file(args.input, args.output, args.password)
        elif args.operation == 'encrypt-folder':
            success = engine.encrypt_folder(args.input, args.output, args.password)
        elif args.operation == 'decrypt-folder':
            success = engine.decrypt_folder(args.input, args.output, args.password)

        elapsed = time.time() - start_time

        if success:
            print(f"Операция успешно завершена за {elapsed:.2f} секунд")
            print(f"Результат сохранен в: {args.output}")
        else:
            print("Ошибка операции")

    except Exception as e:
        print(f"Ошибка: {str(e)}")


# ============= ТОЧКА ВХОДА =============
if __name__ == "__main__":
    # Проверка режима командной строки
    if len(sys.argv) > 1:
        cli_main()
    else:
        root = tk.Tk()
        app = XillenShivroUI(root)
        root.mainloop()