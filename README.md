
---

### 4. XillenShivro Ultimate (`main.py`)  
**Профессиональный инструмент шифрования файлов**  

```markdown
# XillenShivro Ultimate

Мощное приложение для шифрования файлов и папок с использованием современных криптографических алгоритмов.

## 🔒 Особенности
- **Алгоритмы шифрования**: AES-256, ChaCha20
- **Ключи**: Генерация ключей RSA/ECC
- **Сжатие**: Zstandard, LZMA
- **Безопасность**: Самоуничтожение при обнаружении отладки
- **Гибкие настройки**: Выбор алгоритмов через GUI
- **CLI-интерфейс**: Для автоматизации задач

## 📦 Установка
```bash
git clone https://github.com/BengaminButton/xillen-shivro.git
cd xillen-shivro
pip install -r requirements.txt

🖥️ Запуск GUI
bash

python main.py

⌨️ Запуск CLI
bash

# Шифрование файла
python main.py encrypt input.txt output.xsec --password "secret"

# Дешифровка
python main.py decrypt output.xsec decrypted.txt --password "secret"

🛡️ Защитные механизмы

    Анти-отладка

    Мониторинг процессов

    Безопасное удаление ключей

    Контроль целостности файлов

👥 Авторы

    @gazprombankrussla

    @BengaminButton
