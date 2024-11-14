# Простой менеджер паролей

Это простой менеджер паролей, написанный на Python с использованием PyQt6 для графического интерфейса и библиотеки `cryptography` для шифрования. Он позволяет хранить, добавлять, удалять, генерировать и искать пароли. Данные хранятся в зашифрованной базе данных SQLite.


## Возможности

* Хранение учетных данных (сайт, логин, пароль) в зашифрованной базе данных SQLite.
* Добавление и удаление записей.
* Генерация паролей с настраиваемой длиной и набором символов.
* Поиск по сайту, логину и паролю.
* Импорт и экспорт данных в форматах CSV, JSON и TXT.
* Изменение пароля базы данных.


## Зависимости

* Python 3.7+
* PyQt6
* cryptography

Установите зависимости с помощью pip:

pip install -r requirements.txt
