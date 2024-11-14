import base64
import json
import random
import sqlite3
import string
import sys
import csv

from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QTableView,
                             QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox,
                             QHeaderView, QSlider, QCheckBox, QLineEdit,
                             QInputDialog, QStyledItemDelegate, QAbstractItemView,
                             QSpinBox, QGroupBox, QLabel, QMenuBar,
                             QDialog, QFormLayout, QDialogButtonBox)
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class TableEditorDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        return QLineEdit(parent)

    def setEditorData(self, editor, index):
        value = index.model().data(index, Qt.ItemDataRole.DisplayRole)
        editor.setText(value if value is not None else "")

    def setModelData(self, editor, model, index):
        value = editor.text()
        model.setData(index, value, Qt.ItemDataRole.EditRole)


class TableModel(QAbstractTableModel):
    def __init__(self, data):
        super().__init__()
        self._data = data

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole:
            try:
                return self._data[index.row()][index.column()]
            except IndexError:
                return None
        return None

    def rowCount(self, parent=QModelIndex()):
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):
        return len(self._data[0]) if self._data else 0

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole:
            if orientation == Qt.Orientation.Horizontal:
                return ["Сайт", "Логин", "Пароль"][section]
            else:
                return str(section + 1)
        return None

    def flags(self, index):
        return Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsEditable

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if role == Qt.ItemDataRole.EditRole:
            self._data[index.row()][index.column()] = value
            self.dataChanged.emit(index, index, [Qt.ItemDataRole.DisplayRole])
            return True
        return False


class PasswordGenerator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Генератор паролей")

        length_group = QGroupBox("Длина пароля")
        self.length_slider = QSlider(Qt.Orientation.Horizontal)
        self.length_slider.setRange(4, 64)
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(4, 64)
        self.length_slider.valueChanged.connect(self.length_spinbox.setValue)
        self.length_spinbox.valueChanged.connect(self.length_slider.setValue)
        length_layout = QHBoxLayout()
        length_layout.addWidget(self.length_slider)
        length_layout.addWidget(self.length_spinbox)
        length_group.setLayout(length_layout)

        char_set_group = QGroupBox("Набор символов")
        self.lowercase_checkbox = QCheckBox("Строчные буквы (a-z)")
        self.uppercase_checkbox = QCheckBox("Прописные буквы (A-Z)")
        self.digits_checkbox = QCheckBox("Цифры (0-9)")
        self.special_chars_checkbox = QCheckBox("Специальные символы (!@#$%^&*)")
        self.lowercase_checkbox.setChecked(True)
        self.uppercase_checkbox.setChecked(True)
        self.digits_checkbox.setChecked(True)
        self.special_chars_checkbox.setChecked(True)

        char_set_layout = QVBoxLayout()
        char_set_layout.addWidget(self.lowercase_checkbox)
        char_set_layout.addWidget(self.uppercase_checkbox)
        char_set_layout.addWidget(self.digits_checkbox)
        char_set_layout.addWidget(self.special_chars_checkbox)
        char_set_group.setLayout(char_set_layout)

        self.generate_button = QPushButton("Сгенерировать")
        self.password_edit = QLineEdit()
        self.password_edit.setReadOnly(True)
        self.copy_button = QPushButton("Скопировать")

        layout = QVBoxLayout()
        layout.addWidget(length_group)
        layout.addWidget(char_set_group)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.password_edit)
        layout.addWidget(self.copy_button)
        self.setLayout(layout)

        self.generate_button.clicked.connect(self.generate_password)
        self.copy_button.clicked.connect(self.copy_password)

    def generate_password(self):
        length = self.length_slider.value()
        chars = ""
        if self.lowercase_checkbox.isChecked():
            chars += string.ascii_lowercase
        if self.uppercase_checkbox.isChecked():
            chars += string.ascii_uppercase
        if self.digits_checkbox.isChecked():
            chars += string.digits
        if self.special_chars_checkbox.isChecked():
            chars += string.punctuation

        if not chars:
            QMessageBox.warning(self, "Ошибка", "Выберите хотя бы один набор символов.")
            return

        password = ''.join(random.choice(chars) for _ in range(length))
        self.password_edit.setText(password)

    def copy_password(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.password_edit.text())


class SearchFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._search_text = ""

    def setSearchText(self, text):
        self._search_text = text
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        if not self._search_text:
            return True

        model = self.sourceModel()
        for column in range(model.columnCount()):
            index = model.index(source_row, column, source_parent)
            data = model.data(index, Qt.ItemDataRole.DisplayRole)
            if data and self._search_text.lower() in data.lower():
                return True
        return False


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Менеджер паролей")

        screen = QApplication.primaryScreen()
        screen_geometry = screen.geometry()
        screen_width = screen_geometry.width()
        screen_height = screen_geometry.height()

        window_width = int(screen_width * 0.6)
        window_height = int(screen_height * 0.6)

        self.setGeometry(
            (screen_width - window_width) // 2,
            (screen_height - window_height) // 2,
            window_width,
            window_height
        )

        self.table_view = QTableView()
        self.model = TableModel([])
        delegate = TableEditorDelegate(self.table_view)
        self.table_view.setItemDelegate(delegate)
        self.table_view.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked |
                                        QAbstractItemView.EditTrigger.EditKeyPressed)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

        self.add_button = QPushButton("Добавить")
        self.remove_button = QPushButton("Удалить")
        self.generate_password_button = QPushButton("Генерировать пароль")

        self.search_label = QLabel("Поиск:")
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Введите текст")

        menubar = QMenuBar(self)
        file_menu = menubar.addMenu("&Файл")
        help_menu = menubar.addMenu("&Справка")

        load_action = QAction("&Загрузить", self)
        load_action.triggered.connect(self.load_data)
        file_menu.addAction(load_action)

        save_action = QAction("&Сохранить", self)
        save_action.triggered.connect(self.save_data)
        file_menu.addAction(save_action)

        save_as_action = QAction("Сохранить &как...", self)
        save_as_action.triggered.connect(self.save_as)
        file_menu.addAction(save_as_action)

        export_action = QAction("&Экспортировать", self)
        export_action.triggered.connect(self.export_data)
        file_menu.addAction(export_action)

        import_action = QAction("&Импортировать", self)
        import_action.triggered.connect(self.import_data)
        file_menu.addAction(import_action)

        change_password_action = QAction("Изменить &пароль базы данных", self)
        change_password_action.triggered.connect(self.change_db_password)
        file_menu.addAction(change_password_action)

        exit_action = QAction("&Выйти", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        about_action = QAction("&О программе", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        self.add_button.clicked.connect(self.add_row)
        self.remove_button.clicked.connect(self.remove_row)
        self.generate_password_button.clicked.connect(self.show_password_generator)

        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.addWidget(menubar)
        layout.addWidget(self.table_view)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.add_button)
        buttons_layout.addWidget(self.remove_button)
        buttons_layout.addWidget(self.generate_password_button)
        buttons_layout.addWidget(self.search_label)
        buttons_layout.addWidget(self.search_field)

        layout.addLayout(buttons_layout)
        self.setLayout(layout)

        self.proxy_model = SearchFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.model)
        self.table_view.setModel(self.proxy_model)

        self.password_generator = PasswordGenerator()

        self.db_connection = None
        self.filepath = None
        self.key = None
        self.salt = b'ThisIsASaltForPasswordDerivation'

    def closeEvent(self, event):
        if self.model._data:
            reply = QMessageBox.question(self, 'Сохранение', "Сохранить изменения перед закрытием?",
                                         QMessageBox.StandardButton.Yes | \
                                         QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel)
            if reply == QMessageBox.StandardButton.Yes:
                if self.filepath:
                    self.save_data()
                else:
                    self.save_as()
                if self.filepath is None:
                  event.ignore()
                  return
            elif reply == QMessageBox.StandardButton.Cancel:
                event.ignore()
                return
            event.accept()

    def copy_password(self):
        index = self.table_view.currentIndex()
        if index.isValid():
            password = self.model.data(index.siblingAtColumn(2))
            QApplication.clipboard().setText(password)

    def get_encryption_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_string(self, string_to_encrypt):
        f = Fernet(self.key)
        encrypted_string = f.encrypt(string_to_encrypt.encode())
        return encrypted_string.decode()

    def decrypt_string(self, string_to_decrypt):
        f = Fernet(self.key)
        try:
            decrypted_string = f.decrypt(string_to_decrypt.encode()).decode()
            return decrypted_string
        except Exception:
            return None

    def load_data(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Открыть базу данных", "", "SQLite базы данных (*.db)")
        if not filepath:
            return

        password, ok = QInputDialog.getText(self, "Пароль базы данных", "Введите пароль:", QLineEdit.EchoMode.Password)
        if not ok:
            return

        try:
            self.key = self.get_encryption_key(password)
            self.db_connection = sqlite3.connect(filepath)
            self.db_connection.create_function("decrypt_string", 1, self.decrypt_string)
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT decrypt_string(website), decrypt_string(login), decrypt_string(password) FROM passwords")

            data = []
            for row in cursor.fetchall():
                decrypted_password = row
                if decrypted_password is None:
                    raise ValueError("Wrong password or corrupted data.")
                data.append(list(row))

            self.model = TableModel(data)
            self.proxy_model.setSourceModel(self.model)
            self.filepath = filepath

        except ValueError as e:
            QMessageBox.critical(self, "Ошибка", str(e))
            self.key = None
            self.db_connection = None
            return
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить базу данных: {e}")
            self.key = None
            self.db_connection = None
            return

    def save_as(self):
        if not self.model._data:
            QMessageBox.warning(self, "Предупреждение", "Таблица пуста. Нечего сохранять.")
            return

        filepath, _ = QFileDialog.getSaveFileName(self, "Сохранить базу данных как", "", "SQLite базы данных (*.db)")
        if not filepath:
            return

        try:
            connection = sqlite3.connect(filepath)
            cursor = connection.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website TEXT,
                    login TEXT,
                    password TEXT
                )
            ''')

            if self.key is None:
                password, ok = QInputDialog.getText(self, "Пароль базы данных", "Введите пароль:",
                                                    QLineEdit.EchoMode.Password, "")
                if ok and password:
                    self.key = self.get_encryption_key(password)
                else:
                    raise ValueError("Password not set")

            data_to_save = []
            for row in self.model._data:
                encrypted_site = self.encrypt_string(row[0])
                encrypted_login = self.encrypt_string(row[1])
                encrypted_password = self.encrypt_string(row[2])

                data_to_save.append((encrypted_site, encrypted_login, encrypted_password))

            cursor.execute("DELETE FROM passwords")
            cursor.executemany("INSERT INTO passwords (website, login, password) VALUES (?, ?, ?)", data_to_save)
            connection.commit()

            self.db_connection = connection
            self.filepath = filepath

            QMessageBox.information(self, "Успех", f"База данных успешно сохранена в {filepath}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить базу данных: {str(e)}")

    def save_data(self):
        if not self.model._data:
            QMessageBox.warning(self, "Предупреждение", "Таблица пуста. Нечего сохранять.")
            return

        if self.filepath is None:
            self.save_as()
            return
        try:
            connection = sqlite3.connect(self.filepath)
            cursor = connection.cursor()
            cursor.execute("DELETE FROM passwords")

            data_to_save = []
            for row in self.model._data:
                encrypted_password = self.encrypt_string(row[2])
                data_to_save.append((row[0], row[1], encrypted_password))

            cursor.executemany("INSERT INTO passwords (website, login, password) VALUES (?, ?, ?)", data_to_save)
            connection.commit()
            QMessageBox.information(self, "Успех", f"База данных успешно сохранена в {self.filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить базу данных: {str(e)}")

    def export_data(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Экспортировать данные", "", "CSV (*.csv);;JSON (*.json);;TXT (*.txt)"
        )

        if not filepath:
            return

        try:
            if filepath.endswith(".csv"):
                with open(filepath, "w", encoding="utf-8") as f:
                    for row in self.model._data:
                        f.write(",".join(row) + "\n")

            elif filepath.endswith(".json"):
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(self.model._data, f, ensure_ascii=False, indent=4)
            elif filepath.endswith(".txt"):
                with open(filepath, "w", encoding="utf-8") as f:
                    for row in self.model._data:
                        f.write(" | ".join(row) + "\n")
            else:
                raise ValueError("Unsupported file format")

            QMessageBox.information(self, "Успех", f"Данные успешно экспортированы в {filepath}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать данные: {e}")

    def import_data(self):

        filepath, _ = QFileDialog.getOpenFileName(self, "Импортировать данные", "",
                                                  "Все файлы (*.*);;SQLite базы данных (*.db);;JSON файлы \
                                                  (*.json);;TXT файлы (*.txt);;CSV файлы (*.csv)")
        if not filepath:
            return

        try:
            data_to_import = []
            if filepath.endswith(".db"):
                conn = sqlite3.connect(filepath)
                cursor = conn.cursor()
                cursor.execute("SELECT website, login, password FROM passwords")
                data_to_import = [list(row) for row in cursor.fetchall()]
                conn.close()
            elif filepath.endswith(".json"):
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list) and all(isinstance(item, list) and len(item) >= 3 for item in data):
                        data_to_import = data
                    else:
                        raise ValueError("Неверный формат JSON. Ожидается список списков (website, login, password).")
            elif filepath.endswith((".txt", ".csv")):
                with open(filepath, "r", encoding="utf-8") as f:
                    reader = csv.reader(f, delimiter='|' if filepath.endswith(".txt") else ',')
                    for row in reader:
                        if len(row) >= 3:
                            data_to_import.append(row)

            if not data_to_import:
                raise ValueError("No data found in the imported file.")

            self.model.beginInsertRows(QModelIndex(), self.model.rowCount(),
                                       self.model.rowCount() + len(data_to_import) - 1)
            if not self.model._data:
                QMessageBox.information(self, "Ошибка", f"Выберите файл куда импортировать")
            else:
                self.model._data.extend(data_to_import)
                self.model.endInsertRows()
                QMessageBox.information(self, "Успех", f"Данные успешно импортированы.")

        except (sqlite3.Error, FileNotFoundError, json.JSONDecodeError, csv.Error, ValueError) as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка при импорте данных: {e}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Неожиданная ошибка при импорте: {e}")

    def change_db_password(self):
        if not self.filepath:
            QMessageBox.warning(self, "Ошибка", "Нет загруженной базы данных")
            return

        new_password, ok = QInputDialog.getText(
            self, "Новый пароль", "Введите новый пароль:", QLineEdit.EchoMode.Password
        )
        if not ok or not new_password:
            return

        confirm_password, ok = QInputDialog.getText(
            self, "Подтвердите пароль", "Подтвердите новый пароль:", QLineEdit.EchoMode.Password
        )
        if not ok or new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return

        self.key = self.get_encryption_key(new_password)
        self.save_data()

        QMessageBox.information(self, "Успех", "Пароль базы данных успешно изменен")

    def add_row(self):
        dialog = AddPasswordDialog()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            website, login, password = dialog.get_data()
            self.model.beginInsertRows(QModelIndex(), self.model.rowCount(), self.model.rowCount())
            self.model._data.append([website, login, password])
            self.model.endInsertRows()

    def remove_row(self):
        selected_indexes = self.table_view.selectionModel().selectedRows()
        if not selected_indexes:
            return

        rows = sorted(set(index.row() for index in selected_indexes), reverse=True)

        for row in rows:
            proxy_index = self.proxy_model.index(row, 0)
            source_index = self.proxy_model.mapToSource(proxy_index)
            self.model.beginRemoveRows(QModelIndex(), source_index.row(), source_index.row())
            del self.model._data[source_index.row()]
            self.model.endRemoveRows()

        self.table_view.clearSelection()

    def show_password_generator(self):
        self.password_generator.show()

    def show_about_dialog(self):
        QMessageBox.about(self, "О программе", "Это простой менеджер паролей.")


class AddPasswordDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Добавить пароль")

        self.website_edit = QLineEdit()
        self.login_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        layout = QFormLayout()
        layout.addRow("Сайт:", self.website_edit)
        layout.addRow("Логин:", self.login_edit)
        layout.addRow("Пароль:", self.password_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(layout)
        main_layout.addWidget(buttons)
        self.setLayout(main_layout)

    def get_data(self):
        return self.website_edit.text(), self.login_edit.text(), self.password_edit.text()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('icon.png'))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
