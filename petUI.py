import sys
import random
import string
from PyQt6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QTableView,
                             QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox,
                             QHeaderView, QSlider, QCheckBox, QLineEdit,
                             QInputDialog, QStyledItemDelegate, QAbstractItemView,
                             QSpinBox, QGroupBox, QLabel, QMenuBar,
                             QDialog, QFormLayout, QDialogButtonBox)


class TableEditorDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        return QLineEdit(parent)


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

    def rowCount(self, parent=QModelIndex()):  # Correct: No Qt. prefix
        return len(self._data)

    def columnCount(self, parent=QModelIndex()):  # Correct: No Qt. prefix
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

        self.table_view.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu) # Add missing import


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
        file_menu.addAction(load_action)

        save_action = QAction("&Сохранить", self)
        file_menu.addAction(save_action)

        save_as_action = QAction("Сохранить &как...", self)
        file_menu.addAction(save_as_action)

        export_action = QAction("&Экспортировать", self)
        file_menu.addAction(export_action)


        import_action = QAction("&Импортировать", self)
        file_menu.addAction(import_action)


        change_password_action = QAction("Изменить &пароль базы данных", self)
        file_menu.addAction(change_password_action)

        exit_action = QAction("&Выйти", self)
        exit_action.triggered.connect(self.close)  # Keep the close functionality
        file_menu.addAction(exit_action)

        about_action = QAction("&О программе", self)
        help_menu.addAction(about_action)


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


        self.password_generator = PasswordGenerator()
        self.generate_password_button.clicked.connect(self.show_password_generator)


    def show_password_generator(self):
        self.password_generator.show()

class AddPasswordDialog(QDialog): # Add missing import
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