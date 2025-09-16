# PassManager_enhanced.py
# Enhanced version of your PassManager with popups, edit, export/import, clipboard auto-clear,
# delete confirmation, edit dialog, context menu, and minor UX improvements.

import sys
import json
import re
import secrets
import string
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QListWidget, QListWidgetItem, QProgressBar, QFrame,
    QLineEdit, QDialog, QDialogButtonBox, QMessageBox, QFileDialog, QMenu
)
from PyQt6.QtGui import QFont, QColor, QAction
from PyQt6.QtCore import Qt, QPoint, pyqtSignal, QTimer

# --- Global constant for the data file ---
DB_FILE = "passvault.db"

# --- Data Handling & Encryption Layer ---
import sqlite3
import base64
import os
from pathlib import Path

# Crypto imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# Argon2 / AES parameters (tune for your device)
ARGON2_TIME = 2
ARGON2_MEMORY_KB = 65536  # 64 MB
ARGON2_PARALLELISM = 2
KEY_LEN = 32  # AES-256

# Meta key name for storing vault salt
_META_SALT_KEY = 'user_salt_b64'

def init_db():
    """Create SQLite DB and required tables if they don't exist."""
    Path(DB_FILE).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    # accounts: password stored as BLOB (ciphertext) and nonce as BLOB
    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        name TEXT PRIMARY KEY,
        username TEXT,
        password BLOB,
        nonce BLOB
    )
    """)
    # simple key/value meta table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS vault_meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)
    conn.commit()
    conn.close()

# --- Vault management helpers ---
def set_user_salt_b64(salt_b64: str):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("REPLACE INTO vault_meta (key, value) VALUES (?, ?)", (_META_SALT_KEY, salt_b64))
    conn.commit()
    conn.close()

def get_user_salt_b64():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT value FROM vault_meta WHERE key = ?", (_META_SALT_KEY,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def create_vault(master_password: str):
    """Initialize a new encrypted vault by generating and storing a user salt.
    This does not store the master password.
    """
    salt = os.urandom(16)
    salt_b64 = base64.b64encode(salt).decode('ascii')
    set_user_salt_b64(salt_b64)
    return salt_b64

def derive_key_argon2(master_password: str, salt: bytes) -> bytes:
    pwd = master_password.encode('utf-8')
    raw = hash_secret_raw(
        secret=pwd,
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY_KB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Type.ID
    )
    return raw

def encrypt_password(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt the plaintext password with AES-GCM and return (nonce, ciphertext).
    Ciphertext includes the auth tag appended.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), associated_data=None)
    return nonce, ct

def decrypt_password(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return pt.decode('utf-8')

# --- Backwards-compatible load/save wrappers ---
# The UI calls load_data() and save_data(data) without passing a master password.
# To avoid breaking the UI, provide wrappers that behave as follows:
# - If the vault is not initialized (no salt stored) the DB is treated as plaintext storage
#   and load/save operate on cleartext strings for compatibility.
# - If the vault is initialized (salt exists) and a master_password is provided to the
#   explicit functions below, they will encrypt/decrypt. If no master_password is
#   provided, load_data() will return placeholders for passwords ("<locked>").

def load_data(master_password: str | None = None) -> dict:
    """Load all accounts from DB.
    If master_password provided and vault exists, decrypt passwords; otherwise
    if vault exists but no master_password, return locked placeholders.
    Returns format: {name: {"username":..., "password":...}}
    """
    init_db()
    salt_b64 = get_user_salt_b64()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT name, username, password, nonce FROM accounts")
    rows = cur.fetchall()
    conn.close()

    data = {}
    if not salt_b64:
        # no vault encryption configured — assume stored in plaintext (legacy)
        for name, username, password, nonce in rows:
            # password might be bytes or str
            if isinstance(password, bytes):
                try:
                    pw = password.decode('utf-8')
                except Exception:
                    pw = password.hex()
            else:
                pw = password
            data[name] = {"username": username, "password": pw}
        return data

    # vault is encrypted
    if master_password is None:
        # return locked placeholders (UI remain functional but cannot reveal secrets)
        for name, username, password, nonce in rows:
            data[name] = {"username": username, "password": "<locked>"}
        return data

    # decrypt with derived key
    salt = base64.b64decode(salt_b64)
    key = derive_key_argon2(master_password, salt)
    for name, username, password, nonce in rows:
        if password is None:
            continue
        # ensure bytes
        pw_bytes = password if isinstance(password, (bytes, bytearray)) else bytes(password)
        nonce_bytes = nonce if isinstance(nonce, (bytes, bytearray)) else bytes(nonce)
        try:
            plain = decrypt_password(nonce_bytes, pw_bytes, key)
        except Exception:
            plain = "<decrypt-failed>"
        data[name] = {"username": username, "password": plain}
    return data

def save_data(data: dict, master_password: str | None = None):
    """Save the provided dict into the DB.
    If vault configured and master_password provided, encrypt passwords.
    If vault configured but no master_password provided, raise exception to avoid storing plaintext.
    If no vault configured, store plaintext for compatibility.
    """
    init_db()
    salt_b64 = get_user_salt_b64()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    if not salt_b64:
        # plaintext mode (legacy)
        cur.execute("DELETE FROM accounts")
        for name, info in data.items():
            cur.execute("INSERT INTO accounts (name, username, password, nonce) VALUES (?, ?, ?, ?)",
                        (name, info.get('username',''), info.get('password',''), None))
        conn.commit()
        conn.close()
        return

    # vault exists => must have master_password
    if master_password is None:
        conn.close()
        raise ValueError("Vault is encrypted. save_data requires master_password to store encrypted data.")

    salt = base64.b64decode(salt_b64)
    key = derive_key_argon2(master_password, salt)

    # Replace all rows with encrypted versions
    cur.execute("DELETE FROM accounts")
    for name, info in data.items():
        username = info.get('username','')
        pw_plain = info.get('password','')
        nonce, ct = encrypt_password(pw_plain, key)
        cur.execute("INSERT INTO accounts (name, username, password, nonce) VALUES (?, ?, ?, ?)",
                    (name, username, sqlite3.Binary(ct), sqlite3.Binary(nonce)))
    conn.commit()
    conn.close()

# --- Migration helper: import existing JSON (plaintext) into encrypted DB ---

def migrate_json_to_db(json_path: str, master_password: str):
    """Migrate a plaintext JSON file (passwords.json) into the encrypted SQLite DB.
    This will:
      - create a vault (generate and store salt) if none exists
      - read JSON (same format used earlier)
      - encrypt each password with master_password and store in DB
    """
    # load JSON
    try:
        with open(json_path, 'r') as f:
            imported = json.load(f)
        if not isinstance(imported, dict):
            raise ValueError('JSON root must be an object/dict of accounts')
    except Exception as e:
        raise RuntimeError(f"Failed to read JSON import file: {e}")

    # ensure vault
    if not get_user_salt_b64():
        create_vault(master_password)
    # write encrypted data
    save_data(imported, master_password)

# --- Quick DB reference (SQL snippets) ---
# Inspect accounts (shows ciphertext hex if encrypted):
#   SELECT name, username, hex(password) as password_hex, hex(nonce) as nonce_hex FROM accounts;
# List only metadata:
#   SELECT key, value FROM vault_meta;
# Remove a single account:
#   DELETE FROM accounts WHERE name = 'Google';
# Export to JSON via sqlite CLI (example):
#   sqlite3 -json passvault.db "SELECT name, username, hex(password) as password_hex, hex(nonce) as nonce_hex FROM accounts;"

# --- Dialog for Adding or Editing a New Account ---
class AddAccountDialog(QDialog):
    # Signal to emit when the password field changes
    password_changed = pyqtSignal(str)

    def __init__(self, parent=None, initial: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle("Add / Edit Account")
        self.setMinimumWidth(380)

        self.layout = QVBoxLayout(self)

        # Fields for account info
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Account Name (e.g., Google)")
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Username or Email")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        # Emit signal when text changes
        self.password_edit.textChanged.connect(self.password_changed.emit)

        # Prefill if editing
        if initial:
            self.name_edit.setText(initial.get("name", ""))
            self.username_edit.setText(initial.get("username", ""))
            self.password_edit.setText(initial.get("password", ""))

        self.layout.addWidget(QLabel("Account Name:"))
        self.layout.addWidget(self.name_edit)
        self.layout.addWidget(QLabel("Username/Email:"))
        self.layout.addWidget(self.username_edit)
        self.layout.addWidget(QLabel("Password:"))
        self.layout.addWidget(self.password_edit)

        # Extra small button row for Generate / Show
        btn_row = QHBoxLayout()
        self.generate_btn = QPushButton("Generate")
        self.toggle_show_btn = QPushButton("Show")
        self.generate_btn.setFixedWidth(90)
        self.toggle_show_btn.setFixedWidth(90)
        btn_row.addWidget(self.generate_btn)
        btn_row.addWidget(self.toggle_show_btn)
        btn_row.addStretch()
        self.layout.addLayout(btn_row)

        # OK and Cancel buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.button_box.accepted.connect(self._validate_and_accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)

        # Hook up small features
        self.generate_btn.clicked.connect(self._generate_password)
        self.toggle_show_btn.clicked.connect(self._toggle_password_visible)

        # Style the dialog to match the app
        self.setStyleSheet("""
            QDialog { background-color: #1c1c2b; }
            QLabel { color: white; font-size: 14px; }
            QLineEdit { 
                background-color: #2a2a3a; 
                color: white; 
                border: 1px solid #3a3a4a;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton { background-color: #2a2a3a; color: white; border-radius: 6px; padding: 6px; }
            QPushButton:hover { background-color: #3a3a4a; }
        """)

    def _generate_password(self):
        # Simple secure generator - length 16 default
        pwd = generate_password(16)
        self.password_edit.setText(pwd)
        self.password_changed.emit(pwd)

    def _toggle_password_visible(self):
        if self.password_edit.echoMode() == QLineEdit.EchoMode.Normal:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_show_btn.setText("Show")
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_show_btn.setText("Hide")

    def _validate_and_accept(self):
        name = self.name_edit.text().strip()
        pwd = self.password_edit.text()
        if not name:
            QMessageBox.warning(self, "Validation error", "Account name cannot be empty.")
            return
        if not pwd:
            QMessageBox.warning(self, "Validation error", "Password cannot be empty.")
            return
        # Passed validation
        self.accept()

    def get_data(self):
        """Returns the entered data as a dictionary."""
        return {
            "name": self.name_edit.text().strip(),
            "username": self.username_edit.text().strip(),
            "password": self.password_edit.text()
        }


# --- Utility: password generator ---
def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Use secrets for cryptographic quality randomness
    return ''.join(secrets.choice(alphabet) for _ in range(max(8, length)))


# --- Custom Widget for List Items ---
class AccountListItem(QWidget):
    # Signals to notify the main window of an action
    delete_requested = pyqtSignal(str)
    copy_requested = pyqtSignal(str)
    edit_requested = pyqtSignal(str)

    def __init__(self, account_name, username, password):
        super().__init__()
        self.account_name = account_name
        self.username = username
        self.password = password
        self.password_visible = False

        # --- Layouts ---
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(12, 8, 12, 8)

        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(6)

        # --- Widgets ---
        self.account_label = QLabel(f"{self.account_name}")
        self.account_label.setStyleSheet("color: #e0e0e0; font-weight: bold; font-size: 14px;")

        self.username_label = QLabel(self.username)
        self.username_label.setStyleSheet("color: #bfbfbf; font-size: 12px;")

        self.password_label = QLabel("•" * len(self.password))
        self.password_label.setStyleSheet("color: #a0a0a0; font-size: 12px;")

        # Buttons
        self.show_hide_btn = QPushButton("👁")
        self.copy_btn = QPushButton("📋")
        self.delete_btn = QPushButton("🗑️")
        self.edit_btn = QPushButton("✏️")

        for btn in [self.show_hide_btn, self.copy_btn, self.edit_btn, self.delete_btn]:
            btn.setFixedSize(30, 28)
            btn.setStyleSheet("""
                QPushButton { 
                    font-size: 14px; 
                    background-color: #2a2a3a; 
                    border-radius: 6px; 
                    color: #e0e0e0;
                }
                QPushButton:hover { background-color: #3a3a4a; }
            """)
            button_layout.addWidget(btn)

        # --- Arrange Layouts ---
        info_layout.addWidget(self.account_label)
        info_layout.addWidget(self.username_label)
        info_layout.addWidget(self.password_label)

        main_layout.addLayout(info_layout, 1)  # Add with stretch factor
        main_layout.addLayout(button_layout)

        # --- Connect Signals ---
        self.show_hide_btn.clicked.connect(self.toggle_password_visibility)
        self.copy_btn.clicked.connect(lambda: self.copy_requested.emit(self.password))
        self.delete_btn.clicked.connect(lambda: self.delete_requested.emit(self.account_name))
        self.edit_btn.clicked.connect(lambda: self.edit_requested.emit(self.account_name))

    def toggle_password_visibility(self):
        self.password_visible = not self.password_visible
        if self.password_visible:
            self.password_label.setText(self.password)
            self.show_hide_btn.setText("🔒")
            # auto-hide after 8 seconds
            QTimer.singleShot(8000, self._auto_hide)
        else:
            self.password_label.setText("•" * len(self.password))
            self.show_hide_btn.setText("👁")

    def _auto_hide(self):
        # ensure UI still exists
        try:
            self.password_visible = False
            self.password_label.setText("•" * len(self.password))
            self.show_hide_btn.setText("👁")
        except Exception:
            pass


# --- Main Application Window ---
class PassManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.accounts_data = load_data()  # Load data on start
        self.setWindowTitle("AEGIS PassManager")
        self.setGeometry(100, 100, 900, 540)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        self.container = QFrame(self)
        self.container.setObjectName("container")
        self.main_layout = QVBoxLayout(self.container)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self._create_title_bar()

        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(20, 10, 20, 20)
        content_layout.setSpacing(20)

        self._create_left_pane()
        self._create_right_pane()

        content_layout.addWidget(self.left_pane)
        content_layout.addWidget(self.right_pane, 1)

        self.main_layout.addLayout(content_layout)
        self.setCentralWidget(self.container)

        self._create_side_menu()
        self._apply_styles()
        self.populate_account_list()  # Initial population

    def _create_title_bar(self):
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(56)
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(15, 0, 15, 0)
        icon_label = QLabel("Aegis")
        icon_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #e0e0e0;")
        title_label = QLabel("PassManager")
        title_label.setStyleSheet("font-size: 16px; color: #c0c0c0;")
        self.menu_button = QPushButton("☰")
        self.menu_button.setObjectName("menuButton")
        self.menu_button.setFixedSize(40, 40)
        self.menu_button.clicked.connect(self.toggle_side_menu)
        # Minimize and Close buttons
        self.min_btn = QPushButton("—")
        self.min_btn.setFixedSize(36, 36)
        self.min_btn.clicked.connect(self.showMinimized)
        self.close_btn = QPushButton("✕")
        self.close_btn.setFixedSize(36, 36)
        self.close_btn.clicked.connect(self.close)

        title_layout.addWidget(icon_label)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        title_layout.addWidget(self.menu_button)
        title_layout.addWidget(self.min_btn)
        title_layout.addWidget(self.close_btn)
        self.main_layout.addWidget(self.title_bar)

    def _create_left_pane(self):
        self.left_pane = QWidget()
        left_layout = QVBoxLayout(self.left_pane)
        left_layout.setContentsMargins(0, 10, 0, 0)
        left_layout.setSpacing(12)
        strength_label = QLabel("Password Strength Check")
        strength_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")
        self.strength_bar = QProgressBar()
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(False)
        self.gradient_box = QWidget()
        self.gradient_box.setObjectName("gradientBox")
        self.gradient_box.setMinimumSize(220, 180)
        self.info_label = QLabel("Shows Password strength for new passwords")
        self.info_label.setWordWrap(True)
        self.info_label.setStyleSheet("color: #a0a0a0;")
        left_layout.addWidget(strength_label)
        left_layout.addWidget(self.strength_bar)
        left_layout.addWidget(self.gradient_box)
        left_layout.addWidget(self.info_label)
        left_layout.addStretch()

    def _create_right_pane(self):
        self.right_pane = QWidget()
        right_layout = QVBoxLayout(self.right_pane)
        right_layout.setContentsMargins(0, 10, 0, 0)

        top_bar_layout = QHBoxLayout()
        accounts_label = QLabel("Accounts")
        accounts_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search accounts...")
        self.search_bar.textChanged.connect(self.filter_accounts)  # Connect search

        self.add_button = QPushButton("+")
        self.add_button.setObjectName("iconButton")
        self.add_button.clicked.connect(self.add_new_account)  # Connect add

        top_bar_layout.addWidget(accounts_label)
        top_bar_layout.addStretch()
        top_bar_layout.addWidget(self.search_bar)
        top_bar_layout.addWidget(self.add_button)

        self.account_list = QListWidget()
        self.account_list.setObjectName("accountList")
        self.account_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.account_list.customContextMenuRequested.connect(self._on_list_context_menu)

        right_layout.addLayout(top_bar_layout)
        right_layout.addWidget(self.account_list)

    def populate_account_list(self):
        """Clears and repopulates the list from self.accounts_data."""
        self.account_list.clear()
        sorted_names = sorted(self.accounts_data.keys(), key=str.lower)

        for name in sorted_names:
            info = self.accounts_data[name]
            list_item = QListWidgetItem(self.account_list)
            item_widget = AccountListItem(name, info.get("username",""), info.get("password",""))

            # Connect item signals to main window slots
            item_widget.delete_requested.connect(self.delete_account)
            item_widget.copy_requested.connect(self.copy_password_to_clipboard)
            item_widget.edit_requested.connect(self.edit_account)

            list_item.setSizeHint(item_widget.sizeHint())
            self.account_list.addItem(list_item)
            self.account_list.setItemWidget(list_item, item_widget)

    def add_new_account(self):
        """Opens dialog to add a new account."""
        dialog = AddAccountDialog(self)
        # Connect dialog signal to the strength checker
        dialog.password_changed.connect(self.update_strength_meter)

        if dialog.exec():
            data = dialog.get_data()
            if data["name"] and data["password"]:
                if data["name"] in self.accounts_data:
                    QMessageBox.warning(self, "Duplicate", f"Account '{data['name']}' already exists.")
                    return
                self.accounts_data[data["name"]] = {
                    "username": data["username"],
                    "password": data["password"]
                }
                save_data(self.accounts_data)
                self.populate_account_list()
                self.info_label.setText(f"✅ Account '{data['name']}' added.")
                QMessageBox.information(self, "Added", f"Account '{data['name']}' added successfully.")

        # Reset strength meter after dialog closes
        self.update_strength_meter("")

    def edit_account(self, account_name: str):
        """Open edit dialog for existing account."""
        if account_name not in self.accounts_data:
            QMessageBox.warning(self, "Not found", "Account not found.")
            return
        current = self.accounts_data[account_name]
        initial = {"name": account_name, "username": current.get("username",""), "password": current.get("password","")}
        dialog = AddAccountDialog(self, initial=initial)
        dialog.password_changed.connect(self.update_strength_meter)
        if dialog.exec():
            data = dialog.get_data()
            new_name = data["name"]
            # If name changed and collides
            if new_name != account_name and new_name in self.accounts_data:
                QMessageBox.warning(self, "Duplicate", "An account with the new name already exists.")
                return
            # Update data: remove old key if renamed
            del self.accounts_data[account_name]
            self.accounts_data[new_name] = {"username": data["username"], "password": data["password"]}
            save_data(self.accounts_data)
            self.populate_account_list()
            QMessageBox.information(self, "Updated", f"Account '{new_name}' updated.")
        self.update_strength_meter("")

    def delete_account(self, account_name):
        """Deletes an account by its name with confirmation."""
        if account_name not in self.accounts_data:
            QMessageBox.warning(self, "Not found", "Account not found.")
            return
        reply = QMessageBox.question(self, "Confirm delete", f"Delete account '{account_name}'?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            del self.accounts_data[account_name]
            save_data(self.accounts_data)
            self.populate_account_list()
            self.info_label.setText(f"🗑️ Account '{account_name}' deleted.")
            QMessageBox.information(self, "Deleted", f"Account '{account_name}' was removed.")

    def copy_password_to_clipboard(self, password):
        """Copies text to the system clipboard and clears it after 15 seconds."""
        clipboard = QApplication.clipboard()
        clipboard.setText(password)
        self.info_label.setText("📋 Password copied to clipboard! (will clear in 15s)")
        # Clear clipboard after 15 seconds
        QTimer.singleShot(15000, lambda: self._clear_clipboard_if_matches(password))

    def _clear_clipboard_if_matches(self, previous_text):
        clipboard = QApplication.clipboard()
        try:
            if clipboard.text() == previous_text:
                clipboard.clear()
                self.info_label.setText("Clipboard cleared.")
        except Exception:
            pass

    def filter_accounts(self, text):
        """Hides or shows list items based on search text."""
        for i in range(self.account_list.count()):
            item = self.account_list.item(i)
            widget = self.account_list.itemWidget(item)
            if widget:
                is_match = text.lower() in widget.account_name.lower() or text.lower() in widget.username.lower()
                item.setHidden(not is_match)

    def check_password_strength(self, password):
        """Analyzes a password and returns a score (0-100)."""
        score = 0
        if len(password) >= 8:
            score += 25
        if re.search(r"[a-z]", password):
            score += 20
        if re.search(r"[A-Z]", password):
            score += 20
        if re.search(r"\d", password):
            score += 15
        if re.search(r"[\W_]", password):
            score += 20  # Special characters
        return max(0, min(100, int(score)))

    def update_strength_meter(self, password):
        """Updates the UI based on password strength."""
        score = self.check_password_strength(password)
        self.strength_bar.setValue(score)

        # Update gradient box color based on score
        if score < 25:
            color = "qlineargradient(..., stop:0 #ff4b2b, stop:1 #ff416c)"  # Red
        elif score < 50:
            color = "qlineargradient(..., stop:0 #ff8c00, stop:1 #ffaf00)"  # Orange
        elif score < 75:
            color = "qlineargradient(..., stop:0 #ffdd00, stop:1 #ffee00)"  # Yellow
        else:
            color = "qlineargradient(..., stop:0 #76b852, stop:1 #8dc26f)"  # Green

        base_style = "spread:pad, x1:0, y1:1, x2:1, y2:0,"
        self.gradient_box.setStyleSheet(f"#gradientBox {{ background-color: {color.replace('...', base_style)}; border-radius: 10px; }}")

    # --- Side menu and context menu functionality ---
    def _create_side_menu(self):
        self.side_menu = QFrame(self)
        self.side_menu.setObjectName("sideMenu")
        self.side_menu.setGeometry(self.width(), 56, 220, self.height() - 56)
        self.side_menu.hide()
        menu_layout = QVBoxLayout(self.side_menu)
        menu_layout.setContentsMargins(10, 20, 10, 20)
        menu_layout.setSpacing(10)
        btn_account = QPushButton("Account")
        btn_personalization = QPushButton("Export / Import")
        btn_settings = QPushButton("Settings")
        btn_help = QPushButton("About")
        menu_buttons = [btn_account, btn_personalization, btn_settings, btn_help]
        for btn in menu_buttons:
            btn.setObjectName("menuActionButton")
            menu_layout.addWidget(btn)
        menu_layout.addStretch()

        # Connect actions
        btn_personalization.clicked.connect(self._export_import)
        btn_help.clicked.connect(self._show_about)
        btn_settings.clicked.connect(self._show_settings)

    def toggle_side_menu(self):
        if self.side_menu.isHidden():
            self.side_menu.setGeometry(self.width() - 220, 56, 220, self.height() - 56)
            self.side_menu.show()
        else:
            self.side_menu.hide()

    def _on_list_context_menu(self, pos):
        item = self.account_list.itemAt(pos)
        if not item:
            return
        widget = self.account_list.itemWidget(item)
        if not widget:
            return
        menu = QMenu(self)
        act_copy = QAction("Copy password", self)
        act_edit = QAction("Edit", self)
        act_delete = QAction("Delete", self)
        menu.addAction(act_copy)
        menu.addAction(act_edit)
        menu.addAction(act_delete)

        act = menu.exec(self.account_list.mapToGlobal(pos))
        if act == act_copy:
            self.copy_password_to_clipboard(widget.password)
        elif act == act_edit:
            self.edit_account(widget.account_name)
        elif act == act_delete:
            self.delete_account(widget.account_name)

    def _export_import(self):
        # Small dialog offering Export or Import choice
        choice = QMessageBox.question(self, "Export / Import", "Export (Yes) or Import (No)?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel)
        if choice == QMessageBox.StandardButton.Cancel:
            return
        if choice == QMessageBox.StandardButton.Yes:
            path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "pass-export.json", "JSON Files (*.json)")
            if path:
                with open(path, 'w') as f:
                    json.dump(self.accounts_data, f, indent=4)
                QMessageBox.information(self, "Exported", f"Exported to {path}")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Import JSON", "", "JSON Files (*.json)")
            if path:
                try:
                    with open(path, 'r') as f:
                        imported = json.load(f)
                    # Basic validation
                    if not isinstance(imported, dict):
                        raise ValueError('Invalid format')
                    # Merge (existing names kept)
                    merged = {**imported, **self.accounts_data}
                    self.accounts_data = merged
                    save_data(self.accounts_data)
                    self.populate_account_list()
                    QMessageBox.information(self, "Imported", "Data imported and merged.")
                except Exception as e:
                    QMessageBox.warning(self, "Import failed", f"Failed to import: {e}")

    def _show_about(self):
        QMessageBox.information(self, "About", "Hius PassManager\nLocal demo version. No cloud sync. Built for learning.")

    def _show_settings(self):
        QMessageBox.information(self, "Settings", "No settings yet. Coming soon.")

    def _apply_styles(self):
        stylesheet = """
            #container { background-color: #10141f; border-radius: 15px; color: white; font-family: Segoe UI; }
            #menuButton { font-size: 24px; color: #87CEEB; background-color: transparent; border: none; }
            #menuButton:hover { color: #FFFFFF; }
            QProgressBar { border: 1px solid #2a2a3a; border-radius: 7px; background-color: #2a2a3a; height: 15px; text-align: center; }
            QProgressBar::chunk { background-color: #87CEEB; border-radius: 7px; }
            #gradientBox {
                border-radius: 10px;
                background-color: qlineargradient(
                    spread:pad, x1:0, y1:1, x2:1, y2:0,
                    stop:0 rgba(255, 105, 180, 255),
                    stop:1 rgba(255, 215, 0, 255)
                );
            }
            #iconButton { font-size: 20px; font-weight: bold; background-color: #2a2a3a; color: white; border: none; border-radius: 15px; width: 30px; height: 30px; }
            #iconButton:hover { background-color: #3a3a4a; }
            #accountList { border: none; background-color: transparent; }
            #accountList::item { background-color: #1c1c2b; border-radius: 10px; margin-bottom: 8px; }
            #accountList::item:hover { background-color: #2a2a3a; }
            QScrollBar:vertical { border: none; background: #1c1c2b; width: 8px; margin: 0px 0px 0px 0px; }
            QScrollBar::handle:vertical { background: #3a3a4a; min-height: 20px; border-radius: 4px; }
            #sideMenu { background-color: #1c1c2b; border-left: 1px solid #2a2a3a; border-bottom-right-radius: 15px; }
            #menuActionButton { background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(46, 204, 113, 255), stop:1 rgba(39, 174, 96, 255)); color: white; font-size: 14px; font-weight: bold; border: none; border-radius: 8px; padding: 10px; }
            #menuActionButton:hover { background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 rgba(56, 214, 123, 255), stop:1 rgba(49, 184, 106, 255)); }
            QLineEdit { background-color: #2a2a3a; color: white; border: 1px solid #3a3a4a; border-radius: 5px; padding: 5px; }
        """
        self.setStyleSheet(stylesheet)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and hasattr(self, 'old_pos') and self.old_pos:
            delta = QPoint(event.globalPosition().toPoint() - self.old_pos)
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self.old_pos = None


# --- Main execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PassManagerWindow()
    window.show()
    sys.exit(app.exec())
