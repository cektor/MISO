import sys
import hashlib
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox, 
    QVBoxLayout, QProgressBar, QDialog, QHBoxLayout
)
from PyQt5.QtCore import Qt, QPropertyAnimation, QRect
from PyQt5.QtGui import QPixmap, QIcon

class HashChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.app_data_dir = self.get_app_data_dir()

        # Ensure app data directory exists
        if not os.path.exists(self.app_data_dir):
            os.makedirs(self.app_data_dir)

        self.init_ui()
        self.last_used_files = {"iso": "", "md5_sha256": ""}
        self.matching_hash = None

    def init_ui(self):
        self.setWindowTitle("MISO Hash ISO Doğrulayıcı")
        self.setFixedSize(600, 500)  # Increased size to accommodate all elements
        self.setStyleSheet(self.load_styles())

        # Set window icon
        icon_path = self.get_icon_path()
        if icon_path:
            self.setWindowIcon(QIcon(icon_path))

        # Main layout
        main_layout = QVBoxLayout()

        # Logo
        logo_label = QLabel(self)
        logo_path = self.get_logo_path()
        if logo_path and os.path.exists(logo_path):
            logo_pixmap = QPixmap(logo_path)
            if not logo_pixmap.isNull():
                scaled_logo = logo_pixmap.scaled(150, 150, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                logo_label.setPixmap(scaled_logo)
                logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            else:
                logo_label.setText("Logo Yüklenemedi")
        else:
            logo_label.setText("Logo Bulunamadı!")
        main_layout.addWidget(logo_label)

        # ISO File Selection
        iso_layout = QHBoxLayout()
        self.label_iso = QLabel("ISO:")
        self.line_edit_iso = QLineEdit()
        self.line_edit_iso.setPlaceholderText("ISO dosyasını seçin")
        self.line_edit_iso.setReadOnly(True)
        self.button_browse_iso = QPushButton("Gözat")
        iso_layout.addWidget(self.label_iso)
        iso_layout.addWidget(self.line_edit_iso)
        iso_layout.addWidget(self.button_browse_iso)
        main_layout.addLayout(iso_layout)

        # Hash File Selection
        hash_layout = QHBoxLayout()
        self.label_md5_sha256 = QLabel("Hash:")
        self.line_edit_md5_sha256_file = QLineEdit()
        self.line_edit_md5_sha256_file.setPlaceholderText("MD5/SHA-256 dosyasını seçin")
        self.line_edit_md5_sha256_file.setReadOnly(True)
        self.button_browse_md5_sha256 = QPushButton("Gözat")
        hash_layout.addWidget(self.label_md5_sha256)
        hash_layout.addWidget(self.line_edit_md5_sha256_file)
        hash_layout.addWidget(self.button_browse_md5_sha256)
        main_layout.addLayout(hash_layout)

        # Check Button
        self.button_check = QPushButton("Hash Kontrol Et")
        main_layout.addWidget(self.button_check)

        # Progress Bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)

        # Matching Hash Label
        self.label_matching_hash = QLabel("Eşleşen hash değeri: -")
        self.label_matching_hash.setWordWrap(True)
        main_layout.addWidget(self.label_matching_hash)

        # About Button
        self.button_about = QPushButton("Hakkında")
        main_layout.addWidget(self.button_about)

        # Set the main layout
        self.setLayout(main_layout)

        # Connect signals
        self.button_browse_iso.clicked.connect(self.browse_iso_file)
        self.button_browse_md5_sha256.clicked.connect(self.browse_md5_sha256_file)
        self.button_check.clicked.connect(self.check_hash)
        self.button_about.clicked.connect(self.show_about)

        # Add click event to matching hash label
        self.label_matching_hash.mousePressEvent = self.copy_hash_on_click

    def load_styles(self):
        return """
            QWidget {
                background-color: #1f1f1f;
                font-family: Arial, sans-serif;
                color: white;
            }
            QLabel {
                color: white;
                font-size: 14px;
            }
            QLineEdit {
                padding: 5px;
                border-radius: 10px;
                background-color: #333;
                color: white;
                border: 1px solid #555;
            }
            QPushButton {
                background-color: #cca206;
                color: white;
                border: none;
                border-radius: 12px;
                padding: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffcb08;
            }
            QProgressBar {
                height: 20px;
                border-radius: 10px;
                background-color: #444;
            }
            QProgressBar::chunk {
                background-color: #cca206;
                border-radius: 10px;
            }
        """

    def get_app_data_dir(self):
        """Return user data directory based on platform."""
        if sys.platform == "win32":
            home = os.getenv("USERPROFILE", os.path.expanduser("~"))
            return os.path.join(home, "AppData", "Local", "MISO")
        elif sys.platform == "darwin":
            home = os.getenv("HOME", os.path.expanduser("~"))
            return os.path.join(home, "Library", "Application Support", "MISO")
        else:
            home = os.getenv("HOME", os.path.expanduser("~"))
            return os.path.join(home, ".local", "share", "MISO")

    def get_logo_path(self):
        """Return logo file path."""
        possible_paths = [
            getattr(sys, '_MEIPASS', None) and os.path.join(sys._MEIPASS, "misolo.png"),
            os.path.join(os.path.dirname(__file__), "misolo.png"),
            "/usr/share/icons/hicolor/48x48/apps/misolo.png",
            "misolo.png"
        ]
        
        for path in possible_paths:
            if path and os.path.exists(path):
                return path
        return None

    def get_icon_path(self):
        """Return icon file path."""
        possible_paths = [
            getattr(sys, '_MEIPASS', None) and os.path.join(sys._MEIPASS, "misolo.png"),
            os.path.join(os.path.dirname(__file__), "misolo.png"),
            "/usr/share/icons/hicolor/48x48/apps/misolo.png",
            "misolo.png"
        ]
        
        for path in possible_paths:
            if path and os.path.exists(path):
                return path
        return None

    def browse_iso_file(self):
        self.progress_bar.setValue(0)
        self.label_matching_hash.setText("Eşleşen hash değeri: -")
        file_path, _ = QFileDialog.getOpenFileName(self, "ISO Dosyasını Seçin", self.last_used_files.get("iso", ""), "ISO Files (*.iso)")
        if file_path:
            self.line_edit_iso.setText(file_path)
            self.last_used_files["iso"] = file_path

    def browse_md5_sha256_file(self):
        self.progress_bar.setValue(0)
        self.label_matching_hash.setText("Eşleşen hash değeri: -")
        file_path, _ = QFileDialog.getOpenFileName(self, "MD5 veya SHA-256 Dosyasını Seçin", self.last_used_files.get("md5_sha256", ""), "Tüm Dosyalar (*)")
        if file_path:
            self.line_edit_md5_sha256_file.setText(file_path)
            self.last_used_files["md5_sha256"] = file_path

    def check_hash(self):
        iso_path = self.line_edit_iso.text()
        md5_sha256_file_path = self.line_edit_md5_sha256_file.text()

        if not iso_path or not md5_sha256_file_path:
            QMessageBox.warning(self, "Eksik Bilgi", "Lütfen ISO ve MD5/SHA-256 dosyasını seçin.")
            return

        try:
            # Check every line in the hash file
            with open(md5_sha256_file_path, 'r') as f:
                hash_lines = f.readlines()

            # Calculate ISO file hash
            iso_hash_md5 = self.calculate_hash(iso_path, "md5")
            iso_hash_sha256 = self.calculate_hash(iso_path, "sha256")

            # Compare hash values
            match_found = False
            matching_hash = ""
            for line in hash_lines:
                expected_hash = line.split()[0].strip()
                if expected_hash == iso_hash_md5 or expected_hash == iso_hash_sha256:
                    match_found = True
                    matching_hash = expected_hash
                    break

            if match_found:
                self.label_matching_hash.setText(f"Eşleşen hash değeri: {matching_hash}")
                self.label_matching_hash.setStyleSheet("color: #32CD32; font-weight: bold;")
                self.matching_hash = matching_hash
            else:
                self.label_matching_hash.setText("Eşleşen hash değeri bulunamadı.")
                self.label_matching_hash.setStyleSheet("color: #FF6347; font-weight: bold;")

        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Bir hata oluştu: {e}")

    def calculate_hash(self, file_path, hash_type="md5", chunk_size=8192):
        hash_func = hashlib.md5() if hash_type == "md5" else hashlib.sha256()
        total_size = os.path.getsize(file_path)

        try:
            with open(file_path, 'rb') as f:
                bytes_read = 0
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)
                    bytes_read += len(chunk)
                    percent_done = int((bytes_read / total_size) * 100)
                    self.progress_bar.setValue(percent_done)
            return hash_func.hexdigest()
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Dosya okuma hatası: {e}")
            return ""

    def copy_hash_on_click(self, event):
        """Copy matching hash value to clipboard."""
        if self.matching_hash:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.matching_hash)
            QMessageBox.information(self, "Hash Kopyalandı", "Eşleşen hash değeri panoya kopyalandı.")

    def show_about(self):
        """Show about dialog."""
        about_text = (
            "M-ISO Hash Uygulaması\n\n"
            "Hash hesaplama, ISO doğrulama uygulaması.\n\n"
            "Geliştirici: ALG Yazılım Inc.©\n"
            "www.algyazilim.com | info@algyazilim.com\n\n"
            "Fatih ÖNDER (CekToR) | fatih@algyazilim.com\n"
            "GitHub: https://github.com/cektor\n\n"
            "ALG Yazılım Pardus'a Göç'ü Destekler.\n\n"
            "Sürüm: 1.0"
        )
        QMessageBox.about(self, "Hakkında", about_text)


def main():
    app = QApplication(sys.argv)
    window = HashChecker()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
