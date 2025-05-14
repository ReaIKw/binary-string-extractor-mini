# Requires PyQt6: pip install PyQt6
import os
import sys
import threading
import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox, QTextEdit, QGroupBox,
    QFileDialog, QMessageBox, QStatusBar
)
from PyQt6.QtGui import QFont, QIcon, QFontDatabase
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal

# --- Worker class for string extraction in a separate thread ---
class StringExtractorWorker(QObject):
    progress = pyqtSignal(str)
    result = pyqtSignal(list)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, filepath, min_length, encodings):
        super().__init__()
        self.filepath = filepath
        self.min_length = min_length
        self.encodings = encodings
        self._abort = False

    def abort(self):
        self._abort = True

    def run(self):
        try:
            results = []
            chunk_size = 8192
            overlap = 32
            file_offset = 0
            prev_chunk = b''
            total_size = os.path.getsize(self.filepath)
            with open(self.filepath, 'rb') as f:
                while not self._abort:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    data = prev_chunk + chunk
                    if 'ascii' in self.encodings:
                        for offset, s in self._find_ascii_strings(data, self.min_length, file_offset - len(prev_chunk)):
                            results.append((offset, 'ASCII', s))
                    if 'utf8' in self.encodings:
                        for offset, s in self._find_utf8_strings(data, self.min_length, file_offset - len(prev_chunk)):
                            results.append((offset, 'UTF-8', s))
                    if 'utf16le' in self.encodings:
                        for offset, s in self._find_utf16_strings(data, self.min_length, file_offset - len(prev_chunk), 'le'):
                            results.append((offset, 'UTF-16 LE', s))
                    if 'utf16be' in self.encodings:
                        for offset, s in self._find_utf16_strings(data, self.min_length, file_offset - len(prev_chunk), 'be'):
                            results.append((offset, 'UTF-16 BE', s))
                    if len(chunk) >= overlap:
                        prev_chunk = chunk[-overlap:]
                    else:
                        prev_chunk = chunk
                    file_offset += len(chunk)
                    self.progress.emit(f"Scanned {min(file_offset, total_size)} / {total_size} bytes...")
            if self._abort:
                self.finished.emit()
                return
            self.result.emit(results)
        except Exception as e:
            self.error.emit(str(e))
        self.finished.emit()

    # --- Extraction logic (same as before, but as methods) ---
    def _find_ascii_strings(self, data, min_len, base_offset):
        printable = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
        results = []
        start = None
        for i, b in enumerate(data):
            if b in printable:
                if start is None:
                    start = i
            else:
                if start is not None and i - start >= min_len:
                    s = data[start:i].decode('ascii', errors='ignore')
                    results.append((base_offset + start, s))
                start = None
        if start is not None and len(data) - start >= min_len:
            s = data[start:].decode('ascii', errors='ignore')
            results.append((base_offset + start, s))
        return results

    def _find_utf8_strings(self, data, min_len, base_offset):
        import re
        results = []
        pattern = re.compile(
            rb'((?:[\x20-\x7E\x09\x0A\x0D]|'  # ASCII printable and whitespace
            rb'[\xC2-\xF4][\x80-\xBF]+)+'      # UTF-8 multibyte start + continuation
            rb')'
        )
        for match in pattern.finditer(data):
            s_bytes = match.group(0)
            try:
                s = s_bytes.decode('utf-8')
                if sum(c.isprintable() or c in '\t\n\r' for c in s) >= min_len:
                    results.append((base_offset + match.start(), s))
            except Exception:
                continue
        return results

    def _find_utf16_strings(self, data, min_len, base_offset, endian):
        results = []
        decode = 'utf-16le' if endian == 'le' else 'utf-16be'
        i = 0
        start = None
        while i + 1 < len(data):
            try:
                code_unit = int.from_bytes(data[i:i+2], endian)
            except Exception:
                break
            if (0x20 <= code_unit <= 0x7E) or code_unit in (0x09, 0x0A, 0x0D) or (0xA0 <= code_unit <= 0xFFFD):
                if start is None:
                    start = i
            else:
                if start is not None and (i - start) // 2 >= min_len:
                    s_bytes = data[start:i]
                    try:
                        s = s_bytes.decode(decode, errors='ignore').replace('\x00', '')
                        results.append((base_offset + start, s))
                    except Exception:
                        pass
                start = None
            i += 2
        if start is not None and (len(data) - start) // 2 >= min_len:
            s_bytes = data[start:]
            try:
                s = s_bytes.decode(decode, errors='ignore').replace('\x00', '')
                results.append((base_offset + start, s))
            except Exception:
                pass
        return results

# --- Main Application Window ---
class BinaryStringExtractorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Binary String Extractor Mini")
        self.setMinimumSize(700, 500)
        self.setWindowIcon(QIcon.fromTheme("document-open"))
        self.worker_thread = None
        self.worker = None
        self.results = []
        self._setup_ui()
        self._apply_qss()

    def _setup_ui(self):
        # Central widget and main layout
        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 8)
        main_layout.setSpacing(12)
        self.setCentralWidget(central)

        # File selection area
        file_layout = QHBoxLayout()
        self.file_edit = QLineEdit()
        self.file_edit.setReadOnly(True)
        self.file_edit.setPlaceholderText("Select a binary file...")
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setIcon(QIcon.fromTheme("document-open"))
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(self.browse_btn)
        main_layout.addLayout(file_layout)

        # Filtering options
        filter_group = QGroupBox("Filtering Options")
        filter_layout = QGridLayout()
        filter_group.setLayout(filter_layout)
        filter_layout.setHorizontalSpacing(16)
        filter_layout.setVerticalSpacing(8)
        # Min length
        filter_layout.addWidget(QLabel("Minimum String Length:"), 0, 0)
        self.min_length_spin = QSpinBox()
        self.min_length_spin.setMinimum(1)
        self.min_length_spin.setMaximum(1000)
        self.min_length_spin.setValue(4)
        filter_layout.addWidget(self.min_length_spin, 0, 1)
        # Encodings
        filter_layout.addWidget(QLabel("Character Sets/Encodings:"), 0, 2)
        self.ascii_cb = QCheckBox("ASCII Strings")
        self.utf8_cb = QCheckBox("Unicode (UTF-8)")
        self.utf16le_cb = QCheckBox("Unicode (UTF-16 LE)")
        self.utf16be_cb = QCheckBox("Unicode (UTF-16 BE)")
        self.ascii_cb.setChecked(True)
        filter_layout.addWidget(self.ascii_cb, 0, 3)
        filter_layout.addWidget(self.utf8_cb, 0, 4)
        filter_layout.addWidget(self.utf16le_cb, 0, 5)
        filter_layout.addWidget(self.utf16be_cb, 0, 6)
        main_layout.addWidget(filter_group)

        # --- Advanced Filtering Options ---
        adv_filter_group = QGroupBox("Advanced Filtering")
        adv_filter_layout = QGridLayout()
        adv_filter_group.setLayout(adv_filter_layout)
        adv_filter_layout.setHorizontalSpacing(16)
        adv_filter_layout.setVerticalSpacing(8)
        adv_filter_layout.addWidget(QLabel("Exclude Patterns (comma or regex):"), 0, 0)
        self.exclude_patterns_edit = QLineEdit()
        self.exclude_patterns_edit.setPlaceholderText(r"e.g. password,secret,\\d{8,}")
        adv_filter_layout.addWidget(self.exclude_patterns_edit, 0, 1, 1, 3)
        self.require_alpha_cb = QCheckBox("Require at least one letter")
        self.require_alpha_cb.setChecked(True)
        adv_filter_layout.addWidget(self.require_alpha_cb, 1, 0)
        self.exclude_hex_cb = QCheckBox("Exclude hex/base64-like strings")
        self.exclude_hex_cb.setChecked(True)
        adv_filter_layout.addWidget(self.exclude_hex_cb, 1, 1)
        self.use_regex_cb = QCheckBox("Use regex for patterns")
        self.use_regex_cb.setChecked(False)
        adv_filter_layout.addWidget(self.use_regex_cb, 1, 2)
        main_layout.addWidget(adv_filter_group)

        # Extract button
        self.extract_btn = QPushButton("Extract Strings")
        self.extract_btn.setIcon(QIcon.fromTheme("system-search"))
        self.extract_btn.clicked.connect(self.start_extraction)
        main_layout.addWidget(self.extract_btn)

        # Results display
        self.results_edit = QTextEdit()
        self.results_edit.setReadOnly(True)
        self.results_edit.setFontFamily("Consolas")
        self.results_edit.setPlaceholderText("Extracted strings will appear here...")
        main_layout.addWidget(self.results_edit, stretch=1)

        # Save button
        save_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save Results")
        self.save_btn.setIcon(QIcon.fromTheme("document-save"))
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_results)
        save_layout.addStretch(1)
        save_layout.addWidget(self.save_btn)
        main_layout.addLayout(save_layout)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)

    def _apply_qss(self):
        # Modern dark QSS theme
        qss = """
        QWidget {
            background: #23272e;
            color: #e6e6e6;
            font-family: 'Segoe UI', 'Arial', sans-serif;
            font-size: 14px;
        }
        QGroupBox {
            border: 1px solid #3a3f4b;
            border-radius: 8px;
            margin-top: 8px;
            background: #262b33;
            font-weight: bold;
            padding-top: 12px;
        }
        QGroupBox:title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 4px 0 4px;
        }
        QLineEdit, QSpinBox, QTextEdit {
            background: #1a1d22;
            border: 1px solid #3a3f4b;
            border-radius: 6px;
            padding: 6px;
            color: #e6e6e6;
        }
        QTextEdit {
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
        }
        QPushButton {
            background: #2d313a;
            border: 1px solid #3a3f4b;
            border-radius: 6px;
            padding: 6px 18px;
            color: #e6e6e6;
            font-weight: 500;
        }
        QPushButton:hover {
            background: #3a3f4b;
        }
        QPushButton:pressed {
            background: #1a1d22;
        }
        QPushButton:disabled {
            background: #23272e;
            color: #888;
        }
        QCheckBox {
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 1px solid #3a3f4b;
            background: #23272e;
        }
        QCheckBox::indicator:checked {
            background: #4e9cff;
            border: 1px solid #4e9cff;
        }
        QStatusBar {
            background: #1a1d22;
            color: #b0b0b0;
            border-top: 1px solid #3a3f4b;
        }
        QLabel {
            font-size: 14px;
        }
        """
        self.setStyleSheet(qss)

    def browse_file(self):
        filters = "Executable Files (*.exe *.dll *.sys *.ocx *.scr *.cpl *.efi);;All Files (*)"
        file, _ = QFileDialog.getOpenFileName(self, "Select a binary file", "", filters)
        if file:
            self.file_edit.setText(file)

    def start_extraction(self):
        filepath = self.file_edit.text().strip()
        if not filepath:
            QMessageBox.warning(self, "No File Selected", "Please select a binary file to extract strings from.")
            return
        min_len = self.min_length_spin.value()
        encodings = []
        if self.ascii_cb.isChecked():
            encodings.append('ascii')
        if self.utf8_cb.isChecked():
            encodings.append('utf8')
        if self.utf16le_cb.isChecked():
            encodings.append('utf16le')
        if self.utf16be_cb.isChecked():
            encodings.append('utf16be')
        if not encodings:
            QMessageBox.warning(self, "No Encoding Selected", "Please select at least one encoding to extract.")
            return
        if not os.path.isfile(filepath):
            QMessageBox.critical(self, "File Not Found", f"The file '{filepath}' could not be found.")
            return
        self.results_edit.clear()
        self.status.showMessage("Starting extraction...")
        self.extract_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        # Start worker thread
        self.worker_thread = QThread()
        self.worker = StringExtractorWorker(filepath, min_len, encodings)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.status.showMessage)
        self.worker.result.connect(self.display_results)
        self.worker.error.connect(self.show_error)
        self.worker.finished.connect(self.extraction_finished)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)
        self.worker_thread.start()

    def display_results(self, results):
        self.results = results
        # --- Filtering logic ---
        exclude_patterns = [p.strip() for p in self.exclude_patterns_edit.text().split(',') if p.strip()]
        require_alpha = self.require_alpha_cb.isChecked()
        exclude_hex = self.exclude_hex_cb.isChecked()
        use_regex = self.use_regex_cb.isChecked()
        def is_interesting(s):
            # Exclude if matches any pattern
            if exclude_patterns:
                for pat in exclude_patterns:
                    try:
                        if use_regex:
                            if re.search(pat, s):
                                return False
                        else:
                            if pat.lower() in s.lower():
                                return False
                    except Exception:
                        continue
            # Exclude if no letters
            if require_alpha and not re.search(r'[A-Za-z]', s):
                return False
            # Exclude if looks like hex/base64
            if exclude_hex:
                if re.fullmatch(r'[0-9A-Fa-f]+', s) and len(s) > 8:
                    return False
                if re.fullmatch(r'[A-Za-z0-9+/=]+', s) and len(s) > 12:
                    return False
            return True
        filtered = [(offset, encoding, string) for offset, encoding, string in results if is_interesting(string)]
        if not filtered:
            self.results_edit.setPlainText("No strings found with the selected criteria.")
            self.save_btn.setEnabled(False)
        else:
            lines = [f"0x{offset:X}: [{encoding}] {string}" for offset, encoding, string in filtered]
            self.results_edit.setPlainText("\n".join(lines))
            self.save_btn.setEnabled(True)
        self.status.showMessage(f"Extraction complete. {len(filtered)} strings found.")

    def show_error(self, msg):
        QMessageBox.critical(self, "Error", msg)
        self.status.showMessage("Error: " + msg)

    def extraction_finished(self):
        self.extract_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)

    def save_results(self):
        if not self.results:
            QMessageBox.warning(self, "No Results", "There are no results to save.")
            return
        file, _ = QFileDialog.getSaveFileName(self, "Save Extracted Strings", "extracted_strings.txt", "Text Files (*.txt);;All Files (*)")
        if not file:
            return
        try:
            with open(file, 'w', encoding='utf-8') as f:
                for offset, encoding, string in self.results:
                    f.write(f"0x{offset:X}: [{encoding}] {string}\n")
            self.status.showMessage(f"Results saved to {file}")
        except Exception as e:
            QMessageBox.critical(self, "Error Saving File", f"Could not save file:\n{e}")
            self.status.showMessage("Error saving file.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BinaryStringExtractorApp()
    window.show()
    sys.exit(app.exec())
