import sys
from PyQt6.QtWidgets import QApplication
from src.ui_main import PhishingApp

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PhishingApp()
    window.showMaximized() # Cambiado para abrir en grande profesionalmente
    sys.exit(app.exec())