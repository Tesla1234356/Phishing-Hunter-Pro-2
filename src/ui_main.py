# src/ui_main.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QLineEdit, 
                             QPushButton, QFrame, QMessageBox, QHBoxLayout, 
                             QSpacerItem, QSizePolicy, QProgressBar, QScrollArea)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QImage, QPixmap, QColor
from src.extractor import extract_features_v3, extract_features_and_url
from src.model_loader import ModelHandler
from src.xai_explainer import interpretar_caracteristicas
import csv
from datetime import datetime
import os
import cv2
from pyzbar.pyzbar import decode
import numpy as np
import requests
from urllib.parse import urlparse

# IMPORTANTE: Importamos el script de mantenimiento
import pipeline_mantenimiento

# --- ESTILOS CSS PROFESIONALES (STABLE) ---
STYLE_SHEET = """
QWidget {
    background-color: #0f172a;
    color: #f8fafc;
    font-family: 'Segoe UI', Roboto, sans-serif;
}

QScrollArea {
    border: none;
    background-color: #0f172a;
}

QScrollBar:vertical {
    border: none;
    background: #1e293b;
    width: 10px;
    margin: 0px 0px 0px 0px;
}

QScrollBar::handle:vertical {
    background: #475569;
    min-height: 20px;
    border-radius: 5px;
}

QFrame#MainContainer {
    background-color: #1e293b;
    border-radius: 15px;
    border: 1px solid #334155;
}

QLabel#HeaderTitle {
    color: #3b82f6;
    font-size: 32px;
    font-weight: bold;
    margin-bottom: 5px;
}

QLabel#HeaderSub {
    color: #94a3b8;
    font-size: 14px;
    margin-bottom: 20px;
}

QLineEdit {
    background-color: #0f172a;
    border: 2px solid #334155;
    border-radius: 10px;
    padding: 12px;
    font-size: 16px;
    color: #e2e8f0;
}

QLineEdit:focus {
    border: 2px solid #3b82f6;
}

QPushButton#AnalyzeBtn {
    background-color: #3b82f6;
    border-radius: 10px;
    padding: 15px;
    font-size: 16px;
    font-weight: bold;
    color: white;
}

QPushButton#AnalyzeBtn:hover {
    background-color: #2563eb;
}

QPushButton#QRBtn {
    background-color: #334155;
    border-radius: 10px;
    padding: 12px;
    color: white;
}

QPushButton#QRBtn:hover {
    background-color: #475569;
}

QFrame#ResultBox {
    background-color: #0f172a;
    border-radius: 12px;
    border: 1px solid #334155;
}

QLabel#ResultText {
    font-size: 24px;
    font-weight: bold;
}

/* BOTONES FEEDBACK MEJORADOS */
QPushButton#FeedbackOk {
    background-color: #065f46;
    border-radius: 8px;
    padding: 10px;
    font-weight: bold;
    color: white;
}
QPushButton#FeedbackOk:disabled {
    background-color: #1e293b;
    color: #475569;
    border: 1px solid #334155;
}
QPushButton#FeedbackOk:enabled {
    background-color: #10b981;
}
QPushButton#FeedbackOk:hover:enabled {
    background-color: #059669;
}

QPushButton#FeedbackBad {
    background-color: #7f1d1d;
    border-radius: 8px;
    padding: 10px;
    font-weight: bold;
    color: white;
}
QPushButton#FeedbackBad:disabled {
    background-color: #1e293b;
    color: #475569;
    border: 1px solid #334155;
}
QPushButton#FeedbackBad:enabled {
    background-color: #ef4444;
}
QPushButton#FeedbackBad:hover:enabled {
    background-color: #dc2626;
}
"""

# --- HILOS (Igual lógica, mayor estabilidad) ---
class WorkerThread(QThread):
    finished = pyqtSignal(object, int, str)

    def __init__(self, url, handler):
        super().__init__()
        self.url = url
        self.handler = handler

    def run(self):
        features, final_url = extract_features_and_url(self.url)
        result = self.handler.predict(features)
        self.finished.emit(features, result, final_url)

class MaintenanceWorker(QThread):
    finished = pyqtSignal(bool)
    def run(self):
        exito = pipeline_mantenimiento.reentrenar_modelo()
        self.finished.emit(bool(exito))

class QRScannerThread(QThread):
    frame_captured = pyqtSignal(QImage)
    qr_detected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        cap = cv2.VideoCapture(0)
        while self.running:
            ret, frame = cap.read()
            if not ret: continue
            decoded_objects = decode(frame)
            for obj in decoded_objects:
                qr_data = obj.data.decode('utf-8')
                if qr_data:
                    try:
                        res = requests.head(qr_data, timeout=3, allow_redirects=True)
                        self.qr_detected.emit(res.url)
                    except:
                        self.qr_detected.emit(qr_data)
                    self.running = False
                    break
            rgb_image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            h, w, ch = rgb_image.shape
            qt_image = QImage(rgb_image.data, w, h, ch * w, QImage.Format.Format_RGB888)
            self.frame_captured.emit(qt_image.scaled(500, 375, Qt.AspectRatioMode.KeepAspectRatio))
            self.msleep(30)
        cap.release()

    def stop(self):
        self.running = False
        self.wait()

# --- APP PRINCIPAL ---
class PhishingApp(QWidget):
    def __init__(self):
        super().__init__()
        self.model_handler = ModelHandler()
        self.current_url = ""
        self.current_features = []
        self.THRESHOLD_BATCH = 10
        self.qr_thread = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("CyberGuard AI - Phishing Detection Suite")
        self.setStyleSheet(STYLE_SHEET)
        
        # === ARQUITECTURA SCROLLABLE (Solución al corte de pantalla) ===
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0) 

        # 1. Crear el área de scroll
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        
        # 2. Crear el Widget contenedor que va DENTRO del scroll
        self.scroll_content = QWidget()
        scroll_layout = QVBoxLayout(self.scroll_content)
        scroll_layout.setAlignment(Qt.AlignmentFlag.AlignCenter) 
        
        # 3. Crear el Panel Principal (Dashboard)
        container = QFrame()
        container.setObjectName("MainContainer")
        container.setFixedWidth(900)
        container.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)
        
        layout = QVBoxLayout(container)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        # A. HEADER
        header_vbox = QVBoxLayout()
        title = QLabel("🛡️ PHISHING HUNTER PRO")
        title.setObjectName("HeaderTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtitle = QLabel("HYBRID DETECTION SYSTEM: REINFORCEMENT LEARNING + ANOMALY ANALYSIS")
        subtitle.setObjectName("HeaderSub")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        header_vbox.addWidget(title)
        header_vbox.addWidget(subtitle)
        layout.addLayout(header_vbox)

        # B. SECCIÓN DE ENTRADA
        input_area = QVBoxLayout()
        input_area.setSpacing(10)
        
        input_label = QLabel("SITE URL TO ANALYZE:")
        input_label.setStyleSheet("font-weight: bold; color: #60a5fa;")
        input_area.addWidget(input_label)
        
        url_hbox = QHBoxLayout()
        self.input_url = QLineEdit()
        self.input_url.setPlaceholderText("Enter URL or use QR scanner...")
        
        self.btn_qr = QPushButton("📷 SCAN QR")
        self.btn_qr.setObjectName("QRBtn")
        self.btn_qr.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_qr.clicked.connect(self.toggle_qr_scanner)
        
        url_hbox.addWidget(self.input_url, 4)
        url_hbox.addWidget(self.btn_qr, 1)
        input_area.addLayout(url_hbox)
        layout.addLayout(input_area)

        # C. VISOR QR
        self.camera_label = QLabel()
        self.camera_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.camera_label.setFixedSize(600, 400)
        self.camera_label.setStyleSheet("border: 2px solid #3b82f6; background-color: #000; border-radius: 10px;")
        self.camera_label.setVisible(False)
        
        cam_h_layout = QHBoxLayout()
        cam_h_layout.addWidget(self.camera_label)
        layout.addLayout(cam_h_layout)

        # D. BOTÓN ACCIÓN PRINCIPAL
        self.btn = QPushButton("START THREAT SCAN")
        self.btn.setObjectName("AnalyzeBtn")
        self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn.clicked.connect(self.run_analysis)
        layout.addWidget(self.btn)

        # E. RESULTADOS
        self.res_frame = QFrame()
        self.res_frame.setObjectName("ResultBox")
        self.res_frame.setMinimumHeight(150)
        
        res_vbox = QVBoxLayout(self.res_frame)
        res_vbox.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.lbl_res = QLabel("WAITING FOR INPUT...")
        self.lbl_res.setObjectName("ResultText")
        self.lbl_res.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.lbl_desc = QLabel("The system will analyze redirection patterns, SSL, and site structure.")
        self.lbl_desc.setStyleSheet("color: #94a3b8;")
        self.lbl_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # --- NUEVO: AREA DE REPORTE XAI ---
        self.detail_text = QLabel("")
        self.detail_text.setObjectName("XAIReport")
        self.detail_text.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.detail_text.setWordWrap(True)
        self.detail_text.setStyleSheet("""
            padding: 15px;
            background-color: #1e293b;
            border-radius: 8px;
            color: #e2e8f0;
            font-size: 13px;
            margin-top: 10px;
        """)
        self.detail_text.setVisible(False)

        res_vbox.addWidget(self.lbl_res)
        res_vbox.addWidget(self.lbl_desc)
        res_vbox.addWidget(self.detail_text) # Agregamos el reporte al layout
        layout.addWidget(self.res_frame)

        # F. FEEDBACK & IA STATUS
        bottom_layout = QHBoxLayout()
        
        # Feedback Buttons
        fb_vbox = QVBoxLayout()
        fb_vbox.addWidget(QLabel("WAS THE PREDICTION ACCURATE?"))
        
        fb_buttons = QHBoxLayout()
        self.btn_ok = QPushButton("👍 YES, CORRECT")
        self.btn_ok.setObjectName("FeedbackOk")
        self.btn_ok.setEnabled(False)
        self.btn_ok.clicked.connect(lambda: self.save_fb("correct"))
        
        self.btn_bad = QPushButton("👎 NO, INCORRECT")
        self.btn_bad.setObjectName("FeedbackBad")
        self.btn_bad.setEnabled(False)
        self.btn_bad.clicked.connect(lambda: self.save_fb("error"))
        
        fb_buttons.addWidget(self.btn_ok)
        fb_buttons.addWidget(self.btn_bad)
        fb_vbox.addLayout(fb_buttons)
        
        # IA Monitor
        self.ia_status_frame = QFrame()
        self.ia_status_frame.setStyleSheet("background: #0f172a; border-radius: 10px; padding: 10px;")
        ia_vbox = QVBoxLayout(self.ia_status_frame)
        
        self.lbl_maintenance = QLabel("STATUS: CORE OPERATIONAL")
        self.lbl_maintenance.setStyleSheet("color: #10b981; font-weight: bold; font-size: 11px;")
        
        self.pbar = QProgressBar()
        self.pbar.setFixedHeight(8)
        self.pbar.setTextVisible(False)
        self.pbar.setStyleSheet("QProgressBar::chunk { background-color: #3b82f6; }")
        
        ia_vbox.addWidget(self.lbl_maintenance)
        ia_vbox.addWidget(self.pbar)
        
        bottom_layout.addLayout(fb_vbox, 2)
        bottom_layout.addWidget(self.ia_status_frame, 1)
        layout.addLayout(bottom_layout)

        # Finalizar montaje de layouts
        scroll_layout.addWidget(container)
        self.scroll_area.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll_area)
        
        self.update_progress_bar()

    # --- LÓGICA UI ---
    def toggle_qr_scanner(self):
        if self.qr_thread and self.qr_thread.isRunning():
            self.qr_thread.stop()
            self.camera_label.setVisible(False)
            self.btn_qr.setText("📷 SCAN QR")
        else:
            self.camera_label.setVisible(True)
            self.btn_qr.setText("❌ CANCEL")
            self.qr_thread = QRScannerThread()
            self.qr_thread.frame_captured.connect(lambda img: self.camera_label.setPixmap(QPixmap.fromImage(img)))
            self.qr_thread.qr_detected.connect(self.handle_qr_found)
            self.qr_thread.start()

    def handle_qr_found(self, url):
        self.toggle_qr_scanner()
        self.input_url.setText(url)
        self.run_analysis()

    def run_analysis(self):
        url = self.input_url.text().strip()
        if not url: return
        self.current_url = url
        self.lbl_res.setText("🕵️ ANALYZING...")
        self.lbl_res.setStyleSheet("color: #3b82f6;")
        self.btn.setEnabled(False)
        
        self.worker = WorkerThread(url, self.model_handler)
        self.worker.finished.connect(self.show_result)
        self.worker.start()

    def show_result(self, feats, res, final_url):
        self.current_features = feats
        self.current_result = res
        
        if final_url != self.current_url:
            self.input_url.setText(final_url)
            self.current_url = final_url

        self.btn.setEnabled(True)  # <-- REACTIVAR EL BOTÓN AQUÍ
        self.btn_ok.setEnabled(True)
        self.btn_bad.setEnabled(True)

        # --- GENERACIÓN DE REPORTE XAI ---
        explicacion = interpretar_caracteristicas(feats)
        reporte_html = "<b>🔎 FORENSIC FEATURE REPORT:</b><br><br>"
        
        if res == -1: # AMENAZA
            self.lbl_res.setText("🔴 THREAT DETECTED")
            self.lbl_res.setStyleSheet("color: #ef4444;")
            self.lbl_desc.setText(f"ANOMALY DETECTED IN: {urlparse(final_url).netloc}")
            self.res_frame.setStyleSheet("background-color: #450a0a; border: 2px solid #ef4444;")
            
            # Mostramos RIESGOS en Rojo
            if explicacion["riesgos"]:
                reporte_html += "<span style='color:#fca5a5;'>⚠️ RISK FACTORS DETECTED:</span><ul>"
                for riesgo in explicacion["riesgos"]:
                    reporte_html += f"<li>{riesgo}</li>"
                reporte_html += "</ul>"
            else:
                reporte_html += "<i>Anomalous mathematical pattern detected without obvious heuristic indicators.</i>"
                
        else: # SEGURO
            self.lbl_res.setText("🟢 SAFE SITE")
            self.lbl_res.setStyleSheet("color: #10b981;")
            self.lbl_desc.setText(f"NORMAL PATTERN CONFIRMED: {urlparse(final_url).netloc}")
            self.res_frame.setStyleSheet("background-color: #064e3b; border: 2px solid #10b981;")
            
            # Mostramos SEGURIDAD en Verde
            if explicacion["seguridad"]:
                reporte_html += "<span style='color:#86efac;'>🛡️ TRUST INDICATORS:</span><ul>"
                for seguro in explicacion["seguridad"]:
                    reporte_html += f"<li>{seguro}</li>"
                reporte_html += "</ul>"

        self.detail_text.setText(reporte_html)
        self.detail_text.setVisible(True)

    def save_fb(self, tipo):
        try:
            with open('feedback.csv', 'a', newline='') as f:
                csv.writer(f).writerow([datetime.now(), self.current_url, tipo])
            
            self.model_handler.train_agent_online(self.current_features, self.current_result, tipo)
            self.update_progress_bar()
            
            QMessageBox.information(self, "AI Learning", "Reinforcement applied. The agent has adjusted its parameters in real-time.")
            
            count = self.get_feedback_count()
            if count >= self.THRESHOLD_BATCH:
                self.trigger_maintenance()
        except Exception as e:
            QMessageBox.warning(self, "Error", str(e))

    def update_progress_bar(self):
        count = self.get_feedback_count()
        self.pbar.setMaximum(self.THRESHOLD_BATCH)
        self.pbar.setValue(min(count, self.THRESHOLD_BATCH))

    def get_feedback_count(self):
        if not os.path.exists('feedback.csv'): return 0
        with open('feedback.csv', 'r') as f:
            return sum(1 for _ in f)

    def trigger_maintenance(self):
        self.lbl_maintenance.setText("⚠️ RETRAINING IN PROGRESS...")
        self.lbl_maintenance.setStyleSheet("color: #f59e0b;")
        self.setEnabled(False) 
        self.maint_worker = MaintenanceWorker()
        self.maint_worker.finished.connect(self.finish_maintenance)
        self.maint_worker.start()

    def finish_maintenance(self, success):
        self.setEnabled(True)
        if success:
            self.lbl_maintenance.setText("✅ CORE UPDATED")
            self.lbl_maintenance.setStyleSheet("color: #10b981;")
            self.update_progress_bar()
            self.model_handler.load_model()
        else:
            self.lbl_maintenance.setText("❌ QUALITY ERROR")
            self.lbl_maintenance.setStyleSheet("color: #ef4444;")
