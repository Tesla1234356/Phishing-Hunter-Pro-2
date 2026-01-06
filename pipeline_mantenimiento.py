# pipeline_mantenimiento.py
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, classification_report
from src.extractor import extract_features_v3 
import os
import csv
import numpy as np
import warnings

# --- CONFIGURACIÓN ---
RUTA_DATASET_ORIGINAL = "model/Website Phishing.csv"
RUTA_FEEDBACK = "feedback.csv"
RUTA_MODELO = "model/modelo_anomalias.pkl"

# Filtramos advertencias para que la consola se vea limpia en el video
warnings.filterwarnings("ignore")

def evaluar_modelo(modelo, X_test, y_test, nombre_etapa):
    """
    Función auxiliar para calcular métricas rápidas.
    Devuelve la exactitud (accuracy) para comparar.
    """
    if modelo is None: return 0.0
    
    y_pred = modelo.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\n--- 📊 Evaluation: {nombre_etapa} ---")
    print(f"Global Accuracy: {acc:.2%}")
    # Mostramos reporte simplificado
    print(classification_report(y_test, y_pred, target_names=['Anomaly (Phishing)', 'Normal (Legitimate)']))
    return acc

def reentrenar_modelo():
    print("🚀 STARTING AUTOMATED MAINTENANCE PIPELINE...")
    
    # 1. Cargar datos originales y preparar Test Set
    # ---------------------------------------------------------
    try:
        df = pd.read_csv(RUTA_DATASET_ORIGINAL)
        
        # Grupo A: SOLO Legítimos (Para entrenar)
        df_legitimos = df[df['Result'] == 1]
        X_train_base = df_legitimos.drop('Result', axis=1).values.tolist()
        
        # Grupo B: TODO el dataset (Para evaluar/testear)
        X_test_all = df.drop('Result', axis=1)
        # Convertimos etiquetas: 1->1, Resto->-1
        y_test_all = df['Result'].apply(lambda x: 1 if x == 1 else -1)
        
        print(f"✅ Original data loaded: {len(X_train_base)} base patterns.")
    except Exception as e:
        print(f"❌ CRITICAL ERROR: Could not load original dataset ({e}).")
        return False

    # 2. Cargar el modelo VIEJO para comparar después
    # ---------------------------------------------------------
    try:
        modelo_viejo = joblib.load(RUTA_MODELO)
        print("💾 Current model loaded into memory (for comparison).")
        acc_vieja = evaluar_modelo(modelo_viejo, X_test_all, y_test_all, "CURRENT MODEL (BEFORE)")
    except:
        print("⚠️ No previous model exists. Creating from scratch.")
        modelo_viejo = None
        acc_vieja = 0.0

    # 3. Procesar el Feedback (Nuevos datos)
    # ---------------------------------------------------------
    if not os.path.exists(RUTA_FEEDBACK):
        print("❌ No feedback file found. Process ending.")
        return False

    print("\n🔄 Processing user feedback...")
    nuevos_datos = []
    
    with open(RUTA_FEEDBACK, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row: continue
            url = row[1]
            print(f"   -> Processing URL: {url}")
            try:
                features = extract_features_v3(url)
                nuevos_datos.append(features)
            except Exception as e:
                print(f"      Error: {e}")

    if len(nuevos_datos) == 0:
        print("⚠️ No valid new data extracted.")
        return False

    print(f"✅ {len(nuevos_datos)} new patterns added to training.")
    
    # Combinamos: Entrenamiento Viejo + Nuevos Datos
    X_train_total = X_train_base + nuevos_datos

    # 4. Re-Entrenar NUEVO Modelo
    # ---------------------------------------------------------
    print("\n🧠 Training NEW model version...")
    
    modelo_nuevo = IsolationForest(n_estimators=300, 
                                   contamination=0.1, 
                                   random_state=42, 
                                   n_jobs=-1)
    modelo_nuevo.fit(X_train_total)
    
    # 5. Evaluación del NUEVO Modelo
    # ---------------------------------------------------------
    acc_nueva = evaluar_modelo(modelo_nuevo, X_test_all, y_test_all, "NEW MODEL (AFTER)")

    # 6. Decisión de Despliegue (Deployment Decision)
    # ---------------------------------------------------------
    print("\n--- ⚖️ FINAL VERDICT ---")
    print(f"Previous Accuracy: {acc_vieja:.2%}")
    print(f"New Accuracy:      {acc_nueva:.2%}")
    
    # Regla: Si el modelo nuevo es igual o mejor (o baja muy poquito, <1%), lo guardamos.
    if acc_nueva >= (acc_vieja - 0.01):
        joblib.dump(modelo_nuevo, RUTA_MODELO)
        print("✅ SUCCESS: New model APPROVED and SAVED.")
        
        # --- LIMPIEZA AUTOMÁTICA ---
        # Borramos el contenido de feedback.csv para empezar el siguiente lote desde cero
        open(RUTA_FEEDBACK, 'w').close()
        print("🧹 Feedback file cleared. Counter reset to 0.")
        return True # Retorna ÉXITO a la App
    else:
        print("❌ ALERT: New model significantly degraded performance.")
        print("   Changes were not saved. Check feedback data.")
        return False # Retorna FALLO a la App

if __name__ == "__main__":
    reentrenar_modelo()