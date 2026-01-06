import joblib
import os
import numpy as np
from src.rl_agent import PhishingAgent

class ModelHandler:
    def __init__(self):
        # Ajustamos la ruta asumiendo que se ejecuta desde la raíz del proyecto
        self.model_path = os.path.join("model", "modelo_anomalias.pkl")
        self.base_model = None
        
        # Inicializar el Agente de RL (Cerebro Dinámico)
        self.agent = PhishingAgent()
        
        self.load_model()

    def load_model(self):
        try:
            if os.path.exists(self.model_path):
                self.base_model = joblib.load(self.model_path)
                print("Modelo Base (Isolation Forest) cargado exitosamente.")
            else:
                print(f"Error: No se encontró el modelo base en {self.model_path}")
        except Exception as e:
            print(f"Error cargando el modelo base: {e}")

    def predict(self, features):
        """
        Sistema Híbrido de Predicción:
        1. Consulta al Agente RL. Si tiene experiencia, decide él.
        2. Si no, consulta al Modelo Base (Isolation Forest).
        
        Retorna: -1 (Anomalía/Phishing), 1 (Normal)
        """
        # 1. Intentar predicción con el Agente RL
        agent_pred, agent_prob = self.agent.predict(features)
        
        if agent_pred is not None:
            # Mapeo: Agente 1 (Phishing) -> UI -1, Agente 0 (Seguro) -> UI 1
            result = -1 if agent_pred == 1 else 1
            print(f"Agente RL Decision: {result} (Confianza: {agent_prob:.2%})")
            return result

        # 2. Fallback al Modelo Base
        if self.base_model:
            try:
                features_array = np.array(features).reshape(1, -1)
                result = self.base_model.predict(features_array)[0]
                print(f"Modelo Base Decision: {result}")
                return result
            except Exception as e:
                print(f"Error en predicción base: {e}")
                return 1 
        else:
            return 1

    def train_agent_online(self, features, result_shown, feedback_type):
        """
        Puente para entrenar al agente desde la UI.
        Convierte el formato de la UI (-1/1) al formato del Agente (1/0).
        """
        # UI -1 (Phishing) -> Agente 1
        # UI 1 (Normal) -> Agente 0
        prediction_made = 1 if result_shown == -1 else 0
        
        self.agent.learn(features, prediction_made, feedback_type)
