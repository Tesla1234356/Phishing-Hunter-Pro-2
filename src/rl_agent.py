import numpy as np
import joblib
import os
import random
from sklearn.linear_model import SGDClassifier

class PhishingAgent:
    def __init__(self, model_path='model/rl_agent.pkl', memory_path='model/rl_memory.pkl'):
        self.model_path = model_path
        self.memory_path = memory_path
        self.classes = np.array([0, 1])
        
        self.memory_safe = []
        self.memory_phish = []
        
        self.load()
        if not hasattr(self, 'model'):
            self.init_new_model()

    def init_new_model(self):
        self.model = SGDClassifier(
            loss='log_loss', 
            penalty='l2',
            alpha=0.001,
            learning_rate='optimal', 
            random_state=42
        )
        self.is_fitted = False

    def sanitize_memory(self):
        self.memory_safe = [x.tolist() if isinstance(x, np.ndarray) else x for x in self.memory_safe]
        self.memory_phish = [x.tolist() if isinstance(x, np.ndarray) else x for x in self.memory_phish]

    def predict(self, features):
        features = np.array(features).reshape(1, -1)
        if not self.is_fitted:
            return None, 0.0
        
        prediction = self.model.predict(features)[0]
        try:
            proba = self.model.predict_proba(features)[0][prediction]
        except:
            proba = 0.5 
        return prediction, proba

    def learn(self, features, prediction_made, feedback_type):
        features_array = np.array(features).reshape(1, -1)
        features_list = features_array[0].tolist()
        
        if feedback_type == 'correct':
            true_label = prediction_made
        else:
            true_label = 1 - prediction_made
            
        # --- GESTIÓN DE CONTRADICCIONES (La solución a tu problema) ---
        # Si el usuario dice que ahora es SEGURO (0), borramos cualquier recuerdo de que fuera PHISHING.
        if true_label == 0:
            if features_list in self.memory_phish:
                # ¡Borramos la contradicción! "Antes pensé que era malo, pero el usuario me corrigió"
                self.memory_phish.remove(features_list)
            
            # Agregamos a la memoria correcta
            if features_list not in self.memory_safe:
                self.memory_safe.append(features_list)
                
        # Si el usuario dice que ahora es PHISHING (1), borramos recuerdo de que fuera SEGURO.
        else:
            if features_list in self.memory_safe:
                # ¡Borramos la contradicción!
                self.memory_safe.remove(features_list)
                
            # Agregamos a la memoria correcta
            if features_list not in self.memory_phish:
                self.memory_phish.append(features_list)

        # Límite de memoria para no saturar
        if len(self.memory_safe) > 500: self.memory_safe.pop(0)
        if len(self.memory_phish) > 500: self.memory_phish.pop(0)

        # --- ENTRENAMIENTO ---
        batch_X = [features_list]
        batch_y = [true_label]
        
        # Para reforzar el cambio, le damos más peso al dato actual repitiéndolo en el batch
        # Esto ayuda a "desbloquear" la terquedad del modelo inmediatamente.
        batch_X.append(features_list)
        batch_y.append(true_label)
        
        # Relleno de memoria (Experience Replay)
        if true_label == 1 and len(self.memory_safe) > 0:
            n = min(10, len(self.memory_safe))
            batch_X.extend(random.sample(self.memory_safe, n))
            batch_y.extend([0] * n)
            
        elif true_label == 0 and len(self.memory_phish) > 0:
            n = min(10, len(self.memory_phish))
            batch_X.extend(random.sample(self.memory_phish, n))
            batch_y.extend([1] * n)

        self.model.partial_fit(batch_X, batch_y, classes=self.classes)
        self.is_fitted = True
        
        self.save()
        return true_label

    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump({'safe': self.memory_safe, 'phish': self.memory_phish}, self.memory_path)

    def load(self):
        if os.path.exists(self.model_path):
            try: 
                self.model = joblib.load(self.model_path)
                self.is_fitted = True
            except: self.is_fitted = False
        else: self.is_fitted = False
            
        if os.path.exists(self.memory_path):
            try:
                mem = joblib.load(self.memory_path)
                self.memory_safe = mem.get('safe', [])
                self.memory_phish = mem.get('phish', [])
                self.sanitize_memory()
            except: pass
