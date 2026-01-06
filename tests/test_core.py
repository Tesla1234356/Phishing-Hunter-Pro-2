import pytest
from unittest.mock import MagicMock, patch
from src.extractor import extract_features_v3
import os

# --- MOCK DATA ---
# HTML simulado que tiene un formulario seguro y un enlace interno
HTML_SAFE = """
<html>
    <body>
        <form action="/login" method="POST">
            <input type="text" name="user">
        </form>
        <a href="/home">Home</a>
        <img src="/logo.png">
    </body>
</html>
"""

@pytest.fixture
def mock_response():
    """Simula una respuesta HTTP exitosa"""
    mock = MagicMock()
    mock.status_code = 200
    mock.content = HTML_SAFE.encode('utf-8')
    mock.text = HTML_SAFE
    mock.url = "http://example.com"
    return mock

def test_feature_extractor_structure(mock_response):
    """
    Verifica que el extractor devuelva siempre 9 características
    y que maneje correctamente una respuesta simulada.
    """
    with patch('src.extractor.requests.get', return_value=mock_response):
        features = extract_features_v3("http://example.com")
        
        # Debe devolver una lista
        assert isinstance(features, list)
        
        # Debe tener 9 características (según extractor.py)
        # 0:SFH, 1:PopUp, 2:SSL, 3:ReqURL, 4:Anchor, 5:Traffic, 6:Len, 7:Age, 8:IP
        assert len(features) == 9
        
        # Verificamos que los valores sean numéricos (-1, 0, 1)
        for f in features:
            assert f in [-1, 0, 1]

def test_model_files_exist():
    """
    Smoke Test: Verifica que los archivos críticos del modelo existan
    para asegurar que la aplicación pueda arrancar.
    """
    # Asumimos que los tests se corren desde la raíz del proyecto
    assert os.path.exists("model/modelo_anomalias.pkl"), "Falta el modelo de anomalías"
    assert os.path.exists("model/Website Phishing.csv"), "Falta el dataset base"
