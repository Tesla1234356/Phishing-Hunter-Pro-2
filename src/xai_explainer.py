# src/xai_explainer.py

def interpretar_caracteristicas(features):
    """
    Analiza el vector de características y devuelve explicaciones legibles.
    
    Args:
        features (list): Lista de enteros [-1, 0, 1] generada por extractor.py
        
    Returns:
        dict: Contiene listas de 'factores_riesgo' y 'factores_seguridad'
    """
    
    # Mapeo basado en la lógica de src/extractor.py
    # Indices: 
    # 0: SFH (Server Form Handler)
    # 1: PopUp
    # 2: SSL
    # 3: Request_URL (Imágenes/Videos externos)
    # 4: Anchor (Enlaces externos)
    # 5: Traffic (Placeholder)
    # 6: Length (Longitud URL)
    # 7: Age (Edad Dominio)
    # 8: IP (Uso de IP en vez de dominio)

    explicaciones = {
        "riesgos": [],
        "seguridad": []
    }

    # 1. SFH (Formularios)
    if features[0] == 1:
        explicaciones["riesgos"].append("⚠️ Suspicious Form: Sends data to an external or empty domain.")
    elif features[0] == -1:
        explicaciones["seguridad"].append("✅ Secure Forms: Data is processed internally.")

    # 2. PopUp
    if features[1] == 1:
        explicaciones["riesgos"].append("⚠️ Intrusive Behavior: Attempts to open pop-ups.")

    # 3. SSL (HTTPS)
    if features[2] == 1:
        explicaciones["riesgos"].append("🔓 Insecure Connection: Does not use a valid HTTPS certificate.")
    else:
        explicaciones["seguridad"].append("🔒 Encryption Enabled: Secure connection via HTTPS.")

    # 4. Request_URL (Recursos externos)
    if features[3] == 1:
        explicaciones["riesgos"].append("⚠️ Suspicious Resource Loading: High amount of external images/scripts.")

    # 5. Anchor (Enlaces)
    if features[4] == 1:
        explicaciones["riesgos"].append("🔗 Anomalous Link Structure: Most links lead to other sites.")
    else:
        explicaciones["seguridad"].append("✅ Navigation Consistency: Links are consistent with the domain.")

    # 6. Length (Longitud)
    if features[6] == 1:
        explicaciones["riesgos"].append("📏 URL Too Long: Typical in attempts to hide the real domain.")
    elif features[6] == -1:
        explicaciones["seguridad"].append("✅ Concise URL: Standard and verifiable length.")

    # 7. Age (Edad)
    if features[7] == 1:
        explicaciones["riesgos"].append("📅 Domain too recent (<6 months) or hidden WHOIS information.")
    else:
        explicaciones["seguridad"].append("🗓️ Established Domain: Sufficient age (+6 months).")

    # 8. IP
    if features[8] == 1:
        explicaciones["riesgos"].append("🚨 Raw IP Address: Site does not use a registered domain name.")

    return explicaciones
