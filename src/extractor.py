import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import whois
from datetime import datetime
import re
import numpy as np

def extract_features_and_url(url):
    """
    Versión avanzada que devuelve (features, final_url).
    Incluye HEURÍSTICA DE HOSTING GRATUITO para detectar phishing moderno.
    """
    features = []
    final_url = url
    
    if not url.startswith("http"):
        url = "http://" + url
    
    try:
        response = requests.get(url, timeout=3, allow_redirects=True)
        final_url = response.url 
        soup = BeautifulSoup(response.content, 'html.parser')
        domain = urlparse(final_url).netloc.lower()
    except:
        return [1, 1, 1, 1, 1, -1, 1, 1, 1], url 

    # --- DETECCIÓN DE PLATAFORMAS GRATUITAS (High Risk) ---
    free_hosts = [
        'onrender.com', 'herokuapp.com', 'vercel.app', 'netlify.app', 
        'glitch.me', 'firebaseapp.com', '000webhostapp.com', 'github.io',
        'repl.co', 'fly.dev', 'railway.app', 'pages.dev'
    ]
    
    is_free_hosting = any(domain.endswith(host) for host in free_hosts)

    # 1. SFH (Server Form Handler)
    try:
        forms = soup.find_all('form', action=True)
        if len(forms) == 0: sfh = -1
        else:
            sfh = -1
            for form in forms:
                action = form['action']
                if action == "" or action == "about:blank":
                    sfh = 1; break
                elif domain not in action and not action.startswith('/'):
                    sfh = 0
        
        # PENALIZACIÓN POR HOSTING GRATUITO
        if is_free_hosting: sfh = 1 # Consideramos sospechoso cualquier form en hosting gratis
            
        features.append(sfh)
    except: features.append(1)

    # 2. popUp
    if "window.open" in response.text: features.append(1)
    else: features.append(-1)

    # 3. SSL
    if final_url.startswith("https"): features.append(-1)
    else: features.append(1)

    # 4. Request_URL
    imgs = soup.find_all('img', src=True)
    ext = 0
    for i in imgs:
        if domain not in i['src'] and not i['src'].startswith('/'): ext += 1
    
    ratio_req = ext/len(imgs) if len(imgs) > 0 else 0
    if ratio_req > 0.61: features.append(1)
    else: features.append(-1)

    # 5. Anchor
    anchors = soup.find_all('a', href=True)
    ext_a = 0
    for a in anchors:
        if domain not in a['href'] and not a['href'].startswith('/') and not a['href'].startswith('#'): ext_a += 1
    
    ratio_anchor = ext_a/len(anchors) if len(anchors) > 0 else 0
    
    # PENALIZACIÓN POR HOSTING GRATUITO
    if is_free_hosting: 
        # Si es hosting gratis, somos MUY estrictos con los links externos
        features.append(1) 
    elif ratio_anchor > 0.67: 
        features.append(1)
    else: 
        features.append(-1)

    # 6. Traffic (Simulado seguro)
    features.append(1)

    # 7. Length
    l = len(final_url)
    if l < 54: features.append(-1)
    elif l > 75: features.append(1)
    else: features.append(0)

    # 8. Age
    try:
        # Si es hosting gratuito, el WHOIS suele dar la fecha de la plataforma (antigua)
        # Por lo tanto, NO podemos confiar en la antigüedad para validarlo.
        # Forzamos "Sospechoso" (1) o "Neutro" (0) si es hosting gratis.
        if is_free_hosting:
            features.append(1) # Penalizamos la edad porque el subdominio es nuevo aunque el dominio sea viejo
        else:
            w = whois.whois(domain)
            d = w.creation_date
            if isinstance(d, list): d = d[0]
            if d:
                if (datetime.now() - d).days >= 180: features.append(-1)
                else: features.append(1)
            else: features.append(1)
    except: features.append(1)

    # 9. IP
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain): features.append(1)
    else: features.append(0)

    return features, final_url

def extract_features_v3(url):
    """
    Wrapper de compatibilidad.
    """
    feats, _ = extract_features_and_url(url)
    return feats