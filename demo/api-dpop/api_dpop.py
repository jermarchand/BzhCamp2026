# api_dpop.py
import time
import hashlib
import base64
import requests
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from joserfc import jwt, jws
from joserfc.jwk import ECKey, KeySet
from joserfc.errors import BadSignatureError, ExpiredTokenError, MissingClaimError

app = FastAPI(title="API REST sécurisée avec DPoP")

# Activer le CORS pour autoriser ton frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myapp2.zenika.lan"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# -----------------------------------------------------------------------------
# INITIALISATION ET CONFIGURATION OIDC (KEYCLOAK)
# -----------------------------------------------------------------------------
OIDC_CONFIG_URL = "https://keycloak.zenika.lan/realms/bzhcamp/.well-known/openid-configuration"

try:
    print(f"Chargement de la configuration OIDC depuis : {OIDC_CONFIG_URL}...")
    # On télécharge le fichier d'auto-configuration (.well-known)
    oidc_response = requests.get(OIDC_CONFIG_URL, timeout=10, verify=False).json()
    
    KEYCLOAK_ISSUER = oidc_response["issuer"]
    JWKS_URI = oidc_response["jwks_uri"]
    
    # On télécharge le KeySet (JWKS) contenant les clés publiques de Keycloak
    print(f"Chargement des clés publiques de Keycloak depuis : {JWKS_URI}...")
    jwks_data = requests.get(JWKS_URI, timeout=10, verify=False).json()
    KEYCLOAK_KEYSET = KeySet.import_key_set(jwks_data)
    print("Configuration Keycloak chargée avec succès !")
    
except Exception as e:
    print(f"CRITICAL: Impossible d'initialiser la configuration Keycloak: {e}")
    # En cas d'erreur réseau / certificat au démarrage
    KEYCLOAK_ISSUER = "https://keycloak.zenika.lan/realms/bzhcamp"
    KEYCLOAK_KEYSET = None

# -----------------------------------------------------------------------------
# Simulation d'une base de données locale anti-rejeu pour les preuves DPoP (JTI)
USED_JTIS = set()
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# VALIDATEUR DE REQUÊTE DPoP & ACCESS_TOKEN
# -----------------------------------------------------------------------------
def verify_dpop_and_access_token(
    request: Request,
    dpop: str = Header(..., description="La preuve DPoP sous forme de JWT"),
    authorization: str = Header(..., description="L'Access Token au format: DPoP <token>")
):

    # --- ÉTAPE 1 : Extraction et validation cryptographique de la preuve DPoP ---
    try:
        jws_obj = jws.extract_compact(dpop.encode())
        unverified_header = jws_obj.protected
        
        if "jwk" not in unverified_header:
            raise HTTPException(status_code=401, detail="Le header DPoP doit contenir le claim 'jwk'")
        
        # On importe la clé publique éphémère fournie par le client dans son en-tête
        client_public_key = ECKey.import_key(unverified_header["jwk"])
        
        # On valide la signature de la preuve DPoP avec cette même clé
        token = jwt.decode(dpop, client_public_key)
        dpop_claims = token.claims
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Signature de la preuve DPoP invalide : {str(e)}")


    # --- ÉTAPE 2 : Validation des contraintes de la RFC 9449 (Payload DPoP) ---
    if unverified_header.get("typ") != "dpop+jwt":
        raise HTTPException(status_code=401, detail="Le type de jeton DPoP (typ) doit être 'dpop+jwt'")

    # Vérification de la méthode HTTP et de l'URI demandée
    if dpop_claims.get("htm") != request.method:
        raise HTTPException(status_code=401, detail="Méthode HTTP incorrecte (htm) dans la preuve DPoP")
        
    expected_htu = str(request.url).split('?')[0]
    if dpop_claims.get("htu") != expected_htu:
        raise HTTPException(status_code=401, detail="URI de destination incorrecte (htu) dans la preuve DPoP")

    # Vérification du timestamp de la preuve (Doit dater de moins de 2 minutes)
    if int(time.time()) - dpop_claims.get("iat", 0) > 120:
        raise HTTPException(status_code=401, detail="La preuve DPoP a expiré (iat trop vieux)")

    # Protection contre le rejeu (Anti-replay avec le JTI)
    jti = dpop_claims.get("jti")
    if not jti or jti in USED_JTIS:
        raise HTTPException(status_code=401, detail="JTI invalide ou preuve déjà rejouée")
    USED_JTIS.add(jti)

    # --- ÉTAPE 3 : Validation de l'association (Binding) entre l'Access Token et la preuve ---
    # Calcul de l'empreinte SHA-256 de l'access token
    if not authorization.startswith("DPoP "):
        raise HTTPException(status_code=401, detail="L'en-tête Authorization doit utiliser le schéma 'DPoP'")
    
    access_token = authorization.split(" ")[1]
    token_hash = hashlib.sha256(access_token.encode()).digest()
    expected_ath = base64.urlsafe_b64encode(token_hash).decode().rstrip("=")

    if dpop_claims.get("ath") != expected_ath:
        raise HTTPException(status_code=401, detail="Le claim ath ne correspond pas à l'Access Token fourni")

    
    # --- ÉTAPE 4 : Validation de l'Access Token Keycloak ---
    if not KEYCLOAK_KEYSET:
        raise HTTPException(status_code=500, detail="Le serveur de clés Keycloak n'est pas disponible")

    try:
        # joserfc choisit automatiquement la bonne clé dans le KeySet grâce au 'kid' du jeton
        decoded_access_token = jwt.decode(access_token, KEYCLOAK_KEYSET)
        at_claims = decoded_access_token.claims
        
        # Validation de l'émetteur (Issuer) attendu
        if at_claims.get("iss") != KEYCLOAK_ISSUER:
            raise HTTPException(status_code=401, detail="L'émetteur du jeton (iss) ne correspond pas à Keycloak")
            
        # Validation du temps (Expiration de l'access token)
        if int(time.time()) > at_claims.get("exp", 0):
            raise HTTPException(status_code=401, detail="L'Access Token Keycloak a expiré")

        # Validation du thumbprint
        if at_claims["cnf"]["jkt"] != client_public_key.thumbprint():
            raise HTTPException(status_code=401, detail="thumbprint invalide")

    except (BadSignatureError, ExpiredTokenError, Exception) as e:
        raise HTTPException(status_code=401, detail=f"Access Token invalide ou corrompu: {str(e)}")

    return {"user": at_claims.get("preferred_username", "Inconnu"), "scopes": at_claims.get("scope")}


# -----------------------------------------------------------------------------
@app.get("/api/ressource")
def get_protected_data(auth_data: dict = Depends(verify_dpop_and_access_token)):
    """
    Endpoint sécurisé à double niveau : Signature Access Token (Keycloak) + Validation DPoP (Client).
    """
    return {
        "status": "Succès",
        "message": f"Bonjour {auth_data['user']}, vous avez accédé à la ressource BzhCamp !",
        "autorisations": auth_data["scopes"]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)