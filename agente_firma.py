from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import pkcs11
from pkcs11 import Mechanism
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
import base64
import binascii
import re
import platform
import os
import logging
from logging.handlers import RotatingFileHandler
from io import BytesIO
from datetime import datetime, timezone

app = Flask(__name__)


def configurar_logging():
    """Guarda un log local sin registrar PIN, documentos ni firmas."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    log_dir = os.path.join(base, "AVEX", "AgenteFirma")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "agente.log")
    handler = RotatingFileHandler(
        log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(handler)
    return log_path


LOG_PATH = configurar_logging()

# Orígenes permitidos para CORS: agregar acá cada frontend que vaya a
# consumir este agente (desarrollo local + dominio de producción).
CORS(app, origins=[
    "http://localhost:3030",           # Next.js en desarrollo local
    "http://localhost:3031",           # túnel SSH local hacia servidor de prueba
    "http://132.146.70.152",
    "https://prereclamos.mda.gob.ar",       # servidor de prueba
    "https://preavex.mda.gob.ar",           # frontend de preproducción
    "https://avex.mda.gob.ar",              # frontend de producción
    "http://132.146.70.152:3030",      # servidor de prueba con puerto dev
])

# Prefijo DER de DigestInfo para SHA-256 (RFC 8017, sección 9.2, nota 1).
# CKM_RSA_PKCS solo agrega el relleno PKCS#1 v1.5: el DigestInfo lo tiene
# que armar quien llama. Con este prefijo, la firma es la misma que
# "sha256WithRSAEncryption" sobre los datos originales, que es lo que
# verifica el backend de AVEX.
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
LARGO_SHA256 = 32


@app.after_request
def agregar_headers_private_network(response):
    """
    Chrome exige este header cuando una web servida desde otro origen intenta
    llamar a un recurso local/privado como http://localhost:47812.
    Igual la página web debe estar en un contexto seguro (HTTPS o localhost).
    """
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


def detectar_lib_path():
    """
    Detecta automáticamente la ruta del módulo PKCS#11 de SafeNet
    según el sistema operativo donde corre el agente. Así el mismo
    archivo funciona sin cambios en Windows y en Ubuntu.
    """
    sistema = platform.system()

    if sistema == "Windows":
        candidatos = [
            r"C:\Windows\System32\eTPKCS11.dll",
            r"C:\Windows\SysWOW64\eTPKCS11.dll",
        ]
    elif sistema == "Linux":
        candidatos = [
            "/usr/lib/libeTPkcs11.so",
            "/usr/lib/pkcs11/libeTPkcs11.so",
            # Fallback genérico: útil para otros tokens, pero SafeNet eToken
            # 5110 FIPS normalmente requiere el middleware oficial SAC.
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",  # fallback genérico
        ]
    elif sistema == "Darwin":
        candidatos = [
            "/usr/local/lib/libeTPkcs11.dylib",
            "/Library/Application Support/SafeNet/AuthenticationClient/libeTPkcs11.dylib",
        ]
    else:
        raise RuntimeError(f"Sistema operativo no soportado: {sistema}")

    for ruta in candidatos:
        if os.path.exists(ruta):
            return ruta

    raise FileNotFoundError(
        f"No se encontró el módulo PKCS#11 en ninguna ruta conocida para "
        f"{sistema}. Rutas probadas: {candidatos}"
    )


def obtener_lib_path():
    """Resuelve SafeNet al usarlo para permitir que el agente arranque sin SAC."""
    ruta = detectar_lib_path()
    logging.info("Módulo PKCS#11 detectado: %s", ruta)
    return ruta


# Compatibilidad entre versiones de python-pkcs11: algunas exponen la excepción
# base como pkcs11.PKCS11Error y otras debajo de pkcs11.exceptions.
PKCS11Error = getattr(
    pkcs11.exceptions,
    "PKCS11Error",
    getattr(pkcs11, "PKCS11Error", Exception),
)


def get_token_session():
    """Devuelve el primer token PKCS#11 presente, o None si no hay ninguno insertado."""
    # La ausencia del middleware se informa al consultar el token, sin impedir
    # que el servicio local arranque (por ejemplo, antes de instalar SafeNet).
    lib = pkcs11.lib(obtener_lib_path())
    slots = lib.get_slots(token_present=True)
    if not slots:
        return None
    return slots[0].get_token()


@app.route("/estado", methods=["GET"])
def estado():
    """Diagnóstico básico del agente y del middleware, sin solicitar el PIN."""
    try:
        lib_path = obtener_lib_path()
        middleware = True
        error = None
    except Exception as exc:
        lib_path = None
        middleware = False
        error = str(exc)

    return jsonify({
        "agente": "activo",
        "version": "1.0.1",
        "arquitectura": platform.architecture()[0],
        "middleware_safenet": middleware,
        "modulo_pkcs11": lib_path,
        "detalle": error,
    })


def get_common_name(cert):
    """Devuelve el Common Name del certificado, si existe."""
    valores = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return valores[0].value if valores else None


def extraer_cuil(subject):
    """Extrae el CUIL/CUIT del subject textual ('CUIL 20...' o 'CUIT 20...'),
    sin separadores. Solo para mostrar: la comparación la hace el backend."""
    match = re.search(r"CUI[LT]\s*([\d.-]+)", subject)
    return re.sub(r"\D", "", match.group(1)) or None if match else None


def fingerprint_sha256(cert):
    """Huella SHA-256 del certificado, formateada como la muestran los visores."""
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def cert_datetime(cert, attr_utc, attr_legacy):
    """
    cryptography nuevo expone *_utc; versiones anteriores solo exponen el
    atributo legacy sin timezone (en UTC). Devuelve siempre un datetime UTC.
    """
    value = getattr(cert, attr_utc, None)
    if value is None:
        value = getattr(cert, attr_legacy).replace(tzinfo=timezone.utc)
    return value


def cert_datetime_iso(cert, attr_utc, attr_legacy):
    return cert_datetime(cert, attr_utc, attr_legacy).isoformat()


def serializar_certificado(cert, cadena_pem=None):
    """Normaliza el certificado y lo entrega también en PEM para firma externa."""
    subject = cert.subject.rfc4514_string()
    return {
        "cuil": extraer_cuil(subject),
        "subject": subject,
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert_datetime_iso(cert, "not_valid_before_utc", "not_valid_before"),
        "not_valid_after": cert_datetime_iso(cert, "not_valid_after_utc", "not_valid_after"),
        "nombre": get_common_name(cert),
        "fingerprint_sha256": fingerprint_sha256(cert),
        "certificado_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "cadena_pem": cadena_pem or [],
    }


# -----------------------------------------------------------------------------
# Selección del certificado firmante y de su clave privada
# -----------------------------------------------------------------------------
# El token puede traer, además del certificado del firmante, los de las AC
# (y a veces certificados viejos). /certificado y /firmar tienen que elegir
# SIEMPRE el mismo certificado, y /firmar tiene que usar la clave privada de
# ese certificado (mismo CKA_ID). Si no, el backend recibe un certificado y
# una firma que no se corresponden y responde 422.

def leer_id(obj):
    """CKA_ID del objeto PKCS#11, o None si no lo expone."""
    try:
        valor = obj[pkcs11.Attribute.ID]
    except Exception:
        return None
    return bytes(valor) if valor else None


def es_certificado_de_ac(cert):
    """True si el certificado es de una autoridad certificante (BasicConstraints CA)."""
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def sirve_para_firmar(cert):
    """Uso de clave firma digital o no repudio (lo mismo que exige el backend)."""
    try:
        uso = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return uso.digital_signature or uso.content_commitment


def esta_vigente(cert):
    ahora = datetime.now(timezone.utc)
    desde = cert_datetime(cert, "not_valid_before_utc", "not_valid_before")
    hasta = cert_datetime(cert, "not_valid_after_utc", "not_valid_after")
    return desde <= ahora <= hasta


def leer_certificados(session):
    """Certificados del token como [(objeto PKCS#11, certificado)]. Saltea los ilegibles."""
    certificados = []
    for obj in session.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.CERTIFICATE}):
        try:
            der = bytes(obj[pkcs11.Attribute.VALUE])
            certificados.append((obj, x509.load_der_x509_certificate(der, default_backend())))
        except Exception:
            # Un objeto de certificado no interpretable no debe impedir
            # leer el certificado firmante.
            continue
    return certificados


def elegir_certificado_firmante(session):
    """
    Devuelve (objeto PKCS#11, certificado, cadena) del certificado con el que
    se firma, o (None, None, []) si el token no tiene certificados.

    Criterio, en orden: que no sea de una AC, que sirva para firmar, que esté
    vigente y que tenga una clave pública con el mismo CKA_ID en el token (la
    privada no se ve sin PIN). La cadena son los certificados de AC del token.
    """
    certificados = leer_certificados(session)
    if not certificados:
        return None, None, []

    candidatos = [par for par in certificados if not es_certificado_de_ac(par[1])] or certificados
    candidatos = [par for par in candidatos if sirve_para_firmar(par[1])] or candidatos
    candidatos = [par for par in candidatos if esta_vigente(par[1])] or candidatos

    ids_con_clave = {
        leer_id(obj)
        for obj in session.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PUBLIC_KEY})
    } - {None}
    candidatos = [par for par in candidatos if leer_id(par[0]) in ids_con_clave] or candidatos

    cert_obj, cert = candidatos[0]
    cadena = [c for _, c in certificados if es_certificado_de_ac(c) and c != cert]
    return cert_obj, cert, cadena


def buscar_clave_privada(session, cert_id):
    """
    Clave privada del certificado firmante (mismo CKA_ID). Requiere sesión
    con PIN. Si el certificado no expone ID y hay una sola clave, usa esa.
    """
    claves = list(session.get_objects({pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY}))
    if cert_id is not None:
        for clave in claves:
            if leer_id(clave) == cert_id:
                return clave
    return claves[0] if len(claves) == 1 else None


def texto_firma_visible():
    """
    Texto que pyHanko dibuja dentro del campo visible de firma.
    La firma criptográfica es independiente de esta apariencia, pero este
    texto ayuda a que el usuario vea la firma al abrir el PDF.
    """
    return "Firmante: %(signer)s\nFecha: %(ts)s"


def caja_firma_visible(cantidad_firmas_existentes):
    """
    Ubicación del sello visible.
    PDF usa coordenadas en puntos desde abajo a la izquierda. Para firma
    conjunta, alternamos izquierda/derecha para que la segunda firma quede
    al extremo derecho de la primera.
    """
    fila = cantidad_firmas_existentes // 2
    columna = cantidad_firmas_existentes % 2
    # Dejamos espacio suficiente para dos líneas de texto y el QR lateral.
    y_inferior = 60 + (fila * 90)
    y_superior = y_inferior + 82

    if columna == 0:
        return (50, y_inferior, 295, y_superior)
    return (317, y_inferior, 562, y_superior)


def subject_attr(cert, key):
    """Lee un atributo del subject de un certificado asn1crypto de pyHanko."""
    try:
        return cert.subject.native.get(key)
    except Exception:
        return None


def datetime_iso(value):
    """Serializa datetimes de pyHanko/asn1crypto para JSON."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def enum_nombre(value):
    """Convierte enums/objetos de estado de pyHanko a texto estable."""
    if value is None:
        return None
    return getattr(value, "name", str(value))


@app.route("/certificado", methods=["GET"])
def certificado():
    """
    Lee el certificado del firmante (no requiere PIN).
    Devuelve nombre, CUIL, subject, emisor, número de serie, vigencia,
    huella SHA-256, `certificado_pem` y `cadena_pem` (certificados de AC del
    token, vacía si no tiene). El frontend los manda a
    POST /api/v1/firmas/actuaciones/{id}/token/preparar para armar el CMS.
    """
    try:
        token = get_token_session()
        if not token:
            return jsonify({"error": "No se detectó token"}), 404

        with token.open() as session:
            _, cert, cadena = elegir_certificado_firmante(session)
            if cert is None:
                return jsonify({"error": "Token sin certificados"}), 404

            cadena_pem = [
                c.public_bytes(serialization.Encoding.PEM).decode("ascii") for c in cadena
            ]
            return jsonify(serializar_certificado(cert, cadena_pem))
    except PKCS11Error as error:
        return jsonify({"error": "Error PKCS#11 al leer el certificado", "detail": str(error)}), 500
    except Exception as error:
        return jsonify({"error": "Error inesperado al leer el certificado", "detail": str(error)}), 500


@app.route("/firmar", methods=["POST"])
def firmar():
    """
    Firma un digest ya calculado por el backend (no un documento completo).
    Espera JSON: { "digest": "<SHA-256 en base64, 32 bytes>", "pin": "<PIN>" }
    Devuelve: { "firma": "<base64>" }

    La firma es RSA PKCS#1 v1.5 sobre DigestInfo(SHA-256, digest), con
    CKM_RSA_PKCS: el hash no se vuelve a hashear. En AVEX, `digest` es el
    SHA-256 de los atributos firmados del CMS que armó /token/preparar, y el
    backend verifica la firma contra el certificado antes de insertarla.
    Errores: 400 digest/datos inválidos, 401 PIN incorrecto (el frontend
    vuelve a pedir el PIN con la misma preparación), 404 sin token/clave.
    """
    data = request.get_json(silent=True) or {}
    digest_b64 = data.get("digest")
    pin = data.get("pin")

    if not digest_b64 or not pin:
        return jsonify({"error": "faltan datos"}), 400

    try:
        digest = base64.b64decode(digest_b64, validate=True)
    except (binascii.Error, ValueError):
        return jsonify({"error": "digest inválido: debe venir en base64"}), 400

    if len(digest) != LARGO_SHA256:
        return jsonify({"error": "digest inválido: tiene que ser un SHA-256 (32 bytes)"}), 400

    try:
        token = get_token_session()
    except PKCS11Error as error:
        return jsonify({"error": "Error PKCS#11 al buscar el token", "detail": str(error)}), 500
    except Exception as error:
        return jsonify({"error": "Error inesperado al buscar el token", "detail": str(error)}), 500

    if not token:
        return jsonify({"error": "No se detectó token"}), 404

    try:
        with token.open(user_pin=pin) as session:
            cert_obj, cert, _ = elegir_certificado_firmante(session)
            if cert is None:
                return jsonify({"error": "Token sin certificados"}), 404
            if not isinstance(cert.public_key(), rsa.RSAPublicKey):
                return jsonify({"error": "El certificado del token no tiene una clave RSA"}), 422

            priv_key = buscar_clave_privada(session, leer_id(cert_obj))
            if priv_key is None:
                return jsonify({"error": "No se encontró la clave privada del certificado en el token"}), 404

            signature = priv_key.sign(DIGEST_INFO_SHA256 + digest, mechanism=Mechanism.RSA_PKCS)
    except pkcs11.exceptions.PinIncorrect:
        return jsonify({"error": "PIN incorrecto"}), 401
    except pkcs11.exceptions.PinLocked:
        return jsonify({"error": "El PIN del token está bloqueado"}), 403
    except PKCS11Error as error:
        return jsonify({"error": "Error PKCS#11 al firmar", "detail": str(error)}), 500
    except Exception as error:
        return jsonify({"error": "Error inesperado al firmar", "detail": str(error)}), 500

    # Control local: la firma tiene que verificar con el certificado que
    # devuelve /certificado. Si no, el backend la rechazaría con 422; así el
    # error queda claro del lado del agente.
    try:
        cert.public_key().verify(
            signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
        )
    except InvalidSignature:
        return jsonify({
            "error": "La firma del token no corresponde a su certificado",
            "detail": "La clave privada usada no es la del certificado firmante.",
        }), 500

    return jsonify({"firma": base64.b64encode(signature).decode()})


@app.route("/firmar-pdf", methods=["POST"])
def firmar_pdf():
    """
    Firma un PDF completo en formato PAdES usando pyHanko + PKCS#11.
    Espera multipart/form-data:
      - pdf: archivo PDF a firmar
      - pin: PIN del token
      - qr_url: URL pública de verificación que se incrusta en el QR
    Devuelve application/pdf con la firma embebida.

    Solo para la pantalla de prueba ("Probar firma PDF"). Las actuaciones de
    AVEX no usan esta ruta: el PDF no pasa por el navegador y el agente solo
    firma el digest (/firmar).
    """
    archivo = request.files.get("pdf")
    pin = request.form.get("pin")
    qr_url = request.form.get("qr_url", "").strip()

    if not archivo or not pin:
        return jsonify({"error": "faltan datos: pdf y pin son requeridos"}), 400
    if not archivo.filename.lower().endswith(".pdf"):
        return jsonify({"error": "el archivo debe ser PDF"}), 400

    try:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.pdf_utils.layout import AxisAlignment, InnerScaling, SimpleBoxLayoutRule
        from pyhanko import stamp
        from pyhanko.sign import signers
        from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
        from pyhanko.sign.pkcs11 import PKCS11Signer
        from asn1crypto import x509 as asn1_x509
    except ImportError:
        return jsonify({
            "error": "pyHanko no está instalado",
            "detail": "Instalá pyHanko en el entorno del agente: pip install 'pyHanko[pkcs11]'",
        }), 501

    try:
        token = get_token_session()
    except PKCS11Error as error:
        return jsonify({"error": "Error PKCS#11 al buscar el token", "detail": str(error)}), 500
    except Exception as error:
        return jsonify({"error": "Error inesperado al buscar el token", "detail": str(error)}), 500

    if not token:
        return jsonify({"error": "No se detectó token"}), 404

    try:
        pdf_bytes = archivo.read()
        if not pdf_bytes.startswith(b"%PDF-"):
            return jsonify({"error": "el archivo no parece ser un PDF válido"}), 400

        reader_previo = PdfFileReader(BytesIO(pdf_bytes))
        cantidad_firmas_existentes = len(reader_previo.embedded_signatures)

        with token.open(user_pin=pin) as session:
            cert_obj, cert, _ = elegir_certificado_firmante(session)
            if cert is None:
                return jsonify({"error": "Token sin certificados"}), 404

            cert_der = cert.public_bytes(serialization.Encoding.DER)
            nombre_certificado = get_common_name(cert)
            fecha_qr = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            datos_qr = qr_url or (
                f"Firmante: {nombre_certificado}\n"
                f"CUIL: {extraer_cuil(cert.subject.rfc4514_string()) or 'No informado'}\n"
                f"Fecha: {fecha_qr}\n"
                f"Huella SHA-256: {fingerprint_sha256(cert)}"
            )
            cert_id = leer_id(cert_obj)

            if cert_id is None:
                return jsonify({
                    "error": "No se pudo identificar el certificado del token",
                    "detail": "El certificado PKCS#11 no expone Attribute.ID para vincularlo con la clave privada.",
                }), 500

            signer = PKCS11Signer(
                pkcs11_session=session,
                signing_cert=asn1_x509.Certificate.load(cert_der),
                cert_id=cert_id,
                key_id=cert_id,
            )
            writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
            salida = BytesIO()
            nombre_campo_firma = "FirmaAVEX_" + datetime.now().strftime("%Y%m%d%H%M%S")
            pdf_signer = signers.PdfSigner(
                signature_meta=signers.PdfSignatureMetadata(
                    field_name=nombre_campo_firma,
                    md_algorithm="sha256",
                    subfilter=SigSeedSubFilter.PADES,
                    reason="Firma digital AVEX",
                    location="Ciudad Autónoma de Buenos Aires",
                    name=nombre_certificado,
                ),
                signer=signer,
                stamp_style=stamp.QRStampStyle(
                    stamp_text=texto_firma_visible(),
                    timestamp_format="%d/%m/%Y %H:%M:%S",
                    background_opacity=0.0,
                    border_width=1,
                    qr_position=stamp.QRPosition.RIGHT_OF_TEXT,
                    qr_inner_size=42,
                    # Evita que el contenido interno quede fuera del campo
                    # cuando el texto y el QR ocupan más ancho que la caja.
                    inner_content_layout=SimpleBoxLayoutRule(
                        x_align=AxisAlignment.ALIGN_MIN,
                        y_align=AxisAlignment.ALIGN_MID,
                        inner_content_scaling=InnerScaling.SHRINK_TO_FIT,
                    ),
                ),
                new_field_spec=SigFieldSpec(
                    sig_field_name=nombre_campo_firma,
                    on_page=0,
                    box=caja_firma_visible(cantidad_firmas_existentes),
                ),
            )
            pdf_signer.sign_pdf(
                writer,
                output=salida,
                appearance_text_params={"url": datos_qr},
            )
            salida.seek(0)
    except pkcs11.exceptions.PinIncorrect:
        return jsonify({"error": "PIN incorrecto"}), 401
    except PKCS11Error as error:
        return jsonify({"error": "Error PKCS#11 al firmar PDF", "detail": str(error)}), 500
    except Exception as error:
        return jsonify({"error": "Error inesperado al firmar PDF", "detail": str(error)}), 500

    nombre_salida = archivo.filename.rsplit(".", 1)[0] + "-firmado.pdf"
    return send_file(
        salida,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=nombre_salida,
    )


@app.route("/verificar-pdf", methods=["POST"])
def verificar_pdf():
    """
    Lee las firmas embebidas en un PDF y devuelve un resumen para mostrarlo
    en el sistema. No requiere PIN ni token: la verificación se hace sobre
    el documento recibido.
    """
    archivo = request.files.get("pdf")

    if not archivo:
        return jsonify({"error": "falta el archivo pdf"}), 400
    if not archivo.filename.lower().endswith(".pdf"):
        return jsonify({"error": "el archivo debe ser PDF"}), 400

    try:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
    except ImportError:
        return jsonify({
            "error": "pyHanko no está instalado",
            "detail": "Instalá pyHanko en el entorno del agente: pip install 'pyHanko[pkcs11]'",
        }), 501

    try:
        pdf_bytes = archivo.read()
        if not pdf_bytes.startswith(b"%PDF-"):
            return jsonify({"error": "el archivo no parece ser un PDF válido"}), 400

        reader = PdfFileReader(BytesIO(pdf_bytes))
        firmas = []

        for index, embedded_sig in enumerate(reader.embedded_signatures, start=1):
            cert = embedded_sig.signer_cert
            estado = None
            error_validacion = None

            try:
                # Sin una cadena de confianza configurada, pyHanko puede marcar
                # trusted=False aunque la firma esté íntegra. Igual exponemos
                # intact/valid para diferenciar integridad de confianza.
                estado = validate_pdf_signature(embedded_sig)
            except Exception as error:
                error_validacion = str(error)

            firmas.append({
                "numero": index,
                "campo": embedded_sig.field_name,
                "firmante": subject_attr(cert, "common_name"),
                "subject": cert.subject.human_friendly,
                "issuer": cert.issuer.human_friendly,
                "serial_number": str(cert.serial_number),
                "fecha_firma": datetime_iso(
                    getattr(estado, "signer_reported_dt", None)
                    or embedded_sig.self_reported_timestamp
                ),
                "algoritmo_digest": (
                    getattr(estado, "md_algorithm", None)
                    or embedded_sig.md_algorithm
                ),
                "mecanismo_firma": getattr(estado, "pkcs7_signature_mechanism", None),
                "integridad_valida": getattr(estado, "intact", None),
                "firma_valida": getattr(estado, "valid", None),
                "documento_completo": (
                    enum_nombre(getattr(estado, "coverage", None)) == "ENTIRE_FILE"
                ),
                "cobertura": enum_nombre(getattr(estado, "coverage", None)),
                "confiable": getattr(estado, "trusted", None),
                "resumen": estado.summary() if estado else None,
                "error_validacion": error_validacion,
            })

        return jsonify({
            "nombre_archivo": archivo.filename,
            "cantidad_firmas": len(firmas),
            "firmas": firmas,
        })
    except Exception as error:
        return jsonify({"error": "Error inesperado al verificar PDF", "detail": str(error)}), 500


if __name__ == "__main__":
    from waitress import serve

    logging.info(
        "Iniciando Agente Firma AVEX 1.0.1 en 127.0.0.1:47812; log=%s",
        LOG_PATH,
    )
    serve(app, host="127.0.0.1", port=47812, threads=4)


# =============================================================================
# INSTALACIÓN Y USO — UBUNTU / LINUX
# =============================================================================
#
# 1) Dependencias del sistema (una sola vez):
#    sudo apt update
#    sudo apt install -y opensc opensc-pkcs11 pcscd libpcsclite1 pcsc-tools
#    sudo systemctl enable --now pcscd
#
# 2) Middleware SafeNet Authentication Client (obligatorio para eToken 5110,
#    OpenSC genérico no lo reconoce):
#    - Descargar el .deb desde:
#      https://knowledge.digicert.com/general-information/how-to-download-safenet-authentication-client
#    - Si falta libssl1.1 (Ubuntu 22.04+):
#      wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
#      sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb
#    - Instalar el SAC:
#      sudo dpkg -i safenetauthenticationclient_10.X.X_amd64.deb
#      sudo apt --fix-broken install
#    - Confirmar que quedó instalado en /usr/lib/libeTPkcs11.so
#
# 3) Librerías Python:
#    pip install flask flask-cors python-pkcs11 cryptography qrcode 'pyHanko[pkcs11]' --break-system-packages
#
# 4) Correr el agente:
#    python3 agente_firma.py
#    (queda escuchando en http://127.0.0.1:47812)
#
# 5) Probar sin depender del navegador:
#    curl http://localhost:47812/certificado
#    # digest de prueba (SHA-256 de "prueba", en base64):
#    python3 -c "import hashlib,base64;print(base64.b64encode(hashlib.sha256(b'prueba').digest()).decode())"
#    curl -X POST http://localhost:47812/firmar \
#      -H "Content-Type: application/json" \
#      -d '{"digest": "<hash en base64>", "pin": "<PIN>"}'
#    curl -X POST http://localhost:47812/firmar-pdf \
#      -F "pdf=@documento.pdf" \
#      -F "pin=<PIN>" \
#      --output documento-firmado.pdf
#
#
# =============================================================================
# INSTALACIÓN Y USO — WINDOWS
# =============================================================================
#
# 1) Python instalado, con "Add python.exe to PATH" tildado en el instalador.
#    Confirmar con: python --version
#
# 2) Middleware SafeNet Authentication Client para Windows:
#    - Descargar el paquete SAC (misma fuente que en Linux, versión Windows).
#    - Ejecutar el .msi correspondiente a la arquitectura (usar x64 salvo
#      que la máquina sea de 32 bits o ARM):
#      msiexec /i "...\Msi\x64\SafeNetAuthenticationClient-x64-10.X-R1....msi"
#    - Confirmar instalación abriendo "SafeNet Authentication Client Tools"
#      desde el menú Inicio, con el token insertado.
#    - El DLL queda típicamente en:
#      C:\Windows\System32\eTPKCS11.dll   (64 bits)
#      C:\Windows\SysWOW64\eTPKCS11.dll   (32 bits)
#
# 3) Librerías Python:
#    pip install flask flask-cors python-pkcs11 cryptography qrcode "pyHanko[pkcs11]"
#
# 4) Correr el agente:
#    python agente_firma.py
#    (queda escuchando en http://127.0.0.1:47812)
#
# 5) Probar sin depender del navegador (cmd.exe, comillas escapadas con \"):
#    curl http://localhost:47812/certificado
#    python -c "import hashlib,base64;print(base64.b64encode(hashlib.sha256(b'prueba').digest()).decode())"
#    curl -X POST http://localhost:47812/firmar -H "Content-Type: application/json" -d "{\"digest\": \"<hash en base64>\", \"pin\": \"<PIN>\"}"
#    curl -X POST http://localhost:47812/firmar-pdf -F "pdf=@documento.pdf" -F "pin=<PIN>" --output documento-firmado.pdf
#
#
# =============================================================================
# INTEGRACIÓN CON AVEX (firma de actuaciones con token)
# =============================================================================
#
# Contrato: avex-sistema-de-expedientes/documentacion/INTEGRACION-FIRMA-TOKEN-FRONTEND.md
#
# El agente corre SIEMPRE en localhost, en la máquina de cada usuario —
# nunca en el servidor. El navegador es el único puente entre la página web
# y el agente, porque el backend no tiene acceso al token USB. El PDF nunca
# pasa por el navegador ni por el agente: el backend arma la revisión
# incremental y el agente solo firma un hash.
#
#   1. Frontend (FirmarActuacionModal) → GET /certificado del agente:
#      datos del certificado + certificado_pem + cadena_pem.
#
#   2. Frontend → backend POST /api/v1/firmas/actuaciones/{id}/token/preparar
#      { sello_id, clave_mesa, certificado_pem, cadena_pem }.
#      El backend valida el certificado (vigencia, uso de clave, RSA), arma la
#      revisión incremental del PDF con el campo de firma y devuelve
#      { preparacion_id, digest, vence_en } (10 minutos).
#
#   3. Frontend pide el PIN → POST /firmar del agente { digest, pin }.
#      El agente firma DigestInfo(SHA-256, digest) con CKM_RSA_PKCS y
#      devuelve { firma }. Con PIN incorrecto (401) el frontend vuelve a
#      pedirlo con la misma preparación.
#
#   4. Frontend → backend PUT /api/v1/firmas/actuaciones/{id}/firmar-token
#      { preparacion_id, firma }. El backend verifica la firma contra el
#      certificado, inserta el CMS en el PDF, lo valida y avanza el circuito.
#
# La comparación del CUIL/CUIT del certificado con el usuario la hace el
# backend en /token/preparar, con el CUIT de sus datos del Portal
# (public.citizen.cuit) y leyendo el certificado (subject + SAN), no el campo
# `cuil` que devuelve este agente, que es solo para mostrar.
#
# Notas de seguridad:
#   - El PIN nunca pasa por el backend ni queda logueado en ningún lado;
#     viaja únicamente entre el navegador y el agente, en la misma máquina.
#   - Restringir el CORS del agente al dominio real de producción antes de
#     salir a producción (ver el array "origins" al inicio del archivo).
#   - Considerar servir el agente sobre HTTPS local (certificado autofirmado)
#     en una segunda etapa, en vez de HTTP plano.
