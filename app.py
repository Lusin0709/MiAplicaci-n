from flask import Flask, render_template, request, jsonify, session # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
from supabase import create_client # type: ignore
from dotenv import load_dotenv # type: ignore
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
import smtplib
import secrets
import os
import time


# Cargar las variables del archivo .env
CARPETA_PROYECTO = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(CARPETA_PROYECTO, ".env"))

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Faltan las credenciales de Supabase.")

if not FLASK_SECRET_KEY:
    raise RuntimeError("Falta FLASK_SECRET_KEY en el archivo .env.")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)

# Registros pendientes de verificación
registros_pendientes = {}
cambios_correo_pendientes = {}
recuperaciones_pendientes = {}
cambios_contrasena_pendientes = {}
eliminaciones_pendientes = {}
def limpiar_registros_pendientes():
    ahora = time.time()

    vencidos = [
        identificador
        for identificador, datos in registros_pendientes.items()
        if datos["expira_en"] < ahora
    ]

    for identificador in vencidos:
        del registros_pendientes[identificador]
app.secret_key = FLASK_SECRET_KEY


# -----------------------------------------
# FUNCIONES AUXILIARES
# -----------------------------------------

def generar_codigo():
    return str(secrets.randbelow(900000) + 100000)


def enviar_codigo(correo, codigo, asunto="Verificación de correo electrónico",
                  motivo="Recibimos una solicitud de verificación."):

    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise RuntimeError("Faltan las credenciales de Gmail.")

    mensaje = EmailMessage()
    mensaje["Subject"] = asunto
    mensaje["From"] = GMAIL_USER
    mensaje["To"] = correo

    mensaje.set_content(
        f"""
Hola:

{motivo}

Tu código de verificación es: {codigo}

Este código vence en 10 minutos.

Si no solicitaste esta operación, podés ignorar este correo.

Saludos.
"""
    )

    with smtplib.SMTP_SSL(
        "smtp.gmail.com", 465, timeout=20
    ) as servidor:
        servidor.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        servidor.send_message(mensaje)


def convertir_fecha(fecha):
    if not fecha:
        return None

    if isinstance(fecha, datetime):
        resultado = fecha
    else:
        resultado = datetime.fromisoformat(
            fecha.replace("Z", "+00:00")
        )

    if resultado.tzinfo is None:
        resultado = resultado.replace(tzinfo=timezone.utc)

    return resultado


# -----------------------------------------
# PÁGINAS
# -----------------------------------------

@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/prueba")
def prueba():
    return "¡El servidor funciona correctamente!"


# -----------------------------------------
# REGISTRO
# -----------------------------------------

@app.route("/api/registro", methods=["POST"])
def registro():
    datos = request.get_json(silent=True) or {}

    cedula = str(datos.get("cedula", "")).strip()
    correo = str(datos.get("correo", "")).strip().lower()
    password = datos.get("password", "")

    if not cedula or not correo or not isinstance(password, str) or not password:
        return jsonify({
            "exito": False,
            "mensaje": "Completá todos los campos."
        }), 400

    if len(password) < 8 or len(password) > 128:
        return jsonify({
            "exito": False,
            "mensaje": "La contraseña debe tener entre 8 y 128 caracteres."
        }), 400

    try:
        limpiar_registros_pendientes()

        # Comprobar si el correo ya está registrado
        respuesta_correo = supabase.table("usuarios").select(
            "id"
        ).eq("correo", correo).limit(1).execute()

        if respuesta_correo.data:
            return jsonify({
                "exito": False,
                "mensaje": "Ese correo ya está registrado."
            }), 409

        # Comprobar si la cédula ya está registrada
        respuesta_cedula = supabase.table("usuarios").select(
            "id"
        ).eq("cedula", cedula).limit(1).execute()

        if respuesta_cedula.data:
            return jsonify({
                "exito": False,
                "mensaje": "Esa cédula ya está registrada."
            }), 409

        # Generar código y guardar los datos temporalmente
        ahora = time.time()
        codigo = generar_codigo()

        registros_pendientes[correo] = {
            "cedula": cedula,
            "correo": correo,
            "password_hash": generate_password_hash(password),
            "codigo_hash": generate_password_hash(codigo),
            "codigo_expira_en": ahora + 600,
            "expira_en": ahora + 1800,
            "ultimo_envio": ahora,
            "intentos": 0
        }

        # Enviar código al correo
        try:
            enviar_codigo(correo, codigo)

        except Exception as error:
            registros_pendientes.pop(correo, None)

            print("ERROR AL ENVIAR CÓDIGO:", type(error).__name__)
            print("Mensaje:", str(error))

            return jsonify({
                "exito": False,
                "mensaje": "No se pudo enviar el código. Intentá nuevamente."
            }), 502

        print("CÓDIGO DE REGISTRO ENVIADO.")

        return jsonify({
            "exito": True,
            "correo": correo
        })

    except Exception as error:
        print("ERROR EN REGISTRO:", type(error).__name__)
        print("Mensaje:", str(error))

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo iniciar el registro. Intentá nuevamente."
        }), 500


# -----------------------------------------
# VERIFICAR CORREO
# -----------------------------------------

@app.route("/api/verificar-correo", methods=["POST"])
def verificar_correo():
    datos = request.get_json(silent=True) or {}

    correo = str(datos.get("correo", "")).strip().lower()
    codigo = str(datos.get("codigo", "")).strip()

    if not correo or len(codigo) != 6 or not codigo.isdigit():
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá un código válido de seis dígitos."
        }), 400

    try:
        limpiar_registros_pendientes()

        pendiente = registros_pendientes.get(correo)


        if not pendiente:
            return jsonify({
                "exito": False,
                "mensaje": "No encontramos un registro pendiente. Comenzá nuevamente."
            }), 404

        if pendiente["intentos"] >= 5:
            return jsonify({
                "exito": False,
                "mensaje": "Superaste el límite de intentos. Solicitá un nuevo código."
            }), 429

        if time.time() > pendiente["codigo_expira_en"]:
            return jsonify({
                "exito": False,
                "mensaje": "El código venció. Solicitá uno nuevo."
            }), 400

        if not check_password_hash(pendiente["codigo_hash"], codigo):
            pendiente["intentos"] += 1

            return jsonify({
                "exito": False,
                "mensaje": "El código es incorrecto."
            }), 400

        # Código correcto: recién ahora crear el usuario en Supabase
        respuesta = supabase.table("usuarios").insert({
            "cedula": pendiente["cedula"],
            "correo": pendiente["correo"],
            "password_hash": pendiente["password_hash"],
            "email_verificado": True
        }).execute()

        if not respuesta.data:
            raise RuntimeError("No se pudo obtener el usuario creado.")

        usuario = respuesta.data[0]

        # Eliminar los datos temporales
        registros_pendientes.pop(correo, None)

        # Iniciar sesión automáticamente
        session.clear()
        session.clear()
        session.clear()
        session["usuario_id"] = usuario["id"]
        print("USUARIO REGISTRADO Y CORREO VERIFICADO.")

        return jsonify({
            "exito": True,
            "usuario": {
                "cedula": usuario["cedula"],
                "correo": usuario["correo"]
            }
        })

    except Exception as error:
        print("ERROR AL VERIFICAR CORREO:", type(error).__name__)
        print("Mensaje:", str(error))

        if getattr(error, "code", None) == "23505":
            registros_pendientes.pop(correo, None)

            return jsonify({
                "exito": False,
                "mensaje": "La cédula o el correo ya están registrados."
            }), 409

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo verificar el código. Intentá nuevamente."
        }), 500


# -----------------------------------------
# REENVIAR CÓDIGO
# -----------------------------------------

@app.route("/api/reenviar-codigo", methods=["POST"])
def reenviar_codigo():
    datos = request.get_json(silent=True) or {}

    correo = str(datos.get("correo", "")).strip().lower()

    if not correo:
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá tu correo electrónico."
        }), 400

    try:
        limpiar_registros_pendientes()

        pendiente = registros_pendientes.get(correo)

        if not pendiente:
            return jsonify({
                "exito": False,
                "mensaje": "No encontramos un registro pendiente. Comenzá nuevamente."
            }), 404

        ahora = time.time()
        segundos_transcurridos = ahora - pendiente["ultimo_envio"]

        if segundos_transcurridos < 120:
            return jsonify({
                "exito": False,
            }), 429

        codigo = generar_codigo()

        # Enviar el nuevo código
        try:
            enviar_codigo(correo, codigo)

        except Exception as error:
            print("ERROR AL REENVIAR CÓDIGO:", type(error).__name__)
            print("Mensaje:", str(error))

            return jsonify({
                "exito": False,
                "mensaje": "No se pudo enviar el correo. Intentá nuevamente."
            }), 502

        # Actualizar el código temporal después de enviarlo
        pendiente["codigo_hash"] = generate_password_hash(codigo)
        pendiente["codigo_expira_en"] = ahora + 600
        pendiente["ultimo_envio"] = ahora
        pendiente["intentos"] = 0

        return jsonify({
            "exito": True
        })

    except Exception as error:
        print("ERROR AL REENVIAR CÓDIGO:", type(error).__name__)
        print("Mensaje:", str(error))

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo reenviar el código. Intentá nuevamente."
        }), 500
# -----------------------------------------
# SOLICITAR CAMBIO DE CORREO
# -----------------------------------------

@app.route("/api/solicitar-cambio-correo", methods=["POST"])
def solicitar_cambio_correo():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión."
        }), 401

    try:
        respuesta = supabase.table("usuarios").select(
            "correo"
        ).eq("id", usuario_id).limit(1).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No encontramos tu cuenta."
            }), 404

        correo_actual = respuesta.data[0]["correo"]

        ahora = time.time()
        pendiente = cambios_correo_pendientes.get(usuario_id)

        if pendiente and ahora - pendiente["ultimo_envio"] < 120:
            return jsonify({
                "exito": False,
            }), 429

        codigo = generar_codigo()

        enviar_codigo(
            correo_actual,
            codigo,
            asunto="Código para cambiar tu correo",
            motivo="Recibimos una solicitud para cambiar el correo de tu cuenta."
        )

        cambios_correo_pendientes[usuario_id] = {
            "correo_actual": correo_actual,
            "codigo_hash": generate_password_hash(codigo),
            "codigo_expira_en": ahora + 600,
            "ultimo_envio": ahora,
            "intentos": 0
        }

        return jsonify({
            "exito": True,
            "mensaje": "Enviamos un código a tu correo actual."
        })

    except Exception as error:
        print("ERROR AL SOLICITAR CAMBIO DE CORREO:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo enviar el código."
        }), 500
    
# -----------------------------------------
# REENVIAR CÓDIGO DE CAMBIO DE CORREO
# -----------------------------------------

@app.route("/api/reenviar-cambio-correo", methods=["POST"])
def reenviar_cambio_correo():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión."
        }), 401

    try:
        pendiente = cambios_correo_pendientes.get(usuario_id)

        if not pendiente:
            return jsonify({
                "exito": False,
                "mensaje": "No hay ningún cambio de correo pendiente."
            }), 404

        ahora = time.time()

        if ahora - pendiente["ultimo_envio"] < 120:
            return jsonify({
                "exito": False,
            }), 429

        codigo = generar_codigo()

        enviar_codigo(
            pendiente["correo_actual"],
            codigo,
            asunto="Código para cambiar tu correo",
            motivo="Recibimos una solicitud para cambiar el correo de tu cuenta."
        )

        pendiente["codigo_hash"] = generate_password_hash(codigo)
        pendiente["codigo_expira_en"] = ahora + 600
        pendiente["ultimo_envio"] = ahora
        pendiente["intentos"] = 0

        return jsonify({
            "exito": True,
            "mensaje": "Enviamos un nuevo código a tu correo actual."
        })

    except Exception as error:
        print("ERROR AL REENVIAR CÓDIGO DE CAMBIO:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo reenviar el código."
        }), 500

    # -----------------------------------------
# VERIFICAR CAMBIO DE CORREO
# -----------------------------------------

@app.route("/api/verificar-cambio-correo", methods=["POST"])
def verificar_cambio_correo():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión."
        }), 401

    datos = request.get_json(silent=True) or {}
    nuevo_correo = str(datos.get("nuevo_correo", "")).strip().lower()
    codigo = str(datos.get("codigo", "")).strip()

    if not nuevo_correo or len(codigo) != 6 or not codigo.isdigit():
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá un correo y un código válido de seis dígitos."
        }), 400

    try:
        pendiente = cambios_correo_pendientes.get(usuario_id)

        if not pendiente:
            return jsonify({
                "exito": False,
                "mensaje": "No hay ningún cambio de correo pendiente."
            }), 404

        ahora = time.time()

        if pendiente["intentos"] >= 5:
            cambios_correo_pendientes.pop(usuario_id, None)
            return jsonify({
                "exito": False,
                "mensaje": "Superaste el límite de intentos. Solicitá un nuevo código."
            }), 429

        if ahora > pendiente["codigo_expira_en"]:
            cambios_correo_pendientes.pop(usuario_id, None)
            return jsonify({
                "exito": False,
                "mensaje": "El código venció. Solicitá uno nuevo."
            }), 400

        if not check_password_hash(pendiente["codigo_hash"], codigo):
            pendiente["intentos"] += 1
            return jsonify({
                "exito": False,
                "mensaje": "El código es incorrecto."
            }), 400

        # Comprobar que el nuevo correo no esté registrado
        respuesta = supabase.table("usuarios").select(
            "id"
        ).eq("correo", nuevo_correo).limit(1).execute()

        if respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "Ese correo ya está registrado."
            }), 409

        # Actualizar el correo del usuario
        respuesta = supabase.table("usuarios").update({
            "correo": nuevo_correo
        }).eq("id", usuario_id).eq(
            "correo", pendiente["correo_actual"]
        ).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No se pudo actualizar el correo."
            }), 409

        cambios_correo_pendientes.pop(usuario_id, None)

        return jsonify({
            "exito": True,
            "correo": nuevo_correo,
            "mensaje": "Tu correo se actualizó correctamente."
        })

    except Exception as error:
        print("ERROR AL VERIFICAR CAMBIO DE CORREO:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo actualizar el correo. Intentá nuevamente."
        }), 500
    
# -----------------------------------------
# ACTUALIZAR DATOS DEL PERFIL
# -----------------------------------------

@app.route("/api/actualizar-perfil", methods=["POST"])
def actualizar_perfil():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión."
        }), 401

    datos = request.get_json(silent=True) or {}

    telefono = str(datos.get("telefono", "")).strip()
    fecha_nacimiento = str(datos.get("fecha_nacimiento", "")).strip()

    if not telefono or not fecha_nacimiento:
        return jsonify({
            "exito": False,
            "mensaje": "Completá el teléfono y la fecha de nacimiento."
        }), 400

    # Validar formato de fecha
    try:
        fecha = datetime.strptime(fecha_nacimiento, "%Y-%m-%d").date()

        if fecha > datetime.now().date() or fecha.year < 1900:
            raise ValueError()

    except ValueError:
        return jsonify({
            "exito": False,
            "mensaje": "La fecha de nacimiento no es válida."
        }), 400

    try:
        # Obtener los datos actuales del usuario
        respuesta = supabase.table("usuarios").select(
            "cedula, fecha_nacimiento"
        ).eq("id", usuario_id).limit(1).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No encontramos tu cuenta."
            }), 404

        usuario = respuesta.data[0]
        fecha_guardada = usuario["fecha_nacimiento"]

        # Impedir cambiar una fecha que ya fue guardada
        if fecha_guardada is not None:
            fecha_guardada = str(fecha_guardada)[:10]

            if fecha_guardada != fecha_nacimiento:
                return jsonify({
                    "exito": False,
                    "mensaje": "La fecha de nacimiento no se puede modificar."
                }), 403

        # Preparar los datos que se actualizarán
        actualizacion = {
            "telefono": telefono
        }

        # Guardar la fecha solamente si todavía no existe
        if fecha_guardada is None:
            actualizacion["fecha_nacimiento"] = fecha_nacimiento

        respuesta = supabase.table("usuarios").update(
            actualizacion
        ).eq("id", usuario_id).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No se pudieron guardar los datos."
            }), 500

        return jsonify({
            "exito": True,
            "mensaje": "Los datos se guardaron correctamente."
        })

    except Exception as error:
        print("ERROR AL ACTUALIZAR PERFIL:", type(error).__name__)
        print("Mensaje:", str(error))

        return jsonify({
            "exito": False,
            "mensaje": "No se pudieron actualizar los datos."
        }), 500
# -----------------------------------------
# ENTRAR COMO INVITADO
# -----------------------------------------

@app.route("/api/invitado", methods=["POST"])
def entrar_como_invitado():
    # Limpiar cualquier sesión anterior
    session.clear()

    # Crear una sesión de invitado
    session["modo_invitado"] = True

    return jsonify({
        "exito": True,
        "modo_invitado": True,
        "mensaje": "Entraste como invitado."
    })
# -----------------------------------------
# INICIAR SESIÓN
# -----------------------------------------

@app.route("/api/login", methods=["POST"])
def login():
    datos = request.get_json(silent=True) or {}

    correo = str(datos.get("correo", "")).strip().lower()
    password = datos.get("password", "")

    if not correo or not isinstance(password, str):
        return jsonify({
            "exito": False,
            "mensaje": "Completá el correo y la contraseña."
        }), 400

    try:

        respuesta = supabase.table("usuarios").select(
    "id, cedula, correo, password_hash, email_verificado, telefono, fecha_nacimiento"
).eq("correo", correo).limit(1).execute()

        usuarios = respuesta.data

        if usuarios and check_password_hash(
            usuarios[0]["password_hash"], password
        ):
            usuario = usuarios[0]

            if not usuario["email_verificado"]:
                return jsonify({
                    "exito": False,
                    "mensaje": "Primero tenés que verificar tu correo electrónico."
                }), 403

            session["usuario_id"] = usuario["id"]

            return jsonify({
                "exito": True,
                "mensaje": "Inicio de sesión correcto.",
                "usuario": {
                "cedula": usuario["cedula"],
                "correo": usuario["correo"],
                "telefono": usuario["telefono"],
                "fecha_nacimiento": usuario["fecha_nacimiento"]
}
            })

        return jsonify({
            "exito": False,
            "mensaje": "Correo o contraseña incorrectos."
        }), 401

    except Exception as error:
        print("Error al iniciar sesión:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo iniciar sesión. Intentá nuevamente."
        }), 500
    # CAMBIAR CONTRASEÑA DESDE LA CONFIGURACIÓN

@app.route("/api/cambiar-contrasena", methods=["POST"])
def cambiar_contrasena():

    # Comprobar que haya una sesión iniciada
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tu sesión venció. Iniciá sesión nuevamente."
        }), 401

    datos = request.get_json(silent=True) or {}

    password_actual = datos.get("password_actual", "")
    password_nueva = datos.get("password_nueva", "")

    if not isinstance(password_actual, str) or not isinstance(password_nueva, str):
        return jsonify({
            "exito": False,
            "mensaje": "Los datos ingresados no son válidos."
        }), 400

    if not password_actual or not password_nueva:
        return jsonify({
            "exito": False,
            "mensaje": "Completá todos los campos."
        }), 400

    # Validar los requisitos de seguridad de la contraseña nueva
    requisitos_validos = (
        8 <= len(password_nueva) <= 128
        and any(c.isupper() for c in password_nueva)
        and any(c.islower() for c in password_nueva)
        and any(c.isdigit() for c in password_nueva)
        and any(not c.isalnum() for c in password_nueva)
    )

    if not requisitos_validos:
        return jsonify({
            "exito": False,
            "mensaje": "La nueva contraseña no cumple los requisitos de seguridad."
        }), 400

    try:
        # Buscar la cuenta correspondiente a la sesión iniciada
        respuesta = supabase.table("usuarios").select(
            "id, password_hash"
        ).eq("id", usuario_id).limit(1).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No se encontró tu cuenta."
            }), 404

        usuario = respuesta.data[0]

        # Comprobar la contraseña actual
        if not check_password_hash(
            usuario["password_hash"], password_actual
        ):
            return jsonify({
                "exito": False,
                "mensaje": "La contraseña actual es incorrecta."
            }), 401

        # Evitar que se establezca la misma contraseña
        if check_password_hash(
            usuario["password_hash"], password_nueva
        ):
            return jsonify({
                "exito": False,
                "mensaje": "La nueva contraseña debe ser diferente de la actual."
            }), 400

        # Guardar la nueva contraseña como hash
        nuevo_hash = generate_password_hash(password_nueva)

        actualizacion = supabase.table("usuarios").update({
            "password_hash": nuevo_hash
        }).eq("id", usuario_id).execute()

        if not actualizacion.data:
            raise RuntimeError("No se pudo actualizar la contraseña.")

        return jsonify({
            "exito": True,
            "mensaje": "La contraseña se cambió correctamente."
        })

    except Exception as error:
        print("ERROR AL CAMBIAR CONTRASEÑA:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo cambiar la contraseña. Intentá nuevamente."
        }), 500
# SOLICITAR RECUPERACIÓN DE CONTRASEÑA

@app.route("/api/solicitar-recuperacion", methods=["POST"])
def solicitar_recuperacion():

    datos = request.get_json(silent=True) or {}
    correo = str(datos.get("correo", "")).strip().lower()

    if not correo:
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá tu correo electrónico."
        }), 400

    try:
        ahora = time.time()

        # Buscar el usuario por correo
        respuesta = supabase.table("usuarios").select(
            "id, correo"
        ).eq("correo", correo).limit(1).execute()

        # Mensaje genérico para no revelar si existe una cuenta
        mensaje = (
            "Si existe una cuenta asociada a ese correo, "
            "recibirás un código de recuperación."
        )

        if not respuesta.data:
            return jsonify({
                "exito": True,
                "mensaje": mensaje
            })

        usuario = respuesta.data[0]

        pendiente = recuperaciones_pendientes.get(correo)

        # Evitar reenvíos demasiado frecuentes
        if pendiente and ahora - pendiente["ultimo_envio"] < 120:
            return jsonify({
                "exito": False,
                "mensaje": "No se pudo solicitar otro código en este momento."
            }), 429

        codigo = generar_codigo()

        recuperaciones_pendientes[correo] = {
            "usuario_id": usuario["id"],
            "codigo_hash": generate_password_hash(codigo),
            "codigo_expira_en": ahora + 600,
            "ultimo_envio": ahora,
            "intentos": 0
        }

        # Enviar el código al correo
        try:
            enviar_codigo(
                correo,
                codigo,
                asunto="Recuperación de contraseña",
                motivo="Recibimos una solicitud para recuperar tu contraseña."
            )

        except Exception as error:
            recuperaciones_pendientes.pop(correo, None)

            print("ERROR AL ENVIAR CÓDIGO DE RECUPERACIÓN:", type(error).__name__)

            return jsonify({
                "exito": False,
                "mensaje": "No se pudo enviar el código. Intentá nuevamente."
            }), 502

        print("CÓDIGO DE RECUPERACIÓN ENVIADO.")

        return jsonify({
            "exito": True,
            "mensaje": mensaje
        })

    except Exception as error:
        print("ERROR EN RECUPERACIÓN:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo solicitar la recuperación."
        }), 500
    # VERIFICAR CÓDIGO DE RECUPERACIÓN

@app.route("/api/verificar-codigo-recuperacion", methods=["POST"])
def verificar_codigo_recuperacion():

    datos = request.get_json(silent=True) or {}

    correo = str(datos.get("correo", "")).strip().lower()
    codigo = str(datos.get("codigo", "")).strip()

    if not correo or len(codigo) != 6 or not codigo.isdigit():
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá un código válido de seis dígitos."
        }), 400

    try:
        pendiente = recuperaciones_pendientes.get(correo)

        if not pendiente:
            return jsonify({
                "exito": False,
                "mensaje": "El código no es válido o venció."
            }), 400

        if pendiente["intentos"] >= 5:
            recuperaciones_pendientes.pop(correo, None)

            return jsonify({
                "exito": False,
                "mensaje": "Superaste el límite de intentos. Solicitá un nuevo código."
            }), 429

        if time.time() > pendiente["codigo_expira_en"]:
            recuperaciones_pendientes.pop(correo, None)

            return jsonify({
                "exito": False,
                "mensaje": "El código venció. Solicitá uno nuevo."
            }), 400

        if not check_password_hash(pendiente["codigo_hash"], codigo):
            pendiente["intentos"] += 1

            return jsonify({
                "exito": False,
                "mensaje": "El código es incorrecto."
            }), 400

        # Autorizar el cambio de contraseña en esta sesión
        session["recuperacion_usuario_id"] = pendiente["usuario_id"]
        session["recuperacion_expira_en"] = time.time() + 600

        # El código ya fue utilizado
        recuperaciones_pendientes.pop(correo, None)

        return jsonify({
            "exito": True,
            "mensaje": "Código verificado correctamente."
        })

    except Exception as error:
        print("ERROR AL VERIFICAR CÓDIGO DE RECUPERACIÓN:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo verificar el código."
        }), 500
    # RESTABLECER CONTRASEÑA

@app.route("/api/restablecer-contrasena", methods=["POST"])
def restablecer_contrasena():

    usuario_id = session.get("recuperacion_usuario_id")
    expiracion = session.get("recuperacion_expira_en")

    if not usuario_id or not expiracion or time.time() > expiracion:
        session.pop("recuperacion_usuario_id", None)
        session.pop("recuperacion_expira_en", None)

        return jsonify({
            "exito": False,
            "mensaje": "La autorización venció. Solicitá un nuevo código."
        }), 401

    datos = request.get_json(silent=True) or {}
    password = datos.get("password", "")

    if not isinstance(password, str):
        return jsonify({
            "exito": False,
            "mensaje": "La contraseña no es válida."
        }), 400

    # Validar los requisitos de seguridad también en el servidor
    requisitos_validos = (
        8 <= len(password) <= 128
        and any(c.isupper() for c in password)
        and any(c.islower() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )

    if not requisitos_validos:
        return jsonify({
            "exito": False,
            "mensaje": "La contraseña no cumple los requisitos de seguridad."
        }), 400

    try:
        nuevo_hash = generate_password_hash(password)

        respuesta = supabase.table("usuarios").update({
            "password_hash": nuevo_hash
        }).eq("id", usuario_id).execute()

        if not respuesta.data:
            raise RuntimeError("No se pudo actualizar la contraseña.")

        # La autorización se utiliza una sola vez
        session.pop("recuperacion_usuario_id", None)
        session.pop("recuperacion_expira_en", None)

        print("CONTRASEÑA ACTUALIZADA CORRECTAMENTE.")

        return jsonify({
            "exito": True,
            "mensaje": "La contraseña se actualizó correctamente."
        })

    except Exception as error:
        print("ERROR AL RESTABLECER CONTRASEÑA:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo actualizar la contraseña. Intentá nuevamente."
        }), 500
@app.route("/api/solicitar-codigo-cambio", methods=["POST"])
def solicitar_codigo_cambio():

    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tu sesión venció. Iniciá sesión nuevamente."
        }), 401

    try:
        respuesta = supabase.table("usuarios").select(
            "id, correo, email_verificado"
        ).eq("id", usuario_id).limit(1).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No se encontró tu cuenta."
            }), 404

        usuario = respuesta.data[0]
        correo = usuario["correo"]

        if not usuario["email_verificado"]:
            return jsonify({
                "exito": False,
                "mensaje": "Primero tenés que verificar tu correo electrónico."
            }), 403

        ahora = time.time()
        pendiente = cambios_contrasena_pendientes.get(usuario_id)

        if pendiente and ahora - pendiente["ultimo_envio"] < 120:
            return jsonify({
                "exito": False,
                "mensaje": "Esperá un momento antes de solicitar otro código."
            }), 429

        codigo = f"{secrets.randbelow(1000000):06d}"

        enviar_codigo(
            correo,
            codigo,
            "Código para cambiar tu contraseña",
            "cambio_contrasena"
        )

        cambios_contrasena_pendientes[usuario_id] = {
            "codigo_hash": generate_password_hash(codigo),
            "expira": ahora + 600,
            "ultimo_envio": ahora,
            "intentos": 0
        }

        return jsonify({
            "exito": True,
            "mensaje": "Enviamos un código al correo asociado a tu cuenta."
        })

    except Exception as error:
        print("Error al enviar código para cambio de contraseña:",
              type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo enviar el código. Intentá nuevamente."
        }), 500

@app.route("/api/verificar-codigo-cambio", methods=["POST"])
def verificar_codigo_cambio():

    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tu sesión venció. Iniciá sesión nuevamente."
        }), 401

    datos = request.get_json(silent=True) or {}
    codigo = str(datos.get("codigo", "")).strip()

    if not codigo or len(codigo) != 6 or not codigo.isdigit():
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá un código válido de seis dígitos."
        }), 400

    pendiente = cambios_contrasena_pendientes.get(usuario_id)

    if not pendiente:
        return jsonify({
            "exito": False,
            "mensaje": "No hay un código pendiente. Solicitá uno nuevo."
        }), 400

    if time.time() > pendiente["expira"]:
        cambios_contrasena_pendientes.pop(usuario_id, None)

        return jsonify({
            "exito": False,
            "mensaje": "El código venció. Solicitá uno nuevo."
        }), 400

    if pendiente["intentos"] >= 5:
        cambios_contrasena_pendientes.pop(usuario_id, None)

        return jsonify({
            "exito": False,
            "mensaje": "Superaste el límite de intentos. Solicitá otro código."
        }), 429

    if not check_password_hash(pendiente["codigo_hash"], codigo):
        pendiente["intentos"] += 1

        return jsonify({
            "exito": False,
            "mensaje": "El código ingresado es incorrecto."
        }), 400

    cambios_contrasena_pendientes.pop(usuario_id, None)

    session["cambio_contrasena_verificado_usuario_id"] = usuario_id
    session["cambio_contrasena_verificado_expira"] = time.time() + 600

    return jsonify({
        "exito": True,
        "mensaje": "Código verificado correctamente."
    })
@app.route("/api/restablecer-contrasena-cambio", methods=["POST"])
def restablecer_contrasena_cambio():

    usuario_id = session.get("usuario_id")
    usuario_verificado = session.get(
        "cambio_contrasena_verificado_usuario_id"
    )
    expiracion = session.get("cambio_contrasena_verificado_expira")

    if not usuario_id or usuario_verificado != usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Primero tenés que verificar tu identidad."
        }), 403

    if not expiracion or time.time() > expiracion:
        session.pop("cambio_contrasena_verificado_usuario_id", None)
        session.pop("cambio_contrasena_verificado_expira", None)

        return jsonify({
            "exito": False,
            "mensaje": "La verificación venció. Solicitá un nuevo código."
        }), 403

    datos = request.get_json(silent=True) or {}
    password_nueva = datos.get("password_nueva", "")

    if not isinstance(password_nueva, str):
        return jsonify({
            "exito": False,
            "mensaje": "La contraseña ingresada no es válida."
        }), 400

    requisitos_validos = (
        8 <= len(password_nueva) <= 128
        and any(c.isupper() for c in password_nueva)
        and any(c.islower() for c in password_nueva)
        and any(c.isdigit() for c in password_nueva)
        and any(not c.isalnum() for c in password_nueva)
    )

    if not requisitos_validos:
        return jsonify({
            "exito": False,
            "mensaje": "La contraseña no cumple los requisitos de seguridad."
        }), 400

    try:
        respuesta = supabase.table("usuarios").select(
            "id, password_hash"
        ).eq("id", usuario_id).limit(1).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No se encontró tu cuenta."
            }), 404

        usuario = respuesta.data[0]

        if check_password_hash(
            usuario["password_hash"], password_nueva
        ):
            return jsonify({
                "exito": False,
                "mensaje": "La nueva contraseña debe ser diferente de la anterior."
            }), 400

        nuevo_hash = generate_password_hash(password_nueva)

        actualizacion = supabase.table("usuarios").update({
            "password_hash": nuevo_hash
        }).eq("id", usuario_id).select("id").execute()

        if not actualizacion.data:
            raise RuntimeError("No se pudo actualizar la contraseña.")

        session.pop("cambio_contrasena_verificado_usuario_id", None)
        session.pop("cambio_contrasena_verificado_expira", None)

        return jsonify({
            "exito": True,
            "mensaje": "La contraseña se cambió correctamente."
        })

    except Exception as error:
        print(
            "Error al restablecer contraseña desde ajustes:",
            type(error).__name__
        )

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo cambiar la contraseña. Intentá nuevamente."
        }), 500
# -----------------------------------------
# COMPROBAR SESIÓN
# -----------------------------------------

@app.route("/api/sesion", methods=["GET"])
def verificar_sesion():

    # Comprobar primero si la sesión corresponde a un invitado
    if session.get("modo_invitado"):
        return jsonify({
            "exito": True,
            "modo_invitado": True
        })

    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({"exito": False}), 401

    try:
        respuesta = supabase.table("usuarios").select(
            "cedula, correo, email_verificado, telefono, fecha_nacimiento"
        ).eq("id", usuario_id).limit(1).execute()

        usuarios = respuesta.data

        if not usuarios or not usuarios[0]["email_verificado"]:
            session.clear()
            return jsonify({"exito": False}), 401

        usuario = usuarios[0]

        return jsonify({
            "exito": True,
            "modo_invitado": False,
            "usuario": {
                "cedula": usuario["cedula"],
                "correo": usuario["correo"],
                "telefono": usuario["telefono"],
                "fecha_nacimiento": usuario["fecha_nacimiento"]
            }
        })

    except Exception as error:
        print("Error al comprobar sesión:", type(error).__name__)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo comprobar la sesión."
        }), 500
# -----------------------------------------
# CERRAR SESIÓN
# -----------------------------------------

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()

    return jsonify({
        "exito": True,
        "mensaje": "Sesión cerrada."
    })
@app.route("/api/solicitar-eliminacion", methods=["POST"])
def solicitar_eliminacion():
    datos = request.get_json(silent=True) or {}

    correo = str(datos.get("correo", "")).strip().lower()
    password = datos.get("password", "")

    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión nuevamente."
        }), 401

    if not correo or not isinstance(password, str) or not password:
        return jsonify({
            "exito": False,
            "mensaje": "Completá el correo y la contraseña."
        }), 400

    try:
        respuesta = supabase.table("usuarios").select(
            "id, correo, password_hash, email_verificado"
        ).eq("id", usuario_id).limit(1).execute()

        usuarios = respuesta.data

        if not usuarios:
            return jsonify({
                "exito": False,
                "mensaje": "No se encontró la cuenta."
            }), 404

        usuario = usuarios[0]

        if usuario["correo"].lower() != correo or not check_password_hash(
            usuario["password_hash"], password
        ):
            return jsonify({
                "exito": False,
                "mensaje": "El correo o la contraseña son incorrectos."
            }), 401

        if not usuario["email_verificado"]:
            return jsonify({
                "exito": False,
                "mensaje": "Primero tenés que verificar tu correo."
            }), 403

        codigo = generar_codigo()
        ahora = time.time()

        enviar_codigo(
    usuario["correo"],
    codigo,
    asunto="Código para eliminar tu cuenta",
    motivo="eliminar tu cuenta"
)

        eliminaciones_pendientes[usuario_id] = {
    "codigo_hash": generate_password_hash(codigo),
    "expira_en": ahora + 600,
    "ultimo_envio": ahora,
    "intentos": 0
}


        

        return jsonify({
            "exito": True,
            "mensaje": "Te enviamos un código de verificación a tu correo."
        })

    except Exception as error:
        print("Error al solicitar eliminación:", error)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo procesar la solicitud."
        }), 500
@app.route("/api/reenviar-codigo-eliminacion", methods=["POST"])
def reenviar_codigo_eliminacion():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión nuevamente."
        }), 401

    pendiente = eliminaciones_pendientes.get(usuario_id)

    if not pendiente:
        return jsonify({
            "exito": False,
            "mensaje": "Primero tenés que solicitar un código de verificación."
        }), 400

    ahora = time.time()

    if ahora < pendiente["ultimo_envio"] + 120:
        return jsonify({
            "exito": False,
            "mensaje": "Esperá 120 segundos antes de solicitar otro código."
        }), 429

    try:
        respuesta = supabase.table("usuarios").select(
            "correo, email_verificado"
        ).eq("id", usuario_id).limit(1).execute()

        usuarios = respuesta.data

        if not usuarios or not usuarios[0]["email_verificado"]:
            eliminaciones_pendientes.pop(usuario_id, None)

            return jsonify({
                "exito": False,
                "mensaje": "No se pudo verificar la cuenta."
            }), 404

        codigo = generar_codigo()

        enviar_codigo(
    usuarios[0]["correo"],
    codigo,
    asunto="Código para eliminar tu cuenta",
    motivo="eliminar tu cuenta"
)

        eliminaciones_pendientes[usuario_id] = {
    "codigo_hash": generate_password_hash(codigo),
    "expira_en": ahora + 600,
    "ultimo_envio": ahora,
    "intentos": 0
}
        return jsonify({
            "exito": True,
            "mensaje": "Te enviamos un nuevo código de verificación."
        })

    except Exception as error:
        print("Error al reenviar código de eliminación:", error)

        return jsonify({
            "exito": False,
            "mensaje": "No se pudo reenviar el código."
        }), 500
@app.route("/api/verificar-codigo-eliminacion", methods=["POST"])
def verificar_codigo_eliminacion():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Tenés que iniciar sesión nuevamente."
        }), 401

    datos = request.get_json(silent=True) or {}
    codigo = str(datos.get("codigo", "")).strip()

    if not codigo.isdigit() or len(codigo) != 6:
        return jsonify({
            "exito": False,
            "mensaje": "Ingresá un código válido de seis dígitos."
        }), 400

    pendiente = eliminaciones_pendientes.get(usuario_id)

    if not pendiente:
        return jsonify({
            "exito": False,
            "mensaje": "No hay una solicitud de eliminación pendiente."
        }), 400

    if time.time() > pendiente["expira_en"]:
        eliminaciones_pendientes.pop(usuario_id, None)

        return jsonify({
            "exito": False,
            "mensaje": "El código venció. Solicitá uno nuevo."
        }), 400

    pendiente["intentos"] += 1

    if pendiente["intentos"] > 5:
        eliminaciones_pendientes.pop(usuario_id, None)

        return jsonify({
            "exito": False,
            "mensaje": "Superaste el máximo de intentos. Solicitá un nuevo código."
        }), 429

    if not check_password_hash(pendiente["codigo_hash"], codigo):
        return jsonify({
            "exito": False,
            "mensaje": "El código ingresado es incorrecto."
        }), 400

    eliminaciones_pendientes.pop(usuario_id, None)

    session["eliminacion_autorizada_usuario_id"] = usuario_id
    session["eliminacion_autorizada_expira"] = time.time() + 300

    return jsonify({
        "exito": True,
        "mensaje": "Código verificado correctamente."
    })
@app.route("/api/cancelar-eliminacion", methods=["POST"])
def cancelar_eliminacion():
    usuario_id = session.get("usuario_id")

    if not usuario_id:
        return jsonify({"error": "No hay una sesión activa."}), 401

    # Eliminar cualquier código de verificación pendiente.
    eliminaciones_pendientes.pop(usuario_id, None)

    # Revocar la autorización para eliminar la cuenta.
    if session.get("eliminacion_autorizada_usuario_id") == usuario_id:
        session.pop("eliminacion_autorizada_usuario_id", None)
        session.pop("eliminacion_autorizada_expira", None)

    return jsonify({"mensaje": "Proceso de eliminación cancelado."}), 200
@app.route("/api/confirmar-eliminacion", methods=["POST"])
def confirmar_eliminacion():
    usuario_id = session.get("usuario_id")
    usuario_autorizado = session.get("eliminacion_autorizada_usuario_id")
    expira_en = session.get("eliminacion_autorizada_expira", 0)

    if not usuario_id or usuario_autorizado != usuario_id:
        return jsonify({
            "exito": False,
            "mensaje": "Primero tenés que verificar el código."
        }), 403

    if time.time() > expira_en:
        session.pop("eliminacion_autorizada_usuario_id", None)
        session.pop("eliminacion_autorizada_expira", None)

        return jsonify({
            "exito": False,
            "mensaje": "La autorización venció. Volvé a verificar tu identidad."
        }), 403

    try:
        respuesta = supabase.table("usuarios").delete().eq(
            "id", usuario_id
        ).execute()

        if not respuesta.data:
            return jsonify({
                "exito": False,
                "mensaje": "No se pudo encontrar la cuenta para eliminarla."
            }), 404

        eliminaciones_pendientes.pop(usuario_id, None)

        session.clear()

        return jsonify({
            "exito": True,
            "mensaje": "Tu cuenta fue eliminada correctamente."
        })

    except Exception as error:
        print("Error al eliminar la cuenta:", error)

        return jsonify({
            "exito": False,
            "mensaje": "Ocurrió un error al intentar eliminar la cuenta."
        }), 500

if __name__ == "__main__":
    app.run(debug=False)