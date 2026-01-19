import sqlite3
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import qrcode
from io import BytesIO
import random

app = Flask(__name__)
# En producción, usa una variable de entorno. Por ahora, esta llave es fuerte.
app.secret_key = 'super_secreto_barrio_market_key_v2_protegido'

# --- SEGURIDAD ---
csrf = CSRFProtect(app) 
Talisman(app, content_security_policy=None) 

# --- CONFIGURACIÓN DE BASE DE DATOS ---
def get_db_connection():
    # 1. Primero intentamos ver si existe la variable de Render (Neon)
    database_url = os.environ.get('DATABASE_URL')

    if database_url:
        # ESTAMOS EN RENDER (MODO NUBE ☁️)
        try:
            conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
            return conn
        except Exception as e:
            print(f"Error conectando a Neon DB: {e}")
            return None
    else:
        # ESTAMOS EN LOCAL (MODO CASA 🏠)
        try:
            BASE_DIR = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(BASE_DIR, 'tienda.db')
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            print(f"Error DB Local: {e}")
            return None

# --- CREDENCIALES ADMIN ---
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

# Carpetas de Imágenes y Validación
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'} 

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- CONFIGURACIÓN GOOGLE ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='50741375590-5od44e9smdfvfbofc5rubgcl9ep0p6hu.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# ==========================================
#  RUTAS PÚBLICAS (CLIENTES)
# ==========================================
# Cambia esto a True para activar el mantenimiento
MANTENIMIENTO = False

@app.before_request
def check_mantenimiento():
    if MANTENIMIENTO and request.path != '/static/uploads/tu_logo.png':
        # Permite ver el logo pero bloquea todo lo demás
        return render_template('mantenimiento.html')


@app.route('/')
def pagina_principal():
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM comercios WHERE estado = 'activo'")
    lista_comercios = cursor.fetchall()
    cursor.execute("SELECT * FROM comercios WHERE estado = 'activo' AND es_destacado = true")
    lista_destacados = cursor.fetchall()
    conn.close()
    return render_template('index.html', comercios=lista_comercios, destacados=lista_destacados)

@app.route('/comercio/<int:id_comercio>')
def ver_comercio(id_comercio):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM comercios WHERE id = %s", (id_comercio,))
    comercio = cursor.fetchone()
    
    if not comercio: return "Negocio no encontrado", 404
    
    # Si está pausado por ADMIN, nadie entra (salvo admin/dueño)
    if comercio['estado'] != 'activo':
        if session.get('rol') not in ['admin', 'dueno']:
            return render_template('login.html', error="⛔ Este negocio se encuentra pausado temporalmente.")

    cursor.execute("SELECT * FROM productos WHERE comercio_id = %s", (id_comercio,))
    productos = cursor.fetchall()
    
    cursor.execute("SELECT * FROM resenas WHERE comercio_id = %s ORDER BY id DESC", (id_comercio,))
    resenas = cursor.fetchall()
    
    promedio = 0
    if len(resenas) > 0: promedio = round(sum(r['puntaje'] for r in resenas) / len(resenas), 1)
    
    conn.close()
    return render_template('detalle.html', comercio=comercio, productos=productos, resenas=resenas, promedio=promedio, total_resenas=len(resenas))

# --- NUEVA RUTA LEGAL ---
@app.route('/terminos')
def terminos_condiciones():
    return render_template('terminos.html')

# ==========================================
#  SISTEMA DE LOGIN (SEGURIDAD AUMENTADA)
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form.get('login_input')
        password = request.form.get('password')

        # Admin Hardcoded
        if login_input == ADMIN_USER and password == ADMIN_PASS:
            session['rol'] = 'admin'
            return redirect(url_for('admin_panel'))
        
        conn = get_db_connection(); cursor = conn.cursor()
        # Buscamos el usuario PRIMERO, sin chequear contraseña en la SQL
        cursor.execute("""
            SELECT * FROM comercios 
            WHERE (usuario = %s OR email = %s OR telefono = %s)
        """, (login_input, login_input, login_input))
        
        comercio = cursor.fetchone()
        conn.close()

        if comercio:
            # VERIFICACIÓN DE SEGURIDAD HÍBRIDA (Soporta claves viejas y nuevas)
            password_valida = False
            
            # 1. Intenta verificar como Hash (Nueva seguridad)
            try:
                if check_password_hash(comercio['password'], password):
                    password_valida = True
            except:
                pass # No era un hash, probamos texto plano
            
            # 2. Si falla, intenta texto plano (Usuarios viejos)
            if not password_valida and comercio['password'] == password:
                password_valida = True

            if password_valida:
                if comercio['estado'] == 'pendiente': return render_template('login.html', error="⏳ Cuenta pendiente de aprobación.")
                if comercio['estado'] == 'suspendido': return render_template('login.html', error="⛔ Cuenta suspendida.")
                
                session['rol'] = 'dueno'
                session['user_id'] = comercio['id']
                session['nombre_negocio'] = comercio['nombre_negocio']
                session.permanent = True # Sesión persistente segura
                return redirect(url_for('dashboard_dueno'))
        
        return render_template('login.html', error="❌ Credenciales incorrectas")
    
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        user_info = token['userinfo']
        email_google = user_info['email']
        
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("SELECT * FROM comercios WHERE email = %s", (email_google,))
        comercio = cursor.fetchone()
        conn.close()
        
        if comercio:
            if comercio['estado'] == 'pendiente': return render_template('login.html', error="⏳ Cuenta pendiente.")
            if comercio['estado'] == 'suspendido': return render_template('login.html', error="⛔ Cuenta suspendida.")

            session['rol'] = 'dueno'
            session['user_id'] = comercio['id']
            session['nombre_negocio'] = comercio['nombre_negocio']
            return redirect(url_for('dashboard_dueno'))
        else:
            return render_template('login.html', error=f"❌ El email {email_google} no está registrado.")
            
    except Exception as e:
        return render_template('login.html', error=f"Error Google: {e}")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        form = request.form
        conn = get_db_connection(); cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM comercios WHERE email = %s OR usuario = %s", (form['email'], form['usuario']))
        if cursor.fetchone():
            conn.close()
            return render_template('registro.html', error="⚠️ Usuario o Email ya existen.")

        # PROCESAR TELÉFONO INTELIGENTE (COD + NUMERO)
        area = form.get('cod_area', '').strip()
        numero = form.get('telefono_numero', '').strip()
        
        # Limpieza: sacar 0 al principio y 15 al principio
        if area.startswith('0'): area = area[1:]
        if numero.startswith('15'): numero = numero[2:]
        
        telefono_final = f"+549{area}{numero}"

        # VALIDACIÓN DE ARCHIVO
        logo_url = ""
        archivo = request.files.get('logo')
        if archivo and archivo.filename != '' and allowed_file(archivo.filename):
            filename = secure_filename(archivo.filename)
            nombre_unico = f"logo_reg_{random.randint(1000,9999)}_{filename}"
            archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico))
            logo_url = f"/static/uploads/{nombre_unico}"
        
        # ENCRIPTAR CONTRASEÑA
        hashed_password = generate_password_hash(form['password'])
            
        # GUARDA TAMBIÉN: horarios (vacio al inicio) y estado_abierto (0 por defecto)
        cursor.execute("""
            INSERT INTO comercios (nombre_negocio, usuario, email, password, telefono, direccion, categoria, estado, mapa_url, logo_url, horarios, estado_abierto) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'pendiente', %s, %s, %s, false)
        """, (form['nombre'], form['usuario'], form['email'], hashed_password, telefono_final, form['direccion'], form['categoria'], form.get('mapa',''), logo_url, ''))
        
        conn.commit(); conn.close()
        flash('¡Cuenta creada! Espera aprobación.', 'success')
        return redirect(url_for('login'))
    return render_template('registro.html')

# ==========================================
#  PANEL DEL DUEÑO (DASHBOARD + VENTAS)
# ==========================================

@app.route('/mi_negocio')
def dashboard_dueno():
    if session.get('rol') != 'dueno': return redirect(url_for('login'))
    id_comercio = session['user_id']
    
    conn = get_db_connection(); cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM productos WHERE comercio_id = %s", (id_comercio,))
    productos = cursor.fetchall()
    
    cursor.execute("SELECT * FROM comercios WHERE id = %s", (id_comercio,))
    datos_comercio = cursor.fetchone()
    
    try:
        cursor.execute("SELECT SUM(total_venta) FROM ventas WHERE comercio_id = %s", (id_comercio,))
        resultado_ventas = cursor.fetchone()[0]
        total_vendido = round(resultado_ventas, 2) if resultado_ventas else 0
        
        cursor.execute("""
            SELECT v.*, p.nombre_producto 
            FROM ventas v 
            LEFT JOIN productos p ON v.producto_id = p.id 
            WHERE v.comercio_id = %s 
            ORDER BY v.fecha DESC LIMIT 20
        """, (id_comercio,))
        historial_ventas = cursor.fetchall()
        
    except:
        total_vendido = 0
        historial_ventas = []
    
    conn.close()
    
    return render_template('dashboard.html', 
                           productos=productos, 
                           comercio=datos_comercio, 
                           total_vendido=total_vendido,
                           ventas=historial_ventas)

# --- NUEVA RUTA: CAMBIAR ESTADO ABIERTO/CERRADO ---
@app.route('/mi_negocio/cambiar_estado', methods=['POST'])
def cambiar_estado_abierto():
    if session.get('rol') != 'dueno': return jsonify({'success': False})
    
    conn = get_db_connection(); cursor = conn.cursor()
    # Invertir el estado actual (NOT)
    cursor.execute("UPDATE comercios SET estado_abierto = NOT estado_abierto WHERE id = %s", (session['user_id'],))
    conn.commit()
    
    # Obtener nuevo estado para confirmación
    cursor.execute("SELECT estado_abierto FROM comercios WHERE id = %s", (session['user_id'],))
    nuevo_estado = cursor.fetchone()[0]
    conn.close()
    
    return jsonify({'success': True, 'nuevo_estado': nuevo_estado})

@app.route('/mi_negocio/vender', methods=['POST'])
def registrar_venta_manual():
    if session.get('rol') != 'dueno': return redirect(url_for('login'))
    
    try:
        id_prod = request.form.get('id_producto')
        cantidad = int(request.form.get('cantidad', 1))
        if cantidad < 1: cantidad = 1
        
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ventas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comercio_id INTEGER NOT NULL,
                producto_id INTEGER NOT NULL,
                cantidad INTEGER NOT NULL,
                total_venta REAL NOT NULL,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("SELECT * FROM productos WHERE id = %s AND comercio_id = %s", (id_prod, session['user_id']))
        producto = cursor.fetchone()
        
        if not producto:
            conn.close(); flash('Error: Producto no encontrado.', 'danger'); return redirect(url_for('dashboard_dueno'))
        
        if producto['stock'] < cantidad:
            conn.close(); flash(f'❌ Stock insuficiente. Quedan {producto["stock"]}.', 'danger'); return redirect(url_for('dashboard_dueno'))
        
        total = producto['precio'] * cantidad
        
        cursor.execute("INSERT INTO ventas (comercio_id, producto_id, cantidad, total_venta) VALUES (%s, %s, %s, %s)",
                       (session['user_id'], id_prod, cantidad, total))
        
        cursor.execute("UPDATE productos SET stock = stock - %s WHERE id = %s", (cantidad, id_prod))
        
        conn.commit(); conn.close()
        
        flash(f'✅ ¡Venta registrada! +${total}', 'success')
        return redirect(url_for('dashboard_dueno'))
        
    except Exception as e:
        return f"<h1>Error Técnico:</h1><p>{str(e)}</p>", 500

@app.route('/mi_negocio/nuevo', methods=['POST'])
def nuevo_producto_web():
    if session.get('rol') != 'dueno': return redirect(url_for('login'))
    
    nombre = request.form['nombre']
    precio = request.form['precio']
    stock = request.form['stock']
    id_comercio = session['user_id']
    
    url_foto = ""
    archivo = request.files.get('foto')
    # CHECK DE SEGURIDAD DE ARCHIVO
    if archivo and archivo.filename != '' and allowed_file(archivo.filename):
        filename = secure_filename(archivo.filename)
        nombre_unico = f"prod_{id_comercio}_{random.randint(1000,9999)}_{filename}"
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico))
        url_foto = f"/static/uploads/{nombre_unico}"

    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("INSERT INTO productos (comercio_id, nombre_producto, precio, stock, imagen_url) VALUES (%s, %s, %s, %s, %s)",
                   (id_comercio, nombre, precio, stock, url_foto))
    conn.commit(); conn.close()
    
    flash('¡Producto creado!', 'success')
    return redirect(url_for('dashboard_dueno'))

@app.route('/mi_negocio/editar/<int:id_prod>', methods=['POST'])
def editar_producto_web(id_prod):
    if session.get('rol') != 'dueno': return "Acceso denegado"
    
    nombre = request.form['nombre']
    precio = request.form['precio']
    stock = request.form['stock']
    
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("SELECT * FROM productos WHERE id=%s AND comercio_id=%s", (id_prod, session['user_id']))
    if not cursor.fetchone(): return "No permitido"
    
    archivo = request.files.get('foto')
    # CHECK DE SEGURIDAD DE ARCHIVO
    if archivo and archivo.filename != '' and allowed_file(archivo.filename):
        filename = secure_filename(archivo.filename)
        nombre_unico = f"prod_{session['user_id']}_{random.randint(1000,9999)}_{filename}"
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico))
        url_foto = f"/static/uploads/{nombre_unico}"
        cursor.execute("UPDATE productos SET imagen_url=%s WHERE id=%s", (url_foto, id_prod))

    cursor.execute("UPDATE productos SET nombre_producto=%s, precio=%s, stock=%s WHERE id=%s", (nombre, precio, stock, id_prod))
    conn.commit(); conn.close()
    
    flash('Producto actualizado.', 'info')
    return redirect(url_for('dashboard_dueno'))

@app.route('/mi_negocio/borrar/<int:id_prod>')
def borrar_producto_web(id_prod):
    if session.get('rol') != 'dueno': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("DELETE FROM productos WHERE id=%s AND comercio_id=%s", (id_prod, session['user_id']))
    conn.commit(); conn.close()
    flash('Producto eliminado.', 'warning')
    return redirect(url_for('dashboard_dueno'))

@app.route('/mi_negocio/editar_perfil', methods=['POST'])
def editar_perfil_web():
    if session.get('rol') != 'dueno': return redirect(url_for('login'))
    
    telefono = request.form['telefono']
    direccion = request.form['direccion']
    horarios = request.form.get('horarios', '') # NUEVO CAMPO HORARIOS
    
    conn = get_db_connection(); cursor = conn.cursor()
    
    archivo = request.files.get('logo')
    if archivo and archivo.filename != '' and allowed_file(archivo.filename):
        filename = secure_filename(archivo.filename)
        nombre_unico = f"logo_update_{session['user_id']}_{random.randint(1000,9999)}_{filename}"
        archivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico))
        logo_url = f"/static/uploads/{nombre_unico}"
        
        cursor.execute("UPDATE comercios SET telefono=%s, direccion=%s, horarios=%s, logo_url=%s WHERE id=%s", 
                       (telefono, direccion, horarios, logo_url, session['user_id']))
    else:
        cursor.execute("UPDATE comercios SET telefono=%s, direccion=%s, horarios=%s WHERE id=%s", 
                       (telefono, direccion, horarios, session['user_id']))
    
    conn.commit(); conn.close()
    
    flash('✅ ¡Perfil del negocio actualizado!', 'success')
    return redirect(url_for('dashboard_dueno'))

@app.route('/mi_negocio/reporte_mensual')
def reporte_mensual():
    if session.get('rol') != 'dueno': return redirect(url_for('login'))
    
    conn = get_db_connection(); cursor = conn.cursor()
    id_comercio = session['user_id']
    
    ahora = datetime.now()
    mes_actual_str = ahora.strftime('%Y-%m') 
    
    cursor.execute("""
        SELECT v.*, p.nombre_producto 
        FROM ventas v 
        LEFT JOIN productos p ON v.producto_id = p.id 
        WHERE v.comercio_id = %s AND TO_CHAR(v.fecha, 'YYYY-MM') = %s
        ORDER BY v.fecha DESC
    """, (id_comercio, mes_actual_str))
    
    ventas_mes = cursor.fetchall()
    
    total_mes = sum(v['total_venta'] for v in ventas_mes)
    
    cursor.execute("SELECT * FROM comercios WHERE id = %s", (id_comercio,))
    datos_comercio = cursor.fetchone()
    conn.close()
    
    meses_es = {
        1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril", 5: "Mayo", 6: "Junio",
        7: "Julio", 8: "Agosto", 9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"
    }
    nombre_mes = f"{meses_es[ahora.month]} {ahora.year}"
    
    return render_template('reporte_mensual.html', 
                           ventas=ventas_mes, 
                           total_mes=total_mes, 
                           comercio=datos_comercio, 
                           mes_actual=nombre_mes, 
                           hoy=ahora.strftime('%d/%m/%Y %H:%M'))

# ==========================================
#  PANEL SUPER ADMIN
# ==========================================

@app.route('/admin')
def admin_panel():
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM comercios WHERE estado = 'pendiente'")
    pendientes = cursor.fetchall()
    
    try:
        cursor.execute("""
            SELECT c.*, (SELECT COALESCE(SUM(total_venta), 0) FROM ventas WHERE comercio_id = c.id) as total_vendido 
            FROM comercios c WHERE c.estado != 'pendiente'
        """)
        activos = cursor.fetchall()
    except:
        cursor.execute("SELECT *, 0 as total_vendido FROM comercios WHERE estado != 'pendiente'")
        activos = cursor.fetchall()
        
    conn.close()
    
    nombres = [c['nombre_negocio'] for c in activos]
    ventas = [float(c['total_vendido']) for c in activos]
    
    return render_template('admin_dashboard.html', pendientes=pendientes, activos=activos, nombres_grafico=nombres, ventas_grafico=ventas)

@app.route('/admin/negocios')
def admin_negocios():
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT c.*, (SELECT COALESCE(SUM(total_venta), 0) FROM ventas WHERE comercio_id = c.id) as total_vendido 
            FROM comercios c WHERE c.estado != 'pendiente'
        """)
        activos = cursor.fetchall()
    except:
        cursor.execute("SELECT *, 0 as total_vendido FROM comercios WHERE estado != 'pendiente'")
        activos = cursor.fetchall()

    conn.close()
    return render_template('admin_negocios.html', activos=activos)

@app.route('/admin/aprobar/<int:id>')
def aprobar_comercio(id):
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("UPDATE comercios SET estado = 'activo' WHERE id = %s", (id,))
    conn.commit(); conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/estado/<int:id>/<accion>')
def cambiar_estado_comercio(id, accion):
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("UPDATE comercios SET estado = %s WHERE id = %s", ('activo' if accion == 'activar' else 'suspendido', id))
    conn.commit(); conn.close()
    return redirect(url_for('admin_negocios', _anchor=f'negocio-{id}'))

@app.route('/admin/toggle_vip/<int:id>')
def toggle_vip(id):
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("UPDATE comercios SET es_destacado = NOT es_destacado WHERE id = %s", (id,))
    conn.commit(); conn.close()
    return redirect(url_for('admin_negocios', _anchor=f'negocio-{id}'))

@app.route('/admin/toggle_verificado/<int:id>')
def toggle_verificado(id):
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("UPDATE comercios SET es_verificado = NOT es_verificado WHERE id = %s", (id,))
    conn.commit(); conn.close()
    return redirect(url_for('admin_negocios', _anchor=f'negocio-{id}'))

@app.route('/admin/eliminar_negocio/<int:id>')
def eliminar_negocio(id):
    if not session.get('rol') == 'admin': return redirect(url_for('login'))
    conn = get_db_connection(); cursor = conn.cursor()
    
    try: cursor.execute("DELETE FROM ventas WHERE comercio_id = %s", (id,))
    except: pass
    
    cursor.execute("DELETE FROM productos WHERE comercio_id = %s", (id,))
    cursor.execute("DELETE FROM resenas WHERE comercio_id = %s", (id,))
    cursor.execute("DELETE FROM comercios WHERE id = %s", (id,))
    
    conn.commit(); conn.close()
    flash('Negocio eliminado permanentemente.', 'success')
    return redirect(url_for('admin_negocios'))

# ==========================================
#  UTILIDADES
# ==========================================

@app.route('/qr/<int:id_comercio>')
def generar_qr(id_comercio):
    link = f"{request.host_url}comercio/{id_comercio}"
    qr = qrcode.QRCode(box_size=10, border=4); qr.add_data(link); qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO(); img.save(buffer); buffer.seek(0)
    return send_file(buffer, mimetype='image/png')

@app.route('/comercio/<int:id_comercio>/calificar', methods=['POST'])
def agregar_resena(id_comercio):
    conn = get_db_connection(); cursor = conn.cursor()
    cursor.execute("INSERT INTO resenas (comercio_id, puntaje, comentario) VALUES (%s, %s, %s)",
                   (id_comercio, request.form['puntaje'], request.form['comentario']))
    conn.commit(); conn.close()
    flash('¡Gracias por tu opinión!', 'success')
    return redirect(url_for('ver_comercio', id_comercio=id_comercio))

@app.route('/webhook', methods=['POST'])
def recibir_mensaje():
    return jsonify({"status": "ignored", "info": "Bot system disabled"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)