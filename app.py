from flask import Flask, render_template, url_for, redirect, jsonify, flash, send_file, session, request

import bcrypt

from io import BytesIO

from bson.binary import Binary

from bson import ObjectId

import base64

import smtplib

from email.mime.multipart import MIMEMultipart

from email.mime.text import MIMEText

import os

import database as dbase

db = dbase.dbConnection()

app = Flask(__name__)

app.secret_key = 'M0i1Xc$GfPw3Yz@2SbQ9lKpA5rJhDtE7'


# Ruta principal
@app.route('/')
def index():
    return render_template('inicio.html')


# Ruta de Inicio de sesión
@app.route('/login/')
def login():
    return render_template('login.html')


@app.route('/iniciar/', methods=['POST'])
def iniciar():
    empleados = db['empleados']
    admin = db['admin']
    usuarios = db['usuarios']
    correo = request.form['correo']
    password = request.form['password']

    # Buscar en la colección de empleados
    login_empleado = empleados.find_one({'correo': correo})
    if login_empleado and bcrypt.checkpw(password.encode('utf-8'), login_empleado['password']):
        session['correo'] = correo
        return redirect(url_for('colaborador'))

    # Buscar en la colección de admin
    login_usuario = usuarios.find_one({'correo': correo})
    if login_usuario and bcrypt.checkpw(password.encode('utf-8'), login_usuario['password']):
        session['correo'] = correo
        return redirect(url_for('usuario'))

    # Buscar en la colección de admin
    login_admin = admin.find_one({'correo': correo, 'password': password})
    if login_admin:
        session['correo'] = correo
        return redirect(url_for('administrador'))

    flash('Correo o contraseña incorrectos')
    return redirect(url_for('login'))


# Ruta de registro
@app.route('/registro/')
def registro():
    return render_template('registro.html')


# Ruta para registrar a los usuarios
@app.route('/registerUsuario/', methods=['POST', 'GET'])
def registerUsario():
    if request.method == 'POST':
        usuarios = db['usuarios']
        existing_usuario = usuarios.find_one(
            {'correo': request.form['correo']})
        nombre = request.form['nombre']
        correo = request.form['correo']
        password = request.form['password']
        genero = request.form['genero']
        fecha = request.form['fecha']
        telefono = request.form['telefono']

        if existing_usuario is None:
            hashpass = bcrypt.hashpw(
                password.encode('utf-8'), bcrypt.gensalt())
            usuarios.insert_one({
                'nombre': nombre,
                'correo': correo,
                'password': hashpass,
                'telefono': telefono,
                'genero': genero,
                'fecha': fecha
            })
            session['correo'] = request.form['correo']
            return redirect(url_for('usuario'))

        flash('El correo ya está en uso')
        return redirect(url_for('registro'))

    return redirect(url_for('registro'))


# Ruta para registrar a los colaboradores
@app.route('/registerColaborador/', methods=['POST', 'GET'])
def registerColaborador():
    if request.method == 'POST':
        empleados = db['empleados']
        existing_empleado = empleados.find_one(
            {'correo': request.form['correo']})
        nombre = request.form['nombre']
        foto_perfil = request.files['foto_perfil']
        correo = request.form['correo']
        password = request.form['password']
        area_laboral = request.form['area_laboral']
        genero = request.form['genero']
        fecha = request.form['fecha']
        telefono = request.form['telefono']
        estado = request.form['estado']
        municipio = request.form['municipio']
        ciudad = request.form['ciudad']
        colonia = request.form['colonia']
        calle = request.form['calle']
        cp = request.form['cp']

        # Procesar el archivo CV
        cv = request.files['cv']

        if cv:
            if cv.filename.endswith('.pdf') or cv.filename.endswith('.jpg'):
                cv_data = cv.read()
                cv_bin = Binary(cv_data)
            else:
                flash('El archivo debe ser PDF o JPG')
                return redirect(url_for('registerColaborador'))
        else:
            cv_bin = None

        if foto_perfil:
            if foto_perfil.filename.endswith('.jpg'):
                foto_perfil_data = foto_perfil.read()
                foto_perfil_bin = Binary(foto_perfil_data)
            else:
                flash('El archivo debe ser JPG')
                return redirect(url_for('registerColaborador'))
        else:
            foto_perfil_bin = None

        if existing_empleado is None:
            hashpass = bcrypt.hashpw(
                password.encode('utf-8'), bcrypt.gensalt())
            empleados.insert_one({
                'nombre': nombre,
                'correo': correo,
                'password': hashpass,
                'area_laboral': area_laboral,
                'genero': genero,
                'fecha': fecha,
                'telefono': telefono,
                'estado': estado,
                'municipio': municipio,
                'ciudad': ciudad,
                'colonia': colonia,
                'calle': calle,
                'cp': cp,
                'cv': cv_bin,
                'foto_perfil': foto_perfil_bin,
                'estatus': False  # Nuevo campo 'aceptado' por defecto False
            })
            session['correo'] = request.form['correo']
            return redirect(url_for('login'))

        flash('El correo ya está en uso')
        return redirect(url_for('registro'))

    return redirect(url_for('registro'))


# Ruta para cerrar sesión
@app.route('/logout/')
def logout():
    session.clear()  # Elimina todas las variables de sesión
    return redirect(url_for('index'))


############################################


# Ruta para inicio de usuarios
@app.route('/usuario/')
def usuario():
    if 'correo' in session:
        correo = session['correo']
        # Función para obtener datos del usuario desde CouchDB
        usuario = obtener_usuario(correo)
        if usuario:
            return render_template('usuario.html', usuario=usuario)
    else:
        return redirect(url_for('login'))


# Ruta para que los usuarios puedan ver los colaboradores
@app.route('/colaboradores/')
def colaboradores():
    if 'correo' in session:
        correo = session['correo']
        usuario = obtener_usuario(correo)
        empleados = db['empleados']
        empleados_con_foto = []
        for empleado in empleados.find({'estatus': True}):
            foto_perfil_bin = empleado.get('foto_perfil')
            if foto_perfil_bin:
                foto_perfil_base64 = base64.b64encode(
                    foto_perfil_bin).decode('utf-8')
            else:
                foto_perfil_base64 = None

            empleados_con_foto.append({
                '_id': empleado.get('_id'),
                'nombre': empleado.get('nombre'),
                'foto_perfil': foto_perfil_base64,
                'correo': empleado.get('correo'),
                'genero': empleado.get('genero'),
                'fecha': empleado.get('fecha'),
                'telefono': empleado.get('telefono'),
                'estado': empleado.get('estado'),
                'municipio': empleado.get('municipio'),
                'ciudad': empleado.get('ciudad'),
                'colonia': empleado.get('colonia'),
                'calle': empleado.get('calle'),
                'cp': empleado.get('cp'),
                'area_laboral': empleado.get('area_laboral'),
                'cv': empleado.get('cv')
            })

        if usuario:
            return render_template('empleados.html', empleados=empleados_con_foto)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


# Ruta para que los usuarios ingresen comentarios
@app.route('/comentarios/')
def comentarios():
    if 'correo' in session:
        correo = session['correo']
        # Función para obtener datos del usuario desde CouchDB
        usuario = obtener_usuario(correo)
        if usuario:
            return render_template('comentarios.html', usuario=usuario)
    else:
        return redirect(url_for('login'))


# Crear la ruta para insertar los comentarios en la BD
@app.route('/agregarComentario/', methods=['POST'])
def agregarComentario():
    # Obtener los datos del formulario
    nombre = request.form.get("nombre")
    comentario = request.form.get("comentario")

    # Verificar si se recibieron datos válidos
    if nombre and comentario:
        comentarios = db['comentarios']

        # Insertar los datos en la colección de MongoDB
        try:
            comentario_doc = {
                "nombre": nombre,
                "comentario": comentario
            }
            comentarios.insert_one(comentario_doc)
        except Exception as e:
            flash("Error al agregar comentario a la base de datos: " + str(e), "Error")
    else:
        flash("Nombre y comentario son campos obligatorios", "Error")

    # Redirigir a la página de comentarios
    return redirect(url_for('comentarios'))


############################################


# Ruta para el administrador
@app.route('/administrador/')
def administrador():
    if 'correo' in session:
        correo = session['correo']
        # Función para obtener datos del usuario desde CouchDB
        usuario = obtener_admin(correo)
        if usuario:
            return render_template('admin.html')
    else:
        return redirect(url_for('login'))


# Ruta para aceptar colaboradores
@app.route('/administrador/colaboradores/pendientes')
def aceptarEmpleados():
    if 'correo' in session:
        correo = session['correo']
        usuario = obtener_admin(correo)
        empleados = db['empleados']
        empleados_con_foto = []
        for empleado in empleados.find({'estatus': False}):
            foto_perfil_bin = empleado.get('foto_perfil')
            if foto_perfil_bin:
                foto_perfil_base64 = base64.b64encode(
                    foto_perfil_bin).decode('utf-8')
            else:
                foto_perfil_base64 = None

            empleados_con_foto.append({
                '_id': empleado.get('_id'),
                'nombre': empleado.get('nombre'),
                'foto_perfil': foto_perfil_base64,
                'correo': empleado.get('correo'),
                'genero': empleado.get('genero'),
                'fecha': empleado.get('fecha'),
                'telefono': empleado.get('telefono'),
                'estado': empleado.get('estado'),
                'municipio': empleado.get('municipio'),
                'ciudad': empleado.get('ciudad'),
                'colonia': empleado.get('colonia'),
                'calle': empleado.get('calle'),
                'cp': empleado.get('cp'),
                'area_laboral': empleado.get('area_laboral'),
                'cv': empleado.get('cv')
            })

        if usuario:
            return render_template('aceptarEmpleados.html', empleados=empleados_con_foto)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


# Method DELETE
@app.route('/deleteEmpleado/<string:empleado_id>/')
def deleteEmpleado(empleado_id):
    template_name = request.args.get('template_name', 'aceptarEmpleados')
    empleados = db['empleados']
    empleados.delete_one({'_id': ObjectId(empleado_id)})
    return redirect(url_for(template_name))


# Method PUT
@app.route('/actualizaEmpleado/', methods=['POST'])
def actualizaEmpleado():
    if request.method == 'POST':
        empleado_id = request.form.get('empleado_id')
        nuevo_estado_aceptado = request.form.get('nuevo_estado_aceptado')

        # Actualizar el estado 'aceptado' del empleado en la base de datos
        empleados = db['empleados']
        empleados.update_one(
            {'_id': ObjectId(empleado_id)},
            {'$set': {'estatus': nuevo_estado_aceptado == 'True'}}
        )

        # Obtener la información del empleado
        empleado = empleados.find_one({'_id': ObjectId(empleado_id)})

        # Llamar a la función para enviar el mensaje si el estado es True
        if nuevo_estado_aceptado == 'True':
            enviar_mensaje_aceptado(empleado)

        # flash('Estado de empleado actualizado correctamente')

    return redirect(url_for('aceptarEmpleados'))


# Ruta para ver los colaboradores aceptados
@app.route('/administrador/colaboradores/aceptados/')
def empleadosAceptados():
    if 'correo' in session:
        correo = session['correo']
        usuario = obtener_admin(correo)
        empleados = db['empleados']
        empleados_con_foto = []
        for empleado in empleados.find({'estatus': True}):
            foto_perfil_bin = empleado.get('foto_perfil')
            if foto_perfil_bin:
                foto_perfil_base64 = base64.b64encode(
                    foto_perfil_bin).decode('utf-8')
            else:
                foto_perfil_base64 = None

            empleados_con_foto.append({
                '_id': empleado.get('_id'),
                'nombre': empleado.get('nombre'),
                'foto_perfil': foto_perfil_base64,
                'correo': empleado.get('correo'),
                'genero': empleado.get('genero'),
                'fecha': empleado.get('fecha'),
                'telefono': empleado.get('telefono'),
                'estado': empleado.get('estado'),
                'municipio': empleado.get('municipio'),
                'ciudad': empleado.get('ciudad'),
                'colonia': empleado.get('colonia'),
                'calle': empleado.get('calle'),
                'cp': empleado.get('cp'),
                'area_laboral': empleado.get('area_laboral'),
                'cv': empleado.get('cv')
            })

        if usuario:
            return render_template('empleadosAceptados.html', empleados=empleados_con_foto)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


# Ruta para ver comentarios
@app.route('/administrador/comentarios/')
def verComentarios():
    if 'correo' in session:
        comentarios = db['comentarios']
        comentariosEnviados = comentarios.find()
        correo = session['correo']
        # Función para obtener datos del usuario desde CouchDB
        usuario = obtener_admin(correo)
        if usuario:
            return render_template('verComentarios.html', comentarios=comentariosEnviados)
    else:
        return redirect(url_for('login'))


# Función para enviar correo a empleados aceptados
def enviar_mensaje_aceptado(empleado):
    email = 'contact.quarium@gmail.com'
    password = 'otjt nkts nczg qcxw'
    destinatario = empleado['correo']

    template_file = os.path.join('templates', 'correo_aceptacion.html')

 # Cargar el contenido del archivo HTML
    with open(template_file, 'r') as file:
        html_content = file.read()

    # Crear el mensaje
    mensaje = MIMEMultipart()
    mensaje['From'] = email
    mensaje['To'] = destinatario
    mensaje['Subject'] = 'Registro Aceptado'

    # Adjuntar el contenido HTML al mensaje
    mensaje.attach(MIMEText(html_content, 'html'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email, password)
        texto_del_correo = mensaje.as_string()
        server.sendmail(email, destinatario, texto_del_correo)
        server.quit()
        print('Correo enviado correctamente a', destinatario)
    except Exception as e:
        print(f'Error al enviar el correo: {str(e)}')


############################################


# Ruta para los colaboradores
@app.route('/colaborador/')
def colaborador():
    if 'correo' in session:
        correo = session['correo']
        # Función para obtener datos del usuario desde CouchDB
        usuario = obtener_colaborador(correo)
        if usuario:
            return render_template('colaborador.html', empleado=usuario)
    else:
        return redirect(url_for('login'))


# Ruta para que un colaborador edite su informaación
@app.route('/colaborador/editar/')
def editarDatos():
    if 'correo' in session:
        correo_empleado = session['correo']
        empleados = db['empleados']
        empleado_actual = empleados.find_one({'correo': correo_empleado})

        if empleado_actual:
            # Si se encuentra el empleado, obtener la foto de perfil en base64
            foto_perfil_bin = empleado_actual.get('foto_perfil')
            if foto_perfil_bin:
                foto_perfil_base64 = base64.b64encode(
                    foto_perfil_bin).decode('utf-8')
            else:
                foto_perfil_base64 = None

            # Renderizar la plantilla con la información del empleado y la foto de perfil
            return render_template('editarEmpleado.html', empleado=empleado_actual, foto_perfil_base64=foto_perfil_base64)
        else:
            # Si no se encuentra el empleado, mostrar un mensaje de error
            flash('Empleado no encontrado')
            return redirect(url_for('login'))
    else:
        # Si el correo no está en la sesión, redirigir al inicio de sesión
        flash('Debe iniciar sesión primero')
        return redirect(url_for('login'))


# Metodo para actulizar datos de un colaborador
@app.route('/actualizar_datos/', methods=['POST'])
def actualizar_datos():
    if request.method == 'POST':
        empleado_id = request.form.get('empleado_id')
        nuevo_telefono = request.form.get('nuevo_telefono')
        nuevo_estado = request.form.get('nuevo_estado')
        nuevo_municipio = request.form.get('nuevo_municipio')
        nueva_ciudad = request.form.get('nueva_ciudad')
        nueva_colonia = request.form.get('nueva_colonia')
        nueva_calle = request.form.get('nueva_calle')
        nuevo_cp = request.form.get('nuevo_cp')
        # Procesar el archivo CV
        nuevo_CV = request.files['nuevo_cv']

        if nuevo_CV:
            if nuevo_CV.filename.endswith('.pdf') or nuevo_CV.filename.endswith('.jpg'):
                cv_data = nuevo_CV.read()
                cv_bin = Binary(cv_data)
            else:
                flash('El archivo debe ser PDF')
                return redirect(url_for('empleado'))
        else:
            cv_bin = None
        nueva_foto_perfil = request.files['nueva_foto']
        if nueva_foto_perfil:
            if nueva_foto_perfil.filename.endswith('.jpg'):
                nueva_foto_perfil_data = nueva_foto_perfil.read()
                nueva_foto_perfil_bin = Binary(nueva_foto_perfil_data)
            else:
                flash('El archivo debe ser JPG')
                return redirect(url_for('register'))
        else:
            nueva_foto_perfil_bin = None

        # Actualizar el estado 'aceptado' del empleado en la base de datos
        empleados = db['empleados']
        empleados.update_one(
            {'_id': ObjectId(empleado_id)},
            {'$set': {
                'telefono': nuevo_telefono,
                'estado': nuevo_estado,
                'municipio': nuevo_municipio,
                'ciudad': nueva_ciudad,
                'colonia': nueva_colonia,
                'calle': nueva_calle,
                'cp': nuevo_cp,
                'cv': cv_bin,
                'foto_perfil': nueva_foto_perfil_bin
            }}
        )

        # Obtener la información del empleado
        empleados = empleados.find_one({'_id': ObjectId(empleado_id)})

        flash('Estado de empleado actualizado correctamente')

    return redirect(url_for('empleado'))


# Metodo para descargar cv de un colaborador
@app.route('/descargar_cv/<string:empleado_id>')
def descargar_cv(empleado_id):
    empleados = db['empleados']
    empleado = empleados.find_one({'_id': ObjectId(empleado_id)})

    if empleado and empleado['cv']:
        # Obtener el contenido binario del CV
        cv_bin = empleado['cv']
        # Crear un objeto BytesIO para almacenar el contenido binario
        cv_stream = BytesIO(cv_bin)
        # Enviar el contenido binario como un archivo adjunto
        # Asegurar que la posición del cursor esté al inicio del archivo
        cv_stream.seek(0)
        return send_file(cv_stream, mimetype='application/pdf', as_attachment=True, download_name='cv.pdf')
    else:
        flash('CV no encontrado')
        return redirect(url_for(request.url))


########################################################
# FUNCIONES

def obtener_usuario(correo):
    usuario = db['usuarios'].find_one({'correo': correo})
    return usuario


def obtener_colaborador(correo):
    colaborador = db['empleados'].find_one({'correo': correo})
    return colaborador


def obtener_admin(correo):
    admin = db['admin'].find_one({'correo': correo})
    return admin

########################################################


# Ruta para errores
@app.errorhandler(404)
def notFound(error=None):
    message = {
        'message': 'No encontrado ' + request.url,
        'status': '404 Not Found'
    }
    response = jsonify(message)
    response.status_code = 404
    return response


if __name__ == '__main__':
    # Configuración para OpenSSL
    # , host="192.168.33.218", port=5000, ssl_context=("cert.pem", "key.pem")
    app.run(debug=True)
