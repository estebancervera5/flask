### Backend usando Pyhton Flask y MongoDB con JWT y Bcrypt ###
### Universidad Anahuac Mayab
### 31-08-2024, Fabricio Suárez
### Prog de Dispositivos Móviles


#importamos todo lo necesario para que funcione el backend
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import mongo, init_db
from config import Config
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt
import random

#Inicializamos la aplicación y usamos el config file
app = Flask(__name__)
app.config.from_object(Config)

#Inicializamos a bcrypt y jwt
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

#Inicializamos el acceso a MongoDB
init_db(app)

#Definimos el endpoint para registrar un usuario
#Utilizamos el decorador @app.route('/') para definir la ruta de la URL e inmediatamente después
#la función que se ejecutará en esa ruta
@app.route('/register', methods=['POST'])
def register():
    #Estos son los datos que pasamos al post en formato JSON
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "Ese usuario ya existe"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # mongo.db.users.insert_one devuelve un objeto con dos propiedades "acknowledged" 
    # si se guardo correctamente y el id del documento insertado
    result = mongo.db.users.insert_one({"username":username,"email":email,"password": hashed_password})
    if result.acknowledged:
        return jsonify({"msg": "Usuario Creado Correctamente"}), 201
    else:
        return jsonify({"msg": "Hubo un error, no se pudieron guardar los datos"}),400



#Ruta para subir los juegos
@app.route('/rgame', methods=['POST'])
@jwt_required()
def addgame():
    data=request.get_json()
    gamename = data.get('gamename')
    platform = data.get('platform')
    price = data.get('price')
    user_id = str(get_jwt_identity())

    result=mongo.db.games.insert_one({"gamename":gamename,"platform":platform,"price":price, "user_id":user_id})
    if result.acknowledged:
        return jsonify({"msg": "Juego Añadido Correctamente"}), 201
    else:
        return jsonify({"msg": "Error , no se pudo agregar el juego"}), 400


#Ruta para actualizar la info de un juego
@app.route('/update_game/<game_id>', methods=['PUT'])
@jwt_required()
def update_game(game_id):
    current_user = get_jwt_identity()  # Identidad del usuario autenticado

    try:
        # Convertimos el game_id a ObjectId para buscar en MongoDB
        game_object_id = ObjectId(game_id)
    except:
        return jsonify({"msg": "ID de juego inválido"}), 400

    # Obtenemos el juego que pertenece al usuario actual
    game = mongo.db.games.find_one({"_id": game_object_id, "user_id": current_user})

    if not game:
        return jsonify({"msg": "Juego no encontrado o no pertenece al usuario"}), 404

    # Obtenemos los nuevos datos del cuerpo de la petición
    data = request.get_json()
    updated_game = {}

    if 'gamename' in data:
        updated_game['gamename'] = data['gamename']
    
    if 'platform' in data:
        updated_game['platform'] = data['platform']
    
    if 'price' in data:
        updated_game['price'] = data['price']

    # Si hay campos para actualizar
    if updated_game:
        result = mongo.db.games.update_one({"_id": game_object_id}, {"$set": updated_game})
        
        if result.modified_count == 1:
            return jsonify({"msg": "Juego actualizado correctamente"}), 200
        else:
            return jsonify({"msg": "No se pudo actualizar el juego"}), 500
    else:
        return jsonify({"msg": "No se proporcionaron datos para actualizar"}), 400



#Ruta para borrar un juego de la coleccion del usuario por id   
@app.route('/delete_game/<game_id>', methods=['DELETE'])
@jwt_required()
def delete_game(game_id):
    current_user = get_jwt_identity()  # Identidad del usuario autenticado
    try:
        # Convertimos game_id a ObjectId
        game_object_id = ObjectId(game_id)
    except:
        return jsonify({"msg": "ID de juego inválido"}), 400

    # Buscamos el juego por su _id y el usuario que lo subió
    game = mongo.db.games.find_one({"_id": game_object_id, "user_id": current_user})

    if not game:
        return jsonify({"msg": "Juego no encontrado o no pertenece al usuario"}), 404

    # Si el juego existe y pertenece al usuario, lo borramos
    result = mongo.db.games.delete_one({"_id": game_object_id})

    if result.deleted_count == 1:
        return jsonify({"msg": "Juego eliminado correctamente"}), 200
    else:
        return jsonify({"msg": "No se pudo eliminar el juego"}), 500



#Ruta para obtener los juegos de mi perfil
@app.route('/my_games', methods=['GET'])
@jwt_required()
def get_my_games():
    # Obtén el ID del usuario autenticado desde el JWT y conviértelo a string
    user_id = str(get_jwt_identity())

    # Busca todos los juegos que pertenecen a este usuario
    user_games = list(mongo.db.games.find({"user_id": user_id}))

    # Convierte el ObjectId a string para que sea serializable en JSON
    for game in user_games:
        game["_id"] = str(game["_id"])

    return jsonify({"games": user_games}), 200


#Ruta para buscar un usuario y que muestre sus juegos
@app.route('/user_games', methods=['POST'])
@jwt_required()
def user_games():
    data = request.get_json()
    username = data.get('username')

    # Buscar al usuario en la base de datos
    usuario = mongo.db.users.find_one({"username": username}, {"password": 0})

    if usuario:
        # Convertir el ObjectId del usuario a string
        user_id = str(usuario["_id"])

        # Buscar los juegos asociados al user_id del usuario
        user_games_cursor = mongo.db.games.find({"user_id": user_id})

        # Crear una lista de juegos usando un bucle for
        games_list = []
        for game in user_games_cursor:
            # Convertir el ObjectId a string para la serialización JSON
            game["_id"] = str(game["_id"])
            # Agregar el juego a la lista
            games_list.append({
                "gamename": game["gamename"],
                "platform": game["platform"],
                "price": game["price"],
                "_id": game["_id"]
            })

        # Respuesta con la información del usuario y los juegos en formato de lista
        return jsonify({
            "msg": "Usuario y juegos encontrados",
            "Usuario": {
                "username": usuario["username"],
                "email": usuario["email"],
                "_id": user_id
            },
            "Juegos": games_list
        }), 200
    else:
        return jsonify({"msg": "Usuario no encontrado"}), 404


#Ruta para poder buscar juegos de una plataforma
@app.route('/search_by_platform', methods=['POST'])
@jwt_required()
def search_by_platform():
    data = request.get_json()
    platform = data.get('platform')

    # Convertir la plataforma en minúsculas para hacer la búsqueda insensible a mayúsculas/minúsculas
    platform_lower = platform.lower()

    # Buscar juegos donde la plataforma coincida, sin importar mayúsculas/minúsculas
    games = mongo.db.games.find({"platform": {"$regex": platform_lower, "$options": "i"}})

    # Lista para almacenar los juegos encontrados
    games_list = []
    
    for game in games:
        # Obtener el usuario que subió el juego
        user = mongo.db.users.find_one({"_id": ObjectId(game["user_id"])})
        if user:
            games_list.append({
                "_id": str(game["_id"]),
                "gamename": game["gamename"],
                "platform": game["platform"],
                "price": game["price"],
                "user": user["username"]
            })

    if games_list:
        return jsonify({"msg": f"Juegos encontrados para la plataforma {platform}", "games": games_list}), 200
    else:
        return jsonify({"msg": "No se encontraron juegos para esa plataforma"}), 404

    
#Ruta para hacer el login
@app.route('/login', methods=['POST'])
def login():
    data= request.get_json()
    email=data.get('email')
    password=data.get('password')

    user=mongo.db.users.find_one({"email": email})

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Credenciales Incorrectas"})
    




#Codigo Para que te salga feed como instagram
@app.route('/my_feed', methods=['GET'])
@jwt_required()
def my_feed():
    current_user = get_jwt_identity()  # Obtener la identidad del usuario autenticado

    # Obtener juegos de otros usuarios de forma aleatoria, limitados a 30 para tener más variedad
    other_users_games = mongo.db.games.aggregate([
        {"$match": {"user_id": {"$ne": current_user}}},  # Excluir juegos del usuario autenticado
        {"$sample": {"size": 30}}  # Obtener 30 juegos de manera aleatoria
    ])

    # Diccionario para almacenar los juegos por usuario
    user_games = {}
    for game in other_users_games:
        user_id = game["user_id"]
        if user_id not in user_games:
            user_games[user_id] = []
        user_games[user_id].append(game)

    # Crear el feed mezclando los juegos de distintos usuarios
    feed = []
    while len(feed) < 15 and user_games:
        # Obtener un usuario aleatorio y tomar uno de sus juegos
        user_id = random.choice(list(user_games.keys()))
        game = user_games[user_id].pop(0)

        # Obtener el nombre del usuario que subió el juego
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        
        if user:
            feed.append({
                "_id": str(game["_id"]),
                "gamename": game["gamename"],
                "platform": game["platform"],
                "price": game["price"],
                "user": user["username"]  # Nombre del usuario
            })

        # Si el usuario ya no tiene más juegos, eliminarlo del diccionario
        if not user_games[user_id]:
            del user_games[user_id]

    if feed:
        return jsonify({"msg": "Juegos encontrados", "feed": feed}), 200
    else:
        return jsonify({"msg": "No se encontraron juegos en el feed"}), 404
    


#Endpoint Protegido
@app.route('/datos', methods=['POST'])
@jwt_required()
def datos():
    data = request.get_json()
    username=data.get('username')

    usuario = mongo.db.users.find_one({"username": username},{"password":0})

    if usuario:
        usuario["_id"]=str(usuario["_id"])
        return jsonify({"msg": "Usuario encontrado", "Usuario": usuario}), 200
    else:
        return jsonify({"msg":"Usuario no encontrado"}), 404
    



#Endpoint para buscar un juego y que te salgan todos los publicados
@app.route('/search_game', methods=['POST'])
@jwt_required()
def search_game():
    data = request.get_json()
    gamename = data.get('gamename')

    # Buscar todos los juegos con el nombre especificado, ignorando mayúsculas/minúsculas
    games_cursor = mongo.db.games.find({"gamename": {"$regex": gamename, "$options": "i"}})

    # Crear una lista para almacenar la información de los usuarios, el precio, el nombre del juego y la plataforma
    users_list = []
    
    for game in games_cursor:
        # Obtener el user_id del juego y buscar la información del usuario
        user_id = game.get("user_id")
        usuario = mongo.db.users.find_one({"_id": ObjectId(user_id)}, {"password": 0})

        if usuario:
            # Crear un diccionario con la información del juego, usuario, plataforma y precio
            user_info = {
                "gamename": game["gamename"],
                "platform": game["platform"],
                "username": usuario["username"],
                "email": usuario["email"],
                "price": game["price"]
            }
            # Añadir la información a la lista de usuarios
            users_list.append(user_info)
    
    if users_list:
        return jsonify({
            "msg": "Juego y usuarios encontrados",
            "Resultados": users_list
        }), 200
    else:
        return jsonify({"msg": "No se encontraron usuarios para este juego"}), 404




# En Python, cada archivo tiene una variable especial llamada __name__.
# Si el archivo se está ejecutando directamente (no importado como un módulo en otro archivo), 
# __name__ se establece en '__main__'.
# Esta condición verifica si el archivo actual es el archivo principal que se está ejecutando. 
# Si es así, ejecuta el bloque de código dentro de la condición.
# app.run() inicia el servidor web de Flask.
# El argumento debug=True  inicia el servidor web de desarrollo de Flask con el modo de 
# depuración activado, # lo que permite ver errores detallados y reiniciar automáticamente
# el servidor cuando se realizan cambios en el código. (SERIA COMO EL NODEMON)
if __name__ == '__main__':
    app.run(debug=True)
