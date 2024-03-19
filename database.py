from pymongo import MongoClient
import certifi

MONGO_URI = 'mongodb+srv://diazhernandezjosue:fS1nZCwMcZ4kIvbO@cluster0.adyhu6v.mongodb.net/?retryWrites=true&w=majority'

ca = certifi.where()


def dbConnection():
    try:
        client = MongoClient(MONGO_URI, tlsCAFile=ca)
        db = client["QuariumDB"]
    except ConnectionError:
        print('Error de conexión con la BD')
    return db
