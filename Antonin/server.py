# coding: utf-8

import socket
import sqlite3
import sys
from Cryptodome.Cipher import AES
import hashlib
import random
import string

##################################
##### Fonctions Génériques #######
##################################

def GenerationChaineTailleFixe(length):
    
    tabCarac = string.ascii_lowercase
    return ''.join(random.choice(tabCarac) for i in range(length))


def CloseAllSockets(client,socketResponse,socketListen,conn):
    client.close()
    socketResponse.close()
    socketListen.close()
    conn.close()


##################################
######## Fonctions DB ############
##################################

def CreateDatabase(conn,cursor):
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
                id_user TEXT PRIMARY KEY UNIQUE NOT NULL,
                mdp_user TEXT NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages(
            id_msg INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
            id_user TEXT NOT NULL,
            msg TEXT NOT NULL,
            nonce TEXT NOT NULL,
            tag TEXT NOT NULL,
            FOREIGN KEY(id_user) REFERENCES users(id_user)
        )
    """)

    conn.commit()


def InsertAccounts(conn,cursor):
    try:
        cursor.execute("INSERT INTO users(id_user, mdp_user) VALUES(?, ?)", ("server", "c97bb059bd3c9125077c43ece1728879fda9669ffa7ae861fe83a8a812fc410f"));
        cursor.execute("INSERT INTO users(id_user, mdp_user) VALUES(?, ?)", ("client", "6518c3acb645d9a7e1b8acea6c394845bd48cec028f99ce4039f05db1329eaf6"));
        conn.commit()
    except:
        # Base de donnée déjà existante
        pass


def InsertMessage(conn,cursor,id_user,encryptedMessage,nonce,tag):
    try:
        data = {"id_user": id_user,"message": encryptedMessage,"nonce": nonce,"tag":tag}
        cursor.execute("""
        INSERT INTO messages(id_user, msg, nonce, tag) VALUES(:id_user, :message, :nonce, :tag)""", data);
        conn.commit()
    except Exception:
        conn.rollback()


##################################
##### Fonctions Chiffrage ########
##################################

def EncryptAES(keyAES,message):
    cipher = AES.new(keyAES,AES.MODE_GCM)
    nonce = cipher.nonce
    listenEncrypted, tag = cipher.encrypt_and_digest(message)
    
    return [listenEncrypted, nonce, tag]



def DecryptAES(keyAES,encryptedMessage,nonce,tag):
    cipher = AES.new(keyAES,AES.MODE_GCM,nonce)
    messageDecrypted = cipher.decrypt_and_verify(encryptedMessage,tag)
    return messageDecrypted


##################################
## Fonctions liés aux messages ###
##################################

def TraitementMessageCrypteRecu(client,socketResponse,keyAES,conn,cursor,id_user):
    
    # Reception du message chiffré
    encryptedMessage = client.recv(256)
    socketResponse.send(bytes("ok",'mac_roman'))
    nonce = client.recv(16)
    
    socketResponse.send(bytes("ok",'mac_roman'))
    tag = client.recv(16)

    # stockage du message chiffré dans la base de données
    InsertMessage(conn,cursor,id_user,encryptedMessage,nonce,tag)
    
    # Déchiffrement du message pour l'afficher
    messageDecrypted = DecryptAES(keyAES,encryptedMessage,nonce,tag) 
    return messageDecrypted.decode("UTF-8")


def EnvoiMessageCrypte(client,socketResponse,keyAES,message,conn,cursor,id_user):
    
    #Chiffrage du message
    ByteMessage = bytes(message,'mac_roman')
    encryptedMessageInfos = EncryptAES(keyAES,ByteMessage)
    encryptedMessage = encryptedMessageInfos[0]
    nonce = encryptedMessageInfos[1]
    tag = encryptedMessageInfos[2]
    
    # Envoi du message chiffré
    socketResponse.send(encryptedMessage)
    client.recv(15)
    socketResponse.send(nonce)
    client.recv(15)
    socketResponse.send(tag)

    # Ajout du message chiffré dans la base de données
    InsertMessage(conn,cursor,id_user,encryptedMessage,nonce,tag)


def HistoricDisplay(keyAES,conn,cursor):
    cursor.execute("""
    SELECT * FROM messages""")
    messageEncryptedTab = cursor.fetchall()
    for message in messageEncryptedTab:
        id_user = message[1]
        messageEncrypted = bytes(message[2])
        nonce = bytes(message[3])
        tag = bytes(message[4])
        try:
            messageDecrypted = DecryptAES(keyAES,messageEncrypted,nonce,tag)
            print("{} >> {}".format(id_user, messageDecrypted.decode("UTF8")))
        except:
            pass


###########################################
### Fonctions liés à l'authentification ###
###########################################

def VerificationMDPLocal(conn,cursor,mdpInput,salt_server,id_user_local):

    # Récupération du mdp + sel hashé en SHA256 dans la bdd
    data = {"id_user_local" : id_user_local}
    cursor.execute("""
    SELECT mdp_user FROM users WHERE id_user=:id_user_local""",data)
    mdpHashed = cursor.fetchone()[0]

    # hashage du mot de passe donné en input + sel avec SHA256
    mdpSaltInput = mdpInput+salt_server
    mdpSaltBDD = hashlib.sha256(bytes(mdpSaltInput,'mac_roman')).hexdigest()        

    # Retourne vrai si les deux mots de passe hachés sont identiques
    return mdpSaltBDD == mdpHashed



def SendChallenge(conn,cursor,client,socketResponse,id_user_client):
    chaineAleatoire = GenerationChaineTailleFixe(4)

    # Calcul de H' = SHA256(mdpHashed+chaineAleatoire)
    data = {"id_user_client" : id_user_client}
    cursor.execute("""
    SELECT mdp_user FROM users WHERE id_user=:id_user_client""",data)
    mdpHashed = cursor.fetchone()[0]

    hashToCompareServer = hashlib.sha256(bytes(mdpHashed+chaineAleatoire,'mac_roman')).hexdigest()  

    # Envoi du Challenge
    socketResponse.send(bytes(chaineAleatoire,'mac_roman'))
    
    # Récupération de la réponse au challenge
    hashToCompareClient = client.recv(256).decode('mac_roman')
    socketResponse.send(bytes(hashToCompareServer,'mac_roman'))
    return hashToCompareClient == hashToCompareServer    



def ReceveChallenge(conn,cursor,client,socketResponse,id_user_local):
    
    print("client : Authentification auprès de l'hote distant...")

    chaineAleatoire = client.recv(32).decode('mac_roman')

    # Calcul de H' = SHA256(mdpHashed+chaineAleatoire)
    data = {"id_user_local" : id_user_local}
    cursor.execute("""
    SELECT mdp_user FROM users WHERE id_user=:id_user_local""",data)
    mdpHashed = cursor.fetchone()[0]

    hashToCompareServer = hashlib.sha256(bytes(mdpHashed+chaineAleatoire,'mac_roman')).hexdigest()  

    
    socketResponse.send(bytes(hashToCompareServer,'mac_roman'))

    return client.recv(256).decode('mac_roman') == hashToCompareServer

############################
####### Constantes #########
############################

hoteLocal = "localhost"
hoteDistant = "localhost"
portEnvoi = 15556
portReception = 15555
id_user_local = "server"
id_user_client = "client"
keyAES = b'00000010100000010000001010000001'


# Variables pour mot de passe local
salt_server = 'bNwjpg2cZS9LboteeA9nDUUgNnciHPsO8RygbyJw'
# mdp + sel hashé en sha256 : c97bb059bd3c9125077c43ece1728879fda9669ffa7ae861fe83a8a812fc410f


# Generation de la base de données
conn = sqlite3.connect('database-server.db')
cursor = conn.cursor()
CreateDatabase(conn,cursor)
InsertAccounts(conn,cursor)

try:   
    print("\n#####################################")
    print("##### Mise en place des sockets #####")
    print("#####################################\n")

    # Socket d'écoute
    socketListen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketListen.bind((hoteLocal, portReception))
    socketListen.listen(1)
    print("server : J'écoute à l'adresse {} sur le port {}".format(hoteLocal, portReception))
    client, address = socketListen.accept()
    print("server : Le client s'est correctement connecté")

    # socket d'envoi
    socketResponse = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketResponse.connect((hoteDistant,portEnvoi))
    print("server : Connexion à l'adresse {} sur le port {}".format(hoteDistant, portEnvoi))

    


    print("\n#####################################")
    print("##### Phase d'authentification ######")
    print("#####################################\n")

    # Authentification du client
    print("server : Tentative d'authentification du client, envoi d'un challenge")
    if SendChallenge(conn,cursor,client,socketResponse,id_user_client):
        print("server : Challenge réussi, client authentifié")
    else:
        print("server : Echec d'authentification du client")
        sys.exit()


    # Authentification du client auprès du server
    mdpInput = input('Mot de passe : ')
    while VerificationMDPLocal(conn,cursor,mdpInput,salt_server,id_user_local) == False:
        print("server : Mauvais mot de passe, réessayez")
        mdpInput = input('\nMot de passe : ') 

    # Authentification du server auprès du client
    print("\nserver : Tentative d'authentification du client, envoi d'un challenge...")
    if ReceveChallenge(conn,cursor,client,socketResponse,id_user_local):
        print("server : Challenge réussi, serveur authentifié auprès du client")
    else:
        print("server : Echec d'authentification du server auprès du client")
        sys.exit()



    print("\n#####################################")
    print("### Historique des communications ###")
    print("#####################################\n")
    HistoricDisplay(keyAES,conn,cursor)
    
    
    print("\nserver : Historique affiché, nous pouvons commencer à communiquer\n")
    socketResponse.send(bytes("Historique affiché, nous pouvons commencer à communiquer\n",'mac_roman'))
    
    while True:
        
        listenStr = TraitementMessageCrypteRecu(client,socketResponse,keyAES,conn,cursor,id_user_client)
        
        if len(listenStr) == 0:
            CloseAllSockets(client,socketResponse,socketListen,conn)
            break
        print("client >> "+listenStr)

             
        response = input('server >> ')
        while len(response) > 256:
            print("Message trop long (limite 256 caractères)") 
            response = input('server >> ')
        EnvoiMessageCrypte(client,socketResponse,keyAES,response,conn,cursor,id_user_local)
            
   
except:
    print("Unexpected error:", sys.exc_info()[0])
finally:
    CloseAllSockets(client,socketResponse,socketListen,conn)
