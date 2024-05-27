import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from base64 import b64encode
import paho.mqtt.client as mqtt
import socket
import netifaces as ni
import threading
import json

DEVICE_ID = "DEVICE 1"
DEVICE_IPs = ["192.168.1.3", "192.168.1.2", "192.168.1.1"]
# DEVICE_IPs = ["192.168.1.1", "192.168.1.3"]

hostname = socket.gethostname()
LOCAL_IP = ni.ifaddresses('wlp3s0')[ni.AF_INET][0]['addr']
print("Device ID:", DEVICE_ID)
print("LOCAL IP:", LOCAL_IP)


MQTT_CONS = {}
PRIVATE_KEYS = {}
PUBLIC_KEYS = {}
IS_READY = {}

def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    client.subscribe("incoming/")
    print("subscribing to incoming/")


def on_message(client, userdata, msg):
    print()
    payload = msg.payload.decode("utf-8")
    print(msg.topic, payload)
    payload_list = payload.split('+', 2)

    if(payload_list[0] == "1"):
        publicKey = payload_list[2]
        publicKey = "ssh-rsa " + publicKey
        # print(publicKey)
        pubRsaKey = RSA.import_key(publicKey)
        PUBLIC_KEYS[payload_list[1]] = pubRsaKey
        
        privateKey = RSA.generate(1024)
        PRIVATE_KEYS[ip] = privateKey
        
        # Generate a new RSA key pair
        publicKey = privateKey.publickey()
        decoded_key = publicKey.exportKey("OpenSSH").decode('utf-8')[8:]
        message = "2+"+LOCAL_IP+"+"+decoded_key
        print(message)
        MQTT_CONS[payload_list[1]]["MQTT"].publish("incoming/", message)
        IS_READY[payload_list[1]] = True
        print(payload_list[1], "Ready")
    if(payload_list[0] == "2"):
        publicKey = payload_list[2]
        publicKey = "ssh-rsa " + publicKey
        pubRsaKey = RSA.import_key(publicKey)
        PUBLIC_KEYS[payload_list[1]] = pubRsaKey
        
        IS_READY[payload_list[1]] = True
        print(payload_list[1], "Ready")

    if(payload_list[0] == "3"):
        json_message = json.loads(payload_list[2])
        print(json_message)
        ciphertext = base64.b64decode(json_message['ciphertext'])
        signature = base64.b64decode(json_message['signature'])
        cipher_rsa = PKCS1_OAEP.new(PRIVATE_KEYS[payload_list[1]])
        decrypted = cipher_rsa.decrypt(ciphertext)
        
        hash = SHA256.new(decrypted)
        verifier = PKCS115_SigScheme(PUBLIC_KEYS[payload_list[1]])
        try:
            verifier.verify(hash, signature)
            print (payload_list[1]+":", decrypted.decode('utf-8'))
        except:
            print("Signature is invalid.")


threads = []
def job(MQTT_CONS, ip):
    try:
        MQTT_CONS[ip]["MQTT"].loop_forever()
    except Exception as e:
        print(e)

def publish_message_job(MQTT_CONS, ip):
    while True:
        user_input = input("Enter [ip] [message]")
        ip, message = user_input.split(" ", 1)
        if(IS_READY[ip]) == True:
            # ENCRYPT
            cipher_rsa = PKCS1_OAEP.new(PUBLIC_KEYS[ip])
            encrypted = cipher_rsa.encrypt(base64.b64decode(message))
            # DIGITAL SIGNATURE
            hash = SHA256.new(base64.b64decode(message))
            signer = PKCS115_SigScheme(PRIVATE_KEYS[ip])
            signature = signer.sign(hash)

            message = {
                'ciphertext': base64.b64encode(encrypted).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8')
            }

            MQTT_CONS[ip]["MQTT"].publish("incoming/", "3+"+LOCAL_IP+"+"+json.dumps(message))
        else:
            print("Host not yet ready")


t = threading.Thread(target = job)

for i, ip in enumerate(DEVICE_IPs):
    print(ip)
    IS_READY[ip] = False
    try:
        MQTT_CONS[ip] = {}
        MQTT_CONS[ip]["MQTT"] = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        if(ip == LOCAL_IP):
            print("Listening")
            MQTT_CONS[ip]["MQTT"].on_connect = on_connect
            MQTT_CONS[ip]["MQTT"].on_message = on_message
        MQTT_CONS[ip]["MQTT"].connect(ip, 1883, 60)

        # if(ip != LOCAL_IP):
        print("publishing to", ip)
        privateKey = RSA.generate(1024)
        PRIVATE_KEYS[ip] = privateKey
        # Generate a new RSA key pair
        
        publicKey = privateKey.publickey()
        decoded_key = publicKey.exportKey("OpenSSH").decode('utf-8')[8:]
        message = "1+"+LOCAL_IP+"+"+decoded_key
        print(message)

        
        threads.append(threading.Thread(target = job, args = (MQTT_CONS, ip)))
        threads[i].start()
        MQTT_CONS[ip]["MQTT"].publish("incoming/", message)
    except Exception as e:
        print("error", e)


publish_thread = threading.Thread(target = publish_message_job, args = (MQTT_CONS, ip))
publish_thread.start()

# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
# mqttc.loop_start()


