import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
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
        aes_key = get_random_bytes(16)
        PRIVATE_KEYS[payload_list[1]] = aes_key
        cipher = PKCS1_OAEP.new(pubRsaKey)
        aes_encrypted = cipher.encrypt(aes_key)
        message = base64.b64encode(aes_encrypted).decode('utf-8')
        message = "2+"+LOCAL_IP+"+"+message
        print(message)
        MQTT_CONS[payload_list[1]]["MQTT"].publish("incoming/", message)
        IS_READY[payload_list[1]] = True
    if(payload_list[0] == "2"):
        # print(PRIVATE_KEYS)
        encryptedAesKey = payload_list[2]
        cipherRsa = PKCS1_OAEP.new(PRIVATE_KEYS[payload_list[1]])
        encryptedAesKey = base64.b64decode(encryptedAesKey)
        aesKey = cipherRsa.decrypt(encryptedAesKey)
        print(base64.b64encode(aesKey).decode('utf-8'))
        PRIVATE_KEYS[payload_list[1]] = base64.b64encode(aesKey).decode('utf-8')
        IS_READY[payload_list[1]] = True

    if(payload_list[0] == "3"):
        json_message = json.loads(payload_list[2])
        print(json_message)
        ciphertext = base64.b64decode(json_message['ciphertext'])
        nonce = base64.b64decode(json_message['nonce'])
        tag = base64.b64decode(json_message['tag'])
        cipher_aes = AES.new(PRIVATE_KEYS[payload_list[1]].encode("utf-8"), AES.MODE_EAX, nonce)
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print (payload_list[1]+":", decrypted_message.decode('utf-8'))


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
            cipher = AES.new(PRIVATE_KEYS[ip].encode("utf8"), AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
            message = {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
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


