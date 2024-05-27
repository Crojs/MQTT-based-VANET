import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import paho.mqtt.client as mqtt


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("device2/")


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    payload = msg.payload.decode("utf-8")
    print(msg.topic+" "+payload[:2])
    if(payload[:2] == "1+"):
        
        publicKey = payload[2:]
        publicKey = "ssh-rsa " + publicKey
        pubRsaKey = RSA.import_key(publicKey)
        aesKey = get_random_bytes(16)
        cipher = PKCS1_OAEP.new(pubRsaKey)
        print("Symetric Key:", base64.b64encode(aesKey).decode('utf-8'))
        aesEncrypted = cipher.encrypt(aesKey)
        message = base64.b64encode(aesEncrypted).decode('utf-8')
        message = "2+"+message
        mqttc.publish("device1/", message)

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.on_connect = on_connect
mqttc.on_message = on_message

mqttc.connect("127.0.0.1", 1883, 60)

# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
mqttc.loop_forever()
