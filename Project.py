import paho.mqtt.client as mqtt
import json
import time

class MQTTClient:
    def __init__(self, broker="localhost", port=1883):
        self.mqtt_broker = broker
        self.mqtt_port = port
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        
    def connect(self):
        try:
            self.mqtt_client.connect(self.mqtt_broker, self.mqtt_port, 60)
            self.mqtt_client.loop_start()
            print(f"Connected to MQTT broker at {self.mqtt_broker}:{self.mqtt_port}")
        except Exception as e:
            print(f"Failed to connect to MQTT broker: {str(e)}")
            
    def disconnect(self):
        self.mqtt_client.loop_stop()
        self.mqtt_client.disconnect()
        print("Disconnected from MQTT broker")
        
    def publish(self, topic, message):
        try:
            if isinstance(message, dict):
                message = json.dumps(message)
            self.mqtt_client.publish(topic, message)
            print(f"Published message to {topic}")
        except Exception as e:
            print(f"Failed to publish message: {str(e)}")
            
    def subscribe(self, topic):
        try:
            self.mqtt_client.subscribe(topic)
            print(f"Subscribed to {topic}")
        except Exception as e:
            print(f"Failed to subscribe to {topic}: {str(e)}")
            
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("Connected to MQTT broker successfully")
        else:
            print(f"Failed to connect to MQTT broker with code: {rc}")
            
    def on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode()
            print(f"Received message on {msg.topic}: {payload}")
            # Add your message handling logic here
        except Exception as e:
            print(f"Error processing message: {str(e)}")
            
    def on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print("Unexpected disconnection. Attempting to reconnect...")
        else:
            print("Disconnected from MQTT broker")

# Example usage
if __name__ == "__main__":
    # Create MQTT client instance
    client = MQTTClient(broker="localhost", port=1883)
    
    # Connect to broker
    client.connect()
    
    # Subscribe to a topic
    client.subscribe("test/topic")
    
    # Publish a message
    client.publish("test/topic", {"message": "Hello, MQTT!"})
    
    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping MQTT client...")
        client.disconnect() 