import random
import uvicorn
import numpy as np
import pandas as pd
import tensorflow as tf
import joblib
import datetime
import threading
import time
import requests
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from scapy.all import sniff, IP, TCP, ICMP, UDP

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

app = FastAPI()

# CORS Configuration
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Model resources
models = {}
label_encoders = {}
scalers = {}
features_dict = {}
base_path = os.path.dirname(os.path.abspath(__file__))
data_store = {'UNSW-NB15': [], 'CIC-IDS': []}

def log_message(message):
    timestamp = datetime.now().isoformat()
    print(f"[{timestamp}] {message}")

def load_model_resources(model_name, path_prefix):
    try:
        model_path = os.path.join(base_path, path_prefix)
        label_encoders[model_name] = joblib.load(os.path.join(model_path, "label_encoders.pkl"))
        scalers[model_name] = joblib.load(os.path.join(model_path, "scaler.pkl"))
        features_dict[model_name] = joblib.load(os.path.join(model_path, "features.pkl"))
        models[model_name] = tf.keras.models.load_model(os.path.join(model_path, "model.h5"))
        log_message(f"{model_name} resources loaded")
    except Exception as e:
        log_message(f"Error loading {model_name}: {e}")
        exit()

# Load both models
load_model_resources('UNSW-NB15', 'UNSW-NB15')
load_model_resources('CIC-IDS', 'CIC_IDS')

class TrafficData(BaseModel):
    features: dict
    model_name: str = None  


def safe_transform(model_name, encoder, value):
    if value in encoder.classes_:
        return encoder.transform([value])[0]
    default_value = encoder.classes_[0]
    log_message(f"Unknown value '{value}', using default '{default_value}'")
    return encoder.transform([default_value])[0]

def validate_features(input_dict, feature_list):
    missing_features = [f for f in feature_list if f not in input_dict]
    for f in missing_features:
        input_dict[f] = 0
    if missing_features:
        #log_message(f"Missing features: {missing_features}")
        log_message("There are Missing Features")
    return input_dict

@app.post("/predict")
async def predict_traffic(data: TrafficData):
    input_dict = data.features
    predictions = {}
    
    # Determine which models to process
    target_models = []
    if data.model_name:
        if data.model_name in ['UNSW-NB15', 'CIC-IDS']:
            target_models.append(data.model_name)
        else:
            return {"error": "Invalid model name specified"}
    else:
        target_models = ['UNSW-NB15', 'CIC-IDS']  # Default to both if not specified

    for model_name in target_models:  # Only process specified models
        try:
            input_dict_valid = validate_features(input_dict.copy(), features_dict[model_name])

            # Handle categorical features
            for feature in ["proto", "service", "state", "attack_cat"]:
                if feature in input_dict_valid and feature in label_encoders[model_name]:
                    input_dict_valid[feature] = safe_transform(
                        model_name, 
                        label_encoders[model_name][feature], 
                        input_dict_valid.get(feature, "unknown")
                    )

            # Prepare input data
            input_df = pd.DataFrame([[float(input_dict_valid[f]) for f in features_dict[model_name]]],
                                   columns=features_dict[model_name])
            input_data = scalers[model_name].transform(input_df)
            input_data = input_data.reshape(1, len(features_dict[model_name]), 1)

            # Make prediction
            model_output = models[model_name].predict(input_data)[0]
            predicted_class = "Attack" if model_output[1] > 0.7 else "Benign"
            
            prediction = {
                "model_name": model_name,
                "timestamp": datetime.now().isoformat(),
                "anomaly_score": float(model_output[1]),
                "message": predicted_class,
                "alert": predicted_class == "Attack"
            }

            data_store[model_name].append(prediction)
            if len(data_store[model_name]) > 50:
                data_store[model_name].pop(0)

            predictions[model_name] = prediction

        except Exception as e:
            log_message(f"Prediction error for {model_name}: {e}")
            return {"error": f"Prediction failed for {model_name}"}

    return {"Predictions": predictions}

@app.get("/api/ids-data")
async def get_ids_data():
    return {"data": data_store}

@app.get("/api/system-status")
async def get_system_status():
    return {"status": "Running"}

# Fake data generation components
class CSVDataReader:
    def __init__(self, csv_path):
        self.data = pd.read_csv(csv_path)
        log_message(f"Loaded {len(self.data)} samples from {csv_path}")
        self.index = 0

    def get_next_sample(self):
        if self.index >= len(self.data):
            self.index = 0
        sample = self.data.iloc[self.index].to_dict()
        self.index += 1
        return sample

def generate_fake_data():
    def send_to_endpoint(features, model_name):
        try:
            response = requests.post(
                "http://127.0.0.1:8000/predict",
                json={
                    "features": features,
                    "model_name": model_name  # Specify target model
                }
            )
            if response.status_code == 200:
                log_message(f"{model_name} prediction sent")
        except Exception as e:
            log_message(f"Send error: {e}")

    def generate_cic_data():
        data_reader = CSVDataReader("Attack.csv")
        time.sleep(2)
        while True:
            try:
                sample = data_reader.get_next_sample()
                send_to_endpoint(sample, "CIC-IDS")
                time.sleep(1)
            except Exception as e:
                log_message(f"CIC data error: {e}")
                time.sleep(5)

    def generate_unsw_data():
        time.sleep(2)
        while True:
            try:
                valid_services = label_encoders["UNSW-NB15"]['service'].classes_.tolist()
                valid_states = label_encoders["UNSW-NB15"]['state'].classes_.tolist()
                valid_attack_cats = label_encoders["UNSW-NB15"]['attack_cat'].classes_.tolist()

                fake_features = {
                    "service": random.choice(valid_services),
                    "state": random.choice(valid_states),
                    "attack_cat": random.choice(valid_attack_cats) if random.random() < 0.3 else "normal",
                    "dur": random.uniform(0, 1000),
                    "spkts": random.randint(1, 100),
                    "dpkts": random.randint(1, 100),
                    "sbytes": random.randint(1, 1000),
                    "dbytes": random.randint(1, 1000),
                }
                send_to_endpoint(fake_features, "UNSW-NB15")
                time.sleep(1.5)
            except Exception as e:
                log_message(f"UNSW data error: {e}")
                time.sleep(5)

    threading.Thread(target=generate_cic_data, daemon=True).start()
    threading.Thread(target=generate_unsw_data, daemon=True).start()

# Define default values for missing features
DEFAULT_FEATURES = {
    'dur': 0.0, 'spkts': 0, 'dpkts': 0, 'sbytes': 0, 'dbytes': 0, ' Destination Port': 0, ' Flow Duration': 0, ' Total Fwd Packets': 0, ' Total Backward Packets': 0, 'Total Length of Fwd Packets': 0, ' Total Length of Bwd Packets': 0, ' Fwd Packet Length Max': 0, 
    ' Fwd Packet Length Min': 0, ' Fwd Packet Length Mean': 0, ' Fwd Packet Length Std': 0, 'Bwd Packet Length Max': 0, ' Bwd Packet Length Min': 0, ' Bwd Packet Length Mean': 0, ' Bwd Packet Length Std': 0, 'Flow Bytes/s': 0,
    ' Flow Packets/s': 0, ' Flow IAT Mean': 0, ' Flow IAT Std': 0, ' Flow IAT Max': 0, ' Flow IAT Min': 0, 'Fwd IAT Total': 0, ' Fwd IAT Mean': 0, ' Fwd IAT Std': 0, ' Fwd IAT Max': 0, ' Fwd IAT Min': 0, 'Bwd IAT Total': 0, ' Bwd IAT Mean': 0, ' Bwd IAT Std': 0, 
    ' Bwd IAT Max': 0, ' Bwd IAT Min': 0, 'Fwd PSH Flags': 0, ' Bwd PSH Flags': 0, ' Fwd URG Flags': 0, ' Bwd URG Flags': 0, ' Fwd Header Length': 0, ' Bwd Header Length': 0, 'Fwd Packets/s': 0, ' Bwd Packets/s': 0, ' Min Packet Length': 0, ' Max Packet Length': 0, 
    ' Packet Length Mean': 0, ' Packet Length Std': 0, ' Packet Length Variance': 0, 'FIN Flag Count': 0, ' SYN Flag Count': 0, ' RST Flag Count': 0, ' PSH Flag Count': 0, ' ACK Flag Count': 0, ' URG Flag Count': 0, ' CWE Flag Count': 0, 
    ' ECE Flag Count': 0, ' Down/Up Ratio': 0, ' Average Packet Size': 0, ' Avg Fwd Segment Size': 0, ' Avg Bwd Segment Size': 0, ' Fwd Header Length.1': 0, 'Fwd Avg Bytes/Bulk': 0, ' Fwd Avg Packets/Bulk': 0, ' Fwd Avg Bulk Rate': 0, ' Bwd Avg Bytes/Bulk': 0, 
    ' Bwd Avg Packets/Bulk': 0, 'Bwd Avg Bulk Rate': 0, 'Subflow Fwd Packets': 0, ' Subflow Fwd Bytes': 0, ' Subflow Bwd Packets': 0, ' Subflow Bwd Bytes': 0, 'Init_Win_bytes_forward': 0,
    ' Init_Win_bytes_backward': 0, ' act_data_pkt_fwd': 0, ' min_seg_size_forward': 0, 'Active Mean': 0, ' Active Std': 0, ' Active Max': 0, ' Active Min': 0, 'Idle Mean': 0, ' Idle Std': 0, ' Idle Max': 0, ' Idle Min': 0,
    'rate': 0.0, 'sttl': 0, 'dttl': 0, 'sload': 0.0, 'dload': 0.0, 'sloss': 0, 'dloss': 0, 'sinpkt': 0, 'dinpkt': 0, 'sjit': 0, 'djit': 0, 'swin': 0, 'stcpb': 0, 'dtcpb': 0, 'dwin': 0, 'tcprtt': 0, 'synack': 0, 'ackdat': 0,
    'smean': 0, 'dmean': 0, 'trans_depth': 0, 'response_body_len': 0, 'ct_srv_src': 0, 'ct_state_ttl': 0, 'ct_dst_ltm': 0, 'ct_src_dport_ltm': 0, 'ct_dst_sport_ltm': 0, 'ct_dst_src_ltm': 0, 'is_ftp_login': 0, 'ct_ftp_cmd': 0, 'ct_flw_http_mthd': 0, 'ct_src_ltm': 0, 'ct_srv_dst': 0, 'is_sm_ips_ports': 0
}

# Extract features from a packet and prepare for prediction
def extract_packet_features(packet):
    features = {
        'proto': packet.proto,
        'service': "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Unknown",
        'state': "Unknown",  
        'attack_cat': "Benign",  
        'dur': packet.time,  
        'spkts': packet.sport if TCP in packet or UDP in packet else 0,  
        'dpkts': packet.dport if TCP in packet or UDP in packet else 0,  
        'sbytes': len(packet),  
        'dbytes': len(packet)   
    }

    # Handle protocol values
    if features['proto'] == 17 or features['proto'] == 6:
        features['service'] = 'UDP'

    # Add missing features and set unknown values
    for feature, default_value in DEFAULT_FEATURES.items():
        if feature not in features:
            features[feature] = default_value
    
    # Handle unknown protocol or values
    if features['service'] == 'TCP':
        features['service'] = '-'
    if features['state'] == 'Unknown':
        features['state'] = 'CON'
    if features['attack_cat'] == 'Benign':
        features['attack_cat'] = 'Analysis'

    return features

# Define the callback function for sniffing packets and sending data to the prediction API
def packet_callback(packet):
    if IP in packet:
        features = extract_packet_features(packet)
        # Send data for prediction
        try:
            response = requests.post("http://127.0.0.1:8000/predict", json={"features": features})
            if response.status_code == 200:
                print(response.json())  # Display the prediction result
            else:
                print(f"Error with prediction response: {response.status_code}")
        except Exception as e:
            print(f"Error in sending data to the prediction API: {str(e)}")


# Start packet sniffer and background processor
def start_packet_sniffer():
    sniff(prn=packet_callback, store=0)

@app.on_event("startup")
async def startup_event():
    log_message("Starting fake data generation")
    generate_fake_data()

    # Uncomment the following lines to start the packet sniffer VVV
    #print("Starting packet sniffer...")
    #threading.Thread(target=start_packet_sniffer, daemon=True).start()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)