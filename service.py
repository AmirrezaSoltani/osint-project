import asyncio
import websockets
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
import xgboost as xgb
from datetime import datetime
import warnings
import nest_asyncio
import platform
import os
from typing import Set

warnings.filterwarnings('ignore')
nest_asyncio.apply()

class NetworkAnalyzer:
    # ... [Previous NetworkAnalyzer class implementation remains the same]
    def __init__(self):
        self.label_encoders = {
            'category': LabelEncoder(),
            'subcategory': LabelEncoder()
        }
        self.standard_scaler = StandardScaler()
        self.service_encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.model = None
        self.event_type_map = {'Info': 0, 'Warning': 1, 'Error': 2}

    def preprocess_data(self, data):
        try:
            df = pd.DataFrame(data)
            
            df['EventType'] = df['conn_state'].map(lambda x: 
                'Error' if x in ['REJECTED', 'FAILED'] 
                else 'Warning' if x in ['TIMEOUT', 'CLOSED'] 
                else 'Info')
            
            df['EventType'] = df['EventType'].map(self.event_type_map)
            
            df['category'] = df['service'].fillna('unknown')
            df['subcategory'] = df['conn_state'].fillna('unknown')
            
            for col in ['category', 'subcategory']:
                if len(df[col].unique()) > 0:  
                    self.label_encoders[col].fit(df[col])
                    df[col] = self.label_encoders[col].transform(df[col])
            
            df['service'] = df['service'].fillna('unknown')
            service_features = self.service_encoder.fit_transform(df[['service']].values)
            service_feature_names = [f'service_{i}' for i in range(service_features.shape[1])]
            df_services = pd.DataFrame(service_features, columns=service_feature_names, index=df.index)
            
            numerical_features = ['duration', 'orig_pkts', 'orig_bytes']
            df[numerical_features] = self.standard_scaler.fit_transform(
                df[numerical_features].fillna(0))
            
            features = pd.concat([
                df[['EventType', 'category', 'subcategory', 'duration', 
                    'orig_pkts', 'orig_bytes']],
                df_services
            ], axis=1)
            
            return features
            
        except Exception as e:
            print(f"Error preprocessing data: {str(e)}")
            return None

    def calculate_anomaly_score(self, features):
        try:
            coefficients = {
                'EventType': -0.015,
                'category': 0.012,
                'subcategory': 0.008,
                'duration': 0.007,
                'orig_pkts': 0.005,
                'orig_bytes': 0.005,
                'service': 0.003
            }
            
            score = (
                features['EventType'] * coefficients['EventType'] +
                features['category'] * coefficients['category'] +
                features['subcategory'] * coefficients['subcategory'] +
                features['duration'] * coefficients['duration'] +
                features['orig_pkts'] * coefficients['orig_pkts'] +
                features['orig_bytes'] * coefficients['orig_bytes']
            )
            
            service_cols = [col for col in features.columns if col.startswith('service_')]
            service_contribution = features[service_cols].sum(axis=1) * coefficients['service']
            score += service_contribution
            
            score = (score - score.min()) / (score.max() - score.min() + 1e-10)
            
            return score
            
        except Exception as e:
            print(f"Error calculating anomaly score: {str(e)}")
            return None

class WebSocketServer:
    def __init__(self):
        self.connected_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.analyzer = NetworkAnalyzer()

    async def register(self, websocket: websockets.WebSocketServerProtocol):
        """Register a new client connection"""
        self.connected_clients.add(websocket)
        print(f"[{datetime.now()}] New client connected. Total clients: {len(self.connected_clients)}")

    async def unregister(self, websocket: websockets.WebSocketServerProtocol):
        """Unregister a client connection"""
        self.connected_clients.remove(websocket)
        print(f"[{datetime.now()}] Client disconnected. Total clients: {len(self.connected_clients)}")

    async def broadcast(self, message: str):
        """Broadcast message to all connected clients"""
        if self.connected_clients:
            await asyncio.gather(
                *[client.send(message) for client in self.connected_clients],
                return_exceptions=True
            )

    async def handle_client(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Handle individual client connections"""
        await self.register(websocket)
        try:
            await websocket.send(json.dumps({
                'type': 'connection_established',
                'message': 'Connected to Network Analyzer'
            }))
            
            while True:
                try:
                    # Keep connection alive
                    await asyncio.sleep(1)
                except:
                    break
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)

    async def start_server(self, host: str = '0.0.0.0', port: int = 8000):
        """Start the WebSocket server"""
        async with websockets.serve(self.handle_client, host, port):
            print(f"[{datetime.now()}] WebSocket server running on ws://{host}:{port}")
            await self.process_network_data()

    async def process_network_data(self):
        """Process network data and broadcast results"""
        data_uri = "wss://osint.amirrezasoltani.ir/"
        
        while True:
            try:
                async with websockets.connect(data_uri) as websocket:
                    print(f"[{datetime.now()}] Connected to data source")
                    
                    while True:
                        try:
                            data = await websocket.recv()
                            connections = json.loads(data)['connections']
                            
                            if connections:
                                features = self.analyzer.preprocess_data(connections)
                                
                                if features is not None:
                                    scores = self.analyzer.calculate_anomaly_score(features)
                                    
                                    if scores is not None:
                                        results = pd.DataFrame({
                                            'timestamp': [conn['ts'] for conn in connections],
                                            'source': [f"{conn['id.orig_h']}:{conn['id.orig_p']}" 
                                                     for conn in connections],
                                            'destination': [f"{conn['id.resp_h']}:{conn['id.resp_p']}" 
                                                          for conn in connections],
                                            'service': [conn['service'] for conn in connections],
                                            'anomaly_score': scores
                                        })
                                        
                                        results['label'] = results['anomaly_score'].apply(
                                            lambda x: 'Malicious' if x >= 0.8 else 'Benign'
                                        )
                                        
                                        vis_data = {
                                            'timestamp': datetime.now().isoformat(),
                                            'summary': {
                                                'avg_score': float(scores.mean()),
                                                'max_score': float(scores.max()),
                                                'malicious_count': int(results[results['label'] == 'Malicious'].shape[0]),
                                                'benign_count': int(results[results['label'] == 'Benign'].shape[0]),
                                                'total_connections': len(scores)
                                            },
                                            'top_anomalies': results.nlargest(10, 'anomaly_score').to_dict('records')
                                        }
                                        
                                        await self.broadcast(json.dumps(vis_data))
                                        
                                        os.system('cls' if os.name == 'nt' else 'clear')
                                        print(f"\n[{datetime.now()}] Analysis Results:")
                                        print("-" * 80)
                                        print(f"Connected Clients: {len(self.connected_clients)}")
                                        print("Top 10 Potential Anomalies:")
                                        print(results.nlargest(10, 'anomaly_score').to_string())
                                        print("\nSummary Statistics:")
                                        print(f"Average Anomaly Score: {scores.mean():.3f}")
                                        print(f"Max Anomaly Score: {scores.max():.3f}")
                                        print(f"Malicious Connections: {vis_data['summary']['malicious_count']}")
                                        print(f"Benign Connections: {vis_data['summary']['benign_count']}")
                                        print(f"Total Connections Analyzed: {len(scores)}")
                                        print("-" * 80)
                        
                        except json.JSONDecodeError as e:
                            print(f"[{datetime.now()}] Error decoding JSON: {str(e)}")
                        except Exception as e:
                            print(f"[{datetime.now()}] Error processing data: {str(e)}")
                        
                        await asyncio.sleep(5)
                        
            except websockets.exceptions.ConnectionClosed:
                print(f"[{datetime.now()}] Connection to data source closed. Retrying in 2 seconds...")
                await asyncio.sleep(2)
            except Exception as e:
                print(f"[{datetime.now()}] Error: {str(e)}. Retrying in 2 seconds...")
                await asyncio.sleep(2)

def main():
    if platform.system() == 'Windows':
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.stop()
            loop.close()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()
    
    server = WebSocketServer()
    
    try:
        loop.run_until_complete(server.start_server())
    except KeyboardInterrupt:
        print(f"[{datetime.now()}] Server stopped by user")
    except Exception as e:
        print(f"[{datetime.now()}] Unexpected error: {str(e)}")
    finally:
        loop.close()

if __name__ == "__main__":
    main()