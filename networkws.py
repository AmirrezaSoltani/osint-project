import asyncio
import websockets
import psutil
import json
from datetime import datetime
import uuid
import socket
import time
import ipaddress

# TODO FIX "Error processing data: sent 1011 (internal error) keepalive ping timeout; no close frame received" error 


class ConnectionTracker:
    def __init__(self):
        self.connections = {}
        self.start_times = {}

    def is_local_address(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            return (ip_obj.is_private or 
                   ip_obj.is_loopback or 
                   str(ip_obj) == "0.0.0.0" or 
                   str(ip_obj).startswith("169.254"))
        except ValueError:
            return False

    async def get_detailed_connections(self):
        """Get detailed connection information in the specified format"""
        current_time = time.time()
        current_connections = set()
        connections_data = []

        for conn in psutil.net_connections(kind='inet'):
            try:
                # Generate a unique identifier for this connection
                conn_id = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip if conn.raddr else 'None'}:{conn.raddr.port if conn.raddr else 'None'}"
                current_connections.add(conn_id)
                
                # If this is a new connection, record its start time
                if conn_id not in self.start_times:
                    self.start_times[conn_id] = current_time

                # Get process details
                try:
                    process = psutil.Process(conn.pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "unknown"

                # Calculate connection duration
                duration = current_time - self.start_times[conn_id]

                # Determine connection state history
                if conn_id in self.connections:
                    history = self.connections[conn_id].get('history', '') + conn.status[0]
                else:
                    history = conn.status[0]

                # create connection data in specified format  #TODO(orig_h or local_orig ?)
                connection_data = {
                    "ts": datetime.now().isoformat(),
                    "uid": str(uuid.uuid4()),
                    "id.orig_h": conn.laddr.ip,
                    "id.orig_p": conn.laddr.port,
                    "id.resp_h": conn.raddr.ip if conn.raddr else "0.0.0.0",
                    "id.resp_p": conn.raddr.port if conn.raddr else 0,
                    "proto": "tcp" if conn.type == socket.SOCK_STREAM else "udp", #(udp sock_dgram) 
                    "service": process_name,
                    "duration": round(duration, 3),
                    "orig_bytes": 0,  #kernel-level monitoring
                    "resp_bytes": 0,  #kernel-level monitoring
                    "conn_state": conn.status,
                    "local_orig": self.is_local_address(conn.laddr.ip),
                    "local_resp": self.is_local_address(conn.raddr.ip if conn.raddr else "0.0.0.0"),
                    "missed_bytes": 0,
                    "history": history[:20],  # Limit history length
                    "orig_pkts": 0,  #kernel-level monitoring
                    "orig_ip_bytes": 0,  #kernel-level monitoring
                    "resp_pkts": 0,  #kernel-level monitoring
                    "resp_ip_bytes": 0,  # kernel-level monitoring
                    "tunnel_parents": [],
                    "label": "Normal",
                    "detailed-label": f"Process: {process_name}, State: {conn.status}"
                }

                if(self.is_local_address(conn.laddr.ip)==False & conn.laddr.port!=3389): 
                 connections_data.append(connection_data)
                 self.connections[conn_id] = connection_data

            except Exception as e:
                print(f"Error processing connection: {str(e)}")
                continue

        # Clean up old connections
        for conn_id in list(self.start_times.keys()):
            if conn_id not in current_connections:
                del self.start_times[conn_id]
                if conn_id in self.connections:
                    del self.connections[conn_id]

        return connections_data

async def handler(websocket):
    """Handle WebSocket connection"""
    print(f"[{datetime.now()}] New client connected!")
    tracker = ConnectionTracker()
    
    try:
        while True:
            # Get detailed connection data
            connections = await tracker.get_detailed_connections()
            
            # Create message
            message = {
                'timestamp': datetime.now().isoformat(),
                'total_connections': len(connections),
                'connections': connections
            }
            
            # Send to client
            await websocket.send(json.dumps(message))
            
            # Wait before next update
            await asyncio.sleep(2)
            
    except websockets.exceptions.ConnectionClosed:
        print(f"[{datetime.now()}] Client disconnected")
    except Exception as e:
        print(f"[{datetime.now()}] Error: {str(e)}")

async def main():
    host = "0.0.0.0"
    port = 8765
    
    print(f"[{datetime.now()}] Starting WebSocket server...")
    print(f"[{datetime.now()}] Monitoring network connections...")
    
    try:
        async with websockets.serve(handler, host, port):
            print(f"[{datetime.now()}] WebSocket server is running on ws://{host}:{port}")
            await asyncio.Future()  # run forever
            
    except Exception as e:
        print(f"[{datetime.now()}] Failed to start server: {str(e)}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"[{datetime.now()}] Server stopped by user")
    except Exception as e:
        print(f"[{datetime.now()}] Unexpected error: {str(e)}")