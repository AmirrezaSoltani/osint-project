import React, { useState, useEffect, useCallback } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { AlertCircle } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

const NetworkMonitor = () => {
  const [data, setData] = useState([]);
  const [summary, setSummary] = useState({
    avg_score: 0,
    max_score: 0,
    malicious_count: 0,
    benign_count: 0,
    total_connections: 0,
  });
  const [topAnomalies, setTopAnomalies] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState("connecting");
  const [error, setError] = useState(null);

  const connectWebSocket = useCallback(() => {
    const ws = new WebSocket("ws://localhost:8000");

    ws.onopen = () => {
      setConnectionStatus("connected");
      setError(null);
    };

    ws.onclose = () => {
      setConnectionStatus("disconnected");
      // Attempt to reconnect after 2 seconds
      setTimeout(connectWebSocket, 2000);
    };

    ws.onerror = (error) => {
      setError("Failed to connect to server");
      setConnectionStatus("error");
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);

        if (message.type === "analysis_results") {
          const {
            timestamp,
            summary: newSummary,
            top_anomalies,
          } = message.data;

          // Update time series data
          setData((prevData) => {
            const newData = [
              ...prevData,
              {
                timestamp,
                score: newSummary.avg_score,
                maxScore: newSummary.max_score,
              },
            ].slice(-50); // Keep last 50 points
            return newData;
          });

          // Update summary statistics
          setSummary(newSummary);

          // Update top anomalies
          setTopAnomalies(top_anomalies);
        }
      } catch (error) {
        console.error("Error processing message:", error);
      }
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  }, []);

  useEffect(() => {
    const cleanup = connectWebSocket();
    return cleanup;
  }, [connectWebSocket]);

  return (
    <div className="space-y-6 p-4">
      {connectionStatus !== "connected" && (
        <Alert
          variant={
            connectionStatus === "connecting" ? "default" : "destructive"
          }
        >
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {connectionStatus === "connecting"
              ? "Connecting to server..."
              : connectionStatus === "disconnected"
              ? "Disconnected from server. Reconnecting..."
              : error || "Connection error"}
          </AlertDescription>
        </Alert>
      )}

      <Card className="w-full">
        <CardHeader>
          <CardTitle>Network Analysis Monitor</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={data}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="timestamp"
                    tick={false}
                    label={{ value: "Time", position: "bottom" }}
                  />
                  <YAxis
                    domain={[0, 1]}
                    label={{
                      value: "Anomaly Score",
                      angle: -90,
                      position: "insideLeft",
                    }}
                  />
                  <Tooltip
                    labelFormatter={(label) =>
                      new Date(label).toLocaleTimeString()
                    }
                    formatter={(value) => value.toFixed(3)}
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#2563eb"
                    name="Average Score"
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="maxScore"
                    stroke="#dc2626"
                    name="Max Score"
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="p-4 bg-blue-50 rounded-lg">
                <div className="text-sm text-blue-600">Avg Score</div>
                <div className="text-xl font-semibold">
                  {summary.avg_score.toFixed(3)}
                </div>
              </div>
              <div className="p-4 bg-red-50 rounded-lg">
                <div className="text-sm text-red-600">Max Score</div>
                <div className="text-xl font-semibold">
                  {summary.max_score.toFixed(3)}
                </div>
              </div>
              <div className="p-4 bg-yellow-50 rounded-lg">
                <div className="text-sm text-yellow-600">Malicious</div>
                <div className="text-xl font-semibold">
                  {summary.malicious_count}
                </div>
              </div>
              <div className="p-4 bg-green-50 rounded-lg">
                <div className="text-sm text-green-600">Benign</div>
                <div className="text-xl font-semibold">
                  {summary.benign_count}
                </div>
              </div>
              <div className="p-4 bg-purple-50 rounded-lg">
                <div className="text-sm text-purple-600">Total</div>
                <div className="text-xl font-semibold">
                  {summary.total_connections}
                </div>
              </div>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>Top Anomalies</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr>
                        <th className="text-left p-2 bg-gray-50">Source</th>
                        <th className="text-left p-2 bg-gray-50">
                          Destination
                        </th>
                        <th className="text-left p-2 bg-gray-50">Service</th>
                        <th className="text-right p-2 bg-gray-50">Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topAnomalies.map((anomaly, index) => (
                        <tr key={index} className="border-t">
                          <td className="p-2">{anomaly.source}</td>
                          <td className="p-2">{anomaly.destination}</td>
                          <td className="p-2">{anomaly.service || "N/A"}</td>
                          <td className="p-2 text-right">
                            <span
                              className={`px-2 py-1 rounded ${
                                anomaly.anomaly_score >= 0.8
                                  ? "bg-red-100 text-red-800"
                                  : "bg-yellow-100 text-yellow-800"
                              }`}
                            >
                              {anomaly.anomaly_score.toFixed(3)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default NetworkMonitor;
