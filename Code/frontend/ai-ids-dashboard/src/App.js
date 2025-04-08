//ALL CODE IS MINE UNLESS OTHERWISE STATED

import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Card, CardContent } from './components/ui/card';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts';
import './dashboard.css';

const Dashboard = () => {
  const [unswData, setUnswData] = useState([]);
  const [cicData, setCicData] = useState([]);
  const [unswAlerts, setUnswAlerts] = useState([]);
  const [cicAlerts, setCicAlerts] = useState([]);
  const [systemStatus, setSystemStatus] = useState('Starting...');

  const fetchData = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/ids-data');
      const { data } = response.data;

      const formatData = (items) =>
        items.map((item) => ({
          ...item,
          timestamp: new Date(item.timestamp).toLocaleTimeString(),
          anomaly_score: Number(item.anomaly_score),
        }));

      // Process UNSW data
      const unswDataFromApi = data["UNSW-NB15"] || [];
      setUnswData(formatData(unswDataFromApi).slice(-50));
      setUnswAlerts(
        unswDataFromApi
          .filter(item => item.alert)
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 5)
      );

      // Process CIC data
      const cicDataFromApi = data["CIC-IDS"] || [];
      setCicData(formatData(cicDataFromApi).slice(-50));
      setCicAlerts(
        cicDataFromApi
          .filter(item => item.alert)
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 5)
      );

    } catch (error) {
      console.error('Error fetching data:', error);
    }
  };


  const fetchSystemStatus = async () => {
    try {
      const response = await axios.get('http://localhost:8000/api/system-status');
      setSystemStatus(response.data.status || 'Unknown');
    } catch (error) {
      console.error('Error fetching system status:', error);
      setSystemStatus('Error fetching status');
    }
  };

  useEffect(() => {
    fetchData();
    fetchSystemStatus();
    const dataInterval = setInterval(fetchData, 3000); // Fetch every 3 seconds
    const statusInterval = setInterval(fetchSystemStatus, 10000); // Fetch system status every 10 seconds
    return () => {
      clearInterval(dataInterval);
      clearInterval(statusInterval);
    };
  }, []);

  return (
    <div className="dashboard-container">
      <h1 className="dashboard-title">AI-IDS Dashboard</h1>
      <p className="status-indicator">System Status: {systemStatus || 'Loading...'}</p>

      <div className="graphs-container">
        {/* UNSW-NB15 Section */}
        <div className="model-section">
          <Card className="dashboard-card">
            <CardContent>
              <h2 className="card-title">UNSW-NB15 Traffic Analysis</h2>
              {unswData.length === 0 ? (
                <p className="no-data">No data available</p>
              ) : (
                <LineChart width={400} height={300} data={unswData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis 
                    domain={[0, 1]} // Fixed range from 0 to 1
                    tickFormatter={(value) => value.toFixed(2)} // Format to 2 decimal places
                  />
                  <Tooltip />
                  <Line type="monotone" dataKey="anomaly_score" stroke="#ff0000" />
                </LineChart>
              )}
            </CardContent>
          </Card>

          <Card className="alert-card">
            <CardContent>
              <h3 className="alert-title">UNSW-NB15 Alerts</h3>
              {unswAlerts.length === 0 ? (
                <p className="no-alerts">No recent alerts</p>
              ) : (
                <ul className="alert-list">
                  {unswAlerts.map((alert, index) => (
                    <li key={index} className="alert-item unsw-alert">
                      <time>{new Date(alert.timestamp).toLocaleTimeString()}</time>
                      <span>
                        {alert.message} (Score: {alert.anomaly_score.toFixed(4)})
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        {/* CIC-IDS Section */}
        <div className="model-section">
          <Card className="dashboard-card">
            <CardContent>
              <h2 className="card-title">CIC-IDS Traffic Analysis</h2>
              {cicData.length === 0 ? (
                <p className="no-data">No data available</p>
              ) : (
                <LineChart width={400} height={300} data={cicData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis 
                    domain={[0, 1]} 
                    tickFormatter={(value) => value.toFixed(2)} // Show 6 decimal places
                  />
                  <Tooltip 
                    formatter={(value) => [value.toFixed(10), "Anomaly Score"]} // Detailed tooltip
                  />
                  <Line 
                    type="monotone" 
                    dataKey="anomaly_score" 
                    stroke="#00ff00" 
                    dot={{ r: 4 }} // Make dots more visible
                  />
               </LineChart>
              )}
            </CardContent>
          </Card>

          <Card className="alert-card">
            <CardContent>
              <h3 className="alert-title">CIC-IDS Alerts</h3>
              {cicAlerts.length === 0 ? (
                <p className="no-alerts">No recent alerts</p>
              ) : (
                <ul className="alert-list">
                  {cicAlerts.map((alert, index) => (
                    <li key={index} className="alert-item cic-alert">
                      <time>{new Date(alert.timestamp).toLocaleTimeString()}</time>
                      <span>
                        {alert.message} (Score: {alert.anomaly_score.toFixed(4)})
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;