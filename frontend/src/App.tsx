import { useState, useEffect } from 'react';
import axios from 'axios';
import {
    Shield,
    AlertTriangle,
    Activity,
    Terminal,
    Database,
    Zap,
    Clock,
    User,
    Info
} from 'lucide-react';
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    BarElement,
    Title,
    Tooltip,
    Legend,
    ArcElement
} from 'chart.js';
import { Line, Bar, Doughnut } from 'react-chartjs-2';
import { format } from 'date-fns';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    BarElement,
    ArcElement,
    Title,
    Tooltip,
    Legend
);

interface Log {
    id: number;
    timestamp: string;
    source_ip: string;
    event_type: string;
    risk_score: number;
    raw_log: string;
}

interface Alert {
    id: number;
    timestamp: string;
    rule_name: string;
    severity: string;
    description: string;
    source_ip: string;
    risk_score: number;
}

function App() {
    const [logs, setLogs] = useState<Log[]>([]);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [logsRes, alertsRes] = await Promise.all([
                    axios.get('/api/logs'),
                    axios.get('/api/alerts')
                ]);
                setLogs(logsRes.data);
                setAlerts(alertsRes.data);
            } catch (err) {
                console.error("Failed to fetch data", err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const severityData = {
        labels: ['Low', 'Medium', 'High', 'Critical'],
        datasets: [{
            data: [
                alerts.filter(a => a.severity === 'Low').length,
                alerts.filter(a => a.severity === 'Medium').length,
                alerts.filter(a => a.severity === 'High').length,
                alerts.filter(a => a.severity === 'Critical').length,
            ],
            backgroundColor: ['#00ff94', '#ffbd00', '#ff003c', '#9200aa'],
            borderWidth: 0,
        }]
    };

    const riskTrendData = {
        labels: logs.slice(0, 10).reverse().map(l => format(new Date(l.timestamp), 'HH:mm:ss')),
        datasets: [{
            label: 'Event Risk Score',
            data: logs.slice(0, 10).reverse().map(l => l.risk_score),
            borderColor: '#00f2ff',
            backgroundColor: 'rgba(0, 242, 255, 0.1)',
            fill: true,
            tension: 0.4
        }]
    };

    return (
        <div className="min-h-screen p-6 max-w-7xl mx-auto space-y-6">
            {/* Header */}
            <header className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-cyber-accent/20 rounded-lg">
                        <Shield className="w-8 h-8 text-cyber-accent" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold tracking-tight neon-accent">ATD PLATFORM</h1>
                        <p className="text-sm text-gray-500 font-mono italic">Adaptive Threat Detection & Hunting</p>
                    </div>
                </div>
                <div className="flex gap-4">
                    <div className="px-4 py-2 glass-card flex items-center gap-2">
                        <Activity className="w-4 h-4 text-cyber-success animate-pulse" />
                        <span className="text-xs font-mono">ENGINE ONLINE</span>
                    </div>
                </div>
            </header>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {[
                    { label: 'Total Events', val: logs.length, icon: Database, color: 'text-blue-400' },
                    { label: 'Active Alerts', val: alerts.length, icon: AlertTriangle, color: 'text-cyber-danger' },
                    { label: 'Avg Risk', val: (logs.reduce((a, b) => a + b.risk_score, 0) / (logs.length || 1)).toFixed(1), icon: Zap, color: 'text-cyber-warning' },
                    { label: 'Logged IPs', val: new Set(logs.map(l => l.source_ip)).size, icon: User, color: 'text-cyber-success' },
                ].map((stat, i) => (
                    <div key={i} className="glass-card p-4 flex items-center justify-between">
                        <div>
                            <p className="text-xs text-gray-500 font-medium uppercase tracking-wider">{stat.label}</p>
                            <p className="text-2xl font-bold mt-1">{stat.val}</p>
                        </div>
                        <stat.icon className={`w-10 h-10 ${stat.color} opacity-20`} />
                    </div>
                ))}
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="glass-card p-6">
                    <h2 className="text-lg font-semibold mb-6 flex items-center gap-2">
                        <Activity className="w-5 h-5 text-cyber-accent" />
                        Recent Risk Trend
                    </h2>
                    <div className="h-64">
                        <Line data={riskTrendData} options={{ maintainAspectRatio: false }} />
                    </div>
                </div>
                <div className="glass-card p-6">
                    <h2 className="text-lg font-semibold mb-6 flex items-center gap-2">
                        <AlertTriangle className="w-5 h-5 text-cyber-danger" />
                        Severity Distribution
                    </h2>
                    <div className="h-64 flex justify-center">
                        <Doughnut data={severityData} options={{ maintainAspectRatio: false }} />
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Alerts List */}
                <div className="lg:col-span-2 space-y-4">
                    <div className="flex justify-between items-center">
                        <h2 className="text-lg font-semibold flex items-center gap-2">
                            <Zap className="w-5 h-5 text-cyber-warning" />
                            Critical Alerts
                        </h2>
                    </div>
                    <div className="space-y-3">
                        {alerts.length === 0 && (
                            <div className="glass-card p-8 text-center text-gray-500 italic">
                                No alerts detected. Monitoring active...
                            </div>
                        )}
                        {alerts.map(alert => (
                            <div key={alert.id} className="glass-card p-4 border-l-4 border-l-cyber-danger flex items-start justify-between group hover:bg-white/5 transition-colors">
                                <div className="flex gap-4">
                                    <div className={`mt-1 p-1.5 rounded bg-cyber-danger/10`}>
                                        <AlertTriangle className="w-4 h-4 text-cyber-danger" />
                                    </div>
                                    <div>
                                        <h3 className="font-bold text-gray-200">{alert.rule_name}</h3>
                                        <p className="text-sm text-gray-400 mt-1">{alert.description}</p>
                                        <div className="flex gap-4 mt-3 text-[10px] font-mono text-gray-500">
                                            <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss')}</span>
                                            <span className="flex items-center gap-1"><Terminal className="w-3 h-3" /> IP: {alert.source_ip || 'N/A'}</span>
                                        </div>
                                    </div>
                                </div>
                                <div className="text-right">
                                    <span className="text-xs font-bold px-2 py-1 bg-cyber-danger/20 text-cyber-danger rounded">RISK: {alert.risk_score}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Live Logs */}
                <div className="space-y-4">
                    <h2 className="text-lg font-semibold flex items-center gap-2">
                        <Terminal className="w-5 h-5 text-cyber-accent" />
                        Raw Event Stream
                    </h2>
                    <div className="glass-card flex flex-col h-[500px]">
                        <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-thin scrollbar-thumb-white/10">
                            {logs.map(log => (
                                <div key={log.id} className="font-mono text-[11px] p-2 rounded bg-black/30 border border-white/5 hover:border-cyber-accent/30 transition-colors">
                                    <span className="text-cyber-accent mr-2">[{format(new Date(log.timestamp), 'HH:mm:ss')}]</span>
                                    <span className="text-cyber-success mr-2">{log.event_type}</span>
                                    <span className="text-gray-400 truncate block mt-1">{log.raw_log.substring(0, 80)}...</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default App;
