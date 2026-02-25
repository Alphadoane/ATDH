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
    event_type: string;
    raw_log: string;
    hostname?: string;
    risk_score: number;
    source_ip?: string;
}

interface Alert {
    id: number;
    timestamp: string;
    rule_name: string;
    severity: string;
    description: string;
    source_ip: string;
    risk_score: number;
    mitre_technique?: string;
    mitre_id?: string;
    session_id?: number;
    hostname?: string;
}

interface AttackSession {
    id: number;
    source_ip: string;
    risk_score: number;
    start_time: string;
    last_seen: string;
    techniques: string;
    is_active: boolean;
}

interface Asset {
    id: number;
    hostname: string;
    ip_address: string;
    mac_address?: string;
    os_info?: string;
    last_seen: string;
    is_managed: boolean;
}

function App() {
    const [logs, setLogs] = useState<Log[]>([]);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [sessions, setSessions] = useState<AttackSession[]>([]);
    const [assets, setAssets] = useState<Asset[]>([]);
    const [loading, setLoading] = useState(true);
    const [isScanning, setIsScanning] = useState(false);

    const fetchData = async () => {
        try {
            const [logsRes, alertsRes, sessionsRes, assetsRes] = await Promise.all([
                axios.get('/api/logs'),
                axios.get('/api/alerts'),
                axios.get('/api/sessions'),
                axios.get('/api/assets')
            ]);
            setLogs(logsRes.data);
            setAlerts(alertsRes.data);
            setSessions(sessionsRes.data);
            setAssets(assetsRes.data);
        } catch (err) {
            console.error("Failed to fetch data", err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    const triggerScan = async () => {
        setIsScanning(true);
        try {
            await axios.post('/api/scan');
            setTimeout(fetchData, 3000);
        } catch (err) {
            alert("Scan failed");
        } finally {
            setTimeout(() => setIsScanning(false), 2000);
        }
    };

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
                <div className="lg:col-span-2 space-y-6">
                    {/* Active Sessions */}
                    <div className="space-y-4">
                        <h2 className="text-lg font-semibold flex items-center gap-2">
                            <Activity className={`w-5 h-5 text-cyber-accent`} />
                            Active Attack Sessions (Correlated)
                        </h2>
                        <div className="grid grid-cols-1 gap-3">
                            {sessions.length === 0 && (
                                <div className="glass-card p-4 text-center text-gray-500 text-sm">No active multi-stage sessions.</div>
                            )}
                            {sessions.filter(s => s.is_active).map(session => (
                                <div key={session.id} className="glass-card p-4 border-l-4 border-l-cyber-accent bg-cyber-accent/5">
                                    <div className="flex justify-between items-center">
                                        <div className="flex items-center gap-3">
                                            <div className="p-2 bg-cyber-accent/10 rounded">
                                                <Activity className="w-5 h-5 text-cyber-accent" />
                                            </div>
                                            <div>
                                                <h3 className="font-bold text-gray-100">Intrusion Session: {session.source_ip}</h3>
                                                <div className="flex gap-2 mt-1">
                                                    {session.techniques.split(',').filter(t => t).map(t => (
                                                        <span key={t} className="px-1.5 py-0.5 bg-cyber-accent/20 text-cyber-accent text-[9px] font-mono rounded border border-cyber-accent/30">{t}</span>
                                                    ))}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <p className="text-[10px] text-gray-500 uppercase">Cumul. Risk</p>
                                            <p className="text-xl font-black text-cyber-accent">{session.risk_score}</p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="space-y-4">
                        <h2 className="text-lg font-semibold flex items-center gap-2">
                            <Zap className="w-5 h-5 text-cyber-warning" />
                            Security Alerts
                        </h2>
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
                                            <div className="flex items-center gap-2">
                                                <h3 className="font-bold text-gray-200">{alert.rule_name}</h3>
                                                {alert.mitre_id && (
                                                    <span className="px-1.5 py-0.5 bg-white/5 text-gray-400 text-[9px] font-mono rounded border border-white/10 uppercase">{alert.mitre_id}</span>
                                                )}
                                            </div>
                                            <p className="text-sm text-gray-400 mt-1">{alert.description}</p>
                                            <div className="flex gap-4 mt-3 text-[10px] font-mono text-gray-500">
                                                <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss')}</span>
                                                <span className="flex items-center gap-1"><Terminal className="w-3 h-3" /> IP: {alert.source_ip || 'N/A'}</span>
                                                {alert.mitre_technique && (
                                                    <span className="flex items-center gap-1 text-cyber-accent/70"><Info className="w-3 h-3" /> {alert.mitre_technique}</span>
                                                )}
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
                </div>

                {/* Live Logs */}
                <div className="space-y-6">
                    {/* Discovery Section */}
                    <div className="space-y-4">
                        <div className="flex justify-between items-center">
                            <h2 className="text-lg font-semibold flex items-center gap-2">
                                <Database className="w-5 h-5 text-cyber-success" />
                                Network Assets
                            </h2>
                            <button
                                onClick={triggerScan}
                                disabled={isScanning}
                                className={`px-3 py-1 text-[10px] font-bold rounded border transition-all ${isScanning ? 'bg-gray-700 text-gray-500 border-gray-600' : 'bg-cyber-success/10 text-cyber-success border-cyber-success/30 hover:bg-cyber-success/20'}`}
                            >
                                {isScanning ? 'SCANNING...' : 'SCAN NETWORK'}
                            </button>
                        </div>
                        <div className="glass-card overflow-hidden">
                            <div className="max-h-[300px] overflow-y-auto scrollbar-thin scrollbar-thumb-white/10">
                                {assets.length === 0 && (
                                    <div className="p-4 text-center text-gray-500 text-xs italic">No assets discovered yet. Run a scan.</div>
                                )}
                                {assets.map(asset => (
                                    <div key={asset.id} className="p-3 border-b border-white/5 flex items-center justify-between hover:bg-white/5">
                                        <div className="flex items-center gap-3">
                                            <div className={`p-1.5 rounded ${asset.is_managed ? 'bg-cyber-success/20' : 'bg-gray-400/10'}`}>
                                                <User className={`w-3.5 h-3.5 ${asset.is_managed ? 'text-cyber-success' : 'text-gray-500'}`} />
                                            </div>
                                            <div>
                                                <p className="text-xs font-bold text-gray-200">{asset.hostname}</p>
                                                <p className="text-[10px] text-gray-500 font-mono">{asset.ip_address}</p>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <span className={`text-[9px] px-1.5 py-0.5 rounded ${asset.is_managed ? 'bg-cyber-success/10 text-cyber-success' : 'bg-white/5 text-gray-500'}`}>
                                                {asset.is_managed ? 'AGENT ACTIVE' : 'UNMANAGED'}
                                            </span>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>

                    <div className="space-y-4">
                        <h2 className="text-lg font-semibold flex items-center gap-2">
                            <Terminal className="w-5 h-5 text-cyber-accent" />
                            Live Event Stream
                        </h2>
                        <div className="glass-card flex flex-col h-[500px]">
                            <div className="flex-1 overflow-y-auto p-4 space-y-2 scrollbar-thin scrollbar-thumb-white/10">
                                {logs.map(log => (
                                    <div key={log.id} className="font-mono text-[11px] p-2 rounded bg-black/30 border border-white/5 hover:border-cyber-accent/30 transition-colors">
                                        <div className="flex justify-between items-center mb-1">
                                            <span className="text-cyber-accent">[{format(new Date(log.timestamp), 'HH:mm:ss')}]</span>
                                            <span className="text-[9px] text-gray-600 uppercase tracking-widest">{log.hostname || 'unknown-host'}</span>
                                        </div>
                                        <span className="text-cyber-success mr-2">{log.event_type}</span>
                                        <span className="text-gray-400 truncate block mt-0.5">{log.raw_log.substring(0, 80)}...</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default App;
