import { useMemo, useState, type ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  Bot,
  BrainCircuit,
  Check,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  FileSearch,
  Filter,
  Fingerprint,
  Gauge,
  LayoutDashboard,
  Menu,
  Network,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Target,
  User,
  X,
  XCircle,
  Zap,
  type LucideIcon,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

type PageId = 'overview' | 'traffic' | 'agents' | 'intelligence' | 'investigation' | 'performance'
type Tone = 'blue' | 'green' | 'red' | 'amber' | 'purple' | 'slate'

const nav: { id: PageId; label: string; icon: LucideIcon }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'traffic', label: 'Network Traffic', icon: Network },
  { id: 'agents', label: 'AI Agents', icon: Bot },
  { id: 'intelligence', label: 'Threat Intelligence', icon: Target },
  { id: 'investigation', label: 'Investigation', icon: FileSearch },
  { id: 'performance', label: 'Model Performance', icon: Gauge },
]

const trafficSeries = [
  { time: '08:00', benign: 820, threats: 22, anomaly: 10 },
  { time: '09:00', benign: 970, threats: 31, anomaly: 14 },
  { time: '10:00', benign: 890, threats: 19, anomaly: 11 },
  { time: '11:00', benign: 1160, threats: 43, anomaly: 26 },
  { time: '12:00', benign: 1080, threats: 38, anomaly: 17 },
  { time: '13:00', benign: 1370, threats: 61, anomaly: 33 },
  { time: '14:00', benign: 1260, threats: 47, anomaly: 25 },
]

const attackData = [
  { name: 'DDoS', value: 38, color: 'var(--red)' },
  { name: 'PortScan', value: 24, color: 'var(--blue)' },
  { name: 'Botnet', value: 17, color: 'var(--purple)' },
  { name: 'Brute Force', value: 13, color: 'var(--amber)' },
  { name: 'Web Attack', value: 8, color: 'var(--green)' },
]

const rows = [
  { id: 'INC-2841', time: '14:32:18', source: '185.220.101.42', destination: '10.0.24.18', port: '443', protocol: 'TCP', prediction: 'DDoS', confidence: 98.7, anomaly: 0.94, action: 'BLOCK' },
  { id: 'INC-2840', time: '14:31:52', source: '172.16.2.84', destination: '10.0.12.47', port: '22', protocol: 'TCP', prediction: 'Brute Force', confidence: 96.2, anomaly: 0.87, action: 'BLOCK' },
  { id: 'INC-2839', time: '14:31:04', source: '192.168.8.21', destination: '10.0.18.92', port: '53', protocol: 'UDP', prediction: 'Benign', confidence: 99.4, anomaly: 0.08, action: 'ALLOW' },
  { id: 'INC-2838', time: '14:30:47', source: '45.155.205.233', destination: '10.0.33.11', port: '8080', protocol: 'TCP', prediction: 'PortScan', confidence: 93.8, anomaly: 0.82, action: 'BLOCK' },
  { id: 'INC-2837', time: '14:29:36', source: '192.168.4.107', destination: '10.0.8.24', port: '443', protocol: 'TCP', prediction: 'Benign', confidence: 97.9, anomaly: 0.12, action: 'ALLOW' },
  { id: 'INC-2836', time: '14:28:19', source: '91.219.236.166', destination: '10.0.4.55', port: '21', protocol: 'TCP', prediction: 'Botnet', confidence: 91.5, anomaly: 0.79, action: 'BLOCK' },
  { id: 'INC-2835', time: '14:27:53', source: '192.168.12.39', destination: '10.0.2.18', port: '80', protocol: 'TCP', prediction: 'Benign', confidence: 98.2, anomaly: 0.09, action: 'ALLOW' },
]

const alerts = [
  { id: 'INC-2841', title: 'DDoS attack detected', detail: '185.220.101.42 → 10.0.24.18', time: '12 sec ago', tone: 'red' as Tone, severity: 'Critical' },
  { id: 'INC-2840', title: 'Repeated authentication failures', detail: '172.16.2.84 → 10.0.12.47', time: '38 sec ago', tone: 'amber' as Tone, severity: 'High' },
  { id: 'INC-2838', title: 'Port scan pattern identified', detail: '45.155.205.233 → 10.0.33.11', time: '2 min ago', tone: 'purple' as Tone, severity: 'Medium' },
]

function Button({ children, className = '', onClick, title }: { children: ReactNode; className?: string; onClick?: () => void; title?: string }) {
  return <button title={title} onClick={onClick} className={`cursor-pointer ${className}`}>{children}</button>
}

function Input({ value, onChange, placeholder, className = '' }: { value: string; onChange: (value: string) => void; placeholder: string; className?: string }) {
  return <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className={className} />
}

function Select({ value, onChange, children, className = '' }: { value: string; onChange: (value: string) => void; children: ReactNode; className?: string }) {
  return <select value={value} onChange={(event) => onChange(event.target.value)} className={className}>{children}</select>
}

function Title({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <h2 className={className}>{children}</h2>
}

function Badge({ children, tone = 'slate' }: { children: ReactNode; tone?: Tone }) {
  return <span className={`badge badge-${tone}`}>{children}</span>
}

function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <section className={`card ${className}`}>{children}</section>
}

function CardHead({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="card-head">
      <div>
        <Title className="card-title">{title}</Title>
        {subtitle && <p className="card-subtitle">{subtitle}</p>}
      </div>
      {action}
    </div>
  )
}

function ChartTip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tip">
      <p className="chart-tip-label">{label}</p>
      {payload.map((item) => <p key={item.name} style={{ color: item.color }}>{item.name}: <strong>{item.value.toLocaleString()}</strong></p>)}
    </div>
  )
}

function Metric({ label, value, change, icon: Icon, tone }: { label: string; value: string; change: string; icon: LucideIcon; tone: Tone }) {
  const positive = !change.startsWith('-')
  return (
    <Card className="metric-card">
      <div className="metric-top">
        <div className={`icon-box tone-${tone}`}><Icon size={18} /></div>
        <span className={`change ${positive ? 'positive' : 'negative'}`}>{positive ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}{change}</span>
      </div>
      <p className="metric-value">{value}</p>
      <p className="metric-label">{label}</p>
    </Card>
  )
}

function Overview({ openIncident }: { openIncident: (id: string) => void }) {
  return (
    <div className="page-stack">
      <div className="metrics-grid">
        <Metric label="Total flows" value="128,492" change="+12.4%" icon={Activity} tone="blue" />
        <Metric label="Benign traffic" value="124,887" change="+9.8%" icon={ShieldCheck} tone="green" />
        <Metric label="Threats detected" value="2,841" change="+18.2%" icon={ShieldAlert} tone="red" />
        <Metric label="Anomalies" value="764" change="-4.6%" icon={Sparkles} tone="purple" />
        <Metric label="Blocked flows" value="2,506" change="+15.1%" icon={Zap} tone="amber" />
      </div>
      <div className="dashboard-grid">
        <Card className="traffic-chart-card">
          <CardHead title="Traffic analysis" subtitle="Flow classification across replay timeline" action={<Badge tone="blue">Last 7 hours</Badge>} />
          <div className="chart-lg">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficSeries}>
                <defs>
                  <linearGradient id="benign" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--blue)" stopOpacity={0.34} /><stop offset="100%" stopColor="var(--blue)" stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} />
                <Tooltip content={<ChartTip />} />
                <Area type="monotone" dataKey="benign" stroke="var(--blue)" fill="url(#benign)" strokeWidth={2} />
                <Line type="monotone" dataKey="threats" stroke="var(--red)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="legend"><span><i className="dot blue" />Benign flows</span><span><i className="dot red" />Threats</span></div>
        </Card>
        <Card>
          <CardHead title="Attack distribution" subtitle="Detected threat classes" />
          <div className="donut-wrap">
            <div className="chart-donut">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={attackData} dataKey="value" innerRadius={58} outerRadius={78} paddingAngle={3} stroke="none">
                    {attackData.map((item) => <Cell key={item.name} fill={item.color} />)}
                  </Pie>
                  <Tooltip content={<ChartTip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center"><strong>2,841</strong><span>Threats</span></div>
            </div>
            <div className="attack-legend">{attackData.map((item) => <div key={item.name}><span><i style={{ background: item.color }} />{item.name}</span><strong>{item.value}%</strong></div>)}</div>
          </div>
        </Card>
      </div>
      <div className="lower-grid">
        <Card>
          <CardHead title="Agent agreement" subtitle="Multi-agent decision consensus" action={<Badge tone="green">96.4% aligned</Badge>} />
          <div className="agreement">
            <div className="agreement-ring"><span>96%</span><small>Consensus</small></div>
            <div className="agreement-list">
              <Progress label="Unanimous agreement" value={82} tone="green" />
              <Progress label="2 of 3 agents agree" value={14} tone="blue" />
              <Progress label="Escalated conflicts" value={4} tone="amber" />
            </div>
          </div>
        </Card>
        <Card>
          <CardHead title="Recent alerts" subtitle="Highest priority replay detections" action={<Button onClick={() => openIncident('INC-2841')} className="text-button">View all <ArrowRight size={14} /></Button>} />
          <div className="alerts">{alerts.map((alert) => (
            <Button key={alert.id} className="alert-row" onClick={() => openIncident(alert.id)}>
              <span className={`alert-icon tone-${alert.tone}`}><AlertTriangle size={16} /></span>
              <span className="alert-copy"><strong>{alert.title}</strong><small>{alert.detail}</small></span>
              <span className="alert-meta"><Badge tone={alert.tone}>{alert.severity}</Badge><small>{alert.time}</small></span>
            </Button>
          ))}</div>
        </Card>
      </div>
    </div>
  )
}

function Progress({ label, value, tone }: { label: string; value: number; tone: Tone }) {
  return <div className="progress-row"><div><span>{label}</span><strong>{value}%</strong></div><div className="progress-track"><i className={`fill-${tone}`} style={{ width: `${value}%` }} /></div></div>
}

function Traffic({ openIncident }: { openIncident: (id: string) => void }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('All traffic')
  const filtered = rows.filter((row) => {
    const matches = Object.values(row).join(' ').toLowerCase().includes(query.toLowerCase())
    return matches && (filter === 'All traffic' || (filter === 'Threats only' ? row.action === 'BLOCK' : row.action === 'ALLOW'))
  })
  return (
    <div className="page-stack">
      <div className="mini-stats">
        <div><span>Flows in replay</span><strong>128,492</strong></div>
        <div><span>Processed</span><strong className="green-text">94.8%</strong></div>
        <div><span>Avg. throughput</span><strong>1,248 <small>flows/s</small></strong></div>
        <div><span>Replay progress</span><strong>01:42:18 <small>/ 02:00:00</small></strong></div>
      </div>
      <Card className="table-card">
        <div className="table-toolbar">
          <div className="search-field"><Search size={16} /><Input value={query} onChange={setQuery} placeholder="Search IP, class or incident ID..." /></div>
          <div className="toolbar-actions">
            <div className="select-wrap"><Filter size={15} /><Select value={filter} onChange={setFilter}><option>All traffic</option><option>Threats only</option><option>Benign only</option></Select><ChevronDown size={14} /></div>
            <Button className="secondary-button"><SlidersHorizontal size={15} /> Columns</Button>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Timestamp</th><th>Source IP</th><th>Destination IP</th><th>Port</th><th>Protocol</th><th>Predicted class</th><th>Confidence</th><th>Anomaly</th><th>Decision</th><th /></tr></thead>
            <tbody>{filtered.map((row) => (
              <tr key={row.id}>
                <td className="muted">{row.time}</td><td className="mono">{row.source}</td><td className="mono">{row.destination}</td><td>{row.port}</td><td><Badge>{row.protocol}</Badge></td>
                <td><span className={row.prediction === 'Benign' ? 'green-text' : 'danger-text'}>{row.prediction === 'Benign' ? <Check size={14} /> : <AlertTriangle size={14} />}{row.prediction}</span></td>
                <td><span className="confidence">{row.confidence}%<i><b style={{ width: `${row.confidence}%` }} /></i></span></td>
                <td><span className={row.anomaly > 0.7 ? 'danger-text' : 'muted'}>{row.anomaly.toFixed(2)}</span></td>
                <td><Badge tone={row.action === 'BLOCK' ? 'red' : 'green'}>{row.action}</Badge></td>
                <td><Button title="Inspect incident" onClick={() => openIncident(row.id)} className="row-action"><ChevronRight size={16} /></Button></td>
              </tr>
            ))}</tbody>
          </table>
          {!filtered.length && <div className="empty-state"><Search size={24} /><span>No matching flows found</span></div>}
        </div>
        <div className="table-footer"><span>Showing {filtered.length} of 128,492 flows</span><div><Button className="pager active">1</Button><Button className="pager">2</Button><Button className="pager">3</Button><span>…</span><Button className="pager">8,032</Button></div></div>
      </Card>
    </div>
  )
}

function Agents() {
  const agents = [
    { n: '01', title: 'Threat Detection', model: 'Random Forest', icon: ShieldAlert, tone: 'blue' as Tone, result: 'DDoS', score: '98.7%', detail: 'Classifies known CICIDS2017 attack signatures across 78 flow features.' },
    { n: '02', title: 'Anomaly Detection', model: 'Isolation Forest', icon: Fingerprint, tone: 'purple' as Tone, result: 'Anomalous', score: '0.94', detail: 'Detects behavioral deviation without relying on known attack labels.' },
    { n: '03', title: 'Evidence Fusion', model: 'Dempster–Shafer', icon: BrainCircuit, tone: 'green' as Tone, result: 'BLOCK', score: '96.4%', detail: 'Fuses independent agent evidence into an explainable final decision.' },
  ]
  return (
    <div className="page-stack">
      <div className="agent-grid">{agents.map((agent) => {
        const Icon = agent.icon
        return <Card key={agent.n} className="agent-card">
          <div className="agent-head"><div className={`icon-box tone-${agent.tone}`}><Icon size={20} /></div><span className="agent-number">AGENT {agent.n}</span><Badge tone="green"><CircleDot size={10} /> Online</Badge></div>
          <Title className="agent-title">{agent.title}</Title><p className="agent-model">{agent.model}</p><p className="agent-detail">{agent.detail}</p>
          <div className="agent-result"><span>Current prediction</span><div><strong className={agent.n === '03' ? 'danger-text' : ''}>{agent.result}</strong><Badge tone={agent.tone}>{agent.score}</Badge></div></div>
          <div className="evidence"><span>Evidence strength</span><strong>{agent.n === '02' ? '94' : agent.n === '03' ? '96' : '98'}%</strong><div><i className={`fill-${agent.tone}`} style={{ width: agent.n === '02' ? '94%' : agent.n === '03' ? '96%' : '98%' }} /></div></div>
        </Card>
      })}</div>
      <Card>
        <CardHead title="Multi-agent decision workflow" subtitle="Independent analysis with explainable evidence fusion" action={<Badge tone="green">Decision: BLOCK</Badge>} />
        <div className="workflow">
          <WorkflowNode icon={Network} title="Traffic Flow" detail="78 features" tone="slate" />
          <WorkflowArrow />
          <div className="parallel-agents"><WorkflowNode icon={ShieldAlert} title="RF Classifier" detail="DDoS · 98.7%" tone="blue" /><WorkflowNode icon={Fingerprint} title="IF Detector" detail="Anomaly · 0.94" tone="purple" /></div>
          <WorkflowArrow />
          <WorkflowNode icon={BrainCircuit} title="Evidence Fusion" detail="Agreement · 96.4%" tone="green" />
          <WorkflowArrow />
          <WorkflowNode icon={XCircle} title="BLOCK" detail="High confidence" tone="red" />
        </div>
      </Card>
      <div className="two-col">
        <Card><CardHead title="Evidence breakdown" subtitle="Mass assignment by hypothesis" /><div className="evidence-bars"><Progress label="Attack hypothesis" value={92} tone="red" /><Progress label="Benign hypothesis" value={3} tone="green" /><Progress label="Uncertainty" value={5} tone="amber" /></div></Card>
        <Card><CardHead title="System health" subtitle="Agent processing telemetry" /><div className="health-grid"><div><Activity /><span>Latency</span><strong>12.4 ms</strong></div><div><Zap /><span>Throughput</span><strong>1.2k/s</strong></div><div><Check /><span>Uptime</span><strong>99.98%</strong></div></div></Card>
      </div>
    </div>
  )
}

function WorkflowNode({ icon: Icon, title, detail, tone }: { icon: LucideIcon; title: string; detail: string; tone: Tone }) {
  return <div className={`workflow-node tone-${tone}`}><Icon size={21} /><div><strong>{title}</strong><span>{detail}</span></div></div>
}
function WorkflowArrow() { return <div className="workflow-arrow"><ArrowRight size={19} /></div> }

function Intelligence() {
  const trend = trafficSeries.map((item, i) => ({ time: item.time, DDoS: [8, 12, 9, 24, 18, 32, 25][i], PortScan: [4, 8, 7, 14, 11, 18, 16][i], Botnet: [3, 4, 6, 8, 9, 12, 10][i] }))
  return (
    <div className="page-stack">
      <div className="threat-class-grid">{attackData.map((item, index) => <Card key={item.name} className="threat-class"><div><span className={`class-index c${index}`}>{String(index + 1).padStart(2, '0')}</span><Badge tone={index === 0 ? 'red' : index === 1 ? 'blue' : index === 2 ? 'purple' : index === 3 ? 'amber' : 'green'}>{item.value}% share</Badge></div><strong>{item.name}</strong><span>{[1080, 682, 483, 369, 227][index].toLocaleString()} detections</span></Card>)}</div>
      <div className="dashboard-grid">
        <Card className="traffic-chart-card"><CardHead title="Attack trends" subtitle="Detections by class across replay timeline" />
          <div className="chart-lg"><ResponsiveContainer width="100%" height="100%"><LineChart data={trend}><CartesianGrid stroke="var(--border)" strokeDasharray="3 4" vertical={false} /><XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} /><YAxis axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} /><Tooltip content={<ChartTip />} /><Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 11, color: 'var(--muted)' }} /><Line dataKey="DDoS" stroke="var(--red)" strokeWidth={2} dot={false} /><Line dataKey="PortScan" stroke="var(--blue)" strokeWidth={2} dot={false} /><Line dataKey="Botnet" stroke="var(--purple)" strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer></div>
        </Card>
        <Card><CardHead title="Attack distribution" subtitle="Share of all classified threats" /><div className="chart-donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={attackData} dataKey="value" innerRadius={54} outerRadius={79} paddingAngle={3} stroke="none">{attackData.map((item) => <Cell key={item.name} fill={item.color} />)}</Pie><Tooltip content={<ChartTip />} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>5</strong><span>Classes</span></div></div></Card>
      </div>
      <div className="two-col">
        <Card><CardHead title="Top targeted ports" subtitle="Threat detections by destination port" /><div className="rank-list">{[['443 / HTTPS', 842, 92], ['80 / HTTP', 614, 74], ['22 / SSH', 492, 61], ['8080 / HTTP-alt', 287, 39], ['21 / FTP', 196, 24]].map(([name, count, width], i) => <div className="rank-row" key={String(name)}><span>{i + 1}</span><div><strong>{name}</strong><i><b style={{ width: `${width}%` }} /></i></div><em>{count}</em></div>)}</div></Card>
        <Card><CardHead title="Top source IPs" subtitle="External origins by risk score" /><div className="ip-list">{[['185.220.101.42', 'Germany', 'Critical', 'red'], ['45.155.205.233', 'Netherlands', 'Critical', 'red'], ['91.219.236.166', 'Russia', 'High', 'amber'], ['194.26.135.72', 'Romania', 'High', 'amber'], ['103.251.167.20', 'Singapore', 'Medium', 'purple']].map(([ip, country, risk, tone], i) => <div key={ip}><span className="rank-num">{i + 1}</span><span className="ip-copy"><strong>{ip}</strong><small>{country}</small></span><Badge tone={tone as Tone}>{risk}</Badge></div>)}</div></Card>
      </div>
    </div>
  )
}

function Investigation({ incidentId }: { incidentId: string }) {
  return (
    <div className="page-stack">
      <Card className="incident-hero">
        <div className="incident-main"><div className="danger-emblem"><ShieldAlert size={25} /></div><div><span className="eyebrow">INCIDENT {incidentId}</span><Title className="incident-title">Distributed denial-of-service attack</Title><p>High-volume connection flood targeting the public web gateway.</p></div></div>
        <div className="incident-tags"><Badge tone="red">Critical risk</Badge><Badge tone="red">BLOCKED</Badge><span><Clock3 size={14} /> Detected 14:32:18</span></div>
      </Card>
      <div className="investigation-grid">
        <div className="page-stack">
          <Card><CardHead title="Incident details" subtitle="Captured replay flow context" /><div className="detail-grid"><Detail label="Source IP" value="185.220.101.42" mono /><Detail label="Destination IP" value="10.0.24.18" mono /><Detail label="Source port" value="51,842" /><Detail label="Destination port" value="443 / HTTPS" /><Detail label="Protocol" value="TCP" /><Detail label="Flow duration" value="1.28 s" /><Detail label="Packets" value="12,492" /><Detail label="Bytes transferred" value="18.4 MB" /></div></Card>
          <Card><CardHead title="Agent findings" subtitle="Independent model observations" /><div className="finding-list"><Finding number="01" tone="blue" title="Threat Detection" result="DDoS · 98.7%" text="Packet rate, SYN ratio and flow duration strongly match the CICIDS2017 DDoS signature." /><Finding number="02" tone="purple" title="Anomaly Detection" result="Score · 0.94" text="Flow behavior is outside the normal distribution across 11 high-impact features." /><Finding number="03" tone="green" title="Evidence Fusion" result="BLOCK · 96.4%" text="Both analytical agents agree. Conflict mass is below the escalation threshold." /></div></Card>
          <Card><CardHead title="Supporting evidence" subtitle="Highest-impact features behind the decision" /><div className="feature-grid">{[['Flow packets/s', '9,759', '+8.2σ'], ['SYN flag count', '8,417', '+7.6σ'], ['Avg packet size', '64 B', '-3.1σ'], ['Flow IAT mean', '0.10 ms', '-6.8σ']].map(([label, value, delta]) => <div key={label}><span>{label}</span><strong>{value}</strong><Badge tone="red">{delta}</Badge></div>)}</div></Card>
        </div>
        <div className="page-stack">
          <Card className="risk-card"><CardHead title="Risk assessment" subtitle="Composite incident severity" /><div className="risk-score"><div><strong>94</strong><span>/ 100</span></div><Badge tone="red">CRITICAL</Badge></div><Progress label="Model confidence" value={98} tone="red" /><Progress label="Anomaly severity" value={94} tone="purple" /><Progress label="Source reputation" value={89} tone="amber" /></Card>
          <Card><CardHead title="Decision rationale" /><div className="rationale"><div><Check size={16} /><span>Known attack signature matched</span></div><div><Check size={16} /><span>Strong behavioral anomaly</span></div><div><Check size={16} /><span>Source IP has prior detections</span></div><div><Check size={16} /><span>Agent consensus above threshold</span></div></div><div className="decision-callout"><ShieldAlert size={18} /><div><strong>Automated decision: BLOCK</strong><span>Confidence exceeds 90% enforcement policy.</span></div></div></Card>
          <Card><CardHead title="Incident timeline" /><div className="timeline">{[['14:32:18.021', 'Flow ingested', 'CICIDS2017 replay engine'], ['14:32:18.033', 'Threat signature detected', 'Agent 01 · DDoS'], ['14:32:18.041', 'Anomaly confirmed', 'Agent 02 · score 0.94'], ['14:32:18.046', 'Evidence fused', 'Agent 03 · 96.4%'], ['14:32:18.051', 'Flow blocked', 'Policy enforcement']].map(([time, title, detail], i) => <div key={time} className={i === 4 ? 'active' : ''}><i /><span>{time}</span><strong>{title}</strong><small>{detail}</small></div>)}</div></Card>
        </div>
      </div>
    </div>
  )
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) { return <div><span>{label}</span><strong className={mono ? 'mono' : ''}>{value}</strong></div> }
function Finding({ number, tone, title, result, text }: { number: string; tone: Tone; title: string; result: string; text: string }) { return <div className="finding"><span className={`finding-num tone-${tone}`}>{number}</span><div><strong>{title}</strong><p>{text}</p></div><Badge tone={tone}>{result}</Badge></div> }

const classMetrics = [
  { name: 'Benign', precision: 99.3, recall: 99.5, f1: 99.4, support: '124,887' },
  { name: 'DDoS', precision: 98.7, recall: 97.9, f1: 98.3, support: '1,080' },
  { name: 'PortScan', precision: 96.4, recall: 95.8, f1: 96.1, support: '682' },
  { name: 'Botnet', precision: 94.9, recall: 93.6, f1: 94.2, support: '483' },
  { name: 'Brute Force', precision: 93.8, recall: 92.1, f1: 92.9, support: '369' },
  { name: 'Web Attack', precision: 91.6, recall: 89.8, f1: 90.7, support: '227' },
]

function Performance() {
  const matrix = [[124260, 183, 121, 98, 134, 91], [12, 1057, 3, 2, 4, 2], [18, 5, 653, 2, 3, 1], [9, 3, 4, 452, 11, 4], [14, 5, 3, 8, 340, 9], [11, 4, 6, 3, 8, 195]]
  return (
    <div className="page-stack">
      <div className="performance-grid"><Metric label="Overall accuracy" value="98.74%" change="+0.8%" icon={Target} tone="blue" /><Metric label="Macro F1-score" value="95.27%" change="+1.2%" icon={Sparkles} tone="purple" /><Metric label="Macro precision" value="95.78%" change="+0.9%" icon={Check} tone="green" /><Metric label="Macro recall" value="94.78%" change="+1.4%" icon={Activity} tone="amber" /></div>
      <div className="performance-layout">
        <Card><CardHead title="Confusion matrix" subtitle="Predicted versus actual class · validation set" />
          <div className="matrix-scroll"><div className="matrix"><div className="matrix-corner">Actual ↓ / Predicted →</div>{classMetrics.map((item) => <span className="matrix-label" key={item.name}>{item.name}</span>)}{matrix.map((row, ri) => <div className="matrix-row" key={ri}><span className="matrix-y">{classMetrics[ri].name}</span>{row.map((value, ci) => <span key={ci} className={ri === ci ? 'matrix-cell strong' : 'matrix-cell'} style={{ opacity: ri === ci ? 1 : Math.max(.25, value / 700) }}>{value.toLocaleString()}</span>)}</div>)}</div></div>
        </Card>
        <Card><CardHead title="Model comparison" subtitle="Validation metrics by agent" /><div className="chart-lg"><ResponsiveContainer width="100%" height="100%"><BarChart data={[{ name: 'Random Forest', precision: 97.5, recall: 96.8, f1: 97.1 }, { name: 'Isolation Forest', precision: 92.4, recall: 94.1, f1: 93.2 }, { name: 'Evidence Fusion', precision: 98.1, recall: 97.4, f1: 97.7 }]} layout="vertical"><CartesianGrid stroke="var(--border)" horizontal={false} /><XAxis type="number" domain={[80, 100]} axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 10 }} /><YAxis type="category" dataKey="name" width={94} axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 10 }} /><Tooltip content={<ChartTip />} /><Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 10 }} /><Bar dataKey="precision" fill="var(--blue)" radius={3} /><Bar dataKey="recall" fill="var(--purple)" radius={3} /><Bar dataKey="f1" fill="var(--green)" radius={3} /></BarChart></ResponsiveContainer></div></Card>
      </div>
      <Card className="table-card"><CardHead title="Per-class performance" subtitle="Detailed classification report" /><div className="table-scroll"><table><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1-score</th><th>Support</th><th>Performance</th></tr></thead><tbody>{classMetrics.map((item) => <tr key={item.name}><td><strong>{item.name}</strong></td><td>{item.precision}%</td><td>{item.recall}%</td><td><Badge tone={item.f1 > 95 ? 'green' : item.f1 > 92 ? 'blue' : 'amber'}>{item.f1}%</Badge></td><td className="muted">{item.support}</td><td><span className="wide-progress"><i style={{ width: `${item.f1}%` }} /></span></td></tr>)}</tbody></table></div></Card>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState<PageId>('overview')
  const [sidebar, setSidebar] = useState(false)
  const [incidentId, setIncidentId] = useState('INC-2841')
  const [globalSearch, setGlobalSearch] = useState('')
  const pageInfo = useMemo(() => ({
    overview: ['Security Overview', 'Multi-agent network intrusion detection summary'],
    traffic: ['Network Traffic', 'Inspect and classify CICIDS2017 replay flows'],
    agents: ['AI Agents', 'Monitor model predictions and evidence fusion'],
    intelligence: ['Threat Intelligence', 'Analyze attack classes and source patterns'],
    investigation: ['Incident Investigation', 'Explainable evidence and decision trace'],
    performance: ['Model Performance', 'Validation metrics and classification quality'],
  }[page]), [page])
  const navigate = (id: PageId) => { setPage(id); setSidebar(false); window.scrollTo({ top: 0, behavior: 'smooth' }) }
  const openIncident = (id: string) => { setIncidentId(id); navigate('investigation') }
  return (
    <div className="app-shell">
      <aside className={sidebar ? 'sidebar open' : 'sidebar'}>
        <div className="brand"><div className="brand-mark"><Shield size={22} /><i /></div><div><strong>CYBER<span>SENTINEL</span></strong><small>MULTI-AGENT NIDS</small></div><Button className="sidebar-close" onClick={() => setSidebar(false)}><X size={19} /></Button></div>
        <nav>{nav.map((item) => { const Icon = item.icon; return <Button key={item.id} onClick={() => navigate(item.id)} className={`nav-item ${page === item.id ? 'active' : ''}`}><Icon size={18} /><span>{item.label}</span>{page === item.id && <i />}</Button> })}</nav>
        <div className="sidebar-bottom">
          <div className="replay-card"><div><span className="pulse-dot" /><strong>Replay active</strong></div><p>CICIDS2017 · Friday</p><div className="replay-progress"><i /></div><span>94.8% complete</span></div>
          <div className="sidebar-foot"><ShieldCheck size={15} /><span>System secured</span><Badge tone="green">v2.4.1</Badge></div>
        </div>
      </aside>
      {sidebar && <Button className="mobile-overlay" onClick={() => setSidebar(false)}><span className="sr-only">Close menu</span></Button>}
      <main className="main">
        <header className="topbar">
          <Button className="menu-button" onClick={() => setSidebar(true)}><Menu size={20} /></Button>
          <div className="global-search"><Search size={16} /><Input value={globalSearch} onChange={setGlobalSearch} placeholder="Search incidents, IPs, threats..." /><kbd>⌘ K</kbd></div>
          <div className="top-actions"><Badge tone="amber"><Clock3 size={11} /> Offline replay</Badge><div className="system-live"><span className="pulse-dot" /><div><strong>All systems operational</strong><small>3 agents online</small></div></div><Button className="icon-button"><Bell size={18} /><i /></Button><Button className="profile"><span>AS</span><div><strong>Alex Smith</strong><small>SOC Analyst</small></div><ChevronDown size={14} /></Button></div>
        </header>
        <div className="content">
          <div className="page-header"><div><div className="breadcrumb"><span>CYBERSENTINEL</span><ChevronRight size={12} /><span>{pageInfo[0]}</span></div><h1>{pageInfo[0]}</h1><p>{pageInfo[1]}</p></div><div className="header-actions"><Badge tone="slate"><Clock3 size={12} /> Dataset time 14:32:30</Badge><Badge tone="blue">MOCK DATA</Badge></div></div>
          {page === 'overview' && <Overview openIncident={openIncident} />}
          {page === 'traffic' && <Traffic openIncident={openIncident} />}
          {page === 'agents' && <Agents />}
          {page === 'intelligence' && <Intelligence />}
          {page === 'investigation' && <Investigation incidentId={incidentId} />}
          {page === 'performance' && <Performance />}
        </div>
      </main>
    </div>
  )
}
