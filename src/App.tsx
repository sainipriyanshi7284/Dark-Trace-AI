import { useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, Bell, Bot, BrainCircuit, CheckCircle2, ChevronDown,
  ChevronRight, CircleDot, Clock3, Database, Eye, FileSearch, Filter, Gauge,
  Info, LayoutDashboard, LockKeyhole, Menu, Network, Radar, Search, Server,
  Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, Target,
  TrendingDown, TrendingUp, X, XCircle, Zap,
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import {
  createBrowserRouter, Link, NavLink, Outlet, RouterProvider, useLocation,
  useNavigate,
} from 'react-router'

type Threat = 'BENIGN' | 'BRUTE_FORCE' | 'DOS' | 'DDOS' | 'PORT_SCAN'
type Decision = 'ALLOW' | 'BLOCK' | 'REVIEW'

const traffic = [
  { time: '00:00', total: 920, benign: 842, malicious: 78 },
  { time: '04:00', total: 1080, benign: 995, malicious: 85 },
  { time: '08:00', total: 1640, benign: 1480, malicious: 160 },
  { time: '12:00', total: 2120, benign: 1818, malicious: 302 },
  { time: '16:00', total: 1880, benign: 1695, malicious: 185 },
  { time: '20:00', total: 2360, benign: 2072, malicious: 288 },
  { time: '24:00', total: 2040, benign: 1884, malicious: 156 },
]

const attacks = [
  { name: 'Brute Force', value: 38, color: '#f59e0b' },
  { name: 'DDoS', value: 27, color: '#ef4444' },
  { name: 'Port Scan', value: 21, color: '#22d3ee' },
  { name: 'DoS', value: 14, color: '#8b5cf6' },
]

const networkRows: Array<{ id: string; time: string; source: string; dest: string; ports: string; protocol: string; prediction: Threat; confidence: number; anomaly: number; action: Decision }> = [
  { id: 'EVT-8492', time: '14:32:18', source: '185.220.101.14', dest: '10.0.4.21', ports: '52144 → 22', protocol: 'TCP', prediction: 'BRUTE_FORCE', confidence: 98.7, anomaly: 0.94, action: 'BLOCK' },
  { id: 'EVT-8491', time: '14:31:52', source: '10.0.2.45', dest: '10.0.8.10', ports: '49152 → 443', protocol: 'TCP', prediction: 'BENIGN', confidence: 99.4, anomaly: 0.08, action: 'ALLOW' },
  { id: 'EVT-8490', time: '14:31:04', source: '45.95.147.36', dest: '10.0.1.5', ports: '40321 → 80', protocol: 'TCP', prediction: 'DDOS', confidence: 96.2, anomaly: 0.91, action: 'BLOCK' },
  { id: 'EVT-8489', time: '14:29:47', source: '172.16.0.83', dest: '10.0.5.19', ports: '60402 → 3389', protocol: 'TCP', prediction: 'PORT_SCAN', confidence: 87.6, anomaly: 0.76, action: 'REVIEW' },
  { id: 'EVT-8488', time: '14:28:33', source: '10.0.6.12', dest: '34.117.59.81', ports: '58192 → 443', protocol: 'TCP', prediction: 'BENIGN', confidence: 97.8, anomaly: 0.12, action: 'ALLOW' },
  { id: 'EVT-8487', time: '14:26:19', source: '91.240.118.172', dest: '10.0.3.8', ports: '38217 → 53', protocol: 'UDP', prediction: 'DOS', confidence: 93.1, anomaly: 0.89, action: 'BLOCK' },
  { id: 'EVT-8486', time: '14:24:05', source: '10.0.7.99', dest: '10.0.2.10', ports: '51829 → 5432', protocol: 'TCP', prediction: 'BENIGN', confidence: 95.9, anomaly: 0.18, action: 'ALLOW' },
  { id: 'EVT-8485', time: '14:22:41', source: '198.98.51.32', dest: '10.0.4.21', ports: '59117 → 22', protocol: 'TCP', prediction: 'BRUTE_FORCE', confidence: 91.8, anomaly: 0.84, action: 'BLOCK' },
]

const trendData = [
  { day: 'Mon', benign: 18500, brute: 420, dos: 230, ddos: 180, scan: 310 },
  { day: 'Tue', benign: 19200, brute: 380, dos: 290, ddos: 210, scan: 280 },
  { day: 'Wed', benign: 17800, brute: 610, dos: 330, ddos: 520, scan: 390 },
  { day: 'Thu', benign: 20100, brute: 470, dos: 260, ddos: 190, scan: 450 },
  { day: 'Fri', benign: 21400, brute: 530, dos: 380, ddos: 410, scan: 360 },
  { day: 'Sat', benign: 16600, brute: 290, dos: 190, ddos: 150, scan: 220 },
  { day: 'Sun', benign: 17200, brute: 340, dos: 210, ddos: 260, scan: 270 },
]

const alerts = networkRows.filter((r) => r.action !== 'ALLOW').slice(0, 5)
const nav = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/traffic', label: 'Network Traffic', icon: Network },
  { to: '/agents', label: 'AI Agents', icon: Bot },
  { to: '/threats', label: 'Threat Intelligence', icon: Radar },
  { to: '/investigation', label: 'Investigation', icon: FileSearch },
  { to: '/performance', label: 'Model Performance', icon: Gauge },
]

const badgeClass = (value: string) => {
  if (value === 'BENIGN' || value === 'ALLOW') return 'badge badge-green'
  if (value === 'REVIEW' || value === 'BRUTE_FORCE') return 'badge badge-amber'
  if (value === 'PORT_SCAN') return 'badge badge-cyan'
  return 'badge badge-red'
}

function Layout() {
  const [open, setOpen] = useState(false)
  const [notices, setNotices] = useState(true)
  const location = useLocation()
  const title = nav.find((n) => n.to === location.pathname)?.label ?? 'Investigation'
  return (
    <div className="min-h-screen bg-[#080f1e] text-slate-100">
      {open && <button aria-label="Close navigation" className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={() => setOpen(false)} />}
      <aside className={`sidebar ${open ? 'translate-x-0' : '-translate-x-full'} lg:translate-x-0`}>
        <div className="flex h-20 items-center gap-3 border-b border-white/7 px-5">
          <div className="relative grid size-10 place-items-center rounded-xl bg-blue-600 shadow-[0_0_26px_rgba(37,99,235,.45)]">
            <Shield className="size-6" />
            <span className="absolute -right-0.5 -top-0.5 size-2.5 rounded-full border-2 border-[#0b1628] bg-emerald-400" />
          </div>
          <div><p className="text-[15px] font-extrabold tracking-[.08em]">CYBER<span className="text-blue-400">SENTINEL</span></p><p className="text-[10px] tracking-[.22em] text-slate-500">AUTONOMOUS DEFENSE</p></div>
          <button className="ml-auto lg:hidden" onClick={() => setOpen(false)}><X className="size-5 text-slate-400" /></button>
        </div>
        <div className="px-3 py-6">
          <p className="px-3 pb-3 text-[10px] font-bold tracking-[.18em] text-slate-600">COMMAND CENTER</p>
          <nav className="space-y-1">
            {nav.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)} className={({ isActive }) => `nav-item ${isActive ? 'nav-active' : ''}`}>
                <Icon className="size-[18px]" /><span>{label}</span>{label === 'Investigation' && <span className="ml-auto rounded-full bg-red-500/15 px-2 py-0.5 text-[10px] font-bold text-red-400">3</span>}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="mt-auto p-4">
          <div className="rounded-xl border border-emerald-400/15 bg-emerald-400/5 p-3">
            <div className="flex items-center gap-2"><span className="status-dot" /><span className="text-xs font-semibold text-emerald-300">All systems operational</span></div>
            <p className="mt-2 text-[11px] text-slate-500">Last model sync 2 min ago</p>
          </div>
          <div className="mt-4 flex items-center gap-3 px-1">
            <div className="grid size-9 place-items-center rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 text-xs font-bold">AM</div>
            <div className="min-w-0"><p className="truncate text-xs font-semibold">Alex Morgan</p><p className="text-[11px] text-slate-500">Security Analyst</p></div>
            <ChevronDown className="ml-auto size-4 text-slate-500" />
          </div>
        </div>
      </aside>
      <div className="lg:pl-[252px]">
        <header className="sticky top-0 z-20 flex h-20 items-center border-b border-white/7 bg-[#080f1e]/85 px-4 backdrop-blur-xl sm:px-7">
          <button className="mr-3 lg:hidden" onClick={() => setOpen(true)}><Menu className="size-6" /></button>
          <div><p className="text-lg font-bold sm:text-xl">{title}</p><p className="hidden text-xs text-slate-500 sm:block">Real-time network defense & intelligence</p></div>
          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            <div className="hidden items-center gap-2 rounded-lg border border-white/8 bg-white/[.025] px-3 py-2 md:flex"><Search className="size-4 text-slate-500" /><input aria-label="Global search" className="w-36 bg-transparent text-xs outline-none placeholder:text-slate-600" placeholder="Search events..." /><kbd className="rounded border border-white/10 px-1.5 text-[10px] text-slate-600">⌘K</kbd></div>
            <button onClick={() => setNotices(false)} className="relative grid size-10 place-items-center rounded-lg border border-white/8 bg-white/[.025] text-slate-400 hover:text-white"><Bell className="size-[18px]" />{notices && <span className="absolute right-2 top-2 size-2 rounded-full border-2 border-[#0b1628] bg-red-500" />}</button>
            <div className="hidden items-center gap-2 rounded-lg border border-emerald-400/15 bg-emerald-400/5 px-3 py-2 text-xs font-medium text-emerald-300 sm:flex"><span className="status-dot" />Live monitoring</div>
          </div>
        </header>
        <main className="p-4 sm:p-7"><Outlet /></main>
      </div>
    </div>
  )
}

function SectionHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="mb-5 flex flex-wrap items-end justify-between gap-3"><div>{eyebrow && <p className="mb-1 text-[10px] font-bold tracking-[.18em] text-blue-400">{eyebrow}</p>}<h2 className="text-lg font-bold">{title}</h2>{description && <p className="mt-1 text-xs text-slate-500">{description}</p>}</div>{action}</div>
}

function Metric({ icon: Icon, label, value, trend, tone = 'blue' }: { icon: React.ElementType; label: string; value: string; trend: string; tone?: string }) {
  const good = !trend.startsWith('-')
  return <div className="card metric-card"><div className={`icon-box icon-${tone}`}><Icon className="size-5" /></div><div className="mt-5 flex items-end justify-between gap-2"><div><p className="text-2xl font-bold tracking-tight">{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></div><span className={`flex items-center gap-1 text-[11px] font-semibold ${good ? 'text-emerald-400' : 'text-red-400'}`}>{good ? <TrendingUp className="size-3" /> : <TrendingDown className="size-3" />}{trend}</span></div></div>
}

const ChartTip = ({ active, payload, label }: any) => active && payload?.length ? <div className="rounded-lg border border-white/10 bg-[#0b1628] p-3 text-xs shadow-xl"><p className="mb-2 font-semibold text-slate-300">{label}</p>{payload.map((p: any) => <p key={p.dataKey} style={{ color: p.color }} className="mb-1 capitalize">{p.name}: <b>{Number(p.value).toLocaleString()}</b></p>)}</div> : null

function Overview() {
  const [range, setRange] = useState('24H')
  const navigate = useNavigate()
  return <>
    <div className="mb-7 flex flex-wrap items-center justify-between gap-4">
      <div><p className="text-sm text-slate-400">Good afternoon, Alex. Your network is <span className="font-semibold text-emerald-400">secure</span>.</p></div>
      <div className="segmented">{['1H', '24H', '7D', '30D'].map((r) => <button key={r} onClick={() => setRange(r)} className={range === r ? 'selected' : ''}>{r}</button>)}</div>
    </div>
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Metric icon={Activity} label="Events analyzed" value="1.28M" trend="+12.4%" />
      <Metric icon={ShieldAlert} label="Threats blocked" value="2,847" trend="+8.2%" tone="red" />
      <Metric icon={Gauge} label="Detection accuracy" value="98.6%" trend="+1.1%" tone="green" />
      <Metric icon={Clock3} label="Avg. response time" value="47ms" trend="-6.4%" tone="cyan" />
    </div>
    <div className="mt-5 grid gap-5 xl:grid-cols-[1.65fr_1fr]">
      <div className="card">
        <SectionHeader title="Network traffic analytics" description={`Packet flow and threat activity · ${range}`} action={<div className="flex items-center gap-2 text-[11px]"><span className="legend-dot bg-blue-500" />Total traffic <span className="ml-2 legend-dot bg-red-500" />Threats</div>} />
        <div className="h-[280px]"><ResponsiveContainer width="100%" height="100%"><AreaChart data={traffic}><defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#2563eb" stopOpacity=".32" /><stop offset="1" stopColor="#2563eb" stopOpacity="0" /></linearGradient></defs><CartesianGrid stroke="#ffffff0a" vertical={false} /><XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip content={<ChartTip />} /><Area type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} fill="url(#trafficFill)" /><Line type="monotone" dataKey="malicious" stroke="#ef4444" strokeWidth={2} dot={false} /></AreaChart></ResponsiveContainer></div>
      </div>
      <div className="card">
        <SectionHeader title="Attack distribution" description="Detected threats by category" />
        <div className="relative h-[185px]"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={attacks} dataKey="value" innerRadius={58} outerRadius={82} paddingAngle={4} stroke="none">{attacks.map((a) => <Cell key={a.name} fill={a.color} />)}</Pie><Tooltip content={<ChartTip />} /></PieChart></ResponsiveContainer><div className="pointer-events-none absolute inset-0 grid place-items-center"><div className="text-center"><p className="text-2xl font-bold">2,847</p><p className="text-[10px] text-slate-500">THREATS</p></div></div></div>
        <div className="grid grid-cols-2 gap-x-4 gap-y-3">{attacks.map((a) => <div className="flex items-center justify-between text-xs" key={a.name}><span className="flex items-center gap-2 text-slate-400"><span className="size-2 rounded-full" style={{ background: a.color }} />{a.name}</span><b>{a.value}%</b></div>)}</div>
      </div>
    </div>
    <div className="mt-5 card">
      <SectionHeader title="Recent security alerts" description="Prioritized by fusion confidence and impact" action={<Link to="/traffic" className="text-xs font-semibold text-blue-400 hover:text-blue-300">View all events →</Link>} />
      <div className="overflow-x-auto"><table><thead><tr><th>Event</th><th>Time</th><th>Source</th><th>Classification</th><th>Confidence</th><th>Decision</th><th></th></tr></thead><tbody>{alerts.map((a) => <tr key={a.id}><td className="font-mono text-xs text-slate-400">{a.id}</td><td>{a.time}</td><td className="font-mono">{a.source}</td><td><span className={badgeClass(a.prediction)}>{a.prediction.replace('_', ' ')}</span></td><td><Confidence value={a.confidence} /></td><td><span className={badgeClass(a.action)}>{a.action}</span></td><td><button onClick={() => navigate('/investigation')} aria-label={`Investigate ${a.id}`} className="rounded-md p-2 text-slate-500 hover:bg-white/5 hover:text-blue-400"><ChevronRight className="size-4" /></button></td></tr>)}</tbody></table></div>
    </div>
  </>
}

function Confidence({ value }: { value: number }) {
  return <div className="flex min-w-24 items-center gap-2"><div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/7"><div className="h-full rounded-full bg-blue-500" style={{ width: `${value}%` }} /></div><span className="text-xs font-semibold">{value}%</span></div>
}

function NetworkTraffic() {
  const [query, setQuery] = useState('')
  const [threat, setThreat] = useState('ALL')
  const [protocol, setProtocol] = useState('ALL')
  const rows = useMemo(() => networkRows.filter((r) => (`${r.id} ${r.source} ${r.dest}`.toLowerCase().includes(query.toLowerCase())) && (threat === 'ALL' || r.prediction === threat) && (protocol === 'ALL' || r.protocol === protocol)), [query, threat, protocol])
  return <>
    <SectionHeader eyebrow="LIVE PACKET INTELLIGENCE" title="Network event stream" description="Classified connections from all monitored network segments" action={<button className="button-primary"><SlidersHorizontal className="size-4" /> Configure rules</button>} />
    <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4"><MiniStat label="Connections / sec" value="14,892" color="text-blue-400" /><MiniStat label="Active sessions" value="3,284" color="text-cyan-400" /><MiniStat label="Blocked today" value="2,847" color="text-red-400" /><MiniStat label="Data processed" value="18.6 TB" color="text-emerald-400" /></div>
    <div className="card">
      <div className="mb-5 flex flex-wrap gap-3">
        <label className="search-field min-w-[240px] flex-1"><Search className="size-4" /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search IP address or event ID..." /></label>
        <label className="select-field"><Filter className="size-4" /><select value={threat} onChange={(e) => setThreat(e.target.value)}><option value="ALL">All classes</option>{['BENIGN', 'BRUTE_FORCE', 'DOS', 'DDOS', 'PORT_SCAN'].map((x) => <option key={x}>{x}</option>)}</select></label>
        <label className="select-field"><Network className="size-4" /><select value={protocol} onChange={(e) => setProtocol(e.target.value)}><option value="ALL">All protocols</option><option>TCP</option><option>UDP</option></select></label>
      </div>
      <div className="overflow-x-auto"><table><thead><tr><th>Timestamp / ID</th><th>Source IP</th><th>Destination IP</th><th>Ports</th><th>Protocol</th><th>Predicted class</th><th>Confidence</th><th>Anomaly</th><th>Action</th></tr></thead><tbody>{rows.map((r) => <tr key={r.id}><td><p>{r.time}</p><p className="font-mono text-[10px] text-slate-600">{r.id}</p></td><td className="font-mono">{r.source}</td><td className="font-mono">{r.dest}</td><td className="font-mono text-slate-400">{r.ports}</td><td><span className="rounded bg-white/5 px-2 py-1 text-[10px] font-bold">{r.protocol}</span></td><td><span className={badgeClass(r.prediction)}>{r.prediction.replace('_', ' ')}</span></td><td><Confidence value={r.confidence} /></td><td><span className={r.anomaly > .8 ? 'text-red-400' : r.anomaly > .5 ? 'text-amber-400' : 'text-emerald-400'}>{r.anomaly.toFixed(2)}</span></td><td><span className={badgeClass(r.action)}>{r.action}</span></td></tr>)}</tbody></table></div>
      <div className="mt-5 flex items-center justify-between border-t border-white/7 pt-4 text-xs text-slate-500"><span>Showing {rows.length} of 1,284,921 events</span><div className="flex gap-2"><button className="page-btn" disabled>Previous</button><button className="page-btn text-blue-400">1</button><button className="page-btn">2</button><button className="page-btn">Next</button></div></div>
    </div>
  </>
}

function MiniStat({ label, value, color }: { label: string; value: string; color: string }) {
  return <div className="card !p-4"><p className={`text-xl font-bold ${color}`}>{value}</p><p className="mt-1 text-xs text-slate-500">{label}</p></div>
}

const agents = [
  { icon: BrainCircuit, name: 'Random Forest', role: 'Supervised Classifier', status: 'Operational', value: 'BRUTE_FORCE', confidence: '98.7%', color: 'blue', detail: '500 decision trees · 42 features' },
  { icon: Radar, name: 'Isolation Forest', role: 'Anomaly Detector', status: 'Operational', value: 'Anomalous', confidence: '0.94 score', color: 'cyan', detail: 'Contamination 0.03 · 200 estimators' },
  { icon: Sparkles, name: 'Evidence Fusion', role: 'Decision Orchestrator', status: 'Operational', value: 'BLOCK', confidence: '97.1% belief', color: 'violet', detail: 'Dempster–Shafer evidence fusion' },
]

function Agents() {
  const [sample, setSample] = useState('EVT-8492')
  return <>
    <SectionHeader eyebrow="MULTI-AGENT DEFENSE" title="AI agent orchestration" description="Independent agents collaborate to classify traffic and execute policy" action={<label className="select-field"><Database className="size-4" /><select value={sample} onChange={(e) => setSample(e.target.value)}>{networkRows.slice(0, 5).map((r) => <option key={r.id}>{r.id}</option>)}</select></label>} />
    <div className="mb-5 grid gap-4 xl:grid-cols-3">{agents.map((a) => <AgentCard key={a.name} {...a} />)}</div>
    <div className="grid gap-5 xl:grid-cols-[1.45fr_1fr]">
      <div className="card">
        <SectionHeader title="Decision workflow" description={`Live inference trace for ${sample}`} />
        <div className="workflow">
          <FlowStep icon={Network} title="Network event" detail="42 extracted features" tone="slate" />
          <FlowArrow />
          <div className="grid flex-1 gap-3 sm:grid-cols-2"><FlowStep icon={BrainCircuit} title="RF classifier" detail="Brute Force · 98.7%" tone="blue" /><FlowStep icon={Radar} title="IF detector" detail="Anomaly · 0.94" tone="cyan" /></div>
          <FlowArrow />
          <FlowStep icon={Sparkles} title="Evidence fusion" detail="Belief mass · 97.1%" tone="violet" />
          <FlowArrow />
          <FlowStep icon={LockKeyhole} title="BLOCK" detail="Policy executed in 47ms" tone="red" />
        </div>
        <div className="mt-6 rounded-xl border border-white/7 bg-[#0a1424] p-4">
          <div className="mb-4 flex items-center justify-between"><p className="text-sm font-semibold">Agent agreement</p><span className="badge badge-green">HIGH CONSENSUS</span></div>
          {[['Random Forest', 98.7, '#3b82f6'], ['Isolation Forest', 94, '#22d3ee'], ['Fusion belief', 97.1, '#8b5cf6']].map(([name, value, color]) => <div key={String(name)} className="mb-3 grid grid-cols-[110px_1fr_44px] items-center gap-3 text-xs"><span className="text-slate-400">{name}</span><div className="h-2 rounded-full bg-white/5"><div className="h-full rounded-full" style={{ width: `${value}%`, background: String(color) }} /></div><b>{value}%</b></div>)}
        </div>
      </div>
      <div className="card">
        <SectionHeader title="Evidence ledger" description="Signals contributing to the final decision" />
        <div className="space-y-3">
          <Evidence label="Failed login velocity" value="48 attempts / 60 sec" weight="+0.28" severity="Critical" />
          <Evidence label="Known hostile source" value="TOR exit node · confidence 0.91" weight="+0.24" severity="High" />
          <Evidence label="Payload signature" value="SSH credential spray pattern" weight="+0.22" severity="High" />
          <Evidence label="Baseline deviation" value="12.4σ above host norm" weight="+0.18" severity="Medium" />
        </div>
        <div className="mt-5 rounded-xl border border-red-400/20 bg-red-400/5 p-4">
          <div className="flex items-start gap-3"><ShieldAlert className="mt-0.5 size-5 shrink-0 text-red-400" /><div><div className="flex items-center gap-2"><p className="font-bold">Final decision: BLOCK</p><span className="text-xs text-red-400">97.1%</span></div><p className="mt-2 text-xs leading-5 text-slate-400">High-confidence brute-force behavior with strong anomaly evidence. Source quarantined for 24 hours; incident escalated to Tier 1.</p></div></div>
        </div>
      </div>
    </div>
  </>
}

function AgentCard({ icon: Icon, name, role, status, value, confidence, color, detail }: any) {
  return <div className="card relative overflow-hidden"><div className={`absolute inset-x-0 top-0 h-px bg-${color}-500`} /><div className="flex items-start"><div className={`icon-box icon-${color}`}><Icon className="size-5" /></div><span className="ml-auto flex items-center gap-1.5 text-[10px] font-semibold text-emerald-400"><span className="status-dot" />{status}</span></div><p className="mt-5 font-bold">{name}</p><p className="text-xs text-slate-500">{role}</p><div className="mt-5 flex items-end justify-between border-t border-white/7 pt-4"><div><p className="text-[10px] text-slate-600">LATEST OUTPUT</p><p className="mt-1 text-sm font-bold">{value}</p></div><p className="text-xs font-semibold text-blue-400">{confidence}</p></div><p className="mt-3 text-[11px] text-slate-600">{detail}</p></div>
}
function FlowStep({ icon: Icon, title, detail, tone }: any) { return <div className={`flow-step flow-${tone}`}><Icon className="size-5" /><div><p className="text-xs font-semibold">{title}</p><p className="mt-1 text-[10px] text-slate-500">{detail}</p></div></div> }
function FlowArrow() { return <ChevronRight className="hidden size-5 shrink-0 text-slate-700 xl:block" /> }
function Evidence({ label, value, weight, severity }: any) { return <div className="rounded-xl border border-white/7 bg-white/[.02] p-3.5"><div className="flex items-center justify-between"><p className="text-xs font-semibold">{label}</p><span className="text-xs font-bold text-red-400">{weight}</span></div><div className="mt-2 flex items-center justify-between text-[11px]"><span className="text-slate-500">{value}</span><span className={severity === 'Critical' ? 'text-red-400' : severity === 'High' ? 'text-amber-400' : 'text-cyan-400'}>{severity}</span></div></div> }

function Threats() {
  const [active, setActive] = useState('All threats')
  const threatCards = [
    ['BENIGN', '128,421', '92.8%', 'green'], ['BRUTE FORCE', '1,083', '38.0%', 'amber'], ['DOS', '399', '14.0%', 'violet'], ['DDOS', '769', '27.0%', 'red'], ['PORT SCAN', '596', '21.0%', 'cyan'],
  ]
  return <>
    <SectionHeader eyebrow="THREAT INTELLIGENCE" title="Classification intelligence" description="Behavior patterns, prevalence, and campaign trends across the monitored estate" action={<button className="button-primary"><Zap className="size-4" /> Refresh intelligence</button>} />
    <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-5">{threatCards.map(([name, value, share, color]) => <button key={name} onClick={() => setActive(name)} className={`card text-left transition hover:-translate-y-0.5 ${active === name ? 'ring-1 ring-blue-500' : ''}`}><div className="flex items-center justify-between"><span className={`size-2.5 rounded-full bg-${color}-400`} /><span className="text-[10px] text-slate-600">{share}</span></div><p className="mt-4 text-xl font-bold">{value}</p><p className="mt-1 text-[10px] font-semibold tracking-wide text-slate-500">{name}</p></button>)}</div>
    <div className="grid gap-5 xl:grid-cols-[1.7fr_1fr]">
      <div className="card"><SectionHeader title="Seven-day classification trend" description={`${active} · event volume by day`} /><div className="h-[320px]"><ResponsiveContainer width="100%" height="100%"><BarChart data={trendData}><CartesianGrid stroke="#ffffff0a" vertical={false} /><XAxis dataKey="day" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip content={<ChartTip />} /><Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} /><Bar dataKey="brute" name="Brute Force" stackId="a" fill="#f59e0b" /><Bar dataKey="dos" name="DoS" stackId="a" fill="#8b5cf6" /><Bar dataKey="ddos" name="DDoS" stackId="a" fill="#ef4444" /><Bar dataKey="scan" name="Port Scan" stackId="a" fill="#22d3ee" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer></div></div>
      <div className="card"><SectionHeader title="Top attack origins" description="Geolocated malicious sources" /><div className="space-y-4">{[['Russia', '24.8%', 92], ['China', '18.3%', 73], ['United States', '12.7%', 54], ['Netherlands', '9.4%', 42], ['Germany', '7.1%', 31]].map(([country, pct, width], i) => <div key={country}><div className="mb-2 flex justify-between text-xs"><span><b className="mr-2 text-slate-600">0{i + 1}</b>{country}</span><b>{pct}</b></div><div className="h-1.5 rounded-full bg-white/5"><div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-cyan-400" style={{ width: `${width}%` }} /></div></div>)}</div><div className="mt-6 rounded-lg border border-amber-400/15 bg-amber-400/5 p-3 text-xs leading-5 text-slate-400"><span className="font-semibold text-amber-400">Emerging campaign:</span> SSH credential spraying increased 34% in the last six hours.</div></div>
    </div>
    <div className="mt-5 card"><SectionHeader title="Threat class profiles" description="Model characteristics and current intelligence assessment" /><div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">{[
      ['BRUTE FORCE', Target, 'Repeated authentication attempts from distributed sources.', 'SSH · RDP · HTTP Auth', 'High'],
      ['DOS', Zap, 'Single-source resource exhaustion and protocol abuse.', 'SYN · UDP · Slowloris', 'Elevated'],
      ['DDOS', Network, 'Coordinated traffic surge across botnet infrastructure.', 'Volumetric · L7', 'Critical'],
      ['PORT SCAN', Radar, 'Systematic reconnaissance of exposed service ports.', 'TCP SYN · UDP', 'Moderate'],
    ].map(([name, Icon, desc, tactics, risk]: any) => <div key={name} className="rounded-xl border border-white/7 bg-white/[.02] p-4"><Icon className="size-5 text-blue-400" /><p className="mt-4 text-xs font-bold">{name}</p><p className="mt-2 text-[11px] leading-5 text-slate-500">{desc}</p><p className="mt-3 text-[10px] text-slate-600">TACTICS</p><p className="mt-1 text-xs text-slate-300">{tactics}</p><div className="mt-4 flex justify-between border-t border-white/7 pt-3 text-xs"><span className="text-slate-500">Risk level</span><b className={risk === 'Critical' ? 'text-red-400' : 'text-amber-400'}>{risk}</b></div></div>)}</div></div>
  </>
}

function Investigation() {
  const [status, setStatus] = useState('Investigating')
  return <>
    <div className="mb-5 flex flex-wrap items-start justify-between gap-4"><div><div className="mb-2 flex items-center gap-2"><span className="badge badge-red">CRITICAL</span><span className="text-xs text-slate-500">INC-2025-08492</span></div><h1 className="text-xl font-bold sm:text-2xl">Suspected SSH credential brute-force</h1><p className="mt-2 text-xs text-slate-500">Detected today at 14:32:18 · Updated 3 minutes ago</p></div><div className="flex gap-2"><button className="button-secondary" onClick={() => setStatus('False positive')}><XCircle className="size-4" /> False positive</button><button className="button-primary" onClick={() => setStatus('Contained')}><ShieldCheck className="size-4" /> Contain threat</button></div></div>
    <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><MiniStat label="Risk score" value="94 / 100" color="text-red-400" /><MiniStat label="Fusion confidence" value="97.1%" color="text-blue-400" /><MiniStat label="Affected assets" value="1 host" color="text-amber-400" /><MiniStat label="Current status" value={status} color="text-cyan-400" /></div>
    <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
      <div className="space-y-5">
        <div className="card"><SectionHeader title="Incident details" description="Connection and asset context" /><div className="grid gap-5 sm:grid-cols-2"><Detail label="Source address" value="185.220.101.14" sub="Frankfurt, Germany · TOR exit node" /><Detail label="Target asset" value="prod-auth-02" sub="10.0.4.21 · Identity services" /><Detail label="Connection" value="TCP 52144 → 22" sub="SSH · 48 attempts in 60 seconds" /><Detail label="Identity" value="admin, root, deploy" sub="3 accounts targeted · 0 succeeded" /></div></div>
        <div className="card"><SectionHeader title="Decision rationale" description="Explainable evidence from the agent ensemble" /><div className="space-y-3">{[
          ['Behavioral match', 'Random Forest identified a credential-spraying signature across timing, packet size, and failed session features.', '98.7%'],
          ['Anomaly confirmation', 'Traffic deviates significantly from the target host baseline and normal source behavior.', '94.0%'],
          ['Threat reputation', 'Source appears in 6 intelligence feeds and is associated with prior SSH scanning.', '91.0%'],
        ].map(([title, desc, score], i) => <div className="flex gap-3 rounded-xl border border-white/7 p-4" key={title}><div className="grid size-7 shrink-0 place-items-center rounded-full bg-blue-500/10 text-xs font-bold text-blue-400">{i + 1}</div><div><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-semibold">{title}</p><span className="text-xs font-bold text-blue-400">{score}</span></div><p className="mt-1 text-xs leading-5 text-slate-500">{desc}</p></div></div>)}</div></div>
      </div>
      <div className="card"><SectionHeader title="Incident timeline" description="Automated and analyst activity" /><div className="timeline">{[
        ['14:32:18.047', 'Connection detected', 'Inbound SSH session observed from a new external source.', 'blue'],
        ['14:32:18.071', 'Agents completed inference', 'RF: BRUTE_FORCE · IF: anomaly 0.94', 'cyan'],
        ['14:32:18.094', 'Connection blocked', 'Fusion policy rejected traffic after 47 ms.', 'red'],
        ['14:32:20.112', 'Source quarantined', 'Firewall deny rule distributed to 12 edge nodes.', 'amber'],
        ['14:33:04.902', 'Incident created', 'Tier 1 investigation opened automatically.', 'violet'],
      ].map(([time, title, desc, color]) => <div className="timeline-item" key={time}><span className={`timeline-dot bg-${color}-400`} /><p className="text-[10px] font-mono text-slate-600">{time}</p><p className="mt-1 text-xs font-semibold">{title}</p><p className="mt-1 text-[11px] leading-5 text-slate-500">{desc}</p></div>)}</div><div className="mt-5 border-t border-white/7 pt-5"><p className="mb-2 text-xs font-semibold">Analyst note</p><textarea className="h-24 w-full resize-none rounded-lg border border-white/8 bg-[#0a1424] p-3 text-xs outline-none focus:border-blue-500" placeholder="Add investigation notes..." /><button className="button-primary mt-2 w-full justify-center">Add to timeline</button></div></div>
    </div>
  </>
}

function Detail({ label, value, sub }: any) { return <div><p className="text-[10px] font-bold tracking-wide text-slate-600">{label.toUpperCase()}</p><p className="mt-2 font-mono text-sm font-semibold">{value}</p><p className="mt-1 text-xs text-slate-500">{sub}</p></div> }

const matrix = [[985, 4, 2, 1, 8], [7, 231, 3, 2, 7], [3, 4, 184, 6, 3], [2, 1, 7, 228, 12], [9, 5, 2, 6, 228]]
function Performance() {
  const [version, setVersion] = useState('v4.8.2 · Production')
  const modelTrend = [{ x: 'v4.3', accuracy: 95.8, f1: 94.9 }, { x: 'v4.4', accuracy: 96.4, f1: 95.6 }, { x: 'v4.5', accuracy: 97.1, f1: 96.2 }, { x: 'v4.6', accuracy: 97.5, f1: 96.9 }, { x: 'v4.7', accuracy: 98.1, f1: 97.6 }, { x: 'v4.8', accuracy: 98.6, f1: 98.1 }]
  return <>
    <SectionHeader eyebrow="MODEL OBSERVABILITY" title="Model performance" description="Validation metrics, class-level quality, and production health" action={<label className="select-field"><BrainCircuit className="size-4" /><select value={version} onChange={(e) => setVersion(e.target.value)}><option>v4.8.2 · Production</option><option>v4.7.9 · Previous</option></select></label>} />
    <div className="mb-5 grid grid-cols-2 gap-4 xl:grid-cols-4"><Metric icon={Target} label="Overall accuracy" value="98.6%" trend="+0.5%" /><Metric icon={Sparkles} label="Macro F1 score" value="98.1%" trend="+0.5%" tone="violet" /><Metric icon={CheckCircle2} label="Macro precision" value="98.3%" trend="+0.4%" tone="green" /><Metric icon={Radar} label="Macro recall" value="97.9%" trend="+0.6%" tone="cyan" /></div>
    <div className="grid gap-5 xl:grid-cols-[1.1fr_1fr]">
      <div className="card"><SectionHeader title="Confusion matrix" description="Validation set · 2,250 labeled samples" /><div className="overflow-x-auto"><div className="mx-auto min-w-[460px] max-w-[560px]"><div className="mb-2 grid grid-cols-[76px_repeat(5,1fr)] text-center text-[10px] text-slate-500"><span /><span>BENIGN</span><span>BRUTE</span><span>DOS</span><span>DDOS</span><span>SCAN</span></div>{matrix.map((row, i) => <div key={i} className="mb-1 grid grid-cols-[76px_repeat(5,1fr)] gap-1"><span className="flex items-center text-[10px] text-slate-500">{['BENIGN', 'BRUTE', 'DOS', 'DDOS', 'SCAN'][i]}</span>{row.map((v, j) => <div key={j} className="grid aspect-square place-items-center rounded-md text-xs font-bold" style={{ background: i === j ? `rgba(37,99,235,${.25 + Math.min(v / 1000, .65)})` : `rgba(239,68,68,${.04 + v / 100})`, color: i === j ? '#bfdbfe' : '#fca5a5' }}>{v}</div>)}</div>)}<p className="mt-4 text-center text-[10px] tracking-wider text-slate-600">PREDICTED CLASS → · ACTUAL CLASS ↓</p></div></div></div>
      <div className="card"><SectionHeader title="Performance by release" description="Accuracy and macro-F1 across production versions" /><div className="h-[320px]"><ResponsiveContainer width="100%" height="100%"><LineChart data={modelTrend}><CartesianGrid stroke="#ffffff0a" vertical={false} /><XAxis dataKey="x" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis domain={[92, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip content={<ChartTip />} /><Legend wrapperStyle={{ fontSize: 11 }} /><Line dataKey="accuracy" stroke="#3b82f6" strokeWidth={2.5} dot={{ fill: '#3b82f6', r: 3 }} /><Line dataKey="f1" name="Macro F1" stroke="#22d3ee" strokeWidth={2.5} dot={{ fill: '#22d3ee', r: 3 }} /></LineChart></ResponsiveContainer></div></div>
    </div>
    <div className="mt-5 card"><SectionHeader title="Class-level performance" description={`Metrics for ${version}`} /><div className="overflow-x-auto"><table><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1 score</th><th>Support</th><th>Quality</th></tr></thead><tbody>{[
      ['BENIGN', 97.9, 98.5, 98.2, '1,000'], ['BRUTE_FORCE', 98.3, 96.8, 97.5, '250'], ['DOS', 97.4, 92.0, 94.6, '200'], ['DDOS', 93.8, 91.2, 92.5, '250'], ['PORT_SCAN', 88.4, 91.2, 89.8, '250'],
    ].map(([name, precision, recall, f1, support]: any) => <tr key={name}><td><span className={badgeClass(name)}>{name.replace('_', ' ')}</span></td><td>{precision}%</td><td>{recall}%</td><td><Confidence value={f1} /></td><td>{support}</td><td><span className={f1 > 95 ? 'badge badge-green' : 'badge badge-amber'}>{f1 > 95 ? 'Excellent' : 'Good'}</span></td></tr>)}</tbody></table></div></div>
  </>
}

const router = createBrowserRouter([{ path: '/', Component: Layout, children: [
  { index: true, Component: Overview },
  { path: 'traffic', Component: NetworkTraffic },
  { path: 'agents', Component: Agents },
  { path: 'threats', Component: Threats },
  { path: 'investigation', Component: Investigation },
  { path: 'performance', Component: Performance },
  { path: '*', Component: () => <div className="card text-center"><AlertTriangle className="mx-auto size-10 text-amber-400" /><h2 className="mt-4 text-xl font-bold">Page not found</h2><Link to="/" className="button-primary mt-5 inline-flex">Return to overview</Link></div> },
]}])

export default function App() { return <RouterProvider router={router} /> }
