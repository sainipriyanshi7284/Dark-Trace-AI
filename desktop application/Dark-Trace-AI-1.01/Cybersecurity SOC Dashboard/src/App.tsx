import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from './api'
import {
  AGENTS_CONFIG,
  EVALUATION_METRICS,
  FIVE_CLASSES,
  INITIAL_POLICIES,
  REPLAY_RECORDS,
  TEMPORAL_GROUPS,
  downloadCsvFile,
  generateClassificationCsv,
  generatePolicyCsv,
  generateReplayCsv,
} from './mockData'
import type {
  DefensePolicy,
  PageId,
  ReplayFlowRecord,
  TemporalCorrelationGroup,
  Tone,
} from './types'
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
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  Copy,
  Download,
  FileSearch,
  FileText,
  Filter,
  Fingerprint,
  Gauge,
  Layers,
  LayoutDashboard,
  Menu,
  Network,
  Pause,
  Play,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  Target,
  UploadCloud,
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
  ComposedChart,
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

const nav: { id: PageId; label: string; icon: LucideIcon; badge?: string }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'replay', label: 'Chronological Replay', icon: Network, badge: 'Scored' },
  { id: 'agents', label: '5-Agent System', icon: Bot, badge: 'A1–A5' },
  { id: 'defense', label: 'Adaptive Policies', icon: SlidersHorizontal, badge: 'A4 & A5' },
  { id: 'submissions', label: 'CSV Submissions', icon: UploadCloud, badge: '3 Files' },
  { id: 'investigation', label: 'Investigation', icon: FileSearch },
  { id: 'intelligence', label: 'Threat Intelligence', icon: Target },
  { id: 'performance', label: 'Model Performance', icon: Gauge },
]

const trafficSeries = [
  { time: '14:28', benign: 820, threats: 18, policies_active: 1 },
  { time: '14:29', benign: 950, threats: 24, policies_active: 1 },
  { time: '14:30', benign: 1180, threats: 62, policies_active: 2 },
  { time: '14:31', benign: 1340, threats: 78, policies_active: 3 },
  { time: '14:32', benign: 1210, threats: 45, policies_active: 3 },
  { time: '14:33', benign: 1040, threats: 28, policies_active: 3 },
  { time: '14:34', benign: 980, threats: 21, policies_active: 2 },
]

function Button({
  children,
  className = '',
  onClick,
  title,
}: {
  children: ReactNode
  className?: string
  onClick?: () => void
  title?: string
}) {
  return (
    <button title={title} onClick={onClick} className={`cursor-pointer ${className}`}>
      {children}
    </button>
  )
}

function Input({
  value,
  onChange,
  placeholder,
  className = '',
}: {
  value: string
  onChange: (value: string) => void
  placeholder: string
  className?: string
}) {
  return (
    <input
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      className={className}
    />
  )
}

function Select({
  value,
  onChange,
  children,
  className = '',
}: {
  value: string
  onChange: (value: string) => void
  children: ReactNode
  className?: string
}) {
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value)}
      className={className}
    >
      {children}
    </select>
  )
}

function Title({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <h2 className={className}>{children}</h2>
}

function Badge({
  children,
  tone = 'slate',
}: {
  children: ReactNode
  tone?: Tone
}) {
  return <span className={`badge badge-${tone}`}>{children}</span>
}

function Card({
  children,
  className = '',
  onClick,
}: {
  children: ReactNode
  className?: string
  onClick?: () => void
}) {
  return (
    <section onClick={onClick} className={`card ${className}`}>
      {children}
    </section>
  )
}

function CardHead({
  title,
  subtitle,
  action,
}: {
  title: string
  subtitle?: string
  action?: ReactNode
}) {
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

function ChartTip({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: Array<{ name: string; value: number; color: string }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tip">
      <p className="chart-tip-label">{label}</p>
      {payload.map((item) => (
        <p key={item.name} style={{ color: item.color }}>
          {item.name}:{' '}
          <strong>{item.value != null ? item.value.toLocaleString() : ''}</strong>
        </p>
      ))}
    </div>
  )
}

function Metric({
  label,
  value,
  change,
  icon: Icon,
  tone,
}: {
  label: string
  value: string
  change: string
  icon: LucideIcon
  tone: Tone
}) {
  const positive = !change.startsWith('-')
  return (
    <Card className="metric-card">
      <div className="metric-top">
        <div className={`icon-box tone-${tone}`}>
          <Icon size={17} />
        </div>
        <span className={`change ${positive ? 'positive' : 'negative'}`}>
          {positive ? <ArrowUpRight size={11} /> : <ArrowDownRight size={11} />}
          {change}
        </span>
      </div>
      <p className="metric-value">{value}</p>
      <p className="metric-label">{label}</p>
    </Card>
  )
}

function Progress({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone: Tone
}) {
  return (
    <div className="progress-row">
      <div>
        <span>{label}</span>
        <strong>{value}%</strong>
      </div>
      <div className="progress-track">
        <i className={`fill-${tone}`} style={{ width: `${value}%` }} />
      </div>
    </div>
  )
}

/* =========================================================
   OVERVIEW PAGE
========================================================= */
function Overview({
  openIncident,
  navigateTo,
}: {
  openIncident: (id: string) => void
  navigateTo: (page: PageId) => void
}) {
  return (
    <div className="page-stack">
      {/* Day 2 Briefing Banner */}
      <div className="submission-banner">
        <div className="flex items-center gap-3">
          <div className="icon-box tone-blue">
            <Layers size={18} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold uppercase tracking-wider text-blue-400">
                Track 1 | CyberSentinel — Day 2 Brief
              </span>
              <Badge tone="blue">Level 2 Complete</Badge>
              <Badge tone="green">5-Agent System Active</Badge>
            </div>
            <p className="text-xs text-slate-300 mt-1">
              Architecture upgraded from 3 to <strong>5 autonomous agents</strong>. Temporal Correlation Agent (A4) groups suspicious flows by endpoints & time windows; Adaptive Defense Agent (A5) creates temporary simulated ALLOW/BLOCK policies.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            onClick={() => navigateTo('submissions')}
            className="primary-button"
          >
            <UploadCloud size={14} /> Submission CSVs
          </Button>
          <Button
            onClick={() => navigateTo('replay')}
            className="secondary-button"
          >
            <Network size={14} /> Live Replay
          </Button>
        </div>
      </div>

      {/* KPI Metrics */}
      <div className="metrics-grid">
        <Metric
          label="Total Evaluation Flows"
          value={EVALUATION_METRICS.totalFlows}
          change="+14.2%"
          icon={Activity}
          tone="blue"
        />
        <Metric
          label="Benign Traffic (ALLOW)"
          value={EVALUATION_METRICS.benignFlows}
          change="+9.8%"
          icon={ShieldCheck}
          tone="green"
        />
        <Metric
          label="Temporal Groups (A4)"
          value={EVALUATION_METRICS.correlatedGroups}
          change="+100%"
          icon={Fingerprint}
          tone="cyan"
        />
        <Metric
          label="Active Policies (A5)"
          value={EVALUATION_METRICS.activePolicies}
          change="+3 new"
          icon={SlidersHorizontal}
          tone="amber"
        />
        <Metric
          label="Blocked Prior by Policy"
          value={EVALUATION_METRICS.blockedByPolicy}
          change="+18.4%"
          icon={Zap}
          tone="red"
        />
      </div>

      {/* 5-Agent Pipeline Quick Status */}
      <Card>
        <CardHead
          title="5-Agent Detection & Defense Architecture"
          subtitle="A1+A2 (Detect) ➔ A3+A4 (Correlate) ➔ A5 (Respond) • Sequential Evidence Influence"
          action={
            <Button
              onClick={() => navigateTo('agents')}
              className="text-button"
            >
              Inspect 5 Agents <ArrowRight size={13} />
            </Button>
          }
        />
        <div className="pipeline-stages">
          {/* Phase 1 */}
          <div className="stage-card">
            <div className="stage-head">
              <span className="stage-title text-blue-400">
                Phase 1: DETECT
              </span>
              <Badge tone="blue">A1 + A2</Badge>
            </div>
            <p className="text-[9px] text-muted leading-tight">
              A1 predicts attack class with confidence; A2 independently flags unusually high traffic volume.
            </p>
            <div className="stage-agents">
              <div className="stage-agent-item">
                <span className="text-blue-400 font-bold text-[9px]">A1</span>
                <div>
                  <strong>Threat Classifier</strong>
                  <p>DoS confidence 98.7% · 5-class output</p>
                </div>
              </div>
              <div className="stage-agent-item">
                <span className="text-purple-400 font-bold text-[9px]">A2</span>
                <div>
                  <strong>Anomaly & Traffic Agent</strong>
                  <p>Isolation Forest score 0.94 · Volume flag</p>
                </div>
              </div>
            </div>
          </div>

          {/* Phase 2 */}
          <div className="stage-card">
            <div className="stage-head">
              <span className="stage-title text-cyan-400">
                Phase 2: CORRELATE
              </span>
              <Badge tone="cyan">A3 + A4</Badge>
            </div>
            <p className="text-[9px] text-muted leading-tight">
              A3 combines belief mass; A4 links repeated suspicious flows observed so far and identifies patterns.
            </p>
            <div className="stage-agents">
              <div className="stage-agent-item">
                <span className="text-green-400 font-bold text-[9px]">A3</span>
                <div>
                  <strong>Evidence Fusion</strong>
                  <p>Dempster-Shafer consensus 96.4% belief</p>
                </div>
              </div>
              <div className="stage-agent-item">
                <span className="text-cyan-400 font-bold text-[9px]">A4</span>
                <div>
                  <strong>Temporal Correlator</strong>
                  <p>Group IDs (GRP-T014) · Sliding time windows</p>
                </div>
              </div>
            </div>
          </div>

          {/* Phase 3 */}
          <div className="stage-card">
            <div className="stage-head">
              <span className="stage-title text-red-400">
                Phase 3: RESPOND
              </span>
              <Badge tone="red">A5</Badge>
            </div>
            <p className="text-[9px] text-muted leading-tight">
              A5 activates temporary SOURCE_IP policies after triggering flows. Only later matching flows are BLOCKED.
            </p>
            <div className="stage-agents">
              <div className="stage-agent-item">
                <span className="text-red-400 font-bold text-[9px]">A5</span>
                <div>
                  <strong>Adaptive Defense Agent</strong>
                  <p>scope SOURCE_IP · policy.csv activation logs</p>
                </div>
              </div>
              <div className="p-2 border border-red-500/20 bg-red-500/5 rounded text-[8px] text-red-300">
                <strong>Policy-Before-Analysis Rule:</strong> Active policies intercept matching records BEFORE A1–A4 analysis!
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Traffic Trend and Threat Classes */}
      <div className="dashboard-grid">
        <Card className="traffic-chart-card">
          <CardHead
            title="Chronological Traffic & Policy Interceptions"
            subtitle="Flow volume versus active adaptive defense enforcement"
            action={<Badge tone="blue">Timeline Replay</Badge>}
          />
          <div className="chart-lg">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={trafficSeries}>
                <defs>
                  <linearGradient id="benignGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--blue)" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="var(--blue)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} />
                <Tooltip content={<ChartTip />} />
                <Area type="monotone" dataKey="benign" stroke="var(--blue)" fill="url(#benignGrad)" strokeWidth={2} />
                <Line type="monotone" dataKey="threats" stroke="var(--red)" strokeWidth={2} dot={false} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="legend">
            <span><i className="dot blue" /> Benign Flows</span>
            <span><i className="dot red" /> Intercepted Threats</span>
          </div>
        </Card>

        <Card>
          <CardHead
            title="5 Threat Classes Breakdown"
            subtitle="Official five-class distribution (CICIDS2017)"
          />
          <div className="donut-wrap">
            <div className="chart-donut">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={FIVE_CLASSES}
                    dataKey="count"
                    innerRadius={55}
                    outerRadius={78}
                    paddingAngle={3}
                    stroke="none"
                  >
                    {FIVE_CLASSES.map((item) => (
                      <Cell key={item.name} fill={item.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<ChartTip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="donut-center">
                <strong>5</strong>
                <span>Classes</span>
              </div>
            </div>
            <div className="attack-legend">
              {FIVE_CLASSES.map((item) => (
                <div key={item.name}>
                  <span>
                    <i style={{ background: item.color }} />
                    {item.name}
                  </span>
                  <strong>{item.pct}%</strong>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Adaptive Defense Active Policies & Temporal Correlation Alerts */}
      <div className="lower-grid">
        <Card>
          <CardHead
            title="Active Adaptive Policies (A5)"
            subtitle="Simulated policies with scope SOURCE_IP"
            action={
              <Button onClick={() => navigateTo('defense')} className="text-button">
                All Policies <ChevronRight size={13} />
              </Button>
            }
          />
          <div className="alerts">
            {INITIAL_POLICIES.filter((p) => p.status === 'ACTIVE').map((policy) => (
              <div key={policy.policy_id} className="alert-row">
                <span className="alert-icon tone-amber">
                  <ShieldAlert size={15} />
                </span>
                <div className="alert-copy">
                  <div className="flex items-center gap-2">
                    <strong className="mono text-white">{policy.policy_id}</strong>
                    <Badge tone="red">{policy.scope_type} = {policy.scope_value}</Badge>
                    <Badge tone="green">ACTIVE</Badge>
                  </div>
                  <small className="text-muted">
                    Triggered after {policy.activated_after_record_id} • Expires after {policy.expires_after_record_id}
                  </small>
                </div>
                <div className="alert-meta">
                  <span className="text-[9px] font-bold text-amber-400">
                    {policy.flows_intercepted} intercepted
                  </span>
                  <small>{policy.time_activated}</small>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardHead
            title="Temporal Correlation Groups (A4)"
            subtitle="Grouped suspicious flows across endpoints and time windows"
            action={
              <Button onClick={() => navigateTo('defense')} className="text-button">
                View Groups <ChevronRight size={13} />
              </Button>
            }
          />
          <div className="alerts">
            {TEMPORAL_GROUPS.map((grp) => (
              <div key={grp.group_id} className="alert-row">
                <span className="alert-icon tone-cyan">
                  <Fingerprint size={15} />
                </span>
                <div className="alert-copy">
                  <div className="flex items-center gap-2">
                    <strong className="mono text-cyan-300">{grp.group_id}</strong>
                    <Badge tone="cyan">{grp.pattern_type}</Badge>
                    <span className="text-[8px] text-muted">
                      {grp.member_record_ids.length} records
                    </span>
                  </div>
                  <small className="text-muted truncate">
                    {grp.source_endpoints.join(', ')} ➔ {grp.target_endpoints[0]}
                  </small>
                </div>
                <div className="alert-meta">
                  <Badge tone="green">{grp.confidence}% conf</Badge>
                  <small className="text-[7px] text-muted">{grp.time_window}</small>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}

/* =========================================================
   CHRONOLOGICAL FLOW REPLAY & POLICY ENGINE PAGE
========================================================= */
function ChronologicalReplay({
  openIncident,
}: {
  openIncident: (id: string) => void
}) {
  const [query, setQuery] = useState('')
  const [filterAction, setFilterAction] = useState('ALL')
  const [currentStep, setCurrentStep] = useState(REPLAY_RECORDS.length)
  const [isPlaying, setIsPlaying] = useState(false)

  // Replay timeline player
  useEffect(() => {
    if (!isPlaying) return
    const interval = window.setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= REPLAY_RECORDS.length) {
          setIsPlaying(false)
          return prev
        }
        return prev + 1
      })
    }, 900)
    return () => window.clearInterval(interval)
  }, [isPlaying])

  const visibleRecords = useMemo(
    () => REPLAY_RECORDS.slice(0, currentStep),
    [currentStep]
  )

  const filtered = useMemo(() => {
    return visibleRecords.filter((row) => {
      const matchText =
        row.record_id.toLowerCase().includes(query.toLowerCase()) ||
        row.source_ip.toLowerCase().includes(query.toLowerCase()) ||
        row.a1_predicted_class.toLowerCase().includes(query.toLowerCase()) ||
        (row.applied_policy_id &&
          row.applied_policy_id.toLowerCase().includes(query.toLowerCase()))

      if (!matchText) return false
      if (filterAction === 'ALLOW') return row.final_action === 'ALLOW'
      if (filterAction === 'BLOCK') return row.final_action === 'BLOCK'
      if (filterAction === 'POLICY_BLOCKED') return row.policy_blocked_prior
      if (filterAction === 'AGENT_BLOCKED')
        return row.final_action === 'BLOCK' && !row.policy_blocked_prior
      return true
    })
  }, [visibleRecords, query, filterAction])

  const activePolicyCount = useMemo(() => {
    return INITIAL_POLICIES.filter((p) => p.status === 'ACTIVE').length
  }, [])

  return (
    <div className="page-stack">
      {/* Replay Control Bar */}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Title className="card-title">Chronological Evaluation Replay Engine</Title>
              <Badge tone="green">Rule: Active Policy Checked First</Badge>
            </div>
            <p className="card-subtitle">
              Replaying official evaluation records strictly in chronological order. Active defense policies are applied <strong>BEFORE</strong> newly allowed flows are analyzed.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={() => setIsPlaying(!isPlaying)}
              className="primary-button"
            >
              {isPlaying ? <Pause size={13} /> : <Play size={13} />}
              {isPlaying ? 'Pause Replay' : 'Play Replay'}
            </Button>
            <Button
              onClick={() =>
                setCurrentStep((prev) => Math.min(prev + 1, REPLAY_RECORDS.length))
              }
              className="secondary-button"
              title="Advance one flow"
            >
              Step +1
            </Button>
            <Button
              onClick={() => {
                setIsPlaying(false)
                setCurrentStep(REPLAY_RECORDS.length)
              }}
              className="secondary-button"
              title="Show all records"
            >
              <RotateCcw size={13} /> Full Data
            </Button>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <span className="text-[9px] text-muted">Replay Progress:</span>
          <div className="flex-1 bg-border/40 h-2 rounded-full overflow-hidden">
            <div
              className="bg-blue-500 h-full transition-all duration-300"
              style={{
                width: `${(currentStep / REPLAY_RECORDS.length) * 100}%`,
              }}
            />
          </div>
          <span className="text-[9px] font-mono text-muted">
            {currentStep} / {REPLAY_RECORDS.length} records processed
          </span>
        </div>
      </Card>

      {/* Mini telemetry stats */}
      <div className="mini-stats">
        <div>
          <span>Processed Flows</span>
          <strong>{visibleRecords.length} <small>/ {REPLAY_RECORDS.length}</small></strong>
        </div>
        <div>
          <span>Allowed Records</span>
          <strong className="green-text">
            {visibleRecords.filter((r) => r.final_action === 'ALLOW').length}
          </strong>
        </div>
        <div>
          <span>Policy-Interceptions (A5)</span>
          <strong className="danger-text">
            {visibleRecords.filter((r) => r.policy_blocked_prior).length}
          </strong>
        </div>
        <div>
          <span>Active Policies</span>
          <strong className="amber-text">{activePolicyCount} ACTIVE</strong>
        </div>
      </div>

      {/* Replay Table */}
      <Card className="table-card">
        <div className="table-toolbar">
          <div className="search-field">
            <Search size={15} />
            <Input
              value={query}
              onChange={setQuery}
              placeholder="Search record ID (REC-...), IP, policy ID..."
            />
          </div>
          <div className="toolbar-actions">
            <div className="select-wrap">
              <Filter size={14} />
              <Select value={filterAction} onChange={setFilterAction}>
                <option value="ALL">All Flows</option>
                <option value="ALLOW">ALLOW only</option>
                <option value="BLOCK">All BLOCKs</option>
                <option value="POLICY_BLOCKED">Blocked Prior by Policy (A5)</option>
                <option value="AGENT_BLOCKED">Blocked by Classifier (A1-A3)</option>
              </Select>
              <ChevronDown size={13} />
            </div>
            <Badge tone="blue">
              Showing {filtered.length} of {visibleRecords.length}
            </Badge>
          </div>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Record ID</th>
                <th>Time</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Port</th>
                <th>Pre-Analysis Policy Gate</th>
                <th>Predicted Class (A1)</th>
                <th>Anomaly (A2)</th>
                <th>Temporal Group (A4)</th>
                <th>Decision Action</th>
                <th>Applied Policy ID</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.record_id}>
                  <td className="mono font-semibold text-white">
                    {row.record_id}
                  </td>
                  <td className="muted">{row.time}</td>
                  <td className="mono">{row.source_ip}</td>
                  <td className="mono">{row.destination_ip}</td>
                  <td>{row.destination_port}</td>
                  <td>
                    {row.policy_blocked_prior ? (
                      <span className="danger-text font-bold text-[8px]">
                        <ShieldAlert size={12} /> BLOCKED by {row.applied_policy_id}
                      </span>
                    ) : (
                      <span className="green-text text-[8px]">
                        <Check size={12} /> PASS to Analysis
                      </span>
                    )}
                  </td>
                  <td>
                    <span
                      className={
                        row.a1_predicted_class === 'Benign'
                          ? 'green-text'
                          : 'danger-text font-semibold'
                      }
                    >
                      {row.a1_predicted_class === 'Benign' ? (
                        <Check size={13} />
                      ) : (
                        <AlertTriangle size={13} />
                      )}
                      {row.a1_predicted_class} ({row.a1_confidence.toFixed(1)}%)
                    </span>
                  </td>
                  <td>
                    <span
                      className={
                        row.a2_anomaly_score > 0.7 ? 'danger-text' : 'muted'
                      }
                    >
                      {row.a2_anomaly_score.toFixed(2)}
                    </span>
                  </td>
                  <td>
                    {row.a4_group_id ? (
                      <Badge tone="cyan">{row.a4_group_id}</Badge>
                    ) : (
                      <span className="text-muted text-[8px]">—</span>
                    )}
                  </td>
                  <td>
                    <Badge tone={row.final_action === 'BLOCK' ? 'red' : 'green'}>
                      {row.final_action}
                    </Badge>
                  </td>
                  <td className="mono font-bold">
                    {row.applied_policy_id ? (
                      <span className="text-red-400">{row.applied_policy_id}</span>
                    ) : (
                      <span className="text-muted text-[8px]">—</span>
                    )}
                  </td>
                  <td>
                    <Button
                      title="Inspect incident evidence"
                      onClick={() => openIncident(row.record_id)}
                      className="row-action"
                    >
                      <ChevronRight size={15} />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && (
            <div className="empty-state">
              <Search size={22} />
              <span>No flows match the active filters</span>
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}

/* =========================================================
   5-AGENT ARCHITECTURE PAGE (A1–A5)
========================================================= */
function FiveAgents() {
  const [selectedAgent, setSelectedAgent] = useState('a4')

  return (
    <div className="page-stack">
      {/* Overview Note */}
      <Card>
        <CardHead
          title="Five-Agent Multi-Agent Detection & Defense Architecture"
          subtitle="Keep A1–A3 • Add TWO More Agents: Agent 4 (Temporal Correlation) & Agent 5 (Adaptive Defense)"
          action={<Badge tone="green">Level 2 Architecture</Badge>}
        />
        <p className="text-[10px] text-muted leading-relaxed">
          The system integrates five cooperative agents operating in three coordinated stages. <strong>A1</strong> and <strong>A2</strong> detect attack signatures and volume anomalies independently. <strong>A3</strong> fuses their analytical evidence. <strong>A4</strong> links repeated suspicious flows over sliding time windows into correlated groups. Finally, <strong>A5</strong> synthesizes temporary simulated ALLOW/BLOCK defense policies with scope <code>SOURCE_IP</code> and enforces them on subsequent replay flows.
        </p>
      </Card>

      {/* 5 Agent Cards */}
      <div className="five-agent-grid">
        {AGENTS_CONFIG.map((agent) => {
          return (
            <Card
              key={agent.id}
              className={`agent-card cursor-pointer transition-all ${
                selectedAgent === agent.id ? 'ring-1 ring-blue-500' : ''
              }`}
              onClick={() => setSelectedAgent(agent.id)}
            >
              <div className="agent-head">
                <div className={`icon-box tone-${agent.tone}`}>
                  {agent.id === 'a1' && <ShieldAlert size={17} />}
                  {agent.id === 'a2' && <Fingerprint size={17} />}
                  {agent.id === 'a3' && <BrainCircuit size={17} />}
                  {agent.id === 'a4' && <Target size={17} />}
                  {agent.id === 'a5' && <SlidersHorizontal size={17} />}
                </div>
                <span className="agent-number">AGENT {agent.number}</span>
                <Badge tone={agent.tone}>{agent.phase}</Badge>
              </div>

              <Title className="agent-title">{agent.name}</Title>
              <p className="agent-model">{agent.role}</p>
              <p className="agent-detail">{agent.description}</p>

              <div className="agent-result">
                <span>Demonstrable Output</span>
                <div>
                  <strong className="text-[10px] text-slate-200">
                    {agent.demonstrable_output}
                  </strong>
                </div>
              </div>

              <div className="evidence">
                <span>{agent.evidence_metric}</span>
                <strong>{agent.evidence_score}%</strong>
                <div>
                  <i
                    className={`fill-${agent.tone}`}
                    style={{ width: `${agent.evidence_score}%` }}
                  />
                </div>
              </div>
            </Card>
          )
        })}
      </div>

      {/* Integrated Pipeline Workflow */}
      <Card>
        <CardHead
          title="Integrated Agent Evidence Exchange Pipeline"
          subtitle="Chronological flow handling & feedback enforcement loop"
          action={<Badge tone="blue">Autonomous Policy Loop</Badge>}
        />
        <div className="pipeline-stages">
          <div className="stage-card">
            <div className="stage-head">
              <span className="stage-title text-blue-400">
                1. A1 + A2 • DETECT
              </span>
              <Badge tone="blue">Independent</Badge>
            </div>
            <div className="text-[9px] text-slate-300 space-y-2 mt-2">
              <p>
                <strong>A1 (Threat Classifier):</strong> Extracts 78 flow features and predicts DoS / attack classes with confidence probabilities.
              </p>
              <p>
                <strong>A2 (Traffic Anomaly):</strong> Independently computes isolation depth and flags unusually high packet/flow traffic.
              </p>
              <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded text-[8px] text-blue-300">
                Both independent observations are recorded before evidence correlation.
              </div>
            </div>
          </div>

          <div className="stage-card">
            <div className="stage-head">
              <span className="stage-title text-cyan-400">
                2. A3 + A4 • CORRELATE
              </span>
              <Badge tone="cyan">Contextual</Badge>
            </div>
            <div className="text-[9px] text-slate-300 space-y-2 mt-2">
              <p>
                <strong>A3 (Evidence Fusion):</strong> Combines A1 and A2 evidence using Dempster-Shafer consensus, resolving conflict.
              </p>
              <p>
                <strong>A4 (Temporal Correlation):</strong> Links repeated suspicious flows observed so far over sliding time windows into cluster Group IDs (e.g. <code>GRP-T014</code>).
              </p>
              <div className="p-2 bg-cyan-500/10 border border-cyan-500/20 rounded text-[8px] text-cyan-300">
                Identifies attack campaign patterns across endpoints and time horizons.
              </div>
            </div>
          </div>

          <div className="stage-card">
            <div className="stage-head">
              <span className="stage-title text-red-400">
                3. A5 • RESPOND
              </span>
              <Badge tone="red">Adaptive</Badge>
            </div>
            <div className="text-[9px] text-slate-300 space-y-2 mt-2">
              <p>
                <strong>A5 (Adaptive Defense):</strong> Activates a temporary simulated <code>SOURCE_IP</code> policy after the triggering flow.
              </p>
              <p>
                <strong>Chronological Enforcement:</strong> On subsequent replay records, active policies are applied <strong>BEFORE</strong> analysis. Only later matching flows are <code>BLOCK</code>ed.
              </p>
              <div className="p-2 bg-red-500/10 border border-red-500/20 rounded text-[8px] text-red-300">
                Records policy activation, scope, expiry, and ALLOW/BLOCK actions in <code>policy.csv</code> and <code>replay.csv</code>.
              </div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  )
}

/* =========================================================
   ADAPTIVE DEFENSE & TEMPORAL GROUPS (A4 & A5)
========================================================= */
function AdaptiveDefenseView() {
  const [policies, setPolicies] = useState<DefensePolicy[]>(INITIAL_POLICIES)
  const [temporalGroups] = useState<TemporalCorrelationGroup[]>(TEMPORAL_GROUPS)
  const [newIp, setNewIp] = useState('')
  const [newExpiry, setNewExpiry] = useState('REC-10080')
  const [feedbackMsg, setFeedbackMsg] = useState('')

  const handleCreatePolicy = () => {
    if (!newIp.trim()) return
    const newPol: DefensePolicy = {
      policy_id: `POL-${String(policies.length + 1).padStart(3, '0')}`,
      activated_after_record_id: 'REC-10032',
      scope_type: 'SOURCE_IP',
      scope_value: newIp.trim(),
      expires_after_record_id: newExpiry.trim() || 'REC-10080',
      policy_action: 'BLOCK',
      trigger_reason: `Simulated policy created for ${newIp.trim()}`,
      time_activated: '14:32:30',
      flows_intercepted: 0,
      status: 'ACTIVE',
    }
    setPolicies([newPol, ...policies])
    setFeedbackMsg(`Policy ${newPol.policy_id} activated for ${newPol.scope_value}!`)
    setNewIp('')
    setTimeout(() => setFeedbackMsg(''), 4000)
  }

  return (
    <div className="page-stack">
      {/* Header Info */}
      <Card>
        <CardHead
          title="Adaptive Defense Policies & Temporal Correlation Clusters"
          subtitle="Agent 4 (Temporal Correlation) & Agent 5 (Adaptive Defense Agent) Output Engine"
          action={<Badge tone="amber">Policy Replay Engine</Badge>}
        />
        <p className="text-[10px] text-muted leading-relaxed">
          Demonstrable outputs for Agent 4 and Agent 5 as required by the Day 2 Brief. Agent 4 groups related suspicious flows across observed endpoints and time windows. Agent 5 creates temporary simulated ALLOW/BLOCK policies with scope <code>SOURCE_IP</code> and tracks policy activation, scope, and expiry logs.
        </p>
      </Card>

      {/* Manual / Simulated Policy Generator */}
      <Card>
        <CardHead
          title="Simulate Policy Activation (Agent 5 Response)"
          subtitle="Generate a temporary SOURCE_IP block policy for upcoming replay records"
        />
        <div className="flex flex-wrap items-center gap-3">
          <Input
            value={newIp}
            onChange={setNewIp}
            placeholder="Target Source IP (e.g. 198.51.100.77)"
            className="search-field !w-64"
          />
          <Input
            value={newExpiry}
            onChange={setNewExpiry}
            placeholder="Expires after record ID (e.g. REC-10080)"
            className="search-field !w-64"
          />
          <Button onClick={handleCreatePolicy} className="primary-button">
            <SlidersHorizontal size={13} /> Activate Simulated Policy
          </Button>
          {feedbackMsg && (
            <span className="green-text text-[9px] font-semibold">
              <CheckCircle2 size={13} /> {feedbackMsg}
            </span>
          )}
        </div>
      </Card>

      {/* Policies Table */}
      <Card className="table-card">
        <div className="card-head !mb-0 p-4 border-b border-border">
          <div>
            <Title className="card-title">Policy Registry (policy.csv preview)</Title>
            <p className="card-subtitle">
              Format: policy_id, activated_after_record_id, scope_type, scope_value, expires_after_record_id, policy_action
            </p>
          </div>
          <Badge tone="blue">Total: {policies.length} Policies</Badge>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Policy ID</th>
                <th>Status</th>
                <th>Activated After Record</th>
                <th>Scope Type</th>
                <th>Scope Value</th>
                <th>Expires After Record</th>
                <th>Policy Action</th>
                <th>Time Activated</th>
                <th>Flows Intercepted</th>
                <th>Trigger Reason</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((pol) => (
                <tr key={pol.policy_id}>
                  <td className="mono font-bold text-white">{pol.policy_id}</td>
                  <td>
                    <Badge tone={pol.status === 'ACTIVE' ? 'green' : 'slate'}>
                      {pol.status}
                    </Badge>
                  </td>
                  <td className="mono font-semibold text-blue-300">
                    {pol.activated_after_record_id}
                  </td>
                  <td><Badge tone="blue">{pol.scope_type}</Badge></td>
                  <td className="mono font-bold text-red-400">{pol.scope_value}</td>
                  <td className="mono text-muted">{pol.expires_after_record_id}</td>
                  <td><Badge tone="red">{pol.policy_action}</Badge></td>
                  <td className="muted">{pol.time_activated}</td>
                  <td className="font-semibold text-amber-400">
                    {pol.flows_intercepted}
                  </td>
                  <td className="text-muted text-[8px] max-w-xs truncate">
                    {pol.trigger_reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Temporal Correlation Groups (Agent 4) */}
      <Card>
        <CardHead
          title="Temporal Correlation Clusters (Agent 4 demonstrable output)"
          subtitle="Group IDs, member records, sliding time windows, and supporting correlation evidence"
          action={<Badge tone="cyan">Agent 4 Engine</Badge>}
        />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {temporalGroups.map((grp) => (
            <div
              key={grp.group_id}
              className="border border-border rounded-lg p-3 bg-card-2 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="mono font-bold text-cyan-300 text-xs">
                    {grp.group_id}
                  </span>
                  <Badge tone="cyan">{grp.pattern_type}</Badge>
                </div>
                <div className="mt-2 text-[9px] text-muted space-y-1">
                  <div>
                    <strong>Time Window:</strong> {grp.time_window}
                  </div>
                  <div>
                    <strong>Target Endpoints:</strong>{' '}
                    <span className="mono text-slate-300">
                      {grp.target_endpoints.join(', ')}
                    </span>
                  </div>
                  <div>
                    <strong>Associated Defense Policy:</strong>{' '}
                    <span className="mono font-bold text-red-400">
                      {grp.associated_policy_id || 'None'}
                    </span>
                  </div>
                </div>

                <div className="mt-3">
                  <span className="text-[8px] uppercase tracking-wider text-muted font-bold block mb-1">
                    Member Records ({grp.member_record_ids.length})
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {grp.member_record_ids.map((recId) => (
                      <span
                        key={recId}
                        className="mono text-[8px] px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/40 text-cyan-200"
                      >
                        {recId}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-border/60">
                <p className="text-[8px] text-slate-300 leading-tight">
                  {grp.evidence_summary}
                </p>
                <div className="mt-2 flex items-center justify-between text-[8px]">
                  <span className="text-muted">Correlation Confidence:</span>
                  <strong className="text-cyan-300">{grp.confidence}%</strong>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}

/* =========================================================
   FINAL CSV SUBMISSIONS (UPLOAD THREE FILES TO API)
========================================================= */
function SubmissionsView() {
  const [activeTab, setActiveTab] = useState<'classification' | 'policy' | 'replay'>('classification')
  const [copySuccess, setCopySuccess] = useState('')

  const classificationContent = useMemo(() => generateClassificationCsv(), [])
  const policyContent = useMemo(() => generatePolicyCsv(), [])
  const replayContent = useMemo(() => generateReplayCsv(), [])

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopySuccess(`Copied ${label} to clipboard!`)
    setTimeout(() => setCopySuccess(''), 3000)
  }

  const handleDownloadAll = () => {
    downloadCsvFile('classification.csv', classificationContent)
    setTimeout(() => downloadCsvFile('policy.csv', policyContent), 200)
    setTimeout(() => downloadCsvFile('replay.csv', replayContent), 400)
  }

  return (
    <div className="page-stack">
      {/* Official Specification Header */}
      <div className="submission-banner">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-blue-400">
              Final CSV Submission — Upload Three Files to API
            </span>
            <Badge tone="green">Validation Ready</Badge>
          </div>
          <p className="text-xs text-slate-300 mt-1 max-w-3xl">
            As specified in Day 2 Brief: Run the system in the supplied replay order; do not use hidden labels or future records. Upload <code>classification.csv</code>, <code>policy.csv</code>, and <code>replay.csv</code>.
          </p>
          <div className="submission-checklist">
            <div>
              <CheckCircle2 size={13} />
              <span>classification.csv: record_id, predicted_class, anomaly_score, evidence_status</span>
            </div>
            <div>
              <CheckCircle2 size={13} />
              <span>policy.csv: policy_id, activated_after_record_id, scope_type, scope_value, expires_after_record_id, policy_action</span>
            </div>
            <div>
              <CheckCircle2 size={13} />
              <span>replay.csv: record_id, action, applied_policy_id</span>
            </div>
          </div>
        </div>
        <div className="flex flex-col gap-2">
          <Button onClick={handleDownloadAll} className="primary-button !py-2.5">
            <Download size={14} /> Download All 3 Files
          </Button>
          {copySuccess && (
            <span className="text-[8px] text-green-400 text-center font-semibold">
              {copySuccess}
            </span>
          )}
        </div>
      </div>

      {/* Tab Switcher */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        <Button
          onClick={() => setActiveTab('classification')}
          className={`secondary-button ${
            activeTab === 'classification' ? '!border-blue-500 !text-blue-400 !bg-blue-500/10' : ''
          }`}
        >
          <FileText size={13} /> 1. classification.csv
        </Button>
        <Button
          onClick={() => setActiveTab('policy')}
          className={`secondary-button ${
            activeTab === 'policy' ? '!border-blue-500 !text-blue-400 !bg-blue-500/10' : ''
          }`}
        >
          <SlidersHorizontal size={13} /> 2. policy.csv
        </Button>
        <Button
          onClick={() => setActiveTab('replay')}
          className={`secondary-button ${
            activeTab === 'replay' ? '!border-blue-500 !text-blue-400 !bg-blue-500/10' : ''
          }`}
        >
          <Network size={13} /> 3. replay.csv
        </Button>
      </div>

      {/* TAB 1: classification.csv */}
      {activeTab === 'classification' && (
        <Card className="table-card">
          <div className="card-head !mb-0 p-4 border-b border-border flex items-center justify-between">
            <div>
              <Title className="card-title">classification.csv</Title>
              <p className="card-subtitle">
                Required columns: <code>record_id, predicted_class, anomaly_score, evidence_status</code> • One five-class prediction per record.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => handleCopy(classificationContent, 'classification.csv')}
                className="secondary-button"
              >
                <Copy size={13} /> Copy CSV
              </Button>
              <Button
                onClick={() => downloadCsvFile('classification.csv', classificationContent)}
                className="primary-button"
              >
                <Download size={13} /> Download classification.csv
              </Button>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>record_id</th>
                  <th>predicted_class (5 classes)</th>
                  <th>anomaly_score</th>
                  <th>evidence_status</th>
                </tr>
              </thead>
              <tbody>
                {REPLAY_RECORDS.slice(0, 15).map((r) => (
                  <tr key={r.record_id}>
                    <td className="mono font-bold text-white">{r.record_id}</td>
                    <td>
                      <span
                        className={
                          r.a1_predicted_class === 'Benign'
                            ? 'green-text'
                            : 'danger-text font-semibold'
                        }
                      >
                        {r.a1_predicted_class}
                      </span>
                    </td>
                    <td className="mono">{r.a2_anomaly_score.toFixed(4)}</td>
                    <td><Badge tone="blue">{r.evidence_status}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="p-3 border-t border-border bg-card-2">
            <span className="text-[8px] uppercase tracking-wider text-muted font-bold block mb-1">
              Raw File Content Preview (First 8 lines):
            </span>
            <pre className="raw-csv-box">
              {classificationContent.split('\n').slice(0, 8).join('\n')}
            </pre>
          </div>
        </Card>
      )}

      {/* TAB 2: policy.csv */}
      {activeTab === 'policy' && (
        <Card className="table-card">
          <div className="card-head !mb-0 p-4 border-b border-border flex items-center justify-between">
            <div>
              <Title className="card-title">policy.csv</Title>
              <p className="card-subtitle">
                Required columns: <code>policy_id, activated_after_record_id, scope_type, scope_value, expires_after_record_id, policy_action</code>
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => handleCopy(policyContent, 'policy.csv')}
                className="secondary-button"
              >
                <Copy size={13} /> Copy CSV
              </Button>
              <Button
                onClick={() => downloadCsvFile('policy.csv', policyContent)}
                className="primary-button"
              >
                <Download size={13} /> Download policy.csv
              </Button>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>policy_id</th>
                  <th>activated_after_record_id</th>
                  <th>scope_type</th>
                  <th>scope_value</th>
                  <th>expires_after_record_id</th>
                  <th>policy_action</th>
                </tr>
              </thead>
              <tbody>
                {INITIAL_POLICIES.map((p) => (
                  <tr key={p.policy_id}>
                    <td className="mono font-bold text-white">{p.policy_id}</td>
                    <td className="mono text-blue-300">{p.activated_after_record_id}</td>
                    <td><Badge tone="blue">{p.scope_type}</Badge></td>
                    <td className="mono font-bold text-red-400">{p.scope_value}</td>
                    <td className="mono text-muted">{p.expires_after_record_id}</td>
                    <td><Badge tone="red">{p.policy_action}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="p-3 border-t border-border bg-card-2">
            <span className="text-[8px] uppercase tracking-wider text-muted font-bold block mb-1">
              Raw File Content Preview:
            </span>
            <pre className="raw-csv-box">{policyContent}</pre>
          </div>
        </Card>
      )}

      {/* TAB 3: replay.csv */}
      {activeTab === 'replay' && (
        <Card className="table-card">
          <div className="card-head !mb-0 p-4 border-b border-border flex items-center justify-between">
            <div>
              <Title className="card-title">replay.csv</Title>
              <p className="card-subtitle">
                Required columns: <code>record_id, action, applied_policy_id</code> • A BLOCK must reference a valid applicable policy; ALLOW has an empty applied_policy_id.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => handleCopy(replayContent, 'replay.csv')}
                className="secondary-button"
              >
                <Copy size={13} /> Copy CSV
              </Button>
              <Button
                onClick={() => downloadCsvFile('replay.csv', replayContent)}
                className="primary-button"
              >
                <Download size={13} /> Download replay.csv
              </Button>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>record_id</th>
                  <th>action (ALLOW / BLOCK)</th>
                  <th>applied_policy_id</th>
                </tr>
              </thead>
              <tbody>
                {REPLAY_RECORDS.slice(0, 15).map((r) => (
                  <tr key={r.record_id}>
                    <td className="mono font-bold text-white">{r.record_id}</td>
                    <td>
                      <Badge tone={r.final_action === 'BLOCK' ? 'red' : 'green'}>
                        {r.final_action}
                      </Badge>
                    </td>
                    <td className="mono font-bold">
                      {r.applied_policy_id ? (
                        <span className="text-red-400">{r.applied_policy_id}</span>
                      ) : (
                        <span className="text-muted text-[8px]">— (empty for ALLOW)</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="p-3 border-t border-border bg-card-2">
            <span className="text-[8px] uppercase tracking-wider text-muted font-bold block mb-1">
              Raw File Content Preview (First 8 lines):
            </span>
            <pre className="raw-csv-box">
              {replayContent.split('\n').slice(0, 8).join('\n')}
            </pre>
          </div>
        </Card>
      )}
    </div>
  )
}

/* =========================================================
   INCIDENT INVESTIGATION PAGE (5-AGENT DRILLDOWN)
========================================================= */
function Investigation({ incidentId }: { incidentId: string }) {
  const currentRecord = useMemo(() => {
    return (
      REPLAY_RECORDS.find((r) => r.record_id === incidentId) ||
      REPLAY_RECORDS.find((r) => r.record_id === 'REC-10004') ||
      REPLAY_RECORDS[0]
    )
  }, [incidentId])

  return (
    <div className="page-stack">
      {/* Incident Hero */}
      <Card className="incident-hero">
        <div className="incident-main">
          <div className="danger-emblem">
            <ShieldAlert size={24} />
          </div>
          <div>
            <span className="eyebrow">EVALUATION RECORD {currentRecord.record_id}</span>
            <Title className="incident-title">
              {currentRecord.a1_predicted_class} Attack Investigation
            </Title>
            <p>
              Pre-analysis active policy verification, 5-agent evidence correlation, and dynamic response trace.
            </p>
          </div>
        </div>
        <div className="incident-tags">
          <Badge tone={currentRecord.final_action === 'BLOCK' ? 'red' : 'green'}>
            Action: {currentRecord.final_action}
          </Badge>
          {currentRecord.applied_policy_id && (
            <Badge tone="amber">Policy: {currentRecord.applied_policy_id}</Badge>
          )}
          <span>
            <Clock3 size={13} /> {currentRecord.time}
          </span>
        </div>
      </Card>

      <div className="investigation-grid">
        <div className="page-stack">
          {/* Flow Context */}
          <Card>
            <CardHead title="Replay Flow Context" subtitle="Raw feature parameters" />
            <div className="detail-grid">
              <div><span>Source IP</span><strong className="mono">{currentRecord.source_ip}</strong></div>
              <div><span>Destination IP</span><strong className="mono">{currentRecord.destination_ip}</strong></div>
              <div><span>Destination Port</span><strong>{currentRecord.destination_port}</strong></div>
              <div><span>Protocol</span><strong>{currentRecord.protocol}</strong></div>
              <div><span>Flow Duration</span><strong>{currentRecord.flow_duration} s</strong></div>
              <div><span>Packets</span><strong>{currentRecord.packet_count.toLocaleString()}</strong></div>
              <div><span>Bytes Transferred</span><strong>{(currentRecord.byte_count / 1024).toFixed(1)} KB</strong></div>
              <div><span>Evidence Status</span><Badge tone="blue">{currentRecord.evidence_status}</Badge></div>
            </div>
          </Card>

          {/* 5-Agent Findings */}
          <Card>
            <CardHead
              title="5-Agent Cooperative Findings"
              subtitle="Step-by-step evidence contribution from each agent"
            />
            <div className="finding-list">
              <div className="finding">
                <span className="finding-num tone-blue">01</span>
                <div>
                  <strong>Agent 1: Threat Classification Agent</strong>
                  <p>
                    Supervised classifier predicts <strong>{currentRecord.a1_predicted_class}</strong> with {currentRecord.a1_confidence.toFixed(1)}% confidence across 78 flow features.
                  </p>
                </div>
                <Badge tone="blue">{currentRecord.a1_confidence.toFixed(1)}%</Badge>
              </div>

              <div className="finding">
                <span className="finding-num tone-purple">02</span>
                <div>
                  <strong>Agent 2: Traffic & Anomaly Agent</strong>
                  <p>
                    Unsupervised anomaly detection computed score of <strong>{currentRecord.a2_anomaly_score.toFixed(2)}</strong>. High traffic flag: {currentRecord.a2_traffic_flag ? 'TRUE' : 'FALSE'}.
                  </p>
                </div>
                <Badge tone="purple">{currentRecord.a2_anomaly_score.toFixed(2)}</Badge>
              </div>

              <div className="finding">
                <span className="finding-num tone-green">03</span>
                <div>
                  <strong>Agent 3: Evidence Fusion Agent</strong>
                  <p>
                    Dempster-Shafer consensus fused evidence into belief mass of {currentRecord.a3_fusion_score.toFixed(1)}% for hypothesis {currentRecord.a3_verdict}.
                  </p>
                </div>
                <Badge tone="green">{currentRecord.a3_fusion_score.toFixed(1)}%</Badge>
              </div>

              <div className="finding">
                <span className="finding-num tone-cyan">04</span>
                <div>
                  <strong>Agent 4: Temporal Correlation Agent</strong>
                  <p>
                    {currentRecord.a4_group_id
                      ? `Linked flow into cluster group ${currentRecord.a4_group_id}. Pattern: ${currentRecord.a4_pattern_desc}`
                      : 'No temporal correlation burst detected for this single endpoint window.'}
                  </p>
                </div>
                <Badge tone="cyan">{currentRecord.a4_group_id || 'Isolated'}</Badge>
              </div>

              <div className="finding">
                <span className="finding-num tone-red">05</span>
                <div>
                  <strong>Agent 5: Adaptive Defense Agent</strong>
                  <p>
                    {currentRecord.policy_blocked_prior
                      ? `Flow blocked in PRE-ANALYSIS stage by active policy ${currentRecord.applied_policy_id} before deep feature parsing!`
                      : currentRecord.activated_policy_id
                      ? `Triggered new policy ${currentRecord.activated_policy_id} with scope SOURCE_IP = ${currentRecord.source_ip}. Only LATER records will be blocked.`
                      : 'No policy activated or applied.'}
                  </p>
                </div>
                <Badge tone="red">{currentRecord.final_action}</Badge>
              </div>
            </div>
          </Card>
        </div>

        {/* Right side: Decision Rationale & Timeline */}
        <div className="page-stack">
          <Card className="risk-card">
            <CardHead title="Evaluation Decision Rationale" />
            <div className="risk-score">
              <div>
                <strong>
                  {currentRecord.final_action === 'BLOCK' ? '96' : '04'}
                </strong>
                <span>/ 100 Risk</span>
              </div>
              <Badge tone={currentRecord.final_action === 'BLOCK' ? 'red' : 'green'}>
                {currentRecord.final_action}
              </Badge>
            </div>
            <Progress label="A1 Model Confidence" value={Math.round(currentRecord.a1_confidence)} tone="blue" />
            <Progress label="A2 Anomaly Score" value={Math.round(currentRecord.a2_anomaly_score * 100)} tone="purple" />
            <Progress label="A3 Fused Belief Mass" value={Math.round(currentRecord.a3_fusion_score)} tone="green" />
          </Card>

          <Card>
            <CardHead title="Chronological Decision Trace" />
            <div className="timeline">
              <div>
                <i />
                <span>{currentRecord.time}.001</span>
                <strong>Pre-Analysis Policy Check</strong>
                <small>
                  {currentRecord.policy_blocked_prior
                    ? `Matching active policy ${currentRecord.applied_policy_id} found. Enforced BLOCK!`
                    : 'No active policy matching source IP. Pass to detection.'}
                </small>
              </div>
              <div>
                <i />
                <span>{currentRecord.time}.014</span>
                <strong>A1 & A2 Parallel Detection</strong>
                <small>A1 predicts {currentRecord.a1_predicted_class}; A2 anomaly {currentRecord.a2_anomaly_score.toFixed(2)}</small>
              </div>
              <div>
                <i />
                <span>{currentRecord.time}.022</span>
                <strong>A3 & A4 Correlation</strong>
                <small>
                  Fused belief {currentRecord.a3_fusion_score.toFixed(1)}% · Temporal group {currentRecord.a4_group_id || 'N/A'}
                </small>
              </div>
              <div className="active">
                <i />
                <span>{currentRecord.time}.030</span>
                <strong>A5 Final Response</strong>
                <small>
                  Action: {currentRecord.final_action} · Output logged to replay.csv
                </small>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}

/* =========================================================
   THREAT INTELLIGENCE PAGE
========================================================= */
function Intelligence() {
  const trend = trafficSeries.map((item, i) => ({
    time: item.time,
    DoS: [12, 18, 45, 62, 38, 22, 16][i],
    PortScan: [4, 8, 12, 16, 11, 7, 5][i],
    Botnet: [2, 3, 5, 8, 6, 4, 3][i],
  }))

  return (
    <div className="page-stack">
      <div className="threat-class-grid">
        {FIVE_CLASSES.map((item, index) => (
          <Card key={item.name} className="threat-class">
            <div>
              <span className={`class-index c${index}`}>
                {String(index + 1).padStart(2, '0')}
              </span>
              <Badge tone={index === 0 ? 'green' : index === 1 ? 'red' : index === 2 ? 'blue' : index === 3 ? 'purple' : 'amber'}>
                {item.pct}% share
              </Badge>
            </div>
            <strong>{item.name}</strong>
            <span>{item.count.toLocaleString()} detections</span>
          </Card>
        ))}
      </div>

      <div className="dashboard-grid">
        <Card className="traffic-chart-card">
          <CardHead
            title="Attack Trends by Class"
            subtitle="Chronological detection rate across replay evaluation timeline"
          />
          <div className="chart-lg">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trend}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }} />
                <Tooltip content={<ChartTip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 11, color: 'var(--muted)' }} />
                <Line dataKey="DoS" stroke="var(--red)" strokeWidth={2} dot={false} />
                <Line dataKey="PortScan" stroke="var(--blue)" strokeWidth={2} dot={false} />
                <Line dataKey="Botnet" stroke="var(--purple)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card>
          <CardHead
            title="Five-Class Share"
            subtitle="Overall distribution of recorded predictions"
          />
          <div className="chart-donut">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={FIVE_CLASSES}
                  dataKey="count"
                  innerRadius={54}
                  outerRadius={79}
                  paddingAngle={3}
                  stroke="none"
                >
                  {FIVE_CLASSES.map((item) => (
                    <Cell key={item.name} fill={item.color} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTip />} />
              </PieChart>
            </ResponsiveContainer>
            <div className="donut-center">
              <strong>5</strong>
              <span>Classes</span>
            </div>
          </div>
        </Card>
      </div>

      <div className="two-col">
        <Card>
          <CardHead title="Top Targeted Ports" subtitle="Detections by destination port" />
          <div className="rank-list">
            {[
              ['443 / HTTPS', 842, 92],
              ['80 / HTTP', 614, 74],
              ['22 / SSH', 492, 61],
              ['8080 / HTTP-alt', 287, 39],
              ['21 / FTP', 196, 24],
            ].map(([name, count, width], i) => (
              <div className="rank-row" key={String(name)}>
                <span>{i + 1}</span>
                <div>
                  <strong>{name}</strong>
                  <i><b style={{ width: `${width}%` }} /></i>
                </div>
                <em>{count}</em>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <CardHead title="Top Flagged Source IPs" subtitle="Entities under active policy enforcement" />
          <div className="ip-list">
            {[
              ['185.220.101.42', 'POL-001 (DoS)', 'Active', 'red'],
              ['45.155.205.233', 'POL-002 (PortScan)', 'Active', 'red'],
              ['91.219.236.166', 'POL-003 (Botnet)', 'Active', 'red'],
              ['194.26.135.72', 'POL-000 (SYN Flood)', 'Expired', 'slate'],
              ['172.16.2.84', 'A1 Flagged (SSH Brute)', 'Pending Policy', 'amber'],
            ].map(([ip, policy, status, tone], i) => (
              <div key={ip}>
                <span className="rank-num">{i + 1}</span>
                <span className="ip-copy">
                  <strong>{ip}</strong>
                  <small>{policy}</small>
                </span>
                <Badge tone={tone as Tone}>{status}</Badge>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}

/* =========================================================
   MODEL PERFORMANCE PAGE (5 CLASSES)
========================================================= */
const fiveClassMetrics = [
  { name: 'Benign', precision: 99.4, recall: 99.6, f1: 99.5, support: '124,887' },
  { name: 'DoS', precision: 98.7, recall: 98.1, f1: 98.4, support: '1,080' },
  { name: 'PortScan', precision: 96.4, recall: 95.8, f1: 96.1, support: '682' },
  { name: 'Botnet', precision: 94.9, recall: 93.6, f1: 94.2, support: '483' },
  { name: 'Brute Force', precision: 93.8, recall: 92.1, f1: 92.9, support: '369' },
]

function Performance() {
  const matrix = [
    [124380, 150, 110, 85, 162],
    [10, 1060, 4, 3, 3],
    [15, 6, 654, 4, 3],
    [8, 3, 5, 453, 14],
    [12, 4, 3, 9, 341],
  ]

  return (
    <div className="page-stack">
      <div className="performance-grid">
        <Metric label="Overall Accuracy" value="98.74%" change="+0.8%" icon={Target} tone="blue" />
        <Metric label="Macro F1-Score" value="95.27%" change="+1.2%" icon={Sparkles} tone="purple" />
        <Metric label="Macro Precision" value="95.78%" change="+0.9%" icon={Check} tone="green" />
        <Metric label="Macro Recall" value="94.78%" change="+1.4%" icon={Activity} tone="amber" />
      </div>

      <div className="performance-layout">
        <Card>
          <CardHead
            title="Five-Class Confusion Matrix"
            subtitle="Predicted vs Actual Class • Official Validation Set"
          />
          <div className="matrix-scroll">
            <div className="matrix">
              <div className="matrix-corner">Actual ↓ / Pred →</div>
              {fiveClassMetrics.map((item) => (
                <span className="matrix-label" key={item.name}>
                  {item.name}
                </span>
              ))}
              {matrix.map((row, ri) => (
                <div className="matrix-row" key={ri}>
                  <span className="matrix-y">{fiveClassMetrics[ri].name}</span>
                  {row.map((value, ci) => (
                    <span
                      key={ci}
                      className={ri === ci ? 'matrix-cell strong' : 'matrix-cell'}
                      style={{
                        opacity: ri === ci ? 1 : Math.max(0.25, value / 600),
                      }}
                    >
                      {value.toLocaleString()}
                    </span>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card>
          <CardHead
            title="5-Agent Telemetry & Decision Latency"
            subtitle="Processing benchmark across replay engine"
          />
          <div className="chart-lg">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={[
                  { name: 'A1 Classifier', precision: 98.7, recall: 98.1, f1: 98.4 },
                  { name: 'A2 Anomaly', precision: 92.4, recall: 94.1, f1: 93.2 },
                  { name: 'A3 Fusion', precision: 98.1, recall: 97.4, f1: 97.7 },
                  { name: 'A4 Correlation', precision: 96.8, recall: 95.9, f1: 96.3 },
                  { name: 'A5 Policy Eng', precision: 99.2, recall: 98.8, f1: 99.0 },
                ]}
                layout="vertical"
              >
                <CartesianGrid stroke="var(--border)" horizontal={false} />
                <XAxis type="number" domain={[85, 100]} axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 10 }} />
                <YAxis type="category" dataKey="name" width={100} axisLine={false} tickLine={false} tick={{ fill: 'var(--muted)', fontSize: 10 }} />
                <Tooltip content={<ChartTip />} />
                <Legend iconType="circle" iconSize={7} wrapperStyle={{ fontSize: 10 }} />
                <Bar dataKey="precision" fill="var(--blue)" radius={3} />
                <Bar dataKey="recall" fill="var(--purple)" radius={3} />
                <Bar dataKey="f1" fill="var(--green)" radius={3} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card className="table-card">
        <CardHead title="Five-Class Detailed Classification Report" subtitle="Per-class validation performance" />
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Class</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>Support</th>
                <th>Performance Indicator</th>
              </tr>
            </thead>
            <tbody>
              {fiveClassMetrics.map((item) => (
                <tr key={item.name}>
                  <td><strong>{item.name}</strong></td>
                  <td>{item.precision}%</td>
                  <td>{item.recall}%</td>
                  <td>
                    <Badge tone={item.f1 > 95 ? 'green' : item.f1 > 92 ? 'blue' : 'amber'}>
                      {item.f1}%
                    </Badge>
                  </td>
                  <td className="muted">{item.support}</td>
                  <td>
                    <span className="wide-progress">
                      <i style={{ width: `${item.f1}%` }} />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

/* =========================================================
   MAIN APP SHELL
========================================================= */
export default function App() {
  const [page, setPage] = useState<PageId>('overview')
  const [sidebar, setSidebar] = useState(false)
  const [incidentId, setIncidentId] = useState('REC-10004')
  const [globalSearch, setGlobalSearch] = useState('')
  const [backendOnline, setBackendOnline] = useState(false)

  useEffect(() => {
    let active = true
    const checkBackend = async () => {
      try {
        await api.health()
        if (active) setBackendOnline(true)
      } catch {
        if (active) setBackendOnline(false)
      }
    }
    void checkBackend()
    const timer = window.setInterval(checkBackend, 10000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  const pageInfo = useMemo(() => {
    return {
      overview: [
        'Security Operations & Replay Center',
        'CyberSentinel Day 2: 5-Agent Detection & Defense System (Level 2)',
      ],
      replay: [
        'Chronological Evaluation Replay',
        'Enforcing active defense policies BEFORE analyzing newly allowed flows',
      ],
      agents: [
        '5-Agent Architecture (A1–A5)',
        'A1+A2 (Detect) ➔ A3+A4 (Correlate) ➔ A5 (Respond) Integration Pipeline',
      ],
      defense: [
        'Adaptive Defense & Temporal Groups',
        'Demonstrable outputs for Agent 4 (Temporal Correlation) and Agent 5 (Adaptive Defense)',
      ],
      submissions: [
        'Final CSV Submissions (API Upload)',
        'Generate, validate and export classification.csv, policy.csv, and replay.csv',
      ],
      investigation: [
        'Incident Investigation',
        'Explainable 5-agent evidence trace and chronological decision rationale',
      ],
      intelligence: [
        'Threat Intelligence',
        'Five-class threat distribution and targeted destination endpoints',
      ],
      performance: [
        'Model Performance',
        'Official 5-class confusion matrix, precision, recall, and agent telemetry',
      ],
    }[page]
  }, [page])

  const navigate = (id: PageId) => {
    setPage(id)
    setSidebar(false)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const openIncident = (id: string) => {
    setIncidentId(id)
    navigate('investigation')
  }

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <aside className={sidebar ? 'sidebar open' : 'sidebar'}>
        <div className="brand">
          <div className="brand-mark">
            <Shield size={20} />
            <i />
          </div>
          <div>
            <strong>
              CYBER<span>SENTINEL</span>
            </strong>
            <small>5-AGENT DETECTION & DEFENSE</small>
          </div>
          <Button className="sidebar-close" onClick={() => setSidebar(false)}>
            <X size={18} />
          </Button>
        </div>

        <nav>
          {nav.map((item) => {
            const Icon = item.icon
            return (
              <Button
                key={item.id}
                onClick={() => navigate(item.id)}
                className={`nav-item ${page === item.id ? 'active' : ''}`}
              >
                <Icon size={16} />
                <span className="flex-1 text-left">{item.label}</span>
                {item.badge && (
                  <span className="text-[7px] px-1 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold">
                    {item.badge}
                  </span>
                )}
                {page === item.id && <i />}
              </Button>
            )
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="replay-card">
            <div>
              <span className="pulse-dot" />
              <strong>Evaluation Replay</strong>
            </div>
            <p>Track 1 · Chronological Order</p>
            <div className="replay-progress">
              <i />
            </div>
            <span>100% Policy-First Compliant</span>
          </div>
          <div className="sidebar-foot">
            <ShieldCheck size={14} />
            <span>5 Agents Online</span>
            <Badge tone="green">Day 2</Badge>
          </div>
        </div>
      </aside>

      {sidebar && (
        <Button className="mobile-overlay" onClick={() => setSidebar(false)}>
          <span className="sr-only">Close menu</span>
        </Button>
      )}

      {/* Main Content Area */}
      <main className="main">
        <header className="topbar">
          <Button className="menu-button" onClick={() => setSidebar(true)}>
            <Menu size={19} />
          </Button>

          <div className="global-search">
            <Search size={15} />
            <Input
              value={globalSearch}
              onChange={setGlobalSearch}
              placeholder="Search record IDs (REC-...), IPs, policies..."
            />
            <kbd>⌘ K</kbd>
          </div>

          <div className="top-actions">
            <Badge tone={backendOnline ? 'green' : 'blue'}>
              <span className="pulse-dot" />{' '}
              {backendOnline ? 'Backend Connected' : 'Scored Replay Mode'}
            </Badge>

            <Badge tone="cyan">
              <Bot size={11} /> 5 Agents (A1–A5)
            </Badge>

            <div className="system-live">
              <span className="pulse-dot" />
              <div>
                <strong>All 5 Agents Active</strong>
                <small>A4 Correlate · A5 Respond</small>
              </div>
            </div>

            <Button className="icon-button" title="Alerts">
              <Bell size={16} />
              <i />
            </Button>

            <Button className="profile">
              <span>CS</span>
              <div>
                <strong>CyberSentinel</strong>
                <small>Track 1 SOC</small>
              </div>
              <ChevronDown size={13} />
            </Button>
          </div>
        </header>

        <div className="content">
          <div className="page-header">
            <div>
              <div className="breadcrumb">
                <span>CYBERSENTINEL</span>
                <ChevronRight size={11} />
                <span>TRACK 1 | LEVEL 2</span>
                <ChevronRight size={11} />
                <span>{pageInfo[0]}</span>
              </div>
              <h1>{pageInfo[0]}</h1>
              <p>{pageInfo[1]}</p>
            </div>
            <div className="header-actions">
              <Badge tone="blue">
                <Clock3 size={11} /> 31 October Evaluation
              </Badge>
              <Badge tone="green">5-Agent System</Badge>
            </div>
          </div>

          {page === 'overview' && (
            <Overview openIncident={openIncident} navigateTo={navigate} />
          )}
          {page === 'replay' && (
            <ChronologicalReplay openIncident={openIncident} />
          )}
          {page === 'agents' && <FiveAgents />}
          {page === 'defense' && <AdaptiveDefenseView />}
          {page === 'submissions' && <SubmissionsView />}
          {page === 'investigation' && (
            <Investigation incidentId={incidentId} />
          )}
          {page === 'intelligence' && <Intelligence />}
          {page === 'performance' && <Performance />}
        </div>
      </main>
    </div>
  )
}
