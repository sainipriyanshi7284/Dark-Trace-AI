export type PageId =
  | 'overview'
  | 'replay'
  | 'agents'
  | 'defense'
  | 'submissions'
  | 'intelligence'
  | 'investigation'
  | 'performance'

export type Tone = 'blue' | 'green' | 'red' | 'amber' | 'purple' | 'slate' | 'cyan'

export type ThreatClass = 'Benign' | 'DoS' | 'PortScan' | 'Botnet' | 'Brute Force'

export type DecisionAction = 'ALLOW' | 'BLOCK'

export type EvidenceStatus =
  | 'CONFIRMED_DOS'
  | 'TRAFFIC_SPIKE_ANOMALY'
  | 'TEMPORAL_BURST_CORRELATED'
  | 'POLICY_ENFORCED_BLOCK'
  | 'BENIGN_VERIFIED'
  | 'SUSPICIOUS_UNCONFIRMED'

export interface ReplayFlowRecord {
  record_id: string
  time: string
  source_ip: string
  destination_ip: string
  destination_port: number
  protocol: 'TCP' | 'UDP' | 'ICMP'
  flow_duration: number
  packet_count: number
  byte_count: number
  // A1 Output
  a1_predicted_class: ThreatClass
  a1_confidence: number
  // A2 Output
  a2_anomaly_score: number
  a2_traffic_flag: boolean
  // A3 Output
  a3_fusion_score: number
  a3_verdict: ThreatClass
  // A4 Output
  a4_group_id: string | null
  a4_correlated: boolean
  a4_pattern_desc?: string
  // A5 Pre-check & Output
  applied_policy_id: string
  policy_blocked_prior: boolean
  final_action: DecisionAction
  evidence_status: EvidenceStatus
  // Triggered policy if this flow activated a new policy
  activated_policy_id?: string
}

export interface DefensePolicy {
  policy_id: string
  activated_after_record_id: string
  scope_type: 'SOURCE_IP'
  scope_value: string
  expires_after_record_id: string
  policy_action: 'BLOCK'
  trigger_reason: string
  time_activated: string
  flows_intercepted: number
  status: 'ACTIVE' | 'EXPIRED'
}

export interface TemporalCorrelationGroup {
  group_id: string
  time_window: string
  source_endpoints: string[]
  target_endpoints: string[]
  member_record_ids: string[]
  pattern_type: 'Burst DoS Attack' | 'Distributed Port Sweep' | 'C2 Beaconing Pattern' | 'Credential Brute Force'
  confidence: number
  evidence_summary: string
  associated_policy_id: string | null
}

export interface AgentInfo {
  id: string
  number: string
  name: string
  role: string
  model_type: string
  phase: 'DETECT' | 'CORRELATE' | 'RESPOND'
  tone: Tone
  status: 'ONLINE' | 'ACTIVE' | 'EVALUATING'
  description: string
  demonstrable_output: string
  evidence_metric: string
  evidence_score: number
}

