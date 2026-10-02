export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'approved' | 'rejected'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type ControlStatus = 'effective' | 'degraded' | 'failed' | 'planned'
export type ActorRole = 'development' | 'security' | 'business'
export type DecisionType = 'accept' | 'degrade' | 'evidence_required' | 'approved' | 'rejected'
export type BasisStatus = 'confirmed' | 'invalidated' | 'unverified'
export type BasisItemType = 'threat' | 'evidence' | 'mitigation'

export interface SystemBoundary {
  id: string
  name: string
  description: string
  owner: string
  inScope: string
  outOfScope: string
}

export interface TrustZone {
  id: string
  name: string
  level: 'internet' | 'dmz' | 'internal' | 'restricted'
  description: string
}

export interface ArchitectureComponent {
  id: string
  name: string
  type: 'service' | 'asset' | 'data_store' | 'gateway' | 'client'
  zoneId: string
  criticality: Severity
  owner: string
  description: string
}

export interface ExternalDependency {
  id: string
  name: string
  vendor: string
  purpose: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  status: 'active' | 'review_due' | 'retired'
}

export interface DataFlow {
  id: string
  name: string
  sourceId: string
  targetId: string
  protocol: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  crossesTrustBoundary: boolean
  description: string
}

export interface ControlEvidence {
  id: string
  controlId: string
  title: string
  kind: 'test' | 'config' | 'ticket' | 'scan' | 'attestation'
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
}

export interface SecurityControl {
  id: string
  name: string
  type: 'preventive' | 'detective' | 'corrective'
  status: ControlStatus
  owner: string
  componentId: string
  description: string
  evidenceIds: string[]
}

export interface AttackPath {
  id: string
  name: string
  entryPoint: string
  target: string
  steps: string[]
  likelihood: 1 | 2 | 3 | 4 | 5
}

export interface Risk {
  id: string
  code: string
  title: string
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  status: 'open' | 'mitigating' | 'accepted' | 'closed'
  owner: string
  acceptanceExpiresAt?: string
  acceptanceCondition?: string
}

export interface Threat {
  id: string
  code: string
  title: string
  category: 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation'
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  reviewStatus: ReviewStatus
  revision: number
}

export interface MitigationTask {
  id: string
  threatId: string
  title: string
  owner: string
  dueAt: string
  status: 'todo' | 'in_progress' | 'verifying' | 'done'
  action: 'restrict' | 'monitor' | 'encrypt' | 'isolate' | 'allow_with_condition'
  detail: string
  evidenceIds: string[]
  conflictGroup?: string
}

export interface ReviewBasisItem {
  type: BasisItemType
  id: string
  label: string
  fingerprint: string
  /** 证据类依据在记录时是否有效（未失效且未过期） */
  effective?: boolean
}

export interface ReviewBasis {
  /** 依据快照创建时所在的威胁修订号 */
  threatRevision: number
  /** 威胁本体指纹 */
  threatFingerprint: string
  items: ReviewBasisItem[]
  capturedAt: string
  /** 历史回填的依据标记为重建，需要人工确认其可靠性 */
  reconstructed?: boolean
}

export interface ReviewDecision {
  id: string
  threatId: string
  actor: string
  role: ActorRole
  decision: DecisionType
  comment: string
  createdAt: string
  revision: number
  /** 提交时记录的审核依据（威胁、控制证据、缓解任务快照） */
  basis?: ReviewBasis
  basisStatus?: BasisStatus
  invalidReason?: string
  invalidatedAt?: string
}

export interface VersionSnapshot {
  id: string
  revision: number
  label: string
  createdAt: string
  author: string
  notes: string
  threatIds: string[]
  componentIds: string[]
  flowIds: string[]
  controlIds: string[]
  riskIds: string[]
  affectedThreatIds: string[]
  publishedAt?: string
  publishedBy?: string
}

export interface AuditEvent {
  id: string
  entityType: string
  entityId: string
  action: string
  actor: string
  createdAt: string
  detail: string
}

export interface ThreatModelState {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
  decisions: ReviewDecision[]
  versions: VersionSnapshot[]
  audit: AuditEvent[]
  currentRevision: number
  /** 本地数据结构版本，用于升级时回填会签依据 */
  schemaVersion?: number
}

export interface ValidationIssue {
  id: string
  kind: 'uncovered_component' | 'control_failed' | 'risk_acceptance_expired' | 'mitigation_conflict' | 'missing_evidence'
  severity: Severity
  title: string
  detail: string
  entityId: string
}

export interface VersionChange {
  category: string
  id: string
}

export interface VersionDifference {
  added: VersionChange[]
  removed: VersionChange[]
  changed: string[]
}
