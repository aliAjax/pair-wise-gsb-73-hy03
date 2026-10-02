import type {
  BasisEntry,
  ControlEvidence,
  MitigationTask,
  ReleaseBlocker,
  ReviewDecision,
  SecurityControl,
  Threat,
  ThreatModelState,
} from '@/models/domain'
import { evidenceIsExpired } from '@/services/selectors'

export const CURRENT_SCHEMA_VERSION = 2
const REQUIRED_ROLES = ['development', 'security', 'business'] as const

const stableStringify = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(',')}]`
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
    return `{${entries.map(([key, item]) => `"${key}":${stableStringify(item)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

const threatFingerprint = (threat: Threat): string =>
  stableStringify({
    code: threat.code,
    title: threat.title,
    category: threat.category,
    description: threat.description,
    severity: threat.severity,
    status: threat.status,
    componentIds: threat.componentIds,
    flowIds: threat.flowIds,
    externalDependencyIds: threat.externalDependencyIds,
    attackPathIds: threat.attackPathIds,
    controlIds: threat.controlIds,
    riskIds: threat.riskIds,
  })

const controlFingerprint = (control: SecurityControl): string =>
  stableStringify({
    name: control.name,
    type: control.type,
    status: control.status,
    owner: control.owner,
    componentId: control.componentId,
    description: control.description,
    evidenceIds: control.evidenceIds,
  })

const evidenceFingerprint = (evidence: ControlEvidence): string =>
  stableStringify({
    controlId: evidence.controlId,
    title: evidence.title,
    kind: evidence.kind,
    reference: evidence.reference,
    collectedAt: evidence.collectedAt,
    expiresAt: evidence.expiresAt,
    owner: evidence.owner,
    valid: evidence.valid,
  })

const mitigationFingerprint = (task: MitigationTask): string =>
  stableStringify({
    threatId: task.threatId,
    title: task.title,
    owner: task.owner,
    dueAt: task.dueAt,
    status: task.status,
    action: task.action,
    detail: task.detail,
    evidenceIds: task.evidenceIds,
    conflictGroup: task.conflictGroup,
  })

/** 提交会签意见时，把威胁、关联控制、控制证据、缓解任务快照为审核依据。 */
export const buildBasisForThreat = (state: ThreatModelState, threat: Threat): BasisEntry[] => {
  const entries: BasisEntry[] = [
    {
      kind: 'threat',
      refId: threat.id,
      label: `${threat.code} ${threat.title}`,
      fingerprint: threatFingerprint(threat),
      revision: threat.revision,
    },
  ]
  const seenEvidence = new Set<string>()

  const appendEvidence = (evidenceId: string): void => {
    if (seenEvidence.has(evidenceId)) return
    const evidence = state.evidence.find((item) => item.id === evidenceId)
    if (!evidence) return
    seenEvidence.add(evidenceId)
    entries.push({
      kind: 'evidence',
      refId: evidence.id,
      label: evidence.title,
      fingerprint: evidenceFingerprint(evidence),
      revision: state.currentRevision,
    })
  }

  threat.controlIds.forEach((controlId) => {
    const control = state.controls.find((item) => item.id === controlId)
    if (!control) return
    entries.push({
      kind: 'control',
      refId: control.id,
      label: control.name,
      fingerprint: controlFingerprint(control),
      revision: state.currentRevision,
    })
    control.evidenceIds.forEach(appendEvidence)
  })

  state.mitigations
    .filter((task) => task.threatId === threat.id)
    .forEach((task) => {
      entries.push({
        kind: 'mitigation',
        refId: task.id,
        label: task.title,
        fingerprint: mitigationFingerprint(task),
        revision: state.currentRevision,
      })
      task.evidenceIds.forEach(appendEvidence)
    })

  return entries
}

/** 校验单条依据是否仍然成立；返回 null 表示成立，否则返回失效原因。 */
export const validateBasisEntry = (
  state: ThreatModelState,
  entry: BasisEntry,
): string | null => {
  if (entry.kind === 'threat') {
    const threat = state.threats.find((item) => item.id === entry.refId)
    if (!threat) return `审核依据威胁《${entry.label}》已被删除`
    if (threatFingerprint(threat) !== entry.fingerprint) {
      return `审核依据威胁《${entry.label}》内容已修订，原通过意见失效`
    }
    return null
  }

  if (entry.kind === 'control') {
    const control = state.controls.find((item) => item.id === entry.refId)
    if (!control) return `审核依据控制《${entry.label}》已被移除`
    if (controlFingerprint(control) !== entry.fingerprint) {
      return `审核依据控制《${entry.label}》状态或配置发生变化，原通过意见失效`
    }
    return null
  }

  if (entry.kind === 'mitigation') {
    const task = state.mitigations.find((item) => item.id === entry.refId)
    if (!task) return `审核依据缓解任务《${entry.label}》已被删除`
    if (mitigationFingerprint(task) !== entry.fingerprint) {
      return `审核依据缓解任务《${entry.label}》发生变化，原通过意见失效`
    }
    return null
  }

  const evidence = state.evidence.find((item) => item.id === entry.refId)
  if (!evidence) return `审核依据证据《${entry.label}》已被删除`
  if (evidenceFingerprint(evidence) !== entry.fingerprint) {
    return `审核依据证据《${entry.label}》内容发生变化，原通过意见失效`
  }
  if (!evidence.valid) {
    return `审核依据证据《${entry.label}》已被标记为失效，原通过意见失效`
  }
  if (evidenceIsExpired(evidence)) {
    return `审核依据证据《${entry.label}》已于 ${evidence.expiresAt} 到期，原通过意见失效`
  }
  return null
}

export const validateDecision = (state: ThreatModelState, decision: ReviewDecision): string | null => {
  for (const entry of decision.basis ?? []) {
    const reason = validateBasisEntry(state, entry)
    if (reason) return reason
  }
  return null
}

export interface Invalidation {
  decisionId: string
  threatId: string
  actor: string
  role: string
  reason: string
}

/**
 * 重新校验给定威胁当前修订号下仍然生效的“通过”意见。
 * 其他角色、其他威胁以及非通过意见保持不变。
 */
export const revalidateThreatApprovals = (
  state: ThreatModelState,
  threatIds: string[],
): Invalidation[] => {
  const scope = new Set(threatIds)
  const invalidations: Invalidation[] = []
  const touchedThreatIds = new Set<string>()

  state.decisions.forEach((decision) => {
    if (decision.state !== 'active' || decision.decision !== 'approved') return
    const threat = state.threats.find((item) => item.id === decision.threatId)
    if (!threat || !scope.has(threat.id) || decision.revision !== threat.revision) return
    const reason = validateDecision(state, decision)
    if (!reason) return
    decision.state = 'invalidated'
    decision.invalidReason = reason
    decision.invalidatedAt = new Date().toISOString()
    invalidations.push({
      decisionId: decision.id,
      threatId: decision.threatId,
      actor: decision.actor,
      role: decision.role,
      reason,
    })
    touchedThreatIds.add(decision.threatId)
  })

  touchedThreatIds.forEach((threatId) => {
    const threat = state.threats.find((item) => item.id === threatId)
    if (threat) threat.reviewStatus = resolveThreatReviewStatus(state, threat)
  })
  return invalidations
}

/**
 * 威胁被编辑修订时，把该威胁此前修订号下仍生效的“通过”意见统一作失效处理，
 * 并写明原因。其他角色的非通过意见与其他威胁不受影响。
 */
export const invalidateThreatApprovals = (
  state: ThreatModelState,
  threatId: string,
  threatLabel: string,
): Invalidation[] => {
  const invalidations: Invalidation[] = []
  state.decisions.forEach((decision) => {
    if (decision.threatId !== threatId) return
    if (decision.state !== 'active' || decision.decision !== 'approved') return
    decision.state = 'invalidated'
    decision.invalidReason = `审核依据威胁《${threatLabel}》已修订并进入重新审核，原通过意见失效`
    decision.invalidatedAt = new Date().toISOString()
    invalidations.push({
      decisionId: decision.id,
      threatId,
      actor: decision.actor,
      role: decision.role,
      reason: decision.invalidReason,
    })
  })
  return invalidations
}

/** 当前修订号下仍然生效的会签意见（失效、待复核的不计入）。 */
export const activeDecisionsForThreat = (
  state: ThreatModelState,
  threatId: string,
  revision: number,
): ReviewDecision[] =>
  state.decisions.filter(
    (decision) =>
      decision.threatId === threatId &&
      decision.revision === revision &&
      decision.state === 'active',
  )

/** 版本线内（版本修订号起）最近一轮会签意见。 */
export const latestRoundDecisions = (
  state: ThreatModelState,
  threatId: string,
  versionRevision: number,
): ReviewDecision[] => {
  const threat = state.threats.find((item) => item.id === threatId)
  const upper = threat?.revision ?? versionRevision
  const inVersion = state.decisions.filter(
    (decision) =>
      decision.threatId === threatId &&
      decision.revision >= versionRevision &&
      decision.revision <= upper,
  )
  if (inVersion.length === 0) return []
  const latestRound = Math.max(...inVersion.map((decision) => decision.signRound ?? 0))
  return inVersion.filter((decision) => (decision.signRound ?? 0) === latestRound)
}

export const resolveThreatReviewStatus = (
  state: ThreatModelState,
  threat: Threat,
): Threat['reviewStatus'] => {
  const current = latestRoundDecisions(state, threat.id, threat.revision)
  const active = current.filter((decision) => decision.state === 'active')
  if (active.length === 0) {
    return threat.reviewStatus === 'draft' ? 'draft' : 'in_review'
  }
  if (active.some((decision) => decision.decision === 'rejected')) return 'rejected'
  const approvedRoles = new Set(
    active.filter((decision) => decision.decision === 'approved').map((decision) => decision.role),
  )
  if (REQUIRED_ROLES.every((role) => approvedRoles.has(role))) return 'approved'
  return 'in_review'
}

/**
 * 版本发布门禁：受影响威胁必须三端各有一条生效的通过意见；
 * 任一驳回、依据失效或角色缺失都阻止发布。
 */
export const releaseReadiness = (
  state: ThreatModelState,
  version: { revision: number; affectedThreatIds: string[] },
): { canRelease: boolean; blockers: ReleaseBlocker[] } => {
  const blockers: ReleaseBlocker[] = []
  const roleLabels: Record<string, string> = {
    development: '开发',
    security: '安全',
    business: '业务',
  }

  version.affectedThreatIds.forEach((threatId) => {
    const threat = state.threats.find((item) => item.id === threatId)
    if (!threat) {
      blockers.push({ threatId, threatCode: threatId, reason: '威胁已不存在' })
      return
    }
    const push = (reason: string): void => {
      blockers.push({ threatId, threatCode: threat.code, reason })
    }

    // 只认本版本线内（版本修订号起）最近一轮会签；依据失效后重新会签会开启新一轮
    const current = latestRoundDecisions(state, threatId, version.revision)
    if (current.length === 0) {
      push('缺少开发、安全、业务负责人的通过意见')
      return
    }

    const rejected = current.find(
      (decision) => decision.state === 'active' && decision.decision === 'rejected',
    )
    if (rejected) {
      push(`已被${rejected.actor}驳回：${rejected.comment || '驳回意见未填写'}`)
      return
    }

    for (const decision of current) {
      if (decision.state === 'invalidated') {
        push(decision.invalidReason ?? '会签通过意见的审核依据已失效')
        return
      }
      if (decision.state === 'needs_review') {
        push(`${decision.actor}的历史会签意见待复核`)
        return
      }
      if (decision.state === 'active' && decision.decision === 'approved') {
        const reason = validateDecision(state, decision)
        if (reason) {
          push(reason)
          return
        }
      }
    }

    const approvedRoles = new Set(
      current
        .filter((decision) => decision.state === 'active' && decision.decision === 'approved')
        .map((decision) => decision.role),
    )
    const missing = REQUIRED_ROLES.filter((role) => !approvedRoles.has(role))
    if (missing.length > 0) {
      push(`缺少${missing.map((role) => roleLabels[role]).join('、')}负责人的通过意见`)
    }
  })

  return { canRelease: blockers.length === 0, blockers }
}

/**
 * 升级回填：历史意见没有审核依据时按修订号重建；
 * 修订号无法对应当前威胁的意见无法确认依据，等待人工复核。
 * 返回需要提示的待复核意见数量。
 */
export const migrateLegacyState = (state: ThreatModelState): number => {
  let needsReviewCount = 0

  state.versions.forEach((version) => {
    if (version.released === undefined) version.released = false
  })

  state.threats.forEach((threat) => {
    if (threat.signRound === undefined) threat.signRound = 0
  })

  state.decisions.forEach((decision) => {
    if (!decision.state) decision.state = 'active'
    if (decision.signRound === undefined) decision.signRound = 0
    if (decision.basis) return

    const threat = state.threats.find((item) => item.id === decision.threatId)
    if (threat && threat.revision === decision.revision) {
      decision.basis = buildBasisForThreat(state, threat)
      return
    }
    decision.state = 'needs_review'
    decision.invalidReason =
      '历史会签意见未记录审核依据，且意见修订号与威胁当前修订号不一致，无法自动确认，请重新复核会签。'
    needsReviewCount += 1
  })

  state.schemaVersion = CURRENT_SCHEMA_VERSION
  return needsReviewCount
}
