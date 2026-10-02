import type {
  ActorRole,
  BasisItemType,
  BasisStatus,
  ControlEvidence,
  MitigationTask,
  ReviewBasis,
  ReviewBasisItem,
  ReviewDecision,
  ReviewStatus,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { evidenceIsExpired } from '@/services/selectors'

export const SCHEMA_VERSION = 2
export const REQUIRED_ROLES: ActorRole[] = ['development', 'security', 'business']

/* ------------------------------------------------------------------ */
/* 指纹：提交意见时把关联内容固化成可比对的快照                         */
/* ------------------------------------------------------------------ */

const stableStringify = (value: unknown): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map((entry) => stableStringify(entry)).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
  return `{${entries
    .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`)
    .join(',')}}`
}

/** FNV-1a 32 位哈希，指纹只用于本地比对，不需要加密强度 */
const hash = (input: string): string => {
  let value = 0x811c9dc5
  for (let index = 0; index < input.length; index += 1) {
    value ^= input.charCodeAt(index)
    value = Math.imul(value, 0x01000193)
  }
  return (value >>> 0).toString(16).padStart(8, '0')
}

export const fingerprintOf = (value: unknown): string => hash(stableStringify(value))

export const threatFingerprint = (threat: Threat): string =>
  fingerprintOf({
    code: threat.code,
    title: threat.title,
    category: threat.category,
    description: threat.description,
    severity: threat.severity,
    componentIds: [...threat.componentIds].sort(),
    flowIds: [...threat.flowIds].sort(),
    externalDependencyIds: [...threat.externalDependencyIds].sort(),
    attackPathIds: [...threat.attackPathIds].sort(),
    controlIds: [...threat.controlIds].sort(),
    riskIds: [...threat.riskIds].sort(),
  })

const evidenceFingerprint = (evidence: ControlEvidence): string =>
  fingerprintOf({
    title: evidence.title,
    kind: evidence.kind,
    reference: evidence.reference,
    collectedAt: evidence.collectedAt,
    expiresAt: evidence.expiresAt,
    owner: evidence.owner,
    valid: evidence.valid,
  })

const mitigationFingerprint = (task: MitigationTask): string =>
  fingerprintOf({
    threatId: task.threatId,
    title: task.title,
    owner: task.owner,
    dueAt: task.dueAt,
    status: task.status,
    action: task.action,
    detail: task.detail,
    evidenceIds: [...task.evidenceIds].sort(),
    conflictGroup: task.conflictGroup ?? '',
  })

/* ------------------------------------------------------------------ */
/* 依据采集                                                             */
/* ------------------------------------------------------------------ */

const evidenceEffective = (state: ThreatModelState, evidenceId: string): boolean => {
  const evidence = state.evidence.find((item) => item.id === evidenceId)
  return Boolean(evidence && evidence.valid && !evidenceIsExpired(evidence))
}

const dedupe = (items: ReviewBasisItem[]): ReviewBasisItem[] => {
  const seen = new Set<string>()
  return items.filter((item) => {
    const key = `${item.type}:${item.id}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const evidenceLabel = (evidence: ControlEvidence): string =>
  `证据 ${evidence.title}（${evidence.reference}）`

const mitigationLabel = (task: MitigationTask): string => `缓解任务 ${task.title}`

/**
 * 提交会签意见时记录审核依据：威胁本体、威胁关联控制下的全部有效证据，
 * 以及挂在该威胁上的全部缓解任务（含任务关联证据）。
 */
export const captureBasis = (state: ThreatModelState, threat: Threat): ReviewBasis => {
  const evidenceIds = new Set<string>()
  threat.controlIds.forEach((controlId) => {
    state.controls
      .find((control) => control.id === controlId)
      ?.evidenceIds.forEach((id) => evidenceIds.add(id))
  })
  state.mitigations
    .filter((task) => task.threatId === threat.id)
    .forEach((task) => task.evidenceIds.forEach((id) => evidenceIds.add(id)))

  const evidenceItems = [...evidenceIds]
    .map((id) => state.evidence.find((item) => item.id === id))
    .filter((item): item is ControlEvidence => Boolean(item))
    .map<ReviewBasisItem>((evidence) => ({
      type: 'evidence',
      id: evidence.id,
      label: evidenceLabel(evidence),
      fingerprint: evidenceFingerprint(evidence),
      effective: evidence.valid && !evidenceIsExpired(evidence),
    }))

  const mitigationItems = state.mitigations
    .filter((task) => task.threatId === threat.id)
    .map<ReviewBasisItem>((task) => ({
      type: 'mitigation',
      id: task.id,
      label: mitigationLabel(task),
      fingerprint: mitigationFingerprint(task),
    }))

  return {
    threatRevision: threat.revision,
    threatFingerprint: threatFingerprint(threat),
    items: dedupe([...evidenceItems, ...mitigationItems]),
    capturedAt: new Date().toISOString(),
  }
}

/* ------------------------------------------------------------------ */
/* 依据校验                                                             */
/* ------------------------------------------------------------------ */

export interface BasisEvaluation {
  status: 'confirmed' | 'invalidated'
  reason?: string
}

const invalidated = (reason: string): BasisEvaluation => ({ status: 'invalidated', reason })

/** 按提交时记录的依据逐项核对当前模型 */
export const evaluateBasis = (
  state: ThreatModelState,
  decision: ReviewDecision,
): BasisEvaluation => {
  const basis = decision.basis
  if (!basis) return { status: 'confirmed' }

  const threat = state.threats.find((item) => item.id === decision.threatId)
  if (!threat) return invalidated('关联威胁已从当前版本移除')
  if (threatFingerprint(threat) !== basis.threatFingerprint) {
    return invalidated(`威胁内容已修订（r${basis.threatRevision} → r${threat.revision}）`)
  }

  for (const item of basis.items) {
    if (item.type === 'evidence') {
      const evidence = state.evidence.find((entry) => entry.id === item.id)
      if (!evidence) return invalidated(`控制证据已删除：${item.label}`)
      if (item.effective && (!evidence.valid || evidenceIsExpired(evidence))) {
        const reason = evidenceIsExpired(evidence)
          ? `控制证据已过期：${evidenceLabel(evidence)}`
          : `控制证据已失效：${evidenceLabel(evidence)}`
        return invalidated(reason)
      }
      if (evidenceFingerprint(evidence) !== item.fingerprint) {
        return invalidated(`控制依据内容已变更：${evidenceLabel(evidence)}`)
      }
    }
    if (item.type === 'mitigation') {
      const task = state.mitigations.find((entry) => entry.id === item.id)
      if (!task) return invalidated(`缓解任务已删除：${item.label}`)
      if (mitigationFingerprint(task) !== item.fingerprint) {
        return invalidated(`缓解任务已更新：${mitigationLabel(task)}`)
      }
    }
  }

  return { status: 'confirmed' }
}

/* ------------------------------------------------------------------ */
/* 变更影响面：找到可能被某项变更波及的全部威胁                         */
/* ------------------------------------------------------------------ */

const threatsUsingEvidence = (state: ThreatModelState, evidenceId: string): Threat[] => {
  const controlIds = new Set(
    state.controls
      .filter((control) => control.evidenceIds.includes(evidenceId))
      .map((control) => control.id),
  )
  const mitigationThreatIds = new Set(
    state.mitigations
      .filter((task) => task.evidenceIds.includes(evidenceId))
      .map((task) => task.threatId),
  )
  return state.threats.filter(
    (threat) =>
      threat.controlIds.some((controlId) => controlIds.has(controlId)) ||
      mitigationThreatIds.has(threat.id),
  )
}

export const affectedThreatsByChange = (
  state: ThreatModelState,
  collection: string,
  item: { id: string } & Partial<Threat> & Partial<ControlEvidence> & Partial<MitigationTask>,
): Threat[] => {
  if (collection === 'threats') {
    return state.threats.filter((threat) => threat.id === item.id)
  }
  if (collection === 'evidence') {
    return threatsUsingEvidence(state, item.id)
  }
  if (collection === 'mitigations') {
    const threatId = (item as MitigationTask).threatId
    return state.threats.filter((threat) => threat.id === threatId)
  }
  if (collection === 'controls') {
    return state.threats.filter((threat) => threat.controlIds.includes(item.id))
  }
  return []
}

/* ------------------------------------------------------------------ */
/* 会签状态重算：只统计依据仍然成立的意见                               */
/* ------------------------------------------------------------------ */

export const activeDecisionsForThreat = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ReviewDecision[] =>
  decisions.filter(
    (decision) =>
      decision.threatId === threatId &&
      decision.revision === revision &&
      decision.basisStatus === 'confirmed',
  )

/**
 * 依据当前仍然成立的意见重新计算威胁审核状态。
 * 三端（开发、安全、业务）一致通过才算通过；任一有效意见驳回即驳回；否则审核中。
 */
export const recomputeThreatReviewStatus = (
  state: ThreatModelState,
  threat: Threat,
): ReviewStatus => {
  if (threat.reviewStatus === 'draft') return 'draft'
  const active = activeDecisionsForThreat(state.decisions, threat.id, threat.revision)
  if (active.some((decision) => decision.decision === 'rejected')) return 'rejected'
  const approvedRoles = new Set(
    active.filter((decision) => decision.decision === 'approved').map((decision) => decision.role),
  )
  if (REQUIRED_ROLES.every((role) => approvedRoles.has(role))) return 'approved'
  return 'in_review'
}

/**
 * 重新核对受影响威胁的全部意见。依据失效的通过意见标记为 invalidated 并写明原因；
 * 其他角色、其他威胁的意见原样保留。返回状态被重置的威胁 ID。
 */
export const invalidateDecisionsForThreats = (
  state: ThreatModelState,
  threats: Threat[],
  options: { markAudit?: boolean } = {},
): string[] => {
  const threatIds = new Set(threats.map((threat) => threat.id))
  const changedThreatIds = new Set<string>()
  const now = new Date().toISOString()

  state.decisions.forEach((decision) => {
    if (!threatIds.has(decision.threatId) || decision.basisStatus !== 'confirmed' || !decision.basis) {
      return
    }
    const evaluation = evaluateBasis(state, decision)
    if (evaluation.status === 'invalidated' && evaluation.reason) {
      decision.basisStatus = 'invalidated'
      decision.invalidReason = evaluation.reason
      decision.invalidatedAt = now
      changedThreatIds.add(decision.threatId)
      if (options.markAudit) {
        state.audit.unshift({
          id: `aud-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
          entityType: 'decision',
          entityId: decision.id,
          action: '会签依据失效',
          actor: '系统',
          createdAt: now,
          detail: `${decision.actor}（${decision.role}）对 ${decision.threatId} 的通过意见失效：${evaluation.reason}`,
        })
      }
    }
  })

  state.threats.forEach((threat) => {
    if (!threatIds.has(threat.id)) return
    const nextStatus = recomputeThreatReviewStatus(state, threat)
    if (threat.reviewStatus !== 'draft' && threat.reviewStatus !== nextStatus) {
      threat.reviewStatus = nextStatus
      changedThreatIds.add(threat.id)
    }
  })

  return [...changedThreatIds]
}

/* ------------------------------------------------------------------ */
/* 升级回填：历史数据按修订号重建依据，无法确认的等待复核               */
/* ------------------------------------------------------------------ */

const backfillDecision = (state: ThreatModelState, decision: ReviewDecision): void => {
  const threat = state.threats.find((item) => item.id === decision.threatId)
  // 历史记录没有依据快照：按修订号回填，修订号无法对上的等待人工复核
  if (!threat || threat.revision !== decision.revision) {
    decision.basisStatus = 'unverified'
    decision.invalidReason = '历史会签记录缺少审核依据，且修订号无法与当前威胁对齐，等待复核'
    return
  }

  const basis = captureBasis(state, threat)
  basis.threatRevision = decision.revision
  basis.reconstructed = true
  decision.basis = basis

  const evaluation = evaluateBasis(state, { ...decision, basis })
  if (evaluation.status === 'invalidated' && evaluation.reason) {
    decision.basisStatus = 'unverified'
    decision.invalidReason = `历史依据无法确认，等待复核：${evaluation.reason}`
  } else {
    decision.basisStatus = 'confirmed'
  }
}

/**
 * 升级本地数据：为没有依据快照的历史意见回填依据；
 * 随后全量重新核对一次（覆盖证据过期等静默变化），并重算威胁审核状态。
 */
export const migrateState = (state: ThreatModelState): boolean => {
  let changed = false

  state.decisions.forEach((decision) => {
    if (!decision.basis || !decision.basisStatus) {
      backfillDecision(state, decision)
      changed = true
    }
  })

  const expiredNow = new Set<string>()
  state.decisions.forEach((decision) => {
    if (decision.basisStatus === 'confirmed' && decision.basis) {
      const evaluation = evaluateBasis(state, decision)
      if (evaluation.status === 'invalidated' && evaluation.reason) {
        decision.basisStatus = 'invalidated'
        decision.invalidReason = evaluation.reason
        decision.invalidatedAt = new Date().toISOString()
        expiredNow.add(decision.threatId)
        changed = true
      }
    }
  })

  state.threats.forEach((threat) => {
    if (threat.reviewStatus === 'draft') return
    const nextStatus = recomputeThreatReviewStatus(state, threat)
    if (threat.reviewStatus !== nextStatus) {
      threat.reviewStatus = nextStatus
      expiredNow.add(threat.id)
      changed = true
    }
  })

  if (expiredNow.size > 0) {
    state.audit.unshift({
      id: `aud-${Date.now().toString(36)}-migration`,
      entityType: 'decision',
      entityId: 'migration',
      action: '升级回填审核依据',
      actor: '系统',
      createdAt: new Date().toISOString(),
      detail: `已按修订号回填历史会签依据，${expiredNow.size} 条威胁的会签状态需要重新复核。`,
    })
  }

  state.schemaVersion = SCHEMA_VERSION
  return changed
}

/* ------------------------------------------------------------------ */
/* 版本发布闸门                                                        */
/* ------------------------------------------------------------------ */

export interface VersionReadiness {
  version: VersionSnapshot
  total: number
  passed: number
  blockers: { threatId: string; code: string; title: string; reasons: string[] }[]
  ready: boolean
}

export const assessVersionReadiness = (
  state: ThreatModelState,
  version: VersionSnapshot,
): VersionReadiness => {
  const blockers: VersionReadiness['blockers'] = []
  let passed = 0

  version.affectedThreatIds.forEach((threatId) => {
    const threat = state.threats.find((item) => item.id === threatId)
    const reasons: string[] = []
    if (!threat) {
      reasons.push('威胁已不存在')
    } else {
      const active = activeDecisionsForThreat(state.decisions, threat.id, threat.revision)
      if (active.some((decision) => decision.decision === 'rejected')) {
        reasons.push('存在驳回意见，停止发布')
      }

      const decisionsByRole = new Map(active.map((decision) => [decision.role, decision]))
      REQUIRED_ROLES.forEach((role) => {
        const roleDecision = decisionsByRole.get(role)
        if (!roleDecision) {
          reasons.push(`缺少${roleLabel(role)}的会签意见`)
        } else if (roleDecision.decision !== 'approved') {
          reasons.push(`${roleLabel(role)}意见为「${decisionTypeLabel(roleDecision.decision)}」，未通过`)
        }
      })

      state.decisions
        .filter(
          (decision) =>
            decision.threatId === threat.id &&
            decision.revision === threat.revision &&
            decision.basisStatus !== 'confirmed',
        )
        .forEach((decision) => {
          const prefix =
            decision.basisStatus === 'unverified' ? '依据待复核' : '依据已失效'
          reasons.push(
            `${roleLabel(decision.role)}的${prefix}：${decision.invalidReason ?? '审核依据无法确认'}`,
          )
        })

      // 证据闸门：威胁关联控制必须具备未过期且有效的证据
      threat.controlIds.forEach((controlId) => {
        const control = state.controls.find((item) => item.id === controlId)
        if (!control) return
        const hasValidEvidence = control.evidenceIds.some((evidenceId) =>
          evidenceEffective(state, evidenceId),
        )
        if (!hasValidEvidence) {
          reasons.push(`关联控制「${control.name}」缺少有效控制证据，停止发布`)
        }
      })
    }

    const uniqueReasons = [...new Set(reasons)]
    if (uniqueReasons.length > 0) {
      blockers.push({
        threatId,
        code: threat?.code ?? threatId,
        title: threat?.title ?? '威胁已删除',
        reasons: uniqueReasons,
      })
    } else {
      passed += 1
    }
  })

  return {
    version,
    total: version.affectedThreatIds.length,
    passed,
    blockers,
    ready: blockers.length === 0,
  }
}

export const roleLabel = (role: ActorRole): string => {
  const labels: Record<ActorRole, string> = {
    development: '开发负责人',
    security: '安全负责人',
    business: '业务负责人',
  }
  return labels[role]
}

export const decisionTypeLabel = (decision: ReviewDecision['decision']): string => {
  const labels: Record<ReviewDecision['decision'], string> = {
    accept: '接受条件',
    degrade: '同意降级',
    evidence_required: '要求补证',
    approved: '通过',
    rejected: '驳回',
  }
  return labels[decision]
}

export const basisStatusLabel = (status: BasisStatus | undefined): string => {
  const labels: Record<BasisStatus, string> = {
    confirmed: '依据成立',
    invalidated: '依据失效',
    unverified: '待复核',
  }
  return status ? labels[status] : '无依据'
}

export type { BasisItemType }
