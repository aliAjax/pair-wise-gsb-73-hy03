import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  ReleaseBlocker,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { createId, loadState, resetState, saveState } from '@/services/repository'
import {
  activeDecisionsForThreat,
  buildBasisForThreat,
  invalidateThreatApprovals,
  releaseReadiness,
  resolveThreatReviewStatus,
  revalidateThreatApprovals,
} from '@/services/reviewBasis'
import {
  dashboardMetrics,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const initial = loadState()
  const data = ref<ThreatModelState>(initial.state)
  const lastSavedAt = ref(new Date().toISOString())
  const legacyNeedsReviewCount = ref(initial.needsReviewCount)

  // 升级回填后加载期发现的依据失效，补记审计轨迹
  if (initial.invalidations.length > 0) {
    initial.invalidations.forEach((item) => {
      data.value.audit.unshift({
        id: createId('aud'),
        entityType: 'decision',
        entityId: item.decisionId,
        action: '会签意见失效',
        actor: '系统',
        createdAt: new Date().toISOString(),
        detail: `${item.actor}（${item.role}）对威胁 ${item.threatId} 的通过意见失效：${item.reason}`,
      })
    })
    persist()
  }

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )

  function persist(): void {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  function appendAudit(
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    data.value.audit.unshift(event)
  }

  /** 找出控制/证据/缓解任务变更波及的威胁。 */
  function impactedThreatIdsFor(
    collection: CollectionKey,
    item: IdentifiedEntity,
    previousId?: string,
  ): Set<string> {
    const id = previousId ?? item.id
    if (collection === 'controls') {
      return new Set(
        data.value.threats
          .filter((threat) => threat.controlIds.includes(id))
          .map((threat) => threat.id),
      )
    }
    if (collection === 'evidence') {
      const controlIds = new Set(
        data.value.controls
          .filter((control) => control.evidenceIds.includes(id))
          .map((control) => control.id),
      )
      return new Set(
        data.value.threats
          .filter(
            (threat) =>
              threat.controlIds.some((controlId) => controlIds.has(controlId)) ||
              data.value.mitigations.some(
                (task) => task.threatId === threat.id && task.evidenceIds.includes(id),
              ),
          )
          .map((threat) => threat.id),
      )
    }
    if (collection === 'mitigations') {
      const task = item as ThreatModelState['mitigations'][number]
      const previous = data.value.mitigations.find((entry) => entry.id === id)
      const ids = [task.threatId, previous?.threatId].filter(
        (value): value is string => Boolean(value),
      )
      return new Set(ids)
    }
    return new Set()
  }

  function applyInvalidations(threatIds: string[], sourceLabel: string): void {
    const invalidations = revalidateThreatApprovals(data.value, threatIds)
    invalidations.forEach((item) => {
      appendAudit(
        'decision',
        item.decisionId,
        '会签意见失效',
        `${sourceLabel}后，${item.actor}（${item.role}）的通过意见失效：${item.reason}`,
      )
    })
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    const existed = index >= 0
    const impacted =
      !existed && collection !== 'threats' ? new Set<string>() : impactedThreatIdsFor(collection, item)

    if (existed) {
      target[index] = item
    } else {
      target.unshift(item)
    }

    if (collection === 'controls' || collection === 'evidence' || collection === 'mitigations') {
      applyInvalidations([...impacted], `${existed ? '更新' : '新增'}${collectionLabel(collection)}`)
    }

    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, existed ? '更新' : '新增', `${label} 已保存`)
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const previous = target.find((entry) => entry.id === id)
    const impacted = previous
      ? impactedThreatIdsFor(collection, { ...previous, id: '__removed__' }, id)
      : new Set<string>()
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    if (collection === 'controls' || collection === 'evidence' || collection === 'mitigations') {
      applyInvalidations([...impacted], `删除${collectionLabel(collection)}`)
    }
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
    const previous = data.value.threats.find((item) => item.id === threat.id)
    if (previous) {
      // 威胁本身修订：此前修订号的通过意见因依据变化而失效，其他角色与威胁保留
      const invalidations = invalidateThreatApprovals(data.value, threat.id, threat.title)
      invalidations.forEach((item) => {
        appendAudit(
          'decision',
          item.decisionId,
          '会签意见失效',
          `威胁《${threat.title}》修订后，${item.actor}（${item.role}）的通过意见失效：${item.reason}`,
        )
      })
    }
    if (threat.signRound === undefined) threat.signRound = 0
    saveEntity('threats', threat)
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
      released: false,
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, signRound: 0, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核`,
    )
    persist()
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return
    if (threat.signRound === undefined) threat.signRound = 0

    const roundDecisions = data.value.decisions.filter(
      (item) =>
        item.threatId === threatId &&
        item.revision === threat.revision &&
        item.signRound === threat.signRound,
    )
    // 当前轮存在失效依据、待复核或驳回时视为轮次已结束，新提交开启下一轮；
    // 同一轮内三个角色依次提交不递增
    const roundInterrupted = roundDecisions.some(
      (item) =>
        item.state === 'invalidated' ||
        item.state === 'needs_review' ||
        (item.state === 'active' && item.decision === 'rejected'),
    )
    if (roundInterrupted) {
      threat.signRound = threat.signRound + 1
    }
    // 同角色在当前轮重新提交时替换旧意见
    data.value.decisions = data.value.decisions.filter(
      (item) =>
        !(
          item.threatId === threatId &&
          item.revision === threat.revision &&
          item.signRound === threat.signRound &&
          item.role === role
        ),
    )

    const basis = buildBasisForThreat(data.value, threat)
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
      signRound: threat.signRound,
      basis,
      state: 'active',
    })

    threat.reviewStatus = resolveThreatReviewStatus(data.value, threat)

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    appendAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见，已记录 ${basis.length} 项审核依据`,
    )
    persist()
  }

  /** 发布门禁：三端一致通过且审核依据全部成立才允许发布。 */
  const checkRelease = (
    versionId: string,
  ): { version: VersionSnapshot | null; canRelease: boolean; blockers: ReleaseBlocker[] } => {
    const version = data.value.versions.find((item) => item.id === versionId) ?? null
    if (!version) return { version: null, canRelease: false, blockers: [] }
    return { version, ...releaseReadiness(data.value, version) }
  }

  const publishVersion = (versionId: string): ReleaseBlocker[] => {
    const version = data.value.versions.find((item) => item.id === versionId)
    if (!version || version.released) return []
    const { canRelease, blockers } = releaseReadiness(data.value, version)
    if (!canRelease) return blockers
    version.released = true
    version.releasedAt = new Date().toISOString()
    version.releasedBy = '当前用户'
    appendAudit(
      'version',
      version.id,
      '发布版本',
      `${version.label} 已发布，${version.affectedThreatIds.length} 条受影响威胁三端会签通过且审核依据均有效`,
    )
    persist()
    return []
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    applyInvalidations([task.threatId], '缓解任务状态推进')
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  const resetDemo = (): void => {
    data.value = resetState()
    lastSavedAt.value = new Date().toISOString()
  }

  const exportReport = (): string => {
    const decisionStateLabel: Record<string, string> = {
      active: '生效中',
      invalidated: '已失效',
      needs_review: '待复核',
    }
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      '',
      '## 威胁清单',
      ...data.value.threats.map(
        (threat) =>
          `- ${threat.code} [${threat.severity}/${threat.reviewStatus}] ${threat.title}：${threat.description}`,
      ),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map(
          (risk) =>
            `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}，条件：${risk.acceptanceCondition ?? '未填写'}`,
        ),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录',
      ...data.value.decisions.map(
        (decision) =>
          `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision} [${decisionStateLabel[decision.state] ?? decision.state}]：${decision.comment}` +
          (decision.invalidReason ? `（失效原因：${decision.invalidReason}）` : ''),
      ),
      ...data.value.versions.map(
        (version) =>
          `- 版本 ${version.label}（r${version.revision}）：${version.released ? `已发布${version.releasedAt ? `于 ${version.releasedAt}` : ''}` : '未发布'}`,
      ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    legacyNeedsReviewCount,
    metrics,
    issues,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    checkRelease,
    publishVersion,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
    activeDecisionsForThreat,
  }
})

function collectionLabel(collection: CollectionKey): string {
  const labels: Partial<Record<CollectionKey, string>> = {
    controls: '控制',
    evidence: '控制证据',
    mitigations: '缓解任务',
  }
  return labels[collection] ?? collection
}
