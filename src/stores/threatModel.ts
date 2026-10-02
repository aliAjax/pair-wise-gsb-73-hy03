import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { createId, loadState, resetState, saveState } from '@/services/repository'
import {
  dashboardMetrics,
  getValidationIssues,
  reviewProgress,
} from '@/services/selectors'
import {
  activeDecisionsForThreat,
  affectedThreatsByChange,
  assessVersionReadiness,
  captureBasis,
  invalidateDecisionsForThreats,
  recomputeThreatReviewStatus,
  type VersionReadiness,
} from '@/services/reviewBasis'

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
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))
  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => threat.reviewStatus === 'in_review'),
  )

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
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

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    // 更新前先按旧关联计算一次影响面（例如证据被改挂到别的控制时，旧控制下的威胁也要复核）
    const previous = index >= 0 ? target[index] : undefined
    const previousImpacts = previous
      ? affectedThreatsByChange(data.value, collection, previous).map((threat) => threat.id)
      : []

    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)

    if (index >= 0) {
      // 变更后重新核对受影响威胁的会签依据，失效的通过意见自动作废
      const impactIds = new Set([
        ...previousImpacts,
        ...affectedThreatsByChange(data.value, collection, item).map((threat) => threat.id),
      ])
      const impacted = data.value.threats.filter((threat) => impactIds.has(threat.id))
      if (impacted.length > 0) {
        const resetThreatIds = invalidateDecisionsForThreats(data.value, impacted, {
          markAudit: true,
        })
        resetThreatIds.forEach((threatId) => {
          appendAudit(
            'threat',
            threatId,
            '会签状态重算',
            `${label} 的变化波及该威胁，相关会签意见已重新核对`,
          )
        })
      }
    }

    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    const removed = target[index]
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')

    const impacted = affectedThreatsByChange(data.value, collection, removed)
    if (impacted.length > 0) {
      invalidateDecisionsForThreats(data.value, impacted, { markAudit: true })
    }
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
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
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return { ...threat, revision }
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
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

  /** 评估待发布版本：版本依据下三端一致通过、且无失效证据才放行 */
  const assessLatestVersion = (): VersionReadiness | null => {
    const latest = data.value.versions[0]
    return latest ? assessVersionReadiness(data.value, latest) : null
  }

  /**
   * 发布最新版本。任一受影响威胁未取得三端一致通过、存在驳回意见，
   * 或控制证据已失效时，停止发布。
   */
  const publishLatestVersion = (): { ok: boolean; message: string } => {
    const latest = data.value.versions[0]
    if (!latest) return { ok: false, message: '尚无可发布的版本' }
    if (latest.publishedAt) return { ok: false, message: `${latest.label} 已经发布` }
    if (data.value.versions.some((version) => version !== latest && !version.publishedAt)) {
      return { ok: false, message: '存在更早的未发布版本，请先处理历史版本' }
    }

    const readiness = assessVersionReadiness(data.value, latest)
    if (!readiness.ready) {
      return {
        ok: false,
        message: `仍有 ${readiness.blockers.length} 条受影响威胁未满足发布条件，发布已停止`,
      }
    }

    const publishedAt = new Date().toISOString()
    latest.publishedAt = publishedAt
    latest.publishedBy = '当前用户'
    appendAudit(
      'version',
      latest.id,
      '发布版本',
      `${latest.label} 三端会签一致通过、审核依据全部成立，已发布`,
    )
    persist()
    return { ok: true, message: `${latest.label} 已发布` }
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
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )

    // 提交时固化审核依据：威胁本体、控制证据与缓解任务
    const basis = captureBasis(data.value, threat)
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
      basis,
      basisStatus: 'confirmed',
    })

    threat.reviewStatus = recomputeThreatReviewStatus(data.value, threat)

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
      `${actor}（${role}）提交会签意见，已记录 ${basis.items.length + 1} 项审核依据`,
    )
    persist()
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    // 缓解任务状态变化后，关联威胁上依据该任务的通过意见失效
    const impacted = data.value.threats.filter((threat) => threat.id === task.threatId)
    invalidateDecisionsForThreats(data.value, impacted, { markAudit: true })
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
      ...data.value.decisions.map((decision) => {
        const basisNote =
          decision.basisStatus === 'invalidated'
            ? `｜依据失效：${decision.invalidReason ?? ''}`
            : decision.basisStatus === 'unverified'
              ? `｜依据待复核：${decision.invalidReason ?? ''}`
              : decision.basis
                ? `｜依据成立（${decision.basis.items.length} 项关联证据/任务）`
                : '｜无审核依据'
        return `- ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}（r${decision.revision}）${basisNote}：${decision.comment}`
      }),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    metrics,
    issues,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    assessLatestVersion,
    publishLatestVersion,
    activeDecisionsForThreat,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
  }
})
