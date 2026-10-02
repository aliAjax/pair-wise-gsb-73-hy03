/* eslint-disable no-console */
// 逻辑冒烟测试：通过 esbuild 打包后用 node 执行，不依赖前端测试框架
import assert from 'node:assert/strict'
import { createSeedState } from '../src/models/seed'
import {
  assessVersionReadiness,
  captureBasis,
  invalidateDecisionsForThreats,
  migrateState,
  recomputeThreatReviewStatus,
  SCHEMA_VERSION,
} from '../src/services/reviewBasis'
import type { ThreatModelState } from '../src/models/domain'

const clone = <T>(value: T): T => structuredClone(value)
const freshState = (): ThreatModelState => {
  const state = createSeedState()
  migrateState(state)
  return state
}

// 1. 全新种子数据：历史意见按修订号回填，依据不成立的转为待复核
const fresh = createSeedState()
assert.equal(fresh.schemaVersion, SCHEMA_VERSION)
// 模拟 localStorage 中的旧结构数据（无 basis 字段）
const legacy: ThreatModelState = clone(createSeedState())
legacy.decisions.forEach((decision) => {
  delete decision.basis
  delete decision.basisStatus
  delete decision.invalidReason
})
delete legacy.schemaVersion
// thr-02 种子里 revision=2 但仅有开发一条 approved；回填后重算应回到审核中
const changed = migrateState(legacy)
assert.equal(changed, true)
assert.equal(legacy.schemaVersion, SCHEMA_VERSION)
const thr02 = legacy.threats.find((t) => t.id === 'thr-02')!
assert.equal(thr02.reviewStatus, 'in_review', 'thr-02 只有一端通过，重算后回到审核中')
const devDecision = legacy.decisions.find((d) => d.id === 'dec-02')!
// ev-02 在历史记录时就已是无效证据：依据快照与现状一致仍可确认，发布由证据闸门拦截
assert.equal(devDecision.basisStatus, 'confirmed')
assert.equal(devDecision.basis?.reconstructed, true)
const thr02Gate = assessVersionReadiness(legacy, legacy.versions[0])
assert.ok(
  thr02Gate.blockers
    .find((b) => b.threatId === 'thr-02')
    ?.reasons.some((r) => r.includes('缺少有效控制证据')),
  '无效证据必须在发布闸门拦截 thr-02',
)
// 能确认依据的历史意见保留为 confirmed（reconstructed）
const secDecision = legacy.decisions.find((d) => d.id === 'dec-01')!
assert.equal(secDecision.basisStatus, 'confirmed')
assert.equal(secDecision.basis?.reconstructed, true)

// 2. 修订号对不上的历史记录等待复核
const mismatch = clone(createSeedState())
mismatch.decisions.forEach((d) => {
  delete d.basis
  delete d.basisStatus
})
const oldDecision = mismatch.decisions[0]
oldDecision.revision = 99
migrateState(mismatch)
assert.equal(
  mismatch.decisions.find((d) => d.id === oldDecision.id)?.basisStatus,
  'unverified',
)
assert.match(
  mismatch.decisions.find((d) => d.id === oldDecision.id)?.invalidReason ?? '',
  /修订号无法/,
)

// 3. 提交意见后固化依据；证据变化使受影响通过意见失效，其他角色/威胁保留
const state = freshState()
// 准备一条三端一致通过的 thr-03（其关联 ctl-03 证据 ev-03 有效、ctl-04 证据 ev-04 有效）
const thr03 = state.threats.find((t) => t.id === 'thr-03')!
thr03.reviewStatus = 'in_review'
const submitAll = (decision: 'approved' | 'rejected' = 'approved') => {
  for (const role of ['development', 'security', 'business'] as const) {
    const basis = captureBasis(state, thr03)
    state.decisions.push({
      id: `dec-${role}`,
      threatId: 'thr-03',
      actor: role,
      role,
      decision,
      comment: 'ok',
      createdAt: new Date().toISOString(),
      revision: thr03.revision,
      basis,
      basisStatus: 'confirmed',
    })
  }
}
submitAll()
assert.equal(recomputeThreatReviewStatus(state, thr03), 'approved')
assert.equal(assessVersionReadiness(state, state.versions[0]).ready, false, 'thr-01 尚未通过，整版不能发布')

// 让版本只包含 thr-03，应满足发布条件
const only03 = clone(state)
only03.versions[0].affectedThreatIds = ['thr-03']
assert.equal(assessVersionReadiness(only03, only03.versions[0]).ready, true)

// 证据 ev-03 失效 → thr-03 的三条通过意见全部失效，状态回到审核中；发布被阻止
state.evidence.find((e) => e.id === 'ev-03')!.valid = false
const reset = invalidateDecisionsForThreats(state, state.threats.filter((t) => t.id === 'thr-03'))
assert.deepEqual(reset.sort(), ['thr-03'])
for (const role of ['development', 'security', 'business'] as const) {
  const d = state.decisions.find((item) => item.id === `dec-${role}`)!
  assert.equal(d.basisStatus, 'invalidated', `${role} 意见应失效`)
  assert.match(d.invalidReason ?? '', /控制证据已失效/)
}
assert.equal(recomputeThreatReviewStatus(state, thr03), 'in_review')
const blocked = assessVersionReadiness(
  { ...only03, evidence: state.evidence, threats: state.threats, decisions: state.decisions },
  only03.versions[0],
)
assert.equal(blocked.ready, false)
assert.ok(blocked.blockers[0].reasons.some((r) => r.includes('缺少有效控制证据')))

// 4. 其他威胁与其他角色的意见保留
const unrelated = state.decisions.find((d) => d.id === 'dec-01')!
assert.equal(unrelated.basisStatus, 'confirmed')

// 5. 缓解任务变化只影响关联威胁
const state2 = freshState()
const thr01 = state2.threats.find((t) => t.id === 'thr-01')!
const basis01 = captureBasis(state2, thr01)
state2.decisions.push({
  id: 'dec-x',
  threatId: 'thr-01',
  actor: 'x',
  role: 'security',
  decision: 'approved',
  comment: 'ok',
  createdAt: new Date().toISOString(),
  revision: thr01.revision,
  basis: basis01,
  basisStatus: 'confirmed',
})
const task = state2.mitigations.find((m) => m.id === 'mit-01')!
task.status = 'done'
invalidateDecisionsForThreats(state2, state2.threats.filter((t) => t.id === 'thr-01'))
assert.equal(state2.decisions.find((d) => d.id === 'dec-x')?.basisStatus, 'invalidated')
assert.match(state2.decisions.find((d) => d.id === 'dec-x')?.invalidReason ?? '', /缓解任务已更新/)

// 6. 任一角色驳回即停止发布
const rejectedState = clone(only03)
rejectedState.threats.find((t) => t.id === 'thr-03')!.reviewStatus = 'in_review'
rejectedState.decisions = rejectedState.decisions.filter(
  (d) => !['dec-development', 'dec-security', 'dec-business'].includes(d.id),
)
for (const [index, role] of ['development', 'security', 'business'].entries()) {
  rejectedState.decisions.push({
    id: `dec-r-${role}`,
    threatId: 'thr-03',
    actor: role,
    role: role as 'development' | 'security' | 'business',
    decision: index === 1 ? 'rejected' : 'approved',
    comment: 'x',
    createdAt: new Date().toISOString(),
    revision: rejectedState.threats.find((t) => t.id === 'thr-03')!.revision,
    basis: captureBasis(rejectedState, rejectedState.threats.find((t) => t.id === 'thr-03')!),
    basisStatus: 'confirmed',
  })
}
assert.equal(assessVersionReadiness(rejectedState, rejectedState.versions[0]).ready, false)
assert.ok(
  assessVersionReadiness(rejectedState, rejectedState.versions[0]).blockers[0].reasons.some((r) =>
    r.includes('驳回'),
  ),
)

console.log('所有冒烟测试通过 ✔')
