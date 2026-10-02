<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Column from 'primevue/column'
import DataTable from 'primevue/datatable'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import MultiSelect from 'primevue/multiselect'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type {
  ActorRole,
  ReleaseBlocker,
  VersionChange,
  VersionSnapshot,
} from '@/models/domain'
import { compareSnapshots } from '@/services/selectors'
import { latestRoundDecisions } from '@/services/reviewBasis'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const fromVersionId = ref(store.data.versions[1]?.id ?? store.data.versions[0]?.id ?? '')
const toVersionId = ref(store.data.versions[0]?.id ?? '')
const createVisible = ref(false)
const createForm = reactive({
  label: '',
  notes: '',
  affectedThreatIds: [] as string[],
})

const roleLabels: { value: ActorRole; label: string }[] = [
  { value: 'development', label: '开发' },
  { value: 'security', label: '安全' },
  { value: 'business', label: '业务' },
]

const fromVersion = computed(
  () => store.data.versions.find((version) => version.id === fromVersionId.value) ?? null,
)
const toVersion = computed(
  () => store.data.versions.find((version) => version.id === toVersionId.value) ?? null,
)
const difference = computed(() =>
  fromVersion.value && toVersion.value
    ? compareSnapshots(fromVersion.value, toVersion.value)
    : { added: [], removed: [], changed: [] },
)

const releaseTarget = computed(() => store.data.versions[0] ?? null)
const releaseCheck = computed(() =>
  releaseTarget.value ? store.checkRelease(releaseTarget.value.id) : null,
)

const threatById = (id: string) => store.data.threats.find((threat) => threat.id === id)

const roleState = (
  version: VersionSnapshot,
  threatId: string,
  role: ActorRole,
): 'missing' | 'approved' | 'other' | 'rejected' | 'invalidated' | 'needs_review' => {
  const decision = latestRoundDecisions(store.data, threatId, version.revision).find(
    (item) => item.role === role,
  )
  if (!decision) return 'missing'
  if (decision.state === 'invalidated') return 'invalidated'
  if (decision.state === 'needs_review') return 'needs_review'
  if (decision.decision === 'approved') return 'approved'
  if (decision.decision === 'rejected') return 'rejected'
  return 'other'
}

const roleStateLabel: Record<string, string> = {
  missing: '缺',
  approved: '通过',
  other: '非通过',
  rejected: '驳回',
  invalidated: '失效',
  needs_review: '待复核',
}

const blockersByThreat = computed(() => {
  const map = new Map<string, ReleaseBlocker[]>()
  releaseCheck.value?.blockers.forEach((blocker) => {
    const list = map.get(blocker.threatId) ?? []
    list.push(blocker)
    map.set(blocker.threatId, list)
  })
  return map
})

const publish = (): void => {
  if (!releaseTarget.value) return
  const blockers = store.publishVersion(releaseTarget.value.id)
  if (blockers.length > 0) {
    toast.add({
      severity: 'error',
      summary: '发布已停止',
      detail: `仍有 ${blockers.length} 项发布条件未满足`,
      life: 3500,
    })
    return
  }
  toast.add({
    severity: 'success',
    summary: '版本已发布',
    detail: `${releaseTarget.value.label} 三端一致通过且审核依据均有效`,
    life: 3000,
  })
}

const entityName = (change: VersionChange): string => {
  if (change.category === '组件') {
    const item = store.data.components.find((entry) => entry.id === change.id)
    return item ? `${item.name} (${item.id})` : change.id
  }
  if (change.category === '数据流') {
    const item = store.data.flows.find((entry) => entry.id === change.id)
    return item ? `${item.name} (${item.id})` : change.id
  }
  if (change.category === '威胁') {
    const item = store.data.threats.find((entry) => entry.id === change.id)
    return item ? `${item.code} ${item.title} (${item.id})` : change.id
  }
  if (change.category === '控制') {
    const item = store.data.controls.find((entry) => entry.id === change.id)
    return item ? `${item.name} (${item.id})` : change.id
  }
  if (change.category === '风险') {
    const item = store.data.risks.find((entry) => entry.id === change.id)
    return item ? `${item.code} ${item.title} (${item.id})` : change.id
  }
  return change.id
}

const openCreate = (): void => {
  createForm.label = `v1.${store.data.currentRevision + 1} 变更评审`
  createForm.notes = ''
  createForm.affectedThreatIds = []
  createVisible.value = true
}

const createVersion = (): void => {
  if (!createForm.label.trim() || !createForm.notes.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '版本名称和变更说明不能为空', life: 3000 })
    return
  }
  if (createForm.affectedThreatIds.length === 0) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '至少选择一条受影响威胁', life: 3000 })
    return
  }
  const snapshot = store.createVersion(
    createForm.label,
    createForm.notes,
    createForm.affectedThreatIds,
  )
  fromVersionId.value = toVersionId.value
  toVersionId.value = snapshot.id
  createVisible.value = false
  toast.add({ severity: 'success', summary: '版本已创建', detail: '仅受影响威胁进入重新审核', life: 3000 })
}

const approvalLabel = (snapshot: VersionSnapshot): string =>
  `${snapshot.affectedThreatIds.filter((id) => {
    const threat = store.data.threats.find((item) => item.id === id)
    return threat?.reviewStatus === 'approved'
  }).length}/${snapshot.affectedThreatIds.length}`
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="审计与基线"
      title="版本差异"
      description="比较模型基线，识别组件、数据流、控制与风险变化，并限定重新审核的威胁范围。"
    />

    <section class="panel">
      <div class="panel-header">
        <h2 class="panel-title">版本比较</h2>
        <Button label="创建新版本" icon="pi pi-plus" @click="openCreate" />
      </div>
      <div class="compare-toolbar">
        <div class="version-select">
          <span>基准版本</span>
          <select v-model="fromVersionId">
            <option v-for="version in store.data.versions" :key="version.id" :value="version.id">
              {{ version.label }}
            </option>
          </select>
        </div>
        <i class="pi pi-arrow-right"></i>
        <div class="version-select">
          <span>目标版本</span>
          <select v-model="toVersionId">
            <option v-for="version in store.data.versions" :key="version.id" :value="version.id">
              {{ version.label }}
            </option>
          </select>
        </div>
      </div>
      <div class="diff-columns diff-padding">
        <div class="diff-block added-block">
          <h4>新增项</h4>
          <ul v-if="difference.added.length">
            <li v-for="change in difference.added" :key="`${change.category}-${change.id}`">
              <span>{{ change.category }}</span> {{ entityName(change) }}
            </li>
          </ul>
          <span v-else class="muted">无新增项</span>
        </div>
        <div class="diff-block removed-block">
          <h4>移除项</h4>
          <ul v-if="difference.removed.length">
            <li v-for="change in difference.removed" :key="`${change.category}-${change.id}`">
              <span>{{ change.category }}</span> {{ entityName(change) }}
            </li>
          </ul>
          <span v-else class="muted">无移除项</span>
        </div>
      </div>
      <div class="changed-list">
        <h4>重新审核差异</h4>
        <div v-for="item in difference.changed" :key="item" class="changed-item">
          <i class="pi pi-arrow-right"></i>
          <span>{{ item }}</span>
        </div>
      </div>
    </section>

    <section v-if="releaseTarget" class="panel release-panel">
      <div class="panel-header">
        <h2 class="panel-title">版本发布门禁 · {{ releaseTarget.label }}</h2>
        <StatusTag
          :value="releaseTarget.released ? 'approved' : releaseCheck?.canRelease ? 'in_review' : 'rejected'"
          kind="review"
        />
      </div>

      <div class="release-body">
        <div class="release-rules">
          <p class="release-hint">
            发布条件：版本受影响威胁的开发、安全、业务三端均在本修订号提交“通过”意见，且会签时记录的威胁、控制、控制证据、缓解任务审核依据全部仍然成立。
          </p>
          <div v-for="threatId in releaseTarget.affectedThreatIds" :key="threatId" class="release-threat">
            <div class="release-threat-head">
              <strong>{{ threatById(threatId)?.code ?? threatId }} {{ threatById(threatId)?.title ?? '' }}</strong>
              <span class="role-badges">
                <span
                  v-for="role in roleLabels"
                  :key="role.value"
                  class="role-badge"
                  :class="roleState(releaseTarget, threatId, role.value)"
                >
                  {{ role.label }}{{ roleStateLabel[roleState(releaseTarget, threatId, role.value)] }}
                </span>
              </span>
            </div>
            <ul v-if="blockersByThreat.get(threatId)?.length" class="blocker-list">
              <li v-for="blocker in blockersByThreat.get(threatId)" :key="blocker.reason">
                <i class="pi pi-ban"></i>{{ blocker.reason }}
              </li>
            </ul>
            <p v-else class="release-ok"><i class="pi pi-check-circle"></i>三端一致通过，审核依据均有效</p>
          </div>
        </div>

        <aside class="release-action">
          <template v-if="releaseTarget.released">
            <i class="pi pi-verified released-icon"></i>
            <strong>版本已发布</strong>
            <span class="muted">{{ releaseTarget.releasedBy ?? '系统' }}</span>
            <span class="muted">
              {{ releaseTarget.releasedAt ? new Date(releaseTarget.releasedAt).toLocaleString('zh-CN') : '-' }}
            </span>
          </template>
          <template v-else>
            <strong>{{ releaseCheck?.canRelease ? '满足发布条件' : '发布被阻止' }}</strong>
            <span class="muted">
              {{ releaseCheck?.blockers.length ?? 0 }} 项待处理条件
            </span>
            <Button
              label="发布当前版本"
              icon="pi pi-send"
              :disabled="!releaseCheck?.canRelease"
              @click="publish"
            />
            <small v-if="!releaseCheck?.canRelease" class="blocked-note">
              存在驳回意见或审核依据失效时，发布将被停止；补齐三端通过意见后方可发布。
            </small>
          </template>
        </aside>
      </div>
    </section>

    <div class="versions-grid">
      <section class="panel">
        <div class="panel-header">
          <h2 class="panel-title">版本历史</h2>
        </div>
        <DataTable :value="store.data.versions" dataKey="id" size="small" stripedRows>
          <Column header="版本" style="width: 180px">
            <template #body="{ data }">
              <strong>{{ data.label }}</strong>
              <div class="mono">r{{ data.revision }}</div>
            </template>
          </Column>
          <Column header="创建时间" style="width: 155px">
            <template #body="{ data }">
              {{ new Date(data.createdAt).toLocaleDateString('zh-CN') }}
            </template>
          </Column>
          <Column field="author" header="创建人" style="width: 90px" />
          <Column header="受影响" style="width: 80px">
            <template #body="{ data }">{{ data.affectedThreatIds.length }} 条</template>
          </Column>
          <Column header="通过" style="width: 80px">
            <template #body="{ data }">{{ approvalLabel(data) }}</template>
          </Column>
          <Column header="发布状态" style="width: 150px">
            <template #body="{ data }">
              <template v-if="data.released">
                <StatusTag value="approved" kind="review" />
                <div class="mono">{{ data.releasedAt ? new Date(data.releasedAt).toLocaleDateString('zh-CN') : '' }}</div>
              </template>
              <StatusTag v-else value="in_review" kind="review" />
            </template>
          </Column>
          <Column field="notes" header="说明" />
        </DataTable>
      </section>

      <section class="panel audit-panel">
        <div class="panel-header">
          <h2 class="panel-title">审计轨迹</h2>
          <span class="muted">{{ store.data.audit.length }} 条</span>
        </div>
        <div class="audit-list">
          <article v-for="event in store.data.audit.slice(0, 12)" :key="event.id" class="audit-item">
            <i class="pi pi-circle-fill"></i>
            <div>
              <strong>{{ event.action }}</strong>
              <p>{{ event.detail }}</p>
              <span>{{ event.actor }} · {{ new Date(event.createdAt).toLocaleString('zh-CN') }}</span>
            </div>
          </article>
        </div>
      </section>
    </div>

    <Dialog v-model:visible="createVisible" header="创建变更版本" modal :style="{ width: '720px' }">
      <div class="editor-form">
        <div class="field field-wide">
          <label>版本名称</label>
          <InputText v-model="createForm.label" />
        </div>
        <div class="field field-wide">
          <label>变更说明</label>
          <Textarea
            v-model="createForm.notes"
            rows="4"
            placeholder="说明架构、控制或风险发生的变更"
          />
        </div>
        <div class="field field-wide">
          <label>受影响威胁</label>
          <MultiSelect
            v-model="createForm.affectedThreatIds"
            :options="store.data.threats"
            option-label="title"
            option-value="id"
            display="chip"
            filter
            placeholder="只选择需要重新会签的威胁"
          />
          <small class="muted">未选择的威胁保持已通过状态，不会进入新版本会签队列。</small>
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="createVisible = false" />
        <Button label="创建版本" icon="pi pi-check" @click="createVersion" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.compare-toolbar {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 40px minmax(0, 1fr);
  align-items: end;
  gap: 10px;
  padding: 16px;
}

.compare-toolbar > i {
  display: grid;
  place-items: center;
  height: 38px;
  color: #6c7689;
}

.version-select {
  display: grid;
  gap: 6px;
}

.version-select span {
  color: #697489;
  font-size: 12px;
  font-weight: 600;
}

.version-select select {
  width: 100%;
  min-height: 39px;
  padding: 0 10px;
  border: 1px solid #ccd3dc;
  border-radius: 5px;
  color: #273247;
  background: #fff;
}

.diff-padding {
  padding: 0 16px 16px;
}

.added-block {
  border-left: 3px solid #2f8f69;
}

.removed-block {
  border-left: 3px solid #c64b39;
}

.diff-block li span {
  display: inline-block;
  min-width: 55px;
  margin-right: 7px;
  color: #748094;
  font-size: 11px;
}

.changed-list {
  padding: 0 16px 18px;
}

.changed-list h4 {
  margin: 0 0 10px;
  font-size: 14px;
}

.changed-item {
  display: flex;
  gap: 9px;
  padding: 6px 0;
  color: #515e73;
  font-size: 12px;
}

.changed-item i {
  color: #4c78a8;
  font-size: 10px;
}

.release-panel {
  margin-top: 16px;
}

.release-body {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 260px;
  gap: 1px;
  background: #e2e7ee;
  border-top: 1px solid #e2e7ee;
}

.release-rules {
  display: grid;
  gap: 12px;
  padding: 16px;
  background: #fff;
}

.release-hint {
  margin: 0;
  color: #68748a;
  font-size: 12px;
  line-height: 1.65;
}

.release-threat {
  display: grid;
  gap: 7px;
  padding: 11px 13px;
  border: 1px solid #e4e9f0;
  border-radius: 6px;
  background: #fafbfd;
}

.release-threat-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 13px;
}

.role-badges {
  display: flex;
  gap: 6px;
  flex: none;
}

.role-badge {
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 10px;
  border: 1px solid #d8dfe9;
  color: #7b8699;
  background: #fff;
}

.role-badge.approved {
  color: #236048;
  border-color: #a9d9c3;
  background: #ecf8f2;
}

.role-badge.rejected,
.role-badge.invalidated {
  color: #9a3428;
  border-color: #efc4bd;
  background: #fdf0ee;
}

.role-badge.needs_review,
.role-badge.other {
  color: #8a5a12;
  border-color: #ecd3a4;
  background: #fdf7ea;
}

.blocker-list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  gap: 4px;
}

.blocker-list li,
.release-ok {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0;
  font-size: 11px;
  line-height: 1.5;
}

.blocker-list li {
  color: #9a3428;
}

.release-ok {
  color: #2e684f;
}

.release-action {
  display: grid;
  gap: 8px;
  align-content: start;
  padding: 18px 16px;
  background: #fff;
}

.release-action .p-button {
  margin-top: 6px;
}

.released-icon {
  font-size: 26px;
  color: #2f8f69;
}

.blocked-note {
  color: #9a3428;
  font-size: 10px;
  line-height: 1.5;
}

.versions-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.55fr);
  gap: 16px;
  align-items: start;
  margin-top: 16px;
}

.audit-list {
  padding: 8px 16px 14px;
}

.audit-item {
  position: relative;
  display: grid;
  grid-template-columns: 12px 1fr;
  gap: 10px;
  padding: 11px 0;
}

.audit-item::after {
  position: absolute;
  top: 28px;
  bottom: -10px;
  left: 4px;
  width: 1px;
  background: #dce2e9;
  content: "";
}

.audit-item:last-child::after {
  display: none;
}

.audit-item > i {
  margin-top: 5px;
  color: #5b83ad;
  font-size: 7px;
}

.audit-item strong {
  font-size: 12px;
}

.audit-item p {
  margin: 4px 0;
  color: #5f6a7e;
  font-size: 11px;
  line-height: 1.45;
}

.audit-item span {
  color: #8992a1;
  font-size: 10px;
}
</style>
