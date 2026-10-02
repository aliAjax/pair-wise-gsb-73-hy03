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
import type { VersionChange, VersionSnapshot } from '@/models/domain'
import { compareSnapshots } from '@/services/selectors'
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

const latestReadiness = computed(() => store.assessLatestVersion())
const latestVersion = computed(() => store.data.versions[0] ?? null)
const hasUnpublishedBeforeLatest = computed(() =>
  store.data.versions.some((version, index) => index > 0 && !version.publishedAt),
)

const publishLatest = (): void => {
  const result = store.publishLatestVersion()
  toast.add({
    severity: result.ok ? 'success' : 'error',
    summary: result.ok ? '版本已发布' : '发布被阻止',
    detail: result.message,
    life: 3500,
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

const formatPublishedAt = (snapshot: VersionSnapshot): string =>
  snapshot.publishedAt ? new Date(snapshot.publishedAt).toLocaleString('zh-CN') : '未发布'
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="审计与基线"
      title="版本差异"
      description="比较模型基线，识别组件、数据流、控制与风险变化，并限定重新审核的威胁范围。"
    />

    <section v-if="latestVersion" class="panel release-gate" :class="{ open: latestReadiness?.ready }">
      <div class="panel-header">
        <h2 class="panel-title">发布闸门 · {{ latestVersion.label }}</h2>
        <StatusTag
          :value="latestVersion.publishedAt ? 'published' : latestReadiness?.ready ? 'approved' : 'in_review'"
          kind="review"
        />
      </div>
      <div class="gate-summary">
        <div>
          <span>受影响威胁</span>
          <strong>{{ latestReadiness?.total ?? 0 }} 条</strong>
        </div>
        <div>
          <span>三端一致通过且依据成立</span>
          <strong :class="{ 'danger-text': (latestReadiness?.passed ?? 0) !== (latestReadiness?.total ?? 0) }">
            {{ latestReadiness?.passed ?? 0 }}/{{ latestReadiness?.total ?? 0 }}
          </strong>
        </div>
        <div>
          <span>发布条件</span>
          <strong>{{ latestReadiness?.ready ? '全部满足' : '未满足' }}</strong>
        </div>
        <div class="gate-action">
          <Button
            label="发布当前版本"
            icon="pi pi-send"
            :disabled="Boolean(latestVersion.publishedAt) || !latestReadiness?.ready"
            @click="publishLatest"
          />
        </div>
      </div>

      <div v-if="hasUnpublishedBeforeLatest" class="gate-history-hint">
        <i class="pi pi-info-circle"></i>
        存在更早的未发布版本，请确认版本顺序后再发布。
      </div>

      <div v-if="latestReadiness && !latestReadiness.ready" class="gate-blockers">
        <h4>停止发布的原因（{{ latestReadiness.blockers.length }} 条威胁受阻）</h4>
        <article v-for="blocker in latestReadiness.blockers" :key="blocker.threatId" class="blocker-item">
          <div class="blocker-head">
            <strong>{{ blocker.code }} {{ blocker.title }}</strong>
          </div>
          <ul>
            <li v-for="reason in blocker.reasons" :key="reason">
              <i class="pi pi-ban"></i>{{ reason }}
            </li>
          </ul>
        </article>
      </div>
      <div v-else-if="!latestVersion.publishedAt" class="gate-clear">
        <i class="pi pi-check-circle"></i>
        全部受影响威胁已取得开发、安全、业务三端一致通过，审核依据均成立且证据有效，可以发布。
      </div>
      <div v-else class="gate-clear">
        <i class="pi pi-check-circle"></i>
        已于 {{ formatPublishedAt(latestVersion) }} 由 {{ latestVersion.publishedBy }} 发布。
      </div>
    </section>

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
          <Column header="发布状态" style="width: 165px">
            <template #body="{ data }">
              <StatusTag :value="data.publishedAt ? 'published' : 'in_review'" kind="review" />
              <div v-if="data.publishedAt" class="mono">{{ new Date(data.publishedAt).toLocaleDateString('zh-CN') }}</div>
              <span v-else class="muted">未发布</span>
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
.release-gate {
  border-left: 4px solid #d97706;
}

.release-gate.open {
  border-left-color: #2f8f69;
}

.gate-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr)) auto;
  gap: 1px;
  margin: 0 16px;
  overflow: hidden;
  border: 1px solid #e3e7ee;
  border-radius: 6px;
  background: #e3e7ee;
}

.gate-summary > div {
  display: grid;
  gap: 6px;
  padding: 13px 15px;
  background: #fff;
}

.gate-summary span {
  color: #717c8f;
  font-size: 11px;
}

.gate-summary strong {
  font-size: 18px;
}

.gate-action {
  display: flex;
  align-items: center;
}

.gate-history-hint {
  display: flex;
  gap: 8px;
  margin: 12px 16px 0;
  padding: 9px 12px;
  border-radius: 5px;
  background: #fffaf0;
  color: #7b5d2c;
  font-size: 12px;
}

.gate-blockers {
  padding: 14px 16px 4px;
}

.gate-blockers h4 {
  margin: 0 0 10px;
  color: #b03a2e;
  font-size: 13px;
}

.blocker-item {
  margin-bottom: 10px;
  padding: 10px 12px;
  border: 1px solid #f0c4b8;
  border-radius: 5px;
  background: #fdf6f4;
}

.blocker-item ul {
  margin: 7px 0 0;
  padding-left: 4px;
  list-style: none;
}

.blocker-item li {
  display: flex;
  gap: 7px;
  padding: 3px 0;
  color: #8a473f;
  font-size: 12px;
}

.blocker-item li i {
  margin-top: 3px;
  font-size: 9px;
}

.gate-clear {
  display: flex;
  gap: 9px;
  margin: 14px 16px 16px;
  padding: 11px 13px;
  border: 1px solid #bfe3d2;
  border-radius: 5px;
  background: #f1faf5;
  color: #27654c;
  font-size: 12px;
  line-height: 1.55;
}

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

.versions-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(320px, 0.55fr);
  gap: 16px;
  align-items: start;
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
