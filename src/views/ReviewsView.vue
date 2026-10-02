<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import ProgressBar from 'primevue/progressbar'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { ActorRole, DecisionType, ReviewDecision, Threat } from '@/models/domain'
import { reviewProgress } from '@/services/selectors'
import {
  buildBasisForThreat,
  latestRoundDecisions,
  validateDecision,
} from '@/services/reviewBasis'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const selectedThreatId = ref('')
const decisionVisible = ref(false)

const roleOptions: { label: string; value: ActorRole; actor: string }[] = [
  { label: '开发负责人', value: 'development', actor: '赵恺' },
  { label: '安全负责人', value: 'security', actor: '王岚' },
  { label: '业务负责人', value: 'business', actor: '宋雨' },
]
const decisionOptions = [
  { label: '通过', value: 'approved' },
  { label: '接受条件', value: 'accept' },
  { label: '同意降级', value: 'degrade' },
  { label: '要求补证', value: 'evidence_required' },
  { label: '驳回', value: 'rejected' },
]

const form = reactive<{
  role: ActorRole
  decision: DecisionType
  actor: string
  comment: string
}>({
  role: 'security',
  decision: 'approved',
  actor: '王岚',
  comment: '',
})

const latestVersion = computed(() => store.data.versions[0])
const affectedThreats = computed(() => {
  const ids = latestVersion.value?.affectedThreatIds ?? store.data.threats.map((threat) => threat.id)
  return store.data.threats.filter((threat) => ids.includes(threat.id))
})
const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedThreatId.value) ?? null,
)
const currentDecisions = computed(() =>
  selectedThreat.value
    ? latestRoundDecisions(
        store.data,
        selectedThreat.value.id,
        selectedThreat.value.revision,
      )
    : [],
)
// 提交前预览：当前内容构成的审核依据，提交后将按此快照固定
const pendingBasis = computed(() =>
  selectedThreat.value ? buildBasisForThreat(store.data, selectedThreat.value) : [],
)

// 历史轮次会签记录（已失效、被驳回或更早轮次），保留审计可追溯
const historicalDecisions = computed(() => {
  if (!selectedThreat.value) return []
  const currentIds = new Set(currentDecisions.value.map((decision) => decision.id))
  return store.data.decisions.filter(
    (decision) =>
      decision.threatId === selectedThreat.value!.id && !currentIds.has(decision.id),
  )
})

// 升级后无法确认审核依据、等待人工复核的历史意见
const needsReviewDecisions = computed(() =>
  store.data.decisions.filter((decision) => decision.state === 'needs_review'),
)

const basisKindLabel: Record<string, string> = {
  threat: '威胁',
  control: '控制',
  evidence: '控制证据',
  mitigation: '缓解任务',
}

const decisionForRole = (threat: Threat, role: ActorRole): ReviewDecision | undefined =>
  latestRoundDecisions(store.data, threat.id, threat.revision).find(
    (decision) => decision.role === role,
  )

const statusForRole = (
  threat: Threat,
  role: ActorRole,
): DecisionType | 'pending' | 'invalidated' | 'needs_review' => {
  const decision = decisionForRole(threat, role)
  if (!decision) return 'pending'
  if (decision.state === 'invalidated') return 'invalidated'
  if (decision.state === 'needs_review') return 'needs_review'
  return decision.decision
}

const roleProgress = (threat: Threat): number =>
  reviewProgress(
    latestRoundDecisions(store.data, threat.id, threat.revision).filter(
      (decision) => decision.state === 'active',
    ),
  )

const openDecision = (): void => {
  if (!selectedThreat.value) return
  form.comment = ''
  form.role = 'security'
  form.actor = '王岚'
  form.decision = 'approved'
  decisionVisible.value = true
}

const changeRole = (): void => {
  form.actor = roleOptions.find((item) => item.value === form.role)?.actor ?? form.actor
}

const submitDecision = (): void => {
  if (!selectedThreat.value) return
  if (!form.comment.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '会签意见不能为空', life: 3000 })
    return
  }
  store.submitDecision(
    selectedThreat.value.id,
    form.role,
    form.decision,
    form.actor,
    form.comment.trim(),
  )
  decisionVisible.value = false
  toast.add({
    severity: 'success',
    summary: '会签意见已提交',
    detail: '审核依据已随意见固定，关联内容变化将联动失效',
    life: 2500,
  })
}

const decisionLabel = (
  decision: DecisionType | 'pending' | 'invalidated' | 'needs_review',
): string => {
  if (decision === 'pending') return '待提交'
  if (decision === 'invalidated') return '依据失效'
  if (decision === 'needs_review') return '待复核'
  return decisionOptions.find((item) => item.value === decision)?.label ?? decision
}

const liveProblem = (decision: ReviewDecision): string | null => {
  if (decision.state !== 'active' || decision.decision !== 'approved') return null
  return validateDecision(store.data, decision)
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="受影响范围"
      title="逐项会签中心"
      :description="`当前版本 ${latestVersion?.label ?? '未建立'} 仅展示受变更影响、需要重新审核的威胁。`"
    />

    <section class="version-context">
      <div>
        <span>审核基线</span>
        <strong>{{ latestVersion?.label ?? '尚未建立版本' }}</strong>
      </div>
      <div>
        <span>受影响威胁</span>
        <strong>{{ affectedThreats.length }} 条</strong>
      </div>
      <div>
        <span>创建时间</span>
        <strong>
          {{ latestVersion ? new Date(latestVersion.createdAt).toLocaleString('zh-CN') : '-' }}
        </strong>
      </div>
    </section>

    <section v-if="needsReviewDecisions.length" class="review-banner">
      <i class="pi pi-clock"></i>
      <div>
        <strong>{{ needsReviewDecisions.length }} 条历史会签记录待复核</strong>
        <span>
          升级时按修订号无法确认这些意见的审核依据（{{ needsReviewDecisions.map((d) => d.actor).join('、') }}），已暂停将其计入通过结论，请相关角色重新会签。
        </span>
      </div>
    </section>

    <div class="review-board">
      <section class="review-list">
        <article
          v-for="threat in affectedThreats"
          :key="threat.id"
          class="review-card"
          :class="{ selected: selectedThreatId === threat.id }"
          @click="selectedThreatId = threat.id"
        >
          <div class="review-card-head">
            <div>
              <span class="mono">{{ threat.code }}</span>
              <h2>{{ threat.title }}</h2>
            </div>
            <StatusTag :value="threat.reviewStatus" kind="review" />
          </div>
          <div class="role-grid">
            <div v-for="role in roleOptions" :key="role.value" class="role-state">
              <span>{{ role.label }}</span>
              <strong
                :class="{
                  pending: ['pending', 'needs_review'].includes(statusForRole(threat, role.value)),
                  broken: statusForRole(threat, role.value) === 'invalidated',
                }"
              >
                {{ decisionLabel(statusForRole(threat, role.value)) }}
              </strong>
            </div>
          </div>
          <ProgressBar
            :value="roleProgress(threat)"
            :show-value="false"
            class="review-progress"
          />
        </article>
      </section>

      <aside class="decision-panel">
        <template v-if="selectedThreat">
          <div class="decision-head">
            <div>
              <span class="mono">{{ selectedThreat.code }}</span>
              <h2>{{ selectedThreat.title }}</h2>
            </div>
            <StatusTag :value="selectedThreat.reviewStatus" kind="review" />
          </div>
          <p class="decision-description">{{ selectedThreat.description }}</p>

          <section class="basis-section">
            <h3>审核依据（提交时固定快照）</h3>
            <ul class="basis-list">
              <li v-for="entry in pendingBasis" :key="`${entry.kind}-${entry.refId}`" class="basis-item">
                <span class="basis-kind">{{ basisKindLabel[entry.kind] }}</span>
                <strong>{{ entry.label }}</strong>
              </li>
            </ul>
            <p class="basis-note">
              提交后，上述威胁、控制、控制证据或缓解任务任一项发生变化，本威胁对应的“通过”意见将自动失效并记录原因；其他角色与其他威胁的意见保留。
            </p>
          </section>

          <Button label="提交会签意见" icon="pi pi-pencil" @click="openDecision" />

          <section class="decision-history">
            <h3>当前版本会签记录</h3>
            <article
              v-for="decision in currentDecisions"
              :key="decision.id"
              class="decision-entry"
              :class="{ 'decision-invalid': decision.state !== 'active' }"
            >
              <div>
                <strong>{{ decision.actor }}</strong>
                <span>{{ roleOptions.find((role) => role.value === decision.role)?.label }}</span>
              </div>
              <StatusTag
                :value="decision.state === 'active' ? decision.decision : decision.state"
                kind="review"
              />
              <p>{{ decision.comment }}</p>
              <p v-if="decision.state === 'invalidated'" class="invalid-reason">
                <i class="pi pi-exclamation-triangle"></i>
                {{ decision.invalidReason ?? '审核依据已变化' }}
              </p>
              <p v-else-if="decision.state === 'needs_review'" class="invalid-reason">
                <i class="pi pi-clock"></i>
                {{ decision.invalidReason ?? '历史记录缺少审核依据，等待复核' }}
              </p>
              <p v-else-if="liveProblem(decision)" class="invalid-reason">
                <i class="pi pi-exclamation-triangle"></i>
                {{ liveProblem(decision) }}
              </p>
              <div v-if="decision.basis?.length" class="decision-basis">
                <span v-for="entry in decision.basis" :key="`${entry.kind}-${entry.refId}`" class="basis-chip">
                  {{ basisKindLabel[entry.kind] }} · {{ entry.label }}
                </span>
              </div>
              <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
            </article>
            <div v-if="currentDecisions.length === 0" class="empty-state">尚未提交会签意见。</div>
          </section>

          <section v-if="historicalDecisions.length" class="decision-history history-rounds">
            <h3>历史轮次记录（{{ historicalDecisions.length }}）</h3>
            <article
              v-for="decision in historicalDecisions"
              :key="decision.id"
              class="decision-entry decision-invalid"
            >
              <div>
                <strong>{{ decision.actor }}</strong>
                <span>
                  {{ roleOptions.find((role) => role.value === decision.role)?.label }}
                  · v1.{{ decision.revision }} 第 {{ (decision.signRound ?? 0) + 1 }} 轮
                </span>
              </div>
              <StatusTag
                :value="decision.state === 'active' ? decision.decision : decision.state"
                kind="review"
              />
              <p>{{ decision.comment }}</p>
              <p v-if="decision.invalidReason" class="invalid-reason">
                <i class="pi pi-exclamation-triangle"></i>
                {{ decision.invalidReason }}
              </p>
              <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
            </article>
          </section>
        </template>
        <div v-else class="empty-state">从左侧选择一条受影响威胁。</div>
      </aside>
    </div>

    <Dialog v-model:visible="decisionVisible" header="提交会签意见" modal :style="{ width: '620px' }">
      <div class="editor-form">
        <div class="field">
          <label>会签角色</label>
          <Select
            v-model="form.role"
            :options="roleOptions"
            option-label="label"
            option-value="value"
            @change="changeRole"
          />
        </div>
        <div class="field">
          <label>会签人</label>
          <InputText v-model="form.actor" />
        </div>
        <div class="field field-wide">
          <label>意见类型</label>
          <Select
            v-model="form.decision"
            :options="decisionOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>意见与条件</label>
          <Textarea
            v-model="form.comment"
            rows="5"
            placeholder="通过、降级、接受或补证都需要写明具体条件"
          />
        </div>
        <div v-if="selectedThreat" class="field field-wide basis-preview">
          <label>本次将固定的审核依据（{{ pendingBasis.length }} 项）</label>
          <ul>
            <li v-for="entry in pendingBasis" :key="`${entry.kind}-${entry.refId}`">
              {{ basisKindLabel[entry.kind] }} · {{ entry.label }}
            </li>
          </ul>
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="decisionVisible = false" />
        <Button label="提交意见" icon="pi pi-check" @click="submitDecision" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.version-context {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.version-context > div {
  display: grid;
  gap: 7px;
  padding: 14px 16px;
  background: #fff;
}

.version-context span {
  color: #717c8f;
  font-size: 11px;
}

.review-banner {
  display: flex;
  align-items: flex-start;
  gap: 13px;
  margin-top: 14px;
  padding: 13px 16px;
  border: 1px solid #ecd3a4;
  border-left: 4px solid #d97706;
  border-radius: 6px;
  background: #fdf7ea;
}

.review-banner > i {
  margin-top: 2px;
  color: #b45309;
}

.review-banner > div {
  display: grid;
  gap: 4px;
}

.review-banner span {
  color: #7b5d2c;
  font-size: 12px;
  line-height: 1.6;
}

.review-board {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(390px, 0.75fr);
  gap: 16px;
  margin-top: 16px;
  align-items: start;
}

.review-list {
  display: grid;
  gap: 12px;
}

.review-card {
  padding: 16px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
  cursor: pointer;
}

.review-card:hover,
.review-card.selected {
  border-color: #7898bb;
  box-shadow: 0 0 0 1px rgba(70, 108, 150, 0.1);
}

.review-card-head,
.decision-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
}

.review-card h2,
.decision-head h2 {
  margin: 6px 0 0;
  font-size: 16px;
}

.role-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-top: 16px;
}

.role-state {
  display: grid;
  gap: 4px;
  padding: 9px 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
  background: #f9fafb;
}

.role-state span {
  color: #737e91;
  font-size: 10px;
}

.role-state strong {
  color: #2e684f;
  font-size: 11px;
}

.role-state strong.pending {
  color: #a05a00;
}

.role-state strong.broken {
  color: #b3382c;
}

.review-progress {
  height: 4px;
  margin-top: 14px;
}

.decision-panel {
  position: sticky;
  top: 82px;
  padding: 18px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
}

.decision-description {
  margin: 14px 0 18px;
  color: #59657a;
  font-size: 13px;
  line-height: 1.65;
}

.basis-section {
  margin-bottom: 16px;
  padding: 12px 14px;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  background: #f7f9fc;
}

.basis-section h3 {
  margin: 0 0 9px;
  font-size: 12px;
}

.basis-list {
  display: grid;
  gap: 6px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.basis-item {
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 12px;
}

.basis-item strong {
  color: #34415a;
  font-weight: 600;
}

.basis-kind {
  flex: none;
  padding: 1px 7px;
  border-radius: 3px;
  color: #2b5a86;
  background: #e4edf6;
  font-size: 10px;
}

.basis-note {
  margin: 10px 0 0;
  color: #7b879a;
  font-size: 11px;
  line-height: 1.6;
}

.decision-history {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid #e5e9ef;
}

.decision-history h3 {
  margin: 0 0 12px;
  font-size: 13px;
}

.decision-entry {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  padding: 11px 0;
  border-bottom: 1px solid #eef0f3;
}

.decision-entry.decision-invalid {
  opacity: 0.92;
}

.decision-entry > div {
  display: grid;
  gap: 3px;
}

.decision-entry span,
.decision-entry time {
  color: #7a8496;
  font-size: 10px;
}

.decision-entry p {
  grid-column: 1 / -1;
  margin: 0;
  color: #566176;
  font-size: 12px;
  line-height: 1.5;
}

.invalid-reason {
  display: flex;
  gap: 6px;
  padding: 7px 9px;
  border-radius: 4px;
  color: #9a3428 !important;
  background: #fdf0ee;
}

.decision-basis {
  grid-column: 1 / -1;
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}

.basis-chip {
  padding: 1px 7px;
  border: 1px solid #e0e6ee;
  border-radius: 10px;
  color: #5f6c82;
  background: #f8fafc;
  font-size: 10px;
}

.basis-preview {
  padding: 10px 12px;
  border: 1px dashed #ccd6e2;
  border-radius: 6px;
  background: #f8fafc;
}

.basis-preview ul {
  display: grid;
  gap: 4px;
  margin: 6px 0 0;
  padding-left: 18px;
  color: #5b687d;
  font-size: 12px;
}
</style>
