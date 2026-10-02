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
import { decisionsForThreat, reviewProgress } from '@/services/selectors'
import {
  activeDecisionsForThreat,
  basisStatusLabel,
  roleLabel,
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
    ? decisionsForThreat(
        store.data.decisions,
        selectedThreat.value.id,
        selectedThreat.value.revision,
      )
    : [],
)
const basisWarnings = computed(() =>
  currentDecisions.value.filter((decision) => decision.basisStatus !== 'confirmed'),
)

type RoleState = DecisionType | 'pending' | 'invalidated' | 'unverified'

const decisionForRole = (threat: Threat, role: ActorRole): ReviewDecision | undefined =>
  decisionsForThreat(store.data.decisions, threat.id, threat.revision).find(
    (decision) => decision.role === role,
  )

const statusForRole = (threat: Threat, role: ActorRole): RoleState => {
  const decision = decisionForRole(threat, role)
  if (!decision) return 'pending'
  if (decision.basisStatus === 'invalidated') return 'invalidated'
  if (decision.basisStatus === 'unverified') return 'unverified'
  return decision.decision
}

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
    form.comment,
  )
  decisionVisible.value = false
  toast.add({
    severity: 'success',
    summary: '会签意见已提交',
    detail: '已固化威胁、控制证据与缓解任务作为审核依据',
    life: 2500,
  })
}

const decisionLabel = (state: RoleState): string => {
  if (state === 'pending') return '待提交'
  if (state === 'invalidated') return '依据失效'
  if (state === 'unverified') return '待复核'
  return decisionOptions.find((item) => item.value === state)?.label ?? state
}

const basisTag = (decision: ReviewDecision): string => decision.basisStatus ?? 'unverified'

const formatBasisTime = (value: string | undefined): string =>
  value ? new Date(value).toLocaleString('zh-CN') : '-'
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
                  pending: statusForRole(threat, role.value) === 'pending',
                  invalid:
                    statusForRole(threat, role.value) === 'invalidated' ||
                    statusForRole(threat, role.value) === 'unverified',
                }"
              >
                {{ decisionLabel(statusForRole(threat, role.value)) }}
              </strong>
            </div>
          </div>
          <ProgressBar
            :value="reviewProgress(activeDecisionsForThreat(store.data.decisions, threat.id, threat.revision))"
            :show-value="false"
            class="review-progress"
          />
          <p
            v-for="decision in decisionsForThreat(store.data.decisions, threat.id, threat.revision).filter(
              (item) => item.basisStatus !== 'confirmed',
            )"
            :key="decision.id"
            class="basis-inline-warning"
          >
            <i class="pi pi-exclamation-triangle"></i>
            {{ roleLabel(decision.role) }}的意见{{ basisStatusLabel(decision.basisStatus) }}：{{
              decision.invalidReason
            }}
          </p>
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
          <Button label="提交会签意见" icon="pi pi-pencil" @click="openDecision" />

          <section v-if="basisWarnings.length > 0" class="basis-warning-box">
            <h3>
              <i class="pi pi-exclamation-triangle"></i>
              审核依据预警
            </h3>
            <article v-for="decision in basisWarnings" :key="decision.id" class="basis-warning">
              <div class="basis-warning-head">
                <strong>{{ roleLabel(decision.role) }}（{{ decision.actor }}）</strong>
                <StatusTag :value="basisTag(decision)" kind="review" />
              </div>
              <p>{{ decision.invalidReason }}</p>
              <time v-if="decision.invalidatedAt">失效时间：{{ formatBasisTime(decision.invalidatedAt) }}</time>
            </article>
          </section>

          <section class="decision-history">
            <h3>当前修订（r{{ selectedThreat.revision }}）会签记录</h3>
            <article v-for="decision in currentDecisions" :key="decision.id" class="decision-entry">
              <div>
                <strong>{{ decision.actor }}</strong>
                <span>{{ roleOptions.find((role) => role.value === decision.role)?.label }}</span>
              </div>
              <div class="decision-tags">
                <StatusTag :value="decision.decision" kind="review" />
                <StatusTag :value="basisTag(decision)" kind="review" />
              </div>
              <p>{{ decision.comment }}</p>
              <p v-if="decision.invalidReason" class="decision-invalid-reason">
                {{ basisStatusLabel(decision.basisStatus) }}原因：{{ decision.invalidReason }}
              </p>
              <dl v-if="decision.basis" class="basis-list">
                <dt>审核依据（提交时固化）</dt>
                <dd>
                  威胁修订 r{{ decision.basis.threatRevision }} ·
                  {{ decision.basis.items.filter((item) => item.type === 'evidence').length }} 项控制证据 ·
                  {{ decision.basis.items.filter((item) => item.type === 'mitigation').length }} 项缓解任务
                  <em v-if="decision.basis.reconstructed">（历史数据按修订号回填）</em>
                </dd>
                <dd v-for="item in decision.basis.items" :key="`${item.type}-${item.id}`" class="basis-item">
                  <i :class="item.type === 'evidence' ? 'pi pi-file-check' : 'pi pi-flag'"></i>
                  {{ item.label }}
                </dd>
              </dl>
              <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
            </article>
            <div v-if="currentDecisions.length === 0" class="empty-state">尚未提交会签意见。</div>
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

.review-board {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(390px, 0.75fr);
  gap: 16px;
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

.role-state strong.invalid {
  color: #b03a2e;
}

.basis-inline-warning {
  display: flex;
  gap: 7px;
  margin: 10px 0 0;
  padding: 8px 10px;
  border-left: 3px solid #c64b39;
  border-radius: 4px;
  background: #fdf3f1;
  color: #94403a;
  font-size: 11px;
  line-height: 1.5;
}

.basis-inline-warning i {
  margin-top: 3px;
}

.review-progress {
  height: 4px;
  margin-top: 14px;
}

.basis-warning-box {
  margin-top: 18px;
  padding: 12px 14px;
  border: 1px solid #f0c4b8;
  border-radius: 6px;
  background: #fdf6f4;
}

.basis-warning-box h3 {
  display: flex;
  align-items: center;
  gap: 7px;
  margin: 0 0 10px;
  color: #b03a2e;
  font-size: 13px;
}

.basis-warning {
  display: grid;
  gap: 5px;
  padding: 9px 0;
  border-bottom: 1px solid #f2ddd7;
}

.basis-warning:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.basis-warning-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.basis-warning p {
  margin: 0;
  color: #8a473f;
  font-size: 12px;
  line-height: 1.55;
}

.basis-warning time {
  color: #a98e89;
  font-size: 10px;
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

.decision-tags {
  display: flex;
  gap: 5px;
}

.decision-invalid-reason {
  padding: 7px 9px;
  border-left: 3px solid #c64b39;
  border-radius: 3px;
  background: #fdf3f1;
  color: #94403a !important;
}

.basis-list {
  grid-column: 1 / -1;
  margin: 0;
  padding: 9px 10px;
  border: 1px dashed #d3dae3;
  border-radius: 5px;
  background: #f8fafc;
  font-size: 11px;
}

.basis-list dt {
  color: #46546b;
  font-weight: 700;
}

.basis-list dd {
  margin: 4px 0 0;
  color: #6a7689;
  line-height: 1.6;
}

.basis-list dd.basis-item {
  display: flex;
  gap: 6px;
}

.basis-list em {
  color: #a05a00;
  font-style: normal;
}
</style>
