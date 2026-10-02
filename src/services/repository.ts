import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'
import type { Invalidation } from '@/services/reviewBasis'
import {
  CURRENT_SCHEMA_VERSION,
  migrateLegacyState,
  revalidateThreatApprovals,
} from '@/services/reviewBasis'

const STORAGE_KEY = 'scapex-threat-model-v1'

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T

export interface LoadResult {
  state: ThreatModelState
  /** 升级后无法自动确认依据、等待复核的历史意见数 */
  needsReviewCount: number
  /** 加载时因证据到期/失效等被连带作废的通过意见 */
  invalidations: Invalidation[]
}

const upgrade = (state: ThreatModelState): LoadResult => {
  const legacy = state.schemaVersion !== CURRENT_SCHEMA_VERSION
  const needsReviewCount = legacy ? migrateLegacyState(state) : 0
  const threatIds = state.threats.map((threat) => threat.id)
  const invalidations = revalidateThreatApprovals(state, threatIds)
  return { state, needsReviewCount, invalidations }
}

export const loadState = (): LoadResult => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const result = upgrade(createSeedState())
    localStorage.setItem(STORAGE_KEY, JSON.stringify(result.state))
    return result
  }

  try {
    const parsed = JSON.parse(raw) as ThreatModelState
    const result = upgrade(parsed)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(result.state))
    return result
  } catch {
    const result = upgrade(createSeedState())
    localStorage.setItem(STORAGE_KEY, JSON.stringify(result.state))
    return result
  }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = createSeedState()
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
