import type { ThreatModelState } from '@/models/domain'
import { createSeedState } from '@/models/seed'
import { migrateState } from '@/services/reviewBasis'

const STORAGE_KEY = 'scapex-threat-model-v1'

const clone = <T>(value: T): T => structuredClone(value)

const normalize = (state: ThreatModelState): ThreatModelState => {
  // 升级历史数据：按修订号回填会签依据，并重新核对证据是否已静默失效
  migrateState(state)
  return state
}

export const loadState = (): ThreatModelState => {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    const seed = normalize(createSeedState())
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }

  try {
    const parsed = JSON.parse(raw) as ThreatModelState
    const changed = migrateState(parsed)
    if (changed) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed))
    }
    return parsed
  } catch {
    const seed = normalize(createSeedState())
    localStorage.setItem(STORAGE_KEY, JSON.stringify(seed))
    return seed
  }
}

export const saveState = (state: ThreatModelState): void => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(clone(state)))
}

export const resetState = (): ThreatModelState => {
  const seed = normalize(createSeedState())
  saveState(seed)
  return seed
}

export const createId = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`
