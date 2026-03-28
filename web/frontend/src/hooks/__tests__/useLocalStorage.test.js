import { renderHook, act } from '@testing-library/react'
import { useLocalStorage } from '../useLocalStorage'

beforeEach(() => localStorage.clear())

test('returns default value when key not set', () => {
  const { result } = renderHook(() => useLocalStorage('key', 'default'))
  expect(result.current[0]).toBe('default')
})

test('persists value to localStorage', () => {
  const { result } = renderHook(() => useLocalStorage('key', 'default'))
  act(() => result.current[1]('updated'))
  expect(localStorage.getItem('key')).toBe('"updated"')
  expect(result.current[0]).toBe('updated')
})

test('reads existing localStorage value on mount', () => {
  localStorage.setItem('key', '"existing"')
  const { result } = renderHook(() => useLocalStorage('key', 'default'))
  expect(result.current[0]).toBe('existing')
})
