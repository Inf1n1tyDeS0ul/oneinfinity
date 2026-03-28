import { render, screen, fireEvent } from '@testing-library/react'
import { DataTable } from '../DataTable'

const COLS = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'severity', label: 'Severity', sortable: true },
]
const DATA = [
  { id: 1, name: 'Bravo', severity: 'high' },
  { id: 2, name: 'Alpha', severity: 'critical' },
  { id: 3, name: 'Charlie', severity: 'low' },
]

test('renders all rows', () => {
  render(<DataTable columns={COLS} data={DATA} />)
  expect(screen.getByText('Bravo')).toBeInTheDocument()
  expect(screen.getByText('Alpha')).toBeInTheDocument()
  expect(screen.getByText('Charlie')).toBeInTheDocument()
})

test('sorts ascending on header click', () => {
  render(<DataTable columns={COLS} data={DATA} />)
  fireEvent.click(screen.getByText('Name'))
  const rows = screen.getAllByRole('row')
  // First data row (index 1, skipping header) should be Alpha after sort
  expect(rows[1].textContent).toContain('Alpha')
})

test('filters rows by search query', () => {
  render(<DataTable columns={COLS} data={DATA} searchable />)
  fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: 'alpha' } })
  expect(screen.getByText('Alpha')).toBeInTheDocument()
  expect(screen.queryByText('Bravo')).not.toBeInTheDocument()
})

test('shows empty state when no data', () => {
  render(<DataTable columns={COLS} data={[]} emptyMessage="Nothing here" />)
  expect(screen.getByText('Nothing here')).toBeInTheDocument()
})

test('shows loading skeletons when loading prop is true', () => {
  render(<DataTable columns={COLS} data={[]} loading />)
  expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0)
})
