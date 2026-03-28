import { render } from '@testing-library/react'
import { Skeleton, SkeletonTable, SkeletonCard } from '../Skeleton'

test('Skeleton renders with default classes', () => {
  const { container } = render(<Skeleton />)
  const el = container.firstChild
  expect(el).toHaveClass('skeleton')
  expect(el).toHaveClass('h-4')
  expect(el).toHaveClass('w-full')
})

test('Skeleton accepts custom className', () => {
  const { container } = render(<Skeleton className="w-24 h-6" />)
  expect(container.firstChild).toHaveClass('w-24', 'h-6')
})

test('SkeletonTable renders correct number of rows', () => {
  const { getAllByRole } = render(<SkeletonTable rows={3} cols={4} />)
  expect(getAllByRole('listitem')).toHaveLength(3)
})

test('SkeletonCard renders', () => {
  const { container } = render(<SkeletonCard />)
  expect(container.firstChild).toBeTruthy()
})
