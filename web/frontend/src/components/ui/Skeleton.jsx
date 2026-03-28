import React from 'react'
import clsx from 'clsx'

export function Skeleton({ className }) {
  return <div className={clsx('skeleton h-4 w-full', className)} />
}

export function SkeletonTable({ rows = 5, cols = 4 }) {
  return (
    <div className="w-full">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} role="listitem" className="flex gap-3 px-4 py-3 border-b border-bg-border/50">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} className={clsx('h-3', j === 0 ? 'w-32' : j === cols - 1 ? 'w-16' : 'flex-1')} />
          ))}
        </div>
      ))}
    </div>
  )
}

export function SkeletonCard() {
  return (
    <div className="card p-5 flex flex-col gap-3">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="h-8 w-16" />
      <Skeleton className="h-3 w-32" />
    </div>
  )
}

export function SkeletonStatGrid({ count = 4 }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  )
}
