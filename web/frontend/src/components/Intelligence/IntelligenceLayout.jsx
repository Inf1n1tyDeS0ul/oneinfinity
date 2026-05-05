import React from 'react'

export default function IntelligenceLayout({ children }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 auto-rows-auto">
      {children}
    </div>
  )
}
