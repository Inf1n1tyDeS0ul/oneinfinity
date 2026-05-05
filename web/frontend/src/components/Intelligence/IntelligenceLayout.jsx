import React from 'react'

export default function IntelligenceLayout({ children }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-4 md:grid-rows-2 gap-4 auto-rows-auto">
      {children}
    </div>
  )
}
