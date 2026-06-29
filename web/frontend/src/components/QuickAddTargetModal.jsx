import React, { useState } from 'react'
import { X, Target, Plus, Shield } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'

export default function QuickAddTargetModal({ isOpen, onClose }) {
  const { targets, setTargets, addNotification, setSelectedTarget } = useStore()
  const [form, setForm] = useState({ name: '', domain: '', platform: 'hackerone', scope: '' })
  const [saving, setSaving] = useState(false)

  if (!isOpen) return null

  const handleAdd = async () => {
    if (!form.name || !form.domain) {
      addNotification('Name and Domain are required', 'warn')
      return
    }
    setSaving(true)
    try {
      const r = await endpoints.createTarget({
        name: form.name,
        domain: form.domain,
        platform: form.platform,
        scope: form.scope.split('\n').map(s => s.trim()).filter(Boolean),
      })
      
      const newTarget = r.data
      setTargets([...targets, newTarget])
      setSelectedTarget(newTarget.domain)
      
      addNotification(`Target added: ${form.domain}`, 'success')
      onClose()
      setForm({ name: '', domain: '', platform: 'hackerone', scope: '' })
    } catch (e) {
      addNotification(`Failed: ${e.response?.data?.error || e.message}`, 'error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in p-4">
      <div className="bg-bg-secondary border border-bg-border rounded-xl shadow-modal w-full max-w-md overflow-hidden animate-slide-in flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-bg-border bg-bg-elevated/50">
          <div className="flex items-center gap-2">
            <Target size={16} className="text-accent-primary" />
            <span className="text-sm font-bold text-slate-200 uppercase tracking-wider">Quick Add Target</span>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 flex flex-col gap-4 overflow-y-auto">
          <div className="grid grid-cols-1 gap-4">
            <div>
              <label className="label text-[10px] uppercase tracking-widest text-slate-500 mb-1.5 block">Program Name</label>
              <input 
                className="input w-full" 
                placeholder="e.g. ACME Corp" 
                value={form.name}
                autoFocus
                onChange={e => setForm({ ...form, name: e.target.value })} 
              />
            </div>
            <div>
              <label className="label text-[10px] uppercase tracking-widest text-slate-500 mb-1.5 block">Primary Domain</label>
              <input 
                className="input w-full" 
                placeholder="target.com" 
                value={form.domain}
                onChange={e => setForm({ ...form, domain: e.target.value })} 
              />
            </div>
            <div>
              <label className="label text-[10px] uppercase tracking-widest text-slate-500 mb-1.5 block">Platform</label>
              <select 
                className="select w-full" 
                value={form.platform}
                onChange={e => setForm({ ...form, platform: e.target.value })}
              >
                <option value="hackerone">HackerOne</option>
                <option value="bugcrowd">Bugcrowd</option>
                <option value="intigriti">Intigriti</option>
                <option value="yeswehack">YesWeHack</option>
                <option value="other">Other / Private</option>
              </select>
            </div>
            <div>
              <label className="label text-[10px] uppercase tracking-widest text-slate-500 mb-1.5 block">Initial Scope (Optional)</label>
              <textarea 
                className="input w-full h-20 resize-none py-2" 
                placeholder="*.target.com&#10;api.target.com"
                value={form.scope} 
                onChange={e => setForm({ ...form, scope: e.target.value })} 
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-4 bg-bg-elevated/30 border-t border-bg-border flex justify-end gap-3">
          <button 
            className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors"
            onClick={onClose}
          >
            Cancel
          </button>
          <button 
            className="btn-primary px-6 flex items-center gap-2"
            onClick={handleAdd}
            disabled={saving}
          >
            {saving ? (
              <>
                <div className="w-3 h-3 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                Processing...
              </>
            ) : (
              <>
                <Plus size={14} />
                Add & Select
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
