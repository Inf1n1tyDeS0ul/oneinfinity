import React, { useState } from 'react'
import { Plus, Trash2, Target, ExternalLink } from 'lucide-react'
import { useStore } from '../store/useStore'
import { endpoints } from '../utils/api'
import { DataTable } from '../components/ui/DataTable'

const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti', 'yeswehack']

const COLUMNS = [
  { key: 'name',   label: 'Name',   sortable: true },
  { key: 'domain', label: 'Domain', sortable: true },
  { key: 'type',   label: 'Type',   sortable: true },
  { key: 'status', label: 'Status', sortable: true,
    render: (v) => <span className={`badge ${v === 'active' ? 'badge-running' : 'badge-queued'}`}>{v || 'unknown'}</span> },
]

export default function Targets() {
  const { targets, setTargets, addNotification } = useStore()
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ name: '', domain: '', platform: 'hackerone', scope: '' })
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleAdd = async () => {
    if (!form.name || !form.domain) return
    setSaving(true)
    try {
      const r = await endpoints.createTarget({
        name: form.name,
        domain: form.domain,
        platform: form.platform,
        scope: form.scope.split('\n').map(s => s.trim()).filter(Boolean),
      })
      setTargets([...targets, r.data])
      setForm({ name: '', domain: '', platform: 'hackerone', scope: '' })
      setShowAdd(false)
      addNotification(`Target added: ${form.domain}`, 'success')
    } catch (e) {
      addNotification(`Failed: ${e.message}`, 'error')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id, domain) => {
    if (!confirm(`Remove target ${domain}?`)) return
    try {
      await endpoints.deleteTarget(id)
      setTargets(targets.filter(t => t.id !== id))
      addNotification(`Removed: ${domain}`)
    } catch (e) {
      addNotification(`Failed: ${e.message}`, 'error')
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Target size={15} className="text-accent-primary" />
          Targets ({targets.length})
        </h1>
        <button className="btn-primary flex items-center gap-1.5" onClick={() => setShowAdd(!showAdd)}>
          <Plus size={12} />
          Add Target
        </button>
      </div>

      {/* Add form */}
      {showAdd && (
        <div className="card p-4 flex flex-col gap-3">
          <div className="text-xs text-slate-300 font-medium mb-1">New Target</div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label">Program Name</label>
              <input className="input" placeholder="ACME Corp" value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })} />
            </div>
            <div>
              <label className="label">Domain / URL</label>
              <input className="input" placeholder="target.com" value={form.domain}
                onChange={e => setForm({ ...form, domain: e.target.value })} />
            </div>
            <div>
              <label className="label">Platform</label>
              <select className="select" value={form.platform}
                onChange={e => setForm({ ...form, platform: e.target.value })}>
                {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
            <div>
              <label className="label">Scope (one per line)</label>
              <textarea className="input h-16 resize-none" placeholder="*.target.com&#10;api.target.com"
                value={form.scope} onChange={e => setForm({ ...form, scope: e.target.value })} />
            </div>
          </div>
          <div className="flex gap-2">
            <button className="btn-primary" onClick={handleAdd} disabled={saving}>
              {saving ? 'Adding...' : 'Add Target'}
            </button>
            <button className="btn-secondary" onClick={() => setShowAdd(false)}>Cancel</button>
          </div>
        </div>
      )}

      <DataTable
        columns={COLUMNS}
        data={targets}
        searchable
        loading={loading}
        emptyMessage="No targets yet"
        emptyAction={<button className="btn-primary mt-2" onClick={() => setShowAdd(true)}>Add your first target</button>}
      />
    </div>
  )
}
