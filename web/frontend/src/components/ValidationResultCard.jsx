import React, { useState, useEffect } from 'react'
import { CheckCircle2, XCircle, RefreshCw, AlertTriangle, Shield, Target, Zap } from 'lucide-react'
import clsx from 'clsx'
import api, { endpoints } from '../utils/api'
/**
 * ValidationResultCard — Display validation orchestrator results
 *
 * Props:
 * - findingId: string (required)
 * - onRetry: callback function (optional)
 * - compact: boolean (show minimal view)
 */
export function ValidationResultCard({ findingId, onRetry, compact = false }) {
  const [validation, setValidation] = useState(null)
  const [loading, setLoading] = useState(true)
  const [retrying, setRetrying] = useState(false)
  const [error, setError] = useState(null)

  // Fetch validation result on mount
  useEffect(() => {
    if (!findingId) return

    const fetchValidation = async () => {
      try {
        const response = await api.get(`/findings/${findingId}/validation`)
        setValidation(response.data)
        setError(null)
      } catch (err) {
        if (err.response?.status === 404) {
          setValidation(null)
        } else {
          console.error('Failed to fetch validation:', err)
          setError(err.message)
        }
      } finally {
        setLoading(false)
      }
    }

    fetchValidation()
  }, [findingId])

  // WebSocket listener for real-time updates
  useEffect(() => {
    if (!findingId) return

    const handleValidationComplete = (event) => {
      const data = JSON.parse(event.data)

      if (data.type === 'validation_complete' && data.finding_id === findingId) {
        api.get(`/findings/${findingId}/validation`)
          .then(res => setValidation(res.data))
          .catch(err => console.error('Failed to update validation:', err))
      }
    }

    if (window.websocket && window.websocket.readyState === WebSocket.OPEN) {
      window.websocket.addEventListener('message', handleValidationComplete)
      return () => {
        window.websocket.removeEventListener('message', handleValidationComplete)
      }
    }
  }, [findingId])

  const handleRetry = async () => {
    if (!findingId) return
    setRetrying(true)
    setError(null)
    try {
      const response = await api.post(`/findings/${findingId}/validate`, {
        strategies: ['hybrid']
      })
      const data = response.data
      setValidation(data)
      if (onRetry) onRetry(data)
    } catch (err) {
      console.error('Failed to trigger validation:', err)
      setError(err.message)
    } finally {
      setRetrying(false)
    }
  }

  // Loading state
  if (loading) {
    return (
      <div className="flex items-center gap-2 text-slate-500">
        <RefreshCw size={14} className="animate-spin" />
        <span className="text-xs">Loading validation...</span>
      </div>
    )
  }

  // No validation result
  if (!validation) {
    return (
      <div className="flex items-center gap-2">
        <button
          onClick={handleRetry}
          disabled={retrying}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          {retrying ? (
            <><RefreshCw size={14} className="animate-spin" /> Validating...</>
          ) : (
            <><Shield size={14} /> Validate Finding</>
          )}
        </button>
        {error && (
          <span className="text-xs text-red-400">Error: {error}</span>
        )}
      </div>
    )
  }

  // Confidence color mapping
  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.80) return 'emerald'
    if (confidence >= 0.65) return 'yellow'
    if (confidence >= 0.50) return 'orange'
    return 'red'
  }

  const confidenceColor = getConfidenceColor(validation.confidence)
  const confidencePercent = Math.round(validation.confidence * 100)

  // Compact view
  if (compact) {
    return (
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          {validation.valid ? (
            <CheckCircle2 size={16} className="text-emerald-400" />
          ) : (
            <XCircle size={16} className="text-red-400" />
          )}
          <span className="text-xs font-medium">
            {validation.valid ? 'Valid' : 'Invalid'}
          </span>
        </div>

        <div className={clsx(
          'px-2 py-1 rounded text-xs font-bold',
          confidenceColor === 'emerald' && 'bg-emerald-500/20 text-emerald-400',
          confidenceColor === 'yellow' && 'bg-yellow-500/20 text-yellow-400',
          confidenceColor === 'orange' && 'bg-orange-500/20 text-orange-400',
          confidenceColor === 'red' && 'bg-red-500/20 text-red-400',
        )}>
          {confidencePercent}%
        </div>

        <button
          onClick={handleRetry}
          disabled={retrying}
          className="p-1.5 hover:bg-slate-800 rounded transition-colors disabled:opacity-50"
          title="Re-validate"
        >
          <RefreshCw size={14} className={clsx(retrying && 'animate-spin')} />
        </button>
      </div>
    )
  }

  // Full view
  return (
    <div className="bg-bg-primary/50 border border-bg-border/50 rounded-xl p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={clsx(
            'p-2 rounded-lg',
            validation.valid ? 'bg-emerald-500/20' : 'bg-red-500/20'
          )}>
            {validation.valid ? (
              <CheckCircle2 size={20} className="text-emerald-400" />
            ) : (
              <XCircle size={20} className="text-red-400" />
            )}
          </div>

          <div>
            <div className="text-sm font-bold">
              {validation.valid ? 'Finding Validated' : 'Validation Failed'}
            </div>
            <div className="text-xs text-slate-500">
              {validation.retry_count > 0 && `${validation.retry_count} retries • `}
              {Math.round(validation.duration_ms)}ms
            </div>
          </div>
        </div>

        <button
          onClick={handleRetry}
          disabled={retrying}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          {retrying ? (
            <><RefreshCw size={14} className="animate-spin" /> Retrying...</>
          ) : (
            <><RefreshCw size={14} /> Retry</>
          )}
        </button>
      </div>

      {/* Confidence Score */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="font-medium text-slate-400">Confidence Score</span>
          <span className={clsx(
            'font-bold',
            confidenceColor === 'emerald' && 'text-emerald-400',
            confidenceColor === 'yellow' && 'text-yellow-400',
            confidenceColor === 'orange' && 'text-orange-400',
            confidenceColor === 'red' && 'text-red-400',
          )}>
            {confidencePercent}%
          </span>
        </div>

        <div className="h-2 bg-slate-900/50 rounded-full overflow-hidden">
          <div
            className={clsx(
              'h-full transition-all duration-500',
              confidenceColor === 'emerald' && 'bg-emerald-500',
              confidenceColor === 'yellow' && 'bg-yellow-500',
              confidenceColor === 'orange' && 'bg-orange-500',
              confidenceColor === 'red' && 'bg-red-500',
            )}
            style={{ width: `${confidencePercent}%` }}
          />
        </div>
      </div>

      {/* Strategy Results */}
      <div className="grid grid-cols-3 gap-3">
        {/* Live Validation */}
        {validation.live_validation !== null && (
          <div className="bg-slate-900/30 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="flex items-center gap-2">
              <Target size={14} className="text-cyan-400" />
              <span className="text-xs font-medium text-slate-400">Live</span>
            </div>
            <div className="flex items-center gap-2">
              {validation.live_validation ? (
                <><CheckCircle2 size={16} className="text-emerald-400" /> <span className="text-xs font-bold text-emerald-400">Success</span></>
              ) : (
                <><XCircle size={16} className="text-red-400" /> <span className="text-xs font-bold text-red-400">Failed</span></>
              )}
            </div>
          </div>
        )}

        {/* Static Validation */}
        {validation.static_score !== null && (
          <div className="bg-slate-900/30 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-purple-400" />
              <span className="text-xs font-medium text-slate-400">Static</span>
            </div>
            <div className="text-xs font-bold text-purple-400">
              {Math.round(validation.static_score * 100)}%
            </div>
          </div>
        )}

        {/* Context Validation */}
        {validation.context_score !== null && (
          <div className="bg-slate-900/30 border border-slate-800 rounded-lg p-3 space-y-1">
            <div className="flex items-center gap-2">
              <Zap size={14} className="text-yellow-400" />
              <span className="text-xs font-medium text-slate-400">Context</span>
            </div>
            <div className="text-xs font-bold text-yellow-400">
              {Math.round(validation.context_score * 100)}%
            </div>
          </div>
        )}
      </div>

      {/* Notes */}
      {validation.notes && (
        <div className="bg-slate-900/30 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-slate-500" />
            <span className="text-xs font-medium text-slate-400">Notes</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            {validation.notes}
          </p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-center gap-2">
          <XCircle size={14} className="text-red-400" />
          <span className="text-xs text-red-400">{error}</span>
        </div>
      )}
    </div>
  )
}

export default ValidationResultCard
