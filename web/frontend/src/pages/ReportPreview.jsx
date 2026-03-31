import React, { useState, useEffect, useRef } from 'react'
import { useParams, useSearchParams, useNavigate } from 'react-router-dom'
import { X, Download, Loader2, AlertTriangle, RefreshCw } from 'lucide-react'
import api from '../utils/api'

export default function ReportPreview() {
  const { scanId } = useParams()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const [pdfUrl, setPdfUrl] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const blobRef = useRef(null)

  const sectionsParam = searchParams.get('sections') || ''
  const sections = sectionsParam ? sectionsParam.split(',').filter(Boolean) : null

  const fetchPdf = async () => {
    setLoading(true)
    setError(null)
    // Revoke previous blob URL
    if (blobRef.current) {
      URL.revokeObjectURL(blobRef.current)
      blobRef.current = null
      setPdfUrl(null)
    }
    try {
      const resp = await api.post(
        '/reports/publish',
        { scan_id: scanId, sections: sections },
        { responseType: 'blob', timeout: 120000 }
      )
      const blob = new Blob([resp.data], { type: 'application/pdf' })
      const url = URL.createObjectURL(blob)
      blobRef.current = url
      setPdfUrl(url)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to generate report')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchPdf()
    return () => {
      if (blobRef.current) {
        URL.revokeObjectURL(blobRef.current)
      }
    }
  }, [scanId, sectionsParam])

  return (
    <div className="fixed inset-0 z-50 bg-gray-950 flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-sm font-semibold text-white">Security Report</span>
          <span className="text-xs text-gray-500 font-mono">{scanId}</span>
        </div>
        <div className="flex items-center gap-2">
          {pdfUrl && (
            <a
              href={pdfUrl}
              download={`oneinfinity-report-${scanId}.pdf`}
              className="btn-primary text-xs flex items-center gap-1.5"
            >
              <Download size={13} />
              Download PDF
            </a>
          )}
          {error && (
            <button
              onClick={fetchPdf}
              className="btn-secondary text-xs flex items-center gap-1.5"
            >
              <RefreshCw size={13} />
              Retry
            </button>
          )}
          <button
            onClick={() => navigate(-1)}
            className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
            title="Close"
          >
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 relative">
        {loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-gray-400">
            <Loader2 size={32} className="animate-spin text-blue-400" />
            <span className="text-sm">Generating report…</span>
          </div>
        )}

        {error && !loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 text-gray-400">
            <AlertTriangle size={32} className="text-red-400" />
            <span className="text-sm text-red-300">{error}</span>
          </div>
        )}

        {pdfUrl && !loading && (
          <iframe
            src={pdfUrl}
            className="w-full h-full border-0"
            title="Security Report Preview"
          />
        )}
      </div>
    </div>
  )
}
