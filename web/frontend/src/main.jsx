import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null } }
  static getDerivedStateFromError(e) { return { error: e } }
  render() {
    if (this.state.error) {
      return (
        <div style={{padding:'2rem',fontFamily:'monospace',color:'#f87171',background:'#07090f',minHeight:'100vh'}}>
          <h2 style={{marginBottom:'1rem'}}>Runtime Error</h2>
          <pre style={{whiteSpace:'pre-wrap',fontSize:'12px'}}>{String(this.state.error)}{'\n\n'}{this.state.error?.stack}</pre>
        </div>
      )
    }
    return this.props.children
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <ErrorBoundary>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </ErrorBoundary>
)
