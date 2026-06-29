import { create } from 'zustand'

export const useStore = create((set, get) => ({
  // Data
  stats: null,
  targets: [],
  scans: [],
  vulnerabilities: [],
  campaigns: [],
  logs: [],
  attackGraph: { nodes: [], edges: [] },

  // UI state
  selectedTarget: null,
  notifications: [],

  // Actions
  setStats: (stats) => set({ stats }),
  setTargets: (targets) => set({ targets }),
  setScans: (scans) => set({ scans }),
  setVulnerabilities: (vulnerabilities) => set({ vulnerabilities }),
  setCampaigns: (campaigns) => set({ campaigns }),
  setAttackGraph: (attackGraph) => set({ attackGraph }),
  setSelectedTarget: (selectedTarget) => set({ selectedTarget }),

  clearLogs: () => set({ logs: [] }),
  consoleOpen: false,
  setConsoleOpen: (consoleOpen) => set({ consoleOpen }),

  addLog: (entry) => set((state) => ({
    logs: [...state.logs.slice(-499), entry],
  })),

  addNotification: (msg, type = 'info') => {
    const id = Date.now()
    set((state) => ({
      notifications: [...state.notifications, { id, msg, type }],
    }))
    setTimeout(() => {
      set((state) => ({
        notifications: state.notifications.filter(n => n.id !== id),
      }))
    }, 5000)
  },

  updateScan: (scanId, updates) => set((state) => ({
    scans: state.scans.map(s => s.id === scanId ? { ...s, ...updates } : s),
  })),
}))
