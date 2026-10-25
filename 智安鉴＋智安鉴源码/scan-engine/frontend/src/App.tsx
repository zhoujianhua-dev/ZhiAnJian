import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import { ProtectedRoute } from './components/ProtectedRoute'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ScanList from './pages/ScanList'
import ScanDetail from './pages/ScanDetail'
import NewScan from './pages/NewScan'
import Knowledgebase from './pages/Knowledgebase'
import Settings from './pages/Settings'
import Personas from './pages/Personas'
import { AdminPanel } from './pages/AdminPanel'
import { Auth } from './pages/Auth'

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/auth" element={<Auth />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="scans" element={<ScanList />} />
          <Route path="scans/:scanId" element={<ScanDetail />} />
          <Route path="new-scan" element={<NewScan />} />
          <Route path="knowledgebase" element={<Knowledgebase />} />
          <Route path="settings" element={<Settings />} />
          <Route path="personas" element={<Personas />} />
          <Route
            path="admin"
            element={
              <ProtectedRoute requireAdmin>
                <AdminPanel />
              </ProtectedRoute>
            }
          />
        </Route>
      </Routes>
    </AuthProvider>
  )
}

export default App
