import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { ConfirmProvider } from '@/components/ui/confirm'
import { ToastProvider } from '@/components/ui/toast'
import { AppLayout } from '@/layout/AppLayout'
import { AuthProvider, RequireAuth } from '@/store/auth'
import { Login } from '@/pages/Login'
import { Dashboard } from '@/pages/Dashboard'
import { NotFound } from '@/pages/NotFound'
import { Vulnerabilities } from '@/pages/Vulnerabilities'
import { Units } from '@/pages/Units'
import { Tags } from '@/pages/Tags'
import { Domains } from '@/pages/Domains'
import { Scanner } from '@/pages/Scanner'
import { Reports } from '@/pages/Reports'
import { ReportAI } from '@/pages/ReportAI'
import { Assistant } from '@/pages/Assistant'
import { Settings } from '@/pages/Settings'
import { Users } from '@/pages/Users'
import { ToolPassword } from '@/pages/tools/Password'
import { ToolDedup } from '@/pages/tools/Dedup'
import { ToolUrls } from '@/pages/tools/Urls'
import { ToolCompare } from '@/pages/tools/Compare'
import { ToolClassify } from '@/pages/tools/Classify'
import { ToolCvss } from '@/pages/tools/Cvss'

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <ConfirmProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route
                element={
                  <RequireAuth>
                    <AppLayout />
                  </RequireAuth>
                }
              >
                <Route index element={<Dashboard />} />
                <Route path="units" element={<Units />} />
                <Route path="tags" element={<Tags />} />
                <Route path="domains" element={<Domains />} />
                <Route path="vulnerabilities" element={<Vulnerabilities />} />
                <Route path="scanner" element={<Scanner />} />
                <Route path="reports" element={<Reports />} />
                <Route path="reports/ai" element={<ReportAI />} />
                <Route path="assistant" element={<Assistant />} />
                <Route path="tools/password" element={<ToolPassword />} />
                <Route path="tools/dedup" element={<ToolDedup />} />
                <Route path="tools/urls" element={<ToolUrls />} />
                <Route path="tools/compare" element={<ToolCompare />} />
                <Route path="tools/classify" element={<ToolClassify />} />
                <Route path="tools/cvss" element={<ToolCvss />} />
                <Route
                  path="users"
                  element={
                    <RequireAuth adminOnly>
                      <Users />
                    </RequireAuth>
                  }
                />
                <Route path="settings" element={<Settings />} />
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
          </ConfirmProvider>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  )
}
