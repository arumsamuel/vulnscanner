import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanDetails from './pages/ScanDetails'
import History from './pages/History'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan" element={<NewScan />} />
        <Route path="/scan/:scanId" element={<ScanDetails />} />
        <Route path="/history" element={<History />} />
      </Routes>
    </Layout>
  )
}

export default App
