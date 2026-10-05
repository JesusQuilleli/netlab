import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './styles.css'
const t = localStorage.getItem('theme'); if (t) document.documentElement.dataset.theme = t
createRoot(document.getElementById('root')!).render(<BrowserRouter><App /></BrowserRouter>)
