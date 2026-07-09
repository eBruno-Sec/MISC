import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { supabase } from './lib/supabase'
import Login from './pages/Login'
import Onboarding from './pages/Onboarding'
import Dashboard from './pages/Dashboard'
import WorkoutLog from './pages/WorkoutLog'
import Harem from './pages/Harem'
import NavBar from './components/NavBar'

export default function App() {
  const [session, setSession] = useState(null)
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session)
      if (session) fetchProfile(session.user.id)
      else setLoading(false)
    })

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session)
      if (session) fetchProfile(session.user.id)
      else { setProfile(null); setLoading(false) }
    })

    return () => subscription.unsubscribe()
  }, [])

  async function fetchProfile(userId) {
    const { data } = await supabase
      .from('users')
      .select('*')
      .eq('user_id', userId)
      .maybeSingle()
    setProfile(data)
    setLoading(false)
  }

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-rings">
          <div className="load-ring" />
          <div className="load-ring" />
        </div>
        <span className="pixel-text loading-label">LOADING...</span>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        {!session ? (
          <Route path="*" element={<Login />} />
        ) : !profile?.class_archetype ? (
          <Route path="*" element={<Onboarding userId={session.user.id} onComplete={setProfile} />} />
        ) : (
          <>
            <Route path="/" element={<><NavBar /><Dashboard profile={profile} setProfile={setProfile} /></>} />
            <Route path="/workout" element={<><NavBar /><WorkoutLog profile={profile} setProfile={setProfile} /></>} />
            <Route path="/harem" element={<><NavBar /><Harem profile={profile} /></>} />
            <Route path="*" element={<Navigate to="/" />} />
          </>
        )}
      </Routes>
    </BrowserRouter>
  )
}
