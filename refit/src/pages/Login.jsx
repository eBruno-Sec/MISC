import { useState } from 'react'
import { supabase } from '../lib/supabase'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isSignUp, setIsSignUp] = useState(false)
  const [error, setError] = useState(null)
  const [message, setMessage] = useState(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError(null)
    setMessage(null)
    setLoading(true)

    if (isSignUp) {
      const { error } = await supabase.auth.signUp({ email, password })
      if (error) setError(error.message)
      else setMessage('Check your email to confirm your account!')
    } else {
      const { error } = await supabase.auth.signInWithPassword({ email, password })
      if (error) setError(error.message)
    }
    setLoading(false)
  }

  function toggle() {
    setIsSignUp(v => !v)
    setError(null)
    setMessage(null)
  }

  return (
    <div className="login-screen">
      <div className="login-hero">
        <h1 className="pixel-text game-title">Re:Fit</h1>
        <p className="pixel-text game-subtitle">Summoned to Sweat</p>
        <p className="body-text tagline">
          You have been summoned to another world.<br />
          Train. Level up. Build your party. Defeat the Demon Lord of Sloth.
        </p>
      </div>

      <div className="login-card">
        <h2 className="pixel-text card-title">{isSignUp ? 'CREATE ACCOUNT' : 'LOG IN'}</h2>
        {message && <p className="msg success">{message}</p>}
        {error && <p className="msg error">{error}</p>}
        <form onSubmit={handleSubmit}>
          <input
            className="rpg-input"
            type="email"
            placeholder="Email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
          />
          <input
            className="rpg-input"
            type="password"
            placeholder="Password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
          <button className="rpg-btn primary" type="submit" disabled={loading}>
            {loading ? 'LOADING...' : isSignUp ? 'BEGIN JOURNEY' : 'ENTER REALM'}
          </button>
        </form>
        <button className="rpg-btn ghost" type="button" onClick={toggle}>
          {isSignUp ? 'Already a hero? Log in' : 'New hero? Create account'}
        </button>
      </div>
    </div>
  )
}
