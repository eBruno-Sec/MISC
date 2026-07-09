import { useState, useEffect } from 'react'

export default function SummoningCircle({ companion, onComplete }) {
  const [phase, setPhase] = useState('spinning')
  const [imgLoaded, setImgLoaded] = useState(false)

  useEffect(() => {
    if (!imgLoaded) return
    const t1 = setTimeout(() => setPhase('revealing'), 200)
    const t2 = setTimeout(() => setPhase('done'), 1800)
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [imgLoaded])

  return (
    <div className="summoning-overlay">
      {phase === 'spinning' && (
        <div className="summoning-stage">
          <div className="runic-ring ring-outer" />
          <div className="runic-ring ring-middle" />
          <div className="runic-ring ring-inner" />
          <span className="pixel-text summoning-label">SUMMONING...</span>
          {/* Hidden preload — triggers onLoad so we know image is ready */}
          <img
            src={companion?.imageUrl}
            alt=""
            style={{ position: 'absolute', opacity: 0, pointerEvents: 'none', width: 1, height: 1 }}
            onLoad={() => setImgLoaded(true)}
            onError={() => setImgLoaded(true)}
          />
        </div>
      )}

      {(phase === 'revealing' || phase === 'done') && (
        <div className={`reveal-stage ${phase === 'revealing' ? 'flash-in' : ''}`}>
          <img
            src={companion?.imageUrl}
            alt={companion?.name}
            className="summoned-img"
          />
          <div className="reveal-info">
            <h2 className="pixel-text gold">{companion?.name}</h2>
            <p className="body-text">has answered your call!</p>
            <span className="affinity-badge large">{companion?.affinity}</span>
          </div>
          {phase === 'done' && (
            <button className="rpg-btn primary" onClick={onComplete}>
              WELCOME TO THE PARTY
            </button>
          )}
        </div>
      )}
    </div>
  )
}
