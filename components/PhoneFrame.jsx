// QuantumPay — App container (production-ready fullscreen)
export default function PhoneFrame({ children, bg }) {
  return (
    <>
      <style>{`
        html, body, #root, #__next {
          margin: 0;
          padding: 0;
          height: 100%;
          width: 100%;
          overflow: hidden;
        }
        .phone-out {
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          height: 100dvh;
          background: #050510;
          font-family: 'Segoe UI', sans-serif;
        }
        .phone-in {
          width: 100%;
          max-width: 480px;
          height: 100%;
          background: ${bg || "#0d0d1f"};
          overflow: hidden;
          display: flex;
          flex-direction: column;
        }
        @keyframes pulseCheck {
          0% { transform: scale(0.8); opacity: 0; box-shadow: 0 0 0 rgba(16,185,129,0); }
          70% { transform: scale(1.15); opacity: 1; box-shadow: 0 0 60px rgba(16,185,129,0.6); }
          100% { transform: scale(1); opacity: 1; box-shadow: 0 0 40px rgba(16,185,129,0.4); }
        }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
      <div className="phone-out">
        <div className="phone-in">
          {children}
        </div>
      </div>
    </>
  );
}
