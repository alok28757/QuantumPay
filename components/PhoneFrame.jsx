// QuantumPay — App container (production-ready fullscreen)
export default function PhoneFrame({ children, bg }) {
  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", background: "#050510", fontFamily: "'Segoe UI', sans-serif" }}>
      <style>{`
        @keyframes pulseCheck {
          0% { transform: scale(0.8); opacity: 0; box-shadow: 0 0 0 rgba(16,185,129,0); }
          70% { transform: scale(1.15); opacity: 1; box-shadow: 0 0 60px rgba(16,185,129,0.6); }
          100% { transform: scale(1); opacity: 1; box-shadow: 0 0 40px rgba(16,185,129,0.4); }
        }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
      <div style={{ width: "100%", maxWidth: 480, minHeight: "100vh", background: bg || "#0d0d1f", overflow: "hidden", display: "flex", flexDirection: "column" }}>
        {children}
      </div>
    </div>
  );
}
