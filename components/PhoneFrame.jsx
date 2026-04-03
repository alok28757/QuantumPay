// QuantumPay — Phone frame wrapper component
export default function PhoneFrame({ children, bg }) {
  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", background: "#050510", padding: 20, fontFamily: "'Segoe UI', sans-serif" }}>
      <style>{`
        @keyframes pulseCheck {
          0% { transform: scale(0.8); opacity: 0; box-shadow: 0 0 0 rgba(16,185,129,0); }
          70% { transform: scale(1.15); opacity: 1; box-shadow: 0 0 60px rgba(16,185,129,0.6); }
          100% { transform: scale(1); opacity: 1; box-shadow: 0 0 40px rgba(16,185,129,0.4); }
        }
      `}</style>
      <div style={{ width: 390, height: 800, background: bg || "#0d0d1f", borderRadius: 44, overflow: "hidden", display: "flex", flexDirection: "column", boxShadow: "0 40px 100px rgba(139,92,246,0.25), 0 0 0 1px rgba(255,255,255,0.08)" }}>
        {children}
      </div>
    </div>
  );
}
