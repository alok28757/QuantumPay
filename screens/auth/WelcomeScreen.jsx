// QuantumPay — Welcome screen (post-registration/login)
import PhoneFrame from '../../components/PhoneFrame';

export default function WelcomeScreen({ upiId }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16 }}>
        <div style={{ width: 96, height: 96, borderRadius: 48, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 48, boxShadow: "0 0 40px rgba(16,185,129,0.4)" }}>✓</div>
        <div style={{ fontSize: 26, fontWeight: 900, color: "#fff" }}>You're In! 🎉</div>
        <div style={{ fontSize: 14, color: "rgba(255,255,255,0.35)" }}>Welcome to QuantumPay</div>
        <div style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700 }}>{upiId}</div>
      </div>
    </PhoneFrame>
  );
}
