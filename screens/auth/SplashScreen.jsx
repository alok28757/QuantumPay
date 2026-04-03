// QuantumPay — Splash screen
import PhoneFrame from '../../components/PhoneFrame';
import { S } from '../../constants/styles';
import { Atom, ArrowRight } from 'lucide-react';

export default function SplashScreen({ onGetStarted }) {
  return (
    <PhoneFrame bg="linear-gradient(160deg,#1a0533 0%,#0d0d1f 100%)">
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: "10%", width: 280, height: 280, borderRadius: "50%", background: "radial-gradient(circle, rgba(139,92,246,0.3) 0%, transparent 70%)" }} />
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 12, filter: "drop-shadow(0 0 30px rgba(139,92,246,0.5))" }}><Atom size={72} color="#8b5cf6" /></div>
        <div style={{ fontSize: 30, fontWeight: 900, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", letterSpacing: 4 }}>QUANTUMPAY</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.3)", marginTop: 8, letterSpacing: 2 }}>FAST · SECURE · SIMPLE</div>
        <div style={{ position: "absolute", bottom: 60, width: "80%" }}>
          <div onClick={onGetStarted} style={{ ...S.gradBtn(false), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Get Started <ArrowRight size={18} color="#fff" /></div>
        </div>
      </div>
    </PhoneFrame>
  );
}
