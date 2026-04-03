// QuantumPay — Register UPI ID screen
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import { S } from '../../constants/styles';
import { Zap, ArrowLeft, ArrowRight, AlertTriangle } from 'lucide-react';

export default function RegisterUpiScreen({ regUpi, regPhone, regName, regError, setRegUpi, setRegError, handleRegisterUpi, onBack }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}><ArrowLeft size={20} color="#fff" /></div>
        <StepBar step={3} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>Your UPI ID <Zap size={24} color="#8b5cf6" /></div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>This is how others can send you money</div>
        <div style={{ ...S.card, padding: 20, marginBottom: 14 }}>
          <div style={S.label}>UPI ID</div>
          <input value={regUpi} onChange={e => { setRegUpi(e.target.value.toLowerCase().replace(/\s/g, "")); setRegError(""); }} placeholder="yourname@qpay" style={{ ...S.input, marginBottom: 10 }} />
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>Must end with @qpay</div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
          {[regName.toLowerCase().replace(/\s+/g, "").slice(0, 8), regName.toLowerCase().split(" ")[0], regPhone.slice(-4) + "pay"].filter(Boolean).map(s => (
            <div key={s} onClick={() => setRegUpi(s + "@qpay")} style={{ background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 20, padding: "6px 14px", fontSize: 12, color: "#a78bfa", cursor: "pointer" }}>{s}@qpay</div>
          ))}
        </div>
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}><AlertTriangle size={14} color="#f43f5e" /> {regError}</div>}
        <div onClick={handleRegisterUpi} style={{ ...S.gradBtn(!regUpi.includes("@")), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Continue <ArrowRight size={18} color="#fff" /></div>
      </div>
    </PhoneFrame>
  );
}
