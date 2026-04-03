// QuantumPay — Register phone screen
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import { S } from '../../constants/styles';
import { Smartphone, ArrowLeft, ArrowRight, AlertTriangle } from 'lucide-react';

export default function RegisterPhoneScreen({ regPhone, regError, setRegPhone, setRegError, handleRegisterPhone, onBack }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}><ArrowLeft size={20} color="#fff" /></div>
        <StepBar step={1} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>Your phone number <Smartphone size={24} color="#8b5cf6" /></div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>This will be your login identifier</div>
        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>MOBILE NUMBER</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 10, padding: "14px 10px", color: "#8b5cf6", fontWeight: 700, fontSize: 13, flexShrink: 0 }}>+91</div>
            <input value={regPhone} onChange={e => { setRegPhone(e.target.value.replace(/\D/g, "").slice(0, 10)); setRegError(""); }} placeholder="10-digit mobile number" type="tel" style={{ ...S.input }} />
          </div>
        </div>
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}><AlertTriangle size={14} color="#f43f5e" /> {regError}</div>}
        <div onClick={handleRegisterPhone} style={{ ...S.gradBtn(regPhone.length !== 10), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Continue <ArrowRight size={18} color="#fff" /></div>
      </div>
    </PhoneFrame>
  );
}
