// QuantumPay — Register profile screen
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import { S } from '../../constants/styles';

export default function RegisterProfileScreen({ regName, regDob, regError, setRegName, setRegDob, setRegError, handleRegisterProfile, onBack }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={2} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Tell us about you 👤</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>Used for your profile and UPI ID</div>
        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>FULL NAME</div>
          <input value={regName} onChange={e => { setRegName(e.target.value); setRegError(""); }} placeholder="e.g. Alok Sharma" style={{ ...S.input, marginBottom: 16 }} />
          <div style={S.label}>DATE OF BIRTH</div>
          <input value={regDob} onChange={e => setRegDob(e.target.value)} type="date" max={new Date().toISOString().split("T")[0]} style={{ ...S.input, colorScheme: "dark" }} />
        </div>
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16 }}>⚠️ {regError}</div>}
        <div onClick={handleRegisterProfile} style={S.gradBtn(!regName.trim() || !regDob)}>Continue →</div>
      </div>
    </PhoneFrame>
  );
}
