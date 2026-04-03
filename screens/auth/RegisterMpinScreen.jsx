// QuantumPay — Set MPIN screen
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import PinPad from '../../components/PinPad';
import { S } from '../../constants/styles';

export default function RegisterMpinScreen({ regMpin, regError, handleSetMpin, onBack }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={4} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Set your MPIN 🔐</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 28 }}>4-digit PIN to secure your account. Don't share with anyone.</div>
        <PinPad value={regMpin} onChange={handleSetMpin} />
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginTop: 16, textAlign: "center" }}>⚠️ {regError}</div>}
      </div>
    </PhoneFrame>
  );
}
