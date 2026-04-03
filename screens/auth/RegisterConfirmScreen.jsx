// QuantumPay — Confirm MPIN screen
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import PinPad from '../../components/PinPad';
import { S } from '../../constants/styles';

export default function RegisterConfirmScreen({ regMpinConfirm, regError, handleConfirmMpin, onBack }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={4} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Confirm MPIN 🔐</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 28 }}>Re-enter your 4-digit MPIN to confirm</div>
        <PinPad value={regMpinConfirm} onChange={handleConfirmMpin} />
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginTop: 16, textAlign: "center" }}>⚠️ {regError}</div>}
      </div>
    </PhoneFrame>
  );
}
