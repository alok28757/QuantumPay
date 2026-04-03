// QuantumPay — Set MPIN screen
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import PinPad from '../../components/PinPad';
import { S } from '../../constants/styles';
import { Lock, ArrowLeft, AlertTriangle } from 'lucide-react';

export default function RegisterMpinScreen({ regMpin, regError, handleSetMpin, onBack }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}><ArrowLeft size={20} color="#fff" /></div>
        <StepBar step={4} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>Set your MPIN <Lock size={24} color="#8b5cf6" /></div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 28 }}>4-digit PIN to secure your account. Don't share with anyone.</div>
        <PinPad value={regMpin} onChange={handleSetMpin} />
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginTop: 16, display: "flex", alignItems: "center", gap: 6, justifyContent: "center" }}><AlertTriangle size={14} color="#f43f5e" /> {regError}</div>}
      </div>
    </PhoneFrame>
  );
}
