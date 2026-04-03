// QuantumPay — Login screen
import PhoneFrame from '../../components/PhoneFrame';
import PinPad from '../../components/PinPad';
import { S } from '../../constants/styles';
import { Atom, AlertTriangle, ArrowRight } from 'lucide-react';

export default function LoginScreen({ loginPhone, loginMpin, loginError, setLoginPhone, setLoginError, handleLoginMpin, onRegister }) {
  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "50px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div style={{ marginBottom: 32 }}>
          <div style={{ fontSize: 11, color: "#8b5cf6", fontWeight: 700, letterSpacing: 2, marginBottom: 10, display: "flex", alignItems: "center", gap: 6 }}><Atom size={14} color="#8b5cf6" /> QUANTUMPAY</div>
          <div style={{ fontSize: 28, fontWeight: 900, color: "#fff", lineHeight: 1.2 }}>Welcome Back</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.35)", marginTop: 8 }}>Enter your phone number and MPIN</div>
        </div>

        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>PHONE NUMBER</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 10, padding: "14px 10px", color: "#8b5cf6", fontWeight: 700, fontSize: 13, flexShrink: 0 }}>+91</div>
            <input value={loginPhone} onChange={e => { setLoginPhone(e.target.value.replace(/\D/g, "").slice(0, 10)); setLoginError(""); }} placeholder="10-digit mobile number" type="tel" style={{ ...S.input }} />
          </div>
        </div>

        {loginPhone.length === 10 && (
          <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
            <div style={S.label}>4-DIGIT MPIN</div>
            <PinPad value={loginMpin} onChange={handleLoginMpin} />
          </div>
        )}

        {loginError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}><AlertTriangle size={14} color="#f43f5e" /> {loginError}</div>}

        <div style={{ marginTop: "auto", textAlign: "center" }}>
          <span style={{ fontSize: 13, color: "rgba(255,255,255,0.35)" }}>New to QuantumPay? </span>
          <span onClick={onRegister} style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700, cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4 }}>Create Account <ArrowRight size={13} color="#8b5cf6" /></span>
        </div>
      </div>
    </PhoneFrame>
  );
}
