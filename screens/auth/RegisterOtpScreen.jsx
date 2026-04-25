// QuantumPay — Register OTP Verification screen
import { useState, useEffect } from 'react';
import PhoneFrame from '../../components/PhoneFrame';
import StepBar from '../../components/StepBar';
import PinPad from '../../components/PinPad';
import { S } from '../../constants/styles';
import { ShieldCheck, ArrowLeft, ArrowRight, AlertTriangle } from 'lucide-react';
import { setupRecaptcha, sendSignInOTP } from '../../lib/firebase';

export default function RegisterOtpScreen({ phone, regError, setRegError, handleVerifyOtp, onBack }) {
  const [otp, setOtp] = useState("");
  const [isSending, setIsSending] = useState(true);

  useEffect(() => {
    let mounted = true;
    const sendOTP = async () => {
      try {
        const verifier = setupRecaptcha("recaptcha-container");
        const res = await sendSignInOTP(phone, verifier);
        if (!mounted) return;
        if (res.error) {
          setRegError(res.error.message || "Failed to send OTP code.");
        } else {
          // Temporarily attach confirmationResult to window so index.jsx can verify it
          window.confirmationResult = res.data;
        }
      } catch (err) {
        if (mounted) setRegError("Error initializing Recaptcha");
      } finally {
        if (mounted) setIsSending(false);
      }
    };
    sendOTP();
    return () => { mounted = false; };
  }, [phone]);

  const onChangeOtp = (updatedOtp) => {
    setOtp(updatedOtp);
    setRegError("");
  };

  return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={onBack} style={{ ...S.backBtn, marginBottom: 24 }}><ArrowLeft size={20} color="#fff" /></div>
        <StepBar step={2} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
          Verify OTP <ShieldCheck size={24} color="#10b981" />
        </div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24, lineHeight: 1.4 }}>
          Enter the 6-digit code sent via SMS to <br/><strong style={{ color: "#fff" }}>+91 {phone}</strong>
        </div>

        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>{isSending ? "SENDING OTP..." : "6-DIGIT OTP"}</div>
          <div style={{ display: "flex", justifyContent: "center", gap: 8, marginBottom: 10 }}>
            {[...Array(6)].map((_, i) => (
              <div key={i} style={{ width: 14, height: 14, borderRadius: 7, background: otp.length > i ? "#10b981" : "rgba(255,255,255,0.1)", transition: "all 0.2s" }} />
            ))}
          </div>
          <PinPad value={otp} onChange={onChangeOtp} maxLength={6} secure={false} />
        </div>

        {regError && (
          <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}>
            <AlertTriangle size={14} color="#f43f5e" /> {regError}
          </div>
        )}

        {/* Essential invisible container for Firebase Recaptcha */}
        <div id="recaptcha-container"></div>

        <div onClick={() => otp.length === 6 && handleVerifyOtp(otp)} style={{ ...S.gradBtn(otp.length !== 6 || isSending), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
          Verify & Continue <ArrowRight size={18} color="#fff" />
        </div>
      </div>
    </PhoneFrame>
  );
}
