// QuantumPay — Request money screen
import { useState } from 'react';
import { S } from '../constants/styles';
import { ArrowLeft } from 'lucide-react';

export default function RequestScreen({ upiId, user, profile, goBack }) {
  const [reqStep, setReqStep] = useState(1);
  const [reqAmount, setReqAmount] = useState("");
  const [reqNote, setReqNote] = useState("");

  let qrUrl = "";
  if (reqStep === 2) {
    const qrData = `upi://pay?pa=${upiId}&pn=${encodeURIComponent(user?.name || profile?.name || "User")}&am=${reqAmount}&cu=INR&tn=${encodeURIComponent(reqNote)}`;
    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(qrData)}&bgcolor=151525&color=4ade80&qzone=2`;
  }

  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={() => {
          if (reqStep === 2) setReqStep(1);
          else { setReqAmount(""); setReqNote(""); goBack(); }
        }} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Request Money</div>
      </div>

      {reqStep === 1 && (
        <div style={{ paddingTop: 20 }}>
          <div style={{ textAlign: "center", marginBottom: 30 }}>
            <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", marginBottom: 12 }}>How much are you requesting?</div>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "baseline", gap: 4 }}>
              <span style={{ fontSize: 28, color: "rgba(255,255,255,0.3)", fontWeight: 800 }}>₹</span>
              <input
                autoFocus
                type="number"
                placeholder="0"
                value={reqAmount}
                onChange={e => setReqAmount(e.target.value)}
                style={{ background: "transparent", border: "none", color: "#fff", fontSize: 56, fontWeight: 900, outline: "none", width: reqAmount.length > 0 ? `${reqAmount.length + 0.5}ch` : "2ch", textAlign: "center" }}
              />
            </div>
          </div>

          <div style={S.label}>WHAT'S IT FOR? (OPTIONAL)</div>
          <input
            value={reqNote}
            onChange={e => setReqNote(e.target.value)}
            placeholder="e.g. Dinner split"
            style={{ ...S.input, marginBottom: 30 }}
          />

          <div onClick={() => Number(reqAmount) > 0 && setReqStep(2)} style={S.gradBtn(Number(reqAmount) <= 0)}>Generate QR Code</div>
        </div>
      )}

      {reqStep === 2 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 10 }}>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", marginBottom: 8 }}>Requesting</div>
          <div style={{ fontSize: 36, fontWeight: 900, color: "#4ade80", marginBottom: 8 }}>₹{Number(reqAmount).toLocaleString("en-IN")}</div>
          {reqNote && <div style={{ fontSize: 14, color: "#fff", background: "rgba(255,255,255,0.1)", padding: "4px 12px", borderRadius: 12, marginBottom: 24 }}>"{reqNote}"</div>}

          <div style={{ padding: 12, marginBottom: 24, background: "#151525", borderRadius: 16, display: "inline-block", border: "1px solid rgba(16,185,129,0.3)" }}>
            <img src={qrUrl} alt="UPI QR" style={{ width: 220, height: 220, borderRadius: 8, display: "block" }} />
          </div>

          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", textAlign: "center", marginBottom: 30 }}>
            Scan this QR code with any UPI app<br />to pay {user?.name || profile?.name || "User"}
          </div>

          <div style={{ display: "flex", gap: 12, width: "100%" }}>
            <div onClick={() => alert("Mock: Request Link Copied!")} style={{ ...S.gradBtn(false), flex: 1, background: "rgba(255,255,255,0.08)", color: "#fff" }}>Copy Link</div>
            <div onClick={() => alert("Mock: Share Intent Opened")} style={{ ...S.gradBtn(false), flex: 1 }}>Share QR</div>
          </div>
        </div>
      )}
    </div>
  );
}
