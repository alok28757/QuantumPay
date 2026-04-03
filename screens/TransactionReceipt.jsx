// QuantumPay — Transaction receipt overlay
import { useState } from 'react';
import { S } from '../constants/styles';
import { X, ArrowDownLeft, ArrowUpRight, Check, ShieldCheck, ChevronRight, Share2, ArrowDown } from 'lucide-react';

export default function TransactionReceipt({ selectedTx, setSelectedTx, linkedBanks }) {
  const [showPqcDetails, setShowPqcDetails] = useState(false);
  if (!selectedTx) return null;
  const isRx = selectedTx.type === "received";
  // Mock data for realism
  const bankRef = "BRN" + Math.floor(100000000 + Math.random() * 900000000);
  const txId = "QP" + (selectedTx.id?.toString() || Date.now().toString().slice(-8));

  return (
    <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", minHeight: "100%", boxSizing: "border-box", background: "#0a0a18", position: "relative" }}>

      {/* Main Receipt UI */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 30, opacity: showPqcDetails ? 0 : 1, transition: "opacity 0.3s" }}>
        <div onClick={() => setSelectedTx(null)} style={S.backBtn}><X size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Receipt</div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 30, opacity: showPqcDetails ? 0 : 1, transition: "opacity 0.3s" }}>
        <div style={{ width: 80, height: 80, borderRadius: 40, background: isRx ? "rgba(74,222,128,0.15)" : "rgba(244,63,94,0.15)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 16 }}>
          {isRx ? <ArrowDownLeft size={40} color="#4ade80" /> : <ArrowUpRight size={40} color="#f43f5e" />}
        </div>
        <div style={{ fontSize: 16, fontWeight: 700, color: "rgba(255,255,255,0.6)", marginBottom: 8 }}>{isRx ? "Received from" : "Paid to"}</div>
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 12 }}>{selectedTx.name}</div>
        <div style={{ fontSize: 40, fontWeight: 900, color: isRx ? "#4ade80" : "#f43f5e", marginBottom: 4 }}>
          {isRx ? "+" : "−"}₹{selectedTx.amount.toLocaleString("en-IN")}
        </div>
        <div style={{ fontSize: 14, color: isRx ? "#4ade80" : "#f43f5e", display: "flex", alignItems: "center", gap: 6, background: isRx ? "rgba(74,222,128,0.1)" : "rgba(244,63,94,0.1)", padding: "4px 12px", borderRadius: 12 }}>
          <Check size={16} color={isRx ? "#4ade80" : "#f43f5e"} /> {isRx ? "Received Successfully" : "Paid Successfully"}
        </div>
      </div>

      <div style={{ ...S.card, padding: 20, marginBottom: 20, opacity: showPqcDetails ? 0 : 1, transition: "opacity 0.3s" }}>
        <div style={{ fontSize: 14, fontWeight: 800, color: "#fff", marginBottom: 16 }}>Transaction Details</div>
        {[
          { label: "Date & Time", value: selectedTx.time || new Date().toLocaleString("en-IN", { day: "numeric", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit" }) },
          { label: "Transaction ID", value: txId },
          { label: "Bank Reference No.", value: bankRef },
          { label: "Payment Method", value: linkedBanks.length > 0 ? `${linkedBanks[0].bankName} UPI` : "QuantumPay Wallet" }
        ].map((row, i, arr) => (
          <div key={row.label} style={{ display: "flex", justifyContent: "space-between", padding: "12px 0", borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none" }}>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)" }}>{row.label}</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", textAlign: "right", maxWidth: "60%" }}>{row.value}</div>
          </div>
        ))}
      </div>

      <div style={{ flex: 1, opacity: showPqcDetails ? 0 : 1 }} />

      <div style={{ opacity: showPqcDetails ? 0 : 1, transition: "opacity 0.3s" }}>
        <div onClick={() => setShowPqcDetails(true)} style={{ textAlign: "center", padding: "14px", background: "rgba(16,185,129,0.1)", border: "1px solid rgba(16,185,129,0.3)", borderRadius: 16, marginBottom: 12, cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
          <ShieldCheck size={20} color="#10b981" />
          <span style={{ fontSize: 14, fontWeight: 800, color: "#10b981", letterSpacing: 0.5 }}>QUANTUM VALIDATED</span>
          <ChevronRight size={20} color="#10b981" />
        </div>

        <div onClick={() => alert("Mock: Receipt sharing opened")} style={{ ...S.gradBtn(false), background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.4)", color: "#a78bfa", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
          <Share2 size={18} color="#a78bfa" /> Share Receipt
        </div>
        <div style={{ textAlign: "center", marginTop: 24, paddingBottom: 20, fontSize: 12, color: "rgba(255,255,255,0.2)", fontWeight: 700, letterSpacing: 1 }}>POWERED BY QUANTUMPAY</div>
      </div>

      {/* PQC Overlay */}
      {showPqcDetails && (
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, background: "#050510", zIndex: 100, padding: 24, display: "flex", flexDirection: "column", overflowY: "auto", animation: "pulseCheck 0.3s ease-out" }}>
          <div onClick={() => setShowPqcDetails(false)} style={{ ...S.backBtn, alignSelf: "flex-start", marginBottom: 24 }}><ArrowDown size={20} color="#fff" /></div>

          <div style={{ fontSize: 28, fontWeight: 900, color: "#10b981", marginBottom: 8, letterSpacing: -1 }}>Signature Valid</div>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", marginBottom: 32, lineHeight: 1.5 }}>This transaction was signed and verified using Post-Quantum Cryptography algorithms resilient to quantum computer attacks.</div>

          <div style={{ display: "flex", flexDirection: "column", gap: 16, marginBottom: 32 }}>
            <div style={{ ...S.card, padding: 16, background: "rgba(16,185,129,0.05)", borderLeft: "4px solid #10b981" }}>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", fontWeight: 700, letterSpacing: 1, marginBottom: 4 }}>DIGITAL SIGNATURE ALGORITHM</div>
              <div style={{ fontSize: 16, fontWeight: 800, color: "#fff", fontFamily: "monospace" }}>Dilithium ML-DSA-65</div>
            </div>
            <div style={{ ...S.card, padding: 16, background: "rgba(139,92,246,0.05)", borderLeft: "4px solid #8b5cf6" }}>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", fontWeight: 700, letterSpacing: 1, marginBottom: 4 }}>KEY ENCAPSULATION</div>
              <div style={{ fontSize: 16, fontWeight: 800, color: "#fff", fontFamily: "monospace" }}>Kyber-1024 / ML-KEM</div>
            </div>
          </div>

          <div style={{ ...S.card, padding: 16, background: "#0a0a18", border: "1px solid rgba(255,255,255,0.05)" }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", fontWeight: 700, letterSpacing: 1, marginBottom: 12, display: "flex", justifyContent: "space-between" }}>
              <span>CRYPTOGRAPHIC PAYLOAD</span>
              <span style={{ color: "#10b981" }}>VERIFIED</span>
            </div>
            <div style={{ fontFamily: "monospace", fontSize: 11, color: "#8b5cf6", wordBreak: "break-all", lineHeight: 1.6, opacity: 0.8 }}>
              {Array(6).fill(0).map(() => Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)).join("")}...
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
