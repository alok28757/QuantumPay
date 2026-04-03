// QuantumPay — Add money screen
import { S } from '../constants/styles';
import { ArrowLeft, ArrowRight, Landmark, CreditCard, Smartphone, ChevronRight, Check } from 'lucide-react';

export default function AddMoneyScreen({
  addMoneyStep, setAddMoneyStep, addAmount, setAddAmount,
  balance, linkedBanks, goBack, handleAddMoney, setScreen,
}) {
  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={() => addMoneyStep > 1 ? setAddMoneyStep(s => s - 1) : goBack()} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Add Money</div>
      </div>
      {addMoneyStep === 1 && <>
        <div style={{ ...S.card, padding: 24, textAlign: "center", marginBottom: 18 }}>
          <div style={S.label}>ENTER AMOUNT</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, marginTop: 8 }}>
            <span style={{ fontSize: 30, fontWeight: 900, color: "rgba(255,255,255,0.3)" }}>₹</span>
            <input value={addAmount} onChange={e => setAddAmount(e.target.value.replace(/\D/g, ""))} type="number" placeholder="0"
              style={{ background: "none", border: "none", outline: "none", color: "#fff", fontSize: 44, fontWeight: 900, width: 160, textAlign: "center" }} />
          </div>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 20 }}>
          {[500, 1000, 2000, 5000, 10000].map(q => (
            <div key={q} onClick={() => setAddAmount(String(q))} style={{ background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 12, padding: "8px 16px", fontSize: 13, fontWeight: 700, color: "#8b5cf6", cursor: "pointer" }}>₹{q.toLocaleString("en-IN")}</div>
          ))}
        </div>
        {addAmount && <div style={{ ...S.card, padding: 14, marginBottom: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 13 }}>After Adding</span>
            <span style={{ color: "#4ade80", fontWeight: 800 }}>₹{(balance + Number(addAmount)).toLocaleString("en-IN", { minimumFractionDigits: 2 })}</span>
          </div>
        </div>}
        <div onClick={() => addAmount && setAddMoneyStep(2)} style={{ ...S.gradBtn(!addAmount), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Choose Payment Method <ArrowRight size={18} color="#fff" /></div>
      </>}
      {addMoneyStep === 2 && <>
        <div style={{ ...S.card, padding: 14, marginBottom: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 13 }}>Adding</span>
            <span style={{ color: "#4ade80", fontWeight: 900, fontSize: 16 }}>₹{Number(addAmount).toLocaleString("en-IN")}</span>
          </div>
        </div>
        <div style={S.label}>SELECT PAYMENT METHOD</div>
        {linkedBanks.length > 0 && (
          <div onClick={() => { setAddMoneyStep(3); handleAddMoney(); }} style={{ ...S.card, padding: 16, marginTop: 12, marginBottom: 16, display: "flex", alignItems: "center", gap: 14, cursor: "pointer", border: "1px solid rgba(16,185,129,0.4)" }}>
            <div style={{ width: 46, height: 46, borderRadius: 14, background: "rgba(16,185,129,0.15)", border: "1px solid rgba(16,185,129,0.3)", display: "flex", alignItems: "center", justifyContent: "center" }}><Landmark size={22} color="#10b981" /></div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{linkedBanks[0].bankName}</div>
              <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{linkedBanks[0].type} • {linkedBanks[0].accountNumber}</div>
            </div>
            <div style={{ color: "#10b981", fontSize: 12, fontWeight: 700 }}>Primary</div>
          </div>
        )}
        {[
          { icon: Landmark, label: "Net Banking", sub: "HDFC, ICICI, SBI & more", color: "#06b6d4" },
          { icon: CreditCard, label: "Debit / Credit Card", sub: "Visa, Mastercard, RuPay", color: "#8b5cf6" },
          { icon: Smartphone, label: "UPI Transfer", sub: "Pay via any UPI app", color: "#10b981" },
        ].map(m => (
          <div key={m.label} onClick={handleAddMoney} style={{ ...S.card, padding: 16, marginTop: 12, display: "flex", alignItems: "center", gap: 14, cursor: "pointer" }}>
            <div style={{ width: 46, height: 46, borderRadius: 14, background: `${m.color}18`, border: `1px solid ${m.color}30`, display: "flex", alignItems: "center", justifyContent: "center", color: m.color }}><m.icon size={22} /></div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{m.label}</div>
              <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{m.sub}</div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.2)", display: "flex", alignItems: "center" }}><ChevronRight size={20} /></div>
          </div>
        ))}
      </>}
      {addMoneyStep === 3 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", paddingTop: 50 }}>
          <div style={{ width: 90, height: 90, borderRadius: 45, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 22, boxShadow: "0 0 40px rgba(16,185,129,0.3)", animation: "pulseCheck 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275) both" }}><Check size={44} color="#fff" /></div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 8 }}>Money Added!</div>
          <div style={{ fontSize: 34, fontWeight: 900, color: "#4ade80", marginBottom: 32 }}>₹{Number(addAmount).toLocaleString("en-IN")}</div>
          <div onClick={() => { setAddAmount(""); setAddMoneyStep(1); setScreen("home"); }} style={S.gradBtn(false)}>Back to Home</div>
        </div>
      )}
    </div>
  );
}
