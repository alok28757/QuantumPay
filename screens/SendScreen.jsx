// QuantumPay — Send money screen
import { S } from '../constants/styles';
import { ArrowLeft, ArrowRight, Search, X, User, ChevronRight, Smartphone, Landmark, Check, Delete } from 'lucide-react';

export default function SendScreen({
  sendStep, setSendStep, selectedContact, setSelectedContact,
  amount, setAmount, note, setNote, pin, setPin,
  upiSearch, setUpiSearch, contacts,
  balance, goBack, handleSend, setAddMoneyStep, setScreen,
}) {
  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={() => sendStep > 1 ? setSendStep(s => s - 1) : goBack()} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Send Money</div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 5 }}>
          {[1, 2, 3].map(s => <div key={s} style={{ width: s <= sendStep ? 20 : 8, height: 6, borderRadius: 3, background: s <= sendStep ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.12)", transition: "all 0.3s" }} />)}
        </div>
      </div>
      {sendStep === 1 && <>
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 14, padding: "10px 16px", display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <Search size={16} color="rgba(255,255,255,0.4)" />
          <input value={upiSearch} onChange={e => setUpiSearch(e.target.value)} placeholder="Search name or enter UPI ID..." style={{ background: "none", border: "none", outline: "none", color: "#fff", fontSize: 14, flex: 1 }} />
          {upiSearch && <X onClick={() => setUpiSearch("")} size={18} color="rgba(255,255,255,0.4)" style={{ cursor: "pointer" }} />}
        </div>
        {upiSearch && upiSearch.includes("@") && (
          <div onClick={() => { setSelectedContact({ name: upiSearch, upi: upiSearch, color: "#8b5cf6" }); setSendStep(2); setUpiSearch(""); }} style={{ ...S.card, padding: "14px 16px", marginBottom: 14, display: "flex", alignItems: "center", gap: 12, cursor: "pointer", border: "1px solid rgba(139,92,246,0.4)" }}>
            <div style={{ width: 40, height: 40, borderRadius: 20, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", display: "flex", alignItems: "center", justifyContent: "center" }}><User size={20} color="#fff" /></div>
            <div>
              <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 2 }}>Send to UPI ID</div>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#fff" }}>{upiSearch}</div>
            </div>
            <div style={{ marginLeft: "auto", color: "#8b5cf6", display: "flex", alignItems: "center" }}><ChevronRight size={20} /></div>
          </div>
        )}
        <div style={S.label}>CONTACTS</div>
        {contacts.length === 0 && !upiSearch ? (
          <div style={{ padding: "40px 20px", textAlign: "center" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 16 }}><Smartphone size={40} color="rgba(255,255,255,0.2)" /></div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 8 }}>Search to Pay</div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", lineHeight: 1.5 }}>Find anyone on QuantumPay by searching their name or UPI ID above.</div>
          </div>
        ) : contacts.filter(c => !upiSearch || c.name.toLowerCase().includes(upiSearch.toLowerCase()) || c.upi.includes(upiSearch.toLowerCase())).length === 0 ? (
          <div style={{ padding: "30px 20px", textAlign: "center", fontSize: 13, color: "rgba(255,255,255,0.4)" }}>No contacts found matching "{upiSearch}"</div>
        ) : (
          contacts.filter(c => !upiSearch || c.name.toLowerCase().includes(upiSearch.toLowerCase()) || c.upi.includes(upiSearch.toLowerCase())).map(c => (
            <div key={c.id} onClick={() => { setSelectedContact(c); setSendStep(2); setUpiSearch(""); }} style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 0", borderBottom: "1px solid rgba(255,255,255,0.05)", cursor: "pointer" }}>
              <div style={{ width: 46, height: 46, borderRadius: 23, background: `${c.color}20`, border: `1px solid ${c.color}40`, display: "flex", alignItems: "center", justifyContent: "center", color: c.color }}><User size={22} /></div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{c.name}</div>
                <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{c.upi}</div>
              </div>
              <div style={{ color: "rgba(255,255,255,0.2)", display: "flex", alignItems: "center" }}><ChevronRight size={20} /></div>
            </div>
          ))
        )}
      </>}
      {sendStep === 2 && selectedContact && <>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ width: 70, height: 70, borderRadius: 35, background: `${selectedContact.color}20`, border: `2px solid ${selectedContact.color}50`, display: "flex", alignItems: "center", justifyContent: "center", color: selectedContact.color, margin: "0 auto 10px" }}><User size={34} /></div>
          <div style={{ fontSize: 18, fontWeight: 800, color: "#fff" }}>{selectedContact.name}</div>
          <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{selectedContact.upi}</div>
        </div>
        <div style={{ ...S.card, padding: "22px", textAlign: "center", marginBottom: 14 }}>
          <div style={S.label}>ENTER AMOUNT</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, marginTop: 8 }}>
            <span style={{ fontSize: 30, fontWeight: 900, color: "rgba(255,255,255,0.3)" }}>₹</span>
            <input value={amount} onChange={e => setAmount(e.target.value.replace(/\D/g, ""))} type="number" placeholder="0"
              style={{ background: "none", border: "none", outline: "none", color: "#fff", fontSize: 44, fontWeight: 900, width: 160, textAlign: "center" }} />
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 14 }}>
          {[100, 200, 500, 1000].map(q => (
            <div key={q} onClick={() => setAmount(String(q))} style={{ flex: 1, background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 10, padding: "8px 0", textAlign: "center", fontSize: 13, fontWeight: 700, color: "#8b5cf6", cursor: "pointer" }}>₹{q}</div>
          ))}
        </div>
        <input value={note} onChange={e => setNote(e.target.value)} placeholder="Add a note (optional)" style={{ ...S.input, marginBottom: 18 }} />
        {Number(amount) > balance ? (
          <div onClick={() => { setAddMoneyStep(1); setScreen("addmoney"); }} style={S.gradBtn(false)}>Insufficient Balance - Add Money</div>
        ) : (
          <>
            <div style={{ ...S.card, padding: "12px 16px", marginBottom: 18, display: "flex", alignItems: "center", gap: 12 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "rgba(139,92,246,0.15)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Smartphone size={16} color="#8b5cf6" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", marginBottom: 2 }}>Paying from</div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>QuantumPay Wallet (₹{balance.toLocaleString("en-IN", { minimumFractionDigits: 2 })})</div>
              </div>
            </div>
            <div onClick={() => amount && Number(amount) > 0 && setSendStep(3)} style={{ ...S.gradBtn(!amount || Number(amount) <= 0), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Continue <ArrowRight size={18} color="#fff" /></div>
          </>
        )}
      </>}
      {sendStep === 3 && selectedContact && <>
        <div style={{ ...S.card, padding: 20, marginBottom: 18 }}>
          <div style={S.label}>CONFIRM PAYMENT</div>
          {[["To", selectedContact.name], ["UPI ID", selectedContact.upi], ["Amount", `₹${Number(amount).toLocaleString("en-IN")} `], ["Note", note || "—"]].map(([k, v]) => (
            <div key={k} style={{ display: "flex", justifyContent: "space-between", marginTop: 12 }}>
              <span style={{ color: "rgba(255,255,255,0.35)", fontSize: 13 }}>{k}</span>
              <span style={{ color: "#fff", fontWeight: 700, fontSize: 13 }}>{v}</span>
            </div>
          ))}
        </div>
        <div style={S.label}>ENTER UPI PIN</div>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", margin: "12px 0 16px" }}>
          {[0, 1, 2, 3].map(i => (
            <div key={i} style={{ width: 44, height: 44, borderRadius: 22, background: i < pin.length ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.1)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, color: "#fff" }}>
              {i < pin.length ? "●" : ""}
            </div>
          ))}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8 }}>
          {["1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫", "0", "✓"].map(k => (
            <div key={k} onClick={() => {
              if (k === "⌫") setPin(p => p.slice(0, -1));
              else if (k === "✓") { if (pin.length === 4) handleSend(); }
              else if (pin.length < 4) setPin(p => p + k);
            }} style={{ height: 52, borderRadius: 14, background: k === "✓" ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, fontWeight: 700, color: "#fff", cursor: "pointer", border: "1px solid rgba(255,255,255,0.06)" }}>
              {k === "⌫" ? <Delete size={20} color="#fff" /> : k === "✓" ? <Check size={20} color="#fff" /> : k}
            </div>
          ))}
        </div>
      </>}
      {sendStep === 4 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", paddingTop: 50 }}>
          <div style={{ width: 90, height: 90, borderRadius: 45, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 22, boxShadow: "0 0 40px rgba(16,185,129,0.3)", animation: "pulseCheck 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275) both" }}><Check size={44} color="#fff" /></div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 8 }}>Payment Sent!</div>
          <div style={{ fontSize: 34, fontWeight: 900, color: "#4ade80", marginBottom: 8 }}>₹{Number(amount).toLocaleString("en-IN")}</div>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", marginBottom: 30 }}>to {selectedContact?.name}</div>
          <div style={{ ...S.card, padding: "14px 28px", marginBottom: 24, textAlign: "center" }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>Transaction ID</div>
            <div style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700 }}>QP{Date.now().toString().slice(-10)}</div>
          </div>
          <div onClick={() => { setSelectedContact(null); setAmount(""); setNote(""); setPin(""); setSendStep(1); setScreen("home"); }} style={S.gradBtn(false)}>Back to Home</div>
        </div>
      )}
    </div>
  );
}
