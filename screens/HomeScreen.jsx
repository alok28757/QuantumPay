// QuantumPay — Home screen
import { BILLS } from '../constants/data';
import { S } from '../constants/styles';
import TxRow from '../components/TxRow';

export default function HomeScreen({
  userName, userInitial, balance, balanceVisible, setBalanceVisible,
  transactions, contacts, setSelectedTx, navigate,
  setAddMoneyStep, setSendStep,
}) {
  return (
    <div style={{ paddingBottom: 20 }}>
      <div style={{ background: "linear-gradient(160deg,#1a0533 0%,#0d0d1f 65%)", padding: "18px 20px 30px", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: -60, right: -60, width: 220, height: 220, borderRadius: "50%", background: "radial-gradient(circle,rgba(139,92,246,0.2) 0%,transparent 70%)" }} />
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
          <div>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", letterSpacing: 1 }}>WELCOME BACK</div>
            <div style={{ fontSize: 20, fontWeight: 900, color: "#fff" }}>{userName}</div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ width: 38, height: 38, borderRadius: 19, background: "rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, cursor: "pointer" }}>🔔</div>
            <div onClick={() => navigate("profile")} style={{ width: 38, height: 38, borderRadius: 19, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, fontWeight: 900, color: "#fff", cursor: "pointer", letterSpacing: 0 }} title="Profile">{userInitial}</div>
          </div>
        </div>

        <div style={{ ...S.card, padding: "18px 22px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", letterSpacing: 1, marginBottom: 4 }}>TOTAL BALANCE</div>
              <div style={{ fontSize: 30, fontWeight: 900, color: "#fff", letterSpacing: -1 }}>
                {balanceVisible ? `₹${balance.toLocaleString("en-IN", { minimumFractionDigits: 2 })} ` : "₹ ••••••"}
              </div>
            </div>
            <div onClick={() => setBalanceVisible(v => !v)} style={{ fontSize: 20, cursor: "pointer", marginTop: 4 }}>{balanceVisible ? "👁" : "🙈"}</div>
          </div>
          <div style={{ marginTop: 14, display: "flex", gap: 10 }}>
            <div style={{ flex: 1, background: "rgba(74,222,128,0.1)", borderRadius: 10, padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: "#4ade80", fontWeight: 700 }}>↓ RECEIVED</div>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#fff", marginTop: 2 }}>₹{transactions.filter(t => t.type === "received").reduce((s, t) => s + t.amount, 0).toLocaleString("en-IN")}</div>
            </div>
            <div style={{ flex: 1, background: "rgba(244,63,94,0.1)", borderRadius: 10, padding: "10px 12px" }}>
              <div style={{ fontSize: 9, color: "#f43f5e", fontWeight: 700 }}>↑ SENT</div>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#fff", marginTop: 2 }}>₹{transactions.filter(t => t.type === "sent").reduce((s, t) => s + t.amount, 0).toLocaleString("en-IN")}</div>
            </div>
            <div onClick={() => { setAddMoneyStep(1); navigate("addmoney"); }} style={{ flex: 1, background: "rgba(139,92,246,0.15)", borderRadius: 10, padding: "10px 12px", cursor: "pointer", border: "1px solid rgba(139,92,246,0.3)" }}>
              <div style={{ fontSize: 9, color: "#a78bfa", fontWeight: 700 }}>+ ADD</div>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#fff", marginTop: 2 }}>Money</div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ padding: "18px 20px 4px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
          {[
            { icon: "↑", label: "Send", color: "#8b5cf6", bg: "rgba(139,92,246,0.4)", action: () => { setSendStep(1); navigate("send"); } },
            { icon: "↓", label: "Request", color: "#06b6d4", bg: "rgba(6,182,212,0.4)", action: () => navigate("request") },
            { icon: "⊡", label: "Scan", color: "#10b981", bg: "rgba(16,185,129,0.4)", action: () => navigate("scan") },
            { icon: "+", label: "Add Money", color: "#a78bfa", bg: "rgba(167,139,250,0.4)", action: () => { setAddMoneyStep(1); navigate("addmoney"); } },
          ].map(item => (
            <div key={item.label} onClick={item.action} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 7, cursor: "pointer" }}>
              <div style={{ width: 54, height: 54, borderRadius: 17, background: item.bg, border: `1.5px solid ${item.color}80`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, color: item.color, fontWeight: 900, boxShadow: `0 0 12px ${item.color}20` }}>{item.icon}</div>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.6)", fontWeight: 700, textAlign: "center" }}>{item.label}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: "18px 20px 4px" }}>
        <div style={{ fontSize: 15, fontWeight: 800, color: "#fff", marginBottom: 12 }}>Pay Bills</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 8 }}>
          {BILLS.map(b => (
            <div key={b.id} onClick={() => navigate("bills")} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 5, cursor: "pointer" }}>
              <div style={{ width: 42, height: 42, borderRadius: 13, background: `${b.color}18`, border: `1px solid ${b.color}28`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>{b.icon}</div>
              <div style={{ fontSize: 9, color: "rgba(255,255,255,0.4)", textAlign: "center", fontWeight: 600 }}>{b.name}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ padding: "18px 20px 0" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div style={{ fontSize: 15, fontWeight: 800, color: "#fff" }}>Recent</div>
          <div onClick={() => navigate("history")} style={{ fontSize: 12, color: "#8b5cf6", fontWeight: 700, cursor: "pointer" }}>See All →</div>
        </div>
        {transactions.slice(0, 4).map(tx => <TxRow key={tx.id} tx={tx} contacts={contacts} onSelect={setSelectedTx} />)}
      </div>
    </div>
  );
}
