// QuantumPay — Transaction row item
export default function TxRow({ tx, contacts = [], onSelect }) {
  return (
    <div onClick={() => onSelect && onSelect(tx)} style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 0", borderBottom: "1px solid rgba(255,255,255,0.05)", cursor: "pointer" }}>
      <div style={{ width: 44, height: 44, borderRadius: 22, background: tx.type === "received" ? "rgba(74,222,128,0.12)" : "rgba(244,63,94,0.1)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0 }}>
        {contacts.find(c => c.name === tx.name)?.avatar || (tx.type === "received" ? "💰" : "🏢")}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{tx.name}</div>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginTop: 2 }}>{tx.note} · {tx.time}</div>
      </div>
      <div style={{ textAlign: "right", flexShrink: 0 }}>
        <div style={{ fontSize: 15, fontWeight: 800, color: tx.type === "received" ? "#4ade80" : "#f43f5e" }}>{tx.type === "received" ? "+" : "−"}₹{tx.amount.toLocaleString("en-IN")}</div>
        <div style={{ fontSize: 10, color: "#4ade80" }}>✓ success</div>
      </div>
    </div>
  );
}
