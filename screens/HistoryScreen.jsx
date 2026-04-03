// QuantumPay — History screen
import { S } from '../constants/styles';
import TxRow from '../components/TxRow';

export default function HistoryScreen({ transactions, activeTab, setActiveTab, contacts, setSelectedTx, goBack }) {
  const filteredTx = transactions.filter(t => activeTab === "all" ? true : t.type === activeTab);
  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 18 }}>
        <div onClick={goBack} style={S.backBtn}>←</div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>History</div>
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 18 }}>
        {["all", "sent", "received"].map(tab => (
          <div key={tab} onClick={() => setActiveTab(tab)} style={{ padding: "8px 18px", borderRadius: 20, fontSize: 13, fontWeight: 700, cursor: "pointer", textTransform: "capitalize", background: activeTab === tab ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.07)", color: activeTab === tab ? "#fff" : "rgba(255,255,255,0.4)" }}>{tab}</div>
        ))}
      </div>
      {filteredTx.map(tx => <TxRow key={tx.id} tx={tx} contacts={contacts} onSelect={setSelectedTx} />)}
    </div>
  );
}
