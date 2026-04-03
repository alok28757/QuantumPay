// QuantumPay — Pay Bills screen
import { BILLS } from '../constants/data';
import { S } from '../constants/styles';
import { ArrowLeft } from 'lucide-react';

export default function BillsScreen({ goBack }) {
  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={goBack} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Pay Bills</div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        {BILLS.map(b => (
          <div key={b.id} style={{ ...S.card, padding: "18px 10px", textAlign: "center", cursor: "pointer" }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 8 }}><b.icon size={34} color={b.color} /></div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>{b.name}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
