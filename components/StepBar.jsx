// QuantumPay — Registration step progress bar
export default function StepBar({ step }) {
  return (
    <div style={{ display: "flex", gap: 5, marginBottom: 22 }}>
      {[1, 2, 3, 4].map(s => <div key={s} style={{ height: 4, flex: 1, borderRadius: 2, background: s <= step ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.1)", transition: "all 0.3s" }} />)}
    </div>
  );
}
