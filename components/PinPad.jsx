import { Delete, Check } from 'lucide-react';

export default function PinPad({ value, onChange, maxLength = 4 }) {
  const keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫", "0", "✓"];
  return (
    <div>
      <div style={{ display: "flex", gap: 14, justifyContent: "center", marginBottom: 28 }}>
        {[...Array(maxLength)].map((_, i) => (
          <div key={i} style={{ width: maxLength > 4 ? 40 : 52, height: maxLength > 4 ? 40 : 52, borderRadius: 26, background: i < value.length ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.12)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: maxLength > 4 ? 18 : 22, color: "#fff", transition: "all 0.2s" }}>
            {i < value.length ? "●" : ""}
          </div>
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        {keys.map(k => (
          <div key={k} onClick={() => {
            if (k === "⌫") onChange(value.slice(0, -1));
            else if (k === "✓") { if (value.length === maxLength) onChange(value, true); }
            else if (value.length < maxLength) onChange(value + k);
          }} style={{ height: 56, borderRadius: 16, background: k === "✓" ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, fontWeight: 700, color: "#fff", cursor: "pointer", border: "1px solid rgba(255,255,255,0.06)", transition: "all 0.15s" }}>
            {k === "⌫" ? <Delete size={22} color="#fff" /> : k === "✓" ? <Check size={22} color="#fff" /> : k}
          </div>
        ))}
      </div>
    </div>
  );
}
