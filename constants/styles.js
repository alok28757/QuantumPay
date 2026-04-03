// QuantumPay — Shared inline style presets
export const S = {
  backBtn: { width: 36, height: 36, borderRadius: 18, background: "rgba(255,255,255,0.08)", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", fontSize: 18, color: "#fff", flexShrink: 0 },
  card: { background: "rgba(255,255,255,0.04)", borderRadius: 20, border: "1px solid rgba(255,255,255,0.08)" },
  gradBtn: (disabled) => ({ background: disabled ? "rgba(255,255,255,0.08)" : "linear-gradient(135deg, #8b5cf6, #06b6d4)", borderRadius: 18, padding: "16px", textAlign: "center", fontSize: 16, fontWeight: 900, color: disabled ? "rgba(255,255,255,0.3)" : "#fff", cursor: disabled ? "default" : "pointer", transition: "all 0.2s" }),
  label: { fontSize: 11, color: "rgba(255,255,255,0.35)", fontWeight: 700, letterSpacing: 0.8, marginBottom: 6 },
  input: { width: "100%", background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 14, padding: "14px 16px", color: "#fff", fontSize: 15, outline: "none", boxSizing: "border-box" },
};
