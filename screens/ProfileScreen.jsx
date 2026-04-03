// QuantumPay — Profile screen
import { S } from '../constants/styles';
import { ArrowLeft, Zap, ChevronRight, LogOut, Bell, Lock, CreditCard, CircleHelp, FileText, Cake, Calendar, Smartphone } from 'lucide-react';

export default function ProfileScreen({
  userName, userInitial, upiId, user, profile,
  transactions, handleLogout,
  goBack, setBankStep, setScreen, linkedBanks,
}) {
  const totalSent = transactions.filter(t => t.type === "sent").reduce((s, t) => s + t.amount, 0);
  const totalReceived = transactions.filter(t => t.type === "received").reduce((s, t) => s + t.amount, 0);
  const memberSince = user?.createdAt ? new Date(user.createdAt).toLocaleDateString("en-IN", { month: "short", year: "numeric" }) : "Today";
  const SETTINGS = [
    { icon: Bell, label: "Notifications", sub: "Manage alerts & sounds" },
    { icon: Lock, label: "Privacy & Security", sub: "2FA, biometrics" },
    { icon: CreditCard, label: "Linked Cards & Banks", sub: "Manage payment methods" },
    { icon: CircleHelp, label: "Help & Support", sub: "FAQs, chat with us" },
    { icon: FileText, label: "Terms & Privacy", sub: "Legal information" },
  ];
  return (
    <div style={{ padding: "16px 20px 30px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={goBack} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>My Profile</div>
      </div>

      {/* Avatar + name + UPI */}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 20 }}>
        <div style={{ width: 80, height: 80, borderRadius: 40, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 34, fontWeight: 900, color: "#fff", marginBottom: 12, boxShadow: "0 0 30px rgba(139,92,246,0.4)" }}>{userInitial}</div>
        <div style={{ fontSize: 20, fontWeight: 900, color: "#fff", marginBottom: 4 }}>{userName}</div>
        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", marginBottom: 6 }}>+91 {user?.phone || ""}</div>
        <div style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.35)", borderRadius: 20, padding: "5px 14px", fontSize: 12, color: "#a78bfa", fontWeight: 700, display: "flex", alignItems: "center", gap: 6 }}><Zap size={14} color="#a78bfa" /> {upiId}</div>
      </div>

      {/* Stats row */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20 }}>
        {[
          { label: "Total Sent", value: `₹${totalSent.toLocaleString("en-IN")}`, color: "#f43f5e", bg: "rgba(244,63,94,0.1)" },
          { label: "Received", value: `₹${totalReceived.toLocaleString("en-IN")}`, color: "#4ade80", bg: "rgba(74,222,128,0.1)" },
          { label: "Transactions", value: transactions.length, color: "#8b5cf6", bg: "rgba(139,92,246,0.1)" },
        ].map(s => (
          <div key={s.label} style={{ flex: 1, background: s.bg, border: `1px solid ${s.color}30`, borderRadius: 16, padding: "12px 8px", textAlign: "center" }}>
            <div style={{ fontSize: 15, fontWeight: 900, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.4)", marginTop: 3 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Info card: DOB + member since */}
      <div style={{ ...S.card, padding: 16, marginBottom: 16 }}>
        {[
          { icon: Cake, label: "Date of Birth", value: user?.dob ? new Date(user.dob + "T00:00:00").toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" }) : "—" },
          { icon: Calendar, label: "Member Since", value: memberSince },
          { icon: Smartphone, label: "Registered Phone", value: `+91 ${user?.phone || ""}` },
        ].map((item, i, arr) => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none" }}>
            <span style={{ color: "rgba(255,255,255,0.4)" }}><item.icon size={20} /></span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)" }}>{item.label}</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginTop: 2 }}>{item.value}</div>
            </div>
          </div>
        ))}
      </div>


      {/* Settings rows */}
      <div style={{ ...S.card, marginBottom: 16, overflow: "hidden" }}>
        {SETTINGS.map((item, i) => (
          <div key={item.label} onClick={() => { if (item.label.includes("Linked Cards")) { setBankStep(1); setScreen("banks"); } }} style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 18px", borderBottom: i < SETTINGS.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none", cursor: "pointer" }}>
            <div style={{ width: 36, height: 36, borderRadius: 11, background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.2)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, color: "#8b5cf6" }}><item.icon size={18} /></div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{item.label}</div>
              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginTop: 2 }}>{item.sub}</div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.2)", display: "flex", alignItems: "center" }}><ChevronRight size={20} /></div>
          </div>
        ))}
      </div>

      <div onClick={handleLogout} style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 18, padding: 16, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, fontSize: 15, fontWeight: 900, color: "#f43f5e", cursor: "pointer" }}>
        <LogOut size={16} color="#f43f5e" /> Logout
      </div>
      <div style={{ textAlign: "center", marginTop: 20, fontSize: 11, color: "rgba(255,255,255,0.15)" }}>QuantumPay v1.0.0 · Member since {memberSince}</div>
    </div>
  );
}
