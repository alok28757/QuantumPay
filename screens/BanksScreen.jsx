// QuantumPay — Bank linking screen
import { S } from '../constants/styles';
import { db } from '../lib/firebase';
import { LocalDB } from '../lib/localdb';
import { doc, updateDoc } from 'firebase/firestore';

export default function BanksScreen({
  bankStep, setBankStep, selectedBank, setSelectedBank,
  bankOtp, setBankOtp, linkedBanks, setLinkedBanks,
  user, cloudMode, setScreen,
}) {
  const handleLinkBank = async () => {
    const newBank = {
      id: Date.now().toString(),
      bankName: selectedBank.label,
      accountNumber: "XX" + Math.floor(1000 + Math.random() * 9000),
      type: "Savings"
    };
    const updated = [...linkedBanks, newBank];
    setLinkedBanks(updated);

    if (cloudMode && user?.phone) {
      await updateDoc(doc(db, "profiles", user.phone), { linked_banks: updated });
    } else if (user?.phone) {
      const users = LocalDB.getUsers();
      if (users[user.phone]) {
        users[user.phone].linkedBanks = updated;
        LocalDB.saveUsers(users);
      }
    }
    setBankStep(5);
  };

  return (
    <div style={{ padding: "16px 20px" }}>
      {bankStep < 5 && (
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
          <div onClick={() => {
            if (bankStep === 1) setScreen("profile");
            else if (bankStep === 4) setBankStep(2);
            else setBankStep(s => s - 1);
          }} style={S.backBtn}>←</div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>
            {bankStep === 1 ? "Linked Banks" : "Add Bank Account"}
          </div>
        </div>
      )}

      {bankStep === 1 && <>
        {linkedBanks.length === 0 ? (
          <div style={{ padding: "40px 20px", textAlign: "center" }}>
            <div style={{ fontSize: 40, marginBottom: 16, opacity: 0.5 }}>🏦</div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 8 }}>No Banks Linked</div>
            <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", lineHeight: 1.5, marginBottom: 24 }}>Link a bank account to make seamless UPI payments on QuantumPay.</div>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginBottom: 24 }}>
            <div style={S.label}>YOUR LINKED ACCOUNTS</div>
            {linkedBanks.map(b => (
              <div key={b.id} style={{ ...S.card, padding: 16, display: "flex", alignItems: "center", gap: 14 }}>
                <div style={{ width: 44, height: 44, borderRadius: 12, background: "rgba(16,185,129,0.15)", border: "1px solid rgba(16,185,129,0.3)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20 }}>🏦</div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{b.bankName}</div>
                  <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)", marginTop: 2 }}>{b.type} • {b.accountNumber}</div>
                </div>
                <div style={{ fontSize: 12, color: "#10b981", fontWeight: 700, background: "rgba(16,185,129,0.1)", padding: "4px 8px", borderRadius: 8 }}>Primary</div>
              </div>
            ))}
          </div>
        )}
        <div onClick={() => setBankStep(2)} style={S.gradBtn(false)}>+ Add Bank Account</div>
      </>}

      {bankStep === 2 && <>
        <div style={S.label}>SELECT YOUR BANK</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          {[
            { id: "sbi", label: "State Bank of India", color: "#3b82f6" },
            { id: "hdfc", label: "HDFC Bank", color: "#0ea5e9" },
            { id: "icici", label: "ICICI Bank", color: "#f97316" },
            { id: "axis", label: "Axis Bank", color: "#db2777" },
            { id: "pnb", label: "Punjab National Bank", color: "#eab308" },
            { id: "kotak", label: "Kotak Mahindra", color: "#ef4444" }
          ].map(b => (
            <div key={b.id} onClick={() => {
              setSelectedBank(b);
              setBankStep(3);
              setTimeout(() => setBankStep(4), 2500);
            }} style={{ ...S.card, padding: "16px 12px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: 8, cursor: "pointer", border: "1px solid rgba(255,255,255,0.05)" }}>
              <div style={{ width: 36, height: 36, borderRadius: 18, background: `${b.color}20`, color: b.color, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14, fontWeight: 900 }}>{b.label[0]}</div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#fff" }}>{b.label}</div>
            </div>
          ))}
        </div>
      </>}

      {bankStep === 3 && (
        <div style={{ padding: "60px 20px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
          <div style={{ width: 60, height: 60, borderRadius: 30, background: "rgba(139,92,246,0.1)", border: "2px dashed #8b5cf6", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24, marginBottom: 24, animation: "spin 2s linear infinite" }}>🏦</div>
          <div style={{ fontSize: 16, fontWeight: 800, color: "#fff", marginBottom: 8 }}>Fetching Bank Accounts</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)" }}>Finding accounts linked to +91 {user?.phone} at {selectedBank?.label}...</div>
        </div>
      )}

      {bankStep === 4 && <>
        <div style={{ ...S.card, padding: 24, textAlign: "center", marginBottom: 18 }}>
          <div style={{ width: 50, height: 50, borderRadius: 25, background: "rgba(16,185,129,0.15)", margin: "0 auto 12px", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>✅</div>
          <div style={{ fontSize: 18, fontWeight: 800, color: "#fff", marginBottom: 6 }}>Account Found</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)" }}>{selectedBank?.label} • Savings Account</div>
        </div>
        <div style={S.label}>VERIFY WITH OTP</div>
        <p style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 16, lineHeight: 1.4 }}>A 6-digit OTP has been sent to your registered mobile number (+91 {user?.phone}) for verification.</p>
        <input value={bankOtp} onChange={e => setBankOtp(e.target.value.replace(/\D/g, "").slice(0, 6))} type="password" placeholder="• • • • • •" style={{ ...S.input, marginBottom: 24, textAlign: "center", fontSize: 24, letterSpacing: 8 }} />
        <div onClick={() => bankOtp.length === 6 && handleLinkBank()} style={S.gradBtn(bankOtp.length < 6)}>Verify & Link Account</div>
      </>}

      {bankStep === 5 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", paddingTop: 50 }}>
          <div style={{ width: 90, height: 90, borderRadius: 45, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 44, marginBottom: 22, boxShadow: "0 0 40px rgba(16,185,129,0.3)", animation: "pulseCheck 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275) both" }}>✓</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 8 }}>Bank Linked!</div>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", marginBottom: 32, textAlign: "center", padding: "0 20px" }}>You can now use your {selectedBank?.label} account for seamless UPI payments.</div>
          <div onClick={() => { setBankStep(1); setBankOtp(""); }} style={S.gradBtn(false)}>View Linked Banks</div>
        </div>
      )}

    </div>
  );
}
