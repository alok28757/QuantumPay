import { useEffect, useState } from "react";
import { decryptTransaction, encryptTransaction, generatePQCKeys, getPQCPrivateKey, hashMpin, signTransaction, storePQCPrivateKey } from "../../lib/crypto";
import { getSession, signInUser, signOutUser, signUpUser, supabase } from "../../lib/supabase";

// ─── SESSION HELPER (per-tab) ────────────────────────────────────────────────
const Session = {
  get: () => sessionStorage.getItem("qp_current_phone"),
  set: (p) => sessionStorage.setItem("qp_current_phone", p),
  clear: () => sessionStorage.removeItem("qp_current_phone"),
};

// ─── LOCAL FALLBACK ──────────────────────────────────────────────────────────
const LocalDB = {
  getUsers: () => JSON.parse(localStorage.getItem("qp_users") || "{}"),
  saveUsers: (u) => localStorage.setItem("qp_users", JSON.stringify(u)),
};

// Quick connectivity check (3s timeout)
const SUPABASE_URL = process.env.EXPO_PUBLIC_SUPABASE_URL || '';
const SUPABASE_ANON_KEY = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY || '';

const checkSupabase = async () => {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) return false;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/profiles?select=phone&limit=1`,
      { headers: { apikey: SUPABASE_ANON_KEY }, signal: controller.signal }
    );
    clearTimeout(timeout);
    return res.ok;
  } catch { return false; }
};

const CONTACTS = [
  { id: 1, name: "Priya Sharma", upi: "priya@upi", avatar: "👩", color: "#8b5cf6" },
  { id: 2, name: "Rahul Dev", upi: "rahul@upi", avatar: "👨‍💻", color: "#06b6d4" },
  { id: 3, name: "Ananya K", upi: "ananya@upi", avatar: "👩‍🎓", color: "#f43f5e" },
  { id: 4, name: "Vikram S", upi: "vikram@upi", avatar: "🧑‍💼", color: "#10b981" },
  { id: 5, name: "Deepa R", upi: "deepa@upi", avatar: "👩‍🔬", color: "#f97316" },
  { id: 6, name: "Arjun M", upi: "arjun@upi", avatar: "🧑‍🎨", color: "#eab308" },
];

const BILLS = [
  { id: 1, icon: "⚡", name: "Electricity", color: "#f7c948" },
  { id: 2, icon: "📱", name: "Mobile", color: "#4ade80" },
  { id: 3, icon: "💧", name: "Water", color: "#38bdf8" },
  { id: 4, icon: "📺", name: "DTH", color: "#a78bfa" },
  { id: 5, icon: "🌐", name: "Internet", color: "#fb923c" },
  { id: 6, icon: "🏦", name: "Loan EMI", color: "#f43f5e" },
];

const S = {
  backBtn: { width: 36, height: 36, borderRadius: 18, background: "rgba(255,255,255,0.08)", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", fontSize: 18, color: "#fff", flexShrink: 0 },
  card: { background: "rgba(255,255,255,0.04)", borderRadius: 20, border: "1px solid rgba(255,255,255,0.08)" },
  gradBtn: (disabled) => ({ background: disabled ? "rgba(255,255,255,0.08)" : "linear-gradient(135deg, #8b5cf6, #06b6d4)", borderRadius: 18, padding: "16px", textAlign: "center", fontSize: 16, fontWeight: 900, color: disabled ? "rgba(255,255,255,0.3)" : "#fff", cursor: disabled ? "default" : "pointer", transition: "all 0.2s" }),
  label: { fontSize: 11, color: "rgba(255,255,255,0.35)", fontWeight: 700, letterSpacing: 0.8, marginBottom: 6 },
  input: { width: "100%", background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 14, padding: "14px 16px", color: "#fff", fontSize: 15, outline: "none", boxSizing: "border-box" },
};

function PhoneFrame({ children, bg }) {
  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", background: "#050510", padding: 20, fontFamily: "'Segoe UI', sans-serif" }}>
      <div style={{ width: 390, height: 800, background: bg || "#0d0d1f", borderRadius: 44, overflow: "hidden", display: "flex", flexDirection: "column", boxShadow: "0 40px 100px rgba(139,92,246,0.25), 0 0 0 1px rgba(255,255,255,0.08)" }}>
        {children}
      </div>
    </div>
  );
}

function PinPad({ value, onChange }) {
  const keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫", "0", "✓"];
  return (
    <div>
      <div style={{ display: "flex", gap: 14, justifyContent: "center", marginBottom: 28 }}>
        {[0, 1, 2, 3].map(i => (
          <div key={i} style={{ width: 52, height: 52, borderRadius: 26, background: i < value.length ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.08)", border: "1px solid rgba(255,255,255,0.12)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, color: "#fff", transition: "all 0.2s" }}>
            {i < value.length ? "●" : ""}
          </div>
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10 }}>
        {keys.map(k => (
          <div key={k} onClick={() => {
            if (k === "⌫") onChange(value.slice(0, -1));
            else if (k === "✓") { if (value.length === 4) onChange(value, true); }
            else if (value.length < 4) onChange(value + k);
          }} style={{ height: 56, borderRadius: 16, background: k === "✓" ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, fontWeight: 700, color: "#fff", cursor: "pointer", border: "1px solid rgba(255,255,255,0.06)", transition: "all 0.15s" }}>
            {k}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function QuantumPay() {
  const [authStep, setAuthStep] = useState("splash");
  const [loginPhone, setLoginPhone] = useState("");
  const [loginMpin, setLoginMpin] = useState("");
  const [loginError, setLoginError] = useState("");
  const [regPhone, setRegPhone] = useState("");
  const [regName, setRegName] = useState("");
  const [regDob, setRegDob] = useState("");
  const [regUpi, setRegUpi] = useState("");
  const [regMpin, setRegMpin] = useState("");
  const [regMpinConfirm, setRegMpinConfirm] = useState("");
  const [regError, setRegError] = useState("");

  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState({ name: "", phone: "" });
  const [profileSaved, setProfileSaved] = useState(false);
  const [screen, setScreen] = useState("home");
  const [prevScreen, setPrevScreen] = useState("home");
  const [balance, setBalance] = useState(0);
  const [transactions, setTransactions] = useState([]);
  const [sendStep, setSendStep] = useState(1);
  const [selectedContact, setSelectedContact] = useState(null);
  const [amount, setAmount] = useState("");
  const [note, setNote] = useState("");
  const [pin, setPin] = useState("");
  const [activeTab, setActiveTab] = useState("all");
  const [addMoneyStep, setAddMoneyStep] = useState(1);
  const [addAmount, setAddAmount] = useState("");
  const [upiSearch, setUpiSearch] = useState("");
  const [scanTab, setScanTab] = useState("my-qr");
  const [payUpi, setPayUpi] = useState("");
  const [balanceVisible, setBalanceVisible] = useState(true);
  const [cloudMode, setCloudMode] = useState(null);

  // ─── DUAL-MODE DATA LAYER ────────────────────────────────────────────────
  const loadUserData = async (phone, isCloud) => {
    const cloud = isCloud !== undefined ? isCloud : cloudMode;
    if (cloud) {
      const { data: p } = await supabase.from("profiles").select("*").eq("phone", phone).single();
      if (p) {
        setBalance(p.balance || 0);
        setProfile({ name: p.name || "", phone });
        setUser({ phone, name: p.name, dob: p.dob, upiId: p.upi_id, createdAt: p.created_at });
      }
      const { data: txData } = await supabase.from("transactions").select("*")
        .or(`sender_phone.eq.${phone},receiver_phone.eq.${phone}`)
        .order("created_at", { ascending: false }).limit(50);
      if (txData) {
        const decrypted = await Promise.all(txData.map(tx => tx.encrypted ? decryptTransaction(phone, tx) : Promise.resolve(tx)));
        setTransactions(decrypted.map(tx => ({
          id: tx.id,
          name: tx.sender_phone === phone ? (tx.receiver_name || tx.receiver_phone) : (tx.sender_name || tx.sender_phone),
          type: tx.sender_phone === phone ? "sent" : "received",
          amount: Number(tx.amount),
          time: new Date(tx.created_at).toLocaleString("en-IN", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
          note: tx.note || "Payment",
          verified: !!tx.signature,
        })));
      }
    } else {
      const d = LocalDB.getUsers()[phone];
      if (d) {
        setBalance(d.balance || 0);
        setTransactions(d.transactions || []);
        setProfile({ name: d.name || "", phone });
        setUser({ phone, ...d });
      }
    }
  };

  useEffect(() => {
    const init = async () => {
      const isCloud = await checkSupabase();
      setCloudMode(isCloud);
      console.log("QuantumPay mode:", isCloud ? "☁️ CLOUD" : "💾 LOCAL");
      const phone = Session.get();
      if (phone) {
        if (isCloud) {
          // Check for existing Supabase Auth session
          const session = await getSession();
          if (session) { await loadUserData(phone, true); setAuthStep("app"); }
        } else {
          if (LocalDB.getUsers()[phone]) { await loadUserData(phone, false); setAuthStep("app"); }
        }
      }
      if (isCloud) {
        const ch = supabase.channel("tx-live")
          .on("postgres_changes", { event: "INSERT", schema: "public", table: "transactions" }, (payload) => {
            const cp = Session.get();
            if (cp && (payload.new.sender_phone === cp || payload.new.receiver_phone === cp)) loadUserData(cp, true);
          }).subscribe();
        return () => supabase.removeChannel(ch);
      } else {
        const h = (e) => { if (e.key === "qp_users") { const cp = Session.get(); if (cp) loadUserData(cp, false); } };
        window.addEventListener("storage", h);
        return () => window.removeEventListener("storage", h);
      }
    };
    init();
  }, []);

  const navigate = (to) => { setPrevScreen(screen); setScreen(to); };
  const goBack = () => setScreen(prevScreen);

  const handleRegisterPhone = async () => {
    if (!/^\d{10}$/.test(regPhone)) { setRegError("Enter a valid 10-digit phone number"); return; }
    if (cloudMode) {
      const { data } = await supabase.from("profiles").select("phone").eq("phone", regPhone).single();
      if (data) { setRegError("Already registered. Please login."); return; }
    } else {
      if (LocalDB.getUsers()[regPhone]) { setRegError("Already registered. Please login."); return; }
    }
    setRegError(""); setAuthStep("register-profile");
  };

  const handleRegisterProfile = () => {
    if (!regName.trim()) { setRegError("Please enter your full name"); return; }
    if (!regDob) { setRegError("Please enter your date of birth"); return; }
    setRegError("");
    setRegUpi(regName.toLowerCase().replace(/\s+/g, "").slice(0, 10) + "@qpay");
    setAuthStep("register-upi");
  };

  const handleRegisterUpi = async () => {
    if (!regUpi.includes("@")) { setRegError("UPI ID must contain @"); return; }
    if (cloudMode) {
      const { data } = await supabase.from("profiles").select("upi_id").eq("upi_id", regUpi).single();
      if (data) { setRegError("This UPI ID is already taken."); return; }
    } else {
      const users = LocalDB.getUsers();
      if (Object.values(users).some(u => u.upiId === regUpi)) { setRegError("This UPI ID is already taken."); return; }
    }
    setRegError(""); setAuthStep("register-mpin");
  };

  const handleSetMpin = (val, done) => {
    setRegMpin(val);
    if (done) { setRegError(""); setAuthStep("register-confirm"); }
  };

  const handleConfirmMpin = async (val, done) => {
    setRegMpinConfirm(val);
    if (done) {
      if (regMpin !== val) { setRegError("MPINs don't match. Try again."); setRegMpinConfirm(""); return; }
      const hashedPin = await hashMpin(regMpin);
      const pqcKeys = generatePQCKeys();
      storePQCPrivateKey(regPhone, pqcKeys.privateKey);
      if (cloudMode) {
        // 1. Create Supabase Auth account
        const { data: authData, error: authErr } = await signUpUser(regPhone, hashedPin);
        if (authErr) { setRegError("Registration failed: " + authErr.message); return; }
        const userId = authData?.user?.id;
        // 2. Insert profile with user_id link
        const { error } = await supabase.from("profiles").insert({ phone: regPhone, name: regName, dob: regDob, upi_id: regUpi, mpin: hashedPin, balance: 0, public_key: pqcKeys.publicKey, user_id: userId });
        if (error) { setRegError("Registration failed: " + error.message); return; }
      } else {
        const users = LocalDB.getUsers();
        users[regPhone] = { name: regName, dob: regDob, upiId: regUpi, mpin: hashedPin, balance: 0, transactions: [], createdAt: new Date().toISOString(), publicKey: pqcKeys.publicKey };
        LocalDB.saveUsers(users);
      }
      Session.set(regPhone);
      await loadUserData(regPhone);
      setRegError(""); setAuthStep("welcome");
      setTimeout(() => setAuthStep("app"), 2500);
    }
  };

  const handleLoginMpin = async (val, done) => {
    setLoginMpin(val);
    if (done) {
      if (!/^\d{10}$/.test(loginPhone)) { setLoginError("Enter a valid 10-digit phone number"); setLoginMpin(""); return; }
      const hashedVal = await hashMpin(val);
      if (cloudMode) {
        // Authenticate via Supabase Auth
        const { error } = await signInUser(loginPhone, hashedVal);
        if (error) {
          const msg = error.message.includes("Invalid login") ? "Wrong phone or MPIN. Please try again." : error.message;
          setLoginError(msg); setLoginMpin(""); return;
        }
      } else {
        const userData = LocalDB.getUsers()[loginPhone];
        if (!userData) { setLoginError("Phone not registered. Please sign up."); setLoginMpin(""); return; }
        if (userData.mpin !== hashedVal) { setLoginError("Wrong MPIN. Please try again."); setLoginMpin(""); return; }
      }
      Session.set(loginPhone); await loadUserData(loginPhone);
      setLoginError(""); setAuthStep("welcome");
      setTimeout(() => setAuthStep("app"), 2000);
    }
  };

  const handleLogout = async () => {
    if (cloudMode) await signOutUser();
    Session.clear();
    setUser(null); setProfile({ name: "", phone: "" }); setBalance(0); setTransactions([]);
    setLoginPhone(""); setLoginMpin(""); setLoginError("");
    setRegPhone(""); setRegName(""); setRegDob(""); setRegUpi(""); setRegMpin(""); setRegMpinConfirm(""); setRegError("");
    setScreen("home"); setAuthStep("login");
  };

  const handleSaveProfile = async () => {
    const phone = Session.get();
    if (phone) {
      if (cloudMode) { await supabase.from("profiles").update({ name: profile.name }).eq("phone", phone); }
      else { const users = LocalDB.getUsers(); if (users[phone]) { users[phone].name = profile.name; LocalDB.saveUsers(users); } }
    }
    setProfileSaved(true); setTimeout(() => setProfileSaved(false), 2000);
  };

  const handleSend = async () => {
    const amt = Number(amount);
    const senderPhone = Session.get();
    const senderName = profile.name || user?.name || "Someone";
    const recipientUpi = selectedContact.upi;
    const tx = { id: Date.now(), name: selectedContact.name, type: "sent", amount: amt, time: "Just now", note: note || "Payment" };
    setTransactions(p => [tx, ...p]); setBalance(b => b - amt); setSendStep(4);

    if (cloudMode) {
      await supabase.from("profiles").update({ balance: balance - amt }).eq("phone", senderPhone);
      const { data: recipient } = await supabase.from("profiles").select("phone, name").eq("upi_id", recipientUpi).single();
      if (recipient) { await supabase.rpc("increment_balance", { p_phone: recipient.phone, p_amount: amt }); }
      // Build, sign, and insert TWO copies (one per party, each encrypted with their own key)
      const rawTx = { sender_phone: senderPhone, sender_name: senderName, receiver_phone: recipient?.phone || recipientUpi, receiver_name: selectedContact.name, amount: amt, note: note || "Payment" };
      const privKey = getPQCPrivateKey(senderPhone);
      const signature = privKey ? signTransaction(privKey, { sender: senderPhone, receiver: rawTx.receiver_phone, amount: amt, time: Date.now() }) : null;
      // Sender's copy (encrypted with sender's key)
      const senderEncTx = await encryptTransaction(senderPhone, rawTx);
      await supabase.from("transactions").insert({ ...senderEncTx, signature });
      // Receiver's copy (encrypted with receiver's key)
      if (recipient) {
        const receiverEncTx = await encryptTransaction(recipient.phone, rawTx);
        await supabase.from("transactions").insert({ ...receiverEncTx, signature });
      }
    } else {
      const users = LocalDB.getUsers();
      users[senderPhone].balance = (users[senderPhone].balance || 0) - amt;
      users[senderPhone].transactions = [{ id: Date.now(), name: selectedContact.name, type: "sent", amount: amt, time: "Just now", note: note || "Payment" }, ...(users[senderPhone].transactions || [])];
      const rp = Object.keys(users).find(ph => users[ph].upiId === recipientUpi);
      if (rp) {
        users[rp].balance = (users[rp].balance || 0) + amt;
        users[rp].transactions = [{ id: Date.now() + 1, name: senderName, type: "received", amount: amt, time: "Just now", note: note || "Payment from " + senderName }, ...(users[rp].transactions || [])];
      }
      LocalDB.saveUsers(users);
    }
  };

  const handleAddMoney = async () => {
    const amt = Number(addAmount); if (!amt) return;
    const phone = Session.get();
    const tx = { id: Date.now(), name: "Wallet Top-up", type: "received", amount: amt, time: "Just now", note: "Added to wallet" };
    setTransactions(p => [tx, ...p]); setBalance(b => b + amt); setAddMoneyStep(3);
    if (cloudMode) {
      await supabase.from("profiles").update({ balance: balance + amt }).eq("phone", phone);
      const rawTx = { sender_phone: phone, sender_name: "Wallet Top-up", receiver_phone: phone, receiver_name: profile.name || "Self", amount: amt, note: "Added to wallet" };
      const encTx = await encryptTransaction(phone, rawTx);
      await supabase.from("transactions").insert(encTx);
    } else {
      const users = LocalDB.getUsers();
      users[phone].balance = (users[phone].balance || 0) + amt;
      users[phone].transactions = [{ id: Date.now(), name: "Wallet Top-up", type: "received", amount: amt, time: "Just now", note: "Added to wallet" }, ...(users[phone].transactions || [])];
      LocalDB.saveUsers(users);
    }
  };

  const resetSend = () => { setSelectedContact(null); setAmount(""); setNote(""); setPin(""); setSendStep(1); setScreen("home"); };


  const filteredTx = transactions.filter(t => activeTab === "all" ? true : t.type === activeTab);
  const userName = profile.name || user?.name || "User";
  const userInitial = userName.charAt(0).toUpperCase();
  const upiId = user?.upiId || (userName.toLowerCase().replace(/\s+/g, "").slice(0, 10) + "@qpay");

  // ════════════════════════════
  // AUTH SCREENS
  // ════════════════════════════

  if (authStep === "splash") return (
    <PhoneFrame bg="linear-gradient(160deg,#1a0533 0%,#0d0d1f 100%)">
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: "10%", width: 280, height: 280, borderRadius: "50%", background: "radial-gradient(circle, rgba(139,92,246,0.3) 0%, transparent 70%)" }} />
        <div style={{ fontSize: 72, marginBottom: 12, filter: "drop-shadow(0 0 30px rgba(139,92,246,0.5))" }}>⚛</div>
        <div style={{ fontSize: 30, fontWeight: 900, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", letterSpacing: 4 }}>QUANTUMPAY</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.3)", marginTop: 8, letterSpacing: 2 }}>FAST · SECURE · SIMPLE</div>
        <div style={{ position: "absolute", bottom: 60, width: "80%" }}>
          <div onClick={() => setAuthStep("login")} style={S.gradBtn(false)}>Get Started →</div>
        </div>
      </div>
    </PhoneFrame>
  );

  if (authStep === "login") return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "50px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div style={{ marginBottom: 32 }}>
          <div style={{ fontSize: 11, color: "#8b5cf6", fontWeight: 700, letterSpacing: 2, marginBottom: 10 }}>⚛ QUANTUMPAY</div>
          <div style={{ fontSize: 28, fontWeight: 900, color: "#fff", lineHeight: 1.2 }}>Welcome Back 👋</div>
          <div style={{ fontSize: 13, color: "rgba(255,255,255,0.35)", marginTop: 8 }}>Enter your phone number and MPIN</div>
        </div>

        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>PHONE NUMBER</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 10, padding: "14px 10px", color: "#8b5cf6", fontWeight: 700, fontSize: 13, flexShrink: 0 }}>+91</div>
            <input value={loginPhone} onChange={e => { setLoginPhone(e.target.value.replace(/\D/g, "").slice(0, 10)); setLoginError(""); }} placeholder="10-digit mobile number" type="tel" style={{ ...S.input }} />
          </div>
        </div>

        {loginPhone.length === 10 && (
          <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
            <div style={S.label}>4-DIGIT MPIN</div>
            <PinPad value={loginMpin} onChange={handleLoginMpin} />
          </div>
        )}

        {loginError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16 }}>⚠️ {loginError}</div>}

        <div style={{ marginTop: "auto", textAlign: "center" }}>
          <span style={{ fontSize: 13, color: "rgba(255,255,255,0.35)" }}>New to QuantumPay? </span>
          <span onClick={() => { setRegPhone(""); setRegError(""); setAuthStep("register-phone"); }} style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700, cursor: "pointer" }}>Create Account →</span>
        </div>
      </div>
    </PhoneFrame>
  );

  const StepBar = ({ step }) => (
    <div style={{ display: "flex", gap: 5, marginBottom: 22 }}>
      {[1, 2, 3, 4].map(s => <div key={s} style={{ height: 4, flex: 1, borderRadius: 2, background: s <= step ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.1)", transition: "all 0.3s" }} />)}
    </div>
  );

  if (authStep === "register-phone") return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={() => setAuthStep("login")} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={1} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Your phone number 📱</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>This will be your login identifier</div>
        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>MOBILE NUMBER</div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 10, padding: "14px 10px", color: "#8b5cf6", fontWeight: 700, fontSize: 13, flexShrink: 0 }}>+91</div>
            <input value={regPhone} onChange={e => { setRegPhone(e.target.value.replace(/\D/g, "").slice(0, 10)); setRegError(""); }} placeholder="10-digit mobile number" type="tel" style={{ ...S.input }} />
          </div>
        </div>
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16 }}>⚠️ {regError}</div>}
        <div onClick={handleRegisterPhone} style={S.gradBtn(regPhone.length !== 10)}>Continue →</div>
      </div>
    </PhoneFrame>
  );

  if (authStep === "register-profile") return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={() => setAuthStep("register-phone")} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={2} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Tell us about you 👤</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>Used for your profile and UPI ID</div>
        <div style={{ ...S.card, padding: 20, marginBottom: 16 }}>
          <div style={S.label}>FULL NAME</div>
          <input value={regName} onChange={e => { setRegName(e.target.value); setRegError(""); }} placeholder="e.g. Alok Sharma" style={{ ...S.input, marginBottom: 16 }} />
          <div style={S.label}>DATE OF BIRTH</div>
          <input value={regDob} onChange={e => setRegDob(e.target.value)} type="date" max={new Date().toISOString().split("T")[0]} style={{ ...S.input, colorScheme: "dark" }} />
        </div>
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16 }}>⚠️ {regError}</div>}
        <div onClick={handleRegisterProfile} style={S.gradBtn(!regName.trim() || !regDob)}>Continue →</div>
      </div>
    </PhoneFrame>
  );

  if (authStep === "register-upi") return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={() => setAuthStep("register-profile")} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={3} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Your UPI ID ⚡</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 24 }}>This is how others can send you money</div>
        <div style={{ ...S.card, padding: 20, marginBottom: 14 }}>
          <div style={S.label}>UPI ID</div>
          <input value={regUpi} onChange={e => { setRegUpi(e.target.value.toLowerCase().replace(/\s/g, "")); setRegError(""); }} placeholder="yourname@qpay" style={{ ...S.input, marginBottom: 10 }} />
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>Must end with @qpay</div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
          {[regName.toLowerCase().replace(/\s+/g, "").slice(0, 8), regName.toLowerCase().split(" ")[0], regPhone.slice(-4) + "pay"].filter(Boolean).map(s => (
            <div key={s} onClick={() => setRegUpi(s + "@qpay")} style={{ background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 20, padding: "6px 14px", fontSize: 12, color: "#a78bfa", cursor: "pointer" }}>{s}@qpay</div>
          ))}
        </div>
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginBottom: 16 }}>⚠️ {regError}</div>}
        <div onClick={handleRegisterUpi} style={S.gradBtn(!regUpi.includes("@"))}>Continue →</div>
      </div>
    </PhoneFrame>
  );

  if (authStep === "register-mpin") return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={() => setAuthStep("register-upi")} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={4} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Set your MPIN 🔐</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 28 }}>4-digit PIN to secure your account. Don't share with anyone.</div>
        <PinPad value={regMpin} onChange={handleSetMpin} />
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginTop: 16, textAlign: "center" }}>⚠️ {regError}</div>}
      </div>
    </PhoneFrame>
  );

  if (authStep === "register-confirm") return (
    <PhoneFrame>
      <div style={{ flex: 1, padding: "40px 24px 30px", display: "flex", flexDirection: "column" }}>
        <div onClick={() => { setRegMpin(""); setRegMpinConfirm(""); setAuthStep("register-mpin"); }} style={{ ...S.backBtn, marginBottom: 24 }}>←</div>
        <StepBar step={4} />
        <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 6 }}>Confirm MPIN 🔐</div>
        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.4)", marginBottom: 28 }}>Re-enter your 4-digit MPIN to confirm</div>
        <PinPad value={regMpinConfirm} onChange={handleConfirmMpin} />
        {regError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 13, color: "#f43f5e", marginTop: 16, textAlign: "center" }}>⚠️ {regError}</div>}
      </div>
    </PhoneFrame>
  );

  if (authStep === "welcome") return (
    <PhoneFrame>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16 }}>
        <div style={{ width: 96, height: 96, borderRadius: 48, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 48, boxShadow: "0 0 40px rgba(16,185,129,0.4)" }}>✓</div>
        <div style={{ fontSize: 26, fontWeight: 900, color: "#fff" }}>You're In! 🎉</div>
        <div style={{ fontSize: 14, color: "rgba(255,255,255,0.35)" }}>Welcome to QuantumPay</div>
        <div style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700 }}>{upiId}</div>
      </div>
    </PhoneFrame>
  );

  const TxRow = ({ tx }) => (
    <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 0", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
      <div style={{ width: 44, height: 44, borderRadius: 22, background: tx.type === "received" ? "rgba(74,222,128,0.12)" : "rgba(244,63,94,0.1)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0 }}>
        {CONTACTS.find(c => c.name === tx.name)?.avatar || (tx.type === "received" ? "💰" : "🏢")}
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

  // ══════════════════════════
  // MAIN APP
  // ══════════════════════════

  const HomeScreen = () => (
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
                {balanceVisible ? `₹${balance.toLocaleString("en-IN", { minimumFractionDigits: 2 })}` : "₹ ••••••"}
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
            { icon: "↑", label: "Send", color: "#8b5cf6", bg: "rgba(139,92,246,0.15)", action: () => { setSendStep(1); navigate("send"); } },
            { icon: "↓", label: "Request", color: "#06b6d4", bg: "rgba(6,182,212,0.15)", action: () => navigate("request") },
            { icon: "⊡", label: "Scan", color: "#10b981", bg: "rgba(16,185,129,0.15)", action: () => navigate("scan") },
            { icon: "+", label: "Add Money", color: "#a78bfa", bg: "rgba(167,139,250,0.15)", action: () => { setAddMoneyStep(1); navigate("addmoney"); } },
          ].map(item => (
            <div key={item.label} onClick={item.action} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 7, cursor: "pointer" }}>
              <div style={{ width: 54, height: 54, borderRadius: 17, background: item.bg, border: `1px solid ${item.color}30`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, color: item.color, fontWeight: 900 }}>{item.icon}</div>
              <div style={{ fontSize: 10, color: "rgba(255,255,255,0.45)", fontWeight: 600, textAlign: "center" }}>{item.label}</div>
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
        {transactions.slice(0, 4).map(tx => <TxRow key={tx.id} tx={tx} />)}
      </div>
    </div>
  );

  const SendScreen = () => (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={() => sendStep > 1 ? setSendStep(s => s - 1) : goBack()} style={S.backBtn}>←</div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Send Money</div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 5 }}>
          {[1, 2, 3].map(s => <div key={s} style={{ width: s <= sendStep ? 20 : 8, height: 6, borderRadius: 3, background: s <= sendStep ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.12)", transition: "all 0.3s" }} />)}
        </div>
      </div>
      {sendStep === 1 && <>
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 14, padding: "10px 16px", display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <span>🔍</span>
          <input value={upiSearch} onChange={e => setUpiSearch(e.target.value)} placeholder="Search name or enter UPI ID..." style={{ background: "none", border: "none", outline: "none", color: "#fff", fontSize: 14, flex: 1 }} />
          {upiSearch && <span onClick={() => setUpiSearch("")} style={{ color: "rgba(255,255,255,0.3)", cursor: "pointer", fontSize: 18 }}>✕</span>}
        </div>
        {upiSearch && upiSearch.includes("@") && (
          <div onClick={() => { setSelectedContact({ name: upiSearch, upi: upiSearch, avatar: "👤", color: "#8b5cf6" }); setSendStep(2); setUpiSearch(""); }} style={{ ...S.card, padding: "14px 16px", marginBottom: 14, display: "flex", alignItems: "center", gap: 12, cursor: "pointer", border: "1px solid rgba(139,92,246,0.4)" }}>
            <div style={{ width: 40, height: 40, borderRadius: 20, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20 }}>👤</div>
            <div>
              <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 2 }}>Send to UPI ID</div>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#fff" }}>{upiSearch}</div>
            </div>
            <div style={{ marginLeft: "auto", color: "#8b5cf6", fontSize: 20 }}>›</div>
          </div>
        )}
        <div style={S.label}>CONTACTS</div>
        {CONTACTS.filter(c => !upiSearch || c.name.toLowerCase().includes(upiSearch.toLowerCase()) || c.upi.includes(upiSearch.toLowerCase())).map(c => (
          <div key={c.id} onClick={() => { setSelectedContact(c); setSendStep(2); setUpiSearch(""); }} style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 0", borderBottom: "1px solid rgba(255,255,255,0.05)", cursor: "pointer" }}>
            <div style={{ width: 46, height: 46, borderRadius: 23, background: `${c.color}20`, border: `1px solid ${c.color}40`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22 }}>{c.avatar}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{c.name}</div>
              <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{c.upi}</div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 20 }}>›</div>
          </div>
        ))}
      </>}
      {sendStep === 2 && selectedContact && <>
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ width: 70, height: 70, borderRadius: 35, background: `${selectedContact.color}20`, border: `2px solid ${selectedContact.color}50`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 34, margin: "0 auto 10px" }}>{selectedContact.avatar}</div>
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
        <div onClick={() => amount && setSendStep(3)} style={S.gradBtn(!amount)}>Continue →</div>
      </>}
      {sendStep === 3 && selectedContact && <>
        <div style={{ ...S.card, padding: 20, marginBottom: 18 }}>
          <div style={S.label}>CONFIRM PAYMENT</div>
          {[["To", selectedContact.name], ["UPI ID", selectedContact.upi], ["Amount", `₹${Number(amount).toLocaleString("en-IN")}`], ["Note", note || "—"]].map(([k, v]) => (
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
            }} style={{ height: 52, borderRadius: 14, background: k === "✓" ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.07)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, fontWeight: 700, color: "#fff", cursor: "pointer", border: "1px solid rgba(255,255,255,0.06)" }}>{k}</div>
          ))}
        </div>
      </>}
      {sendStep === 4 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", paddingTop: 50 }}>
          <div style={{ width: 90, height: 90, borderRadius: 45, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 44, marginBottom: 22, boxShadow: "0 0 40px rgba(16,185,129,0.3)" }}>✓</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 8 }}>Payment Sent!</div>
          <div style={{ fontSize: 34, fontWeight: 900, color: "#4ade80", marginBottom: 8 }}>₹{Number(amount).toLocaleString("en-IN")}</div>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.4)", marginBottom: 30 }}>to {selectedContact?.name}</div>
          <div style={{ ...S.card, padding: "14px 28px", marginBottom: 24, textAlign: "center" }}>
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>Transaction ID</div>
            <div style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700 }}>QP{Date.now().toString().slice(-10)}</div>
          </div>
          <div onClick={resetSend} style={S.gradBtn(false)}>Back to Home</div>
        </div>
      )}
    </div>
  );

  const AddMoneyScreen = () => (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={() => addMoneyStep > 1 ? setAddMoneyStep(s => s - 1) : goBack()} style={S.backBtn}>←</div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Add Money</div>
      </div>
      {addMoneyStep === 1 && <>
        <div style={{ ...S.card, padding: 24, textAlign: "center", marginBottom: 18 }}>
          <div style={S.label}>ENTER AMOUNT</div>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 4, marginTop: 8 }}>
            <span style={{ fontSize: 30, fontWeight: 900, color: "rgba(255,255,255,0.3)" }}>₹</span>
            <input value={addAmount} onChange={e => setAddAmount(e.target.value.replace(/\D/g, ""))} type="number" placeholder="0"
              style={{ background: "none", border: "none", outline: "none", color: "#fff", fontSize: 44, fontWeight: 900, width: 160, textAlign: "center" }} />
          </div>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 20 }}>
          {[500, 1000, 2000, 5000, 10000].map(q => (
            <div key={q} onClick={() => setAddAmount(String(q))} style={{ background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.3)", borderRadius: 12, padding: "8px 16px", fontSize: 13, fontWeight: 700, color: "#8b5cf6", cursor: "pointer" }}>₹{q.toLocaleString("en-IN")}</div>
          ))}
        </div>
        {addAmount && <div style={{ ...S.card, padding: 14, marginBottom: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 13 }}>After Adding</span>
            <span style={{ color: "#4ade80", fontWeight: 800 }}>₹{(balance + Number(addAmount)).toLocaleString("en-IN", { minimumFractionDigits: 2 })}</span>
          </div>
        </div>}
        <div onClick={() => addAmount && setAddMoneyStep(2)} style={S.gradBtn(!addAmount)}>Choose Payment Method →</div>
      </>}
      {addMoneyStep === 2 && <>
        <div style={{ ...S.card, padding: 14, marginBottom: 18 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: "rgba(255,255,255,0.4)", fontSize: 13 }}>Adding</span>
            <span style={{ color: "#4ade80", fontWeight: 900, fontSize: 16 }}>₹{Number(addAmount).toLocaleString("en-IN")}</span>
          </div>
        </div>
        <div style={S.label}>SELECT PAYMENT METHOD</div>
        {[
          { icon: "🏦", label: "Net Banking", sub: "HDFC, ICICI, SBI & more", color: "#06b6d4" },
          { icon: "💳", label: "Debit / Credit Card", sub: "Visa, Mastercard, RuPay", color: "#8b5cf6" },
          { icon: "📱", label: "UPI Transfer", sub: "Pay via any UPI app", color: "#10b981" },
        ].map(m => (
          <div key={m.label} onClick={handleAddMoney} style={{ ...S.card, padding: 16, marginTop: 12, display: "flex", alignItems: "center", gap: 14, cursor: "pointer" }}>
            <div style={{ width: 46, height: 46, borderRadius: 14, background: `${m.color}18`, border: `1px solid ${m.color}30`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22 }}>{m.icon}</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{m.label}</div>
              <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{m.sub}</div>
            </div>
            <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 20 }}>›</div>
          </div>
        ))}
      </>}
      {addMoneyStep === 3 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", paddingTop: 50 }}>
          <div style={{ width: 90, height: 90, borderRadius: 45, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 44, marginBottom: 22 }}>✓</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 8 }}>Money Added!</div>
          <div style={{ fontSize: 34, fontWeight: 900, color: "#4ade80", marginBottom: 32 }}>₹{Number(addAmount).toLocaleString("en-IN")}</div>
          <div onClick={() => { setAddAmount(""); setAddMoneyStep(1); setScreen("home"); }} style={S.gradBtn(false)}>Back to Home</div>
        </div>
      )}
    </div>
  );

  const ScanScreen = () => {
    const qrData = `upi://pay?pa=${upiId}&pn=${encodeURIComponent(userName)}&cu=INR`;
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData)}&bgcolor=0d0d1f&color=8b5cf6&qzone=2`;
    return (
      <div style={{ padding: "16px 20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
          <div onClick={goBack} style={S.backBtn}>←</div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Scan & Pay</div>
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          {[["my-qr", "My QR Code"], ["pay-upi", "Pay via UPI"]].map(([key, label]) => (
            <div key={key} onClick={() => setScanTab(key)} style={{ flex: 1, padding: "10px", borderRadius: 12, textAlign: "center", fontSize: 13, fontWeight: 700, cursor: "pointer", background: scanTab === key ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.07)", color: scanTab === key ? "#fff" : "rgba(255,255,255,0.4)" }}>{label}</div>
          ))}
        </div>
        {scanTab === "my-qr" && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16 }}>
            <div style={{ ...S.card, padding: 20, display: "flex", flexDirection: "column", alignItems: "center", gap: 14, width: "100%", boxSizing: "border-box" }}>
              <div style={{ width: 200, height: 200, borderRadius: 16, overflow: "hidden", border: "2px solid rgba(139,92,246,0.4)", background: "#0a0a18", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <img src={qrUrl} alt="QR Code" width="200" height="200" style={{ display: "block" }} />
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 16, fontWeight: 800, color: "#fff", marginBottom: 4 }}>{userName}</div>
                <div style={{ fontSize: 13, color: "#8b5cf6", fontWeight: 700 }}>{upiId}</div>
              </div>
            </div>
            <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)", textAlign: "center" }}>Share this QR code to receive payments instantly</div>
          </div>
        )}
        {scanTab === "pay-upi" && (
          <div>
            <div style={{ ...S.card, padding: 18, marginBottom: 14 }}>
              <div style={S.label}>ENTER UPI ID TO PAY</div>
              <input value={payUpi} onChange={e => setPayUpi(e.target.value.toLowerCase().replace(/\s/g, ""))} placeholder="e.g. alok@qpay" style={{ ...S.input }} />
            </div>
            <div onClick={() => { if (payUpi.includes("@")) { setSelectedContact({ name: payUpi, upi: payUpi, avatar: "👤", color: "#8b5cf6" }); setSendStep(2); navigate("send"); } }} style={S.gradBtn(!payUpi.includes("@"))}>Pay Now →</div>
          </div>
        )}
      </div>
    );
  };


  const HistoryScreen = () => (
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
      {filteredTx.map(tx => <TxRow key={tx.id} tx={tx} />)}
    </div>
  );

  const RequestScreen = () => (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={goBack} style={S.backBtn}>←</div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Request Money</div>
      </div>
      <div style={{ textAlign: "center", marginBottom: 22 }}>
        <div style={{ ...S.card, padding: 24, display: "inline-block" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 4, width: 120, height: 120 }}>
            {Array(9).fill(0).map((_, i) => <div key={i} style={{ background: i % 2 === 0 ? "#8b5cf6" : "transparent", borderRadius: 3 }} />)}
          </div>
        </div>
        <div style={{ marginTop: 12, fontSize: 15, fontWeight: 700, color: "#fff" }}>{upiId}</div>
        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>Show this QR to receive money</div>
      </div>
      <div style={{ ...S.card, padding: 16, marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>YOUR UPI ID</div>
        <div style={{ fontSize: 16, fontWeight: 800, color: "#fff" }}>{upiId}</div>
      </div>
      <div style={S.gradBtn(false)}>Share UPI ID</div>
    </div>
  );

  const BillsScreen = () => (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={goBack} style={S.backBtn}>←</div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Pay Bills</div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        {BILLS.map(b => (
          <div key={b.id} style={{ ...S.card, padding: "18px 10px", textAlign: "center", cursor: "pointer" }}>
            <div style={{ fontSize: 34, marginBottom: 8 }}>{b.icon}</div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff" }}>{b.name}</div>
          </div>
        ))}
      </div>
    </div>
  );

  const ProfileScreen = () => {
    const totalSent = transactions.filter(t => t.type === "sent").reduce((s, t) => s + t.amount, 0);
    const totalReceived = transactions.filter(t => t.type === "received").reduce((s, t) => s + t.amount, 0);
    const memberSince = user?.createdAt ? new Date(user.createdAt).toLocaleDateString("en-IN", { month: "short", year: "numeric" }) : "Today";
    const SETTINGS = [
      { icon: "🔔", label: "Notifications", sub: "Manage alerts & sounds" },
      { icon: "🔒", label: "Privacy & Security", sub: "2FA, biometrics" },
      { icon: "💳", label: "Linked Cards & Banks", sub: "Manage payment methods" },
      { icon: "❓", label: "Help & Support", sub: "FAQs, chat with us" },
      { icon: "📄", label: "Terms & Privacy", sub: "Legal information" },
    ];
    return (
      <div style={{ padding: "16px 20px 30px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
          <div onClick={goBack} style={S.backBtn}>←</div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>My Profile</div>
        </div>

        {/* Avatar + name + UPI */}
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 20 }}>
          <div style={{ width: 80, height: 80, borderRadius: 40, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 34, fontWeight: 900, color: "#fff", marginBottom: 12, boxShadow: "0 0 30px rgba(139,92,246,0.4)" }}>{userInitial}</div>
          <div style={{ fontSize: 20, fontWeight: 900, color: "#fff", marginBottom: 4 }}>{userName}</div>
          <div style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", marginBottom: 6 }}>+91 {user?.phone || ""}</div>
          <div style={{ background: "rgba(139,92,246,0.15)", border: "1px solid rgba(139,92,246,0.35)", borderRadius: 20, padding: "5px 14px", fontSize: 12, color: "#a78bfa", fontWeight: 700 }}>⚡ {upiId}</div>
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
            { icon: "🎂", label: "Date of Birth", value: user?.dob ? new Date(user.dob + "T00:00:00").toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" }) : "—" },
            { icon: "📅", label: "Member Since", value: memberSince },
            { icon: "📱", label: "Registered Phone", value: `+91 ${user?.phone || ""}` },
          ].map((item, i, arr) => (
            <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderBottom: i < arr.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none" }}>
              <span style={{ fontSize: 18 }}>{item.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)" }}>{item.label}</div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginTop: 2 }}>{item.value}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Edit display name */}
        <div style={{ ...S.card, padding: 18, marginBottom: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: "#8b5cf6", marginBottom: 14, letterSpacing: 0.5 }}>EDIT DISPLAY NAME</div>
          <div style={S.label}>FULL NAME</div>
          <input value={profile.name} onChange={e => setProfile(p => ({ ...p, name: e.target.value }))} placeholder={userName} style={{ ...S.input, marginBottom: 14 }} />
          <div onClick={handleSaveProfile} style={{ ...S.gradBtn(false), fontSize: 14 }}>
            {profileSaved ? "✓ Saved!" : "Save Changes"}
          </div>
        </div>

        {/* Settings rows */}
        <div style={{ ...S.card, marginBottom: 16, overflow: "hidden" }}>
          {SETTINGS.map((item, i) => (
            <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 14, padding: "13px 18px", borderBottom: i < SETTINGS.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none", cursor: "pointer" }}>
              <div style={{ width: 36, height: 36, borderRadius: 11, background: "rgba(139,92,246,0.12)", border: "1px solid rgba(139,92,246,0.2)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, flexShrink: 0 }}>{item.icon}</div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: "#fff" }}>{item.label}</div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginTop: 2 }}>{item.sub}</div>
              </div>
              <div style={{ color: "rgba(255,255,255,0.2)", fontSize: 18 }}>›</div>
            </div>
          ))}
        </div>

        <div onClick={handleLogout} style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 18, padding: 16, textAlign: "center", fontSize: 15, fontWeight: 900, color: "#f43f5e", cursor: "pointer" }}>
          🚪 &nbsp;Logout
        </div>
        <div style={{ textAlign: "center", marginTop: 20, fontSize: 11, color: "rgba(255,255,255,0.15)" }}>QuantumPay v1.0.0 · Member since {memberSince}</div>
      </div>
    );
  };


  const renderScreen = () => {
    if (screen === "send") return <SendScreen />;
    if (screen === "scan") return <ScanScreen />;
    if (screen === "history") return <HistoryScreen />;
    if (screen === "request") return <RequestScreen />;
    if (screen === "bills") return <BillsScreen />;
    if (screen === "addmoney") return <AddMoneyScreen />;
    if (screen === "profile") return <ProfileScreen />;
    return <HomeScreen />;
  };

  return (
    <PhoneFrame>
      <div style={{ background: "#0a0a18", padding: "10px 24px 6px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12, color: "rgba(255,255,255,0.5)", flexShrink: 0 }}>
        <span style={{ fontWeight: 800 }}>9:41</span>
        <span style={{ fontSize: 11, fontWeight: 900, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", letterSpacing: 2 }}>⚛ QUANTUMPAY</span>
        <span>🔋</span>
      </div>
      <div style={{ flex: 1, overflowY: "auto", scrollbarWidth: "none" }}>{renderScreen()}</div>
      <div style={{ background: "rgba(10,10,24,0.97)", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-around", padding: "10px 0 18px", flexShrink: 0 }}>
        {[["🏠", "Home", "home"], ["↑↓", "Pay", "send"], ["⊡", "Scan", "scan"], ["📋", "History", "history"]].map(([icon, label, key]) => (
          <div key={key} onClick={() => { if (key === "send") setSendStep(1); setScreen(key); }} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, cursor: "pointer", opacity: screen === key ? 1 : 0.35 }}>
            <span style={{ fontSize: 20 }}>{icon}</span>
            <span style={{ fontSize: 10, color: screen === key ? "#8b5cf6" : "rgba(255,255,255,0.4)", fontWeight: screen === key ? 800 : 400 }}>{label}</span>
          </div>
        ))}
        <div onClick={() => setScreen("profile")} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, cursor: "pointer", opacity: screen === "profile" ? 1 : 0.35 }}>
          <div style={{ width: 24, height: 24, borderRadius: 12, background: screen === "profile" ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.2)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 900, color: "#fff" }}>{userInitial}</div>
          <span style={{ fontSize: 10, color: screen === "profile" ? "#8b5cf6" : "rgba(255,255,255,0.4)", fontWeight: screen === "profile" ? 800 : 400 }}>Profile</span>
        </div>
      </div>
    </PhoneFrame>
  );
}