import { collection, doc, getDoc, getDocs, limit, onSnapshot, orderBy, query, runTransaction, setDoc, updateDoc, where } from 'firebase/firestore';
import { useEffect, useState } from "react";
import { decryptTransaction, encryptTransaction, generatePQCKeys, getPQCPrivateKey, hashMpin, signTransaction, storePQCPrivateKey } from "../../lib/crypto";
import { db, getSession, signInUser, signOutUser, signUpUser } from "../../lib/firebase";
import { Session } from "../../lib/session";
import { LocalDB } from "../../lib/localdb";
import { checkFirebase, playSuccessSound } from "../../lib/utils";

// ── Auth Screens ─────────────────────────────────────────────────────────────
import SplashScreen from "../../screens/auth/SplashScreen";
import LoginScreen from "../../screens/auth/LoginScreen";
import RegisterPhoneScreen from "../../screens/auth/RegisterPhoneScreen";
import RegisterProfileScreen from "../../screens/auth/RegisterProfileScreen";
import RegisterUpiScreen from "../../screens/auth/RegisterUpiScreen";
import RegisterMpinScreen from "../../screens/auth/RegisterMpinScreen";
import RegisterConfirmScreen from "../../screens/auth/RegisterConfirmScreen";
import WelcomeScreen from "../../screens/auth/WelcomeScreen";

// ── App Screens ──────────────────────────────────────────────────────────────
import HomeScreen from "../../screens/HomeScreen";
import SendScreen from "../../screens/SendScreen";
import AddMoneyScreen from "../../screens/AddMoneyScreen";
import ScanScreen from "../../screens/ScanScreen";
import HistoryScreen from "../../screens/HistoryScreen";
import RequestScreen from "../../screens/RequestScreen";
import BillsScreen from "../../screens/BillsScreen";
import ProfileScreen from "../../screens/ProfileScreen";
import BanksScreen from "../../screens/BanksScreen";
import TransactionReceipt from "../../screens/TransactionReceipt";

// ── Shared Components ────────────────────────────────────────────────────────
import PhoneFrame from "../../components/PhoneFrame";

export default function QuantumPay() {
  // ═══════════════════════════════════════════════════════════════════════════
  // STATE
  // ═══════════════════════════════════════════════════════════════════════════
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
  const [contacts, setContacts] = useState([]);
  const [linkedBanks, setLinkedBanks] = useState([]);
  const [bankStep, setBankStep] = useState(1);
  const [selectedBank, setSelectedBank] = useState(null);
  const [bankOtp, setBankOtp] = useState("");
  const [selectedTx, setSelectedTx] = useState(null);

  // ═══════════════════════════════════════════════════════════════════════════
  // DATA LAYER
  // ═══════════════════════════════════════════════════════════════════════════
  const loadUserData = async (phone, isCloud) => {
    const cloud = isCloud !== undefined ? isCloud : cloudMode;
    if (cloud) {
      const profileRef = doc(db, "profiles", phone);
      const docSnap = await getDoc(profileRef);
      if (docSnap.exists()) {
        const p = docSnap.data();
        setBalance(p.balance || 0);
        setProfile({ name: p.name || "", phone });
        setUser({ phone, name: p.name, dob: p.dob, upiId: p.upi_id, createdAt: p.created_at });
        if (p.linked_banks) setLinkedBanks(p.linked_banks);
      }
      const txRef = collection(db, "transactions");
      const q = query(txRef, orderBy("created_at", "desc"), limit(50));
      const querySnapshot = await getDocs(q);
      const txData = querySnapshot.docs
        .map(doc => ({ id: doc.id, ...doc.data() }))
        .filter(tx => tx.sender_phone === phone || tx.receiver_phone === phone);
      if (txData.length > 0) {
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
        if (d.linkedBanks) setLinkedBanks(d.linkedBanks);
      }
    }
  };

  useEffect(() => {
    const init = async () => {
      const isCloud = await checkFirebase();
      setCloudMode(isCloud);
      console.log("QuantumPay mode:", isCloud ? "☁️ CLOUD" : "💾 LOCAL");
      const phone = Session.get();
      if (phone) {
        if (isCloud) {
          const session = await getSession();
          if (session) { await loadUserData(phone, true); setAuthStep("app"); }
        } else {
          if (LocalDB.getUsers()[phone]) { await loadUserData(phone, false); setAuthStep("app"); }
        }
      }
      if (isCloud) {
        const txRef = collection(db, "transactions");
        const unsubscribe = onSnapshot(txRef, (snapshot) => {
          snapshot.docChanges().forEach((change) => {
            if (change.type === "added") {
              const tx = change.doc.data();
              const cp = Session.get();
              if (cp && (tx.sender_phone === cp || tx.receiver_phone === cp)) {
                loadUserData(cp, true);
              }
            }
          });
        });
        return () => unsubscribe();
      } else {
        const h = (e) => { if (e.key === "qp_users") { const cp = Session.get(); if (cp) loadUserData(cp, false); } };
        window.addEventListener("storage", h);
        return () => window.removeEventListener("storage", h);
      }
    };
    init();
  }, []);

  // ═══════════════════════════════════════════════════════════════════════════
  // NAVIGATION
  // ═══════════════════════════════════════════════════════════════════════════
  const navigate = (to) => { setPrevScreen(screen); setScreen(to); };
  const goBack = () => setScreen(prevScreen);

  // ═══════════════════════════════════════════════════════════════════════════
  // AUTH HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════
  const handleRegisterPhone = async () => {
    if (!/^\d{10}$/.test(regPhone)) { setRegError("Enter a valid 10-digit phone number"); return; }
    if (cloudMode) {
      const docRef = doc(db, "profiles", regPhone);
      const docSnap = await getDoc(docRef);
      if (docSnap.exists()) { setRegError("Already registered. Please login."); return; }
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
      const q = query(collection(db, "profiles"), where("upi_id", "==", regUpi), limit(1));
      const querySnapshot = await getDocs(q);
      if (!querySnapshot.empty) { setRegError("This UPI ID is already taken."); return; }
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
        const { data: authData, error: authErr } = await signUpUser(regPhone, hashedPin);
        if (authErr) { setRegError("Registration failed: " + authErr.message); return; }
        const userId = authData?.user?.uid;
        try {
          await setDoc(doc(db, "profiles", regPhone), { phone: regPhone, name: regName, dob: regDob, upi_id: regUpi, mpin: hashedPin, balance: 0, public_key: pqcKeys.publicKey, user_id: userId, created_at: new Date().toISOString() });
        } catch (error) { setRegError("Registration failed: " + error.message); return; }
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
        const { error } = await signInUser(loginPhone, hashedVal);
        if (error) {
          const docRef = doc(db, "profiles", loginPhone);
          const docSnap = await getDoc(docRef);
          if (!docSnap.exists()) { setLoginError("Phone not registered. Please sign up."); setLoginMpin(""); return; }
          const data = docSnap.data();
          if (data.mpin !== hashedVal) { setLoginError("Wrong MPIN. Please try again."); setLoginMpin(""); return; }
          const { data: authData } = await signUpUser(loginPhone, hashedVal);
          if (authData?.user?.uid) {
            await updateDoc(docRef, { user_id: authData.user.uid });
          }
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

  // ═══════════════════════════════════════════════════════════════════════════
  // APP HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════
  const handleSaveProfile = async () => {
    const phone = Session.get();
    if (phone) {
      if (cloudMode) { await updateDoc(doc(db, "profiles", phone), { name: profile.name }); }
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
    setTransactions(p => [tx, ...p]); setBalance(b => b - amt); playSuccessSound(); setSendStep(4);

    if (cloudMode) {
      await runTransaction(db, async (transaction) => {
        const senderRef = doc(db, "profiles", senderPhone);
        const senderDoc = await transaction.get(senderRef);
        if (!senderDoc.exists()) throw new Error("Sender not found");
        transaction.update(senderRef, { balance: senderDoc.data().balance - amt });
        const recipientQ = query(collection(db, "profiles"), where("upi_id", "==", recipientUpi), limit(1));
        const recipientSnap = await getDocs(recipientQ);
        if (!recipientSnap.empty) {
          const recipientRef = doc(db, "profiles", recipientSnap.docs[0].id);
          const recipientDoc = await transaction.get(recipientRef);
          if (recipientDoc.exists()) {
            transaction.update(recipientRef, { balance: recipientDoc.data().balance + amt });
          }
        }
      });
      const recipientQSingle = query(collection(db, "profiles"), where("upi_id", "==", recipientUpi), limit(1));
      const recipientSnapSingle = await getDocs(recipientQSingle);
      const recipientPhone = !recipientSnapSingle.empty ? recipientSnapSingle.docs[0].data().phone : recipientUpi;
      const rawTx = { sender_phone: senderPhone, sender_name: senderName, receiver_phone: recipientPhone, receiver_name: selectedContact.name, amount: amt, note: note || "Payment", created_at: new Date().toISOString() };
      const privKey = getPQCPrivateKey(senderPhone);
      const signature = privKey ? signTransaction(privKey, { sender: senderPhone, receiver: rawTx.receiver_phone, amount: amt, time: Date.now() }) : null;
      const senderEncTx = await encryptTransaction(senderPhone, rawTx);
      await setDoc(doc(collection(db, "transactions")), { ...senderEncTx, signature, created_at: rawTx.created_at });
      if (!recipientSnapSingle.empty) {
        const receiverEncTx = await encryptTransaction(recipientPhone, rawTx);
        await setDoc(doc(collection(db, "transactions")), { ...receiverEncTx, signature, created_at: rawTx.created_at });
      }
    } else {
      const users = LocalDB.getUsers();
      users[senderPhone].balance = (users[senderPhone].balance || 0) - amt;
      users[senderPhone].transactions = [{ id: Date.now(), name: selectedContact.name, type: "sent", amount: amt, time: "Just now", note: note || "Payment" }, ...(users[senderPhone].transactions || [])];
      const rp = Object.keys(users).find(ph => users[ph].upiId === recipientUpi);
      if (rp) {
        users[rp].balance = (users[rp].balance || 0) + amt;
        users[rp].transactions = [{ id: Date.now() + 1, name: senderName, type: "received", amount: amt, time: "Just now", note: "Payment from " + senderName }, ...(users[rp].transactions || [])];
      }
      LocalDB.saveUsers(users);
    }
  };

  const handleAddMoney = async () => {
    const amt = Number(addAmount); if (!amt) return;
    const phone = Session.get();
    const tx = { id: Date.now(), name: "Wallet Top-up", type: "received", amount: amt, time: "Just now", note: "Added to wallet" };
    setTransactions(p => [tx, ...p]); setBalance(b => b + amt); playSuccessSound(); setAddMoneyStep(3);
    if (cloudMode) {
      const phoneRef = doc(db, "profiles", phone);
      await updateDoc(phoneRef, { balance: balance + amt });
      const rawTx = { sender_phone: phone, sender_name: "Wallet Top-up", receiver_phone: phone, receiver_name: profile.name || "Self", amount: amt, note: "Added to wallet", created_at: new Date().toISOString() };
      const encTx = await encryptTransaction(phone, rawTx);
      await setDoc(doc(collection(db, "transactions")), { ...encTx, created_at: rawTx.created_at });
    } else {
      const users = LocalDB.getUsers();
      users[phone].balance = (users[phone].balance || 0) + amt;
      users[phone].transactions = [{ id: Date.now(), name: "Wallet Top-up", type: "received", amount: amt, time: "Just now", note: "Added to wallet" }, ...(users[phone].transactions || [])];
      LocalDB.saveUsers(users);
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // DERIVED VALUES
  // ═══════════════════════════════════════════════════════════════════════════
  const userName = profile.name || user?.name || "User";
  const userInitial = userName.charAt(0).toUpperCase();
  const upiId = user?.upiId || (userName.toLowerCase().replace(/\s+/g, "").slice(0, 10) + "@qpay");

  // ═══════════════════════════════════════════════════════════════════════════
  // AUTH SCREEN ROUTING
  // ═══════════════════════════════════════════════════════════════════════════
  if (authStep === "splash") return <SplashScreen onGetStarted={() => setAuthStep("login")} />;
  if (authStep === "login") return <LoginScreen loginPhone={loginPhone} loginMpin={loginMpin} loginError={loginError} setLoginPhone={setLoginPhone} setLoginError={setLoginError} handleLoginMpin={handleLoginMpin} onRegister={() => { setRegPhone(""); setRegError(""); setAuthStep("register-phone"); }} />;
  if (authStep === "register-phone") return <RegisterPhoneScreen regPhone={regPhone} regError={regError} setRegPhone={setRegPhone} setRegError={setRegError} handleRegisterPhone={handleRegisterPhone} onBack={() => setAuthStep("login")} />;
  if (authStep === "register-profile") return <RegisterProfileScreen regName={regName} regDob={regDob} regError={regError} setRegName={setRegName} setRegDob={setRegDob} setRegError={setRegError} handleRegisterProfile={handleRegisterProfile} onBack={() => setAuthStep("register-phone")} />;
  if (authStep === "register-upi") return <RegisterUpiScreen regUpi={regUpi} regPhone={regPhone} regName={regName} regError={regError} setRegUpi={setRegUpi} setRegError={setRegError} handleRegisterUpi={handleRegisterUpi} onBack={() => setAuthStep("register-profile")} />;
  if (authStep === "register-mpin") return <RegisterMpinScreen regMpin={regMpin} regError={regError} handleSetMpin={handleSetMpin} onBack={() => setAuthStep("register-upi")} />;
  if (authStep === "register-confirm") return <RegisterConfirmScreen regMpinConfirm={regMpinConfirm} regError={regError} handleConfirmMpin={handleConfirmMpin} onBack={() => { setRegMpin(""); setRegMpinConfirm(""); setAuthStep("register-mpin"); }} />;
  if (authStep === "welcome") return <WelcomeScreen upiId={upiId} />;

  // ═══════════════════════════════════════════════════════════════════════════
  // APP SCREEN ROUTING
  // ═══════════════════════════════════════════════════════════════════════════
  const renderScreen = () => {
    if (screen === "send") return <SendScreen sendStep={sendStep} setSendStep={setSendStep} selectedContact={selectedContact} setSelectedContact={setSelectedContact} amount={amount} setAmount={setAmount} note={note} setNote={setNote} pin={pin} setPin={setPin} upiSearch={upiSearch} setUpiSearch={setUpiSearch} contacts={contacts} linkedBanks={linkedBanks} goBack={goBack} handleSend={handleSend} setBankStep={setBankStep} setScreen={setScreen} />;
    if (screen === "scan") return <ScanScreen upiId={upiId} userName={userName} scanTab={scanTab} setScanTab={setScanTab} payUpi={payUpi} setPayUpi={setPayUpi} goBack={goBack} navigate={navigate} setSelectedContact={setSelectedContact} setSendStep={setSendStep} />;
    if (screen === "history") return <HistoryScreen transactions={transactions} activeTab={activeTab} setActiveTab={setActiveTab} contacts={contacts} setSelectedTx={setSelectedTx} goBack={goBack} />;
    if (screen === "request") return <RequestScreen upiId={upiId} user={user} profile={profile} goBack={goBack} />;
    if (screen === "bills") return <BillsScreen goBack={goBack} />;
    if (screen === "addmoney") return <AddMoneyScreen addMoneyStep={addMoneyStep} setAddMoneyStep={setAddMoneyStep} addAmount={addAmount} setAddAmount={setAddAmount} balance={balance} linkedBanks={linkedBanks} goBack={goBack} handleAddMoney={handleAddMoney} setScreen={setScreen} />;
    if (screen === "profile") return <ProfileScreen userName={userName} userInitial={userInitial} upiId={upiId} user={user} profile={profile} setProfile={setProfile} transactions={transactions} profileSaved={profileSaved} handleSaveProfile={handleSaveProfile} handleLogout={handleLogout} goBack={goBack} setBankStep={setBankStep} setScreen={setScreen} linkedBanks={linkedBanks} />;
    if (screen === "banks") return <BanksScreen bankStep={bankStep} setBankStep={setBankStep} selectedBank={selectedBank} setSelectedBank={setSelectedBank} bankOtp={bankOtp} setBankOtp={setBankOtp} linkedBanks={linkedBanks} setLinkedBanks={setLinkedBanks} user={user} cloudMode={cloudMode} setScreen={setScreen} />;
    return <HomeScreen userName={userName} userInitial={userInitial} balance={balance} balanceVisible={balanceVisible} setBalanceVisible={setBalanceVisible} transactions={transactions} contacts={contacts} setSelectedTx={setSelectedTx} navigate={navigate} setAddMoneyStep={setAddMoneyStep} setSendStep={setSendStep} />;
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN RENDER
  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <PhoneFrame>
      <div style={{ background: "#0a0a18", padding: "10px 24px 6px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12, color: "rgba(255,255,255,0.5)", flexShrink: 0 }}>
        <span style={{ fontWeight: 800 }}>9:41</span>
        <span style={{ fontSize: 11, fontWeight: 900, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", letterSpacing: 2 }}>⚛ QUANTUMPAY</span>
        <span>🔋</span>
      </div>
      <div style={{ flex: 1, overflowY: "auto", scrollbarWidth: "none", position: "relative" }}>
        {selectedTx ? <TransactionReceipt selectedTx={selectedTx} setSelectedTx={setSelectedTx} linkedBanks={linkedBanks} /> : renderScreen()}
      </div>
      <div style={{ background: "rgba(10,10,24,0.97)", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-around", padding: "10px 0 18px", flexShrink: 0 }}>
        {[["🏠", "Home", "home"], ["💰", "Pay", "send"], ["🔍", "Scan", "scan"], ["📋", "History", "history"]].map(([icon, label, key]) => (
          <div key={key} onClick={() => { if (key === "send") setSendStep(1); setScreen(key); }} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, cursor: "pointer", opacity: screen === key ? 1 : 0.55 }}>
            <span style={{ fontSize: 20 }}>{icon}</span>
            <span style={{ fontSize: 10, color: screen === key ? "#8b5cf6" : "rgba(255,255,255,0.5)", fontWeight: screen === key ? 800 : 600 }}>{label}</span>
          </div>
        ))}
        <div onClick={() => setScreen("profile")} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, cursor: "pointer", opacity: screen === "profile" ? 1 : 0.55 }}>
          <div style={{ width: 24, height: 24, borderRadius: 12, background: screen === "profile" ? "linear-gradient(135deg,#8b5cf6,#06b6d4)" : "rgba(255,255,255,0.2)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 900, color: "#fff" }}>{userInitial}</div>
          <span style={{ fontSize: 10, color: screen === "profile" ? "#8b5cf6" : "rgba(255,255,255,0.5)", fontWeight: screen === "profile" ? 800 : 600 }}>Profile</span>
        </div>
      </div>
    </PhoneFrame>
  );
}