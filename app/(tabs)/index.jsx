import { collection, doc, getDoc, getDocs, limit, onSnapshot, orderBy, query, runTransaction, setDoc, updateDoc, where } from 'firebase/firestore';
import { useEffect, useState } from "react";
import { decryptTransaction, encryptTransaction, generatePQCKeys, getPQCPrivateKey, hashMpin, signTransaction, storePQCPrivateKey } from "../../lib/crypto";
import { db, getSession, signInUser, signOutUser, signUpUser } from "../../lib/firebase";
import { Session } from "../../lib/session";
import { playSuccessSound } from "../../lib/utils";
import { sendMoneyApi } from '../../lib/api';

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
import { BatteryFull, Home as HomeIcon, ScanLine, History as HistoryIcon, Atom } from 'lucide-react';

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
  const [contacts, setContacts] = useState([]);
  const [linkedBanks, setLinkedBanks] = useState([]);
  const [bankStep, setBankStep] = useState(1);
  const [selectedBank, setSelectedBank] = useState(null);
  const [bankOtp, setBankOtp] = useState("");
  const [selectedTx, setSelectedTx] = useState(null);

  // ═══════════════════════════════════════════════════════════════════════════
  // DATA LAYER
  // ═══════════════════════════════════════════════════════════════════════════
  const loadUserData = async (phone) => {
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
      const validTxs = decrypted.filter(tx => !isNaN(Number(tx.amount)));
      setTransactions(validTxs.map(tx => {
        const isTrueSend = tx.sender_phone === phone && tx.receiver_phone !== phone;
        return {
          id: tx.id,
          name: isTrueSend ? (tx.receiver_name || tx.receiver_phone) : (tx.sender_name || tx.sender_phone),
          type: isTrueSend ? "sent" : "received",
          amount: Number(tx.amount),
          time: new Date(tx.created_at).toLocaleString("en-IN", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
          note: tx.note || "Payment",
          verified: !!tx.signature,
        };
      }));
    }
  };

  useEffect(() => {
    const init = async () => {
      console.log("QuantumPay mode: ☁️ CLOUD");
      const phone = Session.get();
      if (phone) {
        const session = await getSession();
        if (session) {
          await loadUserData(phone);
          setAuthStep("app");
          // Start real-time listener only after authenticated
          const txRef = collection(db, "transactions");
          const unsubscribe = onSnapshot(txRef, (snapshot) => {
            snapshot.docChanges().forEach((change) => {
              if (change.type === "added") {
                const tx = change.doc.data();
                const cp = Session.get();
                if (cp && (tx.sender_phone === cp || tx.receiver_phone === cp)) {
                  loadUserData(cp);
                }
              }
            });
          });
          return () => unsubscribe();
        }
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
    const docRef = doc(db, "profiles", regPhone);
    const docSnap = await getDoc(docRef);
    if (docSnap.exists()) { setRegError("Already registered. Please login."); return; }
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
    const q = query(collection(db, "profiles"), where("upi_id", "==", regUpi), limit(1));
    const querySnapshot = await getDocs(q);
    if (!querySnapshot.empty) { setRegError("This UPI ID is already taken."); return; }
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
      const { data: authData, error: authErr } = await signUpUser(regPhone, hashedPin);
      if (authErr) { setRegError("Registration failed: " + authErr.message); return; }
      const userId = authData?.user?.uid;
      try {
        await setDoc(doc(db, "profiles", regPhone), { phone: regPhone, name: regName, dob: regDob, upi_id: regUpi, mpin: hashedPin, balance: 0, public_key: pqcKeys.publicKey, user_id: userId, created_at: new Date().toISOString() });
      } catch (error) { setRegError("Registration failed: " + error.message); return; }
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
      Session.set(loginPhone); await loadUserData(loginPhone);
      setLoginError(""); setAuthStep("welcome");
      setTimeout(() => setAuthStep("app"), 2000);
    }
  };

  const handleLogout = async () => {
    await signOutUser();
    Session.clear();
    setUser(null); setProfile({ name: "", phone: "" }); setBalance(0); setTransactions([]);
    setLoginPhone(""); setLoginMpin(""); setLoginError("");
    setRegPhone(""); setRegName(""); setRegDob(""); setRegUpi(""); setRegMpin(""); setRegMpinConfirm(""); setRegError("");
    setScreen("home"); setAuthStep("login");
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // APP HANDLERS
  // ═══════════════════════════════════════════════════════════════════════════

  const handleSend = async () => {
    if (!selectedContact) return;
    const amt = Number(amount);
    const senderPhone = Session.get();
    const senderName = profile.name || user?.name || "Someone";
    const recipientUpi = selectedContact.upi;

    const recipientQSingle = query(collection(db, "profiles"), where("upi_id", "==", recipientUpi), limit(1));
    const recipientSnapSingle = await getDocs(recipientQSingle);
    const recipientPhone = !recipientSnapSingle.empty ? recipientSnapSingle.docs[0].data().phone : recipientUpi;
    const rawTx = { sender_phone: senderPhone, sender_name: senderName, receiver_phone: recipientPhone, receiver_name: selectedContact.name, amount: amt, note: note || "Payment", created_at: new Date().toISOString() };
    
    const senderEncTx = await encryptTransaction(senderPhone, rawTx);
    let receiverEncTx = null;
    if (!recipientSnapSingle.empty) {
      receiverEncTx = await encryptTransaction(recipientPhone, rawTx);
    }

    const res = await sendMoneyApi({
        senderPhone, recipientUpi, amount: amt, senderEncTx, receiverEncTx
    });

    if (res.error) {
       alert("Failed to send: " + res.error);
       return;
    }

    const tx = { id: Date.now(), name: selectedContact.name, type: "sent", amount: amt, time: "Just now", note: note || "Payment" };
    setTransactions(p => [tx, ...p]); setBalance(b => b - amt); playSuccessSound(); setSendStep(4);
  };

  const handleAddMoney = async () => {
    // The Stripe Webhook will handle all database logic.
    // We only need to play the sound and change the UI step.
    const amt = Number(addAmount); if (!amt) return;
    playSuccessSound(); 
    setAddMoneyStep(3);
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
    if (screen === "profile") return <ProfileScreen userName={userName} userInitial={userInitial} upiId={upiId} user={user} profile={profile} transactions={transactions} handleLogout={handleLogout} goBack={goBack} setBankStep={setBankStep} setScreen={setScreen} linkedBanks={linkedBanks} />;
    if (screen === "banks") return <BanksScreen bankStep={bankStep} setBankStep={setBankStep} selectedBank={selectedBank} setSelectedBank={setSelectedBank} bankOtp={bankOtp} setBankOtp={setBankOtp} linkedBanks={linkedBanks} setLinkedBanks={setLinkedBanks} user={user} setScreen={setScreen} />;
    return <HomeScreen userName={userName} userInitial={userInitial} balance={balance} balanceVisible={balanceVisible} setBalanceVisible={setBalanceVisible} transactions={transactions} contacts={contacts} setSelectedTx={setSelectedTx} navigate={navigate} setAddMoneyStep={setAddMoneyStep} setSendStep={setSendStep} />;
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN RENDER
  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <>
      <PhoneFrame>
        <div style={{ background: "#0a0a18", padding: "10px 24px 6px", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 12, color: "rgba(255,255,255,0.5)", flexShrink: 0 }}>
          <span style={{ fontWeight: 800 }}>9:41</span>
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <Atom size={14} color="#06b6d4" />
            <span style={{ fontSize: 11, fontWeight: 900, background: "linear-gradient(135deg,#8b5cf6,#06b6d4)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", letterSpacing: 2 }}>QUANTUMPAY</span>
          </div>
          <span><BatteryFull size={14} color="rgba(255,255,255,0.5)" /></span>
        </div>
        <div style={{ flex: 1, overflowY: "auto", scrollbarWidth: "none", position: "relative" }}>
          {selectedTx ? <TransactionReceipt selectedTx={selectedTx} setSelectedTx={setSelectedTx} linkedBanks={linkedBanks} /> : renderScreen()}
        </div>
        <div style={{ background: "rgba(10,10,24,0.97)", borderTop: "1px solid rgba(255,255,255,0.06)", display: "flex", justifyContent: "space-around", padding: "10px 0 18px", flexShrink: 0 }}>
          {[[HomeIcon, "Home", "home"], [ScanLine, "Scan", "scan"], [HistoryIcon, "History", "history"]].map(([Icon, label, key]) => (
            <div key={key} onClick={() => setScreen(key)} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4, cursor: "pointer", opacity: screen === key ? 1 : 0.55 }}>
              <div style={{ height: 20, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <Icon size={20} color={screen === key ? "#8b5cf6" : "rgba(255,255,255,0.5)"} />
              </div>
              <span style={{ fontSize: 10, color: screen === key ? "#8b5cf6" : "rgba(255,255,255,0.5)", fontWeight: screen === key ? 800 : 600 }}>{label}</span>
            </div>
          ))}
        </div>
      </PhoneFrame>
    </>
  );
}