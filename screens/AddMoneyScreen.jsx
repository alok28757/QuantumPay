// QuantumPay — Add money screen (Razorpay)
import { S } from '../constants/styles';
import { ArrowLeft, ArrowRight, Check } from 'lucide-react';

import { useRazorpay } from '../lib/razorpayWrapper';
import { createRazorpayOrder, verifyRazorpayPayment } from '../lib/api';
import { Session } from '../lib/session';

export default function AddMoneyScreen({
  addMoneyStep, setAddMoneyStep, addAmount, setAddAmount,
  balance, goBack, handleAddMoney, setScreen,
}) {
  const { openCheckout } = useRazorpay();

  const handleRazorpayCheckout = async (phone) => {
    if (!addAmount) return;
    try {
      const { data, error } = await createRazorpayOrder(Number(addAmount), phone);
      if (error || !data) throw new Error(error || "Failed to create order");

      // Open Razorpay checkout
      const response = await openCheckout({
        key: data.key,
        amount: data.amount,
        currency: data.currency,
        order_id: data.orderId,
        name: "QuantumPay",
        description: "Wallet Top-up",
        prefill: {
          contact: phone,
        },
        theme: {
          color: "#8b5cf6",
        },
      });

      // Payment successful — verify signature on backend
      const verifyRes = await verifyRazorpayPayment({
        razorpay_order_id: response.razorpay_order_id,
        razorpay_payment_id: response.razorpay_payment_id,
        razorpay_signature: response.razorpay_signature,
        phone,
        amount: Number(addAmount),
      });

      if (verifyRes.error) throw new Error(verifyRes.error);

      // Backend verified and credited — update UI
      handleAddMoney();
    } catch (e) {
      if (e.message === "Payment cancelled by user") return;
      console.warn("Payment failed:", e.message);
      alert("Payment Failed: " + e.message);
    }
  };

  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 22 }}>
        <div onClick={() => addMoneyStep > 1 ? setAddMoneyStep(s => s - 1) : goBack()} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
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
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div onClick={() => addAmount && handleRazorpayCheckout(Session.get())} style={{ ...S.gradBtn(!addAmount), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Proceed with Razorpay <ArrowRight size={18} color="#fff" /></div>
          <div onClick={() => addAmount && handleAddMoney(addAmount)} style={{ ...S.gradBtn(!addAmount), display: "flex", alignItems: "center", justifyContent: "center", gap: 8, background: addAmount ? "rgba(16,185,129,0.2)" : undefined, border: "1px solid rgba(16,185,129,0.5)" }}>
            <Check size={16} color="#4ade80" /> Demo Pay (Instant)
          </div>
        </div>
      </>}
      {addMoneyStep === 3 && (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", paddingTop: 50 }}>
          <div style={{ width: 90, height: 90, borderRadius: 45, background: "linear-gradient(135deg,#10b981,#4ade80)", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: 22, boxShadow: "0 0 40px rgba(16,185,129,0.3)", animation: "pulseCheck 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275) both" }}><Check size={44} color="#fff" /></div>
          <div style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 8 }}>Money Added!</div>
          <div style={{ fontSize: 34, fontWeight: 900, color: "#4ade80", marginBottom: 32 }}>₹{Number(addAmount).toLocaleString("en-IN")}</div>
          <div onClick={() => { setAddAmount(""); setAddMoneyStep(1); setScreen("home"); }} style={S.gradBtn(false)}>Back to Home</div>
        </div>
      )}
    </div>
  );
}
