// QuantumPay — Scan & Pay screen
import { useEffect, useRef, useState } from 'react';
import { S } from '../constants/styles';
import { ArrowLeft, ArrowRight, Camera, Search, Square, AlertTriangle, QrCode } from 'lucide-react';

export default function ScanScreen({
  upiId, userName, scanTab, setScanTab, payUpi, setPayUpi,
  goBack, navigate, setSelectedContact, setSendStep,
}) {
  const scannerRef = useRef(null);
  const scannerInstanceRef = useRef(null);
  const [scanError, setScanError] = useState("");
  const [scanning, setScanning] = useState(false);

  // Cleanup scanner on tab switch or unmount
  useEffect(() => {
    return () => {
      if (scannerInstanceRef.current) {
        scannerInstanceRef.current.stop().catch(() => { });
        scannerInstanceRef.current = null;
      }
      setScanning(false);
    };
  }, [scanTab]);

  const qrData = `upi://pay?pa=${upiId}&pn=${encodeURIComponent(userName)}&cu=INR`;
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(qrData)}&bgcolor=0d0d1f&color=8b5cf6&qzone=2`;

  const startScanner = async () => {
    setScanError("");
    setScanning(true);
    try {
      const { Html5Qrcode } = await import("html5-qrcode");
      const scanner = new Html5Qrcode("qr-reader");
      scannerInstanceRef.current = scanner;
      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 220, height: 220 } },
        (decodedText) => {
          // Parse UPI QR: upi://pay?pa=xxx@qpay&pn=Name
          let upi = decodedText;
          if (decodedText.startsWith("upi://")) {
            const params = new URLSearchParams(decodedText.split("?")[1] || "");
            upi = params.get("pa") || decodedText;
          }
          scanner.stop().catch(() => { });
          scannerInstanceRef.current = null;
          setScanning(false);
          setPayUpi(upi);
          // Auto-navigate to send screen
          setSelectedContact({ name: upi, upi: upi, color: "#8b5cf6" });
          setSendStep(2);
          navigate("send");
        },
        () => { } // ignore scan failures
      );
    } catch (err) {
      setScanning(false);
      setScanError(err?.message?.includes("NotAllowed") ? "Camera access denied. Please allow camera permission." : "Camera not available on this device.");
    }
  };

  const stopScanner = () => {
    if (scannerInstanceRef.current) {
      scannerInstanceRef.current.stop().catch(() => { });
      scannerInstanceRef.current = null;
    }
    setScanning(false);
  };

  return (
    <div style={{ padding: "16px 20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
        <div onClick={goBack} style={S.backBtn}><ArrowLeft size={20} color="#fff" /></div>
        <div style={{ fontSize: 18, fontWeight: 900, color: "#fff" }}>Scan & Pay</div>
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
        {[["my-qr", "My QR Code"], ["scan-qr", "Scan QR"]].map(([key, label]) => (
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
      {scanTab === "scan-qr" && (
        <div>
          {/* QR Scanner Area */}
          <div style={{ ...S.card, padding: 20, marginBottom: 16, display: "flex", flexDirection: "column", alignItems: "center", gap: 14 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#8b5cf6", letterSpacing: 0.5, display: "flex", alignItems: "center", gap: 6 }}><QrCode size={16} /> SCAN QR CODE</div>
            <div id="qr-reader" ref={scannerRef} style={{ width: 260, height: 260, borderRadius: 16, overflow: "hidden", background: "#000", border: "2px solid rgba(16,185,129,0.4)" }}>
              {!scanning && (
                <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 12 }}>
                  <div style={{ color: "rgba(255,255,255,0.5)" }}><Camera size={48} /></div>
                  <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", textAlign: "center", padding: "0 20px" }}>Tap button below to open camera</div>
                </div>
              )}
            </div>
            {scanError && <div style={{ background: "rgba(244,63,94,0.1)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 12, padding: "10px 14px", fontSize: 12, color: "#f43f5e", width: "100%", boxSizing: "border-box", display: "flex", alignItems: "center", gap: 6 }}><AlertTriangle size={14} color="#f43f5e" /> {scanError}</div>}
            {!scanning ? (
              <div onClick={startScanner} style={{ ...S.gradBtn(false), width: "100%", boxSizing: "border-box", display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}><Search size={16} /> Start Scanner</div>
            ) : (
              <div onClick={stopScanner} style={{ background: "rgba(244,63,94,0.15)", border: "1px solid rgba(244,63,94,0.3)", borderRadius: 18, padding: "14px", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, fontSize: 14, fontWeight: 800, color: "#f43f5e", cursor: "pointer", width: "100%", boxSizing: "border-box" }}><Square size={16} fill="#f43f5e" /> Stop Scanner</div>
            )}
          </div>

          {/* Manual UPI fallback */}
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
            <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.1)" }} />
            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", fontWeight: 700 }}>OR</div>
            <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.1)" }} />
          </div>
          <div style={{ ...S.card, padding: 18, marginBottom: 14 }}>
            <div style={S.label}>ENTER UPI ID MANUALLY</div>
            <input value={payUpi} onChange={e => setPayUpi(e.target.value.toLowerCase().replace(/\s/g, ""))} placeholder="e.g. alok@qpay" style={{ ...S.input }} />
          </div>
          <div onClick={() => { if (payUpi.includes("@")) { setSelectedContact({ name: payUpi, upi: payUpi, color: "#8b5cf6" }); setSendStep(2); navigate("send"); } }} style={{ ...S.gradBtn(!payUpi.includes("@")), display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>Pay Now <ArrowRight size={18} color="#fff" /></div>
        </div>
      )}
    </div>
  );
}
