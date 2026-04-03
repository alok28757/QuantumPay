// QuantumPay — Per-tab session helper (sessionStorage)
export const Session = {
  get: () => sessionStorage.getItem("qp_current_phone"),
  set: (p) => sessionStorage.setItem("qp_current_phone", p),
  clear: () => sessionStorage.removeItem("qp_current_phone"),
};
