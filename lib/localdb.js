// QuantumPay — Local fallback storage (localStorage)
export const LocalDB = {
  getUsers: () => JSON.parse(localStorage.getItem("qp_users") || "{}"),
  saveUsers: (u) => localStorage.setItem("qp_users", JSON.stringify(u)),
};
