// QuantumPay — Utility functions

export const playSuccessSound = () => {
  try {
    const audio = new Audio("https://cdn.pixabay.com/download/audio/2021/08/04/audio_0625c1539c.mp3");
    audio.volume = 0.5;
    audio.play().catch(() => { });
  } catch (e) { }
};
