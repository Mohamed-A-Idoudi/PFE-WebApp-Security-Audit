export const COLORS = {
  bg: "#060810", surface: "#131c2e", surfaceHover: "#1e2b44",
  border: "#1c2840", borderActive: "#3b82f6", primary: "#3b82f6",
  primaryDark: "#1d4ed8", accent: "#06b6d4", text: "#cdd6e0",
  textMuted: "#8896a8", textDim: "#4a5a72", critical: "#ef4444",
  high: "#f97316", medium: "#f59e0b", low: "#22c55e",
  info: "#6366f1", cardBg: "#0d1117",
};
export const sevColor = (s) => ({ Critical: COLORS.critical, High: COLORS.high, Medium: COLORS.medium, Low: COLORS.low }[s] || COLORS.textMuted);
export const sevCls   = (s) => ({ Critical:"crit", High:"high", Medium:"med", Low:"low" }[s] || "info");
export const cvssClass = (score) => { const n = parseFloat(score)||0; if(n>=9)return"ss-cvss-crit"; if(n>=7)return"ss-cvss-high"; if(n>=4)return"ss-cvss-med"; return"ss-cvss-low"; };
