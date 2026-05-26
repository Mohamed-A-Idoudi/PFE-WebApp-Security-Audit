import { sevCls, cvssClass } from "../utils/colors";

export function Badge({ severity }) {
  if (!severity) return null;
  return <span className={`ss-badge ss-badge-${sevCls(severity)}`}>{severity}</span>;
}
export function CvssChip({ score }) {
  if (!score && score !== 0) return <span className="ss-mono">—</span>;
  return <span className={`ss-cvss ${cvssClass(score)}`}>{parseFloat(score).toFixed(1)}</span>;
}
export function OwaspTag({ id, label }) {
  return <span className="ss-tag ss-tag-owasp" title={label}>{id}</span>;
}
export function StatusDot({ status }) {
  const L = { running:"Running", complete:"Complete", error:"Error", pending:"Pending" };
  return <span className={`ss-status ${status}`}>{L[status] ?? status}</span>;
}
export function Tag({ children }) {
  return <span className="ss-tag">{children}</span>;
}
