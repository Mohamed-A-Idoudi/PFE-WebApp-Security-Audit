export function Card({ children, className="", style={}, noPad=false }) {
  return <div className={`${noPad ? "ss-card-bare" : "ss-card"} ${className}`} style={style}>{children}</div>;
}
