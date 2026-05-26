export function Button({ children, variant="primary", size="md", className="", ...props }) {
  const v = { primary:"ss-btn-primary", secondary:"ss-btn-secondary", ghost:"ss-btn-ghost", danger:"ss-btn-danger" }[variant] ?? "ss-btn-primary";
  const s = { sm:"ss-btn-sm", lg:"ss-btn-lg", md:"" }[size] ?? "";
  return <button className={`ss-btn ${v} ${s} ${className}`} {...props}>{children}</button>;
}
