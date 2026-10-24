interface AuthvexLogoProps {
  className?: string;
  iconOnly?: boolean;
  size?: "sm" | "md" | "lg";
  showBadge?: boolean;
}

const SIZES = {
  sm: { box: 22, text: "text-base", badge: "text-[10px] px-1.5 py-0.5" },
  md: { box: 28, text: "text-lg", badge: "text-[11px] px-2 py-0.5" },
  lg: { box: 38, text: "text-2xl", badge: "text-xs px-2.5 py-0.5" },
} as const;

/** A sovereign shield holding a passkey keyhole (amber) and a green proof-of-possession node. */
export function AuthvexLogo({ className = "", iconOnly = false, size = "md", showBadge = true }: AuthvexLogoProps) {
  const d = SIZES[size];
  return (
    <div className={`inline-flex select-none items-center gap-2.5 text-ink ${className}`}>
      <svg width={d.box} height={d.box} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" className="shrink-0" role="img" aria-label="Authvex logo mark">
        <path d="M16 3L26.5 7.5V15.5C26.5 22.2 22 27.4 16 29.5C10 27.4 5.5 22.2 5.5 15.5V7.5L16 3Z" stroke="currentColor" strokeWidth="2.4" strokeLinejoin="round" />
        <circle cx="16" cy="13.5" r="3.2" stroke="#F59E0B" strokeWidth="2.3" />
        <path d="M16 16.8V22.5" stroke="#F59E0B" strokeWidth="2.4" strokeLinecap="round" />
        <circle cx="16" cy="13.5" r="1.3" fill="#10B981" />
      </svg>
      {!iconOnly && (
        <div className="flex items-center gap-2">
          <span className={`font-semibold tracking-tight ${d.text}`}>
            Auth<span className="font-bold text-amber-ink">vex</span>
          </span>
          {showBadge && <span className={`rounded-md border border-line-strong font-mono font-medium uppercase tracking-wider text-muted ${d.badge}`}>IDENTITY OS</span>}
        </div>
      )}
    </div>
  );
}
