import type { ReactNode } from "react";
import type { ReportView } from "./api";

const ICON = { pass: "✓", warn: "!", fail: "✕", skipped: "–" } as const;
const WORD = { pass: "passes", warn: "warns", fail: "fails", skipped: "skipped" } as const;

/** The eight gate results as a list. Status is shown with a symbol and a word, never colour alone. */
export function ReportChecks({ report, onlyProblems = false }: { report: ReportView; onlyProblems?: boolean }): ReactNode {
  const checks = onlyProblems ? report.checks.filter((c) => c.status === "warn" || c.status === "fail") : report.checks;
  return (
    <ul className="av-checks" role="list">
      {checks.map((c) => (
        <li key={c.code} className={`av-check av-check-${c.status}`}>
          <span className="av-check-code av-mono">{c.code}</span>
          <span>
            <span className="av-check-name">
              <span aria-hidden="true">{ICON[c.status]}</span>
              <span className="av-sr"> {WORD[c.status]}: </span> {c.name}
            </span>
            <span className="av-check-msg">{c.message}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

export function ScoreRing({ score, level }: { score: number; level: ReportView["level"] }): ReactNode {
  const r = 44;
  const c = 2 * Math.PI * r;
  const tone = level === "LOW" ? "ok" : level === "BLOCK" ? "err" : "warn";
  return (
    <figure className={`av-ring av-ring-${tone}`} aria-label={`Trust score ${score} out of 100, ${level.replace("_", " ").toLowerCase()}`}>
      <svg viewBox="0 0 100 100" width="112" height="112" aria-hidden="true">
        <circle cx="50" cy="50" r={r} className="av-ring-track" fill="none" strokeWidth="9" />
        <circle cx="50" cy="50" r={r} className="av-ring-bar" fill="none" strokeWidth="9" strokeLinecap="round" strokeDasharray={`${(score / 100) * c} ${c}`} transform="rotate(-90 50 50)" />
        <text x="50" y="55" textAnchor="middle" className="av-ring-num">{score}</text>
      </svg>
      <figcaption className="av-ring-cap">{level === "LOW" ? "ALLOW" : level === "BLOCK" ? "BLOCK" : "STEP UP"}</figcaption>
    </figure>
  );
}
