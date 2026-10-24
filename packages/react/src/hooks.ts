import { useCallback, useEffect, useRef, useState } from "react";
import { request, type ApiOptions, type WorkspaceView } from "./api";

export interface Workspace {
  data: WorkspaceView | null;
  error: string | null;
  refresh(): Promise<void>;
}

/** Loads the workspace (tenants, users, session families, keys) and reloads it on demand and every `pollMs`. */
export function useWorkspace(api: ApiOptions, pollMs = 4000): Workspace {
  const [data, setData] = useState<WorkspaceView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const live = useRef(true);
  const { baseUrl, adminToken } = api;

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const r = await request<WorkspaceView & { error?: string }>({ baseUrl, ...(adminToken ? { adminToken } : {}) }, "GET", "/api/workspace");
      if (!live.current) return;
      if (r.status === 200) {
        setData(r.body);
        setError(null);
      } else setError(r.body.error ?? `HTTP ${r.status}`);
    } catch (e) {
      if (live.current) setError(e instanceof Error ? e.message : "request failed");
    }
  }, [baseUrl, adminToken]);

  useEffect(() => {
    live.current = true;
    void refresh();
    const id = pollMs > 0 ? setInterval(() => void (document.visibilityState !== "hidden" ? refresh() : undefined), pollMs) : undefined;
    return () => {
      live.current = false;
      if (id) clearInterval(id);
    };
  }, [refresh, pollMs]);

  return { data, error, refresh };
}

export const shortId = (s: string, n = 10): string => (s.length > n + 3 ? `${s.slice(0, n)}…` : s);
