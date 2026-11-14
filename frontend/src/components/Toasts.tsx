import { useCallback, useState } from "react";
import { Icon } from "./ui";

export type ToastKind = "success" | "error" | "info";
export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  body?: string;
}

let nextId = 1;

export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const push = useCallback(
    (kind: ToastKind, title: string, body?: string) => {
      const id = nextId++;
      setToasts((t) => [...t, { id, kind, title, body }]);
      window.setTimeout(() => dismiss(id), kind === "error" ? 8000 : 5000);
    },
    [dismiss],
  );
  return { toasts, push, dismiss };
}

const STYLE: Record<ToastKind, { ring: string; icon: string; name: "check" | "alert" | "eye" }> = {
  success: { ring: "border-emerald-200", icon: "text-emerald-600", name: "check" },
  error: { ring: "border-red-200", icon: "text-red-600", name: "alert" },
  info: { ring: "border-indigo-200", icon: "text-indigo-600", name: "eye" },
};

export function ToastStack({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div className="pointer-events-none fixed inset-x-4 bottom-4 z-50 flex flex-col items-end gap-2 sm:left-auto sm:w-96"
         aria-live="polite">
      {toasts.map((t) => {
        const s = STYLE[t.kind];
        return (
          <div key={t.id} role={t.kind === "error" ? "alert" : "status"}
               className={`pointer-events-auto w-full rounded-xl border bg-white p-4 shadow-lg ${s.ring}`}>
            <div className="flex items-start gap-3">
              <Icon name={s.name} className={`mt-0.5 h-5 w-5 shrink-0 ${s.icon}`} />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-slate-900">{t.title}</p>
                {t.body && <p className="mt-0.5 text-sm text-slate-600">{t.body}</p>}
              </div>
              <button className="text-slate-400 hover:text-slate-600" onClick={() => onDismiss(t.id)}
                      aria-label="Dismiss notification">
                <Icon name="x" />
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
