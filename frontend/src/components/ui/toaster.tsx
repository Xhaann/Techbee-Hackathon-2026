"use client";

import { Toast, ToastClose, ToastDescription, ToastRegion, ToastTitle, toast } from "@ui-sdk/react/toast";
import { CircleCheck, CircleAlert, X } from "lucide-react";
import { describeError } from "@/lib/api/client";

export function Toaster() {
  return (
    <ToastRegion side="bottom" align="end" maxVisible={3} className="fixed right-4 bottom-4 z-50 flex w-[360px] max-w-[calc(100vw-32px)] flex-col gap-2">
      {() => (
        <Toast className="group relative flex items-start gap-2.5 rounded-[10px] bg-raised px-3.5 py-3 text-ink shadow-[var(--shadow-pop)] transition-[opacity,translate] duration-300 ease-(--ease-spring) data-starting-style:translate-y-2 data-starting-style:opacity-0 data-ending-style:opacity-0">
          <CircleCheck className="mt-[1px] hidden size-4 shrink-0 text-green group-data-[type=success]:block" aria-hidden />
          <CircleAlert className="mt-[1px] hidden size-4 shrink-0 text-red group-data-[type=error]:block" aria-hidden />
          <CircleAlert className="mt-[1px] hidden size-4 shrink-0 text-amber group-data-[type=warning]:block" aria-hidden />
          <div className="min-w-0 flex-1">
            <ToastTitle className="text-[13.5px] font-medium tracking-[-0.01em]" />
            <ToastDescription className="mt-0.5 text-[12.5px] leading-[1.45] text-ink-3 text-pretty" />
          </div>
          <ToastClose aria-label="Dismiss" className="-mr-1 grid size-6 place-items-center rounded-[5px] text-ink-4 hover:bg-hover hover:text-ink">
            <X className="size-3.5" aria-hidden />
          </ToastClose>
        </Toast>
      )}
    </ToastRegion>
  );
}

export const notify = {
  success: (title: string, description?: string) => toast.success(title, { description }),
  error: (title: string, detail?: unknown) =>
    toast.error(title, { description: typeof detail === "string" ? detail : detail ? describeError(detail) : undefined, duration: 8000 }),
  warning: (title: string, description?: string) => toast.warning(title, { description, duration: 8000 }),
};
