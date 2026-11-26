"use client";

import { Dialog, DialogBackdrop, DialogClose, DialogContent, DialogDescription, DialogTitle } from "@ui-sdk/react/dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  width = 520,
  dismissible = true,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  width?: number;
  dismissible?: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => onOpenChange(next)} dismissible={dismissible}>
      <DialogBackdrop className="fixed inset-0 bg-[var(--scrim)] transition-opacity duration-200 data-starting-style:opacity-0 data-ending-style:opacity-0" />
      <DialogContent
        style={{ width: `min(${width}px, calc(100vw - 24px))` }}
        className={cn(
          "fixed inset-x-0 top-[10vh] mx-auto max-h-[80vh] overflow-y-auto rounded-[12px] bg-raised text-ink shadow-[var(--shadow-pop)] scroll-thin",
          "transition-[opacity,translate,scale] duration-200 ease-(--ease-spring) data-starting-style:translate-y-2 data-starting-style:scale-[0.98] data-starting-style:opacity-0 data-ending-style:opacity-0",
        )}
      >
        <div className="flex items-start gap-3 px-5 pt-4 pb-1">
          <div className="min-w-0 flex-1">
            <DialogTitle className="text-[16px] font-semibold tracking-[-0.015em] text-ink">{title}</DialogTitle>
            {description ? (
              <DialogDescription className="mt-1 text-[13px] leading-[1.45] text-ink-3 text-pretty">{description}</DialogDescription>
            ) : null}
          </div>
          <DialogClose
            aria-label="Close"
            className="-mr-1.5 grid size-7 place-items-center rounded-[6px] text-ink-3 hover:bg-hover hover:text-ink"
          >
            <X className="size-4" aria-hidden />
          </DialogClose>
        </div>
        <div className="px-5 pt-3 pb-5">{children}</div>
      </DialogContent>
    </Dialog>
  );
}
