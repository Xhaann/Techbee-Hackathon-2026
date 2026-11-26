"use client";

import { Button as BaseButton } from "@ui-sdk/react/button";
import { LoaderCircle } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-accent-strong text-accent-fg hover:bg-accent-strong-hover shadow-[inset_0_1px_0_rgb(255_255_255/0.14),0_1px_2px_rgb(0_0_0/0.3)]",
  secondary: "bg-raised text-ink-2 hover:bg-hover hover:text-ink shadow-[0_0_0_1px_var(--line)]",
  ghost: "text-ink-3 hover:bg-hover hover:text-ink",
  danger: "bg-red-soft text-red hover:brightness-110 shadow-[0_0_0_1px_var(--red-line)]",
};

const SIZES: Record<Size, string> = {
  sm: "h-8 gap-1.5 rounded-[7px] px-2.5 text-[13px]",
  md: "h-9 gap-2 rounded-[8px] px-3.5 text-[13.5px]",
};

type Props = Omit<ComponentProps<typeof BaseButton>, "className" | "children"> & {
  variant?: Variant;
  size?: Size;
  className?: string;
  children?: ReactNode;
  /** Label shown while the Promise returned from onClick runs. */
  pendingLabel?: ReactNode;
};

export function Button({ variant = "secondary", size = "md", className, children, pendingLabel, ...props }: Props) {
  return (
    <BaseButton
      {...props}
      className={cn(
        "inline-flex shrink-0 items-center justify-center whitespace-nowrap font-medium tracking-[-0.01em] transition-[background-color,color,translate] duration-150 select-none active:translate-y-px",
        "data-disabled:pointer-events-none data-disabled:opacity-45 data-pending:cursor-progress",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
    >
      {pendingLabel ? (
        <>
          <span data-show="idle" className="inline-flex items-center gap-[inherit]">
            {children}
          </span>
          <span data-show="pending" className="inline-flex items-center gap-[inherit]">
            <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
            {pendingLabel}
          </span>
        </>
      ) : (
        children
      )}
    </BaseButton>
  );
}

/** A spinner for buttons whose pending state is driven by a mutation rather than onClick's promise. */
export function Spinner({ className }: { className?: string }) {
  return <LoaderCircle className={cn("size-3.5 animate-spin", className)} aria-hidden />;
}
