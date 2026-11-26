"use client";

import { Tooltip, TooltipContent, TooltipTrigger } from "@ui-sdk/react/tooltip";
import type { ReactElement, ReactNode } from "react";

type Side = "top" | "bottom" | "left" | "right";

/** A short hint on hover and focus. The child element becomes the trigger. */
export function Tip({
  label,
  children,
  side = "top",
  type,
}: {
  label: ReactNode;
  children: ReactElement;
  side?: Side;
  type?: "label" | "description";
}) {
  return (
    <Tooltip delay={350} closeDelay={60} type={type}>
      <TooltipTrigger render={children} />
      <TooltipContent
        side={side}
        sideOffset={6}
        className="max-w-[280px] rounded-[7px] bg-raised px-2 py-1.5 text-[12px] leading-[1.4] text-ink-2 shadow-[var(--shadow-pop)] transition-[opacity,scale] duration-120 origin-(--transform-origin) data-starting-style:scale-95 data-starting-style:opacity-0 data-ending-style:opacity-0 data-instant:transition-none"
      >
        {label}
      </TooltipContent>
    </Tooltip>
  );
}
