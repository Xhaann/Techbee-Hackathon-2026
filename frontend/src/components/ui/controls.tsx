"use client";

import { SegmentedControl, SegmentedControlIndicator, SegmentedControlItem } from "@ui-sdk/react/segmented-control";
import { Switch, SwitchThumb } from "@ui-sdk/react/switch";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/** One on/off setting: a plain switch with real material on its thumb. */
export function Toggle({
  checked,
  onCheckedChange,
  disabled,
  label,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  label: ReactNode;
}) {
  return (
    <label className={cn("inline-flex items-center gap-2 text-[12.5px] text-ink-3", disabled && "opacity-50")}>
      <Switch
        checked={checked}
        onCheckedChange={(next) => onCheckedChange(next)}
        disabled={disabled}
        className="relative inline-flex h-[18px] w-[30px] shrink-0 items-center rounded-full bg-[var(--line-strong)] transition-colors duration-200 data-checked:bg-accent-strong"
      >
        <SwitchThumb className="block size-[14px] translate-x-[2px] rounded-full bg-white shadow-[0_1px_2px_rgb(0_0_0/0.3)] transition-transform duration-300 ease-(--ease-spring) data-checked:translate-x-[14px]" />
      </Switch>
      {label}
    </label>
  );
}

/** Two to four visible choices: a raised knob that slides in a recessed well. */
export function Segmented<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  size = "md",
}: {
  value: T;
  onValueChange: (value: T) => void;
  options: { value: T; label: ReactNode; icon?: ReactNode }[];
  ariaLabel: string;
  size?: "sm" | "md";
}) {
  return (
    <SegmentedControl
      aria-label={ariaLabel}
      value={value}
      onValueChange={(next) => {
        if (next) onValueChange(next as T);
      }}
      className={cn(
        "relative inline-flex rounded-[9px] bg-sunken p-[3px] shadow-[inset_0_0_0_1px_var(--line),inset_0_1px_2px_rgb(0_0_0/0.15)]",
        size === "sm" ? "h-8" : "h-9",
      )}
    >
      <SegmentedControlIndicator className="absolute top-[3px] bottom-[3px] left-(--segmented-control-indicator-left) w-(--segmented-control-indicator-width) rounded-[7px] bg-raised shadow-[0_0_0_1px_var(--line-strong),0_1px_2px_rgb(0_0_0/0.25),inset_0_1px_0_rgb(255_255_255/0.06)] transition-[left,width] duration-[480ms] ease-(--ease-spring)" />
      {options.map((option) => (
        <SegmentedControlItem
          key={option.value}
          value={option.value}
          className={cn(
            "relative z-10 inline-flex items-center gap-1.5 rounded-[7px] px-3 font-medium text-ink-3 transition-colors duration-150 hover:text-ink-2 data-checked:text-ink",
            size === "sm" ? "text-[12.5px]" : "text-[13px]",
          )}
        >
          {option.icon}
          {option.label}
        </SegmentedControlItem>
      ))}
    </SegmentedControl>
  );
}
