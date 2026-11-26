"use client";

import { Field, FieldDescription, FieldError, FieldLabel } from "@ui-sdk/react/field";
import { Input } from "@ui-sdk/react/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectItemIndicator,
  SelectTrigger,
  SelectValue,
} from "@ui-sdk/react/select";
import { Textarea } from "@ui-sdk/react/textarea";
import { Check, ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export const controlClass =
  "w-full rounded-[8px] bg-sunken px-3 text-[13.5px] text-ink placeholder:text-ink-4 shadow-[0_0_0_1px_var(--line)] outline-none transition-shadow duration-150 focus:shadow-[0_0_0_1px_var(--accent-ring),0_0_0_3px_var(--accent-soft)] data-invalid:shadow-[0_0_0_1px_var(--red-line)] data-disabled:opacity-50";

const labelClass = "mb-1.5 block text-[12.5px] font-medium text-ink-2";
const hintClass = "mt-1.5 text-[12px] leading-[1.45] text-ink-3";
const errorClass = "mt-1.5 text-[12px] text-red";

export function TextField({
  label,
  hint,
  value,
  onChange,
  placeholder,
  required,
  type = "text",
  mono,
  autoFocus,
  minLength,
  maxLength,
  name,
  error,
  autoComplete,
}: {
  label: ReactNode;
  hint?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
  autoComplete?: string;
  type?: string;
  mono?: boolean;
  autoFocus?: boolean;
  minLength?: number;
  maxLength?: number;
  name?: string;
  error?: string;
}) {
  return (
    <Field name={name} invalid={error ? true : undefined} className="block">
      <FieldLabel className={labelClass}>{label}</FieldLabel>
      <Input
        type={type}
        value={value}
        onValueChange={(next) => onChange(next)}
        placeholder={placeholder}
        required={required}
        autoFocus={autoFocus}
        minLength={minLength}
        maxLength={maxLength}
        autoComplete={autoComplete}
        className={cn(controlClass, "h-10", mono && "font-mono text-[13px]")}
      />
      {hint ? <FieldDescription className={hintClass}>{hint}</FieldDescription> : null}
      <FieldError className={errorClass}>{(state) => error || state.message}</FieldError>
    </Field>
  );
}

export function TextAreaField({
  label,
  hint,
  value,
  onChange,
  placeholder,
  required,
  rows = 3,
  maxLength,
  error,
}: {
  label: ReactNode;
  hint?: ReactNode;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
  rows?: number;
  maxLength?: number;
  error?: string;
}) {
  return (
    <Field invalid={error ? true : undefined} className="block">
      <FieldLabel className={labelClass}>{label}</FieldLabel>
      <Textarea
        value={value}
        onValueChange={(next) => onChange(next)}
        placeholder={placeholder}
        required={required}
        rows={rows}
        maxLength={maxLength}
        className={cn(controlClass, "resize-none py-2.5 leading-[1.5]")}
      />
      {hint ? <FieldDescription className={hintClass}>{hint}</FieldDescription> : null}
      <FieldError className={errorClass}>{(state) => error || state.message}</FieldError>
    </Field>
  );
}

export type Option<T extends string> = { value: T; label: string; disabled?: boolean };

/** A styled select. Use ALL as the value for "no filter". */
export const ALL = "__all";

export function SelectBox<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  placeholder,
  disabled,
  className,
  size = "md",
}: {
  value: T | null;
  onValueChange: (value: T) => void;
  options: Option<T>[];
  ariaLabel: string;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  size?: "sm" | "md";
}) {
  return (
    <Select
      items={options}
      value={value}
      onValueChange={(next) => {
        if (typeof next === "string") onValueChange(next as T);
      }}
      placeholder={placeholder}
      disabled={disabled}
    >
      <SelectTrigger
        aria-label={ariaLabel}
        className={cn(
          controlClass.replace("w-full ", ""),
          className ? undefined : "w-full",
          "inline-flex items-center justify-between gap-2 text-left",
          size === "sm" ? "h-8 px-2.5 text-[13px]" : "h-10",
          "data-placeholder:text-ink-4",
          className,
        )}
      >
        <SelectValue className="truncate" />
        <ChevronDown className="size-3.5 shrink-0 text-ink-3" aria-hidden />
      </SelectTrigger>
      <SelectContent
        sideOffset={4}
        className="popup max-h-[min(320px,var(--available-height))] min-w-(--anchor-width) overflow-y-auto scroll-thin"
      >
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value} disabled={option.disabled} className="popup-item pr-2">
            <span className="flex-1 truncate">{option.label}</span>
            <SelectItemIndicator className="text-accent">
              <Check className="size-3.5" aria-hidden />
            </SelectItemIndicator>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function FieldGroup({ label, children, hint }: { label: ReactNode; children: ReactNode; hint?: ReactNode }) {
  return (
    <div>
      <div className={labelClass}>{label}</div>
      {children}
      {hint ? <div className={hintClass}>{hint}</div> : null}
    </div>
  );
}
