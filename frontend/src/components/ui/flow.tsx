"use client";

import { AnimatePresence, motion, useReducedMotion, type Transition, type Variants } from "motion/react";
import { useState } from "react";

// The blur digit roll, for any figure: a digit that changes slides out blurring while
// the next slides in and settles with a soft give, in the direction the number moved.
// Columns are keyed from the right, so the units stay the units, and a column that
// comes or goes (999 → 1,036) opens or closes its own width instead of snapping.

const swap: Variants = {
  enter: (d: number) => ({ y: `${d * 0.42}em`, opacity: 0, filter: "blur(7px)", scale: 0.92 }),
  rest: { y: "0em", opacity: 1, filter: "blur(0px)", scale: 1 },
  leave: (d: number) => ({ y: `${-d * 0.42}em`, opacity: 0, filter: "blur(7px)", scale: 0.92 }),
};
const settle: Transition = { type: "spring", duration: 0.42, bounce: 0.22 };
const still: Transition = { duration: 0 };

export function Flow({ value, format = String, className }: { value: number; format?: (v: number) => string; className?: string }) {
  const reduce = !!useReducedMotion();
  const [seen, setSeen] = useState({ value, dir: 1 });
  if (seen.value !== value) setSeen({ value, dir: value > seen.value ? 1 : -1 });
  const dir = seen.dir;
  const t = reduce ? still : settle;
  const chars = format(value).split("");

  return (
    <span className={`inline-flex ${className ?? ""}`}>
      <AnimatePresence initial={false}>
        {chars.map((ch, i) => {
          const place = chars.length - i;
          const digit = /\d/.test(ch);
          return (
            <motion.span
              key={`${digit ? "d" : "s"}${place}`}
              className="relative inline-grid justify-items-center"
              initial={{ width: 0, opacity: 0 }}
              animate={{ width: "auto", opacity: 1 }}
              exit={{ width: 0, opacity: 0 }}
              transition={t}
            >
              {digit ? (
                <AnimatePresence initial={false} custom={dir}>
                  <motion.span key={ch} custom={dir} variants={swap} initial="enter" animate="rest" exit="leave" transition={t} className="col-start-1 row-start-1 block">
                    {ch}
                  </motion.span>
                </AnimatePresence>
              ) : (
                <span className="col-start-1 row-start-1 block">{ch}</span>
              )}
            </motion.span>
          );
        })}
      </AnimatePresence>
    </span>
  );
}
