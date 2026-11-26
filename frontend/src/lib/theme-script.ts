export const PREFS_KEY = "noc.prefs";

/** Runs before hydration (inlined in the root layout) so the first paint has the right theme. */
export const THEME_BOOTSTRAP = `(()=>{try{var p=JSON.parse(localStorage.getItem("${PREFS_KEY}")||"{}");var t=p.theme||"dark";if(t==="system"){t=matchMedia("(prefers-color-scheme: light)").matches?"light":"dark"}document.documentElement.dataset.theme=t}catch(e){document.documentElement.dataset.theme="dark"}})()`;
