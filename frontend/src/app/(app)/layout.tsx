import { AppShell } from "@/components/shell/app-shell";

// Everything under here renders in the browser after the API token is read from session storage,
// so navigations wait on client fetches by design.
export const instant = false;

export default function WorkspaceLayout({ children }: LayoutProps<"/">) {
  return <AppShell>{children}</AppShell>;
}
