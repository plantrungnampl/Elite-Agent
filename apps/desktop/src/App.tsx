import { useCallback, useState } from "react";

import { DeliberationScreen } from "./features/deliberation/DeliberationScreen";
import { StartupScreen } from "./features/startup/StartupScreen";
import { ToolActivityScreen } from "./features/tools/ToolActivityScreen";
import { WorkspaceScreen } from "./features/workspace/WorkspaceScreen";

function App() {
  const [ready, setReady] = useState(false);
  const [view, setView] = useState<"workspace" | "tools" | "deliberation">("workspace");
  const handleReady = useCallback(() => setReady(true), []);

  if (!ready) {
    return <StartupScreen onReady={handleReady} />;
  }

  const skipTarget =
    view === "workspace"
      ? "#workspace-main"
      : view === "tools"
        ? "#tool-activity-main"
        : "#deliberation-main";
  const skipLabel =
    view === "workspace"
      ? "Skip to workspace"
      : view === "tools"
        ? "Skip to tool activity"
        : "Skip to deliberation";

  return (
    <>
      <a className="skip-link" href={skipTarget}>{skipLabel}</a>
      <nav className="view-navigation" aria-label="Application views">
        <button
          className="view-navigation-button"
          type="button"
          aria-pressed={view === "workspace"}
          onClick={() => setView("workspace")}
        >
          Workspace recovery
        </button>
        <button
          className="view-navigation-button"
          type="button"
          aria-pressed={view === "tools"}
          onClick={() => setView("tools")}
        >
          Tool activity
        </button>
        <button
          className="view-navigation-button"
          type="button"
          aria-pressed={view === "deliberation"}
          onClick={() => setView("deliberation")}
        >
          Deliberation
        </button>
      </nav>
      {view === "workspace" ? (
        <WorkspaceScreen />
      ) : view === "tools" ? (
        <ToolActivityScreen />
      ) : (
        <DeliberationScreen />
      )}
    </>
  );
}

export default App;
