import { useCallback, useState } from "react";

import { StartupScreen } from "./features/startup/StartupScreen";
import { ToolActivityScreen } from "./features/tools/ToolActivityScreen";
import { WorkspaceScreen } from "./features/workspace/WorkspaceScreen";

function App() {
  const [ready, setReady] = useState(false);
  const [view, setView] = useState<"workspace" | "tools">("workspace");
  const handleReady = useCallback(() => setReady(true), []);

  if (!ready) {
    return <StartupScreen onReady={handleReady} />;
  }

  return (
    <>
      <a
        className="skip-link"
        href={view === "workspace" ? "#workspace-main" : "#tool-activity-main"}
      >
        {view === "workspace" ? "Skip to workspace" : "Skip to tool activity"}
      </a>
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
      </nav>
      {view === "workspace" ? <WorkspaceScreen /> : <ToolActivityScreen />}
    </>
  );
}

export default App;
