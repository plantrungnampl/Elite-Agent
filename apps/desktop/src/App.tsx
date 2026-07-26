import { useCallback, useState } from "react";

import { StartupScreen } from "./features/startup/StartupScreen";
import { WorkspaceScreen } from "./features/workspace/WorkspaceScreen";

function App() {
  const [ready, setReady] = useState(false);
  const handleReady = useCallback(() => setReady(true), []);

  return ready ? <WorkspaceScreen /> : <StartupScreen onReady={handleReady} />;
}

export default App;
