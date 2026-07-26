import { invoke } from "@tauri-apps/api/core";

export const bad = () => invoke("get_startup_status");
