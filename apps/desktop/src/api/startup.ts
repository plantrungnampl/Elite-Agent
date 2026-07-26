import { invoke } from "@tauri-apps/api/core";

export type StartupState = "ready" | "recoverableFailure" | "indeterminate";

export interface RecoveryActionDto {
  code: string;
  label: string;
}

export interface StartupIssueDto {
  code: string;
  message: string;
  recoveryActions: RecoveryActionDto[];
}

export interface StartupStatusDto {
  state: StartupState;
  issues: StartupIssueDto[];
}

export interface LocalDiagnosticDto {
  code: string;
  component: string;
  severity: "info" | "error";
  trustLabel: "trustedCore" | "untrusted";
  observationClass: "coreObservation" | "untrustedClaim";
  errorCategory: string | null;
  correlationId: string | null;
  detail: string;
}

export function getStartupStatus(): Promise<StartupStatusDto> {
  return invoke<StartupStatusDto>("get_startup_status");
}

export function retryStartupValidation(): Promise<StartupStatusDto> {
  return invoke<StartupStatusDto>("retry_startup_validation");
}

export function getLocalDiagnostics(): Promise<LocalDiagnosticDto[]> {
  return invoke<LocalDiagnosticDto[]>("get_local_diagnostics");
}
