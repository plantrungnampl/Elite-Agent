import type {
  DeliberationAvailability,
  DeliberationCardKind,
  EvidenceState,
  PlanApprovalDto,
} from "../../api/deliberation";

const cardLabels: Record<DeliberationCardKind, string> = {
  proposal: "Proposal",
  review: "Review",
  evidence: "Evidence",
  objection: "Objection",
  decision: "Decision",
  status: "Status change",
};

const evidenceLabels: Record<EvidenceState, string> = {
  verified: "Verified",
  unverified: "Unverified",
  inconclusive: "Inconclusive",
};

const availabilityLabels: Record<DeliberationAvailability, string> = {
  ready: "Ready",
  blocked: "Blocked",
  unavailable: "Unavailable",
};

export function cardKindLabel(kind: DeliberationCardKind) {
  return cardLabels[kind];
}

export function evidenceStateLabel(state: EvidenceState) {
  return evidenceLabels[state];
}

export function availabilityLabel(availability: DeliberationAvailability) {
  return availabilityLabels[availability];
}

export function approvalStatusLabel(status: PlanApprovalDto["status"]) {
  switch (status) {
    case "requested":
      return "Approval required";
    case "resolved":
      return "Plan resolved";
    case "rejected":
      return "Plan rejected";
    case "expired":
      return "Approval expired";
    case "invalidated":
      return "Approval invalidated";
    case "digest_changed":
      return "Digest changed";
  }
}

export function commandErrorMessage(cause: unknown, fallback: string) {
  if (
    typeof cause === "object" &&
    cause !== null &&
    "message" in cause &&
    typeof cause.message === "string"
  ) {
    return cause.message;
  }
  return fallback;
}

export function isConflict(cause: unknown) {
  return (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    cause.code === "conflict"
  );
}
