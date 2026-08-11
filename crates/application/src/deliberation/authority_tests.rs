
#[cfg(test)]
mod authority_tests {
    use local_agent_terminal_domain::{
        Condition, DeliberationTaskBudget, FencingToken, OperationState, Sequence, Timestamp,
        WorkspaceVersion,
    };

    use super::*;

    #[test]
    fn private_persistence_validator_rejects_wrong_event_and_arbitrary_task_projection() {
        let task_id = TaskId::new("task-1").unwrap();
        let state = WorkflowState::new(
            Phase::CrossReview,
            Condition::Active,
            OperationState::None,
            Sequence::new(7),
            WorkspaceVersion::new(1),
            FencingToken::new(1).unwrap(),
        )
        .unwrap();
        let record = DeliberationRecord::ThreadSummary {
            thread_id: "thread-1".to_owned(),
            artifact: DeliberationArtifactRef::new(
                ArtifactId::new("artifact-thread-1").unwrap(),
                Sha256Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                17,
            )
            .unwrap(),
        };
        let authority = EventAuthority {
            actor_id: ActorId::new("core").unwrap(),
            event_id: EventId::new("event-1").unwrap(),
            correlation_id: "correlation-1".to_owned(),
            occurred_at: "2026-08-09T00:00:00Z".to_owned(),
        };
        let task_budget = DeliberationTaskBudget::new(
            4,
            4_096,
            20_000,
            Timestamp::from_unix_seconds(1_800_000_000),
        )
        .unwrap();
        let budget_reservation = record.budget_reservation();
        let append = build_append(
            &task_id,
            7,
            &state,
            &authority,
            &record,
            task_budget,
            budget_reservation,
        )
        .unwrap();
        let command = DeliberationPersistenceCommand {
            task_id: task_id.clone(),
            expected_task_version: 7,
            expected_task_state: state,
            task_budget,
            budget_reservation,
            actor_id: authority.actor_id.clone(),
            event_authority: authority.clone(),
            record: record.clone(),
            append: append.clone(),
        };
        command.validate().unwrap();

        let mut wrong_event = command.clone();
        wrong_event.append.events[0].event_type =
            WorkflowEvent::new("deliberation.arbitrary").unwrap();
        assert!(wrong_event.validate().is_err());

        let mut wrong_projection = command;
        wrong_projection
            .append
            .projection_changes
            .push(ProjectionChange::TaskState {
                task_id,
                state: WorkflowState::new(
                    Phase::ParallelAnalysis,
                    Condition::Active,
                    OperationState::Running,
                    Sequence::new(8),
                    WorkspaceVersion::new(2),
                    FencingToken::new(2).unwrap(),
                )
                .unwrap(),
                updated_at: authority.occurred_at,
            });
        assert!(wrong_projection.validate().is_err());
    }
}
