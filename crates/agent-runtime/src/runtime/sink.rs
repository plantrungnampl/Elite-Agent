
struct RuntimeSink {
    store: Arc<dyn AgentRunStore>,
    artifacts: Arc<dyn AgentArtifactStore>,
    clock: Arc<dyn Clock>,
    request_handler: Arc<dyn AgentRequestHandler>,
    request_routing_enabled: bool,
    session: Arc<Mutex<ProtocolSession>>,
    peer: Arc<dyn ProtocolPeer>,
    request: BoundAgentRunRequest,
    active_runs: Arc<Mutex<BTreeMap<String, ActiveRun>>>,
    sessions: Arc<Mutex<BTreeMap<String, Arc<Mutex<ProtocolSession>>>>>,
    slot: RunSlot,
    gate: Arc<SinkGate>,
    slots: Arc<ConnectionSlots>,
    request_gate: Arc<Mutex<()>>,
    cancellation: AgentRequestCancellation,
    request_state: Mutex<RunRequestState>,
    codec: NdjsonCodec,
}

enum PreparedRequestCommit {
    None,
    Context(Box<local_agent_terminal_application::AgentContextQueryCommit>),
    Specialist(Box<local_agent_terminal_application::AgentSpecialistCommit>),
}

impl RuntimeSink {
    fn receive_frame(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.gate.wait_until_ready()?;
        if matches!(
            frame,
            ProtocolFrame::RunCompleteRequest(_)
                | ProtocolFrame::ContextQueryRequest(_)
                | ProtocolFrame::ToolRequest(_)
                | ProtocolFrame::SpecialistRequest(_)
        ) {
            return Err(ProtocolError::InvalidRequest);
        }
        let now =
            runtime_time(self.clock.as_ref()).map_err(|_| ProtocolError::InternalAgentFailure)?;
        let received = {
            let mut session = self
                .session
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            session.receive(frame.clone(), now.date_time)
        };
        let disposition = match received {
            Ok(disposition) => disposition,
            Err(error) => {
                self.handle_protocol_error(error, now)?;
                return Err(error);
            }
        };
        Ok(disposition)
    }

    fn request_frame(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        self.gate.wait_until_ready()?;
        let request_guard = self
            .request_gate
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let value = frame_value(&frame)?;
        let id = required_string(&value, "/id")?;
        let method = required_string(&value, "/method")?;
        let request_bytes =
            serde_json::to_vec(&frame).map_err(|_| ProtocolError::InternalAgentFailure)?;
        let request_digest = digest_bytes(&request_bytes);
        let now = match runtime_time(self.clock.as_ref()) {
            Ok(now) => now,
            Err(_) => {
                self.cancellation.revoke();
                drop(request_guard);
                self.slots
                    .poison_connection(self.request.connection.binding_digest.as_str())
                    .map_err(|_| ProtocolError::InternalAgentFailure)?;
                return error_response(&id, "internal_error", false)
                    .map_err(|_| ProtocolError::InternalAgentFailure);
            }
        };
        match self.replay_response(&id, &method, request_digest.as_str()) {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {}
            Err(error) => {
                drop(request_guard);
                return self.request_error(
                    &frame,
                    &id,
                    request_digest,
                    protocol_request_error_category(error),
                );
            }
        }
        if let Some(reason) = self.preflight_request(&frame, &id)? {
            let response = self.request_error(&frame, &id, request_digest, reason);
            return match response {
                Ok(response) => Ok(response),
                Err(error) => {
                    drop(request_guard);
                    self.fail_request(&id, error, now)
                }
            };
        }

        let received = match self.session.lock() {
            Ok(mut session) => session.receive(frame.clone(), now.date_time),
            Err(_) => {
                drop(request_guard);
                return self.fail_request(&id, ProtocolError::InternalAgentFailure, now);
            }
        };
        let disposition = match received {
            Ok(InboundDisposition::Request(frame)) => frame,
            Ok(InboundDisposition::ReplayRequest(_)) => {
                drop(request_guard);
                return self
                    .replay_response(&id, &method, request_digest.as_str())?
                    .ok_or(ProtocolError::InvalidRequest);
            }
            Ok(_) => return Err(ProtocolError::InvalidRequest),
            Err(error) => {
                let reason = protocol_request_error_category(error);
                let response = self.request_error(&frame, &id, request_digest, reason);
                if error == ProtocolError::OutputLimitExceeded {
                    let _ = self.handle_protocol_error(error, now);
                    drop(request_guard);
                    return response;
                }
                drop(request_guard);
                return match response {
                    Ok(response) => Ok(response),
                    Err(audit_error) => self.fail_request(&id, audit_error, now),
                };
            }
        };
        let routed = match disposition {
            ProtocolFrame::RunCompleteRequest(_) => {
                let content = terminal_content(&frame)?;
                let message_id =
                    required_string(&frame_value(&frame)?, "/params/message/messageId")?;
                let content_artifact_id = self
                    .artifacts
                    .publish_agent_message(&AgentMessageArtifact {
                        task_id: self.request.task_id.clone(),
                        run_id: self.request.run_id.clone(),
                        message_id,
                        content: content.into_bytes(),
                    })
                    .map_err(|_| ProtocolError::InternalAgentFailure)?;
                let terminal =
                    terminal_from_frame(&frame, &self.request, content_artifact_id, now.timestamp)?;
                self.store
                    .persist_terminal(&terminal)
                    .map_err(|_| ProtocolError::InternalAgentFailure)?;
                self.active_runs
                    .lock()
                    .map_err(|_| ProtocolError::InternalAgentFailure)?
                    .remove(self.request.run_id.as_str());
                self.slot.release();
                success_response(
                    &id,
                    json!({
                        "runId": self.request.run_id.as_str(),
                        "recorded": true,
                        "terminalStatus": required_string(&frame_value(&frame)?, "/params/status")?
                    }),
                )
                    .map_err(|_| ProtocolError::InternalAgentFailure)
            }
            ProtocolFrame::ContextQueryRequest(_) => {
                self.route_context_query(&frame, &id, request_digest.clone(), now.timestamp)
            }
            ProtocolFrame::SpecialistRequest(_) => {
                self.route_specialist_request(&frame, &id, request_digest.clone(), now.timestamp)
            }
            ProtocolFrame::ToolRequest(_) => error_response(&id, "policy_denied", false)
                .map_err(|_| ProtocolError::InternalAgentFailure),
            _ => return Err(ProtocolError::InvalidRequest),
        };
        let response = match routed {
            Ok(response) => response,
            Err(error) => {
                drop(request_guard);
                return self.fail_request(&id, error, now);
            }
        };
        let response_time = match runtime_time(self.clock.as_ref()) {
            Ok(response_time) => response_time,
            Err(_) => {
                drop(request_guard);
                return self.fail_request(&id, ProtocolError::InternalAgentFailure, now);
            }
        };
        let outbound = match self.session.lock() {
            Ok(mut session) => session.outbound(response.clone(), response_time.date_time),
            Err(_) => {
                drop(request_guard);
                return self.fail_request(&id, ProtocolError::InternalAgentFailure, response_time);
            }
        };
        if let Err(error) = outbound {
            drop(request_guard);
            return self.fail_request(&id, error, response_time);
        }
        self.remember_replay_response(&id, &method, request_digest.as_str(), &response)?;
        Ok(response)
    }

    fn preflight_request(
        &self,
        frame: &ProtocolFrame,
        request_id: &str,
    ) -> Result<Option<&'static str>, ProtocolError> {
        if !matches!(
            frame,
            ProtocolFrame::RunCompleteRequest(_)
                | ProtocolFrame::ContextQueryRequest(_)
                | ProtocolFrame::ToolRequest(_)
                | ProtocolFrame::SpecialistRequest(_)
        ) {
            return Err(ProtocolError::InvalidRequest);
        }
        if !request_id.starts_with("agent:") {
            return Ok(Some("invalid_request_origin"));
        }
        let value = frame_value(frame)?;
        if required_string(&value, "/params/runId")? != self.request.run_id.as_str() {
            return Ok(Some("request_ownership_mismatch"));
        }
        if !self
            .active_runs
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .contains_key(self.request.run_id.as_str())
        {
            return Ok(Some("run_not_active"));
        }
        let capabilities = self.peer.descriptor().capabilities;
        let negotiated = match frame {
            ProtocolFrame::ContextQueryRequest(_) => capabilities.context_query,
            ProtocolFrame::ToolRequest(_) => capabilities.tool_requests,
            ProtocolFrame::SpecialistRequest(_) => capabilities.specialist_requests,
            ProtocolFrame::RunCompleteRequest(_) => true,
            _ => false,
        };
        if !negotiated {
            return Ok(Some("capability_not_negotiated"));
        }
        Ok(None)
    }

    fn replay_response(
        &self,
        request_id: &str,
        method: &str,
        request_digest: &str,
    ) -> Result<Option<ProtocolFrame>, ProtocolError> {
        let state = self
            .request_state
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        match state.replayed_responses.get(request_id) {
            Some(replay)
                if replay.method == method && replay.request_digest == request_digest =>
            {
                Ok(Some(replay.response.clone()))
            }
            Some(_) => Err(ProtocolError::ProtocolConflict),
            None => Ok(None),
        }
    }

    fn remember_replay_response(
        &self,
        request_id: &str,
        method: &str,
        request_digest: &str,
        response: &ProtocolFrame,
    ) -> Result<(), ProtocolError> {
        self.request_state
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .replayed_responses
            .insert(
                request_id.to_owned(),
                ReplayResponse {
                    method: method.to_owned(),
                    request_digest: request_digest.to_owned(),
                    response: response.clone(),
                },
            );
        Ok(())
    }

    fn request_error(
        &self,
        frame: &ProtocolFrame,
        request_id: &str,
        request_digest: Sha256Digest,
        reason: &str,
    ) -> Result<ProtocolFrame, ProtocolError> {
        match frame {
            ProtocolFrame::ContextQueryRequest(_) => self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                reason,
            ),
            ProtocolFrame::SpecialistRequest(_) => self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                reason,
            ),
            ProtocolFrame::RunCompleteRequest(_) | ProtocolFrame::ToolRequest(_) => {
                error_response(request_id, reason, false)
                    .map_err(|_| ProtocolError::InternalAgentFailure)
            }
            _ => Err(ProtocolError::InvalidRequest),
        }
    }

    fn fail_request(
        &self,
        request_id: &str,
        error: ProtocolError,
        now: RuntimeTime,
    ) -> Result<ProtocolFrame, ProtocolError> {
        let response = error_response(request_id, "internal_error", false)
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let _ = self.handle_protocol_error(error, now);
        Ok(response)
    }

    fn route_context_query(
        &self,
        frame: &ProtocolFrame,
        request_id: &str,
        request_digest: Sha256Digest,
        requested_at: Timestamp,
    ) -> Result<ProtocolFrame, ProtocolError> {
        let value = frame_value(frame)?;
        let run_id = required_string(&value, "/params/runId")?;
        if run_id != self.request.run_id.as_str() {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                "request_ownership_mismatch",
            );
        }
        if !self.request_routing_enabled {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                "policy_denied",
            );
        }
        if requested_at >= self.request.run_config.limits.deadline {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                "request_deadline_exceeded",
            );
        }
        let query_id = required_string(&value, "/params/queryId")?;
        let budget_error = {
            let mut state = self
                .request_state
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            if state.context_query_ids.contains(&query_id) {
                Some("duplicate_query_id")
            } else {
                let next = state.context_queries.checked_add(1);
                if next
                    .is_none_or(|count| count > self.request.run_config.limits.max_context_queries)
                {
                    Some("request_limit_exceeded")
                } else {
                    state.context_queries = next.expect("checked context request count");
                    state.context_query_ids.insert(query_id.clone());
                    None
                }
            }
        };
        if let Some(reason) = budget_error {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                reason,
            );
        }
        let max_tokens = required_u64(&value, "/params/maxTokens")?;
        if max_tokens > self.peer.descriptor().capabilities.max_context_tokens {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                "context_token_limit_exceeded",
            );
        }
        let max_items = u32::try_from(required_u64(&value, "/params/maxItems")?)
            .map_err(|_| ProtocolError::InvalidRequest)?;
        let request = AgentContextQueryRequest {
            run_id: self.request.run_id.clone(),
            task_id: self.request.task_id.clone(),
            connection_id: self.request.connection.connection_id.clone(),
            connection_binding_digest: self.request.connection.binding_digest.clone(),
            phase: self.request.phase.clone(),
            query_id: query_id.clone(),
            query: required_string(&value, "/params/query")?,
            scopes: required_string_array(&value, "/params/scopes")?,
            max_items,
            max_tokens,
            deadline: self.request.run_config.limits.deadline,
            cancellation: self.cancellation.clone(),
        };
        if let Some(reason) = self.request_activity_error()? {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                reason,
            );
        }
        let handler = Arc::clone(&self.request_handler);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(format!("agent-context-{}", self.request.run_id.as_str()))
            .spawn(move || {
                let _ = result_sender.send(handler.query_context(request));
            })
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let mut response = match self.wait_for_handler(result_receiver, worker) {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return self.audited_error(
                    request_id,
                    AgentRequestKind::ContextQuery,
                    request_digest,
                    handler_error_category(&error),
                );
            }
            Err(HandlerWaitError::Rejected(reason)) => {
                return self.audited_error(
                    request_id,
                    AgentRequestKind::ContextQuery,
                    request_digest,
                    reason,
                );
            }
            Err(HandlerWaitError::Internal) => {
                return Err(ProtocolError::InternalAgentFailure);
            }
        };
        if !valid_context_response(&response, &self.request, &query_id, max_items, max_tokens) {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                "invalid_handler_response",
            );
        }
        if let Some(reason) = self.request_activity_error()? {
            return self.audited_error(
                request_id,
                AgentRequestKind::ContextQuery,
                request_digest,
                reason,
            );
        }
        let source_refs = if response.provenance.is_empty() {
            vec![response.supplement_id.clone()]
        } else {
            response.provenance.clone()
        };
        let items = response
            .item_ids
            .iter()
            .map(|item_id| {
                json!({
                    "itemId": item_id,
                    "contentRef": response.supplement_id,
                    "contentDigest": response.content_digest.as_str(),
                    "sourceRefs": source_refs,
                    "observationClass": "core_observed"
                })
            })
            .collect::<Vec<_>>();
        let redaction_report_digest = digest_bytes(
            &serde_json::to_vec(&response.redactions)
                .map_err(|_| ProtocolError::InternalAgentFailure)?,
        );
        let response_frame = success_response(
            request_id,
            json!({
                "queryId": query_id,
                "items": items,
                "truncated": false,
                "effectivePayloadDigest": response.content_digest.as_str(),
                "redactionReportDigest": redaction_report_digest.as_str(),
            }),
        )
        .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let prepared_commit = response
            .prepared_commit
            .take()
            .map(Box::new)
            .map(PreparedRequestCommit::Context)
            .unwrap_or(PreparedRequestCommit::None);
        self.persist_request_audit_with_commit(
            request_id,
            AgentRequestKind::ContextQuery,
            request_digest,
            AgentRequestAuditDecision::Accepted,
            None,
            prepared_commit,
        )?;
        Ok(response_frame)
    }

    fn route_specialist_request(
        &self,
        frame: &ProtocolFrame,
        request_id: &str,
        request_digest: Sha256Digest,
        requested_at: Timestamp,
    ) -> Result<ProtocolFrame, ProtocolError> {
        let value = frame_value(frame)?;
        let run_id = required_string(&value, "/params/runId")?;
        if run_id != self.request.run_id.as_str() {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                "request_ownership_mismatch",
            );
        }
        if !self.request_routing_enabled {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                "policy_denied",
            );
        }
        if requested_at >= self.request.run_config.limits.deadline {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                "request_deadline_exceeded",
            );
        }
        let specialist_request_id = required_string(&value, "/params/requestId")?;
        let over_budget = {
            let mut state = self
                .request_state
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            let next = state.specialist_requests.checked_add(1);
            if next
                .is_none_or(|count| count > self.request.run_config.limits.max_specialist_requests)
            {
                true
            } else {
                state.specialist_requests = next.expect("checked specialist request count");
                false
            }
        };
        if over_budget {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                "request_limit_exceeded",
            );
        }
        let required_context_ids = required_string_array(&value, "/params/requiredContext")?;
        if required_context_ids.is_empty() || has_duplicate_strings(&required_context_ids) {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                if required_context_ids.is_empty() {
                    "missing_required_context"
                } else {
                    "duplicate_context_reference"
                },
            );
        }
        let request = AgentSpecialistRequest {
            run_id: self.request.run_id.clone(),
            task_id: self.request.task_id.clone(),
            connection_id: self.request.connection.connection_id.clone(),
            connection_binding_digest: self.request.connection.binding_digest.clone(),
            phase: self.request.phase.clone(),
            request_id: specialist_request_id.clone(),
            capability: required_string(&value, "/params/capability")?,
            reason: required_string(&value, "/params/reason")?,
            required_context_ids,
            max_tokens: self.request.run_config.limits.max_output_tokens,
            deadline: self.request.run_config.limits.deadline,
            cancellation: self.cancellation.clone(),
        };
        if let Some(reason) = self.request_activity_error()? {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                reason,
            );
        }
        let handler = Arc::clone(&self.request_handler);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(format!("agent-specialist-{}", self.request.run_id.as_str()))
            .spawn(move || {
                let _ = result_sender.send(handler.request_specialist(request));
            })
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let mut response = match self.wait_for_handler(result_receiver, worker) {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return self.audited_error(
                    request_id,
                    AgentRequestKind::SpecialistRequest,
                    request_digest,
                    handler_error_category(&error),
                );
            }
            Err(HandlerWaitError::Rejected(reason)) => {
                return self.audited_error(
                    request_id,
                    AgentRequestKind::SpecialistRequest,
                    request_digest,
                    reason,
                );
            }
            Err(HandlerWaitError::Internal) => {
                return Err(ProtocolError::InternalAgentFailure);
            }
        };
        if response.run_id != self.request.run_id
            || response.task_id != self.request.task_id
            || response.request_id != specialist_request_id
            || !valid_specialist_reason(response.accepted, &response.reason_code)
            || response.accepted != response.prepared_commit.is_some()
        {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                "invalid_handler_response",
            );
        }
        if let Some(reason) = self.request_activity_error()? {
            return self.audited_error(
                request_id,
                AgentRequestKind::SpecialistRequest,
                request_digest,
                reason,
            );
        }
        let decision = if response.accepted {
            AgentRequestAuditDecision::Accepted
        } else {
            AgentRequestAuditDecision::Rejected
        };
        let audit_reason = (!response.accepted).then(|| response.reason_code.clone());
        let specialist_run_id = response
            .prepared_commit
            .as_ref()
            .map(|commit| commit.assignment.run_id().as_str().to_owned());
        let response_frame = success_response(
            request_id,
            json!({
                "requestId": response.request_id,
                "decision": if response.accepted { "accepted" } else { "rejected" },
                "specialistRunId": specialist_run_id,
            }),
        )
        .map_err(|_| ProtocolError::InternalAgentFailure)?;
        let prepared_commit = response
            .prepared_commit
            .take()
            .map(Box::new)
            .map(PreparedRequestCommit::Specialist)
            .unwrap_or(PreparedRequestCommit::None);
        self.persist_request_audit_with_commit(
            request_id,
            AgentRequestKind::SpecialistRequest,
            request_digest,
            decision,
            audit_reason,
            prepared_commit,
        )?;
        Ok(response_frame)
    }

    fn audited_error(
        &self,
        request_id: &str,
        kind: AgentRequestKind,
        request_digest: Sha256Digest,
        reason_code: &str,
    ) -> Result<ProtocolFrame, ProtocolError> {
        self.persist_request_audit(
            request_id,
            kind,
            request_digest,
            AgentRequestAuditDecision::Rejected,
            Some(reason_code.to_owned()),
        )?;
        error_response(request_id, reason_code, false)
            .map_err(|_| ProtocolError::InternalAgentFailure)
    }

    fn persist_request_audit(
        &self,
        request_id: &str,
        kind: AgentRequestKind,
        request_digest: Sha256Digest,
        decision: AgentRequestAuditDecision,
        reason_code: Option<String>,
    ) -> Result<(), ProtocolError> {
        self.persist_request_audit_with_commit(
            request_id,
            kind,
            request_digest,
            decision,
            reason_code,
            PreparedRequestCommit::None,
        )
    }

    fn persist_request_audit_with_commit(
        &self,
        request_id: &str,
        kind: AgentRequestKind,
        request_digest: Sha256Digest,
        decision: AgentRequestAuditDecision,
        reason_code: Option<String>,
        prepared_commit: PreparedRequestCommit,
    ) -> Result<(), ProtocolError> {
        let (context_commit, specialist_commit) = match prepared_commit {
            PreparedRequestCommit::None => (None, None),
            PreparedRequestCommit::Context(commit) => (Some(*commit), None),
            PreparedRequestCommit::Specialist(commit) => (None, Some(*commit)),
        };
        let audit = AgentRequestAudit {
            run_id: self.request.run_id.clone(),
            task_id: self.request.task_id.clone(),
            connection_id: self.request.connection.connection_id.clone(),
            connection_binding_digest: self.request.connection.binding_digest.clone(),
            request_id: request_id.to_owned(),
            kind,
            request_digest,
            decision,
            reason_code,
            deadline: self.request.run_config.limits.deadline,
            fence: AgentRequestAuditFence::new(),
            context_commit,
            specialist_commit,
        };
        let fence = audit.fence.clone();
        let handler = Arc::clone(&self.request_handler);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name(format!("agent-audit-{}", self.request.run_id.as_str()))
            .spawn(move || {
                let _ = result_sender.send(handler.persist_audit(audit));
            })
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
        self.wait_for_audit(result_receiver, worker, fence)
    }

    fn request_activity_error(&self) -> Result<Option<&'static str>, ProtocolError> {
        let now =
            runtime_time(self.clock.as_ref()).map_err(|_| ProtocolError::InternalAgentFailure)?;
        if now.timestamp >= self.request.run_config.limits.deadline {
            self.cancellation.revoke();
            return Ok(Some("request_deadline_exceeded"));
        }
        if self.cancellation.is_cancelled() {
            return Ok(Some("request_cancelled"));
        }
        if !self
            .active_runs
            .lock()
            .map_err(|_| ProtocolError::InternalAgentFailure)?
            .contains_key(self.request.run_id.as_str())
        {
            return Ok(Some("run_not_active"));
        }
        Ok(None)
    }

    fn wait_for_handler<T>(
        &self,
        receiver: mpsc::Receiver<Result<T, PortError>>,
        worker: JoinHandle<()>,
    ) -> Result<Result<T, PortError>, HandlerWaitError> {
        loop {
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(result) => {
                    worker.join().map_err(|_| HandlerWaitError::Internal)?;
                    return Ok(result);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return match worker.join() {
                        Ok(()) => Err(HandlerWaitError::Rejected("handler_failed")),
                        Err(_) => Err(HandlerWaitError::Internal),
                    };
                }
            }
            let now = match runtime_time(self.clock.as_ref()) {
                Ok(now) => now,
                Err(_) => {
                    self.cancellation.revoke();
                    // Handler methods are a side-effect-free preparation boundary. A revoked late
                    // worker may finish computation, but its result cannot be committed or exposed.
                    drop(worker);
                    return Err(HandlerWaitError::Internal);
                }
            };
            if now.timestamp >= self.request.run_config.limits.deadline {
                self.cancellation.revoke();
                // See the side-effect-free handler contract on `AgentRequestHandler`.
                drop(worker);
                return Err(HandlerWaitError::Rejected("request_deadline_exceeded"));
            }
            if self.cancellation.is_cancelled() {
                // See the side-effect-free handler contract on `AgentRequestHandler`.
                drop(worker);
                return Err(HandlerWaitError::Rejected("request_cancelled"));
            }
        }
    }

    fn wait_for_audit(
        &self,
        receiver: mpsc::Receiver<Result<(), PortError>>,
        worker: JoinHandle<()>,
        fence: AgentRequestAuditFence,
    ) -> Result<(), ProtocolError> {
        loop {
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(result) => {
                    worker
                        .join()
                        .map_err(|_| ProtocolError::InternalAgentFailure)?;
                    return result.map_err(|_| ProtocolError::InternalAgentFailure);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = worker.join();
                    return Err(ProtocolError::InternalAgentFailure);
                }
            }
            let expired = runtime_time(self.clock.as_ref())
                .map(|now| now.timestamp >= self.request.run_config.limits.deadline)
                .unwrap_or(true);
            let should_abort = expired || self.cancellation.is_cancelled() || fence.is_revoked();
            // If revocation loses, commit already won the fence. Preserve one coherent outcome
            // by waiting for that transaction rather than publishing a conflicting response.
            if should_abort && fence.revoke() {
                // A late worker may finish preparation, but cannot commit after revocation wins.
                drop(worker);
                return Err(ProtocolError::InternalAgentFailure);
            }
        }
    }

    fn handle_protocol_error(
        &self,
        error: ProtocolError,
        now: RuntimeTime,
    ) -> Result<(), ProtocolError> {
        if error == ProtocolError::OutputLimitExceeded {
            publish_runtime_terminal(
                self.artifacts.as_ref(),
                self.store.as_ref(),
                &self.request,
                AgentRunStatus::Failed,
                "agent output limit exceeded",
                now.timestamp,
            )
            .map_err(|_| ProtocolError::InternalAgentFailure)?;
            self.active_runs
                .lock()
                .map_err(|_| ProtocolError::InternalAgentFailure)?
                .remove(self.request.run_id.as_str());
            self.slot.release();
            let frame = cancel_frame(&self.request.run_id, "core:limit", "output_limit")
                .map_err(|_| ProtocolError::InternalAgentFailure)?;
            let cancel = RunCancel::try_from(frame)?;
            let _ = self.peer.cancel(cancel);
            return Ok(());
        }
        self.interrupt(now)
    }

    fn interrupt(&self, now: RuntimeTime) -> Result<(), ProtocolError> {
        let digest = self.request.connection.binding_digest.as_str();
        interrupt_connection_state(
            self.store.as_ref(),
            self.active_runs.as_ref(),
            self.sessions.as_ref(),
            self.slots.as_ref(),
            digest,
            &now.text,
            None,
        )
        .map(|_| ())
        .map_err(|_| ProtocolError::InternalAgentFailure)
    }
}

fn interrupt_connection_state(
    store: &dyn AgentRunStore,
    active_runs: &Mutex<BTreeMap<String, ActiveRun>>,
    sessions: &Mutex<BTreeMap<String, Arc<Mutex<ProtocolSession>>>>,
    slots: &ConnectionSlots,
    digest: &str,
    at: &str,
    expected_poison: Option<&ConnectionPoison>,
) -> Result<Vec<RunId>, PortError> {
    let cleanup = |cleanup: &ConnectionCleanup| {
        let request_gates = active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .values()
            .filter(|run| run.request.connection.binding_digest.as_str() == digest)
            .map(|run| {
                run.cancellation.revoke();
                Arc::clone(&run.request_gate)
            })
            .collect::<Vec<_>>();
        let _request_guards = request_gates
            .iter()
            .map(|gate| gate.lock().map_err(|_| internal_failure()))
            .collect::<Result<Vec<_>, _>>()?;
        let session = sessions
            .lock()
            .map_err(|_| internal_failure())?
            .get(digest)
            .cloned();
        let mut session_guard = session
            .as_ref()
            .map(|session| session.lock().map_err(|_| internal_failure()))
            .transpose()?;
        if let Some(session) = session_guard.as_mut() {
            session.connection_lost();
        }
        let interrupted = store.interrupt_connection(digest, at)?;
        active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .retain(|_, run| run.request.connection.binding_digest.as_str() != digest);
        sessions
            .lock()
            .map_err(|_| internal_failure())?
            .remove(digest);
        slots.complete_interruption(cleanup)?;
        Ok(interrupted)
    };
    if let Some(poison) = expected_poison {
        return Ok(slots
            .retry_poison(poison, || {
                cleanup(&ConnectionCleanup::Poisoned(poison.clone()))
            })?
            .unwrap_or_default());
    }
    slots.interrupt(digest, cleanup)
}

impl PeerEventSink for RuntimeSink {
    fn receive(&self, frame: ProtocolFrame) -> Result<InboundDisposition, ProtocolError> {
        self.receive_frame(frame)
    }

    fn receive_raw(&self, bytes: &[u8]) -> Result<InboundDisposition, ProtocolError> {
        match self.codec.decode(bytes) {
            Ok(frame) => self.receive_frame(frame),
            Err(error) => {
                self.connection_lost()?;
                Err(error)
            }
        }
    }

    fn request(&self, frame: ProtocolFrame) -> Result<ProtocolFrame, ProtocolError> {
        self.request_frame(frame)
    }

    fn connection_lost(&self) -> Result<(), ProtocolError> {
        self.gate.wait_until_ready()?;
        let now = match runtime_time(self.clock.as_ref()) {
            Ok(now) => now,
            Err(_) => {
                self.slots
                    .poison_connection(self.request.connection.binding_digest.as_str())
                    .map(|_| ())
                    .map_err(|_| ProtocolError::InternalAgentFailure)?;
                return Err(ProtocolError::InternalAgentFailure);
            }
        };
        self.interrupt(now)
    }
}
