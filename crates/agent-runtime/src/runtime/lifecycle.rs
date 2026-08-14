struct RuntimeDependencies {
    store: Arc<dyn AgentRunStore>,
    artifacts: Arc<dyn AgentArtifactStore>,
    protocol_requests: Arc<dyn ProtocolRequestStore>,
    response_artifacts: Arc<dyn ProtocolResponseArtifactPublisher>,
    clock: Arc<dyn Clock>,
}

impl ProtocolAgentRuntime {
    pub fn new(
        store: Arc<dyn AgentRunStore>,
        artifacts: Arc<dyn AgentArtifactStore>,
        protocol_requests: Arc<dyn ProtocolRequestStore>,
        response_artifacts: Arc<dyn ProtocolResponseArtifactPublisher>,
        clock: Arc<dyn Clock>,
        agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
    ) -> Result<Self, PortError> {
        Self::build(
            RuntimeDependencies {
                store,
                artifacts,
                protocol_requests,
                response_artifacts,
                clock,
            },
            agents,
            Arc::new(DenyAgentRequestHandler),
            false,
        )
    }

    pub fn new_with_request_handler(
        store: Arc<dyn AgentRunStore>,
        artifacts: Arc<dyn AgentArtifactStore>,
        protocol_requests: Arc<dyn ProtocolRequestStore>,
        response_artifacts: Arc<dyn ProtocolResponseArtifactPublisher>,
        clock: Arc<dyn Clock>,
        agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
        request_handler: Arc<dyn AgentRequestHandler>,
    ) -> Result<Self, PortError> {
        Self::build(
            RuntimeDependencies {
                store,
                artifacts,
                protocol_requests,
                response_artifacts,
                clock,
            },
            agents,
            request_handler,
            true,
        )
    }

    fn build(
        dependencies: RuntimeDependencies,
        agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
        request_handler: Arc<dyn AgentRequestHandler>,
        request_routing_enabled: bool,
    ) -> Result<Self, PortError> {
        let RuntimeDependencies {
            store,
            artifacts,
            protocol_requests,
            response_artifacts,
            clock,
        } = dependencies;
        let mut agent_ids = BTreeSet::new();
        let mut connection_ids = BTreeSet::new();
        let mut recovery_digests = BTreeSet::new();
        let mut authoritative_connection_digests = BTreeMap::new();
        for (descriptor, connection_digest, peer) in &agents {
            let peer_descriptor = peer.descriptor();
            descriptor.validate().map_err(|_| invalid_input())?;
            validate_descriptor(descriptor, &peer_descriptor)?;
            if !agent_ids.insert(descriptor.agent_id.clone())
                || !connection_ids.insert(peer_descriptor.binding.connection_id.clone())
            {
                return Err(conflict());
            }
            authoritative_connection_digests.insert(
                peer_descriptor.binding.connection_id,
                connection_digest.clone(),
            );
            recovery_digests.insert(connection_digest.as_str().to_owned());
        }
        let mut peers = BTreeMap::new();
        let mut descriptors = BTreeMap::new();
        for (descriptor, _, peer) in agents {
            store.register_descriptor(&descriptor)?;
            peers.insert(descriptor.agent_id.clone(), peer);
            descriptors.insert(descriptor.agent_id.clone(), descriptor);
        }
        let recovery_time = runtime_time(clock.as_ref())?;
        for connection_digest in recovery_digests {
            store.interrupt_connection(&connection_digest, &recovery_time.text)?;
        }
        Ok(Self {
            store,
            artifacts,
            protocol_requests,
            response_artifacts,
            clock,
            request_handler,
            request_routing_enabled,
            peers,
            descriptors,
            authoritative_connection_digests,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            active_runs: Arc::new(Mutex::new(BTreeMap::new())),
            slots: Arc::new(ConnectionSlots::default()),
            pending_run_cleanups: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        })
    }

    pub fn check_timeouts(&self) -> Result<Vec<RunId>, PortError> {
        let poisoned = self.slots.poisoned_connections()?;
        let now = match self.now() {
            Ok(now) => now,
            Err(error) => {
                let digests = self
                    .active_runs
                    .lock()
                    .map_err(|_| internal_failure())?
                    .values()
                    .map(|run| run.request.connection.binding_digest.as_str().to_owned())
                    .collect::<BTreeSet<_>>();
                for digest in digests {
                    self.slots.poison_connection(&digest)?;
                }
                return Err(error);
            }
        };
        let mut resolved = Vec::new();
        let mut retry_error = self.retry_pending_run_cleanups(now.timestamp).err();
        for poison in poisoned {
            match self.retry_interruption(&poison, &now.text) {
                Ok(interrupted) => resolved.extend(interrupted),
                Err(error) => {
                    retry_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = retry_error {
            return Err(error);
        }
        let active = self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut checked_connections = BTreeSet::new();
        for run in active {
            if !self.is_active(&run.request.run_id)? {
                continue;
            }
            if now.date_time >= run.deadline
                || run
                    .cancellation_deadline
                    .is_some_and(|deadline| now.date_time >= deadline)
            {
                run.cancellation.revoke();
                let _request_guard = run.request_gate.lock().map_err(|_| internal_failure())?;
                if !self.is_active(&run.request.run_id)? {
                    continue;
                }
                let deadline_now = self.now()?;
                if deadline_now.date_time < run.deadline
                    && run
                        .cancellation_deadline
                        .is_none_or(|deadline| deadline_now.date_time < deadline)
                {
                    continue;
                }
                let _ = run
                    .session
                    .lock()
                    .map_err(|_| internal_failure())?
                    .check_timeouts(deadline_now.date_time);
                self.persist_runtime_terminal(
                    &run.request,
                    AgentRunStatus::Terminated,
                    "agent run deadline expired",
                    deadline_now.timestamp,
                )?;
                self.active_runs
                    .lock()
                    .map_err(|_| internal_failure())?
                    .remove(run.request.run_id.as_str());
                run.slot.release();
                drop(_request_guard);
                if let Ok(frame) = cancel_frame(&run.request.run_id, &self.request_id(), "deadline")
                {
                    if let Ok(cancel) = RunCancel::try_from(frame) {
                        let _ = run.peer.cancel(cancel);
                    }
                }
                resolved.push(run.request.run_id);
                continue;
            }

            let connection_id = run.request.connection.connection_id.clone();
            if !checked_connections.insert(connection_id) {
                continue;
            }
            let timed_out = matches!(
                run.session
                    .lock()
                    .map_err(|_| internal_failure())?
                    .check_timeouts(now.date_time),
                Err(ProtocolError::Timeout)
            );
            if timed_out {
                resolved.extend(self.interrupt_connection(
                    run.request.connection.binding_digest.as_str(),
                    &now.text,
                )?);
            }
        }
        Ok(resolved)
    }

    pub fn shutdown(&self) -> Result<(), PortError> {
        let mut peer_error = None;
        for peer in self.peers.values() {
            self.slots
                .retire_connection(&peer.descriptor().binding.connection_id)?;
            if let Err(error) = peer.shutdown() {
                peer_error.get_or_insert(error);
            }
        }
        let now = self.now()?;
        let digests = self.slots.known_digests()?;
        for digest in digests {
            self.interrupt_connection(&digest, &now.text)?;
        }
        if let Some(error) = peer_error {
            Err(protocol_port_error(error))
        } else {
            Ok(())
        }
    }

    fn start(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        request.validate().map_err(|_| invalid_input())?;
        let peer = self
            .peers
            .get(&request.agent_id)
            .cloned()
            .ok_or_else(not_found)?;
        if !self
            .descriptors
            .get(&request.agent_id)
            .is_some_and(|descriptor| descriptor.enabled)
        {
            return Err(permission_denied());
        }
        let authoritative_connection_digest = self
            .authoritative_connection_digests
            .get(&request.connection.connection_id)
            .ok_or_else(invalid_input)?;
        validate_request_peer(
            &request,
            &peer.descriptor(),
            authoritative_connection_digest,
        )?;
        let effective_context = self.artifacts.load_effective_context(&request.context)?;
        if digest_bytes(&effective_context) != request.context.content_digest {
            return Err(invalid_input());
        }
        let now = self.now()?;
        if request.run_config.limits.deadline <= now.timestamp {
            return Err(invalid_input());
        }
        let slot = self.slots.reserve(
            &request.connection.connection_id,
            request.connection.binding_digest.as_str(),
            &request.run_id,
            peer.descriptor().capabilities.max_concurrent_runs,
        )?;
        let created = self.store.create_bound_run(&request)?;
        if created.status.is_terminal() {
            slot.release();
            return Err(conflict());
        }

        let deadline = timestamp_date_time(request.run_config.limits.deadline)?;
        let gate = Arc::new(SinkGate::new());
        let request_gate = Arc::new(Mutex::new(()));
        let cancellation = AgentRequestCancellation::new();
        let started = self.slots.start_handshake(&slot, || {
            let session = self.session(&request, &peer.descriptor(), &now)?;
            let request_id = format!("core:run-start:{}", request.run_id.as_str());
            let start = run_start_frame(&request, &request_id)?;
            let begun = self.durable_begin_core_request(&request, &start, &now)?;
            {
                let mut session = session.lock().map_err(|_| internal_failure())?;
                match &begun {
                    DurableCoreRequestBegin::Begun(_) => session
                        .outbound(start.clone(), now.date_time)
                        .map_err(protocol_port_error)?,
                    DurableCoreRequestBegin::Pending(_) => session
                        .restore_pending_request(start.clone(), now.date_time)
                        .map_err(protocol_port_error)?,
                    DurableCoreRequestBegin::Replayed { response } => {
                        session
                            .restore_pending_request(start.clone(), now.date_time)
                            .map_err(protocol_port_error)?;
                        session
                            .receive_response(response.clone(), now.date_time)
                            .map_err(protocol_port_error)?;
                    }
                }
            }
            if let DurableCoreRequestBegin::Replayed { response } = &begun {
                return Ok::<_, PortError>((
                    session,
                    request_id,
                    None,
                    Ok(run_start_acceptance_from_response(response)?),
                ));
            }
            if matches!(&begun, DurableCoreRequestBegin::Pending(_)) {
                return Err(conflict());
            }
            let run_start = RunStart::new(
                start,
                RunExecutionBinding {
                    provider_id: request.run_config.provider_id.clone(),
                    model_id: request.run_config.model_id.clone(),
                    max_output_tokens: request.run_config.limits.max_output_tokens,
                    generation_parameters: request
                        .run_config
                        .generation_parameters
                        .canonical_json
                        .clone(),
                    generation_parameters_digest: request
                        .run_config
                        .generation_parameters
                        .digest
                        .as_str()
                        .to_owned(),
                    effective_context,
                    effective_context_artifact_id: request
                        .context
                        .effective_context_artifact_id
                        .as_str()
                        .to_owned(),
                    effective_context_digest: request.context.content_digest.as_str().to_owned(),
                    supersedes_run_id: request
                        .supersedes_run_id
                        .as_ref()
                        .map(|run_id| run_id.as_str().to_owned()),
                },
            )
            .map_err(protocol_port_error)?;
            let sink = RuntimeSink {
                store: Arc::clone(&self.store),
                artifacts: Arc::clone(&self.artifacts),
                protocol_requests: Arc::clone(&self.protocol_requests),
                response_artifacts: Arc::clone(&self.response_artifacts),
                clock: Arc::clone(&self.clock),
                request_handler: Arc::clone(&self.request_handler),
                request_routing_enabled: self.request_routing_enabled,
                session: Arc::clone(&session),
                peer: Arc::clone(&peer),
                request: request.clone(),
                active_runs: Arc::clone(&self.active_runs),
                sessions: Arc::clone(&self.sessions),
                slot: slot.clone(),
                gate: Arc::clone(&gate),
                slots: Arc::clone(&self.slots),
                request_gate: Arc::clone(&request_gate),
                cancellation: cancellation.clone(),
                request_state: Mutex::new(RunRequestState::default()),
                codec: NdjsonCodec::default(),
            };
            Ok::<_, PortError>((
                session,
                request_id,
                begun.incomplete_begin().cloned(),
                peer.start(run_start, Box::new(sink)),
            ))
        });
        let (session, request_id, durable_begin, started) = match started {
            Ok(started) => started?,
            Err(error) => {
                gate.fail();
                let _ = self.cleanup_unstarted_run(&request);
                return Err(error);
            }
        };
        let acceptance = match started {
            Ok(acceptance)
                if acceptance.accepted && acceptance.run_id == request.run_id.as_str() =>
            {
                acceptance
            }
            Ok(_) => {
                gate.fail();
                let error = invalid_input();
                self.compensate_started_run(
                    &request,
                    peer.as_ref(),
                    AgentRunStatus::Failed,
                    "peer rejected the bound run",
                );
                return Err(error);
            }
            Err(error) => {
                gate.fail();
                let original = protocol_port_error(error);
                self.compensate_started_run(
                    &request,
                    peer.as_ref(),
                    AgentRunStatus::Interrupted,
                    "peer failed before acceptance",
                );
                return Err(original);
            }
        };

        let after_start = (|| {
            let accepted = self.now()?;
            if let Some(begin) = &durable_begin {
                let response = success_response(
                    &request_id,
                    json!({ "accepted": acceptance.accepted, "runId": acceptance.run_id }),
                )?;
                session
                    .lock()
                    .map_err(|_| internal_failure())?
                    .validate_response(&response)
                    .map_err(protocol_port_error)?;
                let durable =
                    self.durable_complete_core_response(begin, &response, &accepted.text)?;
                session
                    .lock()
                    .map_err(|_| internal_failure())?
                    .receive_response(durable.clone(), accepted.date_time)
                    .map_err(protocol_port_error)?;
                let durable_acceptance = run_start_acceptance_from_response(&durable)?;
                if durable_acceptance != acceptance {
                    return Err(conflict());
                }
            }
            gate.accepted()?;
            for channel in ["content", "status", "telemetry"] {
                let stream = ProtocolStreamIdentity::new(
                    request.connection.connection_id.clone(),
                    request.run_id.clone(),
                    channel,
                )?;
                if let Some(sequence) = self.protocol_requests.load_stream_head(&stream)? {
                    session
                        .lock()
                        .map_err(|_| internal_failure())?
                        .restore_stream_head(request.run_id.as_str(), channel, sequence.get())
                        .map_err(protocol_port_error)?;
                }
            }
            self.store.accept_run(&request.run_id, &accepted.text)?;
            let running = self.now()?;
            self.store.mark_running(&request.run_id, &running.text)?;
            self.active_runs
                .lock()
                .map_err(|_| internal_failure())?
                .insert(
                    request.run_id.as_str().to_owned(),
                    ActiveRun {
                        request: request.clone(),
                        peer: Arc::clone(&peer),
                        session: Arc::clone(&session),
                        slot: slot.clone(),
                        deadline,
                        cancellation_deadline: None,
                        request_gate,
                        cancellation,
                    },
                );
            gate.ready()?;
            Ok::<_, PortError>(accepted)
        })();
        let accepted = match after_start {
            Ok(accepted) => accepted,
            Err(error) => {
                gate.fail();
                self.compensate_started_run(
                    &request,
                    peer.as_ref(),
                    AgentRunStatus::Interrupted,
                    "peer start could not be committed",
                );
                return Err(error);
            }
        };
        Ok(AgentRunReceipt {
            run_id: request.run_id,
            accepted_at: accepted.timestamp,
        })
    }

    fn cancel_run(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        request.validate().map_err(|_| invalid_input())?;
        let active = self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .get(request.run_id.as_str())
            .cloned()
            .ok_or_else(not_found)?;
        let request_guard = active.request_gate.lock().map_err(|_| internal_failure())?;
        if !self.is_active(&request.run_id)? {
            return Err(not_found());
        }
        let now = self.now()?;
        let request_id = format!(
            "core:run-cancel:{}:{:x}",
            request.run_id.as_str(),
            Sha256::digest(request.reason.as_bytes()),
        );
        let frame = cancel_frame(&request.run_id, &request_id, &request.reason)?;
        let begun = self.durable_begin_core_request(&active.request, &frame, &now)?;
        {
            let mut session = active.session.lock().map_err(|_| internal_failure())?;
            match &begun {
                DurableCoreRequestBegin::Begun(_) => session
                    .outbound(frame.clone(), now.date_time)
                    .map_err(protocol_port_error)?,
                DurableCoreRequestBegin::Pending(_) => session
                    .restore_pending_request(frame.clone(), now.date_time)
                    .map_err(protocol_port_error)?,
                DurableCoreRequestBegin::Replayed { response } => {
                    session
                        .restore_pending_request(frame.clone(), now.date_time)
                        .map_err(protocol_port_error)?;
                    session
                        .receive_response(response.clone(), now.date_time)
                        .map_err(protocol_port_error)?;
                }
            }
        }
        drop(request_guard);
        let acceptance = match &begun {
            DurableCoreRequestBegin::Replayed { response } => {
                cancel_acceptance_from_response(response)?
            }
            DurableCoreRequestBegin::Begun(_) => active
                .peer
                .cancel(RunCancel::try_from(frame).map_err(protocol_port_error)?)
                .map_err(protocol_port_error)?,
            DurableCoreRequestBegin::Pending(_) => return Err(conflict()),
        };
        if !acceptance.accepted || acceptance.run_id != request.run_id.as_str() {
            return Err(invalid_input());
        }
        if let Some(begin) = begun.incomplete_begin() {
            let response = success_response(
                &request_id,
                json!({
                    "runId": acceptance.run_id.as_str(),
                    "outcome": "cancellation_requested"
                }),
            )?;
            active
                .session
                .lock()
                .map_err(|_| internal_failure())?
                .validate_response(&response)
                .map_err(protocol_port_error)?;
            let durable = self.durable_complete_core_response(begin, &response, &now.text)?;
            active
                .session
                .lock()
                .map_err(|_| internal_failure())?
                .receive_response(durable.clone(), now.date_time)
                .map_err(protocol_port_error)?;
            if cancel_acceptance_from_response(&durable)? != acceptance {
                return Err(conflict());
            }
        }
        let _request_guard = active.request_gate.lock().map_err(|_| internal_failure())?;
        active.cancellation.revoke();
        if let Some(active) = self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .get_mut(request.run_id.as_str())
        {
            active.cancellation_deadline = Some(
                now.date_time
                    + ChronoDuration::milliseconds(
                        i64::try_from(request.deadline_ms).map_err(|_| invalid_input())?,
                    ),
            );
        }
        Ok(AgentCancellationReceipt {
            run_id: request.run_id,
            accepted_at: now.timestamp,
        })
    }

    fn durable_begin_core_request(
        &self,
        request: &BoundAgentRunRequest,
        frame: &ProtocolFrame,
        now: &RuntimeTime,
    ) -> Result<DurableCoreRequestBegin, PortError> {
        let value = frame_value(frame).map_err(protocol_port_error)?;
        let request_id = required_string(&value, "/id").map_err(protocol_port_error)?;
        let method = required_string(&value, "/method").map_err(protocol_port_error)?;
        let begin = ProtocolRequestBegin::new(
            ProtocolRequestIdentity::new(
                request.connection.connection_id.clone(),
                request_id,
                method,
                Sha256Digest::new(
                    canonical_request_digest(frame).map_err(protocol_port_error)?,
                )
                .map_err(|_| internal_failure())?,
            )?,
            Some(request.task_id.clone()),
            Some(request.run_id.clone()),
            now.text.clone(),
        )?;
        match self.protocol_requests.begin(&begin)? {
            ProtocolRequestBeginResult::Begun => Ok(DurableCoreRequestBegin::Begun(begin)),
            ProtocolRequestBeginResult::Pending => Ok(DurableCoreRequestBegin::Pending(begin)),
            ProtocolRequestBeginResult::Replayed(terminal) => {
                if terminal.identity() != begin.identity() {
                    return Err(conflict());
                }
                let response = NdjsonCodec::default()
                    .decode(terminal.response().bytes())
                    .map_err(protocol_port_error)?;
                Ok(DurableCoreRequestBegin::Replayed { response })
            }
        }
    }

    fn durable_complete_core_response(
        &self,
        begin: &ProtocolRequestBegin,
        response: &ProtocolFrame,
        completed_at: &str,
    ) -> Result<ProtocolFrame, PortError> {
        let bytes = serde_json::to_vec(response).map_err(|_| internal_failure())?;
        let artifact = ProtocolResponseArtifact::new(
            protocol_response_artifact_id(begin.identity()).map_err(protocol_port_error)?,
            bytes.clone(),
        )?;
        let artifact = self
            .response_artifacts
            .publish_protocol_response(begin, &artifact)?;
        let durable_response = NdjsonCodec::default()
            .decode(artifact.bytes())
            .map_err(protocol_port_error)?;
        if artifact.bytes() != bytes {
            return Err(conflict());
        }
        let terminal = ProtocolRequestTerminal::new(
            begin.identity().clone(),
            response_terminal_status(&durable_response).map_err(protocol_port_error)?,
            artifact,
            completed_at.to_owned(),
        )?;
        let stored = self.protocol_requests.complete(&terminal)?;
        if stored != terminal {
            return Err(conflict());
        }
        NdjsonCodec::default()
            .decode(stored.response().bytes())
            .map_err(protocol_port_error)
    }

    fn session(
        &self,
        request: &BoundAgentRunRequest,
        descriptor: &PeerDescriptor,
        now: &RuntimeTime,
    ) -> Result<Arc<Mutex<ProtocolSession>>, PortError> {
        let mut sessions = self.sessions.lock().map_err(|_| internal_failure())?;
        let session_key = request.connection.binding_digest.as_str();
        if let Some(session) = sessions.get(session_key) {
            return Ok(Arc::clone(session));
        }
        let mut session = ProtocolSession::new_with_binding_digest(
            descriptor.binding.clone(),
            request.connection.binding_digest.as_str().to_owned(),
            ProtocolOffer {
                protocol_versions: BTreeSet::from([descriptor.protocol_version.clone()]),
                capabilities: descriptor.capabilities.clone(),
            },
            SessionLimits {
                max_output_bytes: MAX_OUTPUT_BYTES,
                heartbeat_timeout: Duration::from_secs(
                    u64::try_from(DEFAULT_HEARTBEAT_TIMEOUT_SECS)
                        .expect("positive heartbeat timeout"),
                ),
            },
            now.date_time,
        );
        let initialize_id = format!(
            "core:initialize:{}",
            request.connection.connection_id
        );
        let initialize = initialize_frame(
            descriptor,
            &initialize_id,
            request.connection.binding_digest.as_str(),
        )?;
        let begun = self.durable_begin_core_request(request, &initialize, now)?;
        let response = match &begun {
            DurableCoreRequestBegin::Begun(_) => {
                session
                    .outbound(initialize.clone(), now.date_time)
                    .map_err(protocol_port_error)?;
                initialize_response(descriptor, &initialize_id)?
            }
            DurableCoreRequestBegin::Pending(_) => {
                session
                    .restore_pending_request(initialize.clone(), now.date_time)
                    .map_err(protocol_port_error)?;
                initialize_response(descriptor, &initialize_id)?
            }
            DurableCoreRequestBegin::Replayed { response } => {
                session
                    .restore_pending_request(initialize, now.date_time)
                    .map_err(protocol_port_error)?;
                response.clone()
            }
        };
        session
            .validate_response(&response)
            .map_err(protocol_port_error)?;
        let response = match begun.incomplete_begin() {
            Some(begin) => self.durable_complete_core_response(begin, &response, &now.text)?,
            None => response,
        };
        session
            .receive_response(response, now.date_time)
            .map_err(protocol_port_error)?;
        session
            .outbound(initialized_frame(descriptor)?, now.date_time)
            .map_err(protocol_port_error)?;
        let session = Arc::new(Mutex::new(session));
        sessions.insert(session_key.to_owned(), Arc::clone(&session));
        Ok(session)
    }

    fn now(&self) -> Result<RuntimeTime, PortError> {
        runtime_time(self.clock.as_ref())
    }

    fn request_id(&self) -> String {
        format!(
            "core:{}",
            self.next_request_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn persist_runtime_terminal(
        &self,
        request: &BoundAgentRunRequest,
        status: AgentRunStatus,
        error: &str,
        at: Timestamp,
    ) -> Result<(), PortError> {
        publish_runtime_terminal(
            self.artifacts.as_ref(),
            self.store.as_ref(),
            request,
            status,
            error,
            at,
        )
    }

    fn compensate_started_run(
        &self,
        request: &BoundAgentRunRequest,
        peer: &dyn ProtocolPeer,
        status: AgentRunStatus,
        error: &str,
    ) {
        if let Ok(frame) = cancel_frame(&request.run_id, "core:start-compensation", "start_failed")
        {
            if let Ok(cancel) = RunCancel::try_from(frame) {
                let _ = peer.cancel(cancel);
            }
        }
        if self
            .slots
            .retire_connection(&request.connection.connection_id)
            .is_err()
        {
            return;
        }
        let _ = peer.shutdown();
        let connection_digest = request.connection.binding_digest.as_str();
        if let Ok(now) = self.now() {
            let _ = self.persist_runtime_terminal(request, status, error, now.timestamp);
            let _ = self.interrupt_connection(connection_digest, &now.text);
        }
    }

    fn cleanup_unstarted_run(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        self.queue_pending_run_cleanup(request)?;
        let now = self.now()?;
        self.retry_pending_run_cleanup(request.run_id.as_str(), now.timestamp)
    }

    fn retry_pending_run_cleanups(&self, at: Timestamp) -> Result<(), PortError> {
        let pending = {
            let mut pending = self
                .pending_run_cleanups
                .lock()
                .map_err(|_| internal_failure())?;
            std::mem::take(&mut *pending)
        };
        let mut retry_error = None;
        for (_, mut cleanup) in pending {
            match self.persist_pending_run_cleanup(&mut cleanup, at) {
                Ok(()) => {}
                Err(error) => {
                    let error = match self.requeue_pending_run_cleanup(cleanup) {
                        Ok(()) => error,
                        Err(requeue_error) => requeue_error,
                    };
                    retry_error.get_or_insert(error);
                }
            }
        }
        retry_error.map_or(Ok(()), Err)
    }

    fn retry_pending_run_cleanup(&self, run_id: &str, at: Timestamp) -> Result<(), PortError> {
        let Some(mut cleanup) = self
            .pending_run_cleanups
            .lock()
            .map_err(|_| internal_failure())?
            .remove(run_id)
        else {
            return Ok(());
        };
        if let Err(error) = self.persist_pending_run_cleanup(&mut cleanup, at) {
            self.requeue_pending_run_cleanup(cleanup)?;
            return Err(error);
        }
        Ok(())
    }

    fn queue_pending_run_cleanup(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        self.pending_run_cleanups
            .lock()
            .map_err(|_| internal_failure())?
            .entry(request.run_id.as_str().to_owned())
            .or_insert_with(|| PendingCleanup {
                request: request.clone(),
                content_artifact_id: None,
            });
        Ok(())
    }

    fn requeue_pending_run_cleanup(&self, cleanup: PendingCleanup) -> Result<(), PortError> {
        let run_id = cleanup.request.run_id.as_str().to_owned();
        self.pending_run_cleanups
            .lock()
            .map_err(|_| internal_failure())?
            .entry(run_id)
            .and_modify(|pending| {
                if pending.content_artifact_id.is_none() {
                    pending.content_artifact_id = cleanup.content_artifact_id.clone();
                }
            })
            .or_insert(cleanup);
        Ok(())
    }

    fn persist_pending_run_cleanup(
        &self,
        cleanup: &mut PendingCleanup,
        at: Timestamp,
    ) -> Result<(), PortError> {
        let error = "stale connection generation";
        let content_artifact_id = match &cleanup.content_artifact_id {
            Some(content_artifact_id) => content_artifact_id.clone(),
            None => {
                let message_id = stable_id("runtime-message", cleanup.request.run_id.as_str());
                let content_artifact_id =
                    self.artifacts
                        .publish_agent_message(&AgentMessageArtifact {
                            task_id: cleanup.request.task_id.clone(),
                            run_id: cleanup.request.run_id.clone(),
                            message_id,
                            content: error.as_bytes().to_vec(),
                        })?;
                cleanup.content_artifact_id = Some(content_artifact_id.clone());
                content_artifact_id
            }
        };
        self.store.persist_terminal(&runtime_terminal(
            &cleanup.request,
            AgentRunStatus::Interrupted,
            error,
            content_artifact_id,
            at,
        ))
    }

    fn interrupt_connection(&self, digest: &str, at: &str) -> Result<Vec<RunId>, PortError> {
        interrupt_connection_state(
            self.store.as_ref(),
            self.active_runs.as_ref(),
            self.sessions.as_ref(),
            self.slots.as_ref(),
            digest,
            at,
            None,
        )
    }

    fn retry_interruption(
        &self,
        poison: &ConnectionPoison,
        at: &str,
    ) -> Result<Vec<RunId>, PortError> {
        interrupt_connection_state(
            self.store.as_ref(),
            self.active_runs.as_ref(),
            self.sessions.as_ref(),
            self.slots.as_ref(),
            &poison.binding_digest,
            at,
            Some(poison),
        )
    }

    fn is_active(&self, run_id: &RunId) -> Result<bool, PortError> {
        Ok(self
            .active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .contains_key(run_id.as_str()))
    }
}

enum DurableCoreRequestBegin {
    Begun(ProtocolRequestBegin),
    Pending(ProtocolRequestBegin),
    Replayed { response: ProtocolFrame },
}

fn run_start_acceptance_from_response(
    response: &ProtocolFrame,
) -> Result<local_agent_terminal_agent_protocol::RunAcceptance, PortError> {
    let value = frame_value(response).map_err(protocol_port_error)?;
    Ok(local_agent_terminal_agent_protocol::RunAcceptance {
        run_id: required_string(&value, "/result/runId").map_err(protocol_port_error)?,
        accepted: value
            .pointer("/result/accepted")
            .and_then(Value::as_bool)
            .ok_or_else(invalid_input)?,
    })
}

fn cancel_acceptance_from_response(
    response: &ProtocolFrame,
) -> Result<local_agent_terminal_agent_protocol::CancelAcceptance, PortError> {
    let value = frame_value(response).map_err(protocol_port_error)?;
    if required_string(&value, "/result/outcome").map_err(protocol_port_error)?
        != "cancellation_requested"
    {
        return Err(invalid_input());
    }
    Ok(local_agent_terminal_agent_protocol::CancelAcceptance {
        run_id: required_string(&value, "/result/runId").map_err(protocol_port_error)?,
        accepted: true,
    })
}

impl DurableCoreRequestBegin {
    fn incomplete_begin(&self) -> Option<&ProtocolRequestBegin> {
        match self {
            Self::Begun(begin) | Self::Pending(begin) => Some(begin),
            Self::Replayed { .. } => None,
        }
    }
}

impl AgentRuntime for ProtocolAgentRuntime {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
        Ok(self.descriptors.values().cloned().collect())
    }

    fn prepare_run(&self, request: &BoundAgentRunRequest) -> Result<(), PortError> {
        self.store.create_bound_run(request).map(|_| ())
    }

    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        self.start(request)
    }

    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        self.cancel_run(request)
    }
}
