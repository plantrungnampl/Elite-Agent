
impl ProtocolAgentRuntime {
    pub fn new(
        store: Arc<dyn AgentRunStore>,
        artifacts: Arc<dyn AgentArtifactStore>,
        clock: Arc<dyn Clock>,
        agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
    ) -> Result<Self, PortError> {
        Self::build(
            store,
            artifacts,
            clock,
            agents,
            Arc::new(DenyAgentRequestHandler),
            false,
        )
    }

    pub fn new_with_request_handler(
        store: Arc<dyn AgentRunStore>,
        artifacts: Arc<dyn AgentArtifactStore>,
        clock: Arc<dyn Clock>,
        agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
        request_handler: Arc<dyn AgentRequestHandler>,
    ) -> Result<Self, PortError> {
        Self::build(store, artifacts, clock, agents, request_handler, true)
    }

    fn build(
        store: Arc<dyn AgentRunStore>,
        artifacts: Arc<dyn AgentArtifactStore>,
        clock: Arc<dyn Clock>,
        agents: Vec<(AgentDescriptor, Sha256Digest, Arc<dyn ProtocolPeer>)>,
        request_handler: Arc<dyn AgentRequestHandler>,
        request_routing_enabled: bool,
    ) -> Result<Self, PortError> {
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
        self.store.create_bound_run(&request)?;

        let deadline = timestamp_date_time(request.run_config.limits.deadline)?;
        let gate = Arc::new(SinkGate::new());
        let request_gate = Arc::new(Mutex::new(()));
        let cancellation = AgentRequestCancellation::new();
        let started = self.slots.start_handshake(&slot, || {
            let session = self.session(&request, &peer.descriptor(), now.date_time)?;
            let request_id = self.request_id();
            let start = run_start_frame(&request, &request_id)?;
            session
                .lock()
                .map_err(|_| internal_failure())?
                .outbound(start.clone(), now.date_time)
                .map_err(protocol_port_error)?;
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
            Ok::<_, PortError>((session, request_id, peer.start(run_start, Box::new(sink))))
        });
        let (session, request_id, started) = match started {
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
        if let Err(error) = gate.accepted() {
            gate.fail();
            self.compensate_started_run(
                &request,
                peer.as_ref(),
                AgentRunStatus::Interrupted,
                "peer start could not be committed",
            );
            return Err(error);
        }

        let after_start = (|| {
            let accepted = self.now()?;
            session
                .lock()
                .map_err(|_| internal_failure())?
                .receive_response(
                    success_response(
                        &request_id,
                        json!({ "accepted": acceptance.accepted, "runId": acceptance.run_id }),
                    )?,
                    accepted.date_time,
                )
                .map_err(protocol_port_error)?;
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
        active.cancellation.revoke();
        let _request_guard = active.request_gate.lock().map_err(|_| internal_failure())?;
        if !self.is_active(&request.run_id)? {
            return Err(not_found());
        }
        let now = self.now()?;
        let request_id = self.request_id();
        let frame = cancel_frame(&request.run_id, &request_id, &request.reason)?;
        active
            .session
            .lock()
            .map_err(|_| internal_failure())?
            .outbound(frame.clone(), now.date_time)
            .map_err(protocol_port_error)?;
        self.active_runs
            .lock()
            .map_err(|_| internal_failure())?
            .get_mut(request.run_id.as_str())
            .ok_or_else(not_found)?
            .cancellation_deadline = Some(
            now.date_time
                + ChronoDuration::milliseconds(
                    i64::try_from(request.deadline_ms).map_err(|_| invalid_input())?,
                ),
        );
        drop(_request_guard);
        let acceptance = active
            .peer
            .cancel(RunCancel::try_from(frame).map_err(protocol_port_error)?)
            .map_err(protocol_port_error)?;
        if !acceptance.accepted || acceptance.run_id != request.run_id.as_str() {
            return Err(invalid_input());
        }
        active
            .session
            .lock()
            .map_err(|_| internal_failure())?
            .receive_response(
                success_response(
                    &request_id,
                    json!({
                        "runId": acceptance.run_id,
                        "outcome": "cancellation_requested"
                    }),
                )?,
                now.date_time,
            )
            .map_err(protocol_port_error)?;
        Ok(AgentCancellationReceipt {
            run_id: request.run_id,
            accepted_at: now.timestamp,
        })
    }

    fn session(
        &self,
        request: &BoundAgentRunRequest,
        descriptor: &PeerDescriptor,
        now: DateTime<Utc>,
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
            now,
        );
        let initialize_id = self.request_id();
        session
            .outbound(
                initialize_frame(
                    descriptor,
                    &initialize_id,
                    request.connection.binding_digest.as_str(),
                )?,
                now,
            )
            .map_err(protocol_port_error)?;
        session
            .receive_response(initialize_response(descriptor, &initialize_id)?, now)
            .map_err(protocol_port_error)?;
        session
            .outbound(initialized_frame(descriptor)?, now)
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
        if let Ok(frame) = cancel_frame(&request.run_id, "core:start-compensation", "start_failed") {
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

impl AgentRuntime for ProtocolAgentRuntime {
    fn list_agents(&self) -> Result<Vec<AgentDescriptor>, PortError> {
        Ok(self.descriptors.values().cloned().collect())
    }

    fn start_run(&self, request: BoundAgentRunRequest) -> Result<AgentRunReceipt, PortError> {
        self.start(request)
    }

    fn cancel(&self, request: CancelAgentRun) -> Result<AgentCancellationReceipt, PortError> {
        self.cancel_run(request)
    }
}
