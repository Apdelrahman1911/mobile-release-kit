# frozen_string_literal: true

# Test-only ownership, shared by the process fixture and its observation commands.
# Default Ruby SIGINT can bypass Thread.handle_interrupt. Queue it through
# Thread#raise instead of raising synchronously from a trap; restore INT last.
module UploadProcessFixture
  # A test-only, reversible observation of the objects the real capture owns.
  # It never supplies a status, closes an endpoint, joins a task, or signals a
  # number on the capture's behalf. In particular a forwarded K/V record is not
  # an O-owned child. Installed callers pass their ALREADY loaded module here.
  class CaptureObservation
    VERSION = 1
    class << self
      attr_accessor :current
    end
    attr_reader :session, :events, :custodian_spec, :source_origins

    class Hooks
      def initialize
        @entries = []
      end

      def wrap(target, name, &wrapper)
        original = target.instance_method(name)
        visibility = if target.private_method_defined?(name)
          :private
        elsif target.protected_method_defined?(name)
          :protected
        else
          :public
        end
        body = proc do |*arguments, **keywords, &block|
          wrapper.call(original.bind(self), self, arguments, keywords, block)
        end
        entry = [target, name, original, visibility, nil]
        @entries << entry # Custody exists BEFORE the potentially effectful call.
        Thread.handle_interrupt(Exception => :never) do
          target.send(:define_method, name, body)
          entry[4] = target.instance_method(name)
          target.send(visibility, name)
        end
      end

      def restore
        failures = []
        @entries.reverse_each do |target, name, original, visibility, installed|
          if installed.nil? && target.instance_method(name) == original
            next # A positively unchanged method, not guessed failed publication.
          end
          unless target.instance_method(name) == installed
            failures << "changed_observation_hook"
            next # Never overwrite another owner's replacement.
          end
          target.send(:define_method, name, original)
          target.send(visibility, name)
          failures << "unrestored_observation_hook" unless target.instance_method(name) == original
        rescue Exception => error
          failures << error.class.name
        end
        failures
      end
    end

    def initialize(native:, root:)
      @native, @root = native, root
      @events, @slots, @attempts, @observer_errors = [], [], [], []
      @constructed_slots, @closed_launches, @finished_creations = [], [], []
      @creator_gate_entered = false
      @actual_joins, @actual_closes, @actual_eofs, @actual_waits = [], [], [], []
      @session = @custodian_spec = @snapshot = nil
      @entered = @finished = @hooks_restored = false
      @real_install_attempted = false
    end

    def origin(method)
      path, line = method.source_location
      raise Failure.new("fixture-source", "native method has no Ruby source") unless path && line
      path = File.realpath(path)
      bytes = File.binread(path, 1_048_577)
      raise Failure.new("fixture-source", "oversized observed runtime source") if bytes.bytesize > 1_048_576
      {"path" => path, "line" => line, "sha256" => Digest::SHA256.hexdigest(bytes)}
    end

    def source_snapshot
      {"capture" => origin(@native.method(:capture)),
       "spawn" => origin(@spawn.method(:create)),
       "helper" => origin(@helper.method(:helper_main))}
    end

    def event(name, object = nil)
      raise Failure.new("fixture-observation", "native observation exceeded its bound") if @events.length >= 256
      @events << {"event" => name.to_s, "thread" => Thread.current.object_id,
                  "object" => object&.object_id}
      on_event(name, object)
    end

    # Subclasses inject test faults at real methods, never through production
    # callbacks or fabricated Open3 streams/waiters.
    def on_event(_name, _object); end

    def install
      @real_install_attempted = true # Monotonic, BEFORE actual hook/source/native effects.
      UploadProcessFixture.assert_domain_reusable!
      raise Failure.new("fixture-observation", "overlapping capture observers") if CaptureObservation.current
      @spawn = MobileReleaseKit.const_get(:NativeProcessSpawn)
      @helper = MobileReleaseKit.const_get(:NativeUploadProcess)
      session_class = @native.const_get(:CaptureSession, false)
      @source_origins = source_snapshot
      @hooks = Hooks.new
      CaptureObservation.current = self
      observer = self
      @hooks.wrap(session_class, :execute) do |original, object, arguments, keywords, block|
        raise Failure.new("fixture-observation", "more than one capture in an observation") if observer.session
        observer.instance_variable_set(:@session, object)
        observer.event(:execute_enter, object)
        begin
          value = original.call(*arguments, **keywords, &block)
          observer.instance_variable_set(:@execute_returned, true)
          value
        ensure
          observer.event(:execute_exit, object)
        end
      end
      @hooks.wrap(session_class, :run) do |original, object, arguments, keywords, block|
        observer.event(:run_enter, object)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(session_class, :start_creator) do |original, object, arguments, keywords, block|
        observer.instance_variable_set(:@creator_gate_entered, true)
        observer.event(:creator_scope_enter, object)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(@helper.const_get(:TaskSlot), :initialize) do |original, object, arguments, keywords, block|
        observer.instance_variable_get(:@constructed_slots) << object
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(session_class, :close_stdin_after_ready) do |original, object, arguments, keywords, block|
        raise Failure.new("fixture-observation", "stdin close preceded real READY") unless object.ready
        observer.event(:ready_before_stdin_close, object)
        value = original.call(*arguments, **keywords, &block)
        observer.event(:stdin_close_returned, object)
        value
      end
      @hooks.wrap(@helper.const_get(:TaskSlot), :start) do |original, object, arguments, keywords, block|
        observer.instance_variable_get(:@slots) << object
        observer.event(:task_start, object)
        original.call(*arguments, **keywords, &block)
      end
      %i[close_launch! cancel! record_cleanup_error].each do |name|
        @hooks.wrap(@helper.const_get(:TaskSlot), name) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          observer.instance_variable_get(:@closed_launches) << object
          value
        end
      end
      @hooks.wrap(@spawn.const_get(:Acquisition), :finish_creation!) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        observer.instance_variable_get(:@finished_creations) << object if value.equal?(true)
        value
      end
      @hooks.wrap(Thread, :join) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        if value.equal?(object) && observer.instance_variable_get(:@slots).any? { |slot| slot.thread.equal?(object) }
          observer.instance_variable_get(:@actual_joins) << object
        end
        value
      end
      @hooks.wrap(@spawn.const_get(:IOLease), :close_once) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        observer.instance_variable_get(:@actual_closes) << object
        value
      end
      @hooks.wrap(IO, :read_nonblock) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        observer.instance_variable_get(:@actual_eofs) << object if value.nil?
        value
      end
      @hooks.wrap(@spawn.const_get(:Child), :poll_wait) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        observer.instance_variable_get(:@actual_waits) << [object, value] if value
        value
      end
      @hooks.wrap(@spawn.singleton_class, :create) do |original, _object, arguments, keywords, block|
        acquisition, spec = arguments
        observer.instance_variable_get(:@attempts) << acquisition
        tracked = observer.session && observer.session.acquisition.equal?(acquisition)
        if tracked
          observer.instance_variable_set(:@custodian_spec,
            {"executable" => spec.executable, "argv" => spec.argv.dup,
             "environment" => spec.env.dup, "creatorCwd" => Dir.pwd,
             "fdRoles" => spec.fd_sources.map { |lease| lease.role.to_s }})
          observer.event(:custodian_attempt, acquisition)
        end
        value = original.call(*arguments, **keywords, &block)
        observer.event(:custodian_published, acquisition) if tracked
        value
      end
    end

    def observe
      UploadProcessFixture.assert_domain_reusable!
      raise Failure.new("fixture-observation", "capture observation already used") if @entered
      @entered = true
      value = primary = nil
      begin
        install
        value = yield
      rescue Exception => error
        primary = error
      ensure
        begin
          @observer_errors.concat(@hooks.restore) if @hooks
          @hooks_restored = @hooks && @observer_errors.empty?
          @observer_errors << "runtime_source_changed" if @source_origins && source_snapshot != @source_origins
        rescue Exception => error
          @observer_errors << error.class.name
        ensure
          CaptureObservation.current = nil if CaptureObservation.current.equal?(self)
          @finished = true
          begin
            @snapshot = build_snapshot
          rescue Exception => error
            @observer_errors << error.class.name
            @snapshot = {"version" => VERSION, "finalized" => false, "noProducers" => false,
                         "unknown" => true, "observerErrors" => @observer_errors.dup}
          end
          if @snapshot.fetch("unknown")
            (UploadProcessFixture.instance_variable_get(:@unresolved_roots) ||
              UploadProcessFixture.instance_variable_set(:@unresolved_roots, {}))[@root] = true
            # An actual install attempt is already effectful even if no session
            # was published. Latch BEFORE rethrowing the caller's original error
            # so a rescued ContractError cannot admit the next acquisition.
            # An overridden, wholly inert toy install still keeps its UNKNOWN
            # diagnostic entry; root type is never an exemption for real work.
            if @real_install_attempted || @session || @custodian_spec || @source_origins ||
               !@slots.empty? || !@attempts.empty? || !@constructed_slots.empty? || !@finished_creations.empty?
              UploadProcessFixture.retain_process_case!(self)
              UploadProcessFixture.retain_unknown_domain!(@root)
            end
          end
        end
      end
      raise primary if primary # Observation/cleanup cannot replace this object.
      raise Failure.new("fixture-observation", "native observation did not restore cleanly") unless @observer_errors.empty?
      if @execute_returned && @snapshot.fetch("unknown")
        raise Failure.new("fixture-observation", "capture returned without proven finality")
      end
      value
    end

    def receipt_record(receipt)
      return {"state" => "unknown"} unless receipt
      raw = receipt.raw_status
      unless raw.is_a?(Process::Status) && raw.pid == receipt.pid &&
             %w[exit signal].include?(receipt.status_kind) &&
             (receipt.status_kind == "exit" ? raw.exited? && raw.exitstatus == receipt.status_code :
               raw.signaled? && raw.termsig == receipt.status_code)
        raise Failure.new("fixture-observation", "custodian receipt is not its original wait")
      end
      {"state" => "reaped", "pid" => receipt.pid,
       "status_kind" => receipt.status_kind, "status_code" => receipt.status_code}
    end

    def task_record(slot, role)
      return {"role" => role, "state" => "unpublished"} unless slot
      closed = slot.launch_retired? && @closed_launches.include?(slot)
      never_started = !slot.start_attempted? && slot.thread.nil? && closed && !slot.unresolved?
      {"role" => role, "identity" => slot.object_id, "thread" => slot.thread&.object_id,
       "state" => never_started ? "not_started" : "attempted",
       "startAttempted" => slot.start_attempted?, "finished" => slot.finished?,
       "joined" => slot.joined?, "actualJoinObserved" => @actual_joins.include?(slot.thread),
       "launchRetired" => slot.launch_retired?, "actualLaunchClosureObserved" => closed,
       "actualConstructionObserved" => @constructed_slots.include?(slot),
       "unresolved" => slot.unresolved?}
    end

    def task_settled?(task)
      return false unless task["actualConstructionObserved"] && task["launchRetired"] &&
                          task["actualLaunchClosureObserved"] && !task["unresolved"]
      if task["state"] == "not_started"
        !task["startAttempted"] && task["thread"].nil? && !task["joined"] && !task["actualJoinObserved"]
      else
        task["startAttempted"] && task["finished"] && task["joined"] && task["actualJoinObserved"]
      end
    end

    def terminal_cleanup_confirmed?(frame)
      return false unless frame.is_a?(Hash) && frame.keys.sort == %w[cleanup group keeper outcome type v validator] &&
                          frame["v"].instance_of?(Integer) && frame["v"] == 1 && frame["type"] == "FINAL" && frame["cleanup"] == "confirmed" &&
                          %w[ok rejected failed].include?(frame["outcome"])
      children = %w[keeper validator].map { |role| frame[role] }
      known = children.all? do |child|
        child == {"state" => "not_attempted"} ||
          (child.is_a?(Hash) && child.keys.sort == %w[pid state status_code status_kind] &&
           child["state"] == "reaped" && child["pid"].is_a?(Integer) && child["pid"].between?(2, 2_147_483_647) &&
           %w[exit signal].include?(child["status_kind"]) && child["status_code"].is_a?(Integer) &&
           child["status_code"].between?(child["status_kind"] == "exit" ? 0 : 1, child["status_kind"] == "exit" ? 255 : @spawn.nsig - 1))
      end
      group = frame["group"]
      group_known = group == {"state" => "not_created"} ||
        (group.is_a?(Hash) && group.keys.sort == %w[absent id state] && group["state"] == "retired" &&
         group["id"].is_a?(Integer) && group["id"].between?(2, 2_147_483_647) && group["absent"].equal?(true))
      return false unless known && group_known
      if children.first["state"] == "not_attempted"
        return @session.reserved.nil? && @session.ready.nil? && children.last["state"] == "not_attempted" &&
          group["state"] == "not_created" && frame["outcome"] == "failed"
      end
      # The private helper exit distinguishes settled local failure (2) from
      # default/tail uncertainty (1). A matching failure label cannot repair an
      # unknown original K outcome or accept a late tail error as finality.
      keeper_codes = frame["outcome"] == "failed" ? [0, 2] : [0]
      return false unless children.first["status_kind"] == "exit" && keeper_codes.include?(children.first["status_code"])
      if group["state"] == "not_created"
        return @session.reserved.nil? && @session.ready.nil? && children.last["state"] == "not_attempted" && frame["outcome"] == "failed"
      end
      return false unless group["state"] == "retired" && children.first["pid"] == group["id"]
      reserved = @session.reserved
      if reserved
        return false unless reserved["keeper_pid"] == children.first["pid"] &&
                            reserved["group_id"] == group["id"] &&
                            reserved["session_id"] == @session.custodian_child.pid
      end
      return @session.ready.nil? && frame["outcome"] == "failed" if children.last["state"] == "not_attempted"
      if @session.ready
        return false unless @session.ready["validator_pid"] == children.last["pid"] &&
                            @session.ready["group_id"] == group["id"]
      end
      return true if frame["outcome"] == "failed"
      return false unless children.all? { |child| child["status_kind"] == "exit" } && children.first["status_code"] == 0
      frame["outcome"] == "ok" ? children.last["status_code"] == 0 : children.last["status_code"].positive?
    end

    def build_snapshot
      base = {"version" => VERSION, "sourceOrigins" => @source_origins,
              "custodianSpawn" => @custodian_spec, "hooksRestored" => !!@hooks_restored,
              "observerErrors" => @observer_errors.dup, "events" => @events.dup}
      unless @session
        # Positive closed-call proof: hooks covered the whole synchronous block,
        # and neither an owned task start nor a native creator was entered. A
        # missing session pointer by itself is deliberately insufficient.
        none = @finished && @hooks_restored && @slots.empty? && @constructed_slots.empty? && @attempts.empty? && @observer_errors.empty?
        return base.merge("custodian" => {"state" => none ? "not_attempted" : "unknown"},
                          "final" => nil, "tasks" => [], "leases" => [], "streams" => {},
                          "settled" => none, "finalized" => false, "noProducers" => none, "unknown" => !none)
      end
      acq = @session.acquisition
      no_attempt = acq && acq.not_attempted? && @finished_creations.include?(acq)
      custodian = no_attempt ? {"state" => "not_attempted"} : receipt_record(@session.custodian_receipt)
      tasks = [task_record(@session.capture_slot, "capture"), task_record(@session.creator_slot, "creator")]
      # The creator's caller must be the real capture Thread, so it is not
      # constructed before that task exists. An absent field alone is not proof:
      # the original closed capture scope must have settled, its creator gate
      # was never entered, and the whole observed call constructed/started no
      # other task and entered no native creation API.
      creator_absent = !@session.creator_slot && !acq && !@creator_gate_entered &&
        task_settled?(tasks.first) && @attempts.empty? &&
        @constructed_slots == [@session.capture_slot] &&
        @slots.all? { |slot| slot.equal?(@session.capture_slot) }
      if creator_absent
        tasks[1] = {"role" => "creator", "state" => "not_constructed", "startAttempted" => false,
                    "creationGateClosed" => true, "actualScopeSettled" => true, "unresolved" => false}
        no_attempt = true
        custodian = {"state" => "not_attempted"}
      end
      leases = @session.leases.map do |role, lease|
        {"role" => role.to_s, "state" => lease.state.to_s,
         "closed" => !!(lease.io && lease.io.closed?), "actualCloseObserved" => @actual_closes.include?(lease),
         "noIOAcquired" => lease.state == :not_acquired && lease.io.nil? &&
           acq && @finished_creations.include?(acq) && acq.launch_retired?,
         "closeError" => lease.close_error&.class&.name}
      end
      settled = @session.settled?
      joined = task_settled?(tasks.first) && (creator_absent || task_settled?(tasks.last))
      closed = leases.all? do |lease|
        lease["closeError"].nil? &&
          ((lease["state"] == "closed" && lease["closed"] && lease["actualCloseObserved"]) || lease["noIOAcquired"])
      end
      stream_eofs = {"stdoutEOF" => @session.stdout_eof, "stderrEOF" => @session.stderr_eof, "statusEOF" => @session.status_eof}
      eof_objects = %i[stdout_read stderr_read status_read].all? do |role|
        lease = @session.leases[role]
        lease && @actual_eofs.include?(lease.io)
      end
      child = @session.custodian_child
      receipt = @session.custodian_receipt
      exact_wait = child && acq && child.equal?(acq.child) && receipt && receipt.equal?(child.receipt) &&
        child.pid == receipt.pid && @actual_waits.any? { |owner, observed| owner.equal?(child) && observed.equal?(receipt) }
      finalized = @session.finality_confirmed? && settled && joined && closed && exact_wait &&
        custodian["state"] == "reaped" && custodian["status_kind"] == "exit" &&
        custodian["status_code"] == (@session.final && @session.final["outcome"] == "failed" ? 2 : 0) &&
        stream_eofs.values.all? { |value| value.equal?(true) } && eof_objects && terminal_cleanup_confirmed?(@session.final) &&
        @hooks_restored && @observer_errors.empty? && !@session.retained_unknown?
      none = no_attempt && settled && joined && closed && @hooks_restored && @observer_errors.empty? && !@session.retained_unknown?
      base.merge("custodian" => custodian, "final" => @session.final,
                 "protocolContext" => {"hello" => @session.hello, "reserved" => @session.reserved, "ready" => @session.ready},
                 "tasks" => tasks, "leases" => leases,
                 "streams" => stream_eofs.merge("actualEOFObserved" => eof_objects),
                 "ready" => @session.ready, "stdinCloseReturned" => @session.stdin_close_returned,
                 "settled" => settled, "finalized" => !!finalized, "noProducers" => !!none,
                 "unknown" => @session.retained_unknown? || (!finalized && !none) || !@observer_errors.empty?)
    end

    def snapshot
      raise Failure.new("fixture-observation", "capture observation is not finished") unless @finished
      Marshal.load(Marshal.dump(@snapshot)) # Detached facts; no live lease/status authority.
    end

    def finalized? = @finished && @snapshot.fetch("finalized")
    def no_producers? = @finished && @snapshot.fetch("noProducers")
    def unknown? = !@finished || @snapshot.fetch("unknown")
  end

  class CancellationScope
    attr_reader :cleanup_depth, :errors

    def initialize
      @originals, @handlers, @pending, @policies = {}, {}, {}, {}
      @cleanup_depth = 0
      @errors = []
    end

    def install
      %w[INT TERM].each do |name|
        number = Signal.list.fetch(name)
        handler = proc do
          case @policies[number]
          when "DEFAULT"
            queue(number)
          when "IGNORE"
            nil
          else
            @pending[number] = true # Policy is not known until trap returns.
          end
        end
        @handlers[name] = handler
        @originals[name] = Signal.trap(name, handler)
        @policies[number] = @originals.fetch(name)
        unless %w[DEFAULT IGNORE].include?(@originals[name])
          raise Failure.new("signal-policy", "process fixture requires default or ignored INT/TERM handlers")
        end
        queue(number) if @pending.delete(number) && @policies[number] == "DEFAULT"
      end
    end

    def queue(number)
      error = number == Signal.list.fetch("INT") ? Interrupt.new("process fixture interrupted by SIGINT") : SignalException.new(number)
      Thread.main.raise(error)
    end

    def cleanup
      @cleanup_depth += 1
      yield
    ensure
      @cleanup_depth -= 1
    end

    def restore_one(name)
      return unless @originals.key?(name)
      # Observe using our deferred-compatible handler, rather than temporarily
      # installing a stale DEFAULT before detecting a foreign handler conflict.
      actual = Signal.trap(name, @handlers.fetch(name))
      target = @originals.fetch(name)
      unless actual.equal?(@handlers.fetch(name))
        target = actual
        @errors << Failure.new("signal-policy", "process fixture signal handler changed during its lifetime")
      end
      Signal.trap(name, target)
    end

    def restore
      begin
        restore_one("TERM")
      rescue Exception => error
        @errors << error
      ensure
        yield # Publish inactive/cleanup-complete BEFORE restoring default INT.
      end
      restore_one("INT") # No necessary trap/registry cleanup may follow this.
    end

    def replay_custom_pending
      @pending.each_key do |number|
        policy = @policies[number]
        next if %w[DEFAULT IGNORE].include?(policy)
        Process.kill(number, Process.pid) # Original policy restored, no resources acquired.
      end
    end
  end

  class Lifetime
    attr_reader :primary

    def initialize(scope, deadline_ns: nil, error_recorder: nil)
      @scope = scope
      @drain_deadline_ns = deadline_ns
      @error_recorder = error_recorder
      @primary = nil
      @cleanup_errors = []
    end

    def remember(error)
      error = @error_recorder.call(error) if @error_recorder
      @primary ||= error
      @drain_cutoff_ns ||= UploadProcessFixture.clock_ns + CLEANUP_LIMIT * 1_000_000_000
    end

    def finishing
      yield
    rescue Exception => error
      remember(error)
    end

    def active
      return yield if @scope.cleanup_depth.positive? # Never reopen an outer cleanup.
      result = nil
      begin
        Thread.handle_interrupt(Exception => :never) do
          begin
            result = Thread.handle_interrupt(Exception => :immediate) { yield }
          rescue Exception => error
            remember(error)
          end
        end
      rescue Exception => error
        remember(error) # A queued repeat at scope exit cannot replace the first.
      end
      raise @primary if @primary
      result
    end

    def cleanup
      Thread.handle_interrupt(Exception => :never) do
        @scope.cleanup { yield }
      rescue Exception => error
        @cleanup_errors << error
        remember(error)
      end
    end

    def report
      @cleanup_errors.each do |error|
        warn "Fixture cleanup incomplete: #{error.class}: #{error.message}; primary=#{@primary.class}: #{@primary.message}"
      end
    end

    def drain_pending
      @drain_cutoff_ns ||= @drain_deadline_ns ? @drain_deadline_ns.call : UploadProcessFixture.clock_ns + CLEANUP_LIMIT * 1_000_000_000
      deadline = @drain_cutoff_ns
      deadline = [deadline, @drain_deadline_ns.call].min if @drain_deadline_ns
      @drain_cutoff_ns = deadline # INT restoration and another drain cannot renew it.
      while Thread.current.pending_interrupt?
        deadline = [deadline, @drain_deadline_ns.call].min if @drain_deadline_ns
        @drain_cutoff_ns = deadline
        raise Failure.new("signal-policy", "fixture cancellation queue did not quiesce after cleanup") if UploadProcessFixture.clock_ns >= deadline
        begin
          Thread.handle_interrupt(Exception => :immediate) {}
        rescue Exception => error
          remember(error)
        end
      end
    end
  end

  # A small same-PID bootstrap supplies test-only setsid/chdir without changing
  # the admitted production SpawnSpec. The native creator maps ONLY 0..2. Every
  # readiness/control file below is opened by the child AFTER that exec.
  class OwnedChild
    BOOTSTRAP_FAILURE_CONDITIONS = {
      "configuration" => %w[directory_read record_read record_parse record_schema directory_identity parent_identity
                              deadline_type request_schema stdio_identity deadline],
      "admission_open" => %w[fifo_open fifo_cloexec fifo_identity],
      "session" => %w[setsid session_identity chdir cwd_identity ready_record],
      "admission_wait" => %w[deadline grant_read grant_select grant_value],
      "admission_close" => %w[close],
      "exec_attempt" => %w[attempt_record deadline exec],
    }.transform_values(&:freeze).freeze

    attr_reader :pid, :status, :phase, :acquisition, :creator, :child,
                :stdout_reader, :stderr_reader, :launch_directory

    class ControlLease
      attr_reader :io, :state

      def initialize
        @state = :unattempted
      end

      def acquire
        raise Failure.new("process-ownership", "control acquisition repeated") unless @state == :unattempted
        @state = :acquiring
        Thread.handle_interrupt(Exception => :never) do
          @io = yield
          raise Failure.new("process-ownership", "control acquisition returned no IO") unless @io.is_a?(IO)
          @state = :open
        end
        @io
      rescue Exception
        @state = :unknown if @state == :acquiring
        raise
      end

      def close_once
        return true if %i[unattempted closed].include?(@state)
        raise Failure.new("process-ownership", "control close is unknown") unless @state == :open
        Thread.handle_interrupt(Exception => :never) do
          @state = :closing
          @io.close
          @state = :closed
        end
        true
      rescue Exception
        @state = :unknown if @state == :closing
        raise
      end
    end

    def self.native_modules
      if defined?(MobileReleaseKit)
        names = %i[NativeProcessSpawn NativeUploadProcess]
        present = names.map { |name| MobileReleaseKit.const_defined?(name, false) }
        return names.map { |name| MobileReleaseKit.const_get(name, false) } if present.all?
        if present.any?
          raise Failure.new("process-ownership", "partial command runtime would mix source origins")
        end
      end
      require_relative "../../fastlane/native_process_spawn"
      require_relative "../../fastlane/native_upload_process"
      [MobileReleaseKit::NativeProcessSpawn, MobileReleaseKit::NativeUploadProcess]
    end

    # Identity excludes size/timestamps: stdout files and the private directory
    # legitimately change after publication. Configuration bytes are additionally
    # pinned by length and SHA256 before admission.
    def self.identity(stat)
      {"dev" => stat.dev, "ino" => stat.ino, "mode" => stat.mode,
       "uid" => stat.uid, "gid" => stat.gid, "rdev" => stat.rdev, "type" => stat.ftype, "nlink" => stat.nlink}
    end

    def self.bounded_file(path, expected: nil, limit: OUTPUT_LIMIT)
      flags = File::RDONLY | File::NOFOLLOW | File::NONBLOCK
      File.open(path, flags) do |io|
        stat = io.stat
        unless stat.file? && stat.uid == Process.uid && stat.nlink == 1 &&
               (stat.mode & 0o7777) == 0o600 && (!expected || identity(stat) == expected)
          raise Failure.new("process-ownership", "bootstrap record identity changed")
        end
        bytes = io.read(limit + 1)
        raise Failure.new("process-ownership", "bootstrap record exceeds bound") if bytes.bytesize > limit
        raise Failure.new("process-ownership", "bootstrap record changed during read") unless identity(io.stat) == identity(stat)
        bytes
      end
    end

    def self.write_record(path, value)
      bytes = JSON.generate(value)
      raise Failure.new("process-ownership", "bootstrap record exceeds bound") if bytes.bytesize > OUTPUT_LIMIT
      File.open(path, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) do |io|
        count = io.write(bytes)
        raise Failure.new("process-ownership", "bootstrap record write incomplete") unless count == bytes.bytesize
        io.flush
      end
    end

    def initialize(root: nil, deadline: nil, hard_deadline: nil, deadline_ns: nil, hard_deadline_ns: nil, parent_slot: nil)
      @root, @run_deadline, @hard_deadline = root, deadline, hard_deadline
      @run_deadline_ns, @hard_deadline_ns = deadline_ns, hard_deadline_ns
      @parent_slot = parent_slot
      @pid = @status = nil
      @phase = :unstarted
      @controls = [@anchor = ControlLease.new, @grant_writer = ControlLease.new, @configuration_file = ControlLease.new]
      @external_leases = []
      @stream_leases, @stream_eofs, @cleanup_errors = {}, {}, []
      @go_state, @go_offset = "not_attempted", 0
      @numeric_retired = @setup_complete = @resources_closed = false
      @provenance = {"version" => 1}
    end

    def fail_unknown!(error = nil)
      @phase = :unknown
      @numeric_retired = true
      @go_state = "unknown" if @go_state == "attempting"
      @acquisition&.mark_unknown!(error)
      UploadProcessFixture.retain_unknown_domain!(@root)
      roots = UploadProcessFixture.instance_variable_get(:@unresolved_roots) ||
        UploadProcessFixture.instance_variable_set(:@unresolved_roots, {})
      roots[@root] = true
      retained = UploadProcessFixture.instance_variable_get(:@unresolved_children) ||
        UploadProcessFixture.instance_variable_set(:@unresolved_children, {})
      retained[object_id] = self
      nil
    end

    def validate_request(environment, argv, options)
      unless environment.instance_of?(Hash) && environment.length <= 64 &&
             environment.all? { |key, value| key.is_a?(String) && value.is_a?(String) && !key.empty? &&
               !key.include?("=") && [key, value].all? { |text| text.bytesize <= 4096 && !text.include?("\0") } } &&
             argv.length.between?(1, 64) && argv.all? { |value| value.is_a?(String) && value.bytesize.between?(1, 4096) && !value.include?("\0") } &&
             argv.first == File.absolute_path(argv.first) && options.keys.sort == %i[chdir err in out pgroup unsetenv_others] &&
             options[:pgroup].equal?(true) && options[:unsetenv_others].equal?(true)
        raise Failure.new("process-ownership", "unsupported owned-child request")
      end
      cwd = options[:chdir] || Dir.pwd
      cwd = File.realpath(cwd)
      raise Failure.new("process-ownership", "owned-child cwd is not a directory") unless File.directory?(cwd)
      [environment.to_h { |key, value| [key.dup.freeze, value.dup.freeze] }.freeze,
       argv.map { |value| value.dup.freeze }.freeze, cwd.freeze]
    end

    def start(environment, *argv, **options)
      UploadProcessFixture.assert_domain_reusable!
      raise Failure.new("process-ownership", "child acquisition was already attempted") unless @phase == :unstarted && !@start_attempted
      if @parent_slot
        UploadProcessFixture.validate_capture_parent!(@parent_slot)
        @parent_validated = true
      end
      options = {chdir: nil, in: File::NULL, out: File::NULL, err: File::NULL}.merge(options)
      environment, argv, cwd = validate_request(environment, argv, options)
      @spawn, @tasks = self.class.native_modules
      now = UploadProcessFixture.clock_ns
      unless [@run_deadline, @hard_deadline].all? { |value| value.nil? || value.is_a?(Numeric) && value.finite? } &&
             [@run_deadline_ns, @hard_deadline_ns].all? { |value| value.nil? || value.instance_of?(Integer) } &&
             !(@run_deadline && @run_deadline_ns) && !(@hard_deadline && @hard_deadline_ns)
        raise Failure.new("process-ownership", "invalid owned-child deadline")
      end
      @run_deadline_ns ||= @run_deadline ? (@run_deadline.to_r * 1_000_000_000).floor : now + DRIVER_LIMIT * 1_000_000_000
      @hard_deadline_ns ||= @hard_deadline ? (@hard_deadline.to_r * 1_000_000_000).floor : @run_deadline_ns + CLEANUP_LIMIT * 1_000_000_000
      @run_deadline_ns = [@run_deadline_ns, @parent_slot&.run_deadline_ns].compact.min
      @hard_deadline_ns = [@hard_deadline_ns, @run_deadline_ns + CLEANUP_LIMIT * 1_000_000_000,
                           @parent_slot&.hard_cleanup_deadline_ns].compact.min
      unless @run_deadline_ns > now && @hard_deadline_ns.between?(@run_deadline_ns, @run_deadline_ns + CLEANUP_LIMIT * 1_000_000_000)
        raise Failure.new("process-ownership", "owned-child admission deadline expired")
      end
      Thread.handle_interrupt(Exception => :never) do
        @start_attempted = true
        @phase = :acquiring
        # The lifetime's original slot exists before the first Thread.new or IO.
        @creator = @tasks::TaskSlot.new(caller: Thread.current, parent_slot: @parent_slot,
          run_deadline_ns: @run_deadline_ns, hard_cleanup_deadline_ns: @hard_deadline_ns)
        @acquisition = @spawn::Acquisition.new(owner_slot: @creator,
          run_deadline_ns: @creator.run_deadline_ns, hard_cleanup_deadline_ns: @creator.hard_cleanup_deadline_ns)
      end
      @requested = {"executable" => argv.first, "argv" => argv, "environment" => environment, "cwd" => cwd}
      @provenance["requested"] = @requested
      @provenance["role"] = @parent_slot ? "fixture-observer" : "fixture-command"
      prepare_launch_directory(options)
      @creator.start do |slot|
        slot.check_creation!
        @stdio = [:in, :out, :err].map.with_index { |name, index| acquire_stdio(options.fetch(name), name, index) }
        prepare_configuration
        ruby = File.realpath(RbConfig.ruby)
        fixture = File.realpath(File.join(__dir__, "upload_process_fixture.rb"))
        bootstrap_argv = [ruby, *@tasks::HELPER_FLAGS, "--", fixture, "owned-child", @launch_directory]
        @provenance["nativeBootstrap"] = {"executable" => ruby, "argv" => bootstrap_argv,
          "environment" => @tasks.helper_environment, "creatorCwd" => Dir.pwd,
          "fixtureSha256" => Digest::SHA256.file(fixture).hexdigest,
          "fdSources" => @stdio.map { |lease| {"role" => lease.role.to_s, "identity" => self.class.identity(lease.io.stat)} }}
        spec = @spawn::SpawnSpec.new(executable: ruby, argv: bootstrap_argv,
          env: @tasks.helper_environment, fd_sources: @stdio)
        @spawn.create(@acquisition, spec)
      end
      unless @creator.admit!
        raise @creator.first_error || Failure.new("process-ownership", "owned creator was not admitted")
      end
      settle_creator(@run_deadline_ns)
      raise @creator.first_error if @creator.first_error
      raise @acquisition.first_error if @acquisition.first_error
      raise Failure.new("process-ownership", "native child was not acquired") unless @child
      close_child_endpoints
      wait_ready
      @anchor.close_once
      grant_exec
      @setup_complete = true
      @pid
    rescue Exception => error
      remember_error(error)
      @acquisition&.close_launch!
      # Permanent admission closure is immediate. No new GO or source creation
      # can be authorized by an eventual late task/native return.
      begin
        @grant_writer.close_once
        @go_state = "closed" if @go_state == "not_attempted"
      rescue Exception => close_error
        @cleanup_errors << close_error
        fail_unknown!(close_error)
      end
      fail_unknown!(error) if @controls.any? { |lease| lease.state == :unknown } || @acquisition&.state == :unknown
      raise @primary
    end

    def remember_error(error, cleanup: false)
      slot = @creator || (@parent_slot if @parent_validated)
      if slot
        cleanup ? slot.record_cleanup_error(error) : slot.cancel!(error: error, reason_code: "lifecycle")
        @primary = slot.first_error || @primary || error
      else
        @primary ||= error
      end
      @primary
    end

    def admission_current!
      error = @creator&.first_error || @primary
      raise error if error
      if UploadProcessFixture.clock_ns >= @run_deadline_ns || @creator&.cancelled? ||
         (@parent_validated && (@parent_slot.cancelled? || @parent_slot.launch_retired?))
        raise Failure.new("process-ownership", "bootstrap admission deadline expired or cancelled")
      end
      true
    end

    def cleanup_cutoff_ns
      @cleanup_deadline_ns ||= [UploadProcessFixture.clock_ns + CLEANUP_LIMIT * 1_000_000_000, @hard_deadline_ns].min
      if @creator&.cancelled?
        @cleanup_deadline_ns = [@cleanup_deadline_ns, @creator.cleanup_deadline_ns].min
      end
      if @parent_validated && @parent_slot.cancelled?
        @cleanup_deadline_ns = [@cleanup_deadline_ns, @parent_slot.cleanup_deadline_ns].min
      end
      @cleanup_deadline_ns
    end

    def prepare_launch_directory(options)
      candidate = @root
      if candidate.nil? && options[:out].is_a?(File)
        candidate = File.dirname(File.absolute_path(options[:out].path))
      end
      @root ||= candidate || Dir.tmpdir
      @launch_state = :acquiring
      Thread.handle_interrupt(Exception => :never) do
        @launch_directory = File.realpath(Dir.mktmpdir("mrk-owned-launch-", @root))
        @launch_state = :open
      end
      @directory_identity = self.class.identity(UploadProcessFixture.owned_fixture_directory(@launch_directory))
      fifo = File.join(@launch_directory, "admission.fifo")
      File.mkfifo(fifo, 0o600)
      @fifo_identity = self.class.identity(File.lstat(fifo))
      unless @fifo_identity["type"] == "fifo" && (@fifo_identity["mode"] & 0o7777) == 0o600
        raise Failure.new("process-ownership", "bootstrap admission endpoint is invalid")
      end
      @anchor.acquire { File.open(fifo, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) }
      @grant_writer.acquire { File.open(fifo, File::WRONLY | File::NONBLOCK | File::NOFOLLOW) }
      [@anchor, @grant_writer].each do |lease|
        unless lease.io.close_on_exec? && self.class.identity(lease.io.stat) == @fifo_identity
          raise Failure.new("process-ownership", "bootstrap admission endpoint changed")
        end
      end
      @provenance["launchDirectory"] = {"path" => @launch_directory, "identity" => @directory_identity}
    rescue Exception => error
      fail_unknown!(error) if @launch_state == :acquiring
      raise
    end

    def acquire_stdio(value, role, index)
      access = index.zero? ? :read : :write
      if value == File::NULL
        @spawn.null(@acquisition, role: role, access: access)
      elsif value == :pipe && index.positive?
        reader, writer = @spawn.pipe(@acquisition, read_role: :"#{role}_read", write_role: role)
        @stream_leases[role] = reader
        @stream_eofs[role] = false
        index == 1 ? @stdout_reader = reader.io : @stderr_reader = reader.io
        writer
      elsif value.is_a?(IO)
        kind = value.stat.pipe? ? :pipe : :file
        lease = @spawn.lease_io(@acquisition, io: value, role: role, access: access, kind: kind)
        @external_leases << lease
        lease
      else
        raise Failure.new("process-ownership", "unsupported owned-child standard stream")
      end
    end

    def prepare_configuration
      value = {"version" => 1, "directory" => @directory_identity, "fifo" => @fifo_identity,
        "request" => @requested, "runDeadlineNs" => @creator.run_deadline_ns,
        "parentPid" => Process.pid, "stdio" => @stdio.map { |lease| self.class.identity(lease.io.stat) }}
      bytes = JSON.generate(value)
      raise Failure.new("process-ownership", "oversized bootstrap configuration") if bytes.bytesize > OUTPUT_LIMIT
      path = File.join(@launch_directory, "configuration.json")
      io = @configuration_file.acquire { File.open(path, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) }
      raise Failure.new("process-ownership", "partial bootstrap configuration") unless io.write(bytes) == bytes.bytesize
      io.flush
      identity = self.class.identity(io.stat)
      @configuration_file.close_once
      @configuration_sha = Digest::SHA256.hexdigest(bytes)
      @provenance["configuration"] = {"path" => path, "identity" => identity,
        "bytes" => bytes.bytesize, "sha256" => @configuration_sha}
    end

    def settle_creator(cutoff)
      cutoff = [cutoff, @parent_slot.cleanup_deadline_ns].min if @parent_validated && @parent_slot.cancelled?
      return if @creation_finished
      if @creation_finish_attempted
        raise Failure.new("process-ownership", "native creator finish return is unknown")
      end
      return unless @creator
      @creator.close_launch! if @primary
      if @creator.start_attempted?
        unless @creator.join_until(deadline_ns: cutoff)
          raise Failure.new("process-ownership", "native creator did not join")
        end
      else
        @creator.close_launch!
      end
      @acquisition.close_launch!
      @creation_finish_attempted = true
      unless @acquisition.finish_creation!(creator_slot: @creator)
        raise Failure.new("process-ownership", "native creator did not settle")
      end
      @creation_finished = true
      @child = @acquisition.child
      if @child
        @pid = @child.pid
        @phase = :reserved unless @phase == :unknown
      elsif !@acquisition.not_attempted?
        raise Failure.new("process-ownership", "native child publication is unknown")
      end
    end

    def close_child_endpoints
      @acquisition.resources.each do |role, lease|
        next unless %i[in out err].include?(role)
        lease.close_once unless @external_leases.include?(lease) || %i[closed not_acquired].include?(lease.state)
      end
    end

    def wait_ready
      path = File.join(@launch_directory, "ready.json")
      loop do
        admission_current!
        if File.exist?(path)
          ready = JSON.parse(self.class.bounded_file(path))
          expected = {"version" => 1, "pid" => @pid, "pgid" => @pid, "sid" => @pid,
            "configurationSha256" => @configuration_sha, "cwd" => @requested.fetch("cwd")}
          unless ready == expected && @child.equal?(@acquisition.child) && @child.state == :running && !@child.numeric_retired? &&
                 Process.getpgid(@pid) == @pid && Process.getsid(@pid) == @pid
            raise Failure.new("process-ownership", "bootstrap readiness is not the reserved child")
          end
          @private_group = true
          @provenance["ready"] = ready
          return
        end
        if File.exist?(File.join(@launch_directory, "failure.json"))
          original = Failure.new("process-ownership", "bootstrap refused admission")
          remember_error(original) # Close first-error/admission BEFORE optional observation.
          snapshot_bootstrap_failure
          raise original
        end
        sleep [10_000_000, [@run_deadline_ns - UploadProcessFixture.clock_ns, 0].max].min / 1_000_000_000.0
      end
    end

    def snapshot_bootstrap_failure
      return if @bootstrap_failure_read_attempted
      @bootstrap_failure_read_attempted = true
      @bootstrap_failure_cutoff_ns = [@run_deadline_ns, @creator.cleanup_deadline_ns].min
      return unless UploadProcessFixture.clock_ns < @bootstrap_failure_cutoff_ns
      raw = self.class.bounded_file(File.join(@launch_directory, "failure.json"), limit: 1024)
      return unless UploadProcessFixture.clock_ns < @bootstrap_failure_cutoff_ns
      return unless raw.instance_of?(String) && raw.bytesize <= 1024
      value = JSON.parse(raw, create_additions: false, max_nesting: 4)
      unless value.instance_of?(Hash) && value.keys.sort == %w[condition pid stage version] &&
             value["version"].instance_of?(Integer) && value["version"] == 1 &&
             value["pid"].instance_of?(Integer) && value["pid"] == @pid &&
             value["stage"].instance_of?(String) && value["condition"].instance_of?(String) &&
             BOOTSTRAP_FAILURE_CONDITIONS.fetch(value["stage"], []).include?(value["condition"]) &&
             JSON.generate(value) == raw
        return
      end
      return unless UploadProcessFixture.clock_ns < @bootstrap_failure_cutoff_ns
      # No PID, original record or authority survives this diagnostic projection.
      @bootstrap_failure_snapshot = {"stage" => value.fetch("stage").freeze,
        "condition" => value.fetch("condition").freeze}.freeze
      nil
    rescue Exception
      nil # Optional observation cannot replace the ALREADY latched refusal.
    end

    def report_bootstrap_failure
      return if @bootstrap_failure_report_attempted || !@bootstrap_failure_snapshot
      @bootstrap_failure_report_attempted = true
      return unless @bootstrap_failure_cutoff_ns && UploadProcessFixture.clock_ns < @bootstrap_failure_cutoff_ns
      line = "MRK_FIXTURE_BOOTSTRAP_FAILURE=#{JSON.generate({"schema" => 1}.merge(@bootstrap_failure_snapshot))}\n"
      return unless line.ascii_only? && line.bytesize <= 256 && UploadProcessFixture.clock_ns < @bootstrap_failure_cutoff_ns
      # Ordinary captured output AFTER stop's original cleanup attempts. No
      # nonblocking/flush/descriptor-policy claim, retry or renewed cutoff.
      STDERR.write(line)
      nil
    rescue Exception
      nil # Preserve stop's original return/error, including a failed close.
    end

    def grant_exec
      bytes = "GO\n".b
      raise Failure.new("process-ownership", "bootstrap grant repeated") unless @go_state == "not_attempted"
      admission_current!
      @go_state = "attempting" # BEFORE the first potentially effectful write.
      while @go_offset < bytes.bytesize
        admission_current!
        returned = @grant_writer.io.write_nonblock(bytes.byteslice(@go_offset..), exception: false)
        if returned == :wait_writable
          IO.select(nil, [@grant_writer.io], nil, [@run_deadline_ns - UploadProcessFixture.clock_ns, 10_000_000].min.clamp(0, 10_000_000) / 1_000_000_000.0)
        elsif returned.is_a?(Integer) && returned.positive? && returned <= bytes.bytesize - @go_offset
          @go_offset += returned # Continue ONLY from the genuinely counted offset.
        else
          raise Failure.new("process-ownership", "bootstrap grant return is ambiguous")
        end
      end
      @grant_writer.close_once
      @go_state = "granted"
    rescue Exception => error
      fail_unknown!(error) if @go_state == "attempting"
      raise
    end

    def retire_numeric!
      return true if @phase == :reaped || @phase == :waiting
      unless @phase == :reserved && @child && @child.equal?(@acquisition.child)
        raise Failure.new("process-ownership", "child wait authority is unknown")
      end
      @numeric_retired = true # All fixture direct/group probe routes close first.
      @child.retire_numeric!
      @phase = :waiting
      true
    rescue Exception => error
      fail_unknown!(error)
      raise
    end

    def poll_wait
      return @status if @phase == :reaped
      raise Failure.new("process-ownership", "child numeric routes were not retired") unless @phase == :waiting && @numeric_retired
      receipt = @child.poll_wait
      if receipt
        unless receipt.equal?(@child.receipt) && receipt.pid == @pid && receipt.raw_status.is_a?(Process::Status)
          raise Failure.new("process-ownership", "child receipt is not its original wait")
        end
        @status = receipt.raw_status
        @phase = :reaped
      end
      @status
    rescue Exception => error
      fail_unknown!(error)
      raise
    end

    def signal(signal, group: true)
      return false if @phase == :unstarted && !@start_attempted
      unless [0, "KILL", "INT", "TERM"].include?(signal) && [true, false].include?(group) &&
             @phase == :reserved && !@numeric_retired && @child && @child.equal?(@acquisition.child) &&
             @child.state == :running && !@child.numeric_retired? && @creator.joined? && @creation_finished &&
             (!group || @private_group)
        raise Failure.new("process-ownership", "child signal authority is not reserved")
      end
      Thread.handle_interrupt(Exception => :never) do
        cutoff = @cleanup_deadline_ns ? cleanup_cutoff_ns : @run_deadline_ns
        cutoff = [cutoff, @parent_slot.cleanup_deadline_ns].min if @parent_validated && @parent_slot.cancelled?
        raise Failure.new("process-ownership", "child signal deadline expired") unless UploadProcessFixture.clock_ns < cutoff
        @signal_in_flight = true
        Process.kill(signal, group ? -@pid : @pid)
        @signal_in_flight = false
      end
      true
    rescue Errno::ESRCH
      @signal_in_flight = false
      retire_numeric! # A failed request cannot reopen or later retry this number.
      false
    rescue Exception => error
      fail_unknown!(error) if @signal_in_flight
      raise
    end

    def close_resources
      return if @resources_closed
      @resource_close_attempted = true
      failures = []
      # The parent alone uses these endpoints, even while its creator remains
      # unresolved. A failed native finish must not skip their actual close.
      creator_done = @creation_finished || @creator&.joined? ||
        (@creator && !@creator.start_attempted? && @creator.launch_retired?)
      safe_controls = [@anchor, @grant_writer]
      safe_controls << @configuration_file if creator_done
      safe_controls.each do |lease|
        begin
          lease.close_once unless lease.state == :unknown
          raise Failure.new("process-ownership", "control close remains unknown") if lease.state == :unknown
        rescue Exception => error
          remember_error(error, cleanup: true)
          failures << error
        end
      end
      # Joined does not repair finish_creation!'s UNKNOWN or release a borrowed
      # lease by fiat. IOLease.close_once still enforces its own borrow gate; an
      # error is retained, never bypassed with a raw File/FD close.
      resources = creator_done && @acquisition ? @acquisition.resources.values : []
      resources.each do |lease|
        begin
          if lease.state == :unknown
            raise lease.close_error || Failure.new("process-ownership", "native IO remains unknown")
          end
          lease.close_once unless %i[closed not_acquired].include?(lease.state)
        rescue Exception => error
          remember_error(error, cleanup: true)
          failures << error
        end
      end
      failures << Failure.new("process-ownership", "creator still owns native close obligations") unless creator_done
      @cleanup_errors.concat(failures)
      @resources_closed = failures.empty?
      unless failures.empty?
        fail_unknown!(failures.first)
        raise failures.first
      end
      true
    end

    # Only this method claims pipe EOF: it witnesses the actual original read,
    # not a caller-supplied boolean or a closed descriptor after an error.
    def read_stream(role, bytes = 4096)
      raise Failure.new("process-ownership", "unknown owned stream") unless @stream_leases.key?(role)
      return nil if @stream_eofs.fetch(role)
      value = @stream_leases.fetch(role).io.read_nonblock(bytes, exception: false)
      @stream_eofs[role] = true if value.nil?
      value
    end

    def streams_complete?
      @stream_eofs.values.all? { |value| value.equal?(true) }
    end

    def drain_streams(cutoff)
      until streams_complete?
        cutoff = [cutoff, cleanup_cutoff_ns].min
        raise Failure.new("process-ownership", "owned stream EOF deadline expired") unless UploadProcessFixture.clock_ns < cutoff
        @stream_leases.each_key { |role| read_stream(role) unless @stream_eofs.fetch(role) }
        break if streams_complete?
        remaining = cutoff - UploadProcessFixture.clock_ns
        raise Failure.new("process-ownership", "owned stream EOF deadline expired") unless remaining.positive?
        readers = @stream_leases.reject { |role, _lease| @stream_eofs.fetch(role) }.values.map(&:io)
        IO.select(readers, nil, nil, [10_000_000, remaining].min / 1_000_000_000.0)
      end
    end

    def snapshot_exec_attempt
      return if @exec_attempt_observed || !@launch_directory || !@status
      @exec_attempt_observed = true
      path = File.join(@launch_directory, "exec-attempt.json")
      return unless File.file?(path)
      value = JSON.parse(self.class.bounded_file(path))
      expected = {"version" => 1, "pid" => @pid, "configurationSha256" => @configuration_sha,
        "argvSha256" => Digest::SHA256.hexdigest(JSON.generate(@requested.fetch("argv"))), "cwd" => @requested.fetch("cwd")}
      raise Failure.new("process-ownership", "bootstrap attempt identity changed") unless value == expected
      @provenance["execAttempt"] = value # Observation only, never repairs UNKNOWN.
    end

    def stop
      return true if complete?
      cleanup_cutoff_ns
      raise Failure.new("process-ownership", "child ownership remains unknown") if @phase == :unknown
      @primary ||= @creator&.first_error
      @creator&.close_launch!
      @acquisition&.close_launch!
      @grant_writer.close_once
      @go_state = "closed" if @go_state == "not_attempted"
      settle_creator(cleanup_cutoff_ns)
      close_child_endpoints
      if @phase == :reserved
        signal("KILL", group: !!@private_group)
        drain_streams(cleanup_cutoff_ns) # Real EOFs before ANY consuming wait.
        retire_numeric! if @phase == :reserved
      end
      drain_streams(cleanup_cutoff_ns)
      while @phase == :waiting
        raise Failure.new("process-ownership", "child cleanup deadline expired") unless UploadProcessFixture.clock_ns < cleanup_cutoff_ns
        poll_wait
        break if @phase == :reaped
        sleep [10_000_000, [cleanup_cutoff_ns - UploadProcessFixture.clock_ns, 0].max].min / 1_000_000_000.0
      end
      unless @phase == :reaped || (@acquisition.not_attempted? && @creation_finished)
        raise Failure.new("process-ownership", "child cleanup is not final")
      end
      snapshot_exec_attempt
      close_resources
      @no_child_confirmed = @acquisition.not_attempted? && !@child
      @phase = :unstarted if @no_child_confirmed
      preserve = @provenance["configuration"]
      if @launch_directory && preserve
        @provenance["grant"] = {"state" => @go_state, "bytesWritten" => @go_offset}
      end
      if @launch_directory
        unless self.class.identity(UploadProcessFixture.owned_fixture_directory(@launch_directory)) == @directory_identity
          raise Failure.new("process-ownership", "bootstrap directory identity changed")
        end
        FileUtils.remove_entry(@launch_directory)
        @launch_removed = true
      end
      true
    rescue Exception => error
      remember_error(error, cleanup: true)
      fail_unknown!(error)
      unless @resource_close_attempted
        begin
          close_resources # Independent known closes; no retry of ambiguous IO.
        rescue Exception => cleanup_error
          @cleanup_errors << cleanup_error unless @cleanup_errors.include?(cleanup_error)
        end
      end
      raise
    ensure
      report_bootstrap_failure
    end

    def complete?
      return true if @phase == :unstarted && !@start_attempted
      (@phase == :reaped || @no_child_confirmed) && @creation_finished && @resources_closed &&
        streams_complete? && (@launch_directory.nil? || @launch_removed) && @phase != :unknown
    end

    def provenance
      value = @provenance.merge("grant" => {"state" => @go_state, "bytesWritten" => @go_offset},
        "phase" => @phase.to_s, "pid" => @pid, "numericRetired" => @numeric_retired,
        "creatorJoined" => !!(@creator && @creator.joined?), "resourcesClosed" => @resources_closed,
        "ownedStreamEOFs" => @stream_eofs.transform_keys(&:to_s))
      if @status
        value["wait"] = {"pid" => @status.pid, "status_kind" => @status.exited? ? "exit" : "signal",
          "status_code" => @status.exited? ? @status.exitstatus : @status.termsig}
      end
      Marshal.load(Marshal.dump(value))
    end

    # Fixed fixture-only dispatch. There is NO thread/fork/spawn between the
    # FIFO open and its checked close. The only exec is the same PID after GO.
    # This child may set CLOEXEC on its newly opened own FIFO; the parent never
    # changes caller/foreign descriptor flags.
    def self.bootstrap(directory)
      stage = "configuration"
      condition = "directory_read"
      expected_directory = identity(UploadProcessFixture.owned_fixture_directory(directory))
      condition = "record_read"
      raw = bounded_file(File.join(directory, "configuration.json"))
      condition = "record_parse"
      config = JSON.parse(raw)
      condition = "record_schema"
      unless config.keys.sort == %w[directory fifo parentPid request runDeadlineNs stdio version] &&
             config["version"] == 1
        raise Failure.new("process-ownership", "bootstrap configuration rejected")
      end
      condition = "directory_identity"
      unless config["directory"] == expected_directory
        raise Failure.new("process-ownership", "bootstrap configuration rejected")
      end
      condition = "parent_identity"
      unless config["parentPid"] == Process.ppid
        raise Failure.new("process-ownership", "bootstrap configuration rejected")
      end
      condition = "deadline_type"
      unless config["runDeadlineNs"].is_a?(Integer)
        raise Failure.new("process-ownership", "bootstrap configuration rejected")
      end
      condition = "request_schema"
      unless config["request"].is_a?(Hash) && config["request"].keys.sort == %w[argv cwd environment executable]
        raise Failure.new("process-ownership", "bootstrap configuration rejected")
      end
      condition = "stdio_identity"
      unless config["stdio"] == [STDIN, STDOUT, STDERR].map { |io| identity(io.stat) }
        raise Failure.new("process-ownership", "bootstrap configuration rejected")
      end
      request = config.fetch("request")
      cutoff = config.fetch("runDeadlineNs")
      condition = "deadline"
      raise Failure.new("process-ownership", "bootstrap configuration expired") unless UploadProcessFixture.clock_ns < cutoff
      stage = "admission_open"
      condition = "fifo_open"
      control = File.open(File.join(directory, "admission.fifo"), File::RDONLY | File::NONBLOCK | File::NOFOLLOW)
      condition = "fifo_cloexec"
      control.close_on_exec = true
      condition = "fifo_identity"
      unless control.close_on_exec? && identity(control.stat) == config.fetch("fifo") && control.stat.pipe?
        raise Failure.new("process-ownership", "bootstrap admission identity rejected")
      end
      stage = "session"
      condition = "setsid"
      Process.setsid
      condition = "session_identity"
      unless Process.getpgrp == Process.pid && Process.getsid(0) == Process.pid
        raise Failure.new("process-ownership", "bootstrap private session failed")
      end
      condition = "chdir"
      Dir.chdir(request.fetch("cwd"))
      condition = "cwd_identity"
      raise Failure.new("process-ownership", "bootstrap cwd changed") unless Dir.pwd == request.fetch("cwd")
      condition = "ready_record"
      digest = Digest::SHA256.hexdigest(raw)
      write_record(File.join(directory, "ready.json"), {"version" => 1, "pid" => Process.pid,
        "pgid" => Process.getpgrp, "sid" => Process.getsid(0), "configurationSha256" => digest, "cwd" => Dir.pwd})
      stage = "admission_wait"
      grant = +"".b
      until grant == "GO\n"
        condition = "deadline"
        raise Failure.new("process-ownership", "bootstrap grant deadline expired") unless UploadProcessFixture.clock_ns < cutoff
        condition = "grant_read"
        chunk = control.read_nonblock(4 - grant.bytesize, exception: false)
        condition = "grant_value"
        case chunk
        when nil
          raise Failure.new("process-ownership", "bootstrap owner closed admission")
        when :wait_readable
          condition = "grant_select"
          IO.select([control], nil, nil, [10_000_000, [cutoff - UploadProcessFixture.clock_ns, 0].max].min / 1_000_000_000.0)
        when String
          grant << chunk
          raise Failure.new("process-ownership", "bootstrap grant rejected") unless "GO\n".start_with?(grant)
        else
          raise Failure.new("process-ownership", "bootstrap grant return rejected")
        end
      end
      stage = "admission_close"
      condition = "close"
      control.close # A lost/failed close prohibits the only exec; never retry.
      control = nil
      stage = "exec_attempt"
      condition = "attempt_record"
      write_record(File.join(directory, "exec-attempt.json"), {"version" => 1, "pid" => Process.pid,
        "configurationSha256" => digest, "argvSha256" => Digest::SHA256.hexdigest(JSON.generate(request.fetch("argv"))),
        "cwd" => Dir.pwd})
      # GO and this record attest admission/attempt ONLY, not successful driver
      # execution. The CLI supplies its own receipt and original wait separately.
      condition = "deadline"
      raise Failure.new("process-ownership", "bootstrap exec deadline expired") unless UploadProcessFixture.clock_ns < cutoff
      condition = "exec"
      Process.exec(request.fetch("environment"), *request.fetch("argv"), unsetenv_others: true)
    rescue Exception
      begin
        write_record(File.join(directory, "failure.json"), {"version" => 1, "stage" => stage,
          "condition" => condition, "pid" => Process.pid})
      rescue Exception
        nil
      end
      125
    end
  end

  def self.lifetime(deadline_ns: nil)
    raise Failure.new("signal-policy", "process fixtures must run on the main Ruby thread") unless Thread.current.equal?(Thread.main)
    outer = @cancellation_scope.nil?
    scope = @cancellation_scope || CancellationScope.new
    fixed_deadline = deadline_ns && -> { deadline_ns }
    frame = Lifetime.new(scope, deadline_ns: fixed_deadline) # First error survives the entire outer mask/trap exit.
    result = nil
    begin
      Thread.handle_interrupt(Exception => :never) do
        begin
          if outer
            scope.install
            @cancellation_scope = scope
          end
          result = yield frame
        rescue Exception => error
          frame.remember(error)
        ensure
          # Diagnostics/queue draining may themselves fail. Neither may bypass
          # restoration of the process-wide policy or replace the first error.
          frame.finishing { frame.report }
          if outer
            # Several joined injectors/repeated OS signals can leave more than
            # one queued exception. Catch ALL of them before returning to a caller;
            # catching only the first at mask exit leaks the next into another test.
            frame.finishing { frame.drain_pending }
            frame.finishing { scope.restore { @cancellation_scope = nil } }
            frame.finishing { frame.drain_pending }
          end
          scope.errors.each { |error| frame.remember(error) }
        end
      end
    rescue Exception => error
      frame.remember(error)
    end
    begin
      scope.replay_custom_pending if outer
    rescue Exception => error
      frame.remember(error)
    end
    raise frame.primary if frame.primary
    result
  end

  # Runs only in a static, isolated Ruby probe process. Observe original command
  # objects/returns; this is not a waiter, cleanup substitute or PID authority.
  class CommandObservation
    attr_reader :owners, :restoration_errors

    def initialize
      @owners, @native_attempts, @tasks, @joins, @waits, @eofs = [], [], [], [], [], []
      @control_leases, @control_closes, @native_closes = [], [], []
      @restoration_errors = []
      @finished = false
    end

    def install
      spawn, helper = OwnedChild.native_modules
      @hooks = CaptureObservation::Hooks.new
      observer = self
      @hooks.wrap(OwnedChild, :initialize) do |original, object, arguments, keywords, block|
        observer.owners << object
        raise Failure.new("ownership-probe", "too many original command objects") if observer.owners.length > 128
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(spawn.singleton_class, :create) do |original, _object, arguments, keywords, block|
        @native_attempts << arguments.first
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(helper::TaskSlot, :start) do |original, object, arguments, keywords, block|
        @tasks << object
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(Thread, :join) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @joins << object if value.equal?(object)
        value
      end
      @hooks.wrap(Process.singleton_class, :waitpid2) do |original, _object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @waits << [arguments.first, value.last] if value
        value
      end
      @hooks.wrap(OwnedChild, :read_stream) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @eofs << [object, arguments.first] if value.nil?
        value
      end
      @hooks.wrap(OwnedChild::ControlLease, :acquire) do |original, object, arguments, keywords, block|
        @control_leases << object
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(OwnedChild::ControlLease, :close_once) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @control_closes << object
        value
      end
      @hooks.wrap(spawn::IOLease, :close_once) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @native_closes << object
        value
      end
    end

    def observe
      raise Failure.new("ownership-probe", "command observation reused") if @finished || @hooks
      value = primary = nil
      begin
        install
        value = yield
      rescue Exception => error
        primary = error
      ensure
        @restoration_errors.concat(@hooks.restore) if @hooks
        @finished = true
      end
      raise primary if primary
      raise Failure.new("ownership-probe", "command observation did not restore") unless @restoration_errors.empty?
      value
    end

    def child_record(owner)
      raise Failure.new("ownership-probe", "unobserved command object") unless @owners.include?(owner)
      acquisition, creator, child, raw = owner.acquisition, owner.creator, owner.child, owner.status
      receipt = child&.receipt
      attempted = owner.instance_variable_get(:@start_attempted).equal?(true)
      never = !attempted && owner.phase == :unstarted && owner.complete?
      exact_wait = child && acquisition && child.equal?(acquisition.child) && receipt && raw &&
        receipt.equal?(child.receipt) && receipt.raw_status.equal?(raw) && raw.is_a?(Process::Status) &&
        @waits.any? { |pid, value| pid == child.pid && value.equal?(raw) }
      genuine_join = creator && creator.joined? && creator.finished? && !creator.unresolved? && @joins.include?(creator.thread)
      no_creator = creator.nil? && !attempted
      never_started_creator = creator && !creator.start_attempted? && creator.thread.nil? && creator.launch_retired?
      no_native = acquisition && acquisition.not_attempted? && child.nil? && acquisition.child.nil? &&
        owner.instance_variable_get(:@creation_finished) && owner.instance_variable_get(:@no_child_confirmed) &&
        owner.phase == :unstarted && owner.complete? && (genuine_join || never_started_creator)
      eof = %i[out err].all? { |role| @eofs.any? { |object, stream| object.equal?(owner) && stream == role } }
      native_closes = acquisition.nil? || acquisition.resources.values.all? do |lease|
        lease.state == :not_acquired && lease.io.nil? ||
          lease.state == :closed && lease.io.closed? && @native_closes.include?(lease)
      end
      final = (never || no_native || owner.complete? && exact_wait && genuine_join && eof) && native_closes
      {"phase" => owner.phase.to_s, "pid" => owner.pid, "finality" => final ? (never || no_native ? "no_producers" : "finalized") : "unknown",
       "originalWaitObserved" => !!exact_wait, "creatorJoinObserved" => !!genuine_join,
       "noCreatorConstructed" => no_creator, "creatorNeverStarted" => !!never_started_creator,
       "noNativeAttemptConfirmed" => !!(never || no_native), "actualStreamEOFs" => eof, "actualNativeCloses" => native_closes,
       "provenance" => owner.provenance}
    end

    def snapshot
      raise Failure.new("ownership-probe", "command observation is still active") unless @finished
      children = @owners.map { |owner| child_record(owner) }
      known_attempts = @native_attempts.all? { |acquisition| @owners.any? { |owner| owner.acquisition.equal?(acquisition) } }
      controls = @control_leases.uniq.all? do |lease|
        lease.state == :closed && lease.io.closed? && @control_closes.include?(lease)
      end
      tasks = @tasks.uniq.all? { |slot| slot.joined? && slot.finished? && !slot.unresolved? && @joins.include?(slot.thread) }
      settled = known_attempts && controls && tasks && @restoration_errors.empty? && children.none? { |record| record["finality"] == "unknown" }
      {"version" => 1, "children" => children, "nativeAttemptsBound" => known_attempts,
       "actualOwnedControlCloses" => controls, "actualTaskJoins" => tasks,
       "hooksRestored" => @restoration_errors.empty?, "observerErrors" => @restoration_errors.dup,
       "settled" => settled, "noProducers" => settled && @native_attempts.empty? &&
         children.all? { |record| record["finality"] == "no_producers" }, "unknown" => !settled}
    end
  end

  # Original fixture callers, not an Open3 facade. Every process syscall is
  # either forwarded under its original Child lease or vetoed BEFORE entry.
  # A veto is always a failed regression, never a containment/finality pass.
  class OwnershipProbe
    CASES = {
      "async" => %w[async-spawn async-reap cleanup-first-async repeated],
      "signals" => %w[INT-spawn TERM-spawn INT-reap TERM-reap
        cleanup-first-INT cleanup-first-TERM install-before-INT install-before-TERM
        install-buffered-INT install-buffered-TERM install-published-INT install-published-TERM
        restore-before-INT restore-before-TERM restore-after-INT restore-after-TERM],
      "policies" => %w[normal ignored-INT ignored-TERM custom-INT custom-TERM custom-pending-INT
        partial-install changed-handler finalize-report finalize-drain],
      "unknown" => %w[unknown-spawn unknown-reap unknown-echild],
    }.freeze

    attr_reader :records

    def initialize(directory, family)
      @directory, @family = directory, family
      @input = UploadProcessFixture.read_json(File.join(directory, "input.json"))
      raise Failure.new("fixture-input", "unknown ownership case family") unless CASES.key?(family)
      @records = []
      @deadline_ns = @input.fetch("deadlineNs")
      raise Failure.new("fixture-input", "ownership cutoff is not original") unless @deadline_ns.instance_of?(Integer)
    end

    def event(name, extra = {})
      raise Failure.new("ownership-probe", "ownership event bound exceeded") if @events.length >= 64
      @events << {"boundary" => name, "ownerPhase" => @owner&.phase&.to_s}.merge(extra)
    end

    def remember_first(error)
      unless @first
        @first, @first_message = error, error.message.dup.freeze
        @first_status = error.status if error.is_a?(SystemExit)
      end
      error
    end

    def install
      spawn, helper = OwnedChild.native_modules
      @spawn, @task_class = spawn, helper::TaskSlot
      @hooks = CaptureObservation::Hooks.new
      probe, context = self, @context # This row is never reused by a later case.
      @hooks.wrap(OwnedChild, :start) do |original, object, arguments, keywords, block|
        probe.starting(context, object, arguments)
        value = original.call(*arguments, **keywords, &block)
        probe.started(context, object)
        value
      end
      @hooks.wrap(helper::TaskSlot, :start) do |original, object, arguments, keywords, block|
        probe.prepare_injectors(context, object)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(spawn.singleton_class, :create) do |original, _object, arguments, keywords, block|
        acquisition, = arguments
        value = original.call(*arguments, **keywords, &block)
        probe.created(context, acquisition, value)
        value
      end
      @hooks.wrap(spawn::Acquisition, :native_call!) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        probe.native_returned(context, object, arguments, value)
        value
      end
      @hooks.wrap(Process.singleton_class, :waitpid2) do |original, _object, arguments, keywords, block|
        probe.before_wait(context, arguments.first)
        value = original.call(*arguments, **keywords, &block)
        probe.wait_returned(context, arguments.first, value)
        value
      end
      @hooks.wrap(OwnedChild, :poll_wait) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        probe.wait_published(context, object, value)
        value
      end
      @hooks.wrap(Process.singleton_class, :kill) do |original, _object, arguments, keywords, block|
        probe.before_signal(context, *arguments)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(OwnedChild, :stop) do |original, object, arguments, keywords, block|
        probe.before_stop(context, object)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(Signal.singleton_class, :trap) do |original, _object, arguments, keywords, block|
        probe.before_trap(context, arguments.first)
        value = original.call(*arguments, **keywords, &block)
        probe.after_trap(context, arguments.first)
        value
      end
      @hooks.wrap(Thread, :raise) do |original, object, arguments, keywords, block|
        if object.equal?(Thread.main) && arguments.first.is_a?(Exception)
          probe.remember_first(arguments.first) if context.equal?(@context) && context[:gate][:active]
        end
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(Lifetime, :initialize) do |original, object, arguments, keywords, block|
        outer = UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?
        value = original.call(*arguments, **keywords, &block)
        @outer_lifetime ||= object if context.equal?(@context) && context[:gate][:active] && outer && Thread.current.equal?(Thread.main)
        value
      end
      %i[report drain_pending].each do |name|
        @hooks.wrap(Lifetime, name) do |original, object, arguments, keywords, block|
          probe.before_finalize(context, object, name == :report ? "report" : "drain")
          original.call(*arguments, **keywords, &block)
        end
      end
      @hooks.wrap(UploadProcessFixture.singleton_class, :observe_owner_death!) do |original, _object, arguments, keywords, block|
        probe.before_native_death(context)
        original.call(*arguments, **keywords, &block)
      end
    end

    def starting(context, owner, arguments)
      raise Failure.new("ownership-probe", "retired row attempted a new command") unless callback_active?(context)
      @all_owners << owner unless @all_owners.include?(owner)
      argv = arguments.drop(1)
      expected = @helper == "capture" ? argv[1] == "-e" : argv[2] == "driver"
      @owner ||= owner if expected
      if @case == "repeated" && @helper == "run" && @stop_entered && !@nested_cancelled &&
         argv.first == UploadProcessFixture.observation_executable
        @nested_cancelled = true
        depth = UploadProcessFixture.instance_variable_get(:@cancellation_scope)&.cleanup_depth
        event("nested-cleanup-observation", "cleanupDepth" => depth)
        raise Failure.new("ownership-probe", "nested observer reopened active cancellation") unless depth&.positive?
        cancel(context, "INT", cleanup: true)
      end
    end

    def started(context, owner)
      return unless callback_active?(context)
      return unless owner.equal?(@owner)
      if @case == "changed-handler"
        event("published-command-handler-change")
        Signal.trap("INT", @foreign)
      end
    end

    def callback_active?(context)
      context.equal?(@context) && context[:gate][:active] &&
        !UploadProcessFixture.domain_disposal_required? && @owner&.phase != :unknown
    end

    # All async senders are constructed, rooted, started and admitted on the
    # original caller BEFORE the original creator's Thread.new/native attempt.
    # A late in-flight native-return wrapper can only request an existing sender;
    # it cannot create a parentless task after the owner/case has retired.
    def prepare_injectors(context, creator)
      return unless @owner && @owner.creator.equal?(creator) && !@injectors_prepared
      raise Failure.new("ownership-probe", "retired row attempted injector preparation") unless callback_active?(context)
      @injectors_prepared = true
      count = @case == "repeated" ? 2 : @case.include?("async") ? 1 : 0
      return if count.zero?
      unless Thread.current.equal?(creator.caller) && !creator.start_attempted? && !creator.cancelled? &&
             !creator.launch_retired? && UploadProcessFixture.clock_ns < creator.run_deadline_ns
        raise Failure.new("ownership-probe", "injectors lack the original unopened creator gate")
      end
      count.times do
        request = {entered: false, error: nil, cleanup: false, sent: false}
        Thread.handle_interrupt(Exception => :never) do
          context[:lock].synchronize do
            raise Failure.new("ownership-probe", "injector preparation after row retirement") unless callback_active?(context)
            slot = @task_class.new(caller: Thread.current, parent_slot: creator,
              run_deadline_ns: creator.run_deadline_ns, hard_cleanup_deadline_ns: creator.hard_cleanup_deadline_ns)
            @injectors << slot
            @injector_requests << request.merge(slot: slot, owner: @owner, creator: creator)
            entry = @injector_requests.last
            slot.start { deliver_pending(context, entry) }
            raise Failure.new("ownership-probe", "prepublished injector not admitted") unless slot.admit!
          end
          until request_entered = context[:lock].synchronize { @injector_requests.last[:entered] }
            raise Failure.new("ownership-probe", "injector did not enter before original creator") if UploadProcessFixture.clock_ns >= creator.run_deadline_ns
            sleep 0.001
          end
          raise Failure.new("ownership-probe", "injector admission not observed") unless request_entered
        end
      end
    end

    def effect_current!(context, cleanup: false)
      raise Failure.new("ownership-probe", "retired/UNKNOWN callback effect vetoed") unless callback_active?(context)
      cutoff = @owner&.creator&.run_deadline_ns || @deadline_ns
      raise Failure.new("ownership-probe", "callback passed original owner cutoff") unless UploadProcessFixture.clock_ns < cutoff
      if @owner&.creator
        creator = @owner.creator
        known_completed = creator.joined? && creator.finished? && @owner.phase != :unknown
        allowed_repeat = cleanup && @stop_entered && @first &&
          UploadProcessFixture.instance_variable_get(:@cancellation_scope)&.cleanup_depth&.positive?
        unless (!creator.launch_retired? || known_completed || allowed_repeat) && (!creator.cancelled? || allowed_repeat)
          raise Failure.new("ownership-probe", "callback left original owner cancellation/launch gate")
        end
      end
      true
    end

    def deliver_pending(context, entry)
      context[:lock].synchronize { entry[:entered] = true }
      loop do
        finished = context[:lock].synchronize do
          # The same lock closes the row before ensure joins. No signal or task
          # publication may race that closure. The already-admitted repeat can
          # run only in the original protected cleanup, never after UNKNOWN.
          if !callback_active?(context) || UploadProcessFixture.clock_ns >= entry[:creator].run_deadline_ns
            true
          elsif entry[:error]
            unless entry[:owner].equal?(@owner) && entry[:creator].equal?(@owner.creator) &&
                   entry[:slot].parent_slot.equal?(entry[:creator])
              raise Failure.new("ownership-probe", "injector original parent binding changed")
            end
            effect_current!(context, cleanup: entry[:cleanup])
            Thread.main.raise(entry[:error])
            entry[:sent] = true
            true
          else
            false
          end
        end
        return true if finished
        sleep 0.001
      end
    end

    def cancel(context, kind, error = nil, cleanup: false)
      Thread.handle_interrupt(Exception => :never) do
        entry = context[:lock].synchronize do
          effect_current!(context, cleanup: cleanup)
          if kind == "async"
            error ||= Interrupt.new("first asynchronous fixture cancellation")
            remember_first(error)
            pending = @injector_requests.find { |item| item[:error].nil? && !item[:sent] }
            raise Failure.new("ownership-probe", "no original preadmitted injector") unless pending && pending[:entered]
            pending[:error], pending[:cleanup] = error, cleanup
            pending
          else
            Process.kill(kind, Process.pid) # This isolated probe's OWN process only.
            nil
          end
        end
        if entry
          slot = entry.fetch(:slot)
          unless slot.join_until(deadline_ns: slot.run_deadline_ns) && entry[:sent]
            raise Failure.new("ownership-probe", "original injector delivery/join missing")
          end
        end
      end
    end

    def created(context, acquisition, actual)
      return unless callback_active?(context)
      return unless @owner && @owner.acquisition.equal?(acquisition)
      unless actual && actual.equal?(acquisition.child) && actual.pid.is_a?(Integer)
        raise Failure.new("ownership-probe", "native return was not the original published Child")
      end
      @target_pid, @published_child = actual.pid, actual
      return if @case.start_with?("unknown-")
      if @case.end_with?("-spawn")
        event("native-child-published-before-bootstrap-GO", "actualPid" => actual.pid)
        cancel(context, @case.split("-").first)
        # Causal barrier: main has actually recorded its original cancellation
        # while the native creator is still here, before it can grant bootstrap
        # GO. Mere scheduling/timestamp order is not the proof.
        cutoff = @owner.creator.run_deadline_ns
        until @first && @owner.creator.first_error.equal?(@first)
          raise Failure.new("ownership-probe", "caller did not latch cancellation before GO") if UploadProcessFixture.clock_ns >= cutoff
          sleep 0.001
        end
        unless @owner.instance_variable_get(:@go_state) == "closed" || @owner.instance_variable_get(:@go_state) == "not_attempted"
          raise Failure.new("ownership-probe", "bootstrap GO preceded cancellation barrier")
        end
        @pre_go_cancellation = true
      elsif @case.start_with?("ignored-")
        event("published-native-child-under-ignored-policy")
        cancel(context, @case.split("-").last)
      end
    end

    def native_returned(context, acquisition, arguments, call)
      return unless callback_active?(context)
      return unless @case == "unknown-spawn" && @owner && @owner.acquisition.equal?(acquisition) && arguments.first == "posix_spawn"
      raise Failure.new("ownership-probe", "native acquisition fault lacks actual success") unless call.state == :returned && call.result == 0
      @raw_pid = arguments.fetch(1)[0, 4].unpack1("l<") # Read-only original native return; NEVER signal/wait authority.
      raise Failure.new("ownership-probe", "invalid actual native PID") unless @raw_pid.between?(2, 2_147_483_647)
      @unknown_seam = true
      event("actual-posix-spawn-return-before-Child-publication", "actualPid" => @raw_pid)
      raise remember_first(Interrupt.new("original lost native creation publication"))
    end

    def owner_for(pid)
      @all_owners.find { |owner| owner.child&.pid == pid || owner.acquisition&.child&.pid == pid }
    end

    def before_wait(context, pid)
      owner = owner_for(pid)
      forbidden = !callback_active?(context) || @unknown_seam && pid == (@raw_pid || @target_pid) || !owner || owner.phase != :waiting ||
        !owner.child || !owner.child.numeric_retired? || owner.child.state == :unknown
      return unless forbidden
      @unsafe_waits << {"pid" => pid, "ownerPhase" => owner&.phase&.to_s}
      raise Failure.new("ownership-probe", "unknown/unowned/retired wait retry VETOED")
    end

    def wait_returned(context, pid, returned)
      return unless callback_active?(context)
      return unless returned && pid == @target_pid
      unless returned.first == pid && returned.last.is_a?(Process::Status) && returned.last.pid == pid
        raise Failure.new("ownership-probe", "wait did not return original OS status")
      end
      @raw_wait = returned.last
      return unless %w[unknown-reap unknown-echild].include?(@case) && !@unknown_seam
      @unknown_seam = true
      event("actual-terminal-wait-before-receipt-publication", "actualPid" => pid)
      error = @case == "unknown-echild" ? Errno::ECHILD.new("lost original terminal wait publication") : Interrupt.new("original lost terminal wait publication")
      raise remember_first(error)
    end

    def wait_published(context, owner, returned)
      return unless callback_active?(context)
      return unless owner.equal?(@owner) && returned && !@injected
      unless owner.phase == :reaped && owner.status.equal?(@raw_wait) && owner.child.receipt.raw_status.equal?(@raw_wait)
        raise Failure.new("ownership-probe", "original wait publication was not observed")
      end
      if %w[async-reap INT-reap TERM-reap].include?(@case)
        @injected = true
        event("original-terminal-receipt-published", "actualPid" => owner.pid)
        cancel(context, @case.split("-").first)
      elsif @case == "repeated" && @helper == "capture"
        @injected = true
        event("first-post-receipt-cancellation")
        cancel(context, "async")
      end
    end

    def before_signal(context, signal, *targets)
      return if callback_active?(context) && targets == [Process.pid] && ["INT", "TERM", Signal.list.fetch("INT"), Signal.list.fetch("TERM")].include?(signal)
      valid = callback_active?(context) && [0, "INT", "TERM", "KILL"].include?(signal) && targets.length == 1 && targets.all? do |target|
        next false unless target.is_a?(Integer)
        owner = owner_for(target.abs)
        owner && !@unknown_seam && owner.phase == :reserved && owner.child &&
          owner.child.equal?(owner.acquisition.child) && owner.child.state == :running &&
          !owner.child.numeric_retired? && owner.creator.joined? &&
          !owner.instance_variable_get(:@numeric_retired) &&
          (target.positive? || owner.instance_variable_get(:@private_group))
      end
      return if valid
      @unsafe_signals << {"signal" => signal, "targets" => targets}
      raise Failure.new("ownership-probe", "stale/unknown/unowned numeric request VETOED") # Includes signal0.
    end

    def before_stop(context, owner)
      return unless callback_active?(context)
      return unless owner.equal?(@owner) && !@stop_entered
      depth = UploadProcessFixture.instance_variable_get(:@cancellation_scope)&.cleanup_depth
      return unless depth&.positive?
      @stop_entered = true
      if @case.start_with?("cleanup-first-")
        event("first-protected-cleanup-entry", "cleanupDepth" => depth, "noEarlierPrimary" => @first.nil?)
        raise Failure.new("ownership-probe", "cleanup-first already had a primary") if @first
        cancel(context, @case.delete_prefix("cleanup-first-"))
      elsif @case == "repeated"
        event("repeat-protected-cleanup-entry", "cleanupDepth" => depth)
        cancel(context, "async", Interrupt.new("repeat cannot replace original fixture cancellation"), cleanup: true)
      end
    end

    def before_native_death(context)
      return unless callback_active?(context)
      return unless @case == "repeated" && @helper == "run" && !@injected
      @injected = true
      event("first-after-native-finality-before-read-only-death")
      cancel(context, "async")
    end

    def before_trap(context, name)
      return unless callback_active?(context)
      name = name.to_s.delete_prefix("SIG")
      @trap_calls[name] += 1
      if @case == "partial-install" && name == "TERM" && @trap_calls[name] == 1
        @partial_install_error = remember_first(Failure.new("signal-policy", "original partial signal policy installation failure"))
        event("before-original-TERM-policy-installation", "intTrapCalls" => @trap_calls["INT"], "termTrapCalls" => @trap_calls["TERM"])
        raise @partial_install_error
      end
      if @case == "install-before-#{name}" && @trap_calls[name] == 1
        event("before-trap-install", "signal" => name)
        cancel(context, name)
      elsif @case == "restore-before-#{name}" && @trap_calls[name] == 3
        event("before-original-trap-restoration", "signal" => name)
        cancel(context, name)
      end
    end

    def after_trap(context, name)
      return unless callback_active?(context)
      name = name.to_s.delete_prefix("SIG")
      if @trap_calls[name] == 1 && ["install-buffered-#{name}", "ignored-#{name}", "custom-pending-#{name}"].include?(@case)
        event("trap-installed-before-policy-publication", "signal" => name)
        cancel(context, name)
      elsif @case == "restore-after-#{name}" && @trap_calls[name] == 3
        event("after-original-trap-restoration", "signal" => name)
        cancel(context, name)
      end
    end

    def before_finalize(context, frame, kind)
      return unless callback_active?(context) && @case == "finalize-#{kind}" && !@injected && frame.equal?(@outer_lifetime)
      @injected = true
      event("finalization-#{kind}-failure", "originalOutermostLifetime" => true)
      raise remember_first(Failure.new("signal-policy", "original #{kind} failure must not skip restoration"))
    end

    def trap_state
      %w[INT TERM].to_h do |name|
        current = Signal.trap(name) {}
        Signal.trap(name, current)
        [name, current]
      end
    end

    def invoke
      if @helper == "capture"
        code = @case.end_with?("-spawn") ? "sleep 30" : "exit 0"
        UploadProcessFixture.capture_command([File.realpath(RbConfig.ruby), "-e", code],
          seconds: 2, root: @case_root, deadline: Rational(@deadline_ns, 1_000_000_000))
      else
        UploadProcessFixture.run(platform: @input.fetch("platform"), root: @case_root,
          parameters: @input.fetch("parameters"), mode: "inherited", deadline_ns: @deadline_ns)
      end
    end

    def one(helper, name, case_root: nil)
      UploadProcessFixture.assert_domain_reusable!
      raise Failure.new("ownership-probe", "original ownership row reused") if @case_started
      @case_started = true
      unless %w[capture run].include?(helper) && CASES.fetch(@family).include?(name)
        raise Failure.new("fixture-input", "unknown fixed ownership case")
      end
      @helper, @case = helper, name
      @case_root = case_root || File.realpath(Dir.mktmpdir("ownership-#{helper}-", @directory))
      @context = {token: Object.new.freeze, helper: helper.dup.freeze, name: name.dup.freeze,
        root: @case_root.dup.freeze, lock: Mutex.new, gate: {active: true}}.freeze
      context = @context
      environment = %w[TMPDIR TMP TEMP].to_h { |key| [key, ENV[key]] }
      %w[TMPDIR TMP TEMP].each { |key| ENV[key] = @case_root }
      @owner = @target_pid = @raw_pid = @raw_wait = @first = @first_message = @first_status = nil
      @hooks = nil
      proof = File.join(@case_root, "case-proof.json") # Original reporting scope before any native attempt.
      @events, @injectors, @all_owners, @unsafe_signals, @unsafe_waits = [], [], [], [], []
      @injector_requests, @injectors_prepared = [], false
      @injected = @unknown_seam = @stop_entered = @nested_cancelled = @pre_go_cancellation = false
      @trap_calls = Hash.new(0)
      @custom_deliveries = []
      @foreign = proc { |number| @custom_deliveries << number }
      saved = trap_state
      signal = name.split("-").last
      Signal.trap(signal, "IGNORE") if name.start_with?("ignored-")
      Signal.trap(signal, @foreign) if name.start_with?("custom-")
      expected_traps = trap_state
      expected_traps["INT"] = @foreign if name == "changed-handler"
      observation = CommandObservation.new
      trace = TracePoint.new(:line) do |point|
        if name.start_with?("install-published-") && point.method_id == :install &&
           point.self.is_a?(CancellationScope) && !@injected && point.self.instance_variable_get(:@policies).key?(Signal.list.fetch(signal))
          @injected = true
          event("after-policy-publication", "signal" => signal)
          cancel(context, signal)
        end
      end
      error = nil
      hook_errors, cleanup_errors = [], []
      begin
        observation.observe do
          operation_error = nil
          begin
            install
            trace.enable
            invoke
          rescue Exception => failure
            operation_error = failure
          ensure
            trace.disable
            # Closing this ORIGINAL row is permanent and precedes the sole
            # join/restore pass. A native call already in flight still retains
            # its original owner/error, but its wrapper cannot renew effects.
            Thread.handle_interrupt(Exception => :never) do
              context[:lock].synchronize do
                context[:gate][:active] = false
                @injectors.each(&:close_launch!)
              end
            end
            # Only the original prepublished injectors are joined. Each failure
            # is secondary to the already returned original operation error.
            @injectors.each do |slot|
              begin
                unless slot.join_until(deadline_ns: slot.hard_cleanup_deadline_ns)
                  raise Failure.new("ownership-probe", "original injector not joined")
                end
              rescue Exception => failure
                cleanup_errors << failure
              end
            end
            hook_errors.concat(@hooks.restore) if @hooks
          end
          raise operation_error if operation_error
          raise cleanup_errors.first unless cleanup_errors.empty?
        end
      rescue Exception => failure
        error = failure
      ensure
        trace.disable
      end
      actual_traps = trap_state
      registry_inactive = UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?
      snapshot = observation.snapshot
      unknown = name.start_with?("unknown-")
      retained = UploadProcessFixture.cleanup_unresolved?(@case_root) || snapshot["unknown"]
      unless unknown || retained || UploadProcessFixture.domain_disposal_required?
        retained ||= UploadProcessFixture.fixture_entry_names(@case_root).any? do |entry|
          entry.start_with?("native-process-", "mrk-process-observation-")
        end
      end
      failures = []
      check = ->(label, value) { failures << label unless value }
      check.call("numeric requests were vetoed", @unsafe_signals.empty? && @unsafe_waits.empty?)
      check.call("original handler policy not restored", actual_traps == expected_traps)
      check.call("lifetime registry remains active", registry_inactive)
      check.call("observation hooks not restored", hook_errors.empty? && snapshot["hooksRestored"])
      check.call("independent injector cleanup failed", cleanup_errors.empty?)
      check.call("original error object/message replaced", !@first || error.equal?(@first) && error.message == @first_message &&
        (!@first.is_a?(SystemExit) || error.status == @first_status))
      check.call("original injectors not joined", @injectors.all? { |slot| slot.joined? && slot.finished? && !slot.unresolved? })
      check.call("original injector custody/gate changed", !context[:gate][:active] &&
        @injector_requests.all? { |entry| entry[:owner].equal?(@owner) && entry[:creator].equal?(@owner.creator) &&
          entry[:slot].parent_slot.equal?(entry[:creator]) && entry[:slot].run_deadline_ns == entry[:creator].run_deadline_ns &&
          entry[:slot].hard_cleanup_deadline_ns == entry[:creator].hard_cleanup_deadline_ns })
      check.call("pending cancellation leaked", !Thread.current.pending_interrupt?)
      normal = name == "normal" || name.start_with?("ignored-")
      finalize = name.start_with?("finalize-")
      policy = name.start_with?("custom-") || %w[partial-install changed-handler].include?(name) || finalize
      if normal
        check.call("normal/ignored original command did not finalize", error.nil? && snapshot["settled"] && @owner&.complete?)
      elsif policy
        check.call("unsupported policy did not fail closed", error.is_a?(Failure) && error.kind == "signal-policy")
        check.call("unsupported policy attempted native creation", snapshot["noProducers"]) unless name == "changed-handler" || finalize
        check.call("original custom pending signal lost", @custom_deliveries == [Signal.list.fetch("INT")]) if name == "custom-pending-INT"
        if name == "partial-install"
          check.call("intended before-TERM partial installation was not exercised", @partial_install_error &&
            error.equal?(@partial_install_error) && @first.equal?(@partial_install_error) &&
            @events.count { |entry| entry["boundary"] == "before-original-TERM-policy-installation" &&
              entry["intTrapCalls"] == 1 && entry["termTrapCalls"] == 1 } == 1)
        end
        if finalize
          check.call("finalization failure skipped original command cleanup", @injected && @owner&.complete? && snapshot["settled"])
          check.call("finalization fault missed the original outermost lifetime", @outer_lifetime && @first &&
            error.equal?(@first) && @events.count { |entry| entry["boundary"] == "finalization-#{name.delete_prefix('finalize-')}-failure" &&
              entry["originalOutermostLifetime"].equal?(true) } == 1)
        end
      else
        check.call("cancellation/lost-publication fault not propagated", error.is_a?(SignalException) || name == "unknown-echild" && error.is_a?(Errno::ECHILD))
        check.call("original injection boundary missing", !@events.empty?)
        expected_signal = name.include?("TERM") ? "TERM" : "INT"
        check.call("wrong original cancellation signal", error.signo == Signal.list.fetch(expected_signal)) if error.is_a?(SignalException) && !unknown
        if unknown
          check.call("UNKNOWN was accepted or scratch removed", @unknown_seam && @owner&.phase == :unknown && snapshot["unknown"] && retained)
          check.call("UNKNOWN invented a published original wait", @owner&.status.nil? && @owner&.child&.receipt.nil?)
          if name == "unknown-spawn"
            check.call("unknown creation dispatched target", @owner.instance_variable_get(:@go_offset).zero?)
            check.call("unknown creation lacks original native return", @raw_pid.is_a?(Integer) && @owner.acquisition.child.nil? &&
              @owner.acquisition.state == :unknown)
          else
            check.call("lost original wait was not genuinely observed", @raw_wait.is_a?(Process::Status) &&
              @raw_wait.pid == @target_pid && @owner.child && @owner.child.pid == @target_pid && @owner.child.state == :unknown)
          end
        else
          check.call("known cancellation did not finish original ownership", snapshot["settled"])
          check.call("native creator published GO before caller cancellation", @pre_go_cancellation) if name.end_with?("-spawn")
          check.call("nested cleanup cancellation not exercised", @nested_cancelled) if name == "repeated" && helper == "run"
        end
      end
      check.call("known case left an unresolved reusable domain", !retained) unless unknown
      UploadProcessFixture.retain_unknown_domain!(@case_root, expected: true) if unknown && failures.empty?
      UploadProcessFixture.mark_process_domain_failed! unless failures.empty?
      summary = {"helper" => helper, "case" => name, "failures" => failures,
        "firstExceptionPreserved" => !@first || error.equal?(@first) && error.message == @first_message,
        "allKnownCommandChildrenFinalized" => snapshot["settled"], "retainedFixture" => retained,
        "domainDisposalRequired" => unknown, "nativeFinality" => unknown ? "unknown" : "finalized",
        "unknownPublication" => unknown && @unknown_seam, "unsafeSignalRequests" => @unsafe_signals,
        "unsafeWaitRequests" => @unsafe_waits, "handlersRestored" => actual_traps == expected_traps,
        "registryInactive" => registry_inactive, "raisersJoined" => @injectors.all? { |slot| slot.joined? && slot.finished? },
        "hooksRestored" => hook_errors.empty? && snapshot["hooksRestored"], "pendingInterrupt" => Thread.current.pending_interrupt?}
      detail = summary.merge("events" => @events, "commandObservation" => snapshot,
        "exceptionClass" => error&.class&.name, "exceptionMessage" => error&.message,
        "actualRawNativePid" => @raw_pid, "actualRawWaitObserved" => !!@raw_wait,
        "nativePublicationBeforeGO" => @pre_go_cancellation, "callbackRowRetired" => !context[:gate][:active],
        "prepublishedInjectors" => @injector_requests.map { |entry| {"enteredBeforeCreator" => entry[:entered],
          "parentBound" => entry[:slot].parent_slot.equal?(entry[:creator]), "sent" => entry[:sent],
          "runDeadlineNs" => entry[:slot].run_deadline_ns, "hardDeadlineNs" => entry[:slot].hard_cleanup_deadline_ns} })
      raise Failure.new("ownership-probe", "ownership proof exceeds original reporting bound") if JSON.generate(detail).bytesize > OUTPUT_LIMIT
      UploadProcessFixture.atomic_json(proof, detail)
      summary["proofSha256"] = Digest::SHA256.file(proof).hexdigest
      @records << summary
      raise Failure.new("ownership-probe", JSON.generate(summary)) unless failures.empty?
      UploadProcessFixture.remove_fixture_directory(@case_root, root: @directory, layout: :joined_case) unless retained || case_root
      summary
    rescue Exception
      UploadProcessFixture.mark_process_domain_failed!(owner: self)
      raise
    ensure
      trace&.disable
      if @context
        @context[:lock].synchronize { @context[:gate][:active] = false }
      end
      saved&.each { |key, handler| Signal.trap(key, handler) }
      environment&.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    end

    def execute
      # Deliberate UNKNOWN is a SINGLE original-disposable-domain capture.
      # The outer runner selects it separately; it is never followed by another
      # helper/case or by a second attempt in this Ruby process/domain.
      raise Failure.new("fixture-input", "UNKNOWN requires a singleton original owner") if @family == "unknown"
      @case_probes = []
      %w[capture run].each do |helper|
        CASES.fetch(@family).each do |name|
          raise Failure.new("ownership-probe", "original family deadline expired") unless UploadProcessFixture.clock_ns < @deadline_ns
          probe = self.class.new(@directory, @family)
          @case_probes << probe # Never repurpose a late wrapper's receiver.
          @records << probe.one(helper, name)
        end
      end
      {"kind" => "pass", "family" => @family, "cases" => @records, "retainedFixture" => false}
    end

    def execute_single(helper, name)
      raise Failure.new("fixture-input", "only fixed UNKNOWN may use singleton dispatch") unless @family == "unknown"
      one(helper, name, case_root: @directory)
      UploadProcessFixture.retain_process_case!(self)
      {"kind" => "pass", "family" => @family, "cases" => @records, "retainedFixture" => true,
       "domainDisposalRequired" => true, "nativeFinality" => "unknown"}
    end
  end

  # Setup fault is before Lifetime#active and before the actual stderr lease
  # acquisition. The original native create API is vetoed BEFORE entry. A real
  # cleanup error and queued self/Thread cancellation must not replace the first.
  class SetupFailureProbe
    def initialize(directory)
      @directory = directory
      @input = UploadProcessFixture.read_json(File.join(directory, "input.json"))
      @deadline_ns = @input.fetch("deadlineNs")
      @records = []
    end

    def install
      @spawn, helper = OwnedChild.native_modules
      @task_class = helper::TaskSlot
      @hooks = CaptureObservation::Hooks.new
      probe = self
      @hooks.wrap(OwnedChild::ControlLease, :acquire) do |original, object, arguments, keywords, block|
        probe.before_acquire(object, block)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(OwnedChild::ControlLease, :close_once) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @closes << object if @active
        value
      end
      @hooks.wrap(UploadProcessFixture.singleton_class, :atomic_json) do |original, _object, arguments, keywords, block|
        probe.writing(arguments.first)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(FileUtils.singleton_class, :remove_entry) do |original, _object, arguments, keywords, block|
        probe.removing(arguments.first)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(Kernel, :warn) do |original, _object, arguments, keywords, block|
        probe.warning(arguments)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(@spawn.singleton_class, :create) do |original, _object, arguments, keywords, block|
        probe.before_native_create
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(Process.singleton_class, :spawn) do |_original, _object, _arguments, _keywords, _block|
        @spawn_attempts += 1
        raise Failure.new("setup-probe", "forbidden Process.spawn fallback VETOED")
      end
      @hooks.wrap(CancellationScope, :queue) do |original, _object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @signals << arguments.first if @active
        value
      end
      @hooks.wrap(Thread, :join) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @raiser_join_observed = true if @active && @raiser && object.equal?(@raiser.thread) && value.equal?(object)
        value
      end
    end

    def owned?(path)
      @active && path.is_a?(String) && path.start_with?(@case_root + "/")
    end

    def before_acquire(lease, block)
      return unless @active && @helper == "capture"
      binding = block&.binding
      return unless binding && binding.receiver.equal?(UploadProcessFixture) &&
        binding.local_variable_defined?(:directory) && binding.local_variable_defined?(:name) &&
        owned?(File.join(binding.local_variable_get(:directory), binding.local_variable_get(:name)))
      @leases << lease
      return unless binding.local_variable_get(:name) == "stderr"
      unless lease.state == :unattempted && lease.io.nil?
        raise Failure.new("setup-probe", "setup fault no longer precedes actual lease acquisition")
      end
      @no_stderr_attempt = true
      setup_fault
    end

    def writing(path)
      setup_fault if @helper != "capture" && owned?(path) && File.basename(path) == "input.json"
    end

    def setup_fault
      @setup_hit = true
      raise @first
    end

    def removing(path)
      cleanup_fault if @helper != "ownership" && owned?(path)
    end

    def warning(messages)
      return unless @active
      expected = "Fixture cleanup incomplete: #{@second.class}: #{@second.message}; primary=#{@first.class}: #{@first.message}"
      @cleanup_reported = true if messages == [expected]
      cleanup_fault if @helper == "ownership" && messages.first.to_s.start_with?("Preserve ownership probe failure:")
    end

    def before_native_create
      return unless @active
      @spawn_attempts += 1
      raise Failure.new("setup-probe", "unexpected original native create entry VETOED")
    end

    def cleanup_fault
      return if @cleanup_hit
      @cleanup_hit = true
      @cleanup_depth = UploadProcessFixture.instance_variable_get(:@cancellation_scope)&.cleanup_depth
      if @repeats
        Process.kill("INT", Process.pid) # Only this isolated probe's own process.
        cutoff = [UploadProcessFixture.clock_ns + 2_000_000_000, @deadline_ns].min
        @raiser = @task_class.new(caller: Thread.current, parent_slot: nil,
          run_deadline_ns: cutoff, hard_cleanup_deadline_ns: cutoff) # Prepublished before actual Thread.new.
        @raiser.start do
          Thread.main.raise(Interrupt.new("queued repeat after original setup and cleanup faults"))
          @repeat_queued = true
          true
        end
        raise Failure.new("setup-probe", "setup injector not admitted") unless @raiser.admit!
        raise Failure.new("setup-probe", "setup injector original join missing") unless @raiser.join_until(deadline_ns: cutoff)
      end
      @cleanup_fault_raised = true
      raise @second
    end

    def trap_state
      %w[INT TERM].to_h do |name|
        value = Signal.trap(name) {}
        Signal.trap(name, value)
        [name, value]
      end
    end

    def one(helper, error_class, repeats)
      UploadProcessFixture.assert_domain_reusable!
      @helper, @repeats = helper, repeats
      @setup_hit = @cleanup_hit = @cleanup_reported = @no_stderr_attempt = false
      @cleanup_fault_raised = @repeat_queued = @raiser_join_observed = false
      @cleanup_depth = @raiser = nil
      @spawn_attempts, @signals, @leases, @closes = 0, [], [], []
      @case_root = File.realpath(Dir.mktmpdir("setup-#{helper}-", @directory))
      identity = OwnedChild.identity(UploadProcessFixture.owned_fixture_directory(@case_root)).reject { |key, _| key == "nlink" }
      environment = %w[TMPDIR TMP TEMP].to_h { |key| [key, ENV[key]] }
      %w[TMPDIR TMP TEMP].each { |key| ENV[key] = @case_root }
      @first = error_class.new("original synchronous #{helper} setup failure")
      message = @first.message.dup.freeze
      @second = IOError.new("distinct cleanup failure must not replace setup")
      before = trap_state
      error = nil
      @active = true
      begin
        if helper == "capture"
          UploadProcessFixture.capture_command([File.realpath(RbConfig.ruby), "-e", "exit 0"], root: @case_root,
            deadline: Rational(@deadline_ns, 1_000_000_000))
        else
          mode = helper == "run" ? "unready" : "ownership-async"
          UploadProcessFixture.run(platform: @input.fetch("platform"), root: @case_root,
            parameters: @input.fetch("parameters"), mode: mode, deadline_ns: @deadline_ns)
        end
      rescue Exception => failure
        error = failure
      ensure
        @active = false
      end
      raiser_joined = !@raiser || @raiser.joined? && @raiser.finished? && !@raiser.unresolved? && @raiser_join_observed
      exact_closes = @leases.all? do |lease|
        lease.state == :unattempted && lease.io.nil? || lease.state == :closed && lease.io.closed? && @closes.include?(lease)
      end
      if UploadProcessFixture.domain_disposal_required? || !raiser_joined || !exact_closes
        UploadProcessFixture.retain_unknown_domain!(@case_root)
        UploadProcessFixture.mark_process_domain_failed!(owner: self)
        raise(error || Failure.new("setup-probe", "setup custody is ambiguous; no further acquisition"))
      end
      unless @spawn_attempts.zero? && @setup_hit && @cleanup_hit && error.equal?(@first)
        UploadProcessFixture.mark_process_domain_failed!(owner: self)
        raise(error || Failure.new("setup-probe", "setup did not reach its exact no-native boundaries"))
      end
      preserved = UploadProcessFixture.fixture_entry_names(@case_root)
      handlers_restored = trap_state == before
      registry_inactive = UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?
      failures = []
      failures << "required setup/cleanup boundary missing" unless @setup_hit && @cleanup_hit
      failures << "setup crossed stderr acquisition" if helper == "capture" && !@no_stderr_attempt
      failures << "distinct protected cleanup fault missing" unless @cleanup_fault_raised && @cleanup_depth&.positive?
      failures << "first object/message replaced" unless error.equal?(@first) && error.message == message
      failures << "cleanup error not separately reported" unless @cleanup_reported
      failures << "native creation was attempted" unless @spawn_attempts.zero?
      failures << "cleanup failure evidence was removed" if preserved.empty?
      failures << "actual original close/join not observed" unless exact_closes && raiser_joined
      failures << "handlers/registry not restored" unless handlers_restored && registry_inactive
      failures << "pending cancellation leaked" if Thread.current.pending_interrupt?
      failures << "actual repeated cancellation missing" if repeats && (@signals != [Signal.list.fetch("INT")] || !@repeat_queued || !@raiser)
      record = {"helper" => helper, "setupClass" => error_class.name, "repeatedCancellation" => repeats,
        "setupHit" => @setup_hit, "cleanupHit" => @cleanup_hit, "cleanupErrorReported" => @cleanup_reported,
        "cleanupDepth" => @cleanup_depth, "cleanupFaultRaised" => @cleanup_fault_raised,
        "originalObjectAndMessagePreserved" => error.equal?(@first) && error.message == message,
        "spawnAttempts" => @spawn_attempts, "noNativeCreateEntered" => @spawn_attempts.zero?,
        "osSignalsQueued" => @signals, "handlersRestored" => handlers_restored, "registryInactive" => registry_inactive,
        "asyncRepeatQueued" => @repeat_queued, "raiserJoined" => raiser_joined, "actualOwnedCloses" => exact_closes,
        "pendingInterrupt" => Thread.current.pending_interrupt?, "preservedDirectories" => preserved.length, "failures" => failures}
      @records << record
      UploadProcessFixture.atomic_json(File.join(@directory, "setup-progress.json"), @records)
      unless failures.empty?
        UploadProcessFixture.mark_process_domain_failed!
        raise Failure.new("setup-probe", JSON.generate(record))
      end
      # This is not UNKNOWN repair: the before-entry native veto, positive
      # no-stderr-acquisition seam and actual closes/joins prove zero producers.
      # Do not clear any original retained-state latch or reuse the case path.
      unless OwnedChild.identity(UploadProcessFixture.owned_fixture_directory(@case_root)).reject { |key, _| key == "nlink" } == identity
        raise Failure.new("setup-probe", "original setup directory identity changed")
      end
      FileUtils.remove_entry(@case_root)
    rescue Exception
      UploadProcessFixture.mark_process_domain_failed!(owner: self)
      raise
    ensure
      @active = false
      environment&.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    end

    def execute
      begin
        install
        %w[capture run ownership].product([IOError, Interrupt], [false, true]).each do |arguments|
          raise Failure.new("setup-probe", "original setup family cutoff expired") unless UploadProcessFixture.clock_ns < @deadline_ns
          one(*arguments)
        end
      ensure
        @active = false
        @hook_errors = @hooks ? @hooks.restore : ["setup_hooks_unpublished"]
      end
      raise Failure.new("setup-probe", "original setup hooks not restored") unless @hook_errors.empty?
      {"kind" => "pass", "cases" => @records, "hooksRestored" => true, "retainedFixture" => false}
    end
  end

  # Substitute only the final read-only C/K/V/descendant observations, after
  # the original driver wait and genuine native finality. Every actual role is
  # independently observed dead BEFORE synthetic uncertainty. Persistent is
  # LAST, retains its original latch/root, and never acquires another observer.
  class ObservationProbe
    def initialize(directory)
      @directory = directory
      @input = UploadProcessFixture.read_json(File.join(directory, "input.json"))
      @deadline_ns = @input.fetch("deadlineNs")
      raise Failure.new("fixture-input", "observation cutoff is not original") unless @deadline_ns.instance_of?(Integer)
      @records = []
      @active_native = @synthetic = @retained = false
    end

    def install
      @hooks = CaptureObservation::Hooks.new
      probe = self
      @hooks.wrap(UploadProcessFixture.singleton_class, :state) do |original, _object, arguments, keywords, block|
        probe.state_call(original, arguments, keywords, block)
      end
      @hooks.wrap(UploadProcessFixture.singleton_class, :dead!) do |original, _object, arguments, keywords, block|
        probe.dead_call(original, arguments, keywords, block)
      end
      @hooks.wrap(UploadProcessFixture.singleton_class, :native_owner_finality?) do |original, _object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        if @active_native && arguments.first == "inherited" && value.equal?(true)
          @final_owner, @final_result = arguments[1], arguments[2]
        end
        value
      end
      @hooks.wrap(UploadProcessFixture.singleton_class, :observe_owner_death!) do |original, _object, arguments, keywords, block|
        if @active_native && keywords[:root] == @case_root
          probe.native_death(original, arguments, keywords, block)
        else
          original.call(*arguments, **keywords, &block)
        end
      end
    end

    def phase
      scope = UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      scope && scope.cleanup_depth.positive? ? "cleanup" : "active"
    end

    def deadline_ns(value)
      (value.to_r * 1_000_000_000).floor
    end

    def state_call(original, arguments, keywords, block)
      pid, group = arguments
      target = @identities&.include?([pid, group])
      if @synthetic && target
        raise Failure.new("observation-probe", "synthetic role observation adopted a capture task") if keywords[:parent_slot]
        index = @counts[[pid, group]]
        token = @persistent ? "?E" : @tokens.fetch(index)
        @counts[[pid, group]] += 1
        now = UploadProcessFixture.clock_ns
        seconds = keywords.fetch(:seconds, 2)
        cutoff = keywords[:deadline] && deadline_ns(keywords[:deadline])
        @within_budget &&= seconds.positive? && seconds <= 2 &&
          (!cutoff || cutoff == @death_deadline_ns && now + (seconds * 1_000_000_000).floor <= cutoff + 50_000_000)
        @after_unknown_observations += 1 if @retained
        item = [pid, group, token, seconds, now, phase]
        @observation_count += 1
        if @samples.length < 32
          @samples << item
        else
          @last_samples << item
          @last_samples.shift if @last_samples.length > 32
        end
        @token_counts[[pid, group]][token] += 1
        @sequences[[pid, group]] << token if @sequences[[pid, group]].length < 16
        stdout, status = token == "absent" ? ["", 1] : ["#{pid} #{group} #{token}\n", 0]
        return UploadProcessFixture.liveness(UploadProcessFixture.parse_state(stdout, "", status, pid, group))
      end
      if @retained
        @unexpected_native_after_unknown = true
        raise Failure.new("observation-probe", "fresh native observer after retained uncertainty VETOED")
      end
      value = original.call(*arguments, **keywords, &block)
      if @proving_physical && target
        @physical_states << {"pid" => pid, "group" => group, "value" => value.to_s,
          "atNs" => UploadProcessFixture.clock_ns, "deadlineNs" => deadline_ns(keywords.fetch(:deadline))}
      end
      value
    end

    def dead_call(original, arguments, keywords, block)
      pid, group = arguments
      target = @identities&.include?([pid, group])
      if @synthetic && target
        raise Failure.new("observation-probe", "too many original death entries") if @dead_calls.length >= 8
        @dead_calls << {"pid" => pid, "group" => group,
          "deadlineNs" => deadline_ns(keywords.fetch(:deadline)), "atNs" => UploadProcessFixture.clock_ns,
          "phase" => phase, "kind" => keywords.fetch(:kind, "fixture-cleanup")}
      end
      value = original.call(*arguments, **keywords, &block)
      if @proving_physical && target
        @physical_deaths << {"pid" => pid, "group" => group, "atNs" => UploadProcessFixture.clock_ns,
          "deadlineNs" => deadline_ns(keywords.fetch(:deadline)), "actualReadOnlyDeathReturned" => true}
      end
      value
    end

    def begin_case(name, tokens:, persistent: false)
      UploadProcessFixture.assert_domain_reusable!
      @name, @tokens, @persistent = name, tokens, persistent
      @samples, @last_samples, @dead_calls, @physical_deaths, @physical_states = [], [], [], [], []
      @counts = Hash.new(0)
      @token_counts = Hash.new { |hash, key| hash[key] = Hash.new(0) }
      @sequences = Hash.new { |hash, key| hash[key] = [] }
      @observation_count = @after_unknown_observations = 0
      @within_budget = true
      @death_deadline_ns = @first_observation_error = @final_owner = @final_result = nil
      @physical_complete = @proving_physical = @unexpected_native_after_unknown = false
    end

    def native_death(original, arguments, keywords, block)
      owner = arguments.first
      cutoff = deadline_ns(keywords.fetch(:deadline))
      @death_deadline_ns ||= cutoff
      unless owner.equal?(@final_owner) && @final_result && cutoff == @death_deadline_ns &&
             cutoff <= @deadline_ns
        raise Failure.new("observation-probe", "role observation lacks original native finality/cutoff")
      end
      unless @physical_complete
        candidates = @command.owners.select do |child|
          request = child.provenance["requested"]
          request && request["argv"][2] == "driver" &&
            request["environment"].values_at("TMPDIR", "TMP", "TEMP").all? { |path| path.start_with?(@case_root + "/") }
        end
        raise Failure.new("observation-probe", "original driver identity is not unique") unless candidates.length == 1
        @direct_driver = @command.child_record(candidates.first)
        unless @direct_driver["finality"] == "finalized" && @direct_driver["originalWaitObserved"] &&
               @direct_driver["creatorJoinObserved"] && @direct_driver["actualStreamEOFs"] &&
               @direct_driver["actualNativeCloses"]
          raise Failure.new("observation-probe", "synthetic observation preceded original driver custody")
        end
        processes = UploadProcessFixture.owner_processes!(owner)
        unless processes.map { |item| item["role"] }.sort == %w[custodian descendant keeper validator]
          raise Failure.new("observation-probe", "inherited role identities were not C/K/V/descendant")
        end
        @identities = processes.map { |item| item.values_at("pid", "group") }
        @proving_physical = true
        actual = original.call(*arguments, **keywords, &block)
        @proving_physical = false
        unless actual.equal?(true) && @physical_deaths.length == 4 &&
               @physical_deaths.map { |item| item.values_at("pid", "group") } == @identities &&
               UploadProcessFixture.clock_ns < cutoff
          raise Failure.new("observation-probe", "independent actual role death was not proved before uncertainty")
        end
        @physical_complete = true
      end
      @synthetic = true
      original.call(*arguments, **keywords, &block)
    rescue Exception => error
      if @persistent && @physical_complete && error.is_a?(Failure) && error.kind == "fixture-cleanup"
        @first_observation_error ||= error
        @retained = true
        UploadProcessFixture.retain_unknown_domain!(@case_root, expected: true)
        UploadProcessFixture.retain_process_case!(self)
      end
      raise
    ensure
      @synthetic = @proving_physical = false
    end

    def record(failures, extra = {})
      trace = {"sampleColumns" => %w[pid group token seconds atNs phase],
        "samples" => @samples + @last_samples, "actualObservationCount" => @observation_count,
        "omittedObservationCount" => @observation_count - @samples.length - @last_samples.length,
        "deadCalls" => @dead_calls, "physicalDeathBeforeUncertainty" => @physical_deaths,
        "physicalStatesBeforeUncertainty" => @physical_states,
        "originalDriverBeforeUncertainty" => @direct_driver,
        "originalNativeBeforeUncertainty" => @final_result && @final_result["nativeObservation"]}
      path = File.join(@directory, "#{@name}-observations.json") # Original bounded reporting scope.
      raise Failure.new("observation-probe", "observation diagnostic exceeded original bound") if JSON.generate(trace).bytesize > OUTPUT_LIMIT
      UploadProcessFixture.atomic_json(path, trace)
      value = {"case" => @name, "platform" => @input.fetch("platform"), "failures" => failures,
        "observationCount" => @observation_count, "deadCalls" => @dead_calls,
        "tokenCounts" => @token_counts.map { |identity, counts| {"identity" => identity, "counts" => counts} },
        "withinOriginalBudget" => @within_budget, "observationTraceSha256" => Digest::SHA256.file(path).hexdigest}.merge(extra)
      @records << value
      UploadProcessFixture.atomic_json(File.join(@directory, "observation-progress.json"), @records)
      unless failures.empty?
        UploadProcessFixture.mark_process_domain_failed!(owner: self)
        raise Failure.new("observation-probe", JSON.generate(value))
      end
      value
    end

    def readiness
      tokens = %w[? ?E ?Es H HE X SE S Z absent]
      begin_case("readiness", tokens: tokens)
      @identities, @synthetic = [[123, 122]], true
      values = tokens.map do
        begin
          UploadProcessFixture.ready?(123, 122)
        rescue Failure => error
          error.kind
        end
      end
      @synthetic = false
      expected = [false] * 7 + [true, "readiness", "readiness"]
      failures = values == expected ? [] : ["indeterminate/stopped observation authorized readiness"]
      record(failures, "readinessResults" => values)
    ensure
      @synthetic = false
    end

    def sequence
      begin_case("sequence", tokens: %w[?E S Z])
      @identities, @synthetic = [[123, 122]], true
      @death_deadline_ns = [UploadProcessFixture.clock_ns + CLEANUP_LIMIT * 1_000_000_000, @deadline_ns].min
      UploadProcessFixture.dead!(123, 122, deadline: Rational(@death_deadline_ns, 1_000_000_000))
      @synthetic = false
      failures = @sequences.fetch([123, 122]) == %w[?E S Z] ? [] : ["cleanup accepted before definite Z"]
      record(failures, "onlyDefiniteStoppedAccepted" => failures.empty?)
    ensure
      @synthetic = false
    end

    def native(persistent:)
      begin_case(persistent ? "persistent-native" : "transient-native", tokens: %w[?E S Z], persistent: persistent)
      @case_root = File.realpath(Dir.mktmpdir("observation-native-", @directory))
      environment = %w[TMPDIR TMP TEMP].to_h { |key| [key, ENV[key]] }
      %w[TMPDIR TMP TEMP].each { |key| ENV[key] = @case_root }
      @command = CommandObservation.new
      @identities, @direct_driver = [], nil
      error = value = nil
      @active_native = true
      begin
        @command.observe do
          value = UploadProcessFixture.run(platform: @input.fetch("platform"), root: @case_root,
            parameters: @input.fetch("parameters"), mode: "inherited", deadline_ns: @deadline_ns)
        end
      rescue Exception => failure
        error = failure
      ensure
        @active_native = @synthetic = false
      end
      commands = @command.snapshot
      failures = []
      failures << "original command custody did not finalize" unless commands["settled"] && !commands["unknown"]
      failures << "physical native/driver proof did not precede substitution" unless @physical_complete && @physical_deaths.length == 4
      failures << "native death calls did not share one original cutoff" unless @dead_calls.map { |call| call["deadlineNs"] }.uniq == [@death_deadline_ns]
      failures << "observation budget exceeded original cutoff" unless @within_budget
      failures << "fresh observation after retained failure" unless @after_unknown_observations.zero? && !@unexpected_native_after_unknown
      phases = @dead_calls.map { |call| call["phase"] }
      if persistent
        failures << "persistent original error/root was not retained" unless error.equal?(@first_observation_error) &&
          error.is_a?(Failure) && error.kind == "fixture-cleanup" && value.nil? &&
          UploadProcessFixture.expected_unknown_retention?(@case_root)
        failures << "active/ensure did not share the exhausted cutoff" unless phases == %w[active cleanup] &&
          @dead_calls.last["atNs"] >= @death_deadline_ns
        failures << "persistent uncertainty was not actually repeated" unless @observation_count > 1 &&
          @token_counts.values.all? { |counts| counts.keys == ["?E"] }
      else
        failures << "transient observation broke genuine native finality" unless error.nil? && value &&
          value["kind"] == "pass" && value["nativeFinality"] == "finalized" && value["knownProcessesDead"]
        failures << "not all four native identities reached definite Z" unless phases == ["active"] * 4 &&
          @sequences.length == 4 && @sequences.values.all? { |tokens| tokens == %w[?E S Z] }
        failures << "transient case retained an unresolved root" if UploadProcessFixture.cleanup_unresolved?(@case_root)
      end
      record(failures, "originalErrorKind" => error.is_a?(Failure) ? error.kind : nil,
        "originalObservationErrorPreserved" => persistent && error.equal?(@first_observation_error),
        "originalNativeFinalityBeforeUncertainty" => @final_result && @final_result["nativeObservation"]["finalized"],
        "originalDriverWaitBeforeUncertainty" => @direct_driver && @direct_driver["originalWaitObserved"],
        "independentRealDeathProofBeforeUncertainty" => @physical_complete, "knownNativeIdentities" => @identities,
        "retainedFixture" => persistent, "domainDisposalRequired" => persistent,
        "nativeFinality" => persistent ? "unknown" : "finalized", "newObserversAfterUncertainty" => @after_unknown_observations)
      UploadProcessFixture.remove_fixture_directory(@case_root, root: @directory, layout: :joined_case) unless persistent
    ensure
      @active_native = @synthetic = false
      environment&.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    end

    def execute
      begin
        install
        readiness
        sequence
        native(persistent: false)
        native(persistent: true) # Deliberate retained uncertainty is always LAST.
      ensure
        @active_native = @synthetic = false
        @hook_errors = @hooks ? @hooks.restore : ["observation_hooks_unpublished"]
      end
      unless @hook_errors.empty? && @retained && UploadProcessFixture.domain_disposal_required?
        UploadProcessFixture.mark_process_domain_failed!(owner: self)
        raise Failure.new("observation-probe", "observation scope was not restored/retained")
      end
      {"kind" => "pass", "cases" => @records, "hooksRestored" => true,
       "retainedFixture" => true, "domainDisposalRequired" => true, "nativeFinality" => "unknown"}
    end
  end

  def self.run_ownership_probe(platform:, root:, parameters:, mode:, deadline_ns: nil)
    assert_domain_reusable!
    validate_request!(platform, mode, parameters)
    unless mode.start_with?("ownership-") && (deadline_ns.nil? || deadline_ns.instance_of?(Integer) && deadline_ns > clock_ns)
      raise Failure.new("fixture-input", "invalid original ownership probe request")
    end
    run_ns = [clock_ns + OWNERSHIP_LIMIT * 1_000_000_000, deadline_ns].compact.min
    expected_unknown = OWNERSHIP_UNKNOWN_MODES.key?(mode) || mode == "ownership-observation"
    accepted = lifetime(deadline_ns: run_ns) do |scope|
      directory = observation = result = nil
      complete = accepted_result = false
      record = {"directoryState" => :unattempted, "captureAttempted" => false}
      (@probe_records ||= {})[record.object_id] = record
      begin
        record["directoryState"] = :acquiring
        Thread.handle_interrupt(Exception => :never) do
          directory = Dir.mktmpdir("ownership-probe-", root)
          record["directory"], record["directoryState"] = directory, :published
          directory = File.realpath(directory)
          record["directoryIdentity"] = OwnedChild.identity(owned_fixture_directory(directory))
          record["directoryState"] = :canonical
        end
        atomic_json(File.join(directory, "input.json"),
          {"platform" => platform, "parameters" => parameters, "mode" => mode, "deadlineNs" => run_ns})
        observation = CommandObservation.new
        record["observation"] = observation
        scope.active do
          argv = [File.realpath(RbConfig.ruby), File.realpath(File.join(__dir__, "upload_process_fixture.rb")),
            "ownership", directory, mode]
          environment = driver_environment(directory)
          request = {"version" => 1, "argv" => argv, "environment" => environment, "cwd" => Dir.pwd,
            "fixtureSha256" => Digest::SHA256.file(argv[1]).hexdigest, "deadlineNs" => run_ns}
          remaining = Rational(run_ns - clock_ns, 1_000_000_000)
          raise Failure.new("ownership-probe", "original probe cutoff expired before capture") unless remaining.positive?
          record["captureAttempted"] = true
          output, errors, status = observation.observe do
            capture_command(argv, seconds: remaining, environment: environment, root: directory,
              deadline: Rational(run_ns, 1_000_000_000))
          end
          snapshot = observation.snapshot
          child = snapshot["children"].one? && snapshot["children"].first
          complete = snapshot["settled"] && child && child["finality"] == "finalized" &&
            child["originalWaitObserved"] && child["creatorJoinObserved"] && child["actualStreamEOFs"] &&
            child["actualNativeCloses"] && snapshot["actualOwnedControlCloses"] && snapshot["actualTaskJoins"]
          raise Failure.new("ownership-probe", "original probe driver custody did not finalize") unless complete
          unless child["provenance"]["requested"] == {"executable" => argv.first, "argv" => argv,
            "environment" => environment, "cwd" => request["cwd"]}
            raise Failure.new("ownership-probe", "probe driver request changed")
          end
          dispatch = JSON.parse(OwnedChild.bounded_file(File.join(directory, "ownership-dispatch.json")))
          raise Failure.new("ownership-probe", "probe dispatch was not the original CLI") unless dispatch == request.merge("pid" => child["pid"])
          raise Failure.new("ownership-probe", "probe failed with original exit #{status}") unless status == 0
          result = JSON.parse(output)
          unless result.is_a?(Hash) && result["kind"] == "pass" && result["cases"].is_a?(Array) &&
                 result["cases"].all? { |entry| entry.is_a?(Hash) && entry["failures"] == [] }
            raise Failure.new("ownership-probe", "incomplete ownership proof")
          end
          cases = result.fetch("cases")
          if OWNERSHIP_UNKNOWN_MODES.key?(mode)
            helper, name = OWNERSHIP_UNKNOWN_MODES.fetch(mode)
            unless cases.length == 1 && cases.first.values_at("helper", "case") == [helper, name] &&
                   cases.first.values_at("unknownPublication", "retainedFixture", "domainDisposalRequired").all? { |value| value.equal?(true) }
              raise Failure.new("ownership-probe", "UNKNOWN singleton selected another row")
            end
          elsif mode == "ownership-observation"
            unless cases.map { |entry| entry["case"] } == %w[readiness sequence transient-native persistent-native] &&
                   cases.last["retainedFixture"] && cases.last["nativeFinality"] == "unknown"
              raise Failure.new("ownership-probe", "observation singleton lost its final retained row")
            end
          elsif mode == "ownership-setup"
            expected = %w[capture run ownership].product(%w[IOError Interrupt], [false, true])
            unless cases.map { |entry| entry.values_at("helper", "setupClass", "repeatedCancellation") } == expected &&
                   cases.all? { |entry| entry["noNativeCreateEntered"] && entry["actualOwnedCloses"] && entry["raiserJoined"] }
              raise Failure.new("ownership-probe", "setup did not prove no native attempt plus original closes/joins")
            end
          else
            family = mode.delete_prefix("ownership-")
            expected = %w[capture run].product(OwnershipProbe::CASES.fetch(family))
            unless cases.map { |entry| entry.values_at("helper", "case") } == expected &&
                   cases.all? { |entry| entry["allKnownCommandChildrenFinalized"] && !entry["retainedFixture"] && !entry["domainDisposalRequired"] }
              raise Failure.new("ownership-probe", "healthy ownership rows lack original finality")
            end
          end
          if expected_unknown
            unless result.values_at("retainedFixture", "domainDisposalRequired").all? { |value| value.equal?(true) } &&
                   result["nativeFinality"] == "unknown" && !result.key?("knownProcessesDead") && !result.key?("allAcquiredChildrenJoined")
              raise Failure.new("ownership-probe", "UNKNOWN was incorrectly promoted to complete")
            end
            retain_unknown_domain!(root, expected: true)
          else
            raise Failure.new("ownership-probe", "healthy probe retained an unsafe domain") if result["retainedFixture"] || result["domainDisposalRequired"]
          end
          accepted_result = true
          value = result.merge("driverJoined" => complete, "probeDriverObservation" => snapshot,
            "probeDispatch" => dispatch, "probeDiagnosticBytes" => errors.bytesize,
            "retainedFixture" => expected_unknown, "domainDisposalRequired" => expected_unknown)
          value["knownProcessesDead"] = true unless expected_unknown # Every exact row was independently required above.
          value
        end
      rescue Exception => error
        scope.remember(error)
        raise
      ensure
        scope.cleanup do
          if directory && accepted_result && complete && !expected_unknown
            unless OwnedChild.identity(owned_fixture_directory(directory)) == record["directoryIdentity"]
              raise Failure.new("fixture-cleanup", "original probe directory identity changed")
            end
            remove_fixture_directory(directory, root: root, layout: :probe)
            @probe_records.delete(record.object_id)
          elsif directory
            (@unresolved_roots ||= {})[root] = true
            retain_unknown_domain!(root, expected: accepted_result && expected_unknown) if record["captureAttempted"] ||
              record["directoryState"] != :canonical
            warn "Preserve ownership probe failure: #{directory}" unless accepted_result && expected_unknown
          elsif record["directoryState"] == :unattempted
            @probe_records.delete(record.object_id)
          else
            retain_unknown_domain!(root)
            warn "Preserve ownership probe failure: unpublished original directory"
          end
        end
      end
    end
    raise Failure.new("ownership-probe", "probe result arrived after original family cutoff") unless clock_ns < run_ns
    accepted
  end
end
