# frozen_string_literal: true

# Test-only ownership, shared by the process fixture and its observation commands.
# Default Ruby SIGINT can bypass Thread.handle_interrupt. Queue it through
# Thread#raise instead of raising synchronously from a trap; restore INT last.
module UploadProcessFixture
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

    def initialize(scope)
      @scope = scope
      @primary = nil
      @cleanup_errors = []
    end

    def remember(error)
      @primary ||= error
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
      deadline = UploadProcessFixture.clock + CLEANUP_LIMIT
      while Thread.current.pending_interrupt?
        raise Failure.new("signal-policy", "fixture cancellation queue did not quiesce after cleanup") if UploadProcessFixture.clock >= deadline
        begin
          Thread.handle_interrupt(Exception => :immediate) {}
        rescue Exception => error
          remember(error)
        end
      end
    end
  end

  class OwnedChild
    attr_reader :pid, :status, :phase

    def initialize
      @pid = @status = nil
      @phase = :unstarted
    end

    def start(*arguments, **options)
      Thread.handle_interrupt(Exception => :never) do
        raise Failure.new("process-ownership", "child acquisition was already attempted") unless @phase == :unstarted
        @phase = :acquiring
        begin
          @pid = Process.spawn(*arguments, **options)
          @phase = :live
        rescue Exception
          @phase = :unknown # A missing published PID is not proof of no acquisition.
          raise
        end
      end
      @pid
    end

    def poll
      Thread.handle_interrupt(Exception => :never) do
        return @status if @phase == :reaped
        return nil if @phase == :unstarted
        raise Failure.new("process-ownership", "child wait authority is unknown") unless @phase == :live
        begin
          waited = Process.waitpid2(@pid, Process::WNOHANG)
          if waited
            @status = waited.last
            @phase = :reaped
          end
        rescue Exception
          @phase = :unknown # In particular ECHILD must never authorize a signal.
          raise
        end
        @status
      end
    end

    def signal(signal, group: true)
      Thread.handle_interrupt(Exception => :never) do
        return false if poll || @phase == :unstarted
        raise Failure.new("process-ownership", "child signal authority is unknown") unless @phase == :live
        begin
          Process.kill(signal, group ? -@pid : @pid)
          true
        rescue Errno::ESRCH
          false # Still reap the reserved direct child; never retry a stale PID.
        end
      end
    end

    def stop
      Thread.handle_interrupt(Exception => :never) do
        return if @phase == :unstarted || poll
        signal("KILL")
        UploadProcessFixture.wait_until(CLEANUP_LIMIT, "process-cleanup") { poll }
      end
    end

    def complete?
      %i[unstarted reaped].include?(@phase)
    end
  end

  def self.lifetime
    raise Failure.new("signal-policy", "process fixtures must run on the main Ruby thread") unless Thread.current.equal?(Thread.main)
    outer = @cancellation_scope.nil?
    scope = @cancellation_scope || CancellationScope.new
    frame = Lifetime.new(scope) # First error survives the entire outer mask/trap exit.
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

  # Runs only in a static, isolated Ruby probe process. Every wrapper forwards
  # the real syscall. A post-reap request is recorded and vetoed BEFORE signalling;
  # that veto makes the regression fail, never manufactures a containment pass.
  class OwnershipProbe
    class << self
      attr_accessor :current
    end

    CASES = {
      "async" => %w[async-spawn async-reap cleanup-first-async repeated],
      "signals" => %w[INT-spawn TERM-spawn INT-reap TERM-reap
                       cleanup-first-INT cleanup-first-TERM
                       install-before-INT install-before-TERM install-buffered-INT install-buffered-TERM
                       install-published-INT install-published-TERM
                       restore-before-INT restore-before-TERM restore-after-INT restore-after-TERM],
      "policies" => %w[normal ignored-INT ignored-TERM custom-INT custom-TERM custom-pending-INT
                        partial-install changed-handler finalize-report finalize-drain],
      "unknown" => %w[unknown-spawn unknown-reap unknown-echild],
    }.freeze

    attr_reader :records

    def initialize(directory, family)
      @directory = directory
      @input = UploadProcessFixture.read_json(File.join(directory, "input.json"))
      @family = family
      @records = []
      @reservations = {}
      @active = false
    end

    def self.instrument
      Process.singleton_class.prepend(Module.new do
        def spawn(*arguments, **options)
          value = super
          OwnershipProbe.current&.spawned(value, arguments)
          value
        end

        def waitpid2(*arguments)
          value = super
          OwnershipProbe.current&.waited(arguments.first, value)
          value
        end

        def kill(signal, *targets)
          probe = OwnershipProbe.current
          return 0 if probe&.veto_signal?(signal, targets)
          super
        end
      end)
      OwnedChild.prepend(Module.new do
        def start(*arguments, **options)
          OwnershipProbe.current&.starting(self, arguments)
          super
        end

        def stop
          OwnershipProbe.current&.before_stop(self)
          super
        ensure
          OwnershipProbe.current&.after_stop(self)
        end
      end)
      Signal.singleton_class.prepend(Module.new do
        def trap(name, *arguments, &block)
          probe = OwnershipProbe.current
          probe&.before_trap(name)
          value = super
          probe&.after_trap(name)
          value
        end
      end)
      Lifetime.prepend(Module.new do
        def report
          OwnershipProbe.current&.before_finalize("report")
          super
        end

        def drain_pending
          OwnershipProbe.current&.before_finalize("drain")
          super
        end
      end)
    end

    def starting(owner, arguments)
      return unless @active && !@owner
      argv = arguments.drop(1)
      match = @helper == "capture" ? argv[1] == "-e" : argv[2] == "driver"
      @owner = owner if match
    end

    def event(name, extra = {})
      @events << {"boundary" => name, "ownerPhase" => @owner&.phase&.to_s}.merge(extra)
    end

    def progress
      UploadProcessFixture.atomic_json(File.join(@directory, "progress.json"),
                                       {"family" => @family, "helper" => @helper, "case" => @case,
                                        "reservations" => @reservations, "events" => @events,
                                        "vetoes" => @vetoes, "completedCases" => @records.length})
    end

    def cancel(kind, object = nil)
      if kind == "async"
        target = Thread.current
        error = object || Interrupt.new("first asynchronous fixture cancellation")
        @first ||= error
        @first_message ||= error.message.dup
        raiser = Thread.new { target.raise(error) }
        @raisers << raiser
        begin
          raise "cancellation injector did not finish" unless raiser.join(2)
        ensure
          raise "cancellation injector did not join" unless raiser.join(2)
        end
      else
        Process.kill(kind, Process.pid) # Only this isolated probe's own process.
      end
    end

    def spawned(pid, arguments)
      @reservations[pid] = {"reaped" => false}
      progress
      return unless @active
      argv = arguments.drop(1)
      target = @owner && !@target_pid && (@helper == "capture" ? argv[1] == "-e" : argv[2] == "driver")
      if target
        @target_pid = pid
        if @helper == "run"
          # Before withholding publication/cancelling, obtain actual native
          # phase evidence. The recorded PID still NEVER authorizes a signal.
          native_directory = argv.fetch(3)
          UploadProcessFixture.wait_until(READINESS_LIMIT, "probe-readiness") do
            File.file?(File.join(native_directory, "owner.json"))
          end
        end
        if @case.end_with?("-spawn")
          event("spawn-return-before-publication", "actualPid" => pid)
          if @case == "unknown-spawn"
            @first = Interrupt.new("synchronous unknown spawn handoff")
            @first_message = @first.message.dup
            raise @first
          end
          cancel(@case.split("-").first)
        elsif @case.start_with?("ignored-")
          cancel(@case.split("-").last)
        elsif @case == "changed-handler"
          Signal.trap("INT", @foreign)
        end
      elsif @case == "repeated" && !@nested_cancelled && @stop_entered &&
            argv.first == UploadProcessFixture.observation_executable
        @nested_cancelled = true
        scope = UploadProcessFixture.instance_variable_get(:@cancellation_scope)
        event("nested-cleanup-observation", "cleanupDepth" => scope.cleanup_depth)
        cancel("INT")
      end
    end

    def waited(pid, value)
      @reservations.fetch(pid)["reaped"] = true if value && @reservations.key?(pid)
      progress if value
      return unless @active && pid == @target_pid
      if value && %w[async-reap INT-reap TERM-reap unknown-reap unknown-echild].include?(@case) && !@injected
        @injected = true
        event("waitpid-return-before-publication", "actualPid" => pid, "actualStatus" => value.last.to_s)
        if @case.start_with?("unknown-")
          @first = @case == "unknown-echild" ? Errno::ECHILD.new("synthetic lost reap observation") : Interrupt.new("synchronous unknown reap handoff")
          @first_message = @first.message.dup
          raise @first
        end
        cancel(@case.split("-").first)
      elsif @case == "repeated" && !@injected
        @injected = true
        event("first-active-cancellation", "stillUnreaped" => value.nil?)
        cancel("async")
      end
    end

    def veto_signal?(signal, targets)
      unsafe = targets.any? do |pid|
        @reservations[pid.abs]&.fetch("reaped") ||
          (@active && @owner&.phase == :unknown && pid.abs == @target_pid)
      end
      if unsafe && signal != 0
        @vetoes << {"signal" => signal, "targets" => targets}
        true
      else
        false
      end
    end

    def before_stop(owner)
      return unless @active && owner.equal?(@owner) && !@stop_entered
      @stop_entered = true
      if @case.start_with?("cleanup-first-")
        event("first-cleanup-entry")
        cancel(@case.delete_prefix("cleanup-first-"))
      elsif @case == "repeated"
        event("repeat-cleanup-entry")
        cancel("async", Interrupt.new("repeat must not replace first cancellation"))
      end
    end

    def after_stop(owner)
      @stop_completed = true if @active && owner.equal?(@owner) && owner.complete?
    end

    def before_trap(name)
      return unless @active
      name = name.to_s.delete_prefix("SIG")
      @trap_calls[name] += 1
      if @case == "partial-install" && name == "TERM" && @trap_calls[name] == 1
        @first = Failure.new("signal-policy", "synthetic second trap installation failure")
        @first_message = @first.message.dup
        raise @first
      end
      if @case == "install-before-#{name}" && @trap_calls[name] == 1
        event("before-trap-install", "signal" => name)
        cancel(name)
      elsif @case == "restore-before-#{name}" && @trap_calls[name] == 3
        event("before-original-trap-restoration", "signal" => name)
        cancel(name)
      end
    end

    def before_finalize(kind)
      return unless @active && @case == "finalize-#{kind}" && !@injected
      @injected = true
      event("finalization-#{kind}-failure")
      @first = Failure.new("signal-policy", "synthetic #{kind} failure must not skip handler restoration")
      @first_message = @first.message.dup
      raise @first
    end

    def after_trap(name)
      return unless @active
      name = name.to_s.delete_prefix("SIG")
      if @trap_calls[name] == 1 && ["install-buffered-#{name}", "ignored-#{name}", "custom-pending-#{name}"].include?(@case)
        event("trap-installed-before-policy-publication", "signal" => name)
        cancel(name)
      elsif @case == "restore-after-#{name}" && @trap_calls[name] == 3
        event("after-original-trap-restoration", "signal" => name)
        cancel(name)
      end
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
        code = @case == "repeated" || @case.end_with?("-spawn") ? "sleep 30" : "exit 0"
        UploadProcessFixture.capture_command([RbConfig.ruby, "-e", code])
      else
        UploadProcessFixture.run(platform: @input.fetch("platform"), root: @case_root,
                                 parameters: @input.fetch("parameters").transform_keys(&:to_sym), mode: "unready")
      end
    end

    def cleanup_actual_reservations
      # Independent probe fallback for intentionally UNKNOWN publication cases.
      # These handles came directly from our syscall wrappers before fault injection,
      # never from diagnostics/markers. This is not a successful fixture cleanup.
      UploadProcessFixture.lifetime do |frame|
        frame.cleanup do
          @reservations.to_a.each do |pid, record|
            next if record.fetch("reaped")
            @fallback = true
            unless Process.waitpid2(pid, Process::WNOHANG)
              Process.kill("KILL", -pid)
              UploadProcessFixture.wait_until(CLEANUP_LIMIT, "probe-fallback") { Process.waitpid2(pid, Process::WNOHANG) }
            end
          end
        end
      end
      @native_death_deadline ||= UploadProcessFixture.clock + CLEANUP_LIMIT
      Dir.glob(File.join(@case_root, "**", "owner.json")).each do |path|
        value = UploadProcessFixture.read_json(path)
        UploadProcessFixture.dead!(value.fetch("leader"), value.fetch("group"), deadline: @native_death_deadline)
        UploadProcessFixture.dead!(value["child"], value.fetch("group"), deadline: @native_death_deadline) if value["child"]
      end
    end

    def one(helper, name)
      @helper, @case = helper, name
      @owner = @target_pid = @first = @first_message = nil
      @events, @raisers, @vetoes = [], [], []
      @trap_calls = Hash.new(0)
      @injected = @stop_entered = @stop_completed = @nested_cancelled = @fallback = false
      @cleanup_confirmed = false
      @native_death_deadline = nil
      @custom_deliveries = []
      @foreign = proc { |number| @custom_deliveries << number }
      @case_root = File.realpath(Dir.mktmpdir("ownership-#{helper}-", @directory))
      ENV["TMPDIR"] = @case_root
      saved = trap_state
      signal = name.split("-").last
      Signal.trap(signal, "IGNORE") if name.start_with?("ignored-")
      Signal.trap(signal, @foreign) if name.start_with?("custom-")
      expected_traps = trap_state
      expected_traps["INT"] = @foreign if name == "changed-handler"
      published_trace = TracePoint.new(:line) do |point|
        if @active && name.start_with?("install-published-") && point.method_id == :install &&
           point.self.is_a?(CancellationScope) && !@injected && point.self.instance_variable_get(:@policies).key?(Signal.list.fetch(signal))
          @injected = true
          event("after-policy-publication", "signal" => signal)
          cancel(signal)
        end
      end
      error = nil
      @active = true
      published_trace.enable
      begin
        invoke
      rescue Exception => failure
        error = failure
      ensure
        @active = false
        published_trace.disable
        @raisers.each { |raiser| raise "injector not joined" unless raiser.join(2) }
      end
      actual_traps = trap_state
      registry_inactive = UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?
      preserved = Dir.glob(File.join(@case_root, "**", "*"), File::FNM_DOTMATCH).select { |path| File.file?(path) }
      owner_phase, status = @owner&.phase, @owner&.status
      # Restore only this probe's original policies before independent inspection.
      saved.each { |key, handler| Signal.trap(key, handler) }
      cleanup_actual_reservations
      @cleanup_confirmed = true
      failures = []
      failures << "unsafe signal requested" unless @vetoes.empty?
      failures << "handler policy not restored" unless actual_traps == expected_traps
      failures << "scope registry still active" unless registry_inactive
      failures << "unjoined child reservation" unless @reservations.values.all? { |record| record.fetch("reaped") }
      failures << "original error object/message replaced" if @first && (!error.equal?(@first) || error.message != @first_message)
      normal = name == "normal" || name.start_with?("ignored-")
      unknown = name.start_with?("unknown-")
      finalize = name.start_with?("finalize-")
      policy = name.start_with?("custom-") || %w[partial-install changed-handler].include?(name) || finalize
      if normal
        failures << "normal/ignored operation failed" if error || owner_phase != :reaped || !status || @fallback
      elsif policy
        failures << "policy violation did not fail closed" unless error.is_a?(Failure) && error.kind == "signal-policy"
        failures << "unsupported policy reached spawn" if name != "changed-handler" && !finalize && @target_pid
        failures << "custom pending signal lost" if name == "custom-pending-INT" && @custom_deliveries != [Signal.list.fetch("INT")]
        if finalize
          failures << "finalization failure skipped cleanup" unless owner_phase == :reaped && status && @stop_completed && !@fallback && @injected
        end
      else
        failures << "cancellation/unknown fault did not propagate" unless error.is_a?(SignalException) || (name == "unknown-echild" && error.is_a?(Errno::ECHILD))
        failures << "required injection not observed" if @events.empty?
        expected_signal = name.include?("TERM") ? "TERM" : "INT"
        if !unknown && error.is_a?(SignalException)
          failures << "wrong cancellation signal" unless error.signo == Signal.list.fetch(expected_signal)
        end
        if unknown
          failures << "unknown ownership was accepted/removed" unless owner_phase == :unknown && !preserved.empty?
        elsif @target_pid
          failures << "known cancellation did not finish owned cleanup" unless owner_phase == :reaped && status && @stop_completed && !@fallback
        end
        if name == "repeated" && helper == "run"
          failures << "nested cleanup cancellation not exercised" unless @nested_cancelled
        end
      end
      record = {"helper" => helper, "case" => name, "events" => @events,
                "exceptionClass" => error&.class&.name, "exceptionMessage" => error&.message,
                "firstExceptionPreserved" => !@first || error.equal?(@first), "ownerPhase" => owner_phase,
                "signalRequestsAfterReap" => @vetoes, "allAcquiredChildrenJoined" => true,
                "probeFallbackForUnknown" => @fallback, "preservedBeforeFallback" => preserved.length,
                "handlersRestored" => actual_traps == expected_traps, "registryInactive" => registry_inactive,
                "raisersJoined" => @raisers.none?(&:alive?), "raiserCount" => @raisers.length,
                "failures" => failures}
      @records << record
      progress
      FileUtils.remove_entry(@case_root) # All actual reservations/native workers proved stopped.
      raise Failure.new("ownership-probe", JSON.generate(record)) unless failures.empty?
    ensure
      @active = false
      published_trace&.disable
      @raisers&.each { |raiser| raiser.join(2) }
      if saved && !@cleanup_confirmed
        %w[TERM INT].each { |key| Signal.trap(key, saved.fetch(key)) }
        cleanup_actual_reservations
        @cleanup_confirmed = true
        progress
      end
    end

    def execute
      self.class.current = self
      self.class.instrument
      %w[capture run].each do |helper|
        CASES.fetch(@family).each { |name| one(helper, name) }
      end
      {"kind" => "pass", "family" => @family, "cases" => @records}
    ensure
      self.class.current = nil
    end
  end

  # Setup occurs under deferral, BEFORE Lifetime#active. This isolated probe
  # combines its first error with a cleanup fault and real queued cancellation.
  # No native child is needed; an attempted spawn is vetoed and fails the test.
  class SetupFailureProbe
    class << self
      attr_accessor :current
    end

    def initialize(directory)
      @directory = directory
      @input = UploadProcessFixture.read_json(File.join(directory, "input.json"))
      @records = []
    end

    def self.instrument
      File.singleton_class.prepend(Module.new do
        def open(path, *arguments, **options, &block)
          SetupFailureProbe.current&.opening(path)
          super
        end
      end)
      UploadProcessFixture.singleton_class.prepend(Module.new do
        def atomic_json(path, value)
          SetupFailureProbe.current&.writing(path)
          super
        end
      end)
      FileUtils.singleton_class.prepend(Module.new do
        def remove_entry(path, *arguments)
          SetupFailureProbe.current&.removing(path)
          super
        end
      end)
      Kernel.prepend(Module.new do
        def warn(*messages)
          SetupFailureProbe.current&.warning(messages)
          super
        end
      end)
      Process.singleton_class.prepend(Module.new do
        def spawn(*arguments, **options)
          SetupFailureProbe.current&.spawning
          super
        end
      end)
      CancellationScope.prepend(Module.new do
        def queue(number)
          SetupFailureProbe.current&.queued(number)
          super
        end
      end)
    end

    def owned?(path)
      @active && path.to_s.start_with?(@case_root + "/")
    end

    def opening(path)
      setup_fault if @helper == "capture" && owned?(path) && File.basename(path) == "stderr"
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
      if @helper == "ownership" && messages.first.to_s.start_with?("Preserve ownership probe failure:")
        cleanup_fault
      end
    end

    def spawning
      return unless @active
      @spawn_attempts += 1
      raise Failure.new("setup-probe", "unexpected native spawn attempt VETOED")
    end

    def queued(number)
      @signals << number if @active
    end

    def cleanup_fault
      return if @cleanup_hit
      @cleanup_hit = true
      @cleanup_depth = UploadProcessFixture.instance_variable_get(:@cancellation_scope)&.cleanup_depth
      if @repeats
        Process.kill("INT", Process.pid) # Only this isolated probe's own process.
        target = Thread.current
        @raiser = Thread.new do
          target.raise(Interrupt.new("queued repeat after setup and cleanup faults"))
          @repeat_queued = true
        end
        raise "setup probe injector did not join" unless @raiser.join(2)
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
      @helper, @repeats = helper, repeats
      @setup_hit = @cleanup_hit = @cleanup_reported = false
      @cleanup_fault_raised = @repeat_queued = false
      @cleanup_depth = nil
      @spawn_attempts, @signals, @raiser = 0, [], nil
      @case_root = File.realpath(Dir.mktmpdir("setup-#{helper}-", @directory))
      ENV["TMPDIR"] = @case_root
      @first = error_class.new("original synchronous #{helper} setup failure")
      message = @first.message.dup
      @second = IOError.new("distinct cleanup failure must not replace setup")
      before = trap_state
      error = nil
      @active = true
      begin
        if helper == "capture"
          UploadProcessFixture.capture_command([RbConfig.ruby, "-e", "exit 0"])
        else
          mode = helper == "run" ? "unready" : "ownership-async"
          UploadProcessFixture.run(platform: @input.fetch("platform"), root: @case_root,
                                   parameters: @input.fetch("parameters"), mode: mode)
        end
      rescue Exception => failure
        error = failure
      ensure
        @active = false
        raise "setup injector not joined" if @raiser && !@raiser.join(2)
      end
      # Ordinary post-return work also detects a queued exception leaking to the
      # next caller, instead of assuming one rescued Interrupt exhausted a queue.
      preserved = Dir.glob(File.join(@case_root, "*"))
      failures = []
      failures << "required setup/cleanup boundary missing" unless @setup_hit && @cleanup_hit
      failures << "distinct protected cleanup fault missing" unless @cleanup_fault_raised && @cleanup_depth&.positive?
      failures << "first object/message replaced" unless error.equal?(@first) && error.message == message
      failures << "cleanup error not separately reported" unless @cleanup_reported
      failures << "native spawn attempted" unless @spawn_attempts.zero?
      failures << "cleanup failure evidence was removed" if preserved.empty?
      handlers_restored = trap_state == before
      registry_inactive = UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?
      failures << "handlers/registry not restored" unless handlers_restored && registry_inactive
      failures << "pending cancellation leaked" if Thread.current.pending_interrupt?
      failures << "actual cancellation missing" if repeats && (@signals != [Signal.list.fetch("INT")] || !@repeat_queued || !@raiser || @raiser.alive?)
      record = {"helper" => helper, "platform" => @input.fetch("platform"), "setupClass" => error_class.name, "repeatedCancellation" => repeats,
                "setupHit" => @setup_hit, "cleanupHit" => @cleanup_hit, "cleanupErrorReported" => @cleanup_reported,
                "cleanupDepth" => @cleanup_depth, "cleanupFaultRaised" => @cleanup_fault_raised,
                "originalObjectAndMessagePreserved" => error.equal?(@first) && error.message == message,
                "spawnAttempts" => @spawn_attempts, "osSignalsQueued" => @signals,
                "handlersRestored" => handlers_restored, "registryInactive" => registry_inactive,
                "asyncRepeatQueued" => @repeat_queued,
                "raiserJoined" => !@raiser || !@raiser.alive?, "pendingInterrupt" => Thread.current.pending_interrupt?,
                "preservedDirectories" => preserved.length, "failures" => failures}
      @records << record
      UploadProcessFixture.atomic_json(File.join(@directory, "setup-progress.json"), @records)
      # No real native acquisition is possible through this probe's spawn veto.
      FileUtils.remove_entry(@case_root)
      raise Failure.new("setup-probe", JSON.generate(record)) unless failures.empty?
    end

    def execute
      self.class.current = self
      self.class.instrument
      %w[capture run ownership].product([IOError, Interrupt], [false, true]).each { |arguments| one(*arguments) }
      {"kind" => "pass", "cases" => @records}
    ensure
      @active = false
      @raiser&.join(2)
      self.class.current = nil
    end
  end

  # Only the parent's read-only observations are substituted. The full adapter,
  # native capture, driver/worker acquisition, signals and wait/reap stay real in
  # their fresh Ruby processes. Restored observations independently prove death
  # before this probe removes its own completed scratch.
  class ObservationProbe
    class << self
      attr_accessor :current
    end

    def initialize(directory)
      @directory = directory
      @input = UploadProcessFixture.read_json(File.join(directory, "input.json"))
      @records = []
      @active = false
    end

    def self.instrument
      UploadProcessFixture.singleton_class.prepend(Module.new do
        def state(pid, group, seconds: 2)
          probe = ObservationProbe.current
          return probe.observe(pid, group, seconds) if probe&.active?
          super
        end

        def dead!(pid, group, deadline: UploadProcessFixture.clock + CLEANUP_LIMIT, kind: "fixture-cleanup")
          probe = ObservationProbe.current
          probe&.before_dead(pid, group, deadline, kind)
          super
        end
      end)
    end

    def active?
      @active
    end

    def phase
      scope = UploadProcessFixture.instance_variable_get(:@cancellation_scope)
      scope && scope.cleanup_depth.positive? ? "cleanup" : "active"
    end

    def before_dead(pid, group, deadline, kind)
      return unless @active
      @dead_calls << {"pid" => pid, "group" => group, "deadline" => deadline, "kind" => kind,
                      "at" => UploadProcessFixture.clock, "phase" => phase}
    end

    def observe(pid, group, seconds)
      index = @counts[[pid, group]]
      token = @persistent ? "?E" : @tokens.fetch(index)
      @counts[[pid, group]] += 1
      @observations << {"pid" => pid, "group" => group, "token" => token, "seconds" => seconds,
                         "at" => UploadProcessFixture.clock, "phase" => phase}
      stdout, status = token == "absent" ? ["", 1] : ["#{pid} #{group} #{token}\n", 0]
      UploadProcessFixture.liveness(UploadProcessFixture.parse_state(stdout, "", status, pid, group))
    end

    def begin_case(name, tokens:, persistent: false)
      @name, @tokens, @persistent = name, tokens, persistent
      @observations, @dead_calls = [], []
      @counts = Hash.new(0)
      @active = true
    end

    def record(failures, extra = {})
      # Keep the complete timed trace on failure, without overflowing the bounded
      # parent result channel on the persistent five-second negative case.
      trace = File.join(@directory, "#{@name}-observations.json")
      UploadProcessFixture.atomic_json(trace, {"observations" => @observations, "deadCalls" => @dead_calls})
      value = {"case" => @name, "platform" => @input.fetch("platform"), "failures" => failures,
               "observationCount" => @observations.length, "deadCalls" => @dead_calls,
               "observationTraceSha256" => Digest::SHA256.file(trace).hexdigest}.merge(extra)
      @records << value
      UploadProcessFixture.atomic_json(File.join(@directory, "observation-progress.json"), @records)
      raise Failure.new("observation-probe", JSON.generate(value)) unless failures.empty?
    end

    def readiness
      tokens = %w[? ?E ?Es H HE X SE S Z absent]
      begin_case("readiness", tokens: tokens)
      values = tokens.map do
        begin
          UploadProcessFixture.ready?(123, 122)
        rescue Failure => error
          error.kind
        end
      end
      @active = false
      expected = [false] * 7 + [true, "readiness", "readiness"]
      failures = values == expected ? [] : ["indeterminate/stopped observation authorized readiness"]
      record(failures, "readinessResults" => values)
    ensure
      @active = false
    end

    def sequence
      begin_case("sequence", tokens: %w[?E S Z])
      deadline = UploadProcessFixture.clock + CLEANUP_LIMIT
      UploadProcessFixture.dead!(123, 122, deadline: deadline)
      @active = false
      failures = @observations.map { |value| value.fetch("token") } == %w[?E S Z] ? [] : ["cleanup accepted before definite Z"]
      record(failures, "onlyDefiniteStoppedAccepted" => failures.empty?)
    ensure
      @active = false
    end

    def native(persistent:)
      root = File.realpath(Dir.mktmpdir("observation-native-", @directory))
      ENV["TMPDIR"] = root
      begin_case(persistent ? "persistent-native" : "transient-native", tokens: %w[?E S Z], persistent: persistent)
      error = value = nil
      begin
        value = UploadProcessFixture.run(platform: @input.fetch("platform"), root: root,
                                         parameters: @input.fetch("parameters").transform_keys(&:to_sym), mode: "inherited")
      rescue Exception => failure
        error = failure
      ensure
        @active = false
      end
      # Observe preservation BEFORE independent real observations or deletion.
      preserved = Dir.glob(File.join(root, "native-process-*"))
      unresolved = UploadProcessFixture.cleanup_unresolved?(root)
      failures = []
      deadlines = @dead_calls.map { |call| call.fetch("deadline") }.uniq
      failures << "native death calls did not share one absolute cutoff" unless deadlines.length == 1
      phases = @dead_calls.map { |call| call.fetch("phase") }
      if persistent
        failures << "persistent uncertainty did not fail/preserve" unless error.is_a?(Failure) && error.kind == "fixture-cleanup" && value.nil? && unresolved && preserved.length == 1
        failures << "active/ensure paths were not both reached" unless phases == %w[active cleanup]
        failures << "cleanup renewed an exhausted observation budget" unless @observations.none? { |entry| entry.fetch("phase") == "cleanup" } &&
                                                                             @dead_calls.last && @dead_calls.last.fetch("at") >= @dead_calls.last.fetch("deadline")
        failures << "persistent case had no actual repeated observations" unless @observations.length > 1 && @observations.all? { |entry| entry.fetch("token") == "?E" }
      else
        failures << "transient observations broke a real inherited-pipe control" unless error.nil? && value && value["kind"] == "pass" && value["deadBeforeFallback"] && value["knownProcessesDead"]
        sequences = @observations.group_by { |entry| [entry.fetch("pid"), entry.fetch("group")] }.values
        failures << "both native identities were not observed through definite Z" unless phases == %w[active active] && sequences.length == 2 && sequences.all? { |entries| entries.map { |entry| entry.fetch("token") } == %w[?E S Z] }
        failures << "successful transient fixture retained unresolved state" unless preserved.empty? && !unresolved
      end
      failures << "observation budget exceeded the remaining cutoff" unless @observations.all? do |entry|
        entry.fetch("seconds").positive? && entry.fetch("seconds") <= 2 &&
          deadlines.length == 1 && entry.fetch("at") + entry.fetch("seconds") <= deadlines.first + 0.05
      end
      # Marker/observation PIDs carry NO signal authority. The real driver already
      # joined; collect all its known native identities for read-only observation.
      identities = @dead_calls.map { |call| [call.fetch("pid"), call.fetch("group")] }
      preserved.each do |directory|
        owner = UploadProcessFixture.read_json(File.join(directory, "owner.json"))
        identities << [owner.fetch("leader"), owner.fetch("group")]
        identities << [owner["child"], owner.fetch("group")] if owner["child"]
      end
      identities.uniq!
      raise Failure.new("observation-probe", "cannot prove native cleanup without identities; preserve #{root}") unless identities.length == 2
      independent_deadline = UploadProcessFixture.clock + CLEANUP_LIMIT
      identities.each { |pid, group| UploadProcessFixture.dead!(pid, group, deadline: independent_deadline) }
      record(failures, "originalErrorKind" => error.is_a?(Failure) ? error.kind : nil,
             "preservedBeforeIndependentProof" => preserved.length, "registryUnresolvedBeforeProof" => unresolved,
             "knownNativeIdentities" => identities, "independentRealDeathProof" => true)
      FileUtils.remove_entry(root) # Only after real, restored observations proved both identities stopped.
    ensure
      @active = false
    end

    def execute
      self.class.current = self
      self.class.instrument
      readiness
      sequence
      native(persistent: false)
      native(persistent: true)
      {"kind" => "pass", "cases" => @records}
    ensure
      @active = false
      self.class.current = nil
    end
  end

  def self.run_ownership_probe(platform:, root:, parameters:, mode:)
    lifetime do |scope|
      directory = nil
      complete = false
      begin
        directory = File.realpath(Dir.mktmpdir("ownership-probe-", root))
        atomic_json(File.join(directory, "input.json"), {"platform" => platform, "parameters" => parameters})
        scope.active do
          output, errors, status = capture_command([RbConfig.ruby, File.realpath(File.join(__dir__, "upload_process_fixture.rb")),
                                                   "ownership", directory, mode.delete_prefix("ownership-")], seconds: 60)
          raise Failure.new("ownership-probe", "probe failed: #{output}\n#{errors}") unless status == 0
          result = JSON.parse(output)
          raise Failure.new("ownership-probe", "incomplete ownership proof") unless result["kind"] == "pass" && result.fetch("cases").all? { |value| value.fetch("failures").empty? }
          complete = true
          # capture_command returned only after its actual waitpid publication.
          result.merge("driverJoined" => true, "knownProcessesDead" => true,
                       "watchdogJoined" => true, "waiterJoined" => true)
        end
      rescue Exception => error
        scope.remember(error) # Includes private-directory/input creation before active.
        raise
      ensure
        scope.cleanup do
          if directory && complete
            FileUtils.remove_entry(directory)
          elsif directory
            (@unresolved_roots ||= {})[root] = true
            warn "Preserve ownership probe failure: #{directory}"
          end
        end
      end
    end
  end
end
