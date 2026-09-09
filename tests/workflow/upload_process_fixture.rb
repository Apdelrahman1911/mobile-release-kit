# frozen_string_literal: true

# Test-only real process fixtures. No production file imports this module.
# Startup is independent of the timeout being tested: a module-local clock is
# advanced only after a live orphan actually holds the real capture pipes open.
# A separate ready-leader case uses the real clock. Fallback closes a private
# control pipe; it never signals a child PID recovered from a late marker.
require "json"
require "tmpdir"
require "tempfile"
require "fileutils"
require "rbconfig"
require "open3"
require "digest"
require_relative "upload_process_ownership"

module UploadProcessFixture
  DEADLINE = 0.2
  READINESS_LIMIT = 5
  CAPTURE_LIMIT = 3
  DRIVER_LIMIT = 15
  CLEANUP_LIMIT = 5
  WORKER_LIMIT = 30
  OUTPUT_LIMIT = 32_768
  NATIVE_PRIMARY_PROOFS = begin
    cases = {}
    %w[publication readiness watchdog].product(%w[standard io interrupt system-exit], %w[none close]).each do |boundary, kind, secondary|
      cases["native-proof-#{boundary}-#{kind}-#{secondary}"] = [boundary, kind, secondary].freeze
    end
    cases.merge!("native-proof-late-cleanup" => %w[readiness standard outer].freeze,
                 "native-proof-lookalike" => %w[publication contract none].freeze,
                 "native-proof-entered-io" => %w[entered io none].freeze,
                 "native-proof-frame-io" => %w[frame io none].freeze,
                 "native-proof-frame-io-close" => %w[frame io close].freeze)
    cases.freeze
  end
  NATIVE_MODES = (%w[native-setup-interrupt native-setup-system-exit native-setup-io-error
                    native-setup-no-cleanup native-setup-second-pipe native-setup-owner-failure
                    native-setup-readiness-failure native-setup-watchdog-unavailable
                    native-setup-watchdog-failure native-setup-post-reap-cancel kill-native-setup] + NATIVE_PRIMARY_PROOFS.keys).freeze
  MODES = (%w[inherited delayed-start late-record unready real-deadline
             real-deadline-slow-cleanup immediate-deadline-slow-cleanup
             leader-only no-deadline immediate-deadline kill-startup kill-descendant
             ownership-async ownership-signals ownership-policies ownership-unknown
             ownership-setup ownership-observation] + NATIVE_MODES).freeze

  class Failure < StandardError
    attr_reader :kind

    def initialize(kind, message)
      @kind = kind
      super(message)
    end
  end

  module_function

  def clock
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def atomic_json(path, value)
    temporary = "#{path}.pending"
    File.write(temporary, JSON.generate(value))
    File.rename(temporary, path)
  end

  def read_json(path)
    text = File.binread(path, OUTPUT_LIMIT + 1)
    raise Failure.new("diagnostic", "oversized fixture diagnostic") if text.bytesize > OUTPUT_LIMIT
    JSON.parse(text)
  end

  def wait_until(seconds, kind)
    deadline = clock + seconds
    until yield
      raise Failure.new(kind, "#{kind} deadline expired") if clock >= deadline
      sleep 0.01
    end
  end

  # Only this parent waits on these direct Process.spawn children. Their PID is
  # reserved until waitpid actually reaps it; no asynchronous detach/waiter runs.
  # No signal is sent after that point, even on an assertion or parser failure.
  def capture_command(argv, seconds: 2)
    lifetime do |scope|
      directory = output = errors = nil
      child = OwnedChild.new
      begin
        directory = File.realpath(Dir.mktmpdir("mrk-process-observation-"))
        output = File.open(File.join(directory, "stdout"), "w+", 0o600)
        errors = File.open(File.join(directory, "stderr"), "w+", 0o600)
        scope.active do
          child.start({}, *argv, out: output, err: errors, in: File::NULL,
                      unsetenv_others: true, pgroup: true)
          wait_until(seconds, "process-observation") do
            !child.poll.nil?
          end
          [output, errors].each(&:rewind)
          stdout, stderr = [output, errors].map { |file| file.read(OUTPUT_LIMIT + 1) || "" }
          raise Failure.new("diagnostic", "oversized process observation") if [stdout, stderr].any? { |text| text.bytesize > OUTPUT_LIMIT }
          [stdout, stderr, child.status.exitstatus]
        end
      rescue Exception => error
        scope.remember(error) # Setup can fail before active installs its rescue.
        raise
      ensure
        scope.cleanup do
          begin
            child.stop
          ensure
            [output, errors].compact.each { |io| close(io) }
            if directory
              if child.complete?
                FileUtils.remove_entry(directory)
              else
                atomic_json(File.join(directory, "ownership.json"), {"phase" => child.phase, "pid" => child.pid})
                warn "Preserve unknown process observation: #{directory}"
              end
            end
          end
        end
      end
    end
  end

  def parse_state(stdout, stderr, status, pid, group)
    raise Failure.new("process-observation", "process probe returned diagnostics") unless stderr == ""
    return "absent" if status == 1 && stdout == ""
    # Union of Linux procps and Darwin ps modifiers, in their emission order.
    # Darwin can report ?E while its BSD/Mach exit snapshots disagree. That is
    # indeterminate, NOT malformed identity and NOT evidence of ready/dead code.
    match = /\A[ \t]*(\d+)[ \t]+(\d+)[ \t]+([RSDTtZXIWUH?][<N]?X?E?V?L?s?l?\+?)[ \t]*\n?\z/.match(stdout)
    unless status == 0 && match && Integer(match[1], 10) == pid && Integer(match[2], 10) == group &&
           !(match[3].start_with?("Z") && match[3].include?("E"))
      # Only numeric PID/group/state columns from /bin/ps, not command lines or
      # process environments. Retain this bounded observation on a failed probe.
      detail = {"pid" => pid, "group" => group, "exit" => status, "stdout" => stdout.byteslice(0, 256)}
      raise Failure.new("process-observation", "process probe returned unsupported or incorrectly scoped state: #{JSON.generate(detail)}")
    end
    match[3]
  end

  def liveness(value)
    return :stopped if value == "absent" || value.start_with?("Z")
    return :indeterminate if %w[? H X].include?(value[0]) || value.include?("E")
    :live
  end

  def state(pid, group, seconds: 2)
    value = parse_state(*capture_command(["/bin/ps", "-o", "pid=,pgid=,stat=", "-p", pid.to_s], seconds: seconds), pid, group)
    liveness(value)
  end

  def alive?(pid, group)
    state(pid, group) == :live
  end

  def ready?(pid, group, seconds: 2)
    value = state(pid, group, seconds: seconds)
    raise Failure.new("readiness", "fixture stopped before readiness") if value == :stopped
    value == :live # Valid indeterminate state proves neither readiness nor death.
  end

  def dead!(pid, group, deadline: clock + CLEANUP_LIMIT, kind: "fixture-cleanup")
    loop do
      remaining = deadline - clock
      raise Failure.new(kind, "#{kind} deadline expired") unless remaining.positive?
      value = state(pid, group, seconds: [remaining, 2].min)
      raise Failure.new(kind, "#{kind} deadline expired") if clock >= deadline
      return if value == :stopped
      sleep [0.01, [deadline - clock, 0].max].min
    end
  end

  def close(io)
    io.close unless io.closed?
  rescue IOError
    nil # Another fixture thread may already have closed this exact descriptor.
  end

  def cleanup_unresolved?(root)
    (@unresolved_roots || {}).key?(root)
  end

  # EOF is monitored in EVERY phase, not only after fork. Losing the driver
  # closes the sole control writer and stops both a delayed leader and an orphan.
  def control_wait(control, seconds)
    return false unless IO.select([control], nil, nil, seconds)
    raise Failure.new("control", "unexpected fixture control bytes") unless control.read(1).nil?
    true
  end

  def worker(directory, mode, control_fd, events_fd)
    control, events = IO.for_fd(control_fd), IO.for_fd(events_fd)
    events.sync = true
    emit = lambda do |kind|
      events.puts(JSON.generate("kind" => kind, "pid" => Process.pid, "group" => Process.getpgrp))
    end
    emit.call("entered")
    if %w[unready kill-startup].include?(mode)
      emit.call("startup-wait")
      eof = control_wait(control, WORKER_LIMIT)
      atomic_json(File.join(directory, "leader-eof.json"), {"eof" => eof})
      return 0
    end
    if NATIVE_MODES.include?(mode) || %w[real-deadline immediate-deadline].include?(mode.delete_suffix("-slow-cleanup"))
      if mode == "native-setup-readiness-failure"
        events.puts(JSON.generate("kind" => "leader-ready", "pid" => "not-a-pid", "group" => Process.getpgrp))
      else
        emit.call("leader-ready")
      end
      eof = control_wait(control, WORKER_LIMIT)
      atomic_json(File.join(directory, "leader-eof.json"), {"eof" => eof})
      return 0
    end
    return 0 if mode == "delayed-start" && control_wait(control, DEADLINE * 2)
    child = fork do
      emit.call("child-ready")
      events.close
      eof = control_wait(control, WORKER_LIMIT)
      atomic_json(File.join(directory, "child-eof.json"), {"eof" => eof})
      exit! 0
    end
    events.close
    return 0 if mode == "late-record" && control_wait(control, DEADLINE * 2)
    # This deliberately late legacy record is NEVER read for ownership/readiness.
    atomic_json(File.join(directory, "legacy-child.json"), {"pid" => child})
    0
  end

  def validate_request!(platform, mode, parameters)
    valid = if NATIVE_MODES.include?(mode)
      platform == "native" && parameters == {}
    else
      MODES.include?(mode) && %w[ios android].include?(platform)
    end
    raise Failure.new("fixture-input", "unknown or mismatched fixture mode/platform/parameters") unless valid
  end

  def no_native_child?(mode, owner, result, proof)
    frame_probe = NATIVE_PRIMARY_PROOFS[mode]&.first == "frame"
    return false unless mode == "native-setup-second-pipe" || frame_probe
    return false unless owner == {"phase" => "no-native-child", "nativeSpawnAttempts" => 0} &&
                        result && result["nativeSpawnAttempts"] == 0 && result["ownedDescriptorsClosed"]
    !frame_probe || (proof && proof["case"] == mode && proof["backendEntries"] == 0 &&
                    proof["callbackEntries"] == 0 && proof["framePublishedBeforeFault"])
  end

  def run(platform:, root:, parameters:, mode:)
    validate_request!(platform, mode, parameters)
    return run_ownership_probe(platform: platform, root: root, parameters: parameters, mode: mode) if mode.start_with?("ownership-")
    lifetime do |scope|
      directory = nil
      child = OwnedChild.new
      cleaned = false
      native_deadline = nil
      result = proof = nil
      begin
        directory = File.realpath(Dir.mktmpdir("native-process-", root))
        atomic_json(File.join(directory, "input.json"), {"platform" => platform, "parameters" => parameters, "mode" => mode})
        File.open(File.join(directory, "driver.stdout"), "w") do |output|
          File.open(File.join(directory, "driver.stderr"), "w") do |errors|
            scope.active do
              child.start({}, RbConfig.ruby, File.realpath(__FILE__), "driver", directory,
                          in: File::NULL, out: output, err: errors, unsetenv_others: true, pgroup: true)
              killed = false
              wait_until(DRIVER_LIMIT, "driver") do
                child.poll
                if !child.status && !killed && mode.start_with?("kill-") && File.file?(File.join(directory, "owner.json"))
                  owner = read_json(File.join(directory, "owner.json"))
                  if owner["phase"] == mode
                    # Only the real unreaped direct child, never owner.json's PID.
                    killed = child.signal("KILL", group: false)
                  end
                end
                !child.status.nil?
              end
              owner = read_json(File.join(directory, "owner.json"))
              if mode.start_with?("kill-")
                raise Failure.new("driver", "driver did not terminate at the requested known phase") unless killed && child.status.signaled? && child.status.termsig == Signal.list.fetch("KILL")
                raise Failure.new("driver", "killed driver unexpectedly supplied a final result") if File.exist?(File.join(directory, "result.json"))
                expected_eof = owner["child"] ? "child-eof.json" : "leader-eof.json"
                wait_until(CLEANUP_LIMIT, "fixture-cleanup") { File.file?(File.join(directory, expected_eof)) }
                raise Failure.new("fixture-cleanup", "orphan stopped for a reason other than control EOF") unless read_json(File.join(directory, expected_eof)) == {"eof" => true}
                result = {"kind" => "driver-terminated", "phase" => owner.fetch("phase"), "eofAfterDriverDeath" => true}
              else
                result = read_json(File.join(directory, "result.json"))
                if NATIVE_PRIMARY_PROOFS.key?(mode)
                  # A passing regression envelope never replaces the actual
                  # failed native driver's result/status or grants PID authority.
                  proof = read_json(File.join(directory, "primary-proof.json"))
                  unless proof["case"] == mode && proof["failures"] == [] && proof["driverExitStatus"] == 1 &&
                         result["kind"] != "pass" && child.status.exitstatus == 0
                    raise Failure.new("fixture-result", "unexpected native primary proof: #{JSON.generate(proof)}")
                  end
                else
                  expected = {"unready" => "readiness", "leader-only" => "descendant-alive",
                              "no-deadline" => "capture-watchdog", "immediate-deadline" => "elapsed-bound",
                              "native-setup-no-cleanup" => "setup-fallback",
                              "native-setup-second-pipe" => "setup-fixture-fault",
                              "native-setup-owner-failure" => "setup-fixture-fault",
                              "native-setup-readiness-failure" => "readiness",
                              "native-setup-watchdog-unavailable" => "setup-fixture-fault",
                              "native-setup-watchdog-failure" => "setup-fixture-fault"}.fetch(mode.delete_suffix("-slow-cleanup"), "pass")
                  unless result["kind"] == expected && child.status.exitstatus == (expected == "pass" ? 0 : 1)
                    raise Failure.new("fixture-result", "unexpected fixture result: #{JSON.generate(result)}")
                  end
                end
              end
              native_deadline ||= clock + CLEANUP_LIMIT
              unless no_native_child?(mode, owner, result, proof)
                dead!(owner.fetch("leader"), owner.fetch("group"), deadline: native_deadline)
                dead!(owner["child"], owner.fetch("group"), deadline: native_deadline) if owner["child"]
              end
              cleaned = true
              result = result.merge("primaryProof" => proof) if proof
              result.merge("driverJoined" => true, "knownProcessesDead" => true)
            end
          end
        end
      rescue Exception => error
        scope.remember(error) # Includes setup and failures while collecting diagnostics.
        if error.is_a?(StandardError)
          diagnostics = {"errorClass" => error.class.name, "error" => error.message,
                         "driverStatus" => child.status&.to_s, "ownedDirectory" => directory}
          if directory
            %w[owner.json result.json driver.stderr driver.stdout].each do |name|
              path = File.join(directory, name)
              diagnostics[name] = File.binread(path, OUTPUT_LIMIT).force_encoding("UTF-8").scrub if File.file?(path)
            end
          end
          warn JSON.generate(diagnostics)
        end
        raise
      ensure
        scope.cleanup do
          begin
            child.stop
            cleaned = true if child.phase == :unstarted
            if directory && !cleaned
              # EOF stops native workers. Marker PIDs authorize observation only.
              owner_path = File.join(directory, "owner.json")
              if File.file?(owner_path)
                owner = read_json(owner_path)
                native_deadline ||= clock + CLEANUP_LIMIT
                unless no_native_child?(mode, owner, result, proof)
                  dead!(owner.fetch("leader"), owner.fetch("group"), deadline: native_deadline)
                  dead!(owner["child"], owner.fetch("group"), deadline: native_deadline) if owner["child"]
                end
                cleaned = true
              end
            end
          ensure
            FileUtils.remove_entry(directory) if directory && cleaned
            if directory && !cleaned
              (@unresolved_roots ||= {})[root] = true
              warn "Fixture ownership/cleanup unresolved; preserve #{directory}"
            end
          end
        end
      end
    end
  end

  # The shared-core setup cases have no application/platform parameters. Their
  # watchdog owns only a private pipe writer, never the asynchronous Open3
  # waiter's numeric PID. An EOF fallback must make the production oracle fail.
  class NativeSetupDriver
    def initialize(directory, mode)
      @directory, @mode = directory, mode
      @control_read = @control_write = @event_read = @event_write = nil
      @stdin = @stdout = @stderr = @waiter = @watchdog = @injector = nil
      @native_frame = nil
      @hook_armed = false
      @owner, @cleanup_errors = {}, []
      @fixture_error = Failure.new("setup-fixture-fault", "synthetic #{@mode} failure")
      @injected_error = case mode
      when "native-setup-system-exit" then SystemExit.new(23)
      when "native-setup-io-error" then IOError.new("synthetic private diagnostic")
      else Interrupt.new("synthetic setup cancellation")
      end
      @injected_message = @injected_error.message.dup.freeze
      @injected_status = @injected_error.status if @injected_error.is_a?(SystemExit)
      @observed = {"mode" => mode, "nativeSpawnAttempts" => 0, "captureEntered" => false,
                   "injectionCount" => 0, "watchdogStarted" => false, "watchdogIntervened" => false,
                   "fallbackUsed" => false, "postReapCancellationInjected" => false}
    end

    def path(name)
      File.join(@directory, name)
    end

    def owned_ios
      [@control_read, @control_write, @event_read, @event_write, @stdin, @stdout, @stderr].compact
    end

    def trap_state
      %w[INT TERM].to_h do |name|
        current = Signal.trap(name) {}
        Signal.trap(name, current)
        [name, current]
      end
    end

    def cleanup_step
      yield
    rescue Exception => error
      @cleanup_errors << error
    end

    def close_owned(io)
      return unless io
      UploadProcessFixture.close(io)
      raise Failure.new("fixture-cleanup", "owned native fixture descriptor remains open") unless io.closed?
    end

    def stop_watchdog
      return unless @watchdog
      @watchdog.kill if @watchdog.alive?
    ensure
      if @watchdog && !@watchdog.join(CLEANUP_LIMIT)
        raise Failure.new("fixture-cleanup", "native fixture watchdog did not join")
      end
    end

    def join_waiter
      if @waiter && !@waiter.join(CLEANUP_LIMIT)
        raise Failure.new("fixture-cleanup", "native fixture waiter did not join")
      end
    end

    def publish_owner
      UploadProcessFixture.atomic_json(path("owner.json"), @owner)
    end

    def cleanup_callback(frame)
      @hook_armed = false # Open3's own close must never inject the native fault.
      reaped = false
      cleanup_step { reaped = !@waiter || !@waiter.join(0).nil? }
      if !@observed["captureEntered"] || !reaped
        @observed["fallbackUsed"] = true
        cleanup_step { close_owned(@control_write) } # BEFORE Open3's implicit join.
      end
      cleanup_step { stop_watchdog }
      cleanup_step { join_waiter }
      cleanup_step do
        if @mode == "native-setup-post-reap-cancel" && @callback_error.equal?(@injected_error)
          raise "post-reap probe lacks an actual reaped native child" unless @waiter&.join(0)
          raise "post-reap probe did not retain the original primary" unless frame.primary.equal?(@injected_error)
          @observed["postReapCancellationInjected"] = true
          @observed["postReapCleanupDepth"] = UploadProcessFixture.instance_variable_get(:@cancellation_scope).cleanup_depth
          # The expected original was remembered before this protected teardown.
          # Both real repeat deliveries must be joined/drained, not leak into a
          # later test or replace the original native cancellation facts.
          @injector = Thread.new { Thread.main.raise(Interrupt.new("repeat after actual native reap")) }
          raise "native cancellation injector did not join" unless @injector.join(2)
          Process.kill("INT", Process.pid) # Only this isolated driver's own process.
          @observed["selfSignalQueued"] = Signal.list.fetch("INT")
        end
      end
      [@control_read, @event_write, @event_read, @stdin, @stdout, @stderr].each do |io|
        cleanup_step { close_owned(io) }
      end
      raise @cleanup_errors.first unless @cleanup_errors.empty?
    end

    def finish_resources
      @hook_armed = false
      cleanup_step { close_owned(@control_write) }
      cleanup_step { stop_watchdog }
      cleanup_step do
        raise "native cancellation injector did not join" if @injector && !@injector.join(2)
      end
      owned_ios.each { |io| cleanup_step { close_owned(io) } }
      cleanup_step { join_waiter }
      cleanup_step do
        if @waiter
          # A one-shot owner-write fault cannot discard the actual acquired
          # identity. This final record grants read-only observation, not signals.
          @owner = {"leader" => @waiter.pid, "group" => @waiter.pid, "phase" => "finished"}
          publish_owner
        elsif @observed["nativeSpawnAttempts"].zero?
          @owner = {"phase" => "no-native-child", "nativeSpawnAttempts" => 0}
          publish_owner
        end
      end
      raise @cleanup_errors.first unless @cleanup_errors.empty?
    end

    def ready!
      deadline = UploadProcessFixture.clock + READINESS_LIMIT
      buffer, announced = +"", false
      loop do
        remaining = deadline - UploadProcessFixture.clock
        raise Failure.new("readiness", "native readiness deadline expired") unless remaining.positive?
        if IO.select([@event_read], nil, nil, [remaining, 0.01].min)
          chunk = @event_read.read_nonblock(4_096, exception: false)
          buffer << chunk if chunk.is_a?(String)
          raise Failure.new("readiness", "oversized native readiness event") if buffer.bytesize > 4_096
          while (line = buffer.slice!(/\A[^\n]*\n/))
            event = JSON.parse(line)
            unless event.keys.sort == %w[group kind pid] && event["pid"] == @waiter.pid && event["group"] == @waiter.pid &&
                   %w[entered leader-ready].include?(event["kind"])
              raise Failure.new("readiness", "malformed or incorrectly scoped native readiness event")
            end
            announced = true if event["kind"] == "leader-ready"
          end
        end
        raise Failure.new("readiness", "native worker stopped before readiness") if @waiter.join(0)
        next unless announced
        remaining = deadline - UploadProcessFixture.clock
        raise Failure.new("readiness", "native readiness deadline expired") unless remaining.positive?
        next unless UploadProcessFixture.ready?(@waiter.pid, @waiter.pid, seconds: [remaining, 2].min)
        raise Failure.new("readiness", "native readiness deadline expired") if UploadProcessFixture.clock >= deadline
        @observed["ready"] = true
        return
      end
    end

    def first_close(location, stdin)
      return unless @hook_armed && location.path == @capture_path && location.lineno == @close_line
      return unless @observed["injectionCount"].zero?
      @observed["injectionCount"] += 1
      @observed["firstCloseFromNative"] = true
      @observed["originalCloseCompleted"] = stdin.closed?
      raise @injected_error
    end

    def start_watchdog
      Thread.handle_interrupt(Exception => :never) do
        @watchdog = Thread.new do
          sleep CAPTURE_LIMIT
          @observed["watchdogIntervened"] = true
          @observed["fallbackUsed"] = true
          close_owned(@control_write) # No waiter/PID/group-based fallback.
        end
        @observed["watchdogStarted"] = true
        raise @fixture_error if @mode == "native-setup-watchdog-failure"
      end
    end

    def popen(environment, *argv, **options, &block)
      unless environment == {} && argv == @argv && options == @options
        raise "unexpected shared native launch contract"
      end
      UploadProcessFixture.lifetime do |frame|
        @native_frame = frame # Remember the whole lifetime, even before a callback exists.
        begin
          @observed["nativeSpawnAttempts"] += 1
          # lifetime defers acquisition/publication; only the registered callback
          # below reopens active cancellation. No writer is inherited by worker.
          Open3.popen3(environment, *argv, **options,
                       @control_read.fileno => @control_read, @event_write.fileno => @event_write) do |stdin, stdout, stderr, waiter|
            @stdin, @stdout, @stderr, @waiter = stdin, stdout, stderr, waiter
            begin # Installed before owner I/O, unused-end closes or readiness.
              @owner = {"leader" => waiter.pid, "group" => waiter.pid, "phase" => "launched"}
              frame.active do
                raise @fixture_error if @mode == "native-setup-owner-failure"
                publish_owner
                close_owned(@control_read)
                close_owned(@event_write)
                ready!
                if @mode == "kill-native-setup"
                  @owner["phase"] = @mode
                  publish_owner
                  sleep READINESS_LIMIT
                  raise Failure.new("driver", "parent did not stop its owned native driver")
                end
                raise @fixture_error if @mode == "native-setup-watchdog-unavailable"
                start_watchdog
                original_close, driver = stdin.method(:close), self
                stdin.define_singleton_method(:close) do
                  original_close.call unless closed?
                  driver.first_close(caller_locations(1, 1).first, self)
                end
                Thread.handle_interrupt(Exception => :never) do
                  @hook_armed = true
                  @observed["captureEntered"] = true
                  Thread.handle_interrupt(Exception => :immediate) { block.call(stdin, stdout, stderr, waiter) }
                ensure
                  @hook_armed = false
                end
              end
            rescue Exception => error
              @callback_error = error
              frame.remember(error)
              raise
            ensure
              frame.cleanup { cleanup_callback(frame) }
            end
          end
        rescue Exception => error
          frame.remember(error)
          raise
        ensure
          # All native callback cleanup and Open3's join have completed. The
          # injected repeat queue belongs to this remembered original exception.
          frame.finishing { frame.drain_pending } if @observed["postReapCancellationInjected"]
        end
      end
    end

    def prepare_native
      require_relative "../../fastlane/native_upload_validation"
      @native = MobileReleaseKit::NativeUploadValidation
      if @mode == "native-setup-no-cleanup"
        source = File.read(File.expand_path("../../fastlane/native_upload_validation.rb", __dir__))
        @observed["mutationSourceSha256"] = Digest::SHA256.hexdigest(source)
        anchor = 'Process.kill("KILL", -waiter.pid)'
        raise "native setup mutation anchor changed" unless source.scan(anchor).length == 1
        source = source.sub(anchor, "nil # synthetic missing production cleanup").sub(
          'require_relative "release_support"', "require #{File.expand_path('../../fastlane/release_support', __dir__).inspect}")
        File.write(path("mutated-native.rb"), source)
        @observed["mutationSha256"] = Digest::SHA256.hexdigest(source)
        load path("mutated-native.rb")
      end
      @capture_path = @native.method(:capture).source_location.first
      lines = File.readlines(@capture_path).each_with_index.select { |line, _| line.strip == "stdin.close" }
      raise "native first-close source anchor changed" unless lines.length == 1
      @close_line = lines.first.last + 1
      @options = {chdir: File.realpath(File.expand_path("../../fastlane", __dir__)), unsetenv_others: true, pgroup: true}
      @argv = [RbConfig.ruby, File.realpath(__FILE__), "worker", @directory, @mode,
               @control_read.fileno.to_s, @event_write.fileno.to_s]
      driver, facade = self, Module.new
      facade.define_singleton_method(:popen3) { |*arguments, **options, &block| driver.popen(*arguments, **options, &block) }
      @native.const_set(:Open3, facade)
    end

    def expected_native_error?(primary)
      return false unless @observed["captureEntered"] && @observed["injectionCount"] == 1 &&
                          @observed["firstCloseFromNative"] && @observed["originalCloseCompleted"] &&
                          primary.equal?(@injected_error) && @injected_error.message == @injected_message
      if @injected_error.is_a?(IOError)
        @native_error.instance_of?(MobileReleaseKit::ContractError) &&
          @native_error.message == "Synthetic validator could not be executed safely; no upload is authorized"
      else
        @native_error.equal?(@injected_error) && @native_error.message == @injected_message &&
          (!@injected_error.is_a?(SystemExit) || @native_error.status == @injected_status)
      end
    end

    def exercise
      begin
        @native.capture({}, @argv, @options.fetch(:chdir), max_seconds: DEADLINE, max_output_bytes: 1_024,
                        label: "Synthetic", failure_message: "synthetic validation failure")
      rescue Exception => error
        @native_error = error
      end
      @observed["nativeErrorClass"] = @native_error&.class&.name
      @observed["nativeErrorMessage"] = @native_error&.message
      @observed["nativeOriginalErrorPreserved"] = @native_error.equal?(@injected_error) && @native_error.message == @injected_message
      @observed["nativeExitStatus"] = @native_error.status if @native_error.is_a?(SystemExit)
      # The native wrapper intentionally redacts IOErrors. Our own first error
      # is still held by the nested lifetime and must not become a later cleanup
      # error/assertion. A mode name or matching redacted message grants no waiver.
      primary = @native_frame&.primary || @callback_error || @native_error
      unless expected_native_error?(primary)
        raise primary if primary
        raise "native capture did not return the expected first-close failure"
      end
      raise @cleanup_errors.first unless @cleanup_errors.empty?
      raise "native capture did not reap its worker" unless @waiter&.join(0)
      if @observed["watchdogIntervened"]
        raise Failure.new("setup-fallback", "native setup cleanup required control EOF")
      end
      unless @waiter.value.signaled? && @waiter.value.termsig == Signal.list.fetch("KILL")
        raise "native cleanup did not SIGKILL the actual worker"
      end
      UploadProcessFixture.dead!(@waiter.pid, @waiter.pid, deadline: UploadProcessFixture.clock + CLEANUP_LIMIT)
      raise "native control closed before death proof" if @control_write.closed? || @observed["fallbackUsed"]
      @observed["deadBeforeFallback"] = true
    end

    def execute
      saved_handlers = trap_state
      failure = nil
      begin
        UploadProcessFixture.lifetime do |frame|
          begin
            @control_read, @control_write = IO.pipe
            raise @fixture_error if @mode == "native-setup-second-pipe"
            @event_read, @event_write = IO.pipe
            prepare_native
            frame.active { exercise }
          rescue Exception => error
            frame.remember(error)
            raise
          ensure
            frame.cleanup { finish_resources }
          end
        end
      rescue Exception => error
        failure = error
      end
      @observed.merge!("ownedDescriptorCount" => owned_ios.length, "ownedDescriptorsClosed" => owned_ios.all?(&:closed?),
                       "watchdogJoined" => !@watchdog || !@watchdog.alive?, "waiterJoined" => !@waiter || !@waiter.alive?,
                       "injectorsJoined" => !@injector || !@injector.alive?, "handlersRestored" => trap_state == saved_handlers,
                       "registryInactive" => UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?,
                       "pendingInterrupt" => Thread.current.pending_interrupt?,
                       "harnessPrimaryRetained" => failure && (failure.equal?(@fixture_error) || failure.equal?(@callback_error) || failure.equal?(@native_frame&.primary)),
                       "cleanupErrors" => @cleanup_errors.map { |error| error.class.name })
      if @waiter && @waiter.join(0)
        @observed["workerExitStatus"] = @waiter.value.exitstatus
        @observed["workerTermSignal"] = @waiter.value.termsig
      end
      @observed["workerControlEOF"] = UploadProcessFixture.read_json(path("leader-eof.json")) == {"eof" => true} if File.file?(path("leader-eof.json"))
      kind = failure ? (failure.is_a?(Failure) ? failure.kind : "unexpected") : "pass"
      unless @observed.values_at("ownedDescriptorsClosed", "watchdogJoined", "waiterJoined", "injectorsJoined", "handlersRestored", "registryInactive").all? &&
             !@observed["pendingInterrupt"] && @cleanup_errors.empty?
        kind = "fixture-cleanup"
      end
      result = @observed.merge("kind" => kind, "errorClass" => failure&.class&.name, "error" => failure&.message)
      UploadProcessFixture.atomic_json(path("result.json"), result)
      kind == "pass" ? 0 : 1
    end
  end

  # One isolated ordinary driver per proof. Faults occur after actual publication,
  # readiness or watchdog registration; the observed final exception comes from
  # the real outer result boundary, not the driver's self-reported boolean.
  class NativePrimaryProbe
    class UnexpectedFailure < StandardError; end
    class CleanupFailure < StandardError; end

    class Driver < NativeSetupDriver
      attr_reader :original, :original_message, :original_status, :secondary, :fault_count,
                  :secondary_count, :frame_published, :signal_requests, :entered_death_before_close

      def initialize(directory, spec)
        @boundary, kind, @secondary_boundary = spec
        super(directory, @boundary == "entered" ? "native-setup-io-error" : "native-setup-interrupt")
        require_relative "../../fastlane/release_support"
        message = @boundary == "entered" ? @injected_message : "unexpected synthetic native setup failure"
        @original = case kind
        when "io" then IOError.new(message)
        when "interrupt" then Interrupt.new(message)
        when "system-exit" then SystemExit.new(41, message)
        when "contract" then MobileReleaseKit::ContractError.new("Synthetic validator could not be executed safely; no upload is authorized")
        else UnexpectedFailure.new(message)
        end
        @original_message = @original.message.dup.freeze
        @original_status = @original.status if @original.is_a?(SystemExit)
        @secondary = CleanupFailure.new("secondary synthetic native cleanup failure") unless @secondary_boundary == "none"
        @fault_count = @secondary_count = 0
        @frame_published = @entered_death_before_close = false
        @signal_requests = []
      end

      def fault(boundary)
        return unless boundary == @boundary && @fault_count.zero?
        @fault_count += 1
        @frame_published = !@native_frame.nil?
        if @original.is_a?(Interrupt)
          Thread.handle_interrupt(Exception => :never) do
            @injector = Thread.new { Thread.main.raise(@original) }
            raise "unexpected-fault injector did not join" unless @injector.join(2)
          end
        else
          raise @original
        end
      end

      def fail_cleanup
        return unless @secondary && @secondary_count.zero?
        @secondary_count += 1
        raise @secondary
      end

      def publish_owner
        super
        fault("publication") if @owner["phase"] == "launched"
        fail_cleanup if @owner["phase"] == "finished" && @secondary_boundary == "outer"
      end

      def ready!
        super
        fault("readiness")
      end

      def start_watchdog
        super
        fault("watchdog")
      end

      def close_owned(io)
        if @boundary == "entered" && io && io.equal?(@control_write) && !io.closed?
          unless @waiter&.join(0) && @waiter.value.signaled? && @waiter.value.termsig == Signal.list.fetch("KILL") &&
                 !@observed["fallbackUsed"] && !@observed["watchdogIntervened"]
            raise "entered unexpected-error worker was not killed before fixture cleanup"
          end
          UploadProcessFixture.dead!(@waiter.pid, @waiter.pid, deadline: UploadProcessFixture.clock + CLEANUP_LIMIT)
          @entered_death_before_close = true
        end
        super
        fail_cleanup if io && io.equal?(@control_write) && @secondary_boundary == "close" && @fault_count == 1
      end

      def prepare_native
        super
        driver, facade = self, Module.new
        facade.const_set(:CLOCK_MONOTONIC, Process::CLOCK_MONOTONIC)
        facade.define_singleton_method(:clock_gettime) { |identifier| Process.clock_gettime(identifier) }
        facade.define_singleton_method(:kill) do |signal, target|
          waiter = driver.instance_variable_get(:@waiter)
          request = {"signal" => signal.to_s, "target" => target, "forwarded" => false}
          driver.signal_requests << request
          # Observation is a rejection oracle, not lasting PID authority. The
          # entered proof requires exclusive isolation until QA-007 is fixed.
          unless signal == "KILL" && waiter && target == -waiter.pid && !waiter.join(0)
            raise "unexpected or post-reap native signal request"
          end
          request["forwarded"] = true
          request["result"] = Process.kill(signal, target)
        end
        @native.const_set(:Process, facade)
      end
    end

    def initialize(directory, mode)
      @directory, @mode = directory, mode
      @spec = NATIVE_PRIMARY_PROOFS.fetch(mode)
    end

    def execute
      driver = Driver.new(@directory, @spec)
      source = File.realpath(__FILE__)
      anchors = {"result" => '@observed.merge!("ownedDescriptorCount"',
                 "frame" => '@observed["nativeSpawnAttempts"] += 1', "entered" => 'raise @injected_error'}
      lines = File.readlines(source)
      anchors.transform_values! do |anchor|
        matches = lines.each_index.select { |index| lines[index].lstrip.start_with?(anchor) }
        raise "native proof source anchor changed" unless matches.length == 1
        matches.first + 1
      end
      outer_error = nil
      result_observations = backend_entries = callback_entries = 0
      actual_waiter = nil
      backend = Open3.method(:popen3)
      trace = TracePoint.new(:line) do |point|
        next unless point.path == source && point.self.equal?(driver)
        if point.lineno == anchors.fetch("result")
          result_observations += 1
          outer_error = point.binding.local_variable_get(:failure)
        elsif %w[frame entered].include?(@spec.first) && point.lineno == anchors.fetch(@spec.first)
          driver.fault(@spec.first)
        end
      end
      begin
        # Count actual backend entry/yield independently, without manufacturing
        # a child, waiter, status, stream, return value or native exception.
        Open3.define_singleton_method(:popen3) do |*arguments, **options, &block|
          backend_entries += 1
          backend.call(*arguments, **options) do |stdin, stdout, stderr, waiter|
            callback_entries += 1
            actual_waiter = waiter
            block.call(stdin, stdout, stderr, waiter)
          end
        end
        trace.enable
        status = driver.execute
      ensure
        trace.disable
        Open3.define_singleton_method(:popen3, backend)
      end
      raw = UploadProcessFixture.read_json(File.join(@directory, "result.json"))
      frame = driver.instance_variable_get(:@native_frame)
      native_error = driver.instance_variable_get(:@native_error)
      callback_error = driver.instance_variable_get(:@callback_error)
      errors = driver.instance_variable_get(:@cleanup_errors)
      reaped = false
      wait_status = nil
      if actual_waiter && actual_waiter.join(0)
        wait_status = actual_waiter.value
        begin
          Process.waitpid2(actual_waiter.pid, Process::WNOHANG)
        rescue Errno::ECHILD
          reaped = true
        end
      end
      proof = {"case" => @mode, "driverExitStatus" => status, "faultCount" => driver.fault_count,
               "framePublishedBeforeFault" => driver.frame_published, "resultObservations" => result_observations,
               "outerPrimarySameObject" => outer_error.equal?(driver.original),
               "nestedPrimarySameObject" => frame&.primary.equal?(driver.original),
               "callbackPrimarySameObject" => callback_error.equal?(driver.original), "callbackAbsent" => callback_error.nil?,
               "originalMessagePreserved" => outer_error&.message == driver.original_message,
               "originalStatusPreserved" => !driver.original.is_a?(SystemExit) ||
                 (outer_error.is_a?(SystemExit) && outer_error.status == driver.original_status),
               "originalNotIntentional" => !driver.original.equal?(driver.instance_variable_get(:@injected_error)),
               "backendEntries" => backend_entries, "callbackEntries" => callback_entries,
               "actualWaiterMatchesDriver" => actual_waiter.equal?(driver.instance_variable_get(:@waiter)),
               "actualWaiterReaped" => reaped, "actualWorkerExitStatus" => wait_status&.exitstatus,
               "actualWorkerTermSignal" => wait_status&.termsig,
               "actualDescriptorsClosed" => driver.owned_ios.all?(&:closed?),
               "secondaryCount" => driver.secondary_count,
               "secondaryObjectRecorded" => driver.secondary && errors.any? { |error| error.equal?(driver.secondary) },
               "enteredDeathBeforeControlClose" => driver.entered_death_before_close,
               "nativeErrorClass" => native_error&.class&.name, "nativeErrorMessage" => native_error&.message,
               "signalRequests" => driver.signal_requests, "failures" => []}
      check = lambda { |name, value| proof["failures"] << name unless value }
      check.call("actual failed native result", status == 1 && raw["kind"] == (driver.secondary ? "fixture-cleanup" : "unexpected"))
      check.call("one real injection/final boundary", driver.fault_count == 1 && result_observations == 1)
      %w[framePublishedBeforeFault outerPrimarySameObject nestedPrimarySameObject originalMessagePreserved
         originalStatusPreserved originalNotIntentional actualWaiterMatchesDriver actualDescriptorsClosed].each do |name|
        check.call(name, proof.fetch(name))
      end
      check.call("secondary identity", driver.secondary ? proof["secondaryObjectRecorded"] && errors.length == 1 && driver.secondary_count == 1 : errors.empty?)
      %w[ownedDescriptorsClosed watchdogJoined waiterJoined injectorsJoined handlersRestored registryInactive].each do |name|
        check.call(name, raw[name])
      end
      check.call("no pending cancellation", !raw["pendingInterrupt"])
      if @spec[1] == "io"
        check.call("unchanged IOError redaction", native_error.instance_of?(MobileReleaseKit::ContractError) &&
                   native_error.message == "Synthetic validator could not be executed safely; no upload is authorized")
      else
        check.call("actual non-IOError return", native_error.equal?(driver.original))
      end
      if @spec.first == "frame"
        check.call("no native acquisition/callback", backend_entries.zero? && callback_entries.zero? && actual_waiter.nil? &&
                   callback_error.nil? && raw["nativeSpawnAttempts"] == 0 && raw["ownedDescriptorCount"] == 4)
        check.call("no native fallback", !raw["fallbackUsed"] && !raw.key?("workerControlEOF"))
      else
        check.call("actual native callback original", backend_entries == 1 && callback_entries == 1 && proof["callbackPrimarySameObject"] &&
                   reaped && raw["nativeSpawnAttempts"] == 1 && raw["ownedDescriptorCount"] == 7)
        if @spec.first == "entered"
          check.call("real first-close boundary", raw["captureEntered"] && raw["injectionCount"] == 1 && raw["firstCloseFromNative"] && raw["originalCloseCompleted"])
          check.call("actual native kill before fallback", proof["enteredDeathBeforeControlClose"] && proof["actualWorkerTermSignal"] == Signal.list.fetch("KILL") &&
                     proof["actualWorkerExitStatus"].nil? && !raw["fallbackUsed"] && !raw["watchdogIntervened"] && !raw.key?("workerControlEOF"))
          check.call("one real native kill", driver.signal_requests.length == 1 && driver.signal_requests.first["forwarded"] && driver.signal_requests.first["result"] == 1)
        else
          check.call("real EOF before reap", raw["workerControlEOF"] && raw["fallbackUsed"] &&
                     proof["actualWorkerExitStatus"] == 0 && proof["actualWorkerTermSignal"].nil?)
        end
      end
      unless @spec.first == "entered"
        check.call("first-close unreached", !raw["captureEntered"] && raw["injectionCount"] == 0 && !raw.key?("firstCloseFromNative"))
        check.call("no native signals/watchdog", driver.signal_requests.empty? && !raw["watchdogIntervened"])
      end
      UploadProcessFixture.atomic_json(File.join(@directory, "primary-proof.json"), proof)
      proof.fetch("failures").empty? ? 0 : 1
    end
  end

  def driver(directory)
    input = read_json(File.join(directory, "input.json"))
    mode, platform = input.values_at("mode", "platform")
    validate_request!(platform, mode, input.fetch("parameters"))
    return NativePrimaryProbe.new(directory, mode).execute if NATIVE_PRIMARY_PROOFS.key?(mode)
    return NativeSetupDriver.new(directory, mode).execute if platform == "native"
    base_mode = mode.delete_suffix("-slow-cleanup")
    real_clock = %w[real-deadline immediate-deadline].include?(base_mode)
    require_relative "../../fastlane/ios_upload_validation"
    require_relative "../../fastlane/android_upload_validation"
    gate = platform == "ios" ? MobileReleaseKit::IosUploadValidation : MobileReleaseKit::AndroidUploadValidation
    native = MobileReleaseKit::NativeUploadValidation
    parameters = input.fetch("parameters").transform_keys(&:to_sym)
    parameters[:environment] = {}
    artifact_key = platform == "ios" ? :ipa_path : :aab_path
    expected_argv = [parameters.fetch(:python), "-I", "-S", "-c", gate::BOOTSTRAP,
                     File.realpath(parameters.fetch(:module_root)), "--app-root", File.realpath(parameters.fetch(:app_root)),
                     "--config-path", parameters.fetch(:config_path), "--operation-intent", parameters.fetch(:intent_path),
                     "--#{platform == 'ios' ? 'ipa' : 'aab'}", parameters.fetch(artifact_key), "--intent-sha256", parameters.fetch(:intent_sha256)]
    expected_options = {chdir: File.realpath(parameters.fetch(:tooling_directory)), unsetenv_others: true, pgroup: true}
    mutation = {}
    if %w[leader-only no-deadline immediate-deadline].include?(base_mode)
      source = File.read(File.expand_path("../../fastlane/native_upload_validation.rb", __dir__))
      mutation["mutationSourceSha256"] = Digest::SHA256.hexdigest(source)
      anchor, replacement = if base_mode == "leader-only"
        ['Process.kill("KILL", -waiter.pid)', 'Process.kill("KILL", waiter.pid)']
      else
        [' + max_seconds', base_mode == "no-deadline" ? ' + 86_400' : ' + 0']
      end
      raise "mutation anchor changed" unless source.scan(anchor).length == 1
      source = source.sub(anchor, replacement).sub('require_relative "release_support"', "require #{File.expand_path('../../fastlane/release_support', __dir__).inspect}")
      copy = File.join(directory, "mutated-native.rb")
      File.write(copy, source)
      mutation["mutationSha256"] = Digest::SHA256.hexdigest(source)
      load copy
    end
    gate.send(:remove_const, :MAX_SECONDS)
    gate.const_set(:MAX_SECONDS, DEADLINE)

    observed = {"mode" => mode, "pipeWaits" => 0, "deadlinePipeWaits" => 0, "nativeClockReads" => 0,
                "legacyRecordUsedForOwnership" => false,
                "watchdogIntervened" => false, "fallbackUsed" => false, "captureEntered" => false}.merge(mutation)
    owner = {}
    control_read, control_write = IO.pipe
    event_read, event_write = IO.pipe
    waiter_handle = watchdog = nil
    stdout_handle = stderr_handle = nil
    result = nil
    deadline_started = nil
    spawn_facade, clock_facade, io_facade = Module.new, Module.new, Module.new
    clock_facade.const_set(:CLOCK_MONOTONIC, Process::CLOCK_MONOTONIC)
    clock_facade.define_singleton_method(:clock_gettime) do |identifier|
      raise "unexpected clock" unless identifier == Process::CLOCK_MONOTONIC
      if real_clock
        value = UploadProcessFixture.clock
        deadline_started ||= value
        observed["nativeClockReads"] += 1
        # These are the REAL values returned to the native deadline calculation.
        # Its last decision read precedes raise/ensure/KILL/join, unlike total capture.
        observed["deadlineDecisionSeconds"] = value - deadline_started
        value
      else
        observed["pipeWaits"].positive? ? 1.0 : 0.0
      end
    end
    clock_facade.define_singleton_method(:kill) do |*arguments|
      started = UploadProcessFixture.clock
      begin
        sleep DEADLINE * 2 if mode.end_with?("-slow-cleanup")
        Process.kill(*arguments)
      ensure
        observed["cleanupSeconds"] = UploadProcessFixture.clock - started
      end
    end
    io_facade.define_singleton_method(:select) do |*arguments|
      unless !arguments[0].empty? && (arguments[0] - [stdout_handle, stderr_handle]).empty?
        raise "unexpected capture pipe selection"
      end
      orphan = owner["child"] && waiter_handle.join(0) && UploadProcessFixture.alive?(owner.fetch("child"), owner.fetch("group"))
      ready_leader = real_clock && observed["ready"] && waiter_handle.alive?
      selected = IO.select(*arguments)
      observed["pipeWaits"] += 1 if orphan && selected.nil?
      observed["deadlinePipeWaits"] += 1 if ready_leader && selected.nil?
      selected
    end
    spawn_facade.define_singleton_method(:popen3) do |environment, *argv, **options, &block|
      raise "unexpected complete adapter launch contract" unless argv == expected_argv && options == expected_options && environment == {"LANG" => "C", "LC_ALL" => "C"}
      # Extra FDs belong only to this static fixture; preserve every real adapter
      # spawn option. Only READ authority for control crosses into the worker.
      Open3.popen3(environment, RbConfig.ruby, File.realpath(__FILE__), "worker", directory, mode,
                   control_read.fileno.to_s, event_write.fileno.to_s, **options,
                   control_read.fileno => control_read, event_write.fileno => event_write) do |stdin, stdout, stderr, waiter|
        waiter_handle, stdout_handle, stderr_handle = waiter, stdout, stderr
        owner.merge!("leader" => waiter.pid, "group" => waiter.pid, "phase" => "launched")
        UploadProcessFixture.atomic_json(File.join(directory, "owner.json"), owner)
        UploadProcessFixture.close(control_read)
        UploadProcessFixture.close(event_write)
        begin
          buffer = +""
          ready_leader = false
          started = UploadProcessFixture.clock
          limit = mode == "unready" ? DEADLINE * 2 : READINESS_LIMIT
          readiness_deadline = started + limit
          UploadProcessFixture.wait_until(limit, "readiness") do
            selected = IO.select([event_read], nil, nil, 0.01)
            if selected
              chunk = event_read.read_nonblock(4_096, exception: false)
              buffer << chunk if chunk.is_a?(String)
              raise "oversized fixture readiness" if buffer.bytesize > 4_096
              while (line = buffer.slice!(/\A[^\n]*\n/))
                event = JSON.parse(line)
                unless event.keys.sort == %w[group kind pid] && event["group"] == waiter.pid && event["pid"].is_a?(Integer) && event["pid"] > 1
                  raise Failure.new("readiness", "unexpected fixture process identity")
                end
                case event.fetch("kind")
                when "entered", "startup-wait", "leader-ready"
                  raise "wrong fixture leader" unless event["pid"] == waiter.pid
                  ready_leader = true if event["kind"] == "leader-ready"
                  owner["phase"] = "kill-startup" if mode == "kill-startup" && event["kind"] == "startup-wait"
                when "child-ready"
                  raise "fixture child is its leader" if event["pid"] == waiter.pid
                  owner["child"] = event.fetch("pid")
                else
                  raise "unknown fixture readiness event"
                end
                UploadProcessFixture.atomic_json(File.join(directory, "owner.json"), owner)
              end
            end
            leader_mode = real_clock
            ready = leader_mode ? ready_leader && waiter.alive? : owner["child"] && waiter.join(0)
            if ready
              target = leader_mode ? waiter.pid : owner.fetch("child")
              remaining = readiness_deadline - UploadProcessFixture.clock
              raise Failure.new("readiness", "readiness deadline expired") unless remaining.positive?
              next false unless UploadProcessFixture.ready?(target, waiter.pid, seconds: [remaining, 2].min)
              raise Failure.new("readiness", "readiness deadline expired") if UploadProcessFixture.clock >= readiness_deadline
              observed["ready"] = true
              observed["leaderExitedBeforeCapture"] = !waiter.join(0).nil?
              observed["liveChildBeforeCapture"] = !owner["child"].nil?
              observed["readinessSeconds"] = UploadProcessFixture.clock - started
              if mode == "kill-descendant"
                owner["phase"] = "kill-descendant"
                UploadProcessFixture.atomic_json(File.join(directory, "owner.json"), owner)
                sleep 0.01 until control_write.closed? # Parent kills this isolated driver.
              end
            end
            ready
          end
          observed["captureEntered"] = true
          watchdog = Thread.new do
            sleep CAPTURE_LIMIT
            observed["watchdogIntervened"] = true
            observed["fallbackUsed"] = true
            UploadProcessFixture.close(control_write)
          end
          capture_started = UploadProcessFixture.clock
          begin
            block.call(stdin, stdout, stderr, waiter)
          ensure
            observed["captureSeconds"] = UploadProcessFixture.clock - capture_started
          end
        ensure
          # Before capture entry Open3 still owns a live waiter. Close the exact
          # lifetime descriptor BEFORE its implicit join on readiness failure.
          unless observed["captureEntered"]
            observed["fallbackUsed"] = true
            UploadProcessFixture.close(control_write)
            raise Failure.new("fixture-cleanup", "unready worker ignored EOF") unless waiter.join(CLEANUP_LIMIT)
          end
        end
      end
    end
    native.const_set(:Open3, spawn_facade)
    native.const_set(:Process, clock_facade)
    native.const_set(:IO, io_facade)
    begin
      error = nil
      begin
        gate.current!(**parameters)
      rescue Exception => failure
        error = failure
      ensure
        watchdog&.kill
        watchdog&.join
      end
      raise Failure.new("capture-watchdog", "independent capture watchdog was required") if observed["watchdogIntervened"]
      raise error if error && !error.is_a?(MobileReleaseKit::ContractError)
      raise Failure.new("timeout", "capture did not report its own timeout") unless error&.message&.include?("timed out")
      raise "capture returned without a reaped leader" unless waiter_handle && !waiter_handle.alive?
      if real_clock
        unless observed["ready"] && observed["deadlinePipeWaits"].positive? &&
               observed["deadlineDecisionSeconds"] >= DEADLINE * 0.75 &&
               observed["deadlineDecisionSeconds"] < CAPTURE_LIMIT && observed["captureSeconds"] < CAPTURE_LIMIT
          raise Failure.new("elapsed-bound", "real timeout decision/pipe-wait bound violated before cleanup")
        end
      else
        unless observed["ready"] && observed["leaderExitedBeforeCapture"] && observed["liveChildBeforeCapture"] && observed["pipeWaits"].positive?
          raise Failure.new("readiness", "inherited-pipe boundary was not observed")
        end
        dead!(owner.fetch("child"), owner.fetch("group"), deadline: clock + 2, kind: "descendant-alive")
      end
      raise "fixture control closed before death proof" if control_write.closed? || observed["fallbackUsed"]
      observed["deadBeforeFallback"] = true
      result = observed.merge("kind" => "pass")
    rescue Exception => error # Isolated test driver must retain cancellation diagnostics and clean owned FDs.
      result = observed.merge("kind" => error.is_a?(Failure) ? error.kind : "unexpected",
                              "error" => error.message, "errorClass" => error.class.name)
    ensure
      watchdog&.kill
      watchdog&.join
      observed["watchdogJoined"] = !watchdog || !watchdog.alive?
      result["fallbackAfterObservation"] = !control_write.closed? && result["kind"] != "pass"
      close(control_write) # Only fallback, and only after the result's death oracle.
      [control_read, event_write, event_read].each { |io| close(io) }
      if waiter_handle
        raise Failure.new("fixture-cleanup", "native waiter did not join") unless waiter_handle.join(CLEANUP_LIMIT)
      end
      result["watchdogJoined"] = observed["watchdogJoined"]
      result["waiterJoined"] = !waiter_handle || !waiter_handle.alive?
      atomic_json(File.join(directory, "result.json"), result)
    end
    result.fetch("kind") == "pass" ? 0 : 1
  end

  module Contracts
    def assert_complete_process_case(mode)
      value = process_case(mode)
      assert value.fetch("driverJoined"), value.inspect
      assert value.fetch("knownProcessesDead"), value.inspect
      unless mode.start_with?("kill-")
        assert value.fetch("watchdogJoined"), value.inspect
        assert value.fetch("waiterJoined"), value.inspect
      end
      value
    end

    def test_deadline_terminates_validator_without_authorizing_upload
      value = assert_complete_process_case("real-deadline")
      assert value.fetch("deadBeforeFallback"), value.inspect
      refute value.fetch("fallbackUsed"), value.inspect
      assert_operator value.fetch("deadlineDecisionSeconds"), :>=, UploadProcessFixture::DEADLINE * 0.75
      assert_operator value.fetch("deadlinePipeWaits"), :>, 0
      assert_operator value.fetch("captureSeconds"), :<, UploadProcessFixture::CAPTURE_LIMIT
    end

    def test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits
      value = assert_complete_process_case("inherited")
      assert value.fetch("leaderExitedBeforeCapture"), value.inspect
      assert value.fetch("liveChildBeforeCapture"), value.inspect
      assert_operator value.fetch("pipeWaits"), :>, 0
      assert value.fetch("deadBeforeFallback"), value.inspect
      refute value.fetch("fallbackUsed"), value.inspect
    end

    def test_descendant_boundary_survives_delayed_start_and_late_parent_record
      %w[delayed-start late-record].each do |mode|
        value = assert_complete_process_case(mode)
        assert value.fetch("deadBeforeFallback"), value.inspect
        assert_operator value.fetch("readinessSeconds"), :>, UploadProcessFixture::DEADLINE
        assert_operator value.fetch("pipeWaits"), :>, 0
        refute value.fetch("legacyRecordUsedForOwnership"), value.inspect
        refute value.fetch("fallbackUsed"), value.inspect
      end
    end

    def test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record
      value = assert_complete_process_case("unready")
      assert_equal "readiness", value.fetch("kind")
      refute value.fetch("captureEntered"), value.inspect
      assert value.fetch("fallbackUsed"), value.inspect
      refute value.fetch("watchdogIntervened"), value.inspect
      refute value.key?("deadBeforeFallback"), value.inspect
    end

    def test_fixture_detects_leader_only_cleanup_and_missing_deadline
      only_leader = assert_complete_process_case("leader-only")
      assert_equal "descendant-alive", only_leader.fetch("kind")
      assert_operator only_leader.fetch("pipeWaits"), :>, 0
      refute only_leader.fetch("watchdogIntervened"), only_leader.inspect
      refute only_leader.key?("deadBeforeFallback"), only_leader.inspect
      no_deadline = assert_complete_process_case("no-deadline")
      assert_equal "capture-watchdog", no_deadline.fetch("kind")
      assert no_deadline.fetch("watchdogIntervened"), no_deadline.inspect
      refute no_deadline.key?("deadBeforeFallback"), no_deadline.inspect
    end

    def test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed
      value = assert_complete_process_case("immediate-deadline")
      assert_equal "elapsed-bound", value.fetch("kind")
      assert value.fetch("ready"), value.inspect
      assert_equal 0, value.fetch("deadlinePipeWaits"), value.inspect
      refute value.fetch("watchdogIntervened"), value.inspect
      refute value.key?("deadBeforeFallback"), value.inspect
    end

    def test_slow_cleanup_cannot_supply_a_positive_deadline_wait
      %w[real-deadline-slow-cleanup immediate-deadline-slow-cleanup].each do |mode|
        value = assert_complete_process_case(mode)
        assert_operator value.fetch("cleanupSeconds"), :>=, UploadProcessFixture::DEADLINE * 2
        assert_operator value.fetch("captureSeconds"), :>=, value.fetch("cleanupSeconds")
        if mode.start_with?("immediate")
          assert_equal "elapsed-bound", value.fetch("kind")
          assert_equal 0, value.fetch("deadlinePipeWaits"), value.inspect
          refute value.key?("deadBeforeFallback"), value.inspect
        else
          assert_equal "pass", value.fetch("kind")
          assert_operator value.fetch("deadlineDecisionSeconds"), :>=, UploadProcessFixture::DEADLINE * 0.75
          assert_operator value.fetch("deadlinePipeWaits"), :>, 0
          assert value.fetch("deadBeforeFallback"), value.inspect
        end
        refute value.fetch("watchdogIntervened"), value.inspect
      end
    end

    def test_driver_termination_stops_startup_and_orphan_via_control_eof
      %w[kill-startup kill-descendant].each do |mode|
        value = assert_complete_process_case(mode)
        assert_equal "driver-terminated", value.fetch("kind")
        assert_equal mode, value.fetch("phase")
        assert value.fetch("eofAfterDriverDeath"), value.inspect
      end
    end

    def test_process_observation_rejects_errors_malformed_output_and_foreign_groups
      parse = UploadProcessFixture.method(:parse_state)
      assert_equal "absent", parse.call("", "", 1, 123, 122)
      assert_equal "Z", parse.call("123 122 Z\n", "", 0, 123, 122)
      assert_equal "S+", parse.call(" 123 122 S+\n", "", 0, 123, 122)
      {"R" => :live, "SNXLsl+" => :live, "R<XVLs+" => :live,
       "?" => :indeterminate, "?E" => :indeterminate, "?Es" => :indeterminate,
       "H" => :indeterminate, "X" => :indeterminate, "SE" => :indeterminate,
       "S<XEVLs+" => :indeterminate, "Zs" => :stopped}.each do |token, expected|
        assert_equal token, parse.call("123 122 #{token}\n", "", 0, 123, 122)
        assert_equal expected, UploadProcessFixture.liveness(token)
      end
      assert_equal :stopped, UploadProcessFixture.liveness(parse.call("", "", 1, 123, 122))
      [["", "", 2], ["", "private diagnostic", 1], ["", "", 0],
       ["123 122 S\n", "warning", 0], ["123 122 S\n123 122 Z\n", "", 0],
       ["garbage", "", 0], ["123 999 Z\n", "", 0], ["999 122 Z\n", "", 0],
       ["123 122 bad\n", "", 0], ["123 122 Z\n", "", 1],
       ["123 999 ?E\n", "", 0], ["999 122 ?Es\n", "", 0]].each do |arguments|
        assert_raises(UploadProcessFixture::Failure) { parse.call(*arguments, 123, 122) }
      end
      %w[Zgarbage Sgarbage ZEvil Z? ?E? S? ZE ZEs SXX SEE Sss S++ SN< S<N
         SsL SlL SEVXE S> S- SB].each do |token|
        assert_raises(UploadProcessFixture::Failure) { parse.call("123 122 #{token}\n", "", 0, 123, 122) }
      end
      error = assert_raises(UploadProcessFixture::Failure) do
        UploadProcessFixture.capture_command([RbConfig.ruby, "-e", "sleep 30"], seconds: 0.05)
      end
      assert_equal "process-observation", error.kind
    end

    %w[async signals policies unknown].each do |family|
      define_method("test_process_ownership_#{family}_through_both_real_fixture_callers") do
        value = assert_complete_process_case("ownership-#{family}")
        assert_equal UploadProcessFixture::OwnershipProbe::CASES.fetch(family).length * 2, value.fetch("cases").length
        value.fetch("cases").each do |entry|
          assert_empty entry.fetch("failures"), entry.inspect
          assert_empty entry.fetch("signalRequestsAfterReap"), entry.inspect
          assert entry.fetch("allAcquiredChildrenJoined"), entry.inspect
          assert entry.fetch("firstExceptionPreserved"), entry.inspect
          assert entry.fetch("raisersJoined"), entry.inspect
          assert entry.fetch("handlersRestored"), entry.inspect
          assert entry.fetch("registryInactive"), entry.inspect
        end
      end
    end

    def test_setup_primary_survives_cleanup_failure_and_real_queued_cancellation
      value = assert_complete_process_case("ownership-setup")
      assert_equal 12, value.fetch("cases").length
      value.fetch("cases").each do |entry|
        assert_empty entry.fetch("failures"), entry.inspect
        assert entry.fetch("setupHit"), entry.inspect
        assert entry.fetch("cleanupHit"), entry.inspect
        assert entry.fetch("cleanupFaultRaised"), entry.inspect
        assert_operator entry.fetch("cleanupDepth"), :>, 0
        assert entry.fetch("cleanupErrorReported"), entry.inspect
        assert entry.fetch("originalObjectAndMessagePreserved"), entry.inspect
        assert_equal 0, entry.fetch("spawnAttempts"), entry.inspect
        assert entry.fetch("raiserJoined"), entry.inspect
        assert entry.fetch("handlersRestored"), entry.inspect
        assert entry.fetch("registryInactive"), entry.inspect
        refute entry.fetch("pendingInterrupt"), entry.inspect
        assert_operator entry.fetch("preservedDirectories"), :>, 0
        if entry.fetch("repeatedCancellation")
          assert_equal [Signal.list.fetch("INT")], entry.fetch("osSignalsQueued"), entry.inspect
          assert entry.fetch("asyncRepeatQueued"), entry.inspect
        end
      end
    end

    def test_indeterminate_observations_never_prove_readiness_or_renew_native_death_budget
      value = assert_complete_process_case("ownership-observation")
      entries = value.fetch("cases")
      assert_equal %w[readiness sequence transient-native persistent-native], entries.map { |entry| entry.fetch("case") }
      entries.each { |entry| assert_empty entry.fetch("failures"), entry.inspect }
      assert_equal [false] * 7 + [true, "readiness", "readiness"], entries[0].fetch("readinessResults")
      assert_equal 3, entries[1].fetch("observationCount")
      assert entries[1].fetch("onlyDefiniteStoppedAccepted")
      entries.drop(2).each do |entry|
        assert entry.fetch("independentRealDeathProof"), entry.inspect
        assert_equal 2, entry.fetch("knownNativeIdentities").length
        assert_equal 1, entry.fetch("deadCalls").map { |call| call.fetch("deadline") }.uniq.length
      end
      assert_equal 0, entries[2].fetch("preservedBeforeIndependentProof")
      assert_equal 1, entries[3].fetch("preservedBeforeIndependentProof")
      assert_equal "fixture-cleanup", entries[3].fetch("originalErrorKind")
      assert entries[3].fetch("registryUnresolvedBeforeProof")
      assert_equal %w[active cleanup], entries[3].fetch("deadCalls").map { |call| call.fetch("phase") }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  File.umask(0o077)
  command, directory, mode, control, events = ARGV
  case command
  when "driver"
    exit UploadProcessFixture.driver(directory)
  when "worker"
    exit! UploadProcessFixture.worker(directory, mode, Integer(control, 10), Integer(events, 10))
  when "ownership"
    probe = case mode
    when "setup"
      UploadProcessFixture::SetupFailureProbe.new(directory)
    when "observation"
      UploadProcessFixture::ObservationProbe.new(directory)
    else
      UploadProcessFixture::OwnershipProbe.new(directory, mode)
    end
    puts JSON.generate(probe.execute)
  else
    abort "unknown static process fixture command"
  end
end
