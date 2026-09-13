# frozen_string_literal: true

# Test-only real process fixtures. No production file imports this module.
# Actual O/C/K/V captures, original child waits and independent pipe EOFs.
# Real monotonic cutoffs include startup; no fake clock or implicit waiter.
# Fallback closes a postexec private FIFO writer, never a marker-derived PID.
require "json"
require "tmpdir"
require "tempfile"
require "fileutils"
require "rbconfig"
require "digest"
require_relative "upload_process_ownership"

module UploadProcessFixture
  DEADLINE = 2
  READINESS_LIMIT = 5
  CAPTURE_LIMIT = 8
  DRIVER_LIMIT = 15
  CLEANUP_LIMIT = 5
  WORKER_LIMIT = 30
  OWNERSHIP_LIMIT = 60
  OUTPUT_LIMIT = 32_768
  PROCESS_OBSERVER_KEY = "MOBILE_RELEASE_TEST_PROCESS_OBSERVER"
  # The owner fixes this before entry. Later configuration/canary changes must
  # not select another executable or leak into the read-only observation.
  PROCESS_OBSERVER_SELECTION = ENV[PROCESS_OBSERVER_KEY]&.dup&.freeze
  PROCESS_OBSERVER_LOCALE = {"LANG" => "C", "LC_ALL" => "C"}.freeze
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
  NATIVE_ORDER_MODES = %w[native-order-task-before-caller-interrupt native-order-task-before-caller-system-exit
    native-order-caller-before-task-interrupt native-order-caller-before-task-system-exit
    native-order-cleanup-before-caller-interrupt native-order-cleanup-before-caller-system-exit].freeze
  NATIVE_SETUP_FAILURE_MODES = %w[native-setup-interrupt native-setup-system-exit native-setup-io-error].freeze
  NATIVE_MODES = (%w[native-setup-interrupt native-setup-system-exit native-setup-io-error
                    native-setup-no-cleanup native-setup-second-pipe native-setup-owner-failure
                    native-setup-readiness-failure native-setup-watchdog-unavailable
                    native-setup-watchdog-failure native-setup-post-reap-cancel kill-native-setup] + NATIVE_PRIMARY_PROOFS.keys + NATIVE_ORDER_MODES).freeze
  OWNERSHIP_UNKNOWN_MODES = {
    "ownership-unknown-capture-spawn" => %w[capture unknown-spawn].freeze,
    "ownership-unknown-capture-reap" => %w[capture unknown-reap].freeze,
    "ownership-unknown-capture-echild" => %w[capture unknown-echild].freeze,
    "ownership-unknown-run-spawn" => %w[run unknown-spawn].freeze,
    "ownership-unknown-run-reap" => %w[run unknown-reap].freeze,
    "ownership-unknown-run-echild" => %w[run unknown-echild].freeze,
  }.freeze
  MODES = (%w[inherited delayed-start late-record unready real-deadline
             real-deadline-slow-cleanup immediate-deadline-slow-cleanup
             leader-only no-deadline immediate-deadline kill-startup kill-descendant
             ownership-async ownership-signals ownership-policies
             ownership-setup ownership-observation] + OWNERSHIP_UNKNOWN_MODES.keys + NATIVE_MODES).freeze

  ADAPTER_FAILURE_PREFIX = "MRK_ADAPTER_FAILURE="
  ADAPTER_FAILURE_CLASSES = {"ios" => "IosUploadValidationTest", "android" => "AndroidUploadValidationTest"}.freeze
  ADAPTER_FAILURE_EXPECTED_KINDS = {
    "real-deadline" => "pass", "inherited" => "pass", "delayed-start" => "pass", "late-record" => "pass",
    "unready" => "readiness", "leader-only" => "descendant-alive", "no-deadline" => "capture-watchdog",
    "immediate-deadline" => "elapsed-bound", "real-deadline-slow-cleanup" => "pass",
    "immediate-deadline-slow-cleanup" => "elapsed-bound",
  }.freeze
  ADAPTER_FAILURE_CALLBACK_MODES = {
    "test_deadline_terminates_validator_without_authorizing_upload" => %w[real-deadline],
    "test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits" => %w[inherited],
    "test_descendant_boundary_survives_delayed_start_and_late_parent_record" => %w[delayed-start late-record],
    "test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record" => %w[unready],
    "test_fixture_detects_leader_only_cleanup_and_missing_deadline" => %w[leader-only no-deadline],
    "test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed" => %w[immediate-deadline],
    "test_slow_cleanup_cannot_supply_a_positive_deadline_wait" => %w[real-deadline-slow-cleanup immediate-deadline-slow-cleanup],
  }.each_with_object({}) do |(callback, modes), table|
    ADAPTER_FAILURE_CLASSES.each_value { |name| table["#{name}##{callback}".freeze] = modes.freeze }
  end.freeze
  ADAPTER_FAILURE_FIELDS = %w[schema platform mode expectedKind failedPredicates resultKind driverExitStatus
    retainedDriverErrorCategory retainedDriverErrorCode adapterErrorCategory resultChecks nativeChecks timingChecks].freeze
  ADAPTER_FAILURE_KINDS = %w[pass readiness descendant-alive capture-watchdog elapsed-bound fixture-cleanup
    setup-fixture-fault process-observation process-ownership fixture-result fixture-source fixture-input
    fixture-observation fixture-control signal-policy diagnostic control unexpected].freeze
  ADAPTER_FAILURE_CATEGORIES = {
    "UploadProcessFixture::Failure" => "fixture-error", "MobileReleaseKit::ContractError" => "contract-error",
    "MobileReleaseKit::NativeUploadProcess::Error" => "native-error",
    "MobileReleaseKit::NativeUploadProcess::LifecycleError" => "native-lifecycle-error",
    "MobileReleaseKit::NativeUploadProcess::ProtocolError" => "native-protocol-error",
    "MobileReleaseKit::NativeProcessSpawn::Error" => "native-spawn-error",
    "IOError" => "io-error", "Interrupt" => "interrupt", "SystemExit" => "system-exit",
  }.freeze
  # Only exact source-literal pairs classify the already persisted driver error.
  # This is not necessarily the earliest exercise/native cause: cleanup may own it.
  ADAPTER_FAILURE_CODES = begin
    literals = {
      "oversized adapter source" => "source-size",
      "adapter mutation anchor changed" => "mutation-anchor",
      "complete actual adapter capture contract changed" => "capture-contract",
      "actual adapter result parser call changed" => "parser-contract",
      "actual capture start/cutoff was not observed" => "capture-clock-binding",
      "fixture record missed original capture cutoff" => "record-cutoff",
      "validator record is not bound" => "validator-marker",
      "validator original cutoff expired" => "validator-cutoff",
      "validator was not independently live before the original cutoff" => "validator-live",
      "descendant record is not bound" => "descendant-marker",
      "descendant original cutoff expired" => "descendant-cutoff",
      "descendant was not independently live before the original cutoff" => "descendant-live",
      "actual native READY was not accepted" => "native-ready",
      "fixture deliberately never became ready" => "deliberately-unready",
      "actual validator dispatch contract changed" => "dispatch-contract",
      "descendant was not the actual original fork" => "descendant-fork",
      "no original inherited-pipe observation interval" => "pipe-interval",
      "real inherited data pipes were not blocked" => "pipes-not-blocked",
      "watchdog was not admitted" => "watchdog-admission",
      "unbounded timeout construction" => "timeout-construction-count",
      "group cleanup omission was not bound" => "omission-binding",
      "omission did not leave a live original descendant" => "omission-not-live",
      "adapter capture retained UNKNOWN" => "native-unknown",
      "capture required independent writer watchdog" => "watchdog-intervened",
      "group omission boundary was not actually observed" => "omission-unobserved",
      "omitted native group cleanup required independent writer EOF" => "omission-fallback",
      "actual ready timeout cause was not observed" => "ready-timeout-unobserved",
      "startup consumed the premature-timeout control interval" => "premature-interval-consumed",
      "timeout decision preceded original bound or real blocked data interval" => "elapsed-bound",
      "genuine V0/descendant/EOF-before-COMMIT progress was not observed" => "inherited-progress",
      "actual worker delay was not observed" => "worker-delay",
      "fixture fallback preceded death proof" => "fallback-before-finality",
      "slow cleanup lacks original bound" => "slow-cleanup-budget",
      "fixture watchdog did not join" => "watchdog-join",
      "fixture injector did not join" => "injector-join",
    }
    table = literals.to_h { |message, code| [["UploadProcessFixture::Failure", message].freeze, code] }
    %w[Error LifecycleError ProtocolError].each do |name|
      reasons = name == "ProtocolError" ? %w[protocol] : %w[cancelled deadline parent_lost protocol io creation lifecycle]
      reasons.each do |reason|
        key = ["MobileReleaseKit::NativeUploadProcess::#{name}".freeze, "native capture #{reason} failure".freeze].freeze
        table[key] = "native-#{reason}".freeze
      end
    end
    %w[abi runtime origin symbol spec launch deadline state io fd busy native waitability spawn wait join close unknown].each do |code|
      table[["MobileReleaseKit::NativeProcessSpawn::Error", "native process #{code} failure".freeze].freeze] = "spawn-#{code}".freeze
    end
    table.freeze
  end
  ADAPTER_FAILURE_RESULT_CHECKS = %w[ready stdinClosedAfterReady deadlinePrimarySameObject deadlineResultSameObject
    watchdogStarted watchdogIntervened fallbackUsed deadBeforeFallback nativeFinalityBeforeFallback adapterRejected
    adapterCallObserved captureEntered descendantLiveBeforeRelease inheritedPipeBlockObserved validatorReapedAfterRelease
    commitAfterDataEOF ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined handlersRestored registryInactive
    pendingInterrupt cleanupErrorsEmpty].freeze
  ADAPTER_FAILURE_NATIVE_CHECKS = %w[finalized noProducers settled unknown hooksRestored observerErrorsEmpty].freeze
  ADAPTER_FAILURE_TIMING_CHECKS = %w[runSpanMatchesMode firstTimeoutCutoff selectedTimeoutCutoff blockedDataWaitsPositive
    firstBlockedDataWithinRun captureWithinLimit slowCleanupAtLeastFour captureCoversSlowCleanup].freeze

  class Failure < StandardError
    attr_reader :kind

    def initialize(kind, message)
      @kind = kind
      super(message)
    end
  end

  # Retain the actual failed/disposal-required case through Minitest::Result
  # copying and GC. A later setup cannot silently enter this original domain.
  module CaseGuard
    def run(*arguments, **keywords, &block)
      result = super
      UploadProcessFixture.mark_process_domain_failed!(owner: self) unless failures.empty?
      UploadProcessFixture.retain_process_case!(self) if UploadProcessFixture.domain_disposal_required?
      result
    rescue Exception
      UploadProcessFixture.mark_process_domain_failed!(owner: self)
      raise
    end
  end

  module_function

  def assert_domain_reusable!
    if @process_domain_failed || @domain_disposal_required
      raise Failure.new("fixture-domain", "original process domain requires disposal before another case or owner")
    end
    true
  end

  def retain_process_case!(owner)
    (@retained_fixture_cases ||= {})[owner.object_id] = owner
    nil
  end

  def mark_process_domain_failed!(owner: nil)
    @process_domain_failed = true
    retain_process_case!(owner) if owner
    nil
  end

  def retain_unknown_domain!(root, expected: false)
    @domain_disposal_required = true
    (@unresolved_roots ||= {})[root] = true
    (@expected_unknown_roots ||= {})[root] = true if expected
    nil
  end

  def domain_disposal_required?
    @domain_disposal_required.equal?(true)
  end

  def expected_unknown_retention?(root)
    !!(root && @domain_disposal_required && (@expected_unknown_roots || {}).key?(root) && cleanup_unresolved?(root))
  end

  def clock
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def clock_ns
    Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
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

  # Native, singly owned direct child; real stdout/stderr EOF precedes numeric
  # retirement. This path must not call state(): state itself uses this collector.
  # An explicit overall deadline also caps the ONE cleanup grace.
  def capture_command(argv, seconds: 2, environment: process_observer_environment,
                      cwd: nil, root: nil, deadline: nil, parent_slot: nil)
    assert_domain_reusable!
    unless seconds.is_a?(Numeric) && seconds.finite? && seconds.positive? &&
           (deadline.nil? || deadline.is_a?(Numeric) && deadline.finite?)
      raise Failure.new("process-observation", "invalid observation deadline")
    end
    validate_capture_parent!(parent_slot) if parent_slot
    run_ns = [clock_ns + (seconds.to_r * 1_000_000_000).floor, deadline && (deadline.to_r * 1_000_000_000).floor,
              parent_slot&.run_deadline_ns].compact.min
    hard_ns = [run_ns + CLEANUP_LIMIT * 1_000_000_000, deadline && (deadline.to_r * 1_000_000_000).floor,
               parent_slot&.hard_cleanup_deadline_ns].compact.min
    value = command_lifetime(parent_slot: parent_slot, hard_deadline_ns: hard_ns) do |scope|
      directory = nil
      child = nil
      files = [OwnedChild::ControlLease.new, OwnedChild::ControlLease.new]
      record = {"files" => files, "child" => nil, "directory" => nil, "directoryState" => :unattempted, "errors" => []}
      (@collector_records ||= {})[record.object_id] = record
      cleanup_complete = false
      begin
        record["directoryState"] = :acquiring
        Thread.handle_interrupt(Exception => :never) do
          directory = Dir.mktmpdir("mrk-process-observation-", root)
          record["directory"] = directory
          record["directoryState"] = :published
          directory = File.realpath(directory)
          record["directoryIdentity"] = OwnedChild.directory_identity(directory)
          record["directoryState"] = :canonical
        end
        child = OwnedChild.new(root: directory, deadline_ns: run_ns, hard_deadline_ns: hard_ns, parent_slot: parent_slot)
        record["child"] = child
        files.zip(%w[stdout stderr]).each do |lease, name|
          lease.acquire { File.open(File.join(directory, name), File::WRONLY | File::CREAT | File::EXCL, 0o600) }
        end
        scope.active do
          child.start(environment, *argv, out: :pipe, err: :pipe, in: File::NULL,
                      unsetenv_others: true, pgroup: true, chdir: cwd)
          readers = [child.stdout_reader, child.stderr_reader]
          outputs = [+"".b, +"".b]
          eof = [false, false]
          until eof.all?
            remaining = run_ns - clock_ns
            raise Failure.new("process-observation", "process observation deadline expired") unless remaining.positive?
            readers.each_with_index do |io, index|
              next if eof[index]
              chunk = child.read_stream(index.zero? ? :out : :err)
              if chunk.nil?
                eof[index] = true # Actual independent EOF, never a closed? flag.
              elsif chunk.is_a?(String)
                outputs[index] << chunk
                files[index].io.write(chunk)
                raise Failure.new("diagnostic", "oversized process observation") if outputs[index].bytesize > OUTPUT_LIMIT
              elsif chunk != :wait_readable
                raise Failure.new("process-observation", "invalid observation stream result")
              end
            end
            IO.select(readers.each_with_index.reject { |_io, index| eof[index] }.map(&:first), nil, nil,
                      [10_000_000, [run_ns - clock_ns, 0].max].min / 1_000_000_000.0) unless eof.all?
          end
          child.retire_numeric!
          loop do
            remaining = run_ns - clock_ns
            raise Failure.new("process-observation", "process observation wait deadline expired") unless remaining.positive?
            break if child.poll_wait
            sleep [remaining, 10_000_000].min / 1_000_000_000.0
          end
          unless child.status.exited?
            raise Failure.new("process-observation", "process observer did not exit normally")
          end
          [*outputs, child.status.exitstatus]
        end
      rescue Exception => error
        parent_slot&.cancel!(error: error, reason_code: "lifecycle") # Before any cleanup, including pre-creator failures.
        scope.remember(error)
        raise
      ensure
        scope.cleanup do
          operations = [-> { child&.stop }] + files.map { |lease| -> { lease.close_once } }
          operations.each do |operation|
            begin
              operation.call
            rescue Exception => error
              parent_slot&.record_cleanup_error(error) # Shared first boundary BEFORE another exact close.
              record["errors"] << error
              scope.remember(error)
            end
          end
          cleanup_complete = record["directoryState"] == :canonical && (child.nil? || child.complete? && child.streams_complete?) &&
            files.all? { |lease| %i[unattempted closed].include?(lease.state) } && record["errors"].empty?
          raise record["errors"].first unless record["errors"].empty?
        end
        scope.cleanup do
          begin
            if directory && cleanup_complete
              unless OwnedChild.directory_identity(directory) == record.fetch("directoryIdentity")
                raise Failure.new("fixture-cleanup", "observation directory identity changed")
              end
              FileUtils.remove_entry(directory)
              @collector_records.delete(record.object_id)
            elsif directory
              (@unresolved_roots ||= {})[root] = true
              retain_unknown_domain!(root) if record["directoryState"] != :canonical ||
                child && !child.complete? || files.any? { |lease| !%i[unattempted closed].include?(lease.state) }
              atomic_json(File.join(directory, "ownership.json"), child ? child.provenance : {"phase" => "not_constructed"})
              warn "Preserve unknown process observation: #{directory}"
            elsif record["directoryState"] == :unattempted
              @collector_records.delete(record.object_id)
            else
              (@unresolved_roots ||= {})[root] = true
              retain_unknown_domain!(root)
              warn "Preserve unresolved process observation acquisition"
            end
          rescue Exception => error
            parent_slot&.record_cleanup_error(error)
            (@unresolved_roots ||= {})[root] = true
            retain_unknown_domain!(root) if record["directoryState"] != :canonical ||
              child && !child.complete? || files.any? { |lease| !%i[unattempted closed].include?(lease.state) }
            record["errors"] << error
            raise
          end
        end
      end
    end
    # Cleanup/finality remain real even when a receipt or close arrived late.
    # Do not accept the tuple merely because cleanup finished in the grace.
    begin
      validate_capture_parent!(parent_slot) if parent_slot
      raise Failure.new("process-observation", "process observation result arrived after deadline") unless clock_ns < run_ns
    rescue Exception => error
      parent_slot&.cancel!(error: error, reason_code: "lifecycle")
      raise(parent_slot&.first_error || error)
    end
    value
  end

  # Only an already-owned actual capture task can use the nested command path.
  # It has LOCAL error/mask/cleanup depth; it never changes the main traps or
  # policy registry. Child creation shares the actual parent's FailureRecord.
  def validate_capture_parent!(parent_slot)
    scope = @cancellation_scope
    helper = MobileReleaseKit::NativeUploadProcess if defined?(MobileReleaseKit::NativeUploadProcess)
    observation = CaptureObservation.current
    unless scope && scope.cleanup_depth.zero? && helper && parent_slot.instance_of?(helper::TaskSlot) &&
           observation && observation.session && observation.session.capture_slot.equal?(parent_slot) &&
           parent_slot.thread.equal?(Thread.current) && parent_slot.caller.equal?(Thread.main) &&
           parent_slot.caller.alive? && !parent_slot.caller.pending_interrupt? &&
           !parent_slot.cancelled? && !parent_slot.launch_retired? &&
           helper.monotonic_ns < parent_slot.run_deadline_ns
      raise Failure.new("signal-policy", "nested observer lacks active original capture custody")
    end
    parent_slot
  end

  def command_lifetime(parent_slot:, hard_deadline_ns:)
    return lifetime(deadline_ns: hard_deadline_ns) { |frame| yield frame } if Thread.current.equal?(Thread.main) && parent_slot.nil?
    validate_capture_parent!(parent_slot)
    cutoff = lambda do
      [hard_deadline_ns, parent_slot.cleanup_deadline_ns].min
    end
    record_error = lambda do |error|
      parent_slot.cancel!(error: error, reason_code: "lifecycle")
      parent_slot.first_error || error
    end
    local = Lifetime.new(CancellationScope.new, deadline_ns: cutoff, error_recorder: record_error)
    value = nil
    begin
      Thread.handle_interrupt(Exception => :never) do
        begin
          value = yield local
        rescue Exception => error
          parent_slot.cancel!(error: error, reason_code: "lifecycle")
          local.remember(parent_slot.first_error || error)
        ensure
          local.finishing { local.report }
          local.finishing { local.drain_pending }
        end
      end
    rescue Exception => error
      parent_slot.cancel!(error: error, reason_code: "lifecycle")
      local.remember(parent_slot.first_error || error)
    end
    raise local.primary if local.primary
    value
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

  def process_observer_environment
    PROCESS_OBSERVER_SELECTION.nil? ? {} : {PROCESS_OBSERVER_KEY => PROCESS_OBSERVER_SELECTION}
  end

  def owned_fixture_directory(directory)
    unless directory.is_a?(String) && directory.bytesize.between?(1, 4096) &&
           directory == File.absolute_path(directory) && File.realpath(directory) == directory
      raise Failure.new("fixture-cleanup", "fixture directory is not canonical")
    end
    value = File.lstat(directory) # A symlink is not an owned case directory.
    unless value.directory? && value.uid == Process.uid && (value.mode & 0o7777) == 0o700 &&
           value.nlink.instance_of?(Integer) && value.nlink.positive?
      raise Failure.new("fixture-cleanup", "fixture directory is not private and owned")
    end
    value
  end

  def driver_environment(directory)
    owned_fixture_directory(directory)
    process_observer_environment.merge("TMPDIR" => directory, "TMP" => directory, "TEMP" => directory)
  end

  def fixture_directory_identity(value)
    %i[dev ino mode uid gid nlink size mtime ctime].map { |name| value.public_send(name) }
  end

  # Pin the no-follow directory identity before streaming bounded entry names.
  # The enumerator's borrowed descriptor must match BEFORE any names are read;
  # no content/PID records are opened and no recursive traversal is performed.
  def fixture_entry_names(directory)
    expected = fixture_directory_identity(owned_fixture_directory(directory))
    File.open(directory, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |pin|
      raise Failure.new("fixture-cleanup", "fixture directory changed before enumeration") unless fixture_directory_identity(pin.stat) == expected
      Dir.open(directory, encoding: Encoding::BINARY) do |entries|
        borrowed = IO.for_fd(entries.fileno, autoclose: false) # Dir owns this FD; never close it through IO.
        raise Failure.new("fixture-cleanup", "fixture directory enumeration changed identity") unless fixture_directory_identity(borrowed.stat) == expected
        names = []
        entries.each_child do |name|
          unless names.length < 256 && name.is_a?(String) && name.bytesize.between?(1, 255) &&
                 /\A[\x20-\x7e]+\z/.match?(name) && !name.include?("/") && !%w[. ..].include?(name) && !names.include?(name)
            raise Failure.new("fixture-cleanup", "fixture directory listing is oversized or ambiguous")
          end
          names << name
        end
        unless [pin.stat, borrowed.stat, owned_fixture_directory(directory)].all? { |value| fixture_directory_identity(value) == expected }
          raise Failure.new("fixture-cleanup", "fixture directory changed during enumeration")
        end
        names
      end
    end
  rescue SystemCallError, IOError, ArgumentError
    raise Failure.new("fixture-cleanup", "fixture directory enumeration failed")
  end

  def assert_fixture_cleanup!(directory, root:, layout:)
    names = fixture_entry_names(directory)
    case layout
    when :driver
      raise Failure.new("fixture-cleanup", "unresolved observer scratch prevents fixture removal") if names.any? { |name| name.start_with?("mrk-process-observation-", "mrk-owned-launch-") }
    when :joined_case
      # Direct scratch belongs to independently joined SAME-VM reservations.
      # Those reservations do not cover a nested driver's observer children.
      names.grep(/\Anative-process-/).each do |name|
        nested = fixture_entry_names(File.join(directory, name))
        raise Failure.new("fixture-cleanup", "nested observer scratch prevents case removal") if nested.any? { |entry| entry.start_with?("mrk-process-observation-", "mrk-owned-launch-") }
      end
    when :probe
      prefix = /\A(?:ownership-(?:capture|run)-|setup-(?:capture|run|ownership)-|observation-native-)/
      raise Failure.new("fixture-cleanup", "retained proof case prevents probe removal") if names.any? { |name| prefix.match?(name) }
    else
      raise Failure.new("fixture-cleanup", "unknown fixed fixture cleanup layout")
    end
    true
  rescue Exception
    (@unresolved_roots ||= {})[root] = true
    raise
  end

  def remove_fixture_directory(directory, root:, layout:)
    assert_fixture_cleanup!(directory, root: root, layout: layout)
    FileUtils.remove_entry(directory)
  rescue Exception
    (@unresolved_roots ||= {})[root] = true
    raise
  end

  # Shared only with the native raw-proof collector and its inert contract.
  # A caught raw failure may not later clear the retained-evidence latch.
  module RawCaptureCleanup
    def check_raw_capture_scratch!(directory)
      UploadProcessFixture.assert_fixture_cleanup!(directory, root: @root, layout: :driver)
    rescue Exception
      @retain_raw_evidence = true
      raise
    end

    def finish_raw_proof_copies!
      if UploadProcessFixture.cleanup_unresolved?(@root)
        @retain_raw_evidence = true
        raise Failure.new("fixture-cleanup", "raw observer cleanup remains unresolved")
      end
      @retain_raw_evidence = false
    end
  end

  def validate_process_observer_path(path, darwin:)
    return nil if path.nil? && !darwin
    unless darwin && path.is_a?(String) && path.ascii_only? && path.bytesize.between?(1, 4096) &&
           !path.include?("\0") && !path.include?("\n") && path == File.absolute_path(path) &&
           File.basename(path) == "process-observer" && File.basename(File.dirname(path)) == "bootstrap" &&
           File.dirname(File.dirname(File.dirname(path))) == "/private/tmp"
      raise Failure.new("process-observation", "missing or invalid owner-fixed process observer")
    end
    file = File.lstat(path)
    parents = [File.dirname(path), File.dirname(File.dirname(path))].map { |name| File.lstat(name) }
    unless File.realpath(path) == path && file.file? && file.uid.zero? && file.nlink == 1 &&
           (file.mode & 0o7777) == 0o555 && File.executable?(path) &&
           parents.all? { |parent| parent.directory? && parent.uid.zero? && (parent.mode & 0o6022).zero? }
      raise Failure.new("process-observation", "owner-fixed process observer is not immutable")
    end
    path
  rescue SystemCallError, ArgumentError
    raise Failure.new("process-observation", "owner-fixed process observer is unavailable")
  end

  def process_observer_path
    # Requiring this only on actual observation lets non-observing workers load
    # the fixture with their unchanged production environment. A scrubbed Mac
    # driver that loses its selector must fail, never downgrade to system ps.
    validate_process_observer_path(PROCESS_OBSERVER_SELECTION, darwin: RUBY_PLATFORM.include?("darwin"))
  end

  def observation_executable
    process_observer_path || "/bin/ps"
  end

  def parse_process_observer(stdout, stderr, status, pid, group, uid: Process.uid, gid: Process.gid)
    valid_identity = pid.is_a?(Integer) && pid.between?(2, 2_147_483_647) &&
                     group.is_a?(Integer) && group.between?(2, 2_147_483_647) &&
                     uid.is_a?(Integer) && uid.between?(1, 4_294_967_295) &&
                     gid.is_a?(Integer) && gid.between?(0, 4_294_967_295)
    unless valid_identity && stdout.is_a?(String) && stdout.ascii_only? && stdout.bytesize <= 512 &&
           stderr == "" && status.is_a?(Integer) && status.zero?
      raise Failure.new("process-observation", "process observer failed or returned unsupported output")
    end
    absent = /\AMRK_PROCESS_V1 absent ([1-9][0-9]*)\n\z/.match(stdout)
    return "absent" if absent && Integer(absent[1], 10) == pid
    number = "(?:0|[1-9][0-9]*)"
    match = /\AMRK_PROCESS_V1 present ((?:#{number} ){9}#{number}) (live|indeterminate|zombie)\n\z/.match(stdout)
    if match
      values = match[1].split(" ").map { |value| Integer(value, 10) }
      target, pgid, ruid, euid, suid, rgid, egid, sgid, bsd_status, inexit = values
      expected_state = if bsd_status == 5
        "zombie" # BSD SZOMB wins even when the independent INEXIT flag is set.
      elsif inexit == 1 || ![2, 3, 4].include?(bsd_status)
        "indeterminate"
      else
        "live"
      end
      if target == pid && pgid == group && [ruid, euid, suid] == [uid] * 3 &&
         [rgid, egid, sgid] == [gid] * 3 && bsd_status.between?(0, 4_294_967_295) &&
         [0, 1].include?(inexit) && match[2] == expected_state
        return expected_state
      end
    end
    # Denied/kernel, denied/identity and generic error are all failures, never
    # an invented absent result. Do not echo arbitrary observer diagnostics.
    raise Failure.new("process-observation", "process observer returned malformed or incorrectly scoped metadata")
  end

  def observer_liveness(value)
    {"live" => :live, "indeterminate" => :indeterminate,
     "zombie" => :stopped, "absent" => :stopped}.fetch(value)
  end

  def state(pid, group, seconds: 2, parent_slot: nil, deadline: nil)
    observer = process_observer_path
    custody = parent_slot ? {parent_slot: parent_slot} : {}
    custody[:deadline] = deadline unless deadline.nil?
    if observer
      result = capture_command([observer, pid.to_s], seconds: seconds, environment: PROCESS_OBSERVER_LOCALE, **custody)
      observer_liveness(parse_process_observer(*result, pid, group))
    else
      result = capture_command(["/bin/ps", "-o", "pid=,pgid=,stat=", "-p", pid.to_s], seconds: seconds,
                               environment: PROCESS_OBSERVER_LOCALE, **custody)
      liveness(parse_state(*result, pid, group))
    end
  end

  def alive?(pid, group)
    state(pid, group) == :live
  end

  def ready?(pid, group, seconds: 2, parent_slot: nil, deadline: nil)
    custody = {}
    custody[:parent_slot] = parent_slot if parent_slot
    custody[:deadline] = deadline unless deadline.nil?
    value = state(pid, group, seconds: seconds, **custody)
    raise Failure.new("readiness", "fixture stopped before readiness") if value == :stopped
    value == :live # Valid indeterminate state proves neither readiness nor death.
  end

  def dead!(pid, group, deadline: clock + CLEANUP_LIMIT, kind: "fixture-cleanup")
    loop do
      remaining = deadline - clock
      raise Failure.new(kind, "#{kind} deadline expired") unless remaining.positive?
      value = state(pid, group, seconds: [remaining, 2].min, deadline: deadline)
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
    yield clock_ns if block_given? # The ORIGINAL read(nil), not a later liveness sample.
    true
  end

  def worker(directory, mode)
    owned_fixture_directory(directory)
    config = JSON.parse(OwnedChild.bounded_file(File.join(directory, "worker-control.json")))
    unless config.keys.sort == %w[identity version] && config["version"] == 1
      raise Failure.new("fixture-control", "invalid postexec worker control")
    end
    control = File.open(File.join(directory, "worker-control.fifo"), File::RDONLY | File::NONBLOCK | File::NOFOLLOW)
    control.close_on_exec = true
    unless control.close_on_exec? && control.stat.pipe? && OwnedChild.identity(control.stat) == config.fetch("identity")
      raise Failure.new("fixture-control", "worker control identity changed")
    end
    emit = lambda do |kind, name = kind|
      record = {"kind" => kind, "pid" => Process.pid, "group" => Process.getpgrp, "sid" => Process.getsid(0)}
      if kind == "child-ready"
        unless STDOUT.stat.pipe? && STDERR.stat.pipe?
          raise Failure.new("fixture-control", "descendant does not own the actual data pipes")
        end
        record["stdout"], record["stderr"] = [STDOUT, STDERR].map { |io| OwnedChild.identity(io.stat) }
      end
      record["pid"] = "not-a-pid" if mode == "native-setup-readiness-failure" && kind == "leader-ready"
      OwnedChild.write_record(File.join(directory, "#{name}.json"), record)
    end
    delay = lambda do |stage|
      started = clock_ns
      return true if control_wait(control, 0.3)
      OwnedChild.write_record(File.join(directory, "delay.json"),
        {"stage" => stage, "startNs" => started, "endNs" => clock_ns})
      false
    end
    await_eof = lambda do |name|
      actual = nil
      eof = control_wait(control, WORKER_LIMIT) do |at|
        actual = {"version" => 1, "eof" => true, "controlReadNil" => true,
          "readNilNs" => at, "pid" => Process.pid, "group" => Process.getpgrp, "sid" => Process.getsid(0),
          "fifoIdentity" => OwnedChild.identity(control.stat)}
      end
      OwnedChild.write_record(File.join(directory, "#{name}-eof.json"), actual || {"version" => 1, "eof" => eof})
      eof
    end
    emit.call("entered")
    if %w[unready kill-startup].include?(mode)
      emit.call("startup-wait")
      await_eof.call("leader")
      return 0
    end
    emit.call("leader-ready")
    leader_mode = NATIVE_MODES.include?(mode) || %w[real-deadline immediate-deadline no-deadline].include?(mode.delete_suffix("-slow-cleanup"))
    if leader_mode
      await_eof.call("leader")
      return 0
    end
    return 0 if mode == "delayed-start" && delay.call("before_fork")
    child = Process.fork do
      emit.call("child-ready")
      await_eof.call("child")
      Process.exit!(0)
    end
    OwnedChild.write_record(File.join(directory, "fork-return.json"),
      {"parent" => Process.pid, "child" => child, "group" => Process.getpgrp})
    cutoff = clock + WORKER_LIMIT
    until File.file?(File.join(directory, "release-validator.json"))
      return 0 if control_wait(control, 0.01)
      raise Failure.new("fixture-control", "descendant was never released") if clock >= cutoff
    end
    release = JSON.parse(OwnedChild.bounded_file(File.join(directory, "release-validator.json")))
    unless release == {"parent" => Process.pid, "child" => child, "group" => Process.getpgrp}
      raise Failure.new("fixture-control", "descendant release was not the original fork")
    end
    return 0 if mode == "late-record" && delay.call("after_release")
    # A deliberately late legacy file never supplies custody/readiness.
    atomic_json(File.join(directory, "legacy-child.json"), {"pid" => child})
    0
  end

  def validate_request!(platform, mode, parameters)
    valid = parameters.instance_of?(Hash) && if NATIVE_MODES.include?(mode)
      platform == "native" && parameters == {}
    else
      MODES.include?(mode) && %w[ios android].include?(platform)
    end
    raise Failure.new("fixture-input", "unknown or mismatched fixture mode/platform/parameters") unless valid
  end

  def no_native_child?(_mode, owner, result, _proof)
    snapshot = result && result["nativeObservation"]
    snapshot && snapshot["version"] == 1 && snapshot["noProducers"].equal?(true) &&
      snapshot["settled"].equal?(true) && !snapshot["unknown"] && snapshot["hooksRestored"].equal?(true) &&
      snapshot["custodian"] == {"state" => "not_attempted"} && owner["finality"] == "no_producers" &&
      owner.values_at("custodian", "keeper", "validator").all? { |record| record == {"state" => "not_attempted"} } &&
      owner["group"] == {"state" => "not_created"} && owner["processes"] == []
  end

  # Detached helper identities authorize ONLY bounded read-only observations.
  # No record here is ever adopted as a Child or passed to Process.kill.
  def owner_processes!(owner)
    unless owner.is_a?(Hash) && owner.keys.sort == %w[custodian finality group keeper phase processes validator version] &&
           owner["version"].instance_of?(Integer) && owner["version"] == 2 &&
           %w[active finalized no_producers unknown].include?(owner["finality"]) &&
           owner["phase"].is_a?(String) && owner["phase"].bytesize.between?(1, 64) &&
           owner["processes"].is_a?(Array) && owner["processes"].length <= 4
      raise Failure.new("fixture-result", "invalid native owner observation")
    end
    processes = owner.fetch("processes")
    roles = %w[custodian keeper validator descendant]
    unless processes.all? do |item|
      item.is_a?(Hash) && item.keys.sort == %w[group pid role] && roles.include?(item["role"]) &&
        %w[pid group].all? { |key| item[key].instance_of?(Integer) && item[key].between?(2, 2_147_483_647) }
    end
      raise Failure.new("fixture-result", "unbound native process observation")
    end
    unless processes.map { |item| item["role"] }.uniq.length == processes.length &&
           processes.map { |item| item["pid"] }.uniq.length == processes.length
      raise Failure.new("fixture-result", "duplicate native observation identity")
    end
    by_role = processes.to_h { |item| [item.fetch("role"), item] }
    custodian, keeper, validator, descendant = by_role.values_at(*roles)
    if custodian && custodian["pid"] != custodian["group"] ||
       keeper && (!custodian || keeper["group"] != custodian["pid"]) ||
       validator && (!keeper || validator["group"] != keeper["pid"]) ||
       descendant && (!validator || descendant["group"] != validator["group"])
      raise Failure.new("fixture-result", "native observation graph changed")
    end
    processes
  end

  def observe_owner_death!(owner, deadline:, root: nil)
    owner_processes!(owner).each do |item|
      dead!(item.fetch("pid"), item.fetch("group"), deadline: deadline)
    end
    true
  rescue Exception
    # A failed actual role observation is retained, not a licence to acquire a
    # fresh observer with a new budget. The ensure path may only recheck an
    # already exhausted original cutoff (dead! rejects before any acquisition).
    retain_unknown_domain!(root)
    raise
  end

  # Physical cleanup only. The same original observation is required on the
  # normal path and when a caller cancellation arrives after the driver wait.
  # Neither this predicate nor a detached process observation accepts a result.
  def native_owner_finality?(mode, owner, result, proof = nil)
    snapshot = result && result["nativeObservation"]
    snapshot && snapshot["version"] == 1 && snapshot["hooksRestored"] == true &&
      snapshot["observerErrors"] == [] && !snapshot["unknown"] &&
      ((snapshot["finalized"] && snapshot["settled"] && owner["finality"] == "finalized" &&
        owner["custodian"] == snapshot["custodian"] && snapshot["final"] &&
        %w[keeper validator group].all? { |role| owner[role] == snapshot["final"][role] }) ||
       no_native_child?(mode, owner, result, proof))
  end

  def validate_signal_observation!(platform, mode, enabled)
    unless (enabled.equal?(false) || enabled.equal?(true)) &&
           (!enabled || (platform == "native" && NativeSignalProbe::MODES.include?(mode)))
      raise Failure.new("fixture-input", "invalid native signal observation request")
    end
  end

  # Called only by the original compound primary-proof rejection below. Keep
  # private, already-read values in the caller's fresh optional Hash; nothing
  # is projected before the actual rejection survives the complete lifetime.
  def reject_native_primary_proof!(mode:, proof:, result:, status:, deadline_ns:, state:)
    original = Failure.new("fixture-result", "native primary proof rejected")
    if state
      state[:rejection] = original
      state[:mode] = mode
      state[:deadline_ns] = deadline_ns
      state[:proof] = proof
      state[:result] = result
      state[:status] = status
    end
    raise original
  end

  def reject_native_order_proof!(mode:, proof:, result:, status:, expected_sources:, deadline_ns:, state:)
    original = Failure.new("fixture-result", "native order proof rejected")
    if state
      state[:rejection] = original
      state[:mode] = mode
      state[:deadline_ns] = deadline_ns
      state[:proof] = proof
      state[:result] = result
      state[:status] = status
      state[:expected_sources] = expected_sources
    end
    raise original
  end

  def reject_native_setup_result!(mode:, result:, status:, deadline_ns:, state:)
    original = Failure.new("fixture-result", "unexpected fixture result kind/status")
    if state && NATIVE_SETUP_FAILURE_MODES.include?(mode)
      state[:rejection] = original
      state[:mode] = mode
      state[:deadline_ns] = deadline_ns
      state[:result] = result
      state[:status] = status
    end
    raise original
  end

  def adapter_failure_mode?(platform, mode)
    platform.instance_of?(String) && mode.instance_of?(String) &&
      ADAPTER_FAILURE_CLASSES.key?(platform) && ADAPTER_FAILURE_EXPECTED_KINDS.key?(mode)
  end

  def reject_adapter_result!(platform:, mode:, result:, status:, deadline_ns:, state:)
    original = Failure.new("fixture-result", "unexpected fixture result kind/status")
    if state.instance_of?(Hash) && adapter_failure_mode?(platform, mode)
      state[:rejection] = original
      state[:platform] = platform
      state[:mode] = mode
      state[:deadline_ns] = deadline_ns
      state[:result] = result
      state[:status] = status
    end
    raise original
  end

  def adapter_failure_line(platform:, mode:, result:, status:)
    return unless adapter_failure_mode?(platform, mode) && result.instance_of?(Hash)

    code = status.exitstatus
    return unless code.instance_of?(Integer) && code.between?(0, 255)

    expected = ADAPTER_FAILURE_EXPECTED_KINDS.fetch(mode)
    failed = []
    failed << "result-kind" unless result["kind"] == expected
    failed << "driver-status" unless code == (expected == "pass" ? 0 : 1)
    return if failed.empty?

    kind = if !result.key?("kind")
      "missing"
    elsif !result["kind"].instance_of?(String)
      "invalid"
    else
      ADAPTER_FAILURE_KINDS.include?(result["kind"]) ? result["kind"] : "other"
    end
    category = lambda do |key|
      next "missing" unless result.key?(key)
      value = result.fetch(key)
      next "none" if value.nil?
      next "invalid" unless value.instance_of?(String)
      ADAPTER_FAILURE_CATEGORIES.fetch(value, "other")
    end
    error_code = if !result.key?("errorClass") || !result.key?("error")
      "missing"
    elsif result["errorClass"].nil? && result["error"].nil?
      "none"
    elsif !result["errorClass"].instance_of?(String) || !result["error"].instance_of?(String)
      "invalid"
    else
      ADAPTER_FAILURE_CODES.fetch([result["errorClass"], result["error"]], "other")
    end
    check = lambda do |record, key, absent: false, empty: false|
      next "missing" if absent
      next "invalid" unless record.instance_of?(Hash)
      next "missing" unless record.key?(key)
      value = record.fetch(key)
      if empty
        value.instance_of?(Array) ? value.empty? : "invalid"
      else
        value.equal?(true) || value.equal?(false) ? value : "invalid"
      end
    end
    result_checks = ADAPTER_FAILURE_RESULT_CHECKS.to_h do |key|
      [key, key == "cleanupErrorsEmpty" ? check.call(result, "cleanupErrors", empty: true) : check.call(result, key)]
    end
    native_checks = ADAPTER_FAILURE_NATIVE_CHECKS.to_h do |key|
      empty = key == "observerErrorsEmpty"
      [key, check.call(result["nativeObservation"], empty ? "observerErrors" : key,
        absent: !result.key?("nativeObservation"), empty: empty)]
    end
    # Only relations on already recorded operands; no fresh clock/native query.
    timestamp = ->(value) { value.instance_of?(Integer) && value.positive? && value <= (1 << 63) - 1 }
    duration = lambda do |value|
      (value.instance_of?(Integer) || value.instance_of?(Float)) && value.finite? && value >= 0
    end
    measure = lambda do |keys, valid, &relation|
      next "missing" unless keys.all? { |key| result.key?(key) }
      values = keys.map { |key| result.fetch(key) }
      next "invalid" unless values.all? { |value| valid.call(value) }
      relation.call(*values)
    end
    cutoff_relation = lambda do |key|
      measure.call(["nativeStartedNs", "nativeRunDeadlineNs", key], timestamp) do |start, cutoff, decision|
        if cutoff <= start then "invalid"
        elsif decision < start then "before-start"
        elsif decision < cutoff then "before-cutoff"
        else "at-or-after-cutoff"
        end
      end
    end
    timing_checks = {
      "runSpanMatchesMode" => measure.call(%w[nativeStartedNs nativeRunDeadlineNs], timestamp) { |start, cutoff|
        cutoff > start ? cutoff - start == (mode == "no-deadline" ? 10 : DEADLINE) * 1_000_000_000 : "invalid"
      },
      "firstTimeoutCutoff" => cutoff_relation.call("firstTimeoutDecisionNs"),
      "selectedTimeoutCutoff" => cutoff_relation.call("selectedTimeoutNs"),
      "blockedDataWaitsPositive" => measure.call(["blockedDataWaits"], ->(value) { value.instance_of?(Integer) && value >= 0 }) { |count| count.positive? },
      "firstBlockedDataWithinRun" => measure.call(%w[nativeStartedNs nativeRunDeadlineNs firstBlockedDataNs], timestamp) { |start, cutoff, first|
        cutoff > start ? first >= start && first < cutoff : "invalid"
      },
      "captureWithinLimit" => measure.call(["captureSeconds"], duration) { |seconds| seconds < CAPTURE_LIMIT },
      "slowCleanupAtLeastFour" => measure.call(["slowCleanupSeconds"], duration) { |seconds| seconds >= 4 },
      "captureCoversSlowCleanup" => measure.call(%w[captureSeconds slowCleanupSeconds], duration) { |capture, cleanup| capture >= cleanup },
    }
    line = "#{ADAPTER_FAILURE_PREFIX}#{JSON.generate({"schema" => 1, "platform" => platform, "mode" => mode,
      "expectedKind" => expected, "failedPredicates" => failed, "resultKind" => kind, "driverExitStatus" => code,
      "retainedDriverErrorCategory" => category.call("errorClass"), "retainedDriverErrorCode" => error_code,
      "adapterErrorCategory" => category.call("adapterErrorClass"), "resultChecks" => result_checks,
      "nativeChecks" => native_checks, "timingChecks" => timing_checks})}\n"
    line.freeze if line.ascii_only? && line.bytesize <= 2048
  end

  def report_adapter_failure(state, original, platform:, mode:, callback:)
    return unless state.instance_of?(Hash) && original.instance_of?(Failure) && state[:rejection].equal?(original)
    return if state[:report_attempted]

    state[:report_attempted] = true
    return unless adapter_failure_mode?(platform, mode) && state[:platform].instance_of?(String) &&
      state[:platform] == platform && state[:mode].instance_of?(String) && state[:mode] == mode &&
      callback.instance_of?(String) && ADAPTER_FAILURE_CALLBACK_MODES.fetch(callback, []).include?(mode) &&
      callback.start_with?("#{ADAPTER_FAILURE_CLASSES.fetch(platform)}#")

    deadline_ns = state.fetch(:deadline_ns)
    return unless deadline_ns.instance_of?(Integer) && deadline_ns.positive? && clock_ns < deadline_ns

    line = adapter_failure_line(platform: platform, mode: mode, result: state.fetch(:result), status: state.fetch(:status))
    return unless line && clock_ns < deadline_ns

    state[:write_attempted] = true
    state[:write_complete] = STDERR.write(line) == line.bytesize
    nil
  rescue Exception => diagnostic_error
    begin
      state[:diagnostic_error] ||= diagnostic_error if state.instance_of?(Hash)
    rescue Exception
      nil # Partial/frozen optional custody must not replace the escaping primary.
    end
    nil
  end

  def run(platform:, root:, parameters:, mode:, observe_signals: false, deadline_ns: nil,
          primary_failure_state: nil, order_failure_state: nil, setup_failure_state: nil, adapter_failure_state: nil)
    assert_domain_reusable!
    validate_request!(platform, mode, parameters)
    validate_signal_observation!(platform, mode, observe_signals)
    unless deadline_ns.nil? || deadline_ns.instance_of?(Integer) && deadline_ns > clock_ns
      raise Failure.new("fixture-input", "invalid original fixture cutoff")
    end
    if observe_signals && !NativeSignalProbe.current
      return NativeSignalProbe.observe_parent(root, mode) do
        run(platform: platform, root: root, parameters: parameters, mode: mode,
            observe_signals: true, deadline_ns: deadline_ns, primary_failure_state: primary_failure_state,
            order_failure_state: order_failure_state, setup_failure_state: setup_failure_state,
            adapter_failure_state: adapter_failure_state)
      end
    end
    if observe_signals && !NativeSignalProbe.current.parent_for?(root, mode)
      raise Failure.new("fixture-input", "native signal observer scope does not match the run")
    end
    return run_ownership_probe(platform: platform, root: root, parameters: parameters, mode: mode,
                               deadline_ns: deadline_ns) if mode.start_with?("ownership-")
    run_ns = [clock_ns + DRIVER_LIMIT * 1_000_000_000, deadline_ns].compact.min
    hard_ns = [run_ns + CLEANUP_LIMIT * 1_000_000_000, deadline_ns].compact.min
    accepted = lifetime(deadline_ns: hard_ns) do |scope|
      directory = child = result = proof = order_proof = owner = death_deadline = nil
      transcripts = [OwnedChild::ControlLease.new, OwnedChild::ControlLease.new]
      held_writer = OwnedChild::ControlLease.new if ContainmentEvidence::HARD_LOSS.include?(mode)
      known_dead = native_final = false
      record = {"directory" => nil, "directoryState" => :unattempted, "child" => nil, "transcripts" => transcripts,
        "heldWriter" => held_writer}
      (@driver_records ||= {})[record.object_id] = record
      begin
        record["directoryState"] = :acquiring
        Thread.handle_interrupt(Exception => :never) do
          directory = Dir.mktmpdir("native-process-", root)
          record["directory"], record["directoryState"] = directory, :published
          directory = File.realpath(directory)
          record["directoryIdentity"] = OwnedChild.directory_identity(directory)
          record["directoryState"] = :canonical
        end
        input = {"platform" => platform, "parameters" => parameters, "mode" => mode, "deadlineNs" => run_ns}
        input["observeSignals"] = true if observe_signals
        atomic_json(File.join(directory, "input.json"), input)
        child = OwnedChild.new(root: directory, deadline_ns: run_ns, hard_deadline_ns: hard_ns)
        record["child"] = child
        transcripts.zip(%w[driver.stdout driver.stderr]).each do |lease, name|
          lease.acquire { File.open(File.join(directory, name), File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) }
        end
        value = scope.active do
          expected_argv = [File.realpath(RbConfig.ruby), File.realpath(__FILE__), "driver", directory]
          environment = driver_environment(directory)
          expected_cwd = Dir.pwd
          record["requestedDispatch"] = {"version" => 1, "argv" => expected_argv,
            "environment" => environment, "cwd" => expected_cwd, "fixtureSha256" => Digest::SHA256.file(__FILE__).hexdigest,
            "deadlineNs" => run_ns}
          if NATIVE_ORDER_MODES.include?(mode)
            source_root = File.realpath(File.expand_path("../..", __dir__))
            record["orderSources"] = NativeOrderProbe::SOURCES.to_h { |name| [name, Digest::SHA256.file(File.join(source_root, name)).hexdigest] }
          end
          if held_writer || mode == ContainmentEvidence::MISSING
            record["containmentSources"] = ContainmentEvidence.source_hashes
          end
          child.start(environment, *expected_argv, in: File::NULL, out: :pipe, err: :pipe,
                      unsetenv_others: true, pgroup: true)
          killed = false
          bytes = [0, 0]
          loop do
            remaining = run_ns - clock_ns
            raise Failure.new("driver", "driver deadline expired") unless remaining.positive?
            if mode.start_with?("kill-") && !killed && child.phase == :reserved && File.file?(File.join(directory, "owner.json"))
              candidate = read_json(File.join(directory, "owner.json"))
              owner_processes!(candidate)
              if candidate["phase"] == mode
                owner = candidate
                # Root and acquire the SAME identity-bound private FIFO writer
                # BEFORE the only reserved-driver KILL. Driver loss alone can
                # no longer manufacture descendant EOF via fixture fallback.
                prior = ContainmentEvidence.prekill!(directory, mode, owner, record.fetch("containmentSources"), held_writer)
                record["prekillContainment"] = prior
                prior["driverPid"], prior["driverKillEntryNs"] = child.pid, clock_ns
                # Only this original unretired direct Child, never a marker PID.
                killed = child.signal("KILL", group: false)
                raise Failure.new("driver", "original reserved driver KILL did not return") unless killed
              end
            end
            %i[out err].each_with_index do |role, index|
              chunk = child.read_stream(role)
              if chunk.is_a?(String)
                bytes[index] += chunk.bytesize
                raise Failure.new("diagnostic", "oversized driver diagnostic") if bytes[index] > OUTPUT_LIMIT
                transcripts[index].io.write(chunk)
              elsif !chunk.nil? && chunk != :wait_readable
                raise Failure.new("driver", "invalid actual driver stream")
              end
            end
            # No fresh process observer is admitted while a nested driver may
            # already hold UNKNOWN. Actual BOTH pipe EOFs retire all numeric
            # routes before the first original consuming wait. A still-live
            # post-EOF driver can only return genuine nil polls until this SAME
            # cutoff; cleanup never reopens KILL after retirement.
            child.retire_numeric! if child.phase == :reserved && child.streams_complete?
            break if child.phase == :waiting && child.poll_wait
            sleep [10_000_000, [run_ns - clock_ns, 0].max].min / 1_000_000_000.0
          end
          child.stop # Original wait, actual creator join and all owned pipe closes.
          transcripts.each(&:close_once)
          raise Failure.new("driver", "driver receipt/close arrived after original deadline") unless clock_ns < run_ns
          unless child.complete? && child.status && child.status.equal?(child.child.receipt.raw_status)
            raise Failure.new("driver", "direct driver ownership did not finalize")
          end
          dispatch = JSON.parse(OwnedChild.bounded_file(File.join(directory, "driver-dispatch.json")))
          expected_dispatch = record.fetch("requestedDispatch").merge("pid" => child.pid)
          raise Failure.new("driver", "driver dispatch was not the original requested CLI") unless dispatch == expected_dispatch
          owner ||= read_json(File.join(directory, "owner.json"))
          owner_processes!(owner)
          if mode.start_with?("kill-")
            unless killed && child.status.signaled? && child.status.termsig == Signal.list.fetch("KILL") && owner["phase"] == mode
              raise Failure.new("driver", "driver did not terminate at the requested known phase")
            end
            raise Failure.new("driver", "killed driver supplied a final result") if File.exist?(File.join(directory, "result.json"))
            containment = ContainmentEvidence.hardloss!(directory, mode, record.fetch("prekillContainment"),
              held_writer, deadline_ns: run_ns)
            containment["heldWriterClose"] = ContainmentEvidence.close_held!(record)
            # Actual descendant-group containment is NOT an original C wait.
            result = {"kind" => "driver-terminated", "phase" => mode,
              "driverTermSignal" => child.status.termsig, "nativeFinality" => "unknown", "containmentProof" => containment}
          else
            raise Failure.new("driver", "driver did not exit normally") unless child.status.exited?
            result = read_json(File.join(directory, "result.json"))
            if observe_signals
              signal_proof = read_json(File.join(directory, "native-signal-proof.json"))
              unless signal_proof["case"] == mode && signal_proof["kind"] == "native-signal-observation" &&
                     signal_proof["sourceSha256"] == NativeSignalProbe.current.source_hashes &&
                     signal_proof["failures"] == [] && signal_proof["hooksRestored"] == true &&
                     signal_proof["baseDriverReturn"] == 0 && child.status.exitstatus == 0
                raise Failure.new("fixture-result", "native signal proof rejected")
              end
              result = result.merge("nativeSignalProof" => signal_proof, "observedDriverExitStatus" => child.status.exitstatus)
            end
            if NATIVE_PRIMARY_PROOFS.key?(mode)
              proof = read_json(File.join(directory, "primary-proof.json"))
              unless proof["case"] == mode && proof["failures"] == [] && proof["driverExitStatus"] == 1 &&
                     result["kind"] != "pass" && child.status.exitstatus == 0
                reject_native_primary_proof!(mode: mode, proof: proof, result: result, status: child.status,
                  deadline_ns: run_ns, state: primary_failure_state)
              end
            elsif NATIVE_ORDER_MODES.include?(mode)
              order_proof = read_json(File.join(directory, "native-order-proof.json"))
              unknown_order = NativeOrderProbe::MODES.fetch(mode).first == "cleanup-before-caller"
              unless order_proof["version"] == 1 && order_proof["kind"] == "native-order-observation" &&
                     order_proof["case"] == mode && order_proof["sourceSha256"] == record["orderSources"] &&
                     order_proof["failures"] == [] && order_proof["baseDriverReturn"] == 1 &&
                     order_proof["expectedUnknown"].equal?(unknown_order) && order_proof["originalAccepted"].equal?(false) &&
                     result["kind"] == (unknown_order ? "fixture-cleanup" : "unexpected") && child.status.exitstatus == 0
                reject_native_order_proof!(mode: mode, proof: order_proof, result: result, status: child.status,
                  expected_sources: record["orderSources"], deadline_ns: run_ns, state: order_failure_state)
              end
            else
              expected = {"unready" => "readiness", "leader-only" => "descendant-alive",
                "no-deadline" => "capture-watchdog", "immediate-deadline" => "elapsed-bound",
                "native-setup-second-pipe" => "setup-fixture-fault", "native-setup-owner-failure" => "setup-fixture-fault",
                "native-setup-readiness-failure" => "readiness", "native-setup-watchdog-unavailable" => "setup-fixture-fault",
                "native-setup-watchdog-failure" => "setup-fixture-fault"}.fetch(mode.delete_suffix("-slow-cleanup"), "pass")
              expected = %w[setup-fallback fixture-cleanup] if mode == "native-setup-no-cleanup"
              unless Array(expected).include?(result["kind"]) && child.status.exitstatus == (expected == "pass" ? 0 : 1)
                if NATIVE_SETUP_FAILURE_MODES.include?(mode)
                  reject_native_setup_result!(mode: mode, result: result, status: child.status,
                    deadline_ns: run_ns, state: setup_failure_state)
                elsif adapter_failure_mode?(platform, mode)
                  reject_adapter_result!(platform: platform, mode: mode, result: result, status: child.status,
                    deadline_ns: run_ns, state: adapter_failure_state)
                end
                raise Failure.new("fixture-result", "unexpected fixture result kind/status")
              end
            end
            snapshot = result["nativeObservation"]
            native_final = native_owner_finality?(mode, owner, result, proof)
            if order_proof && order_proof["expectedUnknown"]
              unless snapshot && snapshot["unknown"] && !snapshot["finalized"] && !snapshot["noProducers"] &&
                     order_proof["retainedOriginalSession"] && !order_proof["captureFinished"] && order_proof["captureJoined"]
                raise Failure.new("fixture-result", "cleanup-first order control did not retain original UNKNOWN")
              end
            elsif mode == "native-setup-no-cleanup"
              unless snapshot && snapshot["unknown"] && !snapshot["finalized"] && !snapshot["noProducers"] &&
                     result["fallbackUsed"] && result["watchdogIntervened"]
                raise Failure.new("fixture-result", "missing-cleanup control did not retain actual UNKNOWN")
              end
              result["missingCleanupProof"] = ContainmentEvidence.missing_cleanup!(directory, owner, result,
                record.fetch("containmentSources"), deadline_ns: run_ns, driver_dispatch: dispatch)
            elsif !native_final
              raise Failure.new("fixture-result", "driver lacks physical native finality")
            end
            result["nativeFinality"] = native_final ? owner.fetch("finality") : "unknown"
          end
          if native_final
            death_deadline ||= Rational([clock_ns + CLEANUP_LIMIT * 1_000_000_000, hard_ns].min, 1_000_000_000)
            known_dead = observe_owner_death!(owner, deadline: death_deadline, root: root)
          else
            # The direct driver receipt/EOF is not a C/K/V wait. Fixed held
            # channel/event proofs below are separate containment evidence;
            # neither they nor Session disposal repair missing native custody.
            retain_unknown_domain!(root, expected: true)
          end
          result = result.merge("primaryProof" => proof) if proof
          result = result.merge("nativeOrderProof" => order_proof) if order_proof
          result = result.merge("driverJoined" => true,
            "driverProvenance" => child.provenance, "driverDispatch" => dispatch,
            "retainedFixture" => !native_final, "domainDisposalRequired" => !native_final)
          result["knownProcessesDead"] = known_dead if native_final
          result
        end
        value
      rescue Exception => error
        scope.remember(error)
        death_deadline ||= Rational([clock_ns + CLEANUP_LIMIT * 1_000_000_000, hard_ns].min, 1_000_000_000)
        warn JSON.generate("errorClass" => error.class.name, "error" => error.message,
                           "ownedDirectory" => directory, "driverPhase" => child&.phase&.to_s) if error.is_a?(StandardError)
        raise
      ensure
        scope.cleanup { child&.stop }
        transcripts.each { |lease| scope.cleanup { lease.close_once } }
        scope.cleanup { ContainmentEvidence.close_held!(record) } if held_writer
        scope.cleanup do
          if directory && child&.complete? && !native_final && !domain_disposal_required?
            provenance = child.provenance
            if provenance["grant"] == {"state" => "closed", "bytesWritten" => 0}
              # Positive original no-GO transition, NOT a missing marker. The
              # fixed bootstrap cannot dispatch the driver without this grant.
              # Its genuine original terminal status may itself be SIGKILL.
              record["driverTargetNeverDispatched"] = true
              native_final = known_dead = true
            elsif child.status&.exited? && record["requestedDispatch"] &&
                  %w[driver-dispatch.json owner.json result.json].all? { |name| File.file?(File.join(directory, name)) }
              recovered_dispatch = JSON.parse(OwnedChild.bounded_file(File.join(directory, "driver-dispatch.json")))
              unless recovered_dispatch == record.fetch("requestedDispatch").merge("pid" => child.pid)
                raise Failure.new("fixture-cleanup", "completed driver dispatch changed before cleanup accounting")
              end
              recovered_owner = read_json(File.join(directory, "owner.json"))
              owner_processes!(recovered_owner)
              recovered_result = read_json(File.join(directory, "result.json"))
              if native_owner_finality?(mode, recovered_owner, recovered_result)
                owner, native_final = recovered_owner, true
              end
            end
          end
        end
        scope.cleanup do
          if directory && child&.complete? && native_final && !known_dead &&
             (!domain_disposal_required? || death_deadline && clock >= death_deadline) &&
             File.file?(File.join(directory, "owner.json"))
            owner ||= read_json(File.join(directory, "owner.json"))
            death_deadline ||= Rational([clock_ns + CLEANUP_LIMIT * 1_000_000_000, hard_ns].min, 1_000_000_000)
            known_dead = observe_owner_death!(owner, deadline: death_deadline, root: root)
          end
        end
        scope.cleanup do
          never_started = child.nil? || child.phase == :unstarted && child.complete?
          if directory && record["directoryState"] == :canonical &&
             (transcripts + [held_writer].compact).all? { |lease| %i[unattempted closed].include?(lease.state) } &&
             (never_started || child.complete? && known_dead && native_final)
            unless OwnedChild.directory_identity(directory) == record["directoryIdentity"]
              raise Failure.new("fixture-cleanup", "driver directory identity changed")
            end
            remove_fixture_directory(directory, root: root, layout: :driver)
            @driver_records.delete(record.object_id)
          elsif record["directoryState"] == :unattempted
            @driver_records.delete(record.object_id)
          else
            (@unresolved_roots ||= {})[root] = true
            retain_unknown_domain!(root) unless record["directoryState"] == :canonical &&
              (child.nil? || child.phase == :unstarted && child.complete?) &&
              (transcripts + [held_writer].compact).all? { |lease| %i[unattempted closed].include?(lease.state) }
            warn "Fixture ownership/cleanup unresolved; preserve #{directory || 'unpublished private driver directory'}"
          end
        end
      end
    end
    # The original run bound still applies after BOTH restoration drains and
    # every required cleanup. Grace is not a renewed result-acceptance window.
    raise Failure.new("driver", "driver result arrived after original deadline") unless clock_ns < run_ns
    accepted
  end

  # A fixture-only fallback channel, opened by V after exec. Native inheritance
  # remains exactly 0..2. Markers authorize bounded read-only observation only.
  class WorkerControl
    attr_reader :writer, :anchor, :directory, :identity

    def initialize(directory)
      @directory = directory
      @anchor = OwnedChild::ControlLease.new
      @writer = OwnedChild::ControlLease.new
      @fifo = File.join(directory, "worker-control.fifo")
    end

    def prepare
      UploadProcessFixture.owned_fixture_directory(@directory)
      File.mkfifo(@fifo, 0o600)
      @identity = OwnedChild.identity(File.lstat(@fifo))
      @anchor.acquire { File.open(@fifo, File::RDONLY | File::NONBLOCK | File::NOFOLLOW) }
      @writer.acquire { File.open(@fifo, File::WRONLY | File::NONBLOCK | File::NOFOLLOW) }
      [@anchor, @writer].each do |lease|
        unless lease.io.close_on_exec? && OwnedChild.identity(lease.io.stat) == @identity
          raise Failure.new("fixture-control", "fixture FIFO identity or inheritance changed")
        end
      end
      OwnedChild.write_record(File.join(@directory, "worker-control.json"), {"version" => 1, "identity" => @identity})
    end

    def admitted!
      @anchor.close_once
    end

    def close_writer
      @writer.close_once
    end

    def close
      errors = []
      [@anchor, @writer].each do |lease|
        begin
          lease.close_once
        rescue Exception => error
          errors << error
        end
      end
      raise errors.first unless errors.empty?
      true
    end

    def closed?
      [@anchor, @writer].all? { |lease| %i[unattempted closed].include?(lease.state) }
    end
  end

  # Fixture copies have their own provenance, never the original six-file hash
  # map. Replacing helper argv here changes only a test dispatch, not SpawnSpec
  # semantics or a production hook. Ordinary installed gates never call this.
  def copied_helper(directory, label, insertion)
    helper = File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__))
    leaf = File.realpath(File.expand_path("../../fastlane/native_process_spawn.rb", __dir__))
    source = File.binread(helper, 1_048_577)
    anchor = 'if $PROGRAM_NAME == __FILE__'
    raise Failure.new("fixture-source", "helper dispatch anchor changed") unless source.scan(anchor).length == 1
    dependency = 'require_relative "native_process_spawn"'
    raise Failure.new("fixture-source", "helper dependency anchor changed") unless source.scan(dependency).length == 1
    changed = source.sub(dependency, "require #{leaf.inspect}").sub(anchor, insertion + "\n" + anchor)
    copy = File.join(directory, "#{label}-helper.rb")
    File.open(copy, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(changed) }
    [copy, {"originalPath" => helper, "originalSha256" => Digest::SHA256.hexdigest(source),
            "path" => copy, "sha256" => Digest::SHA256.hexdigest(changed), "label" => label}]
  end

  def capture_owner(observer, phase:, descendant: nil)
    session = observer&.session
    child = session&.custodian_child || session&.acquisition&.child
    snapshot = observer&.finalized? || observer&.no_producers? || observer&.instance_variable_get(:@finished) ? observer.snapshot : nil
    final = session&.final
    no_producers = snapshot && snapshot["noProducers"]
    unknown = {"state" => "unknown"}
    value = {"version" => 2, "phase" => phase,
      "finality" => snapshot ? (snapshot["finalized"] ? "finalized" : no_producers ? "no_producers" : "unknown") : "active",
      "custodian" => snapshot ? snapshot.fetch("custodian", unknown) : unknown,
      "keeper" => final ? final.fetch("keeper") : no_producers ? {"state" => "not_attempted"} : unknown,
      "validator" => final ? final.fetch("validator") : no_producers ? {"state" => "not_attempted"} : unknown,
      "group" => final ? final.fetch("group") : no_producers ? {"state" => "not_created"} : unknown,
      "processes" => []}
    if child && session&.hello && session.hello["pid"] == child.pid
      value["processes"] << {"role" => "custodian", "pid" => child.pid, "group" => session.hello.fetch("pgid")}
    end
    if session&.reserved && session.ready
      value["processes"] << {"role" => "keeper", "pid" => session.reserved.fetch("keeper_pid"), "group" => session.ready.fetch("keeper_pgid")}
      value["processes"] << {"role" => "validator", "pid" => session.ready.fetch("validator_pid"), "group" => session.ready.fetch("group_id")}
      value["processes"] << {"role" => "descendant", "pid" => descendant.fetch("pid"), "group" => descendant.fetch("group")} if descendant
    end
    value
  end

  class NativeSetupDriver
    attr_reader :observation, :observed, :cleanup_errors, :outer_failure

    class Observation < CaptureObservation
      def initialize(driver, **options)
        @driver = driver
        super(**options)
      end

      def on_event(name, object)
        @driver.native_event(name, object)
      end

      def install
        super
        driver, observer = @driver, self
        @hooks.wrap(@spawn.singleton_class, :pipe) do |original, _object, arguments, keywords, block|
          if observer.session && arguments.first.equal?(observer.session.acquisition)
            driver.before_native_pipe
          end
          original.call(*arguments, **keywords, &block)
        end
        copy = @driver.instance_variable_get(:@helper_copy)
        if copy
          @hooks.wrap(@helper.singleton_class, :helper_argv) do |original, _object, arguments, keywords, block|
            result = original.call(*arguments, **keywords, &block)
            original_path = File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__))
            raise Failure.new("fixture-source", "helper argv source changed") unless result.count(original_path) == 1
            result.map { |part| part == original_path ? copy : part }.freeze
          end
        end
      end
    end

    def initialize(directory, mode)
      @directory, @mode = directory, mode
      @cleanup_errors, @injectors = [], []
      @control = WorkerControl.new(directory)
      @fixture_error = Failure.new("setup-fixture-fault", "synthetic #{@mode} failure")
      @injected_error = case mode
      when "native-setup-system-exit" then SystemExit.new(23)
      when "native-setup-io-error" then IOError.new("synthetic private diagnostic")
      else Interrupt.new("synthetic setup cancellation")
      end
      @injected_message = @injected_error.message.dup.freeze
      @injected_status = @injected_error.status if @injected_error.is_a?(SystemExit)
      @observed = {"mode" => mode, "injectionCount" => 0, "firstCloseEntered" => false,
        "ready" => false, "watchdogStarted" => false, "watchdogIntervened" => false,
        "fallbackUsed" => false, "postReapCancellationInjected" => false}
      @pipe_calls = 0
    end

    def path(name)
      File.join(@directory, name)
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
      @cleanup_errors << error unless @cleanup_errors.any? { |known| known.equal?(error) }
    end

    def publish_owner(phase = "active")
      @owner = UploadProcessFixture.capture_owner(@observation, phase: phase, descendant: @descendant)
      UploadProcessFixture.atomic_json(path("owner.json"), @owner)
    end

    def prepare_native
      require_relative "../../fastlane/native_upload_validation"
      @native = MobileReleaseKit::NativeUploadValidation
      @tooling = File.realpath(File.expand_path("../../fastlane", __dir__))
      @argv = [File.realpath(RbConfig.ruby), File.realpath(__FILE__), "worker", @directory, @mode]
      if @mode == "native-setup-no-cleanup"
        insertion = <<~'RUBY'
          MobileReleaseKit::NativeUploadProcess::GroupLease.prepend(Module.new do
            def request(signal)
              return 0 if signal == "KILL" # Deliberate missing actual C cleanup.
              super
            end
          end)
          MobileReleaseKit::NativeUploadProcess::Keeper.prepend(Module.new do
            def request_group(signal)
              return 0 if signal == "KILL" # Also remove the genuine self-owned fallback.
              super
            end
          end)
        RUBY
        @helper_copy, facts = UploadProcessFixture.copied_helper(@directory, "missing-cleanup", insertion)
        @observed.merge!("helperCopy" => facts, "mutationSourceSha256" => facts.fetch("originalSha256"),
                         "mutationSha256" => facts.fetch("sha256"))
      end
      @observation = Observation.new(self, native: @native, root: @directory)
    end

    def before_native_pipe
      @pipe_calls += 1
      raise @fixture_error if @mode == "native-setup-second-pipe" && @pipe_calls == 2
    end

    def inject(error)
      if error.is_a?(Interrupt)
        helper = MobileReleaseKit::NativeUploadProcess
        cutoff = UploadProcessFixture.clock + 2
        slot = helper::TaskSlot.new(caller: Thread.current, parent_slot: nil,
          run_deadline_ns: (cutoff * 1_000_000_000).floor,
          hard_cleanup_deadline_ns: (cutoff * 1_000_000_000).floor)
        @injectors << slot # Prepublished BEFORE the actual Thread.new.
        target = Thread.current
        Thread.handle_interrupt(Exception => :never) do
          slot.start { target.raise(error); true }
          raise "fixture injector admission failed" unless slot.admit!
          raise "fixture injector did not join" unless slot.join_until(deadline_ns: slot.hard_cleanup_deadline_ns)
          raise slot.first_error if slot.first_error
        end
      else
        raise error
      end
    end

    def native_event(name, object)
      case name
      when :execute_enter
        @native_frame = object
      when :custodian_published
        publish_owner("launched")
        raise @fixture_error if @mode == "native-setup-owner-failure"
      when :ready_before_stdin_close
        ready!
        if @mode == "kill-native-setup"
          publish_owner(@mode)
          sleep READINESS_LIMIT
          raise Failure.new("driver", "parent did not stop its actual driver")
        end
        raise @fixture_error if @mode == "native-setup-watchdog-unavailable"
        start_watchdog
        @observed["firstCloseEntered"] = true
      when :stdin_close_returned
        first_close
      end
    end

    def ready!
      session = @observation.session
      ready = session.ready
      raise Failure.new("readiness", "native READY was not bound") unless ready && session.reserved
      cutoff = [UploadProcessFixture.clock + READINESS_LIMIT,
                session.capture_slot.run_deadline_ns / 1_000_000_000.0].min
      marker_path = path("leader-ready.json")
      loop do
        remaining = cutoff - UploadProcessFixture.clock
        raise Failure.new("readiness", "native fixture readiness deadline expired") unless remaining.positive?
        if File.file?(marker_path)
          marker = JSON.parse(OwnedChild.bounded_file(marker_path))
          unless marker.keys.sort == %w[group kind pid sid] && marker["kind"] == "leader-ready" &&
                 marker["pid"] == ready.fetch("validator_pid") && marker["group"] == ready.fetch("group_id") &&
                 marker["sid"] == session.custodian_child.pid
            raise Failure.new("readiness", "fixture readiness did not match actual V/G/C")
          end
          if UploadProcessFixture.ready?(marker.fetch("pid"), marker.fetch("group"), seconds: [remaining, 2].min, parent_slot: session.capture_slot)
            raise Failure.new("readiness", "native fixture readiness deadline expired") if UploadProcessFixture.clock >= cutoff
            @control.admitted!
            @observed["ready"] = true
            @observed["readinessSeconds"] = UploadProcessFixture.clock - @capture_started
            publish_owner("ready")
            return marker
          end
        end
        sleep [0.01, [cutoff - UploadProcessFixture.clock, 0].max].min
      end
    end

    def start_watchdog
      helper = MobileReleaseKit::NativeUploadProcess
      @watchdog_at = UploadProcessFixture.clock + (@mode == "native-setup-no-cleanup" ? CLEANUP_LIMIT + 0.3 : CAPTURE_LIMIT)
      hard = @watchdog_at + 1
      @watchdog = helper::TaskSlot.new(caller: Thread.current, parent_slot: nil,
        run_deadline_ns: (hard * 1_000_000_000).floor, hard_cleanup_deadline_ns: (hard * 1_000_000_000).floor)
      @watchdog.start do
        until @watchdog_stop || UploadProcessFixture.clock >= @watchdog_at
          sleep [0.01, [@watchdog_at - UploadProcessFixture.clock, 0].max].min
        end
        unless @watchdog_stop
          @observed["watchdogIntervened"] = @observed["fallbackUsed"] = true
          @control.close_writer # The exact private writer, never a helper PID.
        end
        true
      end
      raise Failure.new("setup-fixture-fault", "fixture watchdog was not admitted") unless @watchdog.admit!
      @observed["watchdogStarted"] = true
      raise @fixture_error if @mode == "native-setup-watchdog-failure"
    end

    def first_close
      return unless @observed["injectionCount"].zero?
      @observed["injectionCount"] += 1
      @observed["firstCloseFromNative"] = true
      lease = @observation.session.leases.fetch(:stdin_write)
      @observed["originalCloseCompleted"] = lease.state == :closed && lease.io.closed? && @observation.session.stdin_close_returned
      raise "first-close effect was not real" unless @observed["originalCloseCompleted"]
      inject(@injected_error)
    end

    def expected_native_error?(primary)
      return false unless @observed["firstCloseEntered"] && @observed["injectionCount"] == 1 &&
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
      @capture_started = UploadProcessFixture.clock
      begin
        @observation.observe do
          @native.capture({}, @argv, @tooling, max_seconds: READINESS_LIMIT, max_output_bytes: 1_024,
            label: "Synthetic", failure_message: "synthetic validation failure")
        end
      rescue Exception => error
        @native_error = error
      ensure
        @observed["captureSeconds"] = UploadProcessFixture.clock - @capture_started
      end
      @observed["nativeErrorClass"] = @native_error&.class&.name
      @observed["nativeErrorMessage"] = @native_error&.message
      @observed["nativeOriginalErrorPreserved"] = @native_error.equal?(@injected_error) && @native_error.message == @injected_message
      @observed["nativeExitStatus"] = @native_error.status if @native_error.is_a?(SystemExit)
      primary = @observation.session&.primary_error || @native_error
      unless expected_native_error?(primary)
        raise primary if primary
        raise "native capture did not return the expected first-close failure"
      end
      if @mode == "native-setup-no-cleanup"
        # A genuine UNKNOWN remains UNKNOWN. Wait only for the already registered
        # independent fixture fallback; it cannot repair the native observation.
        unless @watchdog.join_until(deadline_ns: watchdog_join_deadline_ns)
          raise Failure.new("fixture-cleanup", "fixture fallback did not join")
        end
        raise Failure.new("setup-fallback", "native setup required independent fixture EOF")
      end
      unless @observation.finalized? || @observation.no_producers?
        raise Failure.new("fixture-cleanup", "native capture did not prove finality")
      end
      @observed["deadBeforeFallback"] = true
      post_reap_cancellation if @mode == "native-setup-post-reap-cancel"
    end

    def post_reap_cancellation
      unless @observation.finalized? && @observation.session.custodian_receipt.equal?(@observation.session.custodian_child.receipt)
        raise Failure.new("fixture-cleanup", "post-reap probe lacks original actual wait")
      end
      begin
        UploadProcessFixture.lifetime do |frame|
          frame.remember(@injected_error)
          frame.cleanup do
            @observed["postReapCancellationInjected"] = true
            @observed["postReapCleanupDepth"] = UploadProcessFixture.instance_variable_get(:@cancellation_scope).cleanup_depth
            inject(Interrupt.new("repeat after actual native reap"))
            Process.kill("INT", Process.pid) # Isolated fixture's own process only.
            @observed["selfSignalQueued"] = Signal.list.fetch("INT")
          end
          frame.finishing { frame.drain_pending }
        end
      rescue Exception => error
        raise error unless error.equal?(@injected_error)
      end
    end

    def close_control
      @control.close
    end

    def watchdog_join_deadline_ns
      @watchdog.hard_cleanup_deadline_ns
    end

    def finish_resources
      if @watchdog
        @watchdog_stop = true
        cleanup_step do
          raise Failure.new("fixture-cleanup", "fixture watchdog did not join") unless @watchdog.join_until(deadline_ns: watchdog_join_deadline_ns)
          raise @watchdog.first_error if @watchdog.first_error
        end
      end
      @injectors.each do |slot|
        cleanup_step do
          raise Failure.new("fixture-cleanup", "fixture injector did not join") unless slot.join_until(deadline_ns: slot.hard_cleanup_deadline_ns)
          raise slot.first_error if slot.first_error
        end
      end
      cleanup_step { close_control }
      cleanup_step { publish_owner("finished") }
      raise @cleanup_errors.first unless @cleanup_errors.empty?
    end

    def publish_result(failure, kind)
      result = @observed.merge("kind" => kind, "errorClass" => failure&.class&.name, "error" => failure&.message)
      UploadProcessFixture.atomic_json(path("result.json"), result)
      kind == "pass" ? 0 : 1
    end

    def execute
      saved_handlers = trap_state
      failure = nil
      begin
        UploadProcessFixture.lifetime do |frame|
          begin
            @control.prepare
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
      @outer_failure = failure
      snapshot = @observation&.snapshot
      if snapshot
        @observed["nativeObservation"] = snapshot
        UploadProcessFixture.atomic_json(path("native-observation.json"), snapshot)
      end
      task_accounted = snapshot && snapshot.fetch("tasks").all? do |task|
        task["state"] == "not_constructed" || task["state"] == "not_started" || task["finished"] && task["joined"] && task["actualJoinObserved"]
      end
      descriptors_closed = @control.closed? && snapshot && snapshot.fetch("leases").all? { |lease| lease["noIOAcquired"] || lease["closed"] && lease["actualCloseObserved"] }
      @observed.merge!("ownedDescriptorsClosed" => !!descriptors_closed, "tasksJoined" => !!task_accounted,
        "watchdogJoined" => !@watchdog || @watchdog.joined? && @watchdog.finished?,
        "injectorsJoined" => @injectors.all? { |slot| slot.joined? && slot.finished? && !slot.unresolved? },
        "handlersRestored" => trap_state == saved_handlers,
        "registryInactive" => UploadProcessFixture.instance_variable_get(:@cancellation_scope).nil?,
        "pendingInterrupt" => Thread.current.pending_interrupt?,
        "harnessPrimaryRetained" => failure && (failure.equal?(@fixture_error) || failure.equal?(@observation&.session&.primary_error)),
        "cleanupErrors" => @cleanup_errors.map { |error| error.class.name })
      kind = failure ? (failure.is_a?(Failure) ? failure.kind : "unexpected") : "pass"
      unless @observed.values_at("ownedDescriptorsClosed", "watchdogJoined", "tasksJoined", "injectorsJoined", "handlersRestored", "registryInactive").all? &&
             !@observed["pendingInterrupt"] && @cleanup_errors.empty?
        kind = "fixture-cleanup"
      end
      publish_result(failure, kind)
    end
  end

  # One actual ordinary driver per primary proof. The capture TaskSlot's original
  # first-error record and the actual outer result method are observed separately.
  class NativePrimaryProbe
    class UnexpectedFailure < StandardError; end
    class CleanupFailure < StandardError; end

    class Driver < NativeSetupDriver
      attr_reader :original, :original_message, :original_status, :secondary,
                  :fault_count, :secondary_count, :frame_published, :entered_death_before_close

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
      end

      def fault(boundary)
        return unless boundary == @boundary && @fault_count.zero?
        @frame_published = !!(@observation.session && @observation.session.capture_slot)
        @fault_count += 1
        inject(@original)
        # READY dispatch deliberately retains the production frame mask. The
        # genuine injector is already joined; deliver its queued Interrupt at
        # THIS proof's pre-entry boundary, not after the intentional first close.
        # No synthetic raise repairs a missing injection. Common inject remains
        # deferred for cleanup probes that intentionally rely on that policy.
        Thread.handle_interrupt(Interrupt => :immediate) {}
      end

      def native_event(name, object)
        if name == :run_enter
          fault("frame")
        elsif name == :custodian_published
          super
          fault("publication")
          return
        end
        super
      end

      def ready!
        super
        fault("readiness")
      end

      def start_watchdog
        super
        fault("watchdog")
      end

      def first_close
        if @boundary == "entered"
          @observed["injectionCount"] += 1
          @observed["firstCloseFromNative"] = true
          lease = @observation.session.leases.fetch(:stdin_write)
          @observed["originalCloseCompleted"] = lease.state == :closed && lease.io.closed? && @observation.session.stdin_close_returned
          raise "unexpected entered proof before real close" unless @observed["originalCloseCompleted"]
          fault("entered")
        else
          super
        end
      end

      def fail_cleanup
        return unless @secondary && @secondary_count.zero?
        @secondary_count += 1
        raise @secondary
      end

      def close_control
        if @boundary == "entered"
          snapshot = @observation.snapshot
          record = snapshot["final"] && snapshot["final"]["validator"]
          unless snapshot["finalized"] && record && record["state"] == "reaped" &&
                 record["status_kind"] == "signal" && record["status_code"] == Signal.list.fetch("KILL") &&
                 !@observed["fallbackUsed"] && !@observed["watchdogIntervened"]
            raise "entered proof lacked genuine K wait before fixture control close"
          end
          @entered_death_before_close = true
        end
        super
        fail_cleanup if @secondary_boundary == "close" && @fault_count == 1
      end

      def publish_owner(phase = "active")
        super
        fail_cleanup if phase == "finished" && @secondary_boundary == "outer"
      end
    end

    def initialize(directory, mode)
      @directory, @mode = directory, mode
      @spec = NATIVE_PRIMARY_PROOFS.fetch(mode)
    end

    def execute
      driver = Driver.new(@directory, @spec)
      result_observations = 0
      outer_error = nil
      trace = TracePoint.new(:call) do |point|
        if point.self.equal?(driver) && point.method_id == :publish_result
          result_observations += 1
          outer_error = point.binding.local_variable_get(:failure)
        end
      end
      begin
        trace.enable
        status = driver.execute
      ensure
        trace.disable
      end
      raw = UploadProcessFixture.read_json(File.join(@directory, "result.json"))
      observer = driver.observation
      session = observer&.session
      native_error = driver.instance_variable_get(:@native_error)
      receipt = session&.custodian_receipt
      child = session&.custodian_child
      snapshot = raw.fetch("nativeObservation")
      proof = {"case" => @mode, "driverExitStatus" => status, "faultCount" => driver.fault_count,
        "framePublishedBeforeFault" => driver.frame_published, "resultObservations" => result_observations,
        "outerPrimarySameObject" => outer_error.equal?(driver.original),
        "nestedPrimarySameObject" => session&.primary_error.equal?(driver.original),
        "taskPrimarySameObject" => session&.capture_slot&.first_error.equal?(driver.original),
        "originalMessagePreserved" => outer_error&.message == driver.original_message,
        "originalStatusPreserved" => !driver.original.is_a?(SystemExit) || outer_error.is_a?(SystemExit) && outer_error.status == driver.original_status,
        "originalNotIntentional" => !driver.original.equal?(driver.instance_variable_get(:@injected_error)),
        "actualCustodianReceiptBound" => !!(child && child.equal?(session.acquisition.child) && receipt && receipt.equal?(child.receipt) && receipt.raw_status.is_a?(Process::Status)),
        "actualTaskJoins" => raw.fetch("tasksJoined"), "actualDescriptorsClosed" => raw.fetch("ownedDescriptorsClosed"),
        "secondaryCount" => driver.secondary_count,
        "secondaryObjectRecorded" => !!(driver.secondary && driver.cleanup_errors.any? { |error| error.equal?(driver.secondary) }),
        "enteredDeathBeforeControlClose" => driver.entered_death_before_close,
        "firstCloseReturned" => snapshot["stdinCloseReturned"] == true,
        "nativeErrorClass" => native_error&.class&.name, "nativeErrorMessage" => native_error&.message, "failures" => []}
      check = lambda { |name, value| proof["failures"] << name unless value }
      check.call("actual failed native result", status == 1 && raw["kind"] == (driver.secondary ? "fixture-cleanup" : "unexpected"))
      check.call("one real injection/final boundary", driver.fault_count == 1 && result_observations == 1)
      %w[framePublishedBeforeFault outerPrimarySameObject nestedPrimarySameObject taskPrimarySameObject originalMessagePreserved
         originalStatusPreserved originalNotIntentional actualTaskJoins actualDescriptorsClosed].each { |name| check.call(name, proof[name]) }
      check.call("secondary identity", driver.secondary ? proof["secondaryObjectRecorded"] && driver.cleanup_errors.length == 1 && driver.secondary_count == 1 : driver.cleanup_errors.empty?)
      %w[ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined handlersRestored registryInactive].each { |name| check.call(name, raw[name]) }
      check.call("no pending cancellation", !raw["pendingInterrupt"])
      if @spec[1] == "io"
        check.call("unchanged IOError redaction", native_error.instance_of?(MobileReleaseKit::ContractError) && native_error.message == "Synthetic validator could not be executed safely; no upload is authorized")
      else
        check.call("actual non-IOError return", native_error.equal?(driver.original))
      end
      check.call("native cleanup without fixture fallback", !raw["fallbackUsed"] && !raw["watchdogIntervened"])
      check.call("actual capture finality", @spec.first == "frame" ? snapshot["noProducers"] && !proof["actualCustodianReceiptBound"] : snapshot["finalized"] && proof["actualCustodianReceiptBound"])
      check.call("first-close boundary", @spec.first == "entered" ? proof["firstCloseReturned"] && raw["injectionCount"] == 1 && proof["enteredDeathBeforeControlClose"] : !proof["firstCloseReturned"] && raw["injectionCount"] == 0)
      UploadProcessFixture.atomic_json(File.join(@directory, "primary-proof.json"), proof)
      proof.fetch("failures").empty? ? 0 : 1
    end
  end

  # Test-only original-error ordering. A completed original TaskSlot latch,
  # never a timestamp or detached file, releases each deliberately later fault.
  # The cleanup-first cases remain UNKNOWN in their original isolated driver.
  class NativeOrderProbe
    MODES = {
      "native-order-task-before-caller-interrupt" => %w[task-before-caller interrupt],
      "native-order-task-before-caller-system-exit" => %w[task-before-caller system-exit],
      "native-order-caller-before-task-interrupt" => %w[caller-before-task interrupt],
      "native-order-caller-before-task-system-exit" => %w[caller-before-task system-exit],
      "native-order-cleanup-before-caller-interrupt" => %w[cleanup-before-caller interrupt],
      "native-order-cleanup-before-caller-system-exit" => %w[cleanup-before-caller system-exit],
    }.transform_values(&:freeze).freeze
    SOURCES = %w[tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb
                 fastlane/native_upload_validation.rb fastlane/native_process_spawn.rb
                 fastlane/native_upload_process.rb fastlane/release_support.rb].freeze
    FINITE_VALIDATOR = "STDOUT.write(\"native-order-complete\\n\")\n".freeze
    CALLER_EXIT_STATUS = 47
    class BodyFailure < StandardError; end
    class CleanupFailure < StandardError; end

    class Observation < NativeSetupDriver::Observation
      def install
        super
        driver = @driver
        session_class = @native.const_get(:CaptureSession, false)
        %i[cancel! record_cleanup_error].each do |operation|
          @hooks.wrap(@helper::TaskSlot, operation) do |original, object, arguments, keywords, block|
            error = operation == :cancel! ? keywords[:error] : arguments.first
            before = driver.before_latch(object, operation, error)
            value = original.call(*arguments, **keywords, &block)
            driver.latch_returned(before, value) if before
            value
          end
        end
        @hooks.wrap(session_class, :caller_failure) do |original, object, arguments, keywords, block|
          receipt = driver.caller_failure_entered(object, arguments.first)
          value = original.call(*arguments, **keywords, &block)
          driver.caller_failure_returned(receipt) if receipt
          value
        end
        @hooks.wrap(session_class, :run) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          driver.body_returned(object, value)
          value
        end
        @hooks.wrap(@helper::TaskSlot, :close_launch!) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          # Exactly the installed Hooks body and this wrapper precede the
          # original caller. Never search ancestors for a convenient match.
          driver.launch_closed(object, value, caller_locations(2, 1).first)
          value
        end
      end
    end

    class Driver < NativeSetupDriver
      attr_reader :family, :caller_kind

      def initialize(directory, mode)
        @family, @caller_kind = MODES.fetch(mode)
        super
        @caller_error = if @caller_kind == "interrupt"
          Interrupt.new("original native order caller cancellation")
        else
          SystemExit.new(CALLER_EXIT_STATUS, "original native order caller cancellation")
        end
        @caller_message = @caller_error.message.dup.freeze
        @caller_status = @caller_error.status if @caller_error.is_a?(SystemExit)
        @body_error = caller_first? ? IOError.new("later native order body IOError") : BodyFailure.new("original native order body failure")
        @cleanup_error = CleanupFailure.new("original native order task cleanup failure")
        @injected_error = cleanup_first? ? @cleanup_error : caller_first? ? @caller_error : @body_error
        @injected_message = @injected_error.message.dup.freeze
        @injected_status = @injected_error.status if @injected_error.is_a?(SystemExit)
        @driver_thread = Thread.current
        @receipts, @receipt_lock = [], Mutex.new
        @body_fault_count = @cleanup_fault_count = @caller_send_count = 0
      end

      def caller_first? = @family == "caller-before-task"
      def cleanup_first? = @family == "cleanup-before-caller"

      def require_order!(condition, message)
        raise Failure.new("native-order", message) unless condition
      end

      def remember(kind, **fields)
        @receipt_lock.synchronize do
          require_order!(@receipts.length < 64, "original order observation exceeded its bound")
          receipt = fields.merge(kind: kind, thread: Thread.current, ordinal: @receipts.length).freeze
          @receipts << receipt
          receipt
        end
      end

      def source_snapshot
        root = File.expand_path("../..", __dir__)
        SOURCES.to_h do |name|
          path = File.join(root, name)
          before = File.lstat(path)
          require_order!(before.file? && File.realpath(path) == path && before.size <= 1_048_576,
                         "order source is not the original bounded regular file")
          bytes = File.binread(path, 1_048_577)
          after = File.lstat(path)
          identity = ->(stat) { [stat.dev, stat.ino, stat.mode, stat.size, stat.mtime, stat.ctime] }
          require_order!(bytes.bytesize == before.size && identity.call(before) == identity.call(after),
                         "order source changed during observation")
          [name, Digest::SHA256.hexdigest(bytes)]
        end
      end

      def prepare_native
        super
        @source_hashes = source_snapshot.freeze
        helper = MobileReleaseKit::NativeUploadProcess
        if cleanup_first?
          @argv = [File.realpath(RbConfig.ruby), *helper::HELPER_FLAGS, "-e", FINITE_VALIDATOR].freeze
        end
        source, = helper::TaskSlot.instance_method(:task_entry).source_location
        source = File.realpath(source)
        lines = File.binread(source, 1_048_577).lines
        tail = "          begin\n            close_launch!\n            @lock.synchronize { @finished = true }\n          rescue Exception => error\n            record_cleanup_error(error)\n"
        starts = lines.each_index.select { |index| lines[index, tail.lines.length]&.join == tail }
        require_order!(starts.length == 1 && Digest::SHA256.file(source).hexdigest == @source_hashes.fetch("fastlane/native_upload_process.rb"),
                       "original TaskSlot cleanup tail is not uniquely bound")
        @tail_site = {"path" => source, "line" => starts.first + 2}.freeze
        @observation = Observation.new(self, native: @native, root: @directory)
      end

      def native_event(name, object)
        if cleanup_first? && name == :ready_before_stdin_close
          session = @observation.session
          require_order!(object.equal?(session) && session.hello && session.reserved && session.ready,
                         "finite order validator lacks the original native READY")
          @control.admitted!
          @observed["ready"] = @observed["firstCloseEntered"] = true
          @observed["readinessSeconds"] = UploadProcessFixture.clock - @capture_started
          publish_owner("ready")
        else
          super
        end
      end

      def first_close
        session = @observation.session
        require_order!(!@first_close && Thread.current.equal?(session.capture_slot.thread),
                       "order close did not enter once on the original capture task")
        lease = session.leases.fetch(:stdin_write)
        require_order!(lease.state == :closed && lease.io.closed? && session.stdin_close_returned && session.primary_error.nil?,
                       "order fault preceded genuine close or followed an earlier error")
        @first_close = remember("stdin-close-return", session: session, slot: session.capture_slot, lease: lease)
        @observed["firstCloseFromNative"] = @observed["originalCloseCompleted"] = true
        return if cleanup_first?

        @observed["injectionCount"] += 1
        if caller_first?
          send_caller(nil)
          barrier = await_caller_latch(session.capture_slot)
          @body_throw = remember("body-raise", error: @body_error, barrier: barrier)
        else
          @body_throw = remember("body-raise", error: @body_error, barrier: @first_close)
        end
        @body_fault_count += 1
        raise @body_error
      end

      def before_latch(slot, operation, error)
        session = @observation.session
        return unless session && slot.equal?(session.capture_slot) && error
        {slot: slot, record: slot.__send__(:failure_record), operation: operation, error: error,
         prior: slot.first_error, thread: Thread.current}.freeze
      end

      def latch_returned(before, value)
        slot, error, operation = before.values_at(:slot, :error, :operation)
        require_order!(Thread.current.equal?(before.fetch(:thread)) &&
                       (operation == :cancel! ? value.equal?(true) : value.nil?),
                       "order latch lacks its original completed call")
        receipt = remember("latch-return", **before.reject { |key, _| key == :thread },
                           first: slot.first_error, launch_retired: slot.launch_retired?, returned: true)
        if error.equal?(@injected_error) && before[:prior].nil?
          expected_thread = caller_first? ? slot.caller : slot.thread
          expected_operation = cleanup_first? ? :record_cleanup_error : :cancel!
          origin = cleanup_first? ? @cleanup_throw : caller_first? ? @send_enter : @body_throw
          require_order!(origin && operation == expected_operation && Thread.current.equal?(expected_thread) &&
                         slot.first_error.equal?(@injected_error) && slot.launch_retired?,
                         "first order error was not latched by its original task/caller path")
          @receipt_lock.synchronize do
            require_order!(@first_latch.nil?, "more than one original first-latch receipt")
            @first_latch = receipt
          end
          send_caller(receipt) unless caller_first?
        end
        later = caller_first? ? @body_error : @caller_error
        if error.equal?(later)
          expected_thread = caller_first? ? slot.thread : slot.caller
          require_order!(before[:prior].equal?(@injected_error) && slot.first_error.equal?(@injected_error) &&
                         Thread.current.equal?(expected_thread), "later original error replaced or preceded the first latch")
          @receipt_lock.synchronize { @later_latch ||= receipt }
        end
      end

      def send_caller(barrier)
        slot = @observation.session.capture_slot
        require_order!(@caller_send_count.zero? && Thread.current.equal?(slot.thread) &&
                       slot.caller.equal?(@driver_thread) && !slot.caller.equal?(Thread.current),
                       "order cancellation was not sent by the original capture task to its caller")
        require_order!(caller_first? ? barrier.nil? && slot.first_error.nil? : barrier.equal?(@first_latch) && slot.first_error.equal?(@injected_error),
                       "caller delivery crossed an unobserved first-error boundary")
        @caller_send_count += 1
        @send_enter = remember("caller-raise-enter", error: @caller_error, target: slot.caller,
                               slot: slot, barrier: barrier, first: slot.first_error)
        slot.caller.raise(@caller_error) # Actual Thread#raise, never direct cancel!/a reconstructed exception.
        @send_return = remember("caller-raise-return", entry: @send_enter, target: slot.caller)
      end

      def await_caller_latch(slot)
        loop do
          receipt = @receipt_lock.synchronize { @first_latch }
          if receipt
            require_order!(receipt[:error].equal?(@caller_error) && receipt[:slot].equal?(slot) &&
                           receipt[:record].equal?(slot.__send__(:failure_record)) && receipt[:returned] &&
                           slot.first_error.equal?(@caller_error), "caller barrier is not the original TaskSlot latch")
            return receipt
          end
          # This clock bounds waiting only. It never decides error order.
          remaining = [slot.run_deadline_ns, slot.cleanup_deadline_ns].min - MobileReleaseKit::NativeUploadProcess.monotonic_ns
          require_order!(remaining.positive?, "original caller latch missed the original capture cutoff")
          sleep [remaining, MobileReleaseKit::NativeUploadProcess::POLL_NS].min.fdiv(1_000_000_000)
        end
      end

      def caller_failure_entered(session, error)
        return unless error.equal?(@caller_error)
        require_order!(session.equal?(@observation.session) && Thread.current.equal?(session.capture_slot.caller) && @send_enter,
                       "caller error did not enter the original capture caller rescue")
        remember("caller-failure-enter", session: session, error: error, delivery: @send_enter)
      end

      def caller_failure_returned(entry)
        session = entry.fetch(:session)
        require_order!(session.primary_error.equal?(@injected_error) &&
                       session.instance_variable_get(:@caller_errors).any? { |error| error.equal?(@caller_error) },
                       "original caller rescue did not preserve the first latch")
        @caller_rescue ||= remember("caller-failure-return", entry: entry, first: session.primary_error)
      end

      def body_returned(session, value)
        return unless cleanup_first? && session.equal?(@observation.session)
        slot, child, receipt = session.capture_slot, session.custodian_child, session.custodian_receipt
        require_order!(Thread.current.equal?(slot.thread) && session.primary_error.nil? && slot.cleanup_errors.empty? &&
                       session.instance_variable_get(:@argv).equal?(@argv) &&
                       value.equal?(session.instance_variable_get(:@stdout)) && value == "native-order-complete\n" &&
                       child && receipt && receipt.equal?(child.receipt) && receipt.raw_status.is_a?(Process::Status) &&
                       receipt.status_kind == "exit" && receipt.status_code == 0 && session.final && session.final["outcome"] == "ok",
                       "cleanup-first body did not really return without an earlier error")
        @body_return = remember("body-return", session: session, slot: slot, value: value, child: child, receipt: receipt,
                                primary: session.primary_error)
      end

      def launch_closed(slot, value, location)
        return unless cleanup_first? && @body_return && slot.equal?(@observation.session.capture_slot) &&
                      Thread.current.equal?(slot.thread) && @cleanup_fault_count.zero?
        path = location && (location.absolute_path || location.path)
        require_order!(path && File.realpath(path) == @tail_site.fetch("path") && location.lineno == @tail_site.fetch("line") &&
                       value.equal?(true) && slot.launch_retired? && slot.first_error.nil? && slot.cleanup_errors.empty? &&
                       slot.offer.equal?(@body_return.fetch(:value)), "cleanup fault is not the original post-offer task ensure")
        @tail_close = remember("task-tail-close-return", slot: slot, body: @body_return, source: @tail_site, primary: slot.first_error)
        @cleanup_fault_count += 1
        @cleanup_throw = remember("cleanup-raise", error: @cleanup_error, barrier: @tail_close)
        raise @cleanup_error # Original TaskSlot ensure rescue records this exact object.
      end

      def exercise
        @capture_started = UploadProcessFixture.clock
        begin
          @observation.observe do
            @native.capture({}, @argv, @tooling, max_seconds: READINESS_LIMIT, max_output_bytes: 1_024,
                            label: "Synthetic", failure_message: "synthetic validation failure")
          end
        rescue Exception => error
          @native_error = error
        ensure
          @observed["captureSeconds"] = UploadProcessFixture.clock - @capture_started
        end
        @observed["nativeErrorClass"], @observed["nativeErrorMessage"] = @native_error&.class&.name, @native_error&.message
        @observed["nativeOriginalErrorPreserved"] = @native_error.equal?(@injected_error) && @native_error.message == @injected_message
        @observed["nativeExitStatus"] = @native_error.status if @native_error.is_a?(SystemExit)
        primary = @observation.session&.primary_error
        unless @injected_error.equal?(primary) && @native_error.equal?(@injected_error)
          raise @native_error || primary || Failure.new("native-order", "native order capture did not deliver its actual first error")
        end
        if cleanup_first?
          require_order!(@observation.unknown? && !@observation.finalized? && @observation.session.retained_unknown?,
                         "task cleanup uncertainty was promoted to native finality")
        else
          require_order!(@observation.finalized?, "ordered native cancellation did not prove actual finality")
          @observed["deadBeforeFallback"] = true
        end
        # The fixture's original outer Lifetime must retain this object too.
        # No fresh capture/observer follows UNKNOWN in this original driver.
        raise primary
      end

      def error_fact(error)
        {"class" => error.class.name, "message" => error.message,
         "exitStatus" => error.is_a?(SystemExit) ? error.status : nil}
      end

      def receipt_fact(receipt)
        return nil unless receipt
        slot = @observation.session.capture_slot
        {"operation" => receipt.fetch(:operation).to_s, "originalCallReturned" => receipt[:returned],
         "thread" => receipt[:thread].equal?(slot.caller) ? "caller" : receipt[:thread].equal?(slot.thread) ? "capture" : "other",
         "originalSlot" => receipt[:slot].equal?(slot), "originalSharedRecord" => receipt[:record].equal?(slot.__send__(:failure_record)),
         "priorWasNil" => receipt[:prior].nil?, "priorWasFirst" => receipt[:prior].equal?(@injected_error),
         "firstSameObject" => receipt[:first].equal?(@injected_error), "launchRetired" => receipt[:launch_retired]}
      end

      def proof(status, raw)
        session = @observation.session
        slot, creator = session.capture_slot, session.creator_slot
        snapshot = raw.fetch("nativeObservation")
        failures = []
        check = ->(name, value) { failures << name unless value }
        first, later = @first_latch, @later_latch
        check.call("original failed fixture result", status == 1 && raw["kind"] == (cleanup_first? ? "fixture-cleanup" : "unexpected"))
        check.call("same first object through original boundaries", @outer_failure.equal?(@injected_error) &&
          @native_error.equal?(@injected_error) && session.primary_error.equal?(@injected_error) && slot.first_error.equal?(@injected_error))
        check.call("unchanged original first message/status", @injected_error.message == @injected_message &&
          (!@injected_error.is_a?(SystemExit) || @injected_error.status == @injected_status))
        check.call("unchanged original caller message/status", @caller_error.message == @caller_message &&
          (!@caller_error.is_a?(SystemExit) || @caller_error.status == @caller_status))
        check.call("no original upload acceptance", session.phase != :accepted)
        check.call("original shared creator/capture latch", creator && creator.__send__(:failure_record).equal?(slot.__send__(:failure_record)) &&
          creator.first_error.equal?(@injected_error))
        check.call("actual first and later latch returns", first && later && first[:prior].nil? && first[:returned] && later[:returned] &&
          first[:error].equal?(@injected_error) && first[:first].equal?(@injected_error) && later[:prior].equal?(@injected_error) &&
          later[:first].equal?(@injected_error) && first[:record].equal?(later[:record]))
        causal = caller_first? ? @body_throw && @body_throw[:barrier].equal?(first) : @send_enter && @send_enter[:barrier].equal?(first)
        check.call("actual latch released later fault", causal)
        check.call("actual caller delivery and rescue", @caller_send_count == 1 && @send_return &&
          @send_return[:entry].equal?(@send_enter) && @caller_rescue && @caller_rescue[:entry][:delivery].equal?(@send_enter) &&
          session.caller_primary.equal?(@caller_error) && session.instance_variable_get(:@caller_errors).any? { |error| error.equal?(@caller_error) })
        check.call("actual original stdin close", @first_close && snapshot["stdinCloseReturned"] &&
          raw["ready"] && raw["firstCloseEntered"] && raw["firstCloseFromNative"] && raw["originalCloseCompleted"])
        check.call("actual capture/creator joins", snapshot.fetch("tasks").all? { |task| task["joined"] && task["actualJoinObserved"] && !task["unresolved"] })
        check.call("actual original native closes", snapshot.fetch("leases").all? { |lease| lease["state"] == "closed" && lease["closed"] && lease["actualCloseObserved"] && lease["closeError"].nil? })
        check.call("actual original native EOFs", snapshot.fetch("streams").values.all? { |value| value.equal?(true) })
        child, receipt = session.custodian_child, session.custodian_receipt
        check.call("actual original C wait", child && child.equal?(session.acquisition.child) && receipt && receipt.equal?(child.receipt) &&
          receipt.raw_status.is_a?(Process::Status) && receipt.raw_status.pid == child.pid)
        check.call("no fixture fallback or pending cancellation", !raw["fallbackUsed"] && !raw["watchdogIntervened"] && !raw["pendingInterrupt"])
        %w[ownedDescriptorsClosed watchdogJoined injectorsJoined handlersRestored registryInactive].each { |name| check.call(name, raw[name]) }
        check.call("no fixture cleanup errors", @cleanup_errors.empty? && raw["cleanupErrors"] == [])
        check.call("observation restored", snapshot["hooksRestored"] && snapshot["observerErrors"] == [])
        check.call("unchanged original sources", source_snapshot == @source_hashes)
        if cleanup_first?
          check.call("actual clean body then original cleanup fault", @body_return && @body_return[:primary].nil? && @tail_close &&
            @tail_close[:body].equal?(@body_return) && @tail_close[:primary].nil? && @cleanup_throw &&
            @cleanup_throw[:barrier].equal?(@tail_close) && @cleanup_fault_count == 1 && @body_fault_count.zero? &&
            first && first[:operation] == :record_cleanup_error && slot.cleanup_errors.any? { |error| error.equal?(@cleanup_error) })
          check.call("unknown original task/session retained", snapshot["unknown"] && !snapshot["finalized"] && !snapshot["noProducers"] &&
            !slot.finished? && slot.joined? && !slot.unresolved? && session.retained_unknown? && !session.finality_confirmed? &&
            MobileReleaseKit::NativeUploadValidation.__send__(:unresolved_sessions).any? { |item| item.equal?(session) })
          check.call("real pre-tail native success not finality", session.final["outcome"] == "ok" && session.final["cleanup"] == "confirmed" &&
            receipt.status_kind == "exit" && receipt.status_code == 0 && session.final["validator"]["status_kind"] == "exit" &&
            session.final["validator"]["status_code"] == 0 && !raw["tasksJoined"] && !raw["watchdogStarted"] && !raw.key?("deadBeforeFallback"))
        else
          check.call("actual body error recorded", @body_fault_count == 1 && @cleanup_fault_count.zero? &&
            session.instance_variable_get(:@task_errors).any? { |error| error.equal?(@body_error) })
          check.call("actual settled native cancellation", snapshot["finalized"] && !snapshot["unknown"] && slot.finished? &&
            raw["tasksJoined"] && raw["watchdogStarted"] && raw["deadBeforeFallback"] &&
            session.final["outcome"] == "failed" && session.final["cleanup"] == "confirmed" &&
            receipt.status_kind == "exit" && receipt.status_code == 2 && session.final["validator"]["status_kind"] == "signal" &&
            session.final["validator"]["status_code"] == Signal.list.fetch("KILL"))
        end
        {"version" => 1, "kind" => "native-order-observation", "case" => @mode, "family" => @family, "callerKind" => @caller_kind,
         "sourceSha256" => @source_hashes, "baseDriverReturn" => status, "failures" => failures,
         "firstError" => error_fact(@injected_error), "callerError" => error_fact(@caller_error),
         "bodyError" => error_fact(@body_error), "cleanupError" => error_fact(@cleanup_error),
         "firstLatch" => receipt_fact(first), "laterLatch" => receipt_fact(later),
         "causalBarrierBound" => !!causal, "callerDeliveryReturned" => !!@send_return, "callerRescueObserved" => !!@caller_rescue,
         "callerDeliveries" => @caller_send_count, "bodyFaults" => @body_fault_count, "cleanupFaults" => @cleanup_fault_count,
         "outerFirstSameObject" => @outer_failure.equal?(@injected_error), "nativeFirstSameObject" => @native_error.equal?(@injected_error),
         "captureFirstSameObject" => slot.first_error.equal?(@injected_error), "creatorFirstSameObject" => creator.first_error.equal?(@injected_error),
         "captureFinished" => slot.finished?, "captureJoined" => slot.joined?, "retainedOriginalSession" => session.retained_unknown?,
         "expectedUnknown" => cleanup_first?, "ordinaryProductionPass" => false, "originalAccepted" => session.phase == :accepted,
         "cleanupTailSource" => cleanup_first? ? @tail_site : nil,
         "finiteValidator" => cleanup_first? ? {"argv" => session.instance_variable_get(:@argv), "sha256" => Digest::SHA256.hexdigest(FINITE_VALIDATOR)} : nil,
         "receiptEvents" => @receipts.map { |entry| {"kind" => entry[:kind], "ordinal" => entry[:ordinal],
           "thread" => entry[:thread].equal?(slot.caller) ? "caller" : entry[:thread].equal?(slot.thread) ? "capture" : "other"} }}
      end
    end

    def initialize(directory, mode)
      MODES.fetch(mode)
      @directory, @mode = directory, mode
    end

    def execute
      driver = Driver.new(@directory, @mode)
      status = driver.execute
      raw = UploadProcessFixture.read_json(File.join(@directory, "result.json"))
      proof = driver.proof(status, raw)
      raise Failure.new("native-order", "oversized native order proof") if JSON.generate(proof).bytesize > OUTPUT_LIMIT
      UploadProcessFixture.atomic_json(File.join(@directory, "native-order-proof.json"), proof)
      proof.fetch("failures").empty? ? 0 : 1
    end
  end

  # Separate opt-in proof, never installed by the ordinary native/adapter suites.
  # Actual helper/group receipts are observed, never adopted as process authority;
  # entered runs still require the admitted disposable hosted environment.
  class NativeSignalProbe
    MODES = %w[native-setup-interrupt native-setup-system-exit native-setup-io-error
               native-setup-post-reap-cancel].freeze
    SOURCES = %w[tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb
                 fastlane/native_upload_validation.rb fastlane/native_process_spawn.rb
                 fastlane/native_upload_process.rb fastlane/release_support.rb].freeze
    CONTROL_STATES = %w[reserved unknown retired-before-first-nil-wait reaped].freeze
    ROUTES = %w[custodian-group keeper-self-group custodian-direct-keeper fixture].freeze
    MAX_REQUESTS = 64
    class << self
      attr_accessor :current, :last_parent
    end
    attr_reader :source_hashes, :requests, :failures, :records, :control_forwards, :hooks_restored

    def initialize(role, mode, root: nil, driver: nil, helper_copy: nil)
      raise "invalid fixed signal proof" unless %i[parent driver helper control].include?(role) && MODES.include?(mode)
      @role, @mode, @root, @driver, @helper_copy = role, mode, root, driver, helper_copy
      @requests, @failures, @records, @creations, @groups = [], [], [], [], []
      @wait_entered, @waits, @joined_threads, @finished_creations = {}, [], [], []
      @constructed_slots, @closed_launches, @closed_leases = [], [], []
      @retiring_groups, @retired_groups, @scope = [], [], nil
      @control_forwards = 0
      @hooks_restored = false
      base = File.expand_path("../..", __dir__)
      @paths = SOURCES.to_h { |name| [name, File.realpath(File.join(base, name))] }
      @source_hashes = source_snapshot.freeze
      if defined?(MobileReleaseKit::NativeUploadProcess)
        @helper = MobileReleaseKit::NativeUploadProcess
        @spawn = @helper.native # Copied helpers retain their explicit original leaf dependency.
      else
        @spawn, @helper = OwnedChild.native_modules
      end
      @helper_path = helper_copy ? helper_copy.fetch("path") : @paths.fetch("fastlane/native_upload_process.rb")
      if helper_copy
        unless helper_copy.keys.sort == %w[label originalPath originalSha256 path sha256] &&
               helper_copy["label"] == "signal-observed" && helper_copy["originalPath"] == @paths.fetch("fastlane/native_upload_process.rb") &&
               helper_copy["originalSha256"] == @source_hashes.fetch("fastlane/native_upload_process.rb") &&
               helper_copy["path"] == File.realpath(helper_copy.fetch("path")) &&
               Digest::SHA256.hexdigest(bounded_source(helper_copy.fetch("path"))) == helper_copy["sha256"]
          raise Failure.new("signal-observation", "helper copy provenance is not bound")
        end
      end
      @anchors = {
        "custodian-group" => anchor(@helper_path, 'result = Process.kill(signal, -@id)'),
        "keeper-self-group" => anchor(@helper_path, 'result = Process.kill(signal, -@pid)'),
        "custodian-direct-keeper" => anchor(@helper_path, 'result = Process.kill("KILL", @keeper.pid)'),
        "fixture" => anchor(@paths.fetch("tests/workflow/upload_process_ownership.rb"), 'Process.kill(signal, group ? -@pid : @pid)'),
        "self" => anchor(@paths.fetch("tests/workflow/upload_process_fixture.rb"), 'Process.kill("INT", Process.pid)')
      }
      @helper_main_origin = @helper.method(:helper_main).source_location
    end

    def parent_for?(root, mode)
      @role == :parent && @root == root && @mode == mode
    end

    def bounded_source(path)
      File.open(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) do |file|
        before = file.stat
        raise "unbounded signal proof source" unless before.file? && before.size <= 1_048_576
        bytes = file.read(1_048_577)
        identity = ->(stat) { [stat.dev, stat.ino, stat.mode, stat.size, stat.mtime, stat.ctime] }
        unless bytes && bytes.bytesize == before.size && identity.call(before) == identity.call(file.stat)
          raise "signal proof source changed while read"
        end
        bytes
      end
    end

    def source_snapshot
      @paths.to_h { |name, path| [name, Digest::SHA256.hexdigest(bounded_source(path))] }
    end

    def anchor(path, prefix)
      lines = bounded_source(path).lines
      positions = lines.each_index.select { |index| lines[index].strip.start_with?(prefix) }
      raise "signal proof source anchor changed" unless positions.length == 1
      [File.realpath(path), positions.first + 1].freeze
    end

    def fail!(reason)
      @failures << reason unless @failures.include?(reason)
    end

    def check(name, condition)
      fail!(name) unless condition
      !!condition
    end

    def with_owner(route, owner)
      previous = @scope
      @scope = [route, owner]
      yield
    ensure
      @scope = previous
    end

    def fixture_record(owner)
      existing = @records.find { |record| record[:owner].equal?(owner) }
      return existing if existing
      raise "signal fixture reservation bound exceeded" if @records.length >= 128
      record = {owner: owner, pid: nil, child: nil, private_group: false, state: :unknown, status: nil}
      @records << record # Exists before the potentially effectful start.
      record
    end

    def actual_receipt?(child, receipt)
      return false unless child && receipt && receipt.equal?(child.receipt) && child.state == :reaped
      raw = receipt.raw_status
      raw.instance_of?(Process::Status) && raw.pid == child.pid && receipt.pid == child.pid &&
        (receipt.status_kind == "exit" ? raw.exited? && raw.exitstatus == receipt.status_code :
         receipt.status_kind == "signal" && raw.signaled? && raw.termsig == receipt.status_code) &&
        @waits.any? { |actual, observed| actual.equal?(child) && observed.equal?(receipt) }
    end

    def update_fixture(owner)
      record = fixture_record(owner)
      child = owner.child
      if child && owner.acquisition && child.equal?(owner.acquisition.child)
        record[:child], record[:pid] = child, child.pid
        ready = owner.provenance["ready"]
        record[:private_group] = ready && ready.values_at("pid", "pgid", "sid") == [child.pid] * 3
        if actual_receipt?(child, child.receipt) && owner.status.equal?(child.receipt.raw_status)
          record[:state], record[:status] = :reaped, owner.status
        elsif @wait_entered[child] || child.numeric_retired?
          record[:state] = :retired
        elsif owner.phase == :reserved && child.state == :running && child.receipt.nil?
          record[:state] = :reserved
        else
          record[:state] = :unknown
        end
      end
      record
    end

    def child_state(child, group: nil)
      return "unknown" unless child
      return "reaped" if child.state == :reaped && child.receipt
      return "unknown" if child.state == :unknown
      if @wait_entered[child] || child.numeric_retired? || (group && (@retiring_groups.include?(group) || group.retired?))
        return "retired-before-first-nil-wait"
      end
      child.state == :running && child.receipt.nil? ? "reserved" : "unknown"
    end

    def created_child?(owner, child)
      acquisition, slot = owner.creator_acquisition, owner.creator_slot
      child && acquisition && child.equal?(acquisition.child) && slot && slot.joined? && slot.finished? &&
        @joined_threads.include?(slot.thread) && @finished_creations.include?(acquisition) &&
        @constructed_slots.include?(slot) && @closed_launches.include?(slot) && slot.launch_retired? &&
        acquisition.owner_slot.equal?(slot) && acquisition.launch_retired? &&
        @creations.any? { |entry| entry[:returned] && entry[:acquisition].equal?(acquisition) && entry[:child].equal?(child) && entry[:result].equal?(child) }
    end

    def context_for(signal, targets, source)
      route, owner = @scope
      context = {"origin" => "unrecognized", "route" => route || "unrecognized", "signal" => signal,
        "targets" => targets, "source" => source, "state" => "unknown", "sourceBound" => false,
        "ownerBound" => false, "targetBound" => false, "holderPid" => nil,
        "beforeFirstWait" => false, "numericRetired" => true, "groupRetired" => nil}
      return context unless route && owner
      context["sourceBound"] = source == @anchors[route]
      case route
      when "fixture"
        record = update_fixture(owner)
        child = record[:child]
        bound = child && owner.phase == :reserved && owner.acquisition && child.equal?(owner.acquisition.child) && owner.creator&.joined? &&
          @joined_threads.include?(owner.creator.thread)
        state = {reserved: "reserved", reaped: "reaped", retired: "retired-before-first-nil-wait", unknown: "unknown"}.fetch(record[:state])
        context.merge!("origin" => "fixture", "state" => state, "ownerBound" => !!bound,
          "targetBound" => !!(child && (targets == [child.pid] || (record[:private_group] && targets == [-child.pid]))),
          "holderPid" => child&.pid, "beforeFirstWait" => !!(child && !@wait_entered[child]),
          "numericRetired" => !child || child.numeric_retired?, "groupRetired" => !child || child.numeric_retired?)
      when "custodian-group"
        group = owner
        keeper = group.keeper
        bound = @runtime.is_a?(@helper::Custodian) && @runtime.group.equal?(group) && @groups.include?(group) &&
          @runtime.keeper.equal?(keeper) && created_child?(@runtime, keeper) && @runtime.pid == Process.pid &&
          group.id == keeper.pid && group.session_id == Process.pid
        context.merge!("origin" => "native", "state" => child_state(keeper, group: group), "ownerBound" => !!bound,
          "targetBound" => targets == [-group.id], "holderPid" => keeper.pid,
          "beforeFirstWait" => !@wait_entered[keeper], "numericRetired" => keeper.numeric_retired?,
          "groupRetired" => group.retired? || @retiring_groups.include?(group), "absent" => group.absent?)
      when "custodian-direct-keeper"
        keeper = owner.keeper
        group_closed = owner.instance_variable_get(:@group_routes_retired) && (!owner.group || owner.group.retired?)
        bound = owner.equal?(@runtime) && owner.is_a?(@helper::Custodian) && owner.pid == Process.pid &&
          created_child?(owner, keeper) && group_closed
        context.merge!("origin" => "native", "state" => child_state(keeper), "ownerBound" => !!bound,
          "targetBound" => !!(keeper && targets == [keeper.pid]), "holderPid" => keeper&.pid,
          "beforeFirstWait" => !!(keeper && !@wait_entered[keeper]), "numericRetired" => !keeper || keeper.numeric_retired?,
          "groupRetired" => !!group_closed)
      when "keeper-self-group"
        retired = owner.instance_variable_get(:@self_group_retired)
        absent = owner.instance_variable_get(:@self_group_absent)
        bound = owner.equal?(@runtime) && owner.is_a?(@helper::Keeper) && owner.pid == Process.pid &&
          owner.instance_variable_get(:@group_created) && Process.getsid(0) == owner.parent_pid
        context.merge!("origin" => "native", "state" => retired ? "retired-before-first-nil-wait" : bound ? "reserved" : "unknown",
          "ownerBound" => !!bound, "targetBound" => targets == [-Process.pid], "holderPid" => Process.pid,
          "beforeFirstWait" => true, "numericRetired" => !!retired, "groupRetired" => !!retired,
          "absent" => !!absent)
      when "self"
        session = @driver&.observation&.session
        original = @driver&.instance_variable_get(:@injected_error)
        scope = UploadProcessFixture.instance_variable_get(:@cancellation_scope)
        bound = @mode == MODES.last && owner.equal?(@driver) && @driver.observation.finalized? && session &&
          session.primary_error.equal?(original) && actual_receipt?(session.custodian_child, session.custodian_receipt) &&
          scope && scope.cleanup_depth.positive?
        context.merge!("origin" => "self", "state" => "self", "ownerBound" => !!bound,
          "targetBound" => targets == [Process.pid], "holderPid" => Process.pid,
          "beforeFirstWait" => false, "numericRetired" => true)
      end
      context
    end

    def refusal(context)
      targets = context["targets"]
      return "shape" unless targets.is_a?(Array) && targets.length == 1 && targets.first.instance_of?(Integer) && targets.first.abs > 1
      if context["origin"] != "self"
        return "post-reap" if context["state"] == "reaped"
        return "post-retirement" if context["state"] == "retired-before-first-nil-wait"
        return "unknown" unless context["state"] == "reserved"
      end
      return "source" unless context["sourceBound"]
      return "owner" unless context["ownerBound"]
      return "target" unless context["targetBound"]
      expected = context["origin"] == "self" ? ["INT"] : context["route"] == "custodian-direct-keeper" ? ["KILL"] : [0, "KILL"]
      return "signal" unless expected.include?(context["signal"])
      return "retired" if context["origin"] != "self" && (!context["beforeFirstWait"] || context["numericRetired"])
      if %w[custodian-group keeper-self-group].include?(context["route"])
        return "retired" if context["groupRetired"] || context["absent"]
      end
      nil
    end

    def request(signal, targets, location, backend)
      source = location ? [location.absolute_path || location.path, location.lineno] : [nil, nil]
      context = context_for(signal, targets, source)
      dispatch(context, backend: backend)
    rescue Exception => error
      fail!("request observation:#{error.class.name}") unless error.is_a?(Errno::ESRCH)
      raise
    end

    def dispatch(context, backend: nil)
      raise "signal observation exceeded its bound" if @requests.length >= MAX_REQUESTS
      raise "inert observer cannot choose a native backend" if @role == :control && backend
      reason = refusal(context)
      path, line = context.fetch("source")
      source_name = path == @helper_path ? "fastlane/native_upload_process.rb" : @paths.key(path)
      item = context.reject { |key, _| key == "source" }.merge(
        "signal" => context.fetch("signal").to_s,
        "source" => {"path" => source_name || "unrecognized", "executedPath" => path, "line" => line,
                     "sha256" => path == @helper_path && @helper_copy ? @helper_copy.fetch("sha256") : @source_hashes[source_name]},
        "forwarded" => false, "rejection" => reason, "result" => nil, "absenceObserved" => false)
      @requests << item
      if reason
        fail!("#{context.fetch('route')}:#{reason}")
        return 0 # Safe veto is a failure, never evidence of real containment.
      end
      item["forwarded"] = true
      if @role == :control
        @control_forwards += 1
        item["result"] = 1
      else
        raise "actual signal lacks its saved syscall" unless backend
        begin
          item["result"] = backend.call(context.fetch("signal"), *context.fetch("targets"))
        rescue Errno::ESRCH
          item["absenceObserved"] = true
          raise # The actual owner, not this observer, interprets ESRCH.
        rescue Exception => error
          item["backendErrorClass"] = error.class.name
          fail!("signal syscall:#{error.class.name}")
          raise
        end
      end
    end

    def install
      raise "signal observer is already active" if self.class.current
      self.class.current = self
      @hooks = CaptureObservation::Hooks.new
      probe = self
      @hooks.wrap(Process.singleton_class, :kill) do |original, _object, arguments, _keywords, _block|
        # One wrapper-block frame and Hooks' installed method frame intervene;
        # use the DIRECT syscall caller, never search for a convenient ancestor.
        probe.request(arguments.first, arguments.drop(1), caller_locations(2, 1).first, original)
      end
      @hooks.wrap(Process.singleton_class, :spawn) do |_original, _object, _arguments, _keywords, _block|
        probe.fail!("unowned Process.spawn")
        raise Failure.new("signal-observation", "unowned process creation vetoed")
      end
      @hooks.wrap(Thread, :join) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        probe.instance_variable_get(:@joined_threads) << object if value.equal?(object)
        value
      end
      @hooks.wrap(@spawn::Child, :poll_wait) do |original, object, arguments, keywords, block|
        probe.before_wait(object)
        value = original.call(*arguments, **keywords, &block)
        probe.instance_variable_get(:@waits) << [object, value] if value
        value
      end
      @hooks.wrap(@spawn::Acquisition, :finish_creation!) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        probe.instance_variable_get(:@finished_creations) << object if value.equal?(true)
        value
      end
      if @role == :helper
        install_helper_hooks
      else
        @hooks.wrap(OwnedChild, :start) do |original, object, arguments, keywords, block|
          raise "inert observer cannot acquire a child" if probe.instance_variable_get(:@role) == :control
          probe.fixture_record(object)
          original.call(*arguments, **keywords, &block)
        ensure
          probe.update_fixture(object) unless probe.instance_variable_get(:@role) == :control
        end
        @hooks.wrap(OwnedChild, :signal) do |original, object, arguments, keywords, block|
          probe.with_owner("fixture", object) { original.call(*arguments, **keywords, &block) }
        end
        if @role == :driver
          @hooks.wrap(NativeSetupDriver, :post_reap_cancellation) do |original, object, arguments, keywords, block|
            probe.with_owner("self", object) { original.call(*arguments, **keywords, &block) }
          end
          @hooks.wrap(@helper.singleton_class, :helper_argv) do |original, _object, arguments, keywords, block|
            result = original.call(*arguments, **keywords, &block)
            original_path = probe.instance_variable_get(:@paths).fetch("fastlane/native_upload_process.rb")
            copy = probe.instance_variable_get(:@helper_copy).fetch("path")
            raise "G1 helper argv source changed" unless result.count(original_path) == 1
            result.map { |part| part == original_path ? copy : part }.freeze
          end
        end
      end
    end

    def before_wait(child)
      @wait_entered[child] = true # Irreversible BEFORE a potentially consuming call.
      return unless @role == :helper && @runtime.is_a?(@helper::Custodian) && @runtime.keeper.equal?(child)
      group = @runtime.group
      unless @runtime.instance_variable_get(:@group_routes_retired) &&
             (!group || group.retired? && @retired_groups.include?(group))
        fail!("keeper wait preceded actual group retirement")
        raise Failure.new("signal-observation", "keeper wait without retired group vetoed")
      end
      @keeper_wait_after_retirement = true
    end

    def install_helper_hooks
      probe = self
      @hooks.wrap(@helper::Role, :run) do |original, object, arguments, keywords, block|
        raise "multiple helper runtime owners" if probe.instance_variable_get(:@runtime)
        probe.instance_variable_set(:@runtime, object)
        original.call(*arguments, **keywords, &block)
      end
      @hooks.wrap(@helper::TaskSlot, :initialize) do |original, object, arguments, keywords, block|
        probe.instance_variable_get(:@constructed_slots) << object
        original.call(*arguments, **keywords, &block)
      end
      %i[close_launch! cancel! record_cleanup_error].each do |name|
        @hooks.wrap(@helper::TaskSlot, name) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          probe.instance_variable_get(:@closed_launches) << object
          value
        end
      end
      @hooks.wrap(@spawn::IOLease, :close_once) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        probe.instance_variable_get(:@closed_leases) << object if value.equal?(true)
        value
      end
      @hooks.wrap(@spawn.singleton_class, :create) do |original, _object, arguments, keywords, block|
        acquisition, spec = arguments
        entry = {acquisition: acquisition, spec: spec, returned: false, child: nil}
        probe.instance_variable_get(:@creations) << entry
        value = original.call(*arguments, **keywords, &block)
        entry[:child], entry[:result], entry[:returned] = acquisition.child, value, true
        value
      end
      @hooks.wrap(@helper::GroupLease, :initialize) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        probe.instance_variable_get(:@groups) << object
        value
      end
      @hooks.wrap(@helper::GroupLease, :request) do |original, object, arguments, keywords, block|
        probe.with_owner("custodian-group", object) { original.call(*arguments, **keywords, &block) }
      end
      @hooks.wrap(@helper::GroupLease, :retire!) do |original, object, arguments, keywords, block|
        probe.instance_variable_get(:@retiring_groups) << object
        value = original.call(*arguments, **keywords, &block)
        probe.instance_variable_get(:@retired_groups) << object if value.equal?(true)
        value
      end
      @hooks.wrap(@helper::Keeper, :request_group) do |original, object, arguments, keywords, block|
        probe.with_owner("keeper-self-group", object) { original.call(*arguments, **keywords, &block) }
      end
      @hooks.wrap(@helper::Custodian, :last_resort_keeper_kill) do |original, object, arguments, keywords, block|
        probe.with_owner("custodian-direct-keeper", object) { original.call(*arguments, **keywords, &block) }
      end
    end

    def restore
      @failures.concat(@hooks.restore.map { |reason| "hook:#{reason}" }) if @hooks
      @hooks_restored = !!@hooks && !@failures.any? { |reason| reason.start_with?("hook:") }
    ensure
      self.class.current = nil if self.class.current.equal?(self)
    end

    def observe
      primary = value = nil
      begin
        Thread.handle_interrupt(Exception => :never) do
          begin
            install
            value = Thread.handle_interrupt(Exception => :immediate) { yield }
          rescue Exception => error
            primary ||= error
            fail!("observation body:#{error.class.name}")
          ensure
            begin
              restore
              @records.each do |record|
                owner = record.fetch(:owner)
                update_fixture(owner)
                check("fixture reservation not finally reaped", record[:state] == :reaped && owner.phase == :reaped &&
                  owner.complete? && record[:status].equal?(owner.status) && @joined_threads.include?(owner.creator.thread))
              end
              check("source changed during observation", source_snapshot == @source_hashes)
              if @helper_copy
                check("helper copy changed", Digest::SHA256.hexdigest(bounded_source(@helper_copy.fetch("path"))) == @helper_copy.fetch("sha256"))
              end
            rescue Exception => error
              primary ||= error
              fail!("observation finalization:#{error.class.name}")
            end
          end
        end
      rescue Exception => error
        primary ||= error
        fail!("observation finalization:#{error.class.name}")
      end
      raise primary if primary
      raise Failure.new("signal-observation", @failures.join("; ")) unless @failures.empty?
      value
    end

    def terminal_record(child)
      return {"state" => "unknown"} unless child && actual_receipt?(child, child.receipt)
      receipt = child.receipt
      {"state" => "reaped", "pid" => receipt.pid, "status_kind" => receipt.status_kind, "status_code" => receipt.status_code}
    end

    def evidence
      value = {"kind" => "native-signal-observation", "role" => @role.to_s, "case" => @mode,
        "sourceSha256" => @source_hashes, "hooksRestored" => !!@hooks_restored,
        "requests" => @requests, "failures" => @failures, "controlForwards" => @control_forwards,
        "fixtureReservations" => @records.map do |record|
          owner = record.fetch(:owner)
          {"pid" => record[:pid], "privateGroup" => !!record[:private_group], "phase" => record[:state].to_s,
           "ownerPhase" => owner.phase.to_s, "exitStatus" => record[:status]&.exitstatus,
           "termSignal" => record[:status]&.termsig, "complete" => owner.complete?,
           "originalWaitBound" => actual_receipt?(record[:child], record[:child]&.receipt),
           "creatorJoinObserved" => !!(owner.creator && @joined_threads.include?(owner.creator.thread))}
        end}
      text = JSON.generate(value)
      raise "oversized signal observation" if text.bytesize > OUTPUT_LIMIT
      JSON.parse(text) # Detached history; never live signal/wait permission.
    end

    def helper_facts(result, argv)
      owner = @runtime
      role = argv.first
      check("actual helper owner", owner && owner.pid == Process.pid &&
            (role == "custodian" ? owner.is_a?(@helper::Custodian) : owner.is_a?(@helper::Keeper)))
      child = role == "custodian" ? owner&.keeper : owner&.validator
      check("actual helper creator publication", owner && created_child?(owner, child))
      check("one actual helper child creation", @creations.length == 1)
      check("actual helper original child wait", child && actual_receipt?(child, child.receipt))
      slots = owner ? [owner.bootstrap_slot, owner.creator_slot] : []
      check("actual helper task joins", slots.length == 2 && @constructed_slots == slots && slots.all? do |slot|
        slot && slot.joined? && slot.finished? && !slot.unresolved? && slot.launch_retired? &&
          @closed_launches.include?(slot) && @joined_threads.include?(slot.thread)
      end)
      acquisitions = owner ? [owner.bootstrap_acquisition, owner.creator_acquisition] : []
      check("actual helper acquisitions settled", acquisitions.length == 2 && acquisitions.zip(slots).all? do |acquisition, slot|
        acquisition && acquisition.owner_slot.equal?(slot) && acquisition.launch_retired? &&
          acquisition.state == :settled && @finished_creations.include?(acquisition)
      end)
      leases = acquisitions.compact.flat_map.with_index do |acquisition, index|
        acquisition.resources.values.map do |lease|
          lifetime = lease.process_lifetime?
          closed = !!(lease.io && lease.io.closed?)
          observed = @closed_leases.include?(lease)
          absent = lease.state == :not_acquired && lease.io.nil? && @finished_creations.include?(acquisition)
          if lifetime
            null_roles = {null_stdin: [:read, 0], null_stdout: [:write, 1], null_stderr: [:write, 2]}
            expected = null_roles[lease.role]
            check("helper declared process-lifetime null", index.zero? && expected && lease.kind == :null &&
              lease.access == expected.first && lease.state == :open && lease.io.fileno == expected.last && !closed && !observed && lease.close_error.nil?)
          else
            check("actual helper owned close", lease.close_error.nil? && (absent || lease.state == :closed && closed && observed))
          end
          {"acquisition" => index.zero? ? "bootstrap" : "creator", "role" => lease.role.to_s,
           "state" => lease.state.to_s, "kind" => lease.kind.to_s, "access" => lease.access.to_s,
           "processLifetime" => lifetime, "closed" => closed, "actualCloseObserved" => observed, "noIOAcquired" => absent}
        end
      end
      group = role == "custodian" ? owner&.group : nil
      if role == "custodian"
        check("actual C group lifetime", group && @groups.include?(group) && group.keeper.equal?(child) &&
          group.id == child.pid && group.session_id == Process.pid && group.retired? && group.absent? && @retired_groups.include?(group))
        check("actual C group retirement before first K wait", @keeper_wait_after_retirement)
      end
      {"helperRole" => role, "helperReturn" => result, "pid" => Process.pid, "parentPid" => owner&.parent_pid,
       "sessionId" => owner&.session_id, "helperMainOrigin" => {"path" => @helper_main_origin.first, "line" => @helper_main_origin.last},
       "helperCopy" => @helper_copy, "child" => terminal_record(child),
       "originalWaitBound" => !!(child && actual_receipt?(child, child.receipt)),
       "creatorJoined" => !!(owner&.creator_slot && @joined_threads.include?(owner.creator_slot.thread)),
       "leases" => leases, "keeperWaitAfterRetirement" => role == "custodian" ? !!@keeper_wait_after_retirement : nil,
       "group" => group ? group.record : {"state" => owner&.instance_variable_get(:@self_group_retired) ? "retired" : "unknown",
                                          "id" => Process.pid, "absent" => !!owner&.instance_variable_get(:@self_group_absent)},
       "taskJoinsObserved" => slots.all? { |slot| slot && @joined_threads.include?(slot.thread) }}
    end

    def check_native(status, raw, helpers)
      session = @driver.observation&.session
      original = @driver.instance_variable_get(:@injected_error)
      native_error = @driver.instance_variable_get(:@native_error)
      check("base driver result", status == 0 && raw["kind"] == "pass" && raw["mode"] == @mode)
      check("actual native original primary", session && session.primary_error.equal?(original) && original.message == @driver.instance_variable_get(:@injected_message))
      if original.is_a?(IOError)
        check("actual IOError redaction", native_error.instance_of?(MobileReleaseKit::ContractError) && native_error.message == "Synthetic validator could not be executed safely; no upload is authorized")
      else
        check("actual native original", native_error.equal?(original) && native_error.message == original.message)
        check("actual SystemExit status", native_error.status == 23) if original.is_a?(SystemExit)
      end
      check("actual native finality", @driver.observation.finalized? && session && actual_receipt?(session.custodian_child, session.custodian_receipt))
      %w[ready firstCloseEntered firstCloseFromNative originalCloseCompleted watchdogStarted deadBeforeFallback
         ownedDescriptorsClosed watchdogJoined tasksJoined injectorsJoined handlersRestored registryInactive].each do |name|
        check(name, raw[name] == true)
      end
      check("one actual first close", raw["injectionCount"] == 1 && session&.stdin_close_returned)
      check("no fallback or pending cleanup", !raw["fallbackUsed"] && !raw["watchdogIntervened"] &&
        !raw.key?("workerControlEOF") && !raw["pendingInterrupt"] && raw["cleanupErrors"] == [])
      custodian, keeper = helpers.values_at("custodian", "keeper")
      helpers.each do |role, proof|
        check("#{role} helper proof", proof["case"] == @mode && proof["kind"] == "native-signal-observation" &&
          proof["helperRole"] == role && proof["sourceSha256"] == @source_hashes && proof["helperCopy"] == @helper_copy &&
          proof["hooksRestored"] && proof["failures"] == [] && proof["originalWaitBound"] && proof["creatorJoined"] && proof["taskJoinsObserved"])
      end
      if session && custodian && keeper
        check("actual failed FINAL with settled C exit2", session.final && session.final["outcome"] == "failed" &&
          session.final["cleanup"] == "confirmed" && custodian["helperReturn"] == 2)
        check("C method return bound to actual OS receipt", custodian["pid"] == session.custodian_child.pid &&
          session.custodian_receipt.status_kind == "exit" && session.custodian_receipt.status_code == custodian["helperReturn"])
        check("K method return bound to actual C wait", custodian["child"] == session.final["keeper"] &&
          custodian["child"]["pid"] == keeper["pid"] && custodian["child"]["status_kind"] == "exit" &&
          custodian["child"]["status_code"] == keeper["helperReturn"])
        check("actual original V SIGKILL", keeper["child"] == session.final["validator"] &&
          keeper["child"]["status_kind"] == "signal" && keeper["child"]["status_code"] == Signal.list.fetch("KILL"))
        check("actual reserved group finality", custodian["group"] == session.final["group"] &&
          custodian["group"]["id"] == keeper["pid"] && custodian["group"]["absent"])
      end
      native_requests = helpers.values.flat_map { |proof| proof.fetch("requests") }
      group_requests = native_requests.select { |request| %w[custodian-group keeper-self-group].include?(request["route"]) }
      kills = group_requests.select { |request| request["signal"] == "KILL" && request["forwarded"] && request["rejection"].nil? && request["result"] == 1 }
      check("actual per-case reserved-group KILL", !kills.empty?)
      check("actual per-case custodian signal zero", group_requests.any? { |request| request["route"] == "custodian-group" && request["signal"] == "0" && request["forwarded"] && request["rejection"].nil? })
      self_requests = @requests.select { |request| request["origin"] == "self" }
      if @mode == MODES.last
        check("actual post-reap repeats", raw["postReapCancellationInjected"] && raw["postReapCleanupDepth"].to_i.positive? &&
          raw["selfSignalQueued"] == Signal.list.fetch("INT") && self_requests.length == 1 && self_requests.first["forwarded"] && self_requests.first["result"] == 1)
      else
        check("no unexpected self signal", self_requests.empty?)
      end
      {"helpers" => helpers, "helperCopy" => @helper_copy, "actualOriginalPrimary" => !!(session && session.primary_error.equal?(original)),
       "actualCustodianReceiptBound" => !!(session && actual_receipt?(session.custodian_child, session.custodian_receipt)),
       "actualNativeDescriptorsClosed" => raw["ownedDescriptorsClosed"], "successfulGroupKILLs" => kills.length}
    end

    def self.observe_parent(root, mode)
      probe = new(:parent, mode, root: root)
      self.last_parent = probe
      primary = value = nil
      begin
        Thread.handle_interrupt(Exception => :never) do
          begin
            value = probe.observe { yield }
          rescue Exception => error
            primary ||= error
          ensure
            begin
              UploadProcessFixture.atomic_json(File.join(root, "#{mode}.signal-proof.json"), probe.evidence)
            rescue Exception => error
              probe.fail!("parent proof publication:#{error.class.name}")
              primary ||= error
            end
          end
        end
      rescue Exception => error
        primary ||= error
      end
      raise primary if primary
      value.merge("parentSignalProof" => probe.evidence)
    end

    def self.execute_driver(directory, mode)
      driver = NativeSetupDriver.new(directory, mode)
      insertion = <<~RUBY
        if $PROGRAM_NAME == __FILE__
          require #{File.realpath(__FILE__).inspect}
          UploadProcessFixture::NativeSignalProbe.install_helper_observation(#{directory.inspect}, #{mode.inspect})
        end
      RUBY
      _path, copy = UploadProcessFixture.copied_helper(directory, "signal-observed", insertion)
      OwnedChild.write_record(File.join(directory, "signal-copy.json"), copy)
      probe = new(:driver, mode, root: directory, driver: driver, helper_copy: copy)
      status, facts = nil, {}
      begin
        probe.observe { status = driver.execute }
        helpers = %w[custodian keeper].to_h do |role|
          [role, JSON.parse(OwnedChild.bounded_file(File.join(directory, "signal-helper-#{role}.json")))]
        end
        facts = probe.check_native(status, UploadProcessFixture.read_json(File.join(directory, "result.json")), helpers)
      rescue Exception => error
        probe.fail!("driver proof:#{error.class.name}")
      end
      proof = probe.evidence.merge(facts).merge("baseDriverReturn" => status)
      raise "oversized native signal proof" if JSON.generate(proof).bytesize > OUTPUT_LIMIT
      UploadProcessFixture.atomic_json(File.join(directory, "native-signal-proof.json"), proof)
      probe.failures.empty? ? 0 : 1
    end

    def self.install_helper_observation(directory, mode)
      UploadProcessFixture.owned_fixture_directory(directory)
      copy = JSON.parse(OwnedChild.bounded_file(File.join(directory, "signal-copy.json")))
      helper = MobileReleaseKit::NativeUploadProcess
      actual_path = File.realpath(helper.method(:helper_main).source_location.first)
      unless copy["path"] == actual_path && copy["label"] == "signal-observed"
        raise Failure.new("signal-observation", "executed helper copy is not bound")
      end
      probe = new(:helper, mode, root: directory, helper_copy: copy)
      entry = CaptureObservation::Hooks.new
      entry.wrap(helper.singleton_class, :helper_main) do |original, _object, arguments, keywords, block|
        result, facts = nil, {}
        argv = arguments.first
        begin
          probe.observe { result = original.call(*arguments, **keywords, &block) }
          facts = probe.helper_facts(result, argv)
        rescue Exception => error
          probe.fail!("helper proof:#{error.class.name}")
        ensure
          restoration = entry.restore
          restoration.each { |reason| probe.fail!("hook:entry:#{reason}") }
          probe.instance_variable_set(:@hooks_restored, false) unless restoration.empty?
        end
        proof = probe.evidence.merge(facts)
        raise "oversized helper signal proof" if JSON.generate(proof).bytesize > OUTPUT_LIMIT
        OwnedChild.write_record(File.join(directory, "signal-helper-#{argv.first}.json"), proof)
        probe.failures.empty? ? result : 1
      end
    end

    def control_context(seed, route, state, signal)
      unless @role == :control && ROUTES.include?(route) && CONTROL_STATES.include?(state) && [0, "KILL"].include?(signal)
        raise "only fixed inert signal controls accept synthetic contexts"
      end
      if route == "fixture"
        owner = seed.fetch(:owner)
        unless seed[:state] == :reaped && seed[:private_group] && owner.complete? && seed[:status].equal?(owner.status)
          raise "inert control seed lacks an actual reaped fixture child"
        end
        pid, source = seed.fetch(:pid), @anchors.fetch(route)
      else
        role = route == "keeper-self-group" ? "keeper" : "custodian"
        proof = seed.fetch(role)
        unless proof["originalWaitBound"] && proof["failures"] == [] && proof["hooksRestored"]
          raise "inert control seed lacks an actual helper receipt"
        end
        pid = route == "keeper-self-group" ? proof.fetch("pid") : proof.fetch("child").fetch("pid")
        # This is a detached, explicitly synthetic source/reservation template.
        # It never reinstates a helper object or adopts one of these numbers.
        source = @anchors.fetch(route)
      end
      {"origin" => route == "fixture" ? "fixture" : "native", "route" => route, "signal" => signal,
       "targets" => [route == "custodian-direct-keeper" ? pid : -pid], "source" => source,
       "state" => state, "sourceBound" => true, "ownerBound" => true, "targetBound" => true,
       "holderPid" => pid, "beforeFirstWait" => true, "numericRetired" => false,
       "groupRetired" => route == "custodian-direct-keeper", "absent" => false}.freeze
    end
  end

  # The actual adapter selects a per-case, fixed fake Python executable. That
  # executable receives the COMPLETE real argv/environment/cwd; only its program
  # body is the credential-free worker. No caller interpreter file is modified.
  class AdapterDriver < NativeSetupDriver
    class Observation < NativeSetupDriver::Observation
      def install
        super
        driver, observer = @driver, self
        session_class = @native.const_get(:CaptureSession, false)
        @hooks.wrap(session_class, :initialize) do |original, object, arguments, keywords, block|
          started = nil
          source = original.source_location.first
          trace = TracePoint.new(:return) do |point|
            if point.self.equal?(object) && point.method_id == :initialize && point.path == source &&
               point.binding.local_variable_defined?(:started_ns)
              started = point.binding.local_variable_get(:started_ns)
            end
          end
          value = trace.enable { original.call(*arguments, **keywords, &block) }
          driver.capture_initialized(object, started)
          value
        end
        @hooks.wrap(@native.singleton_class, :capture) do |original, _object, arguments, keywords, block|
          driver.assert_adapter_call(arguments, keywords)
          original.call(*arguments, **keywords, &block)
        end
        @hooks.wrap(MobileReleaseKit.singleton_class, :strict_json) do |original, _object, arguments, keywords, block|
          selected = driver.adapter_json_entry(arguments, keywords)
          begin
            original.call(*arguments, **keywords, &block)
          rescue Exception => error
            driver.adapter_json_error(error) if selected
            raise
          end
        end
        @hooks.wrap(session_class, :timeout_error) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          driver.timeout_constructed(object, value)
          value
        end
        @hooks.wrap(@helper::TaskSlot, :cancel!) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          driver.failure_recorded(object)
          value
        end
        @hooks.wrap(session_class, :validate_final) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          driver.after_validated_final(object, arguments.first)
          value
        end
        @hooks.wrap(session_class, :receive_frame) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          driver.status_received(object, arguments.first) if arguments.first["type"] == "STATUS"
          value
        end
        @hooks.wrap(session_class, :queue_frame) do |original, object, arguments, keywords, block|
          value = original.call(*arguments, **keywords, &block)
          if arguments.first == "COMMIT"
            driver.observed["commitAfterDataEOF"] = object.stdout_eof && object.stderr_eof && object.stdin_close_returned
            driver.observed["commitQueuedNs"] = UploadProcessFixture.clock_ns
          end
          value
        end
        @hooks.wrap(session_class, :finish_task_ownership) do |original, object, arguments, keywords, block|
          started = UploadProcessFixture.clock_ns
          value = original.call(*arguments, **keywords, &block)
          driver.observed["cleanupSeconds"] = (UploadProcessFixture.clock_ns - started) / 1_000_000_000.0
          value
        end
        @hooks.wrap(IO.singleton_class, :select) do |original, _object, arguments, keywords, block|
          session = observer.session
          streams = session && %i[stdout_read stderr_read].map { |role| session.leases[role]&.io }
          actual = session && Thread.current.equal?(session.capture_slot.thread) && streams.all? &&
            arguments.first.is_a?(Array) && (streams - arguments.first).empty?
          started = UploadProcessFixture.clock_ns
          value = original.call(*arguments, **keywords, &block)
          if actual && value.nil? && driver.observed["ready"] && !session.primary_error
            driver.blocked_data_wait(started, UploadProcessFixture.clock_ns)
          end
          value
        end
      end
    end

    def initialize(directory, platform, mode, parameters)
      super(directory, mode)
      @platform, @base_mode = platform, mode.delete_suffix("-slow-cleanup")
      @parameters = parameters.transform_keys(&:to_sym).merge(environment: {})
      @timeout_objects = []
      @observed.merge!("blockedDataWaits" => 0, "legacyRecordUsedForOwnership" => false,
        "adapterCallObserved" => false, "captureEntered" => false, "stdinClosedAfterReady" => false,
        "descendantLiveBeforeRelease" => false, "inheritedPipeBlockObserved" => false)
    end

    def source_copy(path, label, replacements)
      source = File.binread(path, 1_048_577)
      raise Failure.new("fixture-source", "oversized adapter source") if source.bytesize > 1_048_576
      changed = source.dup
      replacements.each do |anchor, replacement|
        raise Failure.new("fixture-source", "adapter mutation anchor changed") unless changed.scan(anchor).length == 1
        changed = changed.sub(anchor, replacement)
      end
      copy = path("#{label}.rb")
      File.open(copy, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o600) { |io| io.write(changed) }
      facts = {"originalPath" => File.realpath(path), "originalSha256" => Digest::SHA256.hexdigest(source),
        "path" => copy, "sha256" => Digest::SHA256.hexdigest(changed), "label" => label}
      (@observed["sourceCopies"] ||= []) << facts
      [copy, facts]
    end

    def prepare_native
      base = File.realpath(File.expand_path("../../fastlane", __dir__))
      outer = File.join(base, "native_upload_validation.rb")
      adapter = File.join(base, "#{@platform}_upload_validation.rb")
      if @base_mode == "immediate-deadline" || @base_mode == "no-deadline" || @mode.end_with?("-slow-cleanup")
        changes = %w[release_support native_process_spawn native_upload_process].map do |name|
          [%(require_relative "#{name}"), "require #{File.join(base, "#{name}.rb").inspect}"]
        end
        if @base_mode == "no-deadline"
          changes << ['@run_deadline_ns = started_ns + (max_seconds * NANOSECONDS).floor',
                      '@run_deadline_ns = started_ns + 10 * NANOSECONDS # Test-only shared O/C/K bound.']
        elsif @base_mode == "immediate-deadline"
          changes << ['@stdin_close_returned = true', "@stdin_close_returned = true\n        raise timeout_error # Deliberately premature AFTER the real close."]
        end
        if @mode.end_with?("-slow-cleanup")
          anchor = "      def finish_task_ownership\n"
          delay = <<~'RUBY'
                  unless @fixture_slow_cleanup
                    @fixture_slow_cleanup = true
                    remaining = cleanup_deadline_ns - monotonic_ns
                    raise UploadProcessFixture::Failure.new("readiness", "slow cleanup lacks original bound") unless remaining > 4_250_000_000
                    before = monotonic_ns
                    sleep 4
                    @fixture_slow_cleanup_ns = monotonic_ns - before
                  end
          RUBY
          changes << [anchor, anchor + delay.lines.map { |line| "        " + line }.join]
        end
        copy, facts = source_copy(outer, "#{@mode}-outer", changes)
        @observed["mutationSourceSha256"], @observed["mutationSha256"] = facts.values_at("originalSha256", "sha256")
        adapter, = source_copy(adapter, "#{@mode}-adapter", [
          ['require_relative "release_support"', "require #{File.join(base, 'release_support.rb').inspect}"],
          ['require_relative "native_upload_validation"', "require #{copy.inspect}"]])
      end
      require adapter
      @gate = @platform == "ios" ? MobileReleaseKit::IosUploadValidation : MobileReleaseKit::AndroidUploadValidation
      @native = MobileReleaseKit::NativeUploadValidation
      @gate.send(:remove_const, :MAX_SECONDS)
      @gate.const_set(:MAX_SECONDS, DEADLINE)
      @observed["adapterLimitSeconds"] = DEADLINE
      if @base_mode == "leader-only"
        insertion = <<~RUBY
          require #{File.realpath(__FILE__).inspect}
          MobileReleaseKit::NativeUploadProcess::GroupLease.prepend(Module.new do
            def request(signal)
              if signal == "KILL"
                unless @fixture_omission_entered
                  @fixture_omission_entered = true
                  UploadProcessFixture::OwnedChild.write_record(#{path('omitted-group-kill.json').inspect},
                    {"version" => 1, "custodian" => Process.pid, "keeper" => @keeper.pid, "group" => @id, "signal" => "KILL"})
                end
                return 0 # Omission ENTRY only, never a successful syscall receipt.
              end
              super
            end
          end)
          MobileReleaseKit::NativeUploadProcess::Keeper.prepend(Module.new do
            def request_group(signal)
              return 0 if signal == "KILL" # No hidden independent native cleanup.
              super
            end
          end)
        RUBY
        @helper_copy, facts = UploadProcessFixture.copied_helper(@directory, "omitted-group-kill", insertion)
        @observed["helperCopy"] = facts
        @observed["mutationSourceSha256"], @observed["mutationSha256"] = facts.values_at("originalSha256", "sha256")
      end
      prepare_fake_interpreter
      @observation = Observation.new(self, native: @native, root: @directory)
    end

    def prepare_fake_interpreter
      fake = path("adapter-python")
      source = <<~RUBY
        #!#{File.realpath(RbConfig.ruby)}
        require #{File.realpath(__FILE__).inspect}
        File.umask(0o077)
        UploadProcessFixture::OwnedChild.write_record(#{path('adapter-dispatch.json').inspect},
          {"version" => 1, "pid" => Process.pid, "group" => Process.getpgrp, "sid" => Process.getsid(0),
           "argv" => [File.realpath(__FILE__), *ARGV], "environment" => ENV.to_h, "cwd" => Dir.pwd,
           "sourceSha256" => Digest::SHA256.file(__FILE__).hexdigest})
        Process.exit!(UploadProcessFixture.worker(#{@directory.inspect}, #{@mode.inspect}))
      RUBY
      File.open(fake, File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, 0o700) { |io| io.write(source) }
      @parameters[:python] = fake
      artifact_key = @platform == "ios" ? :ipa_path : :aab_path
      @expected_argv = [fake, "-I", "-S", "-c", @gate::BOOTSTRAP,
        File.realpath(@parameters.fetch(:module_root)), "--app-root", File.realpath(@parameters.fetch(:app_root)),
        "--config-path", MobileReleaseKit.safe_path(@parameters.fetch(:app_root), @parameters.fetch(:config_path)),
        "--operation-intent", MobileReleaseKit.safe_path(@parameters.fetch(:app_root), @parameters.fetch(:intent_path)),
        "--#{@platform == 'ios' ? 'ipa' : 'aab'}", MobileReleaseKit.safe_path(@parameters.fetch(:app_root), @parameters.fetch(artifact_key)),
        "--intent-sha256", @parameters.fetch(:intent_sha256)]
      @fake_source_sha = Digest::SHA256.hexdigest(source)
      @expected_environment = {"LANG" => "C", "LC_ALL" => "C"}
      @tooling = File.realpath(@parameters.fetch(:tooling_directory))
    end

    def assert_adapter_call(arguments, keywords)
      label = @platform == "ios" ? "Current IPA" : "Current AAB"
      failure = @platform == "ios" ?
        "Current IPA signing/profile validation failed; no new upload is authorized (inspect the original IPA with credential-free preflight)" :
        "Current AAB signing/identity validation failed; no new upload is authorized (inspect the original AAB with credential-free preflight)"
      unless arguments == [@expected_environment, @expected_argv, @parameters.fetch(:tooling_directory)] &&
             keywords == {max_seconds: DEADLINE, max_output_bytes: @gate::MAX_OUTPUT_BYTES, label: label, failure_message: failure}
        raise Failure.new("fixture-input", "complete actual adapter capture contract changed")
      end
      @observed["adapterCallObserved"] = true
    end

    def adapter_json_entry(arguments, keywords)
      label = @platform == "ios" ? "current IPA validation result" : "current AAB validation result"
      return false unless keywords[:label] == label
      unless arguments.length == 1 && keywords == {label: label}
        raise Failure.new("fixture-input", "actual adapter result parser call changed")
      end
      @observed["adapterEmptyJSONObserved"] = arguments.first == ""
      true
    end

    def adapter_json_error(error)
      @adapter_json_error = error
    end

    def capture_initialized(session, started)
      span = (@base_mode == "no-deadline" ? 10 : DEADLINE) * 1_000_000_000
      unless started.instance_of?(Integer) && session.capture_slot.run_deadline_ns == started + span
        raise Failure.new("fixture-source", "actual capture start/cutoff was not observed")
      end
      @native_started_ns = started
      @observed["nativeStartedNs"] = started
      @observed["nativeRunDeadlineNs"] = session.capture_slot.run_deadline_ns
    end

    def native_event(name, object)
      case name
      when :execute_enter
        @native_frame = object
        @observed["captureEntered"] = true
      when :custodian_published
        publish_owner("launched")
      when :ready_before_stdin_close
        ready!
        start_watchdog
      when :stdin_close_returned
        @observed["stdinClosedAfterReady"] = true
      end
    end

    def run_remaining_ns
      @observation.session.capture_slot.run_deadline_ns - UploadProcessFixture.clock_ns
    end

    def wait_record(name, kind: "readiness")
      loop do
        remaining = run_remaining_ns
        raise Failure.new(kind, "fixture record missed original capture cutoff") unless remaining.positive?
        return JSON.parse(OwnedChild.bounded_file(path(name))) if File.file?(path(name))
        sleep [remaining, 10_000_000].min / 1_000_000_000.0
      end
    end

    def live_marker!(marker, expected, label)
      raise Failure.new("readiness", "#{label} record is not bound") unless marker == expected
      remaining = run_remaining_ns
      raise Failure.new("readiness", "#{label} original cutoff expired") unless remaining.positive?
      session = @observation.session
      live = UploadProcessFixture.ready?(marker.fetch("pid"), marker.fetch("group"),
        seconds: [remaining / 1_000_000_000.0, 2].min,
        deadline: Rational(session.capture_slot.run_deadline_ns, 1_000_000_000), parent_slot: session.capture_slot)
      raise Failure.new("readiness", "#{label} was not independently live before the original cutoff") unless live && run_remaining_ns.positive?
    end

    def ready!
      session = @observation.session
      ready = session.ready
      raise Failure.new("readiness", "actual native READY was not accepted") unless ready && session.reserved
      kind = @mode == "kill-startup" ? "startup-wait" : "leader-ready"
      if @mode == "unready"
        wait_record("startup-wait.json")
        raise Failure.new("readiness", "fixture deliberately never became ready")
      end
      marker = wait_record("#{kind}.json")
      expected = {"kind" => kind, "pid" => ready.fetch("validator_pid"), "group" => ready.fetch("group_id"), "sid" => session.custodian_child.pid}
      live_marker!(marker, expected, "validator")
      dispatch = wait_record("adapter-dispatch.json")
      expected_dispatch = {"version" => 1, "pid" => marker.fetch("pid"), "group" => marker.fetch("group"), "sid" => marker.fetch("sid"),
        "argv" => @expected_argv, "environment" => @expected_environment, "cwd" => @tooling, "sourceSha256" => @fake_source_sha}
      raise Failure.new("fixture-input", "actual validator dispatch contract changed") unless dispatch == expected_dispatch
      @observed["adapterDispatch"] = dispatch
      @control.admitted!
      @observed["ready"] = true
      @observed["readinessSeconds"] = (UploadProcessFixture.clock_ns - @native_started_ns) / 1_000_000_000.0
      if @mode == "kill-startup"
        publish_owner(@mode)
        wait_for_driver_loss
      end
      unless %w[real-deadline immediate-deadline no-deadline].include?(@base_mode)
        fork = wait_record("fork-return.json")
        child = wait_record("child-ready.json")
        unless fork.keys.sort == %w[child group parent] && fork["parent"] == marker["pid"] && fork["group"] == marker["group"] &&
               fork["child"].instance_of?(Integer) && fork["child"] > 1 && ![session.custodian_child.pid, marker["pid"], marker["group"]].include?(fork["child"])
          raise Failure.new("readiness", "descendant was not the actual original fork")
        end
        @descendant = {"pid" => fork.fetch("child"), "group" => fork.fetch("group")}
        child_expected = {"kind" => "child-ready", "pid" => @descendant.fetch("pid"), "group" => @descendant.fetch("group"),
          "sid" => marker.fetch("sid"), "stdout" => OwnedChild.identity(session.leases.fetch(:stdout_read).io.stat),
          "stderr" => OwnedChild.identity(session.leases.fetch(:stderr_read).io.stat)}
        live_marker!(child, child_expected, "descendant")
        @observed["descendantProof"] = {"forkReturn" => fork, "readyRecord" => child,
          "stdoutReaderIdentity" => child_expected.fetch("stdout"), "stderrReaderIdentity" => child_expected.fetch("stderr")}
        @observed["descendantLiveBeforeRelease"] = true
        observe_inherited_block!
        if @mode == "kill-descendant"
          publish_owner(@mode)
          wait_for_driver_loss
        end
        @release_ns = UploadProcessFixture.clock_ns
        OwnedChild.write_record(path("release-validator.json"), fork)
        @observed["validatorReleasedNs"] = @release_ns
      end
      publish_owner("ready")
    end

    def wait_for_driver_loss
      until run_remaining_ns <= 0
        sleep [run_remaining_ns, 10_000_000].min.clamp(0, 10_000_000) / 1_000_000_000.0
      end
      raise Failure.new("driver", "parent did not stop its actual reserved driver")
    end

    def observe_inherited_block!
      session = @observation.session
      remaining = run_remaining_ns
      raise Failure.new("readiness", "no original inherited-pipe observation interval") unless remaining > 20_000_000
      pipes = %i[stdout_read stderr_read].map { |role| session.leases.fetch(role).io }
      before = UploadProcessFixture.clock_ns
      actual = IO.select(pipes, nil, nil, 0.02)
      unless actual.nil? && UploadProcessFixture.clock_ns > before && run_remaining_ns.positive?
        raise Failure.new("readiness", "real inherited data pipes were not blocked")
      end
      @observed["inheritedPipeBlockObserved"] = true
    end

    def start_watchdog
      helper = MobileReleaseKit::NativeUploadProcess
      at = @capture_started_ns + CAPTURE_LIMIT * 1_000_000_000
      @watchdog = helper::TaskSlot.new(caller: Thread.current, parent_slot: nil,
        run_deadline_ns: at + 1_000_000_000, hard_cleanup_deadline_ns: at + 1_000_000_000)
      @watchdog.start do
        until @watchdog_stop || UploadProcessFixture.clock_ns >= at
          sleep [10_000_000, [at - UploadProcessFixture.clock_ns, 0].max].min / 1_000_000_000.0
        end
        unless @watchdog_stop
          @observed["watchdogIntervened"] = @observed["fallbackUsed"] = true
          @control.close_writer
        end
        true
      end
      raise Failure.new("setup-fixture-fault", "watchdog was not admitted") unless @watchdog.admit!
      @observed["watchdogStarted"] = true
      @observed["watchdogDeadlineNs"] = at
    end

    def blocked_data_wait(before, after)
      return unless after > before && before < @observation.session.capture_slot.run_deadline_ns
      @observed["blockedDataWaits"] += 1
      @observed["firstBlockedDataNs"] ||= before
      @observed["lastBlockedDataNs"] = after
    end

    # Choose only this late timeout-fixture interleaving, AFTER the original
    # validator accepted the frame. The original caller still finishes its own
    # timed join and records its own first error; this hook creates neither.
    def after_validated_final(session, frame)
      return unless @base_mode == "real-deadline" && !@late_final_yielded &&
        session.equal?(@observation.session) && frame["type"] == "FINAL" &&
        frame["outcome"] == "failed" && frame["cleanup"] == "confirmed"
      slot = session.capture_slot
      caller = slot.caller
      return unless Thread.current.equal?(slot.thread) && !caller.equal?(Thread.current) && caller.alive? &&
        session.ready && session.reserved && @observed["ready"] == true && @observed["blockedDataWaits"].positive?
      run_cutoff, hard_cutoff = slot.run_deadline_ns, slot.hard_cleanup_deadline_ns
      return unless run_cutoff.instance_of?(Integer) && hard_cutoff.instance_of?(Integer) &&
        run_cutoff == @observed["nativeRunDeadlineNs"]
      # cancelled?/cleanup_deadline_ns call refresh_parent! and can cancel the
      # task. Read the existing shared latch without causing the awaited event.
      failure = slot.__send__(:failure_record)
      now = UploadProcessFixture.clock_ns
      return unless now >= run_cutoff && now < hard_cutoff
      return if session.primary_error || failure.failed? || slot.launch_retired? ||
        session.retained_unknown? || !session.cleanup_errors.empty?
      @late_final_yielded = true
      loop do
        return if session.primary_error || failure.failed? || slot.launch_retired? ||
          session.retained_unknown? || !session.cleanup_errors.empty? || !caller.alive?
        remaining = hard_cutoff - UploadProcessFixture.clock_ns
        return unless remaining.positive?
        sleep [remaining, 10_000_000].min / 1_000_000_000.0
      end
    end

    def timeout_constructed(session, error)
      return unless session.equal?(@observation.session)
      @timeout_objects << [error, UploadProcessFixture.clock_ns]
      raise Failure.new("fixture-observation", "unbounded timeout construction") if @timeout_objects.length > 32
      @observed["firstTimeoutDecisionNs"] ||= @timeout_objects.last.last
      @observed["deadlineDecisionSeconds"] = (@observed.fetch("firstTimeoutDecisionNs") - @native_started_ns) / 1_000_000_000.0
    end

    def failure_recorded(slot)
      session = @observation.session
      return unless session && [session.capture_slot, session.creator_slot].include?(slot)
      actual = @timeout_objects.find { |error, _time| error.equal?(session.primary_error) }
      return unless actual
      @selected_timeout ||= actual
      @observed["deadlinePrimarySameObject"] = session.primary_error.equal?(@selected_timeout.first)
      @observed["selectedTimeoutNs"] = @selected_timeout.last
    end

    def status_received(session, frame)
      return unless session.equal?(@observation.session) && @release_ns
      @observed["validatorReapedAfterRelease"] = frame["status_kind"] == "exit" && frame["status_code"] == 0 &&
        frame["validator_pid"] == session.ready.fetch("validator_pid") && UploadProcessFixture.clock_ns >= @release_ns
      return unless @base_mode == "leader-only" && !@omission_observed
      omission = wait_record("omitted-group-kill.json", kind: "descendant-alive")
      unless omission == {"version" => 1, "custodian" => session.custodian_child.pid,
                         "keeper" => session.reserved.fetch("keeper_pid"), "group" => @descendant.fetch("group"), "signal" => "KILL"}
        raise Failure.new("fixture-source", "group cleanup omission was not bound")
      end
      remaining = run_remaining_ns
      alive = UploadProcessFixture.ready?(@descendant.fetch("pid"), @descendant.fetch("group"),
        seconds: [remaining / 1_000_000_000.0, 2].min, parent_slot: session.capture_slot,
        deadline: Rational(session.capture_slot.run_deadline_ns, 1_000_000_000))
      raise Failure.new("readiness", "omission did not leave a live original descendant") unless alive && run_remaining_ns.positive?
      observe_inherited_block!
      @omission_observed = true
      @observed["descendantLiveAfterOmittedCleanup"] = true
      @observed["fallbackAfterObservation"] = @observed["fallbackUsed"] = true
      @control.close_writer # Only after actual live/pipe/entry observations.
    end

    def exercise
      @capture_started_ns = UploadProcessFixture.clock_ns
      @capture_started = @capture_started_ns / 1_000_000_000.0
      @observed["captureStartedNs"] = @capture_started_ns
      error = value = nil
      begin
        value = @observation.observe { @gate.current!(**@parameters) }
      rescue Exception => failure
        error = failure
      ensure
        @observed["captureSeconds"] = (UploadProcessFixture.clock_ns - @capture_started_ns) / 1_000_000_000.0
      end
      @observed["adapterRejected"] = value.nil? && error.is_a?(MobileReleaseKit::ContractError)
      @observed["adapterJSONErrorSameObject"] = !!(@adapter_json_error && error.equal?(@adapter_json_error))
      @observed["adapterErrorClass"], @observed["adapterError"] = error&.class&.name, error&.message
      @observed["stdinClosedAfterReady"] = @observation.snapshot["stdinCloseReturned"].equal?(true)
      unless @observation.finalized? || @observation.no_producers?
        raise Failure.new("fixture-cleanup", "adapter capture retained UNKNOWN")
      end
      @observed["nativeFinalityBeforeFallback"] = !@observed["fallbackUsed"]
      raise error if error && !error.is_a?(MobileReleaseKit::ContractError)
      raise Failure.new("capture-watchdog", "capture required independent writer watchdog") if @observed["watchdogIntervened"]
      if @base_mode == "leader-only"
        raise Failure.new("readiness", "group omission boundary was not actually observed") unless @omission_observed
        raise Failure.new("descendant-alive", "omitted native group cleanup required independent writer EOF")
      end
      if %w[real-deadline immediate-deadline].include?(@base_mode)
        session = @observation.session
        failure_recorded(session.capture_slot)
        @observed["deadlineResultSameObject"] = !!(@selected_timeout && error.equal?(@selected_timeout.first) && session.primary_error.equal?(error))
        if @mode.end_with?("-slow-cleanup")
          @observed["slowCleanupSeconds"] = session.instance_variable_get(:@fixture_slow_cleanup_ns).to_i / 1_000_000_000.0
        end
        unless @observed["ready"] && @observed["deadlinePrimarySameObject"] && @observed["deadlineResultSameObject"] &&
               error&.message&.include?("timed out") && @observed["firstTimeoutDecisionNs"]
          raise Failure.new("readiness", "actual ready timeout cause was not observed")
        end
        if @base_mode == "immediate-deadline" && @observed["firstTimeoutDecisionNs"] >= session.capture_slot.run_deadline_ns
          raise Failure.new("readiness", "startup consumed the premature-timeout control interval")
        end
        unless @observed["firstTimeoutDecisionNs"] >= session.capture_slot.run_deadline_ns &&
               @observed["blockedDataWaits"].positive? && @observed["captureSeconds"] < CAPTURE_LIMIT
          raise Failure.new("elapsed-bound", "timeout decision preceded original bound or real blocked data interval")
        end
      else
        unless @observed["adapterRejected"] && @observed["adapterEmptyJSONObserved"] && @observed["adapterJSONErrorSameObject"] &&
               @observed["descendantLiveBeforeRelease"] &&
               @observed["inheritedPipeBlockObserved"] && @observed["validatorReapedAfterRelease"] &&
               @observed["commitAfterDataEOF"] && @observation.session.primary_error.nil? &&
               @observation.session.final.fetch("outcome") == "ok"
          raise Failure.new("readiness", "genuine V0/descendant/EOF-before-COMMIT progress was not observed")
        end
        if %w[delayed-start late-record].include?(@mode)
          delay = JSON.parse(OwnedChild.bounded_file(path("delay.json")))
          unless delay.keys.sort == %w[endNs stage startNs] && delay["startNs"].instance_of?(Integer) &&
                 delay["endNs"].instance_of?(Integer) && delay["endNs"] - delay["startNs"] >= 300_000_000 &&
                 delay["stage"] == (@mode == "delayed-start" ? "before_fork" : "after_release") &&
                 delay["startNs"] >= @native_started_ns && delay["endNs"] < @observation.session.capture_slot.run_deadline_ns
            raise Failure.new("readiness", "actual worker delay was not observed")
          end
          @observed["workerDelaySeconds"] = (delay["endNs"] - delay["startNs"]) / 1_000_000_000.0
          @observed["workerDelayStage"] = delay["stage"]
          @observed["workerDelay"] = delay
        end
      end
      raise Failure.new("fixture-cleanup", "fixture fallback preceded death proof") if @observed["fallbackUsed"] || @control.writer.state != :open
      @observed["deadBeforeFallback"] = true # Actual R1 finality, never a PID sample.
    end
  end

  # Bounded, source-bound events from the EXISTING C/K helpers. This adds no
  # observer process, consuming wait, numeric query, cleanup signal or budget.
  # Every helper report is written before the original terminal arm is called.
  class ContainmentEvidence
    HARD_LOSS = %w[kill-native-setup kill-startup kill-descendant].freeze
    MISSING = "native-setup-no-cleanup"
    OMISSION_LIMIT = 8192
    OMISSION_FILES = {"custodian" => "containment-custodian-omission.json",
                      "keeper" => "containment-keeper-omission.json"}.freeze
    SOURCES = NativeSignalProbe::SOURCES

    def self.source_hashes
      base = File.realpath(File.expand_path("../..", __dir__))
      SOURCES.to_h { |name| [name, Digest::SHA256.file(File.join(base, name)).hexdigest] }
    end

    def self.prepare(driver)
      directory, mode = driver.instance_variable_get(:@directory), driver.instance_variable_get(:@mode)
      raise Failure.new("fixture-source", "unknown containment case") unless (HARD_LOSS + [MISSING]).include?(mode)
      insertion = <<~RUBY
        require #{File.realpath(__FILE__).inspect}
        if $PROGRAM_NAME == __FILE__
          UploadProcessFixture::ContainmentEvidence.observe_helper(#{directory.inspect}, #{mode.inspect}, __FILE__)
        end
      RUBY
      copy, facts = UploadProcessFixture.copied_helper(directory, "containment-events", insertion)
      manifest = {"version" => 1, "mode" => mode, "helperCopy" => facts, "sourceSha256" => source_hashes}
      OwnedChild.write_record(File.join(directory, "containment-source.json"), manifest)
      driver.instance_variable_set(:@helper_copy, copy)
      driver.observed.merge!("helperCopy" => facts, "containmentSource" => manifest)
      manifest
    end

    def self.manifest!(directory, mode, sources)
      value = JSON.parse(OwnedChild.bounded_file(File.join(directory, "containment-source.json")))
      facts = value["helperCopy"]
      original = File.realpath(File.expand_path("../../fastlane/native_upload_process.rb", __dir__))
      copy = File.join(directory, "containment-events-helper.rb")
      unless value.keys.sort == %w[helperCopy mode sourceSha256 version] && value["version"] == 1 &&
             value["mode"] == mode && value["sourceSha256"] == sources && facts.instance_of?(Hash) &&
             facts.keys.sort == %w[label originalPath originalSha256 path sha256] &&
             facts["label"] == "containment-events" && facts["originalPath"] == original &&
             facts["originalSha256"] == sources.fetch("fastlane/native_upload_process.rb") && facts["path"] == copy &&
             Digest::SHA256.hexdigest(OwnedChild.bounded_file(copy, limit: 1_048_576)) == facts["sha256"]
        raise Failure.new("fixture-source", "containment copy is not bound to the original source")
      end
      value
    end

    def self.observe_helper(directory, mode, helper_path)
      UploadProcessFixture.owned_fixture_directory(directory)
      manifest = manifest!(directory, mode, source_hashes)
      raise Failure.new("fixture-source", "wrong copied helper dispatch") unless File.realpath(helper_path) == manifest["helperCopy"]["path"]
      observer = new(directory, mode, manifest)
      (@helper_observers ||= []) << observer
      observer.install
    end

    def initialize(directory, mode, manifest)
      @directory, @mode, @manifest = directory, mode, manifest
      @helper = MobileReleaseKit::NativeUploadProcess
      @spawn = @helper.native
      @role = @route = @wait = @released = @retirement = nil
      @kills, @absences, @omissions, @joins, @closes, @eofs = [], [], [], [], [], []
      @request_counts = {"0" => 0, "KILL" => 0}
      @hooks = CaptureObservation::Hooks.new
      @origins = {}
    end

    def bind_origin(label, klass, name)
      path, line = klass.instance_method(name).source_location
      unless path && File.realpath(path) == @manifest.fetch("helperCopy").fetch("path") && line.instance_of?(Integer)
        raise Failure.new("fixture-source", "containment event method left the copied original helper")
      end
      @origins[label] = {"path" => File.realpath(path), "line" => line}
    end

    def install
      bind_origin("custodian-group", @helper::GroupLease, :request)
      bind_origin("keeper-group", @helper::Keeper, :request_group)
      bind_origin("retire", @helper::GroupLease, :retire!)
      bind_origin("released", @helper::Custodian, :accept_released)
      bind_origin("arm", @helper::Role, :seal_exit_handoff)
      @hooks.wrap(@helper::Role, :initialize) do |original, object, arguments, keywords, block|
        raise Failure.new("fixture-source", "multiple helper roles in one event scope") if @role
        value = original.call(*arguments, **keywords, &block)
        @role = object
        value
      end
      [[@helper::GroupLease, :request, "custodian-group"], [@helper::Keeper, :request_group, "keeper-group"]].each do |klass, name, route|
        @hooks.wrap(klass, name) do |original, object, arguments, keywords, block|
          group_request(original, object, arguments, keywords, block, route)
        end
      end
      @hooks.wrap(Process.singleton_class, :kill) do |original, _object, arguments, keywords, block|
        actual_kill(original, arguments, keywords, block)
      end
      @hooks.wrap(@helper::GroupLease, :retire!) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        if @role&.is_a?(@helper::Custodian) && object.equal?(@role.group) && keywords[:absent].equal?(true)
          @retirement = {"atNs" => UploadProcessFixture.clock_ns, "group" => object.id,
            "actualOriginalRetireReturned" => value.equal?(true) && object.retired? && object.absent?,
            "originalESRCHObserved" => @absences.any? { |event| event["group"] == object.id },
            "origin" => @origins.fetch("retire")}
        end
        value
      end
      @hooks.wrap(Process.singleton_class, :waitpid2) do |original, _object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        child = own_child
        if value && child && arguments.first == child.pid
          raise Failure.new("fixture-source", "multiple original terminal helper waits") if @wait
          @wait = {child: child, returned: value, at: UploadProcessFixture.clock_ns}
        end
        value
      end
      @hooks.wrap(Thread, :join) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        @joins << object if value.equal?(object) && @role &&
          [@role.bootstrap_slot, @role.creator_slot].compact.any? { |slot| slot.thread.equal?(object) } && !@joins.include?(object)
        value
      end
      @hooks.wrap(@spawn::IOLease, :close_once) do |original, object, arguments, keywords, block|
        before = object.state
        value = original.call(*arguments, **keywords, &block)
        @closes << object if before == :open && object.state == :closed && object.io.closed?
        value
      end
      @hooks.wrap(IO, :read_nonblock) do |original, object, arguments, keywords, block|
        labels = channels.select { |_label, channel| channel && channel.reader&.io.equal?(object) && channel.reader.state == :open }.keys
        identity = OwnedChild.identity(object.stat) unless labels.empty?
        value = original.call(*arguments, **keywords, &block)
        labels.each do |label|
          @eofs << {"channel" => label, "ioIdentity" => identity, "atNs" => UploadProcessFixture.clock_ns,
            "actualReadNil" => true} if value.nil?
        end
        value
      end
      @hooks.wrap(@helper::Custodian, :accept_released) do |original, object, arguments, keywords, block|
        value = original.call(*arguments, **keywords, &block)
        frame = arguments.first
        if object.equal?(@role) && object.instance_variable_get(:@released).equal?(frame)
          @released = {"frame" => frame, "atNs" => UploadProcessFixture.clock_ns,
            "actualOriginalAcceptReturned" => true, "origin" => @origins.fetch("released")}
        end
        value
      end
      @hooks.wrap(@helper::Role, :seal_exit_handoff) do |original, object, arguments, keywords, block|
        # This is deliberately BEFORE original arming. Hooks/report writes are
        # finished here; nothing is acquired, signalled or reported afterward.
        report = before_arm(object, arguments.first)
        report["hookRestorationErrors"] = @hooks.restore
        raise Failure.new("fixture-source", "containment hooks failed to restore before arm") unless report["hookRestorationErrors"].empty?
        OwnedChild.write_record(File.join(@directory, "containment-#{report.fetch('role')}.json"), report)
        original.call(*arguments, **keywords, &block)
      end
    end

    def channels
      return {} unless @role
      {"parent" => @role.instance_variable_get(:@parent_channel), "keeper" => @role.instance_variable_get(:@keeper_channel)}
    end

    def own_child
      return nil unless @role
      @role.is_a?(@helper::Custodian) ? @role.keeper : @role.validator
    end

    def group_request(original, object, arguments, keywords, block, route)
      signal = arguments.first
      c = route == "custodian-group"
      valid = @role && @route.nil? && arguments.length == 1 && keywords.empty? && [0, "KILL"].include?(signal)
      if c
        valid &&= @role.is_a?(@helper::Custodian) && object.equal?(@role.group) && object.keeper.equal?(@role.keeper) &&
          object.keeper.equal?(@role.creator_acquisition&.child) && object.keeper.state == :running &&
          !object.keeper.numeric_retired? && object.keeper.receipt.nil? && !object.retired? && !object.absent?
        group = object.id
      else
        valid &&= @role.is_a?(@helper::Keeper) && object.equal?(@role) &&
          object.instance_variable_get(:@group_created) && !object.instance_variable_get(:@self_group_retired) &&
          !object.instance_variable_get(:@self_group_absent) && object.pid == Process.pid
        group = object.pid
      end
      valid &&= UploadProcessFixture.clock_ns < @role.__send__(:effective_deadline_ns)
      raise Failure.new("fixture-source", "unreserved helper group request VETOED before syscall") unless valid
      return missing_omission!(object, route, group) if @mode == MISSING && signal == "KILL"
      entry = {"route" => route, "group" => group, "signal" => signal, "atNs" => UploadProcessFixture.clock_ns,
        "originalReservedAuthority" => true, "origin" => @origins.fetch(route)}
      @request_counts.fetch(signal.to_s)
      @request_counts[signal.to_s] += 1
      @route = entry
      original.call(*arguments, **keywords, &block)
    ensure
      @route = nil
    end

    def missing_omission!(object, route, group)
      c = route == "custodian-group"
      role = c ? "custodian" : "keeper"
      child = own_child
      moved = @role.instance_variable_get(c ? :@moved : :@moved_frame)
      graph = {"custodian" => c ? @role.pid : @role.parent_pid,
        "keeper" => c ? child&.pid : @role.pid,
        "validator" => c ? moved&.fetch("validator_pid", nil) : child&.pid,
        "group" => group, "sid" => @role.session_id}
      unless @omissions.empty? && @mode == MISSING && OMISSION_FILES.key?(role) &&
             route == (c ? "custodian-group" : "keeper-group") && @role.pid == Process.pid &&
             child && child.equal?(@role.creator_acquisition&.child) &&
             graph.values.all? { |pid| pid.instance_of?(Integer) && pid > 1 } &&
             graph.values_at("custodian", "keeper", "validator").uniq.length == 3 &&
             graph["group"] == graph["keeper"] && graph["sid"] == graph["custodian"] &&
             @role.parent_pid.instance_of?(Integer) && @role.parent_pid > 1 &&
             (c ? object.equal?(@role.group) && object.session_id == graph["sid"] &&
               !graph.values.include?(@role.parent_pid) && moved.instance_of?(Hash) : object.equal?(@role) &&
               @role.parent_pid == graph["custodian"]) &&
             (!moved || moved.instance_of?(Hash) && moved.values_at("validator_pid", "group_id", "keeper_pgid") ==
               graph.values_at("validator", "group", "custodian"))
        raise Failure.new("fixture-source", "missing cleanup entry lacks its original role graph")
      end
      origin = @origins.fetch(route) # Captured BEFORE the original helper method was wrapped.
      deadline = @role.__send__(:effective_deadline_ns)
      at = UploadProcessFixture.clock_ns
      unless deadline.instance_of?(Integer) && at < deadline
        raise Failure.new("fixture-source", "original cleanup omission entry deadline expired")
      end
      entry = {"route" => route, "group" => group, "signal" => "KILL", "atNs" => at,
        "effectiveDeadlineNs" => deadline, "originalReservedAuthority" => true, "origin" => origin,
        "actualOmissionEntry" => true, "nativeCallOmitted" => true}.freeze
      @omissions << entry # Irreversible before publication, including a write with an uncertain effect.
      @request_counts["KILL"] = @request_counts.fetch("KILL") + 1
      record = {"version" => 1, "kind" => "original-helper-cleanup-omission-entry", "mode" => MISSING,
        "sourceSha256" => @manifest.fetch("sourceSha256"), "helperCopy" => @manifest.fetch("helperCopy"),
        "role" => role, "pid" => @role.pid, "parentPid" => @role.parent_pid, "identities" => graph, "entry" => entry}
      raise Failure.new("fixture-source", "cleanup omission entry exceeds bound") if JSON.generate(record).bytesize > OMISSION_LIMIT
      OwnedChild.write_record(File.join(@directory, OMISSION_FILES.fetch(role)), record)
      0 # GROUP call omitted, not a syscall/return/terminal receipt; original direct C-to-K cleanup remains.
    end

    def actual_kill(original, arguments, keywords, block)
      entry = @route
      return original.call(*arguments, **keywords, &block) unless entry
      unless arguments == [entry.fetch("signal"), -entry.fetch("group")] && keywords.empty?
        raise Failure.new("fixture-source", "helper syscall no longer matches its reserved group entry")
      end
      value = original.call(*arguments, **keywords, &block)
      if entry["signal"] == "KILL"
        raise Failure.new("fixture-source", "unbounded actual helper KILL evidence") unless @kills.length < 2
        @kills << entry.merge("returned" => value, "returnNs" => UploadProcessFixture.clock_ns, "actualSyscallReturned" => true)
      end
      value
    rescue Errno::ESRCH
      @absences << entry.merge("actualESRCH" => true, "returnNs" => UploadProcessFixture.clock_ns) if entry
      raise # The ORIGINAL request method records absence and retires G.
    end

    def child_proof
      child = own_child
      receipt = child&.receipt
      creator = @role.creator_slot
      observed = @wait && receipt && @wait[:child].equal?(child) &&
        @wait[:returned].first == child.pid && @wait[:returned].last.equal?(receipt.raw_status) &&
        receipt.raw_status.is_a?(Process::Status) && receipt.raw_status.pid == child.pid &&
        child.equal?(@role.creator_acquisition&.child) && child.numeric_retired? && child.state == :reaped
      record = receipt && {"state" => "reaped", "pid" => receipt.pid,
        "status_kind" => receipt.status_kind, "status_code" => receipt.status_code}
      {"record" => record, "actualOriginalWaitObserved" => !!observed, "waitNs" => @wait && @wait[:at],
        "actualCreatorJoinObserved" => !!(creator && creator.finished? && creator.joined? && @joins.include?(creator.thread))}
    end

    def before_arm(object, returned)
      unless object.equal?(@role) && object.pid == Process.pid && !object.instance_variable_get(:@terminal_exit_armed)
        raise Failure.new("fixture-source", "helper report was not before original terminal arm")
      end
      c = @role.is_a?(@helper::Custodian)
      custodian = c ? object.pid : object.parent_pid
      keeper = c ? object.keeper&.pid : object.pid
      validator = c ? object.instance_variable_get(:@moved)&.fetch("validator_pid") : object.validator&.pid
      child = child_proof
      parent = channels["parent"]
      status = object.instance_variable_get(:@roles)[:status]
      {"version" => 1, "kind" => "original-helper-containment-events", "mode" => @mode,
       "sourceSha256" => @manifest.fetch("sourceSha256"), "helperCopy" => @manifest.fetch("helperCopy"),
       "role" => c ? "custodian" : "keeper", "pid" => object.pid, "parentPid" => object.parent_pid,
       "identities" => {"custodian" => custodian, "keeper" => keeper, "validator" => validator,
         "group" => keeper, "sid" => object.session_id},
       "preArmNs" => UploadProcessFixture.clock_ns, "terminalAlreadyArmed" => false,
       "originalRunReturn" => returned, "runDeadlineNs" => object.instance_variable_get(:@run_deadline_ns),
       "hardDeadlineNs" => object.instance_variable_get(:@hard_cleanup_deadline_ns),
       "actualKills" => @kills, "actualAbsences" => @absences, "groupRetirement" => @retirement,
       "originalChild" => child, "acceptedReleased" => @released, "actualEOFs" => @eofs,
       "keeperChannelEOF" => c && !!(channels["keeper"]&.eof?),
       "releasedWritten" => !c && !!(parent&.written?("RELEASED")),
       "releasedFrame" => !c ? object.instance_variable_get(:@terminal_frame) : nil,
       "actualStatusCloseObserved" => !!(status && status.state == :closed && @closes.include?(status)),
       "omissions" => @omissions, "requestCounts" => @request_counts}
    end

    def self.wait_records(directory, names, deadline_ns:)
      loop do
        raise Failure.new("fixture-result", "original containment report cutoff expired") unless UploadProcessFixture.clock_ns < deadline_ns
        if names.all? { |name| File.file?(File.join(directory, name)) }
          values = names.to_h { |name| [name, JSON.parse(OwnedChild.bounded_file(File.join(directory, name)))] }
          raise Failure.new("fixture-result", "containment report read passed original cutoff") unless UploadProcessFixture.clock_ns < deadline_ns
          return values
        end
        sleep [10_000_000, [deadline_ns - UploadProcessFixture.clock_ns, 0].max].min / 1_000_000_000.0
      end
    end

    def self.report_hashes(directory, records)
      records.to_h do |name, expected|
        bytes = OwnedChild.bounded_file(File.join(directory, name))
        raise Failure.new("fixture-result", "original containment report changed") unless JSON.parse(bytes) == expected
        [name, Digest::SHA256.hexdigest(bytes)]
      end
    end

    def self.omission_records!(directory, manifest, graph, driver_pid:, deadline_ns:, capture_entry_ns:, arm_ns:, before_ns:)
      unless graph.instance_of?(Hash) && graph.keys.sort == %w[custodian group keeper sid validator] &&
             graph.values.all? { |pid| pid.instance_of?(Integer) && pid > 1 } &&
             graph.values_at("custodian", "keeper", "validator").uniq.length == 3 &&
             graph["custodian"] == graph["sid"] && graph["keeper"] == graph["group"] &&
             driver_pid.instance_of?(Integer) && driver_pid > 1 && !graph.values.include?(driver_pid) &&
             [deadline_ns, capture_entry_ns, arm_ns, before_ns].all? { |time| time.instance_of?(Integer) && time.positive? } &&
             capture_entry_ns <= arm_ns && arm_ns < before_ns && before_ns < deadline_ns &&
             manifest.instance_of?(Hash) && manifest["mode"] == MISSING
        raise Failure.new("fixture-result", "cleanup omission context is not the original capture")
      end
      records, bindings = {}, {}
      OMISSION_FILES.each do |role, name|
        raise Failure.new("fixture-result", "original cleanup omission read cutoff expired") unless UploadProcessFixture.clock_ns < deadline_ns
        path = File.join(directory, name)
        identity = OwnedChild.identity(File.lstat(path))
        bytes = OwnedChild.bounded_file(path, expected: identity, limit: OMISSION_LIMIT)
        unless OwnedChild.identity(File.lstat(path)) == identity
          raise Failure.new("fixture-result", "original cleanup omission path changed during read")
        end
        item = JSON.parse(bytes)
        route = role == "custodian" ? "custodian-group" : "keeper-group"
        helper = MobileReleaseKit::NativeUploadProcess
        original = role == "custodian" ? helper::GroupLease.instance_method(:request) : helper::Keeper.instance_method(:request_group)
        source, line = original.source_location
        copy = manifest.fetch("helperCopy")
        unless source && File.realpath(source) == copy.fetch("originalPath") && line.instance_of?(Integer) && line.positive?
          raise Failure.new("fixture-source", "cleanup omission origin left the original native method")
        end
        entry = item.instance_of?(Hash) && item["entry"]
        unless item.instance_of?(Hash) && item.keys.sort == %w[entry helperCopy identities kind mode parentPid pid role sourceSha256 version] &&
               item["version"].instance_of?(Integer) && item["version"] == 1 &&
               item["kind"] == "original-helper-cleanup-omission-entry" && item["mode"] == MISSING &&
               item["sourceSha256"] == manifest.fetch("sourceSha256") && item["helperCopy"] == copy &&
               item["identities"].instance_of?(Hash) && item["identities"] == graph &&
               item["identities"].values.all? { |pid| pid.instance_of?(Integer) } && item["role"] == role &&
               item["pid"].instance_of?(Integer) && item["pid"] == graph.fetch(role) &&
               item["parentPid"].instance_of?(Integer) && item["parentPid"] == (role == "custodian" ? driver_pid : graph.fetch("custodian")) &&
               entry.instance_of?(Hash) && entry.keys.sort == %w[actualOmissionEntry atNs effectiveDeadlineNs group nativeCallOmitted origin originalReservedAuthority route signal] &&
               entry["route"] == route && entry["group"].instance_of?(Integer) && entry["group"] == graph.fetch("group") &&
               entry["signal"] == "KILL" && entry["originalReservedAuthority"].equal?(true) &&
               entry["actualOmissionEntry"].equal?(true) && entry["nativeCallOmitted"].equal?(true) &&
               entry["origin"].instance_of?(Hash) && entry["origin"] == {"path" => copy.fetch("path"), "line" => line} &&
               entry["origin"]["line"].instance_of?(Integer) &&
               entry["atNs"].instance_of?(Integer) && entry["effectiveDeadlineNs"].instance_of?(Integer) &&
               arm_ns <= entry["atNs"] && entry["atNs"] < before_ns &&
               entry["atNs"] < entry["effectiveDeadlineNs"] && entry["effectiveDeadlineNs"] <= deadline_ns
          raise Failure.new("fixture-result", "original cleanup omission entry/source/identity binding changed")
        end
        records[name] = item
        bindings[name] = {"identity" => identity, "sha256" => Digest::SHA256.hexdigest(bytes)}
      end
      raise Failure.new("fixture-result", "cleanup omission read passed original cutoff") unless UploadProcessFixture.clock_ns < deadline_ns
      [records, bindings]
    end

    def self.graph!(owner, mode)
      roles = UploadProcessFixture.owner_processes!(owner).to_h { |item| [item.fetch("role"), item] }
      expected = mode == "kill-descendant" ? %w[custodian descendant keeper validator] : %w[custodian keeper validator]
      raise Failure.new("fixture-result", "containment graph is not the original C/K/V scope") unless roles.keys.sort == expected
      {"custodian" => roles.fetch("custodian").fetch("pid"), "keeper" => roles.fetch("keeper").fetch("pid"),
        "validator" => roles.fetch("validator").fetch("pid"), "group" => roles.fetch("validator").fetch("group"),
        "sid" => roles.fetch("custodian").fetch("pid")}
    end

    def self.prekill!(directory, mode, owner, sources, held_writer)
      manifest = manifest!(directory, mode, sources)
      graph = graph!(owner, mode)
      config = JSON.parse(OwnedChild.bounded_file(File.join(directory, "worker-control.json")))
      fifo = File.join(directory, "worker-control.fifo")
      identity = OwnedChild.identity(File.lstat(fifo))
      unless owner["phase"] == mode && owner["finality"] == "active" && config == {"version" => 1, "identity" => identity} &&
             identity["type"] == "fifo" && identity["uid"] == Process.uid && identity["nlink"] == 1 &&
             (identity["mode"] & 0o7777) == 0o600
        raise Failure.new("fixture-control", "held writer lost original worker FIFO binding")
      end
      held_writer.acquire { File.open(fifo, File::WRONLY | File::NONBLOCK | File::NOFOLLOW) }
      unless held_writer.state == :open && held_writer.io.close_on_exec? && OwnedChild.identity(held_writer.io.stat) == identity
        raise Failure.new("fixture-control", "held original worker writer was not actually acquired")
      end
      {"manifest" => manifest, "identities" => graph, "fifoIdentity" => identity,
       "heldWriterAcquiredNs" => UploadProcessFixture.clock_ns}
    end

    def self.bound_reports!(records, manifest, graph)
      %w[custodian keeper].to_h do |role|
        item = records.fetch("containment-#{role}.json")
        unless item["version"] == 1 && item["kind"] == "original-helper-containment-events" &&
               item["mode"] == manifest["mode"] && item["sourceSha256"] == manifest["sourceSha256"] &&
               item["helperCopy"] == manifest["helperCopy"] && item["role"] == role && item["identities"] == graph &&
               item["pid"] == graph.fetch(role) && item["terminalAlreadyArmed"].equal?(false) &&
               item["hookRestorationErrors"] == [] && item["preArmNs"].instance_of?(Integer)
          raise Failure.new("fixture-result", "original helper event/source/identity binding changed")
        end
        [role, item]
      end
    end

    def self.hardloss!(directory, mode, prior, held_writer, deadline_ns:)
      open_writer = lambda do
        held_writer.state == :open && !held_writer.io.closed? && held_writer.io.close_on_exec? &&
          OwnedChild.identity(held_writer.io.stat) == prior.fetch("fifoIdentity")
      end
      raise Failure.new("fixture-control", "driver death released the independent held writer") unless open_writer.call
      records = wait_records(directory, %w[containment-custodian.json containment-keeper.json], deadline_ns: deadline_ns)
      reports = bound_reports!(records, prior.fetch("manifest"), prior.fetch("identities"))
      c, k = reports.values_at("custodian", "keeper")
      graph = prior.fetch("identities")
      unless c["parentPid"] == prior.fetch("driverPid") && k["parentPid"] == graph["custodian"] &&
             c["preArmNs"] >= prior.fetch("driverKillEntryNs") && k["preArmNs"] >= prior.fetch("driverKillEntryNs") &&
             reports.values.all? { |item| item["originalChild"]["actualOriginalWaitObserved"] &&
               item["originalChild"]["actualCreatorJoinObserved"] && item["omissions"] == [] } &&
             c["originalChild"]["record"] == {"state" => "reaped", "pid" => graph["keeper"], "status_kind" => "exit", "status_code" => k["originalRunReturn"]} &&
             [0, 2].include?(k["originalRunReturn"]) && k["originalChild"]["record"]["pid"] == graph["validator"] &&
             c["acceptedReleased"] && c["acceptedReleased"]["actualOriginalAcceptReturned"] &&
             c["acceptedReleased"]["frame"] == k["releasedFrame"] && k["releasedFrame"] ==
               {"v" => 1, "type" => "RELEASED", "validator" => k["originalChild"]["record"]} &&
             k["releasedWritten"] && k["actualStatusCloseObserved"] && c["keeperChannelEOF"] &&
             c["actualEOFs"].any? { |event| event["channel"] == "keeper" && event["actualReadNil"] } &&
             c["groupRetirement"] && c["groupRetirement"]["group"] == graph["group"] &&
             c["groupRetirement"]["actualOriginalRetireReturned"] && c["groupRetirement"]["originalESRCHObserved"] &&
             reports.values.flat_map { |item| item["actualKills"] }.any? { |event| event["group"] == graph["group"] &&
               event["signal"] == "KILL" && event["returned"] == 1 && event["actualSyscallReturned"] &&
               event["originalReservedAuthority"] && event["atNs"] >= prior.fetch("driverKillEntryNs") } && open_writer.call
        raise Failure.new("fixture-result", "runtime containment before held-writer fallback was not proved")
      end
      {"version" => 1, "kind" => "runtime-containment-before-fixture-eof", "mode" => mode,
       "identities" => graph, "fifoIdentity" => prior.fetch("fifoIdentity"), "helperCopy" => prior["manifest"]["helperCopy"],
       "sourceSha256" => prior["manifest"]["sourceSha256"], "heldWriterAcquiredNs" => prior.fetch("heldWriterAcquiredNs"),
       "driverKillEntryNs" => prior.fetch("driverKillEntryNs"), "proofCompletedNs" => UploadProcessFixture.clock_ns,
       "heldWriterOpenThroughProof" => true, "originalCustodianWaitMissing" => true,
       "reservedGroupAbsentBeforeFixtureEOF" => true, "runtimeGroupKillObserved" => true,
       "originalKeeperWaitObserved" => true, "originalValidatorWaitObserved" => true,
       "releasedAndControlEOFObserved" => true, "keeperExitStatus" => k["originalRunReturn"],
       "validatorReceipt" => k["originalChild"]["record"], "nativeFinality" => "unknown",
       "helperReportSha256" => report_hashes(directory, records)}
    end

    def self.close_held!(record)
      lease = record["heldWriter"]
      return nil unless lease && lease.state != :unattempted
      return record.fetch("heldWriterClose") if lease.state == :closed
      record["heldWriterCloseEntryNs"] ||= UploadProcessFixture.clock_ns
      value = lease.close_once
      unless value.equal?(true) && lease.state == :closed && lease.io.closed?
        raise Failure.new("fixture-control", "held original writer close was not accounted")
      end
      record["heldWriterClose"] = {"actualCloseReturned" => true, "closed" => true,
        "entryNs" => record.fetch("heldWriterCloseEntryNs"), "returnNs" => UploadProcessFixture.clock_ns}
    end

    def self.missing_cleanup!(directory, owner, result, sources, deadline_ns:, driver_dispatch:)
      manifest = manifest!(directory, MISSING, sources)
      unless manifest == result["containmentSource"]
        raise Failure.new("fixture-result", "cleanup omission manifest changed after original preparation")
      end
      graph = graph!(owner, MISSING)
      records = wait_records(directory, %w[fallback-writer-close.json leader-eof.json], deadline_ns: deadline_ns)
      close, eof = records.values_at("fallback-writer-close.json", "leader-eof.json")
      custody = close["watchdogOwnership"]
      times = %w[driverDeadlineNs preparedNs prearmDeadlineNs slotCeilingNs startReturnedNs admitReturnedNs
                 captureEntryNs armNs fallbackNs effectiveHardDeadlineNs]
      facts = %w[actualDriverCaller actualStartReturned actualAdmitReturned captureCallerIsDriver
                 captureFinishedBeforeClose captureThreadExitedBeforeClose]
      unless custody.instance_of?(Hash) && custody.keys.sort == (times + facts + %w[driverPid captureJoinedBeforeClose]).sort &&
             times.all? { |key| custody[key].instance_of?(Integer) && custody[key].positive? } &&
             facts.all? { |key| custody[key].equal?(true) } && result["watchdogPreadmitted"].equal?(true) &&
             (custody["captureJoinedBeforeClose"].equal?(true) || custody["captureJoinedBeforeClose"].equal?(false)) &&
             custody["driverPid"].instance_of?(Integer) && custody["driverPid"].positive? &&
             custody["driverPid"] == driver_dispatch.fetch("pid") &&
             custody["driverDeadlineNs"] == deadline_ns && custody["driverDeadlineNs"] == driver_dispatch.fetch("deadlineNs") &&
             custody["prearmDeadlineNs"] == [custody["preparedNs"] + MissingCleanupDriver::PREARM_NS,
               deadline_ns - MissingCleanupDriver::FALLBACK_DELAY_NS - MissingCleanupDriver::FALLBACK_FINISH_NS].min &&
             custody["preparedNs"] < custody["prearmDeadlineNs"] &&
             custody["slotCeilingNs"] == custody["prearmDeadlineNs"] + MissingCleanupDriver::FALLBACK_DELAY_NS + MissingCleanupDriver::FALLBACK_FINISH_NS &&
             custody["slotCeilingNs"] <= deadline_ns &&
             custody["preparedNs"] <= custody["startReturnedNs"] && custody["startReturnedNs"] <= custody["admitReturnedNs"] &&
             custody["admitReturnedNs"] <= custody["captureEntryNs"] && custody["captureEntryNs"] <= custody["armNs"] &&
             custody["armNs"] < custody["prearmDeadlineNs"] &&
             custody["fallbackNs"] == custody["armNs"] + MissingCleanupDriver::FALLBACK_DELAY_NS &&
             custody["effectiveHardDeadlineNs"] == custody["fallbackNs"] + MissingCleanupDriver::FALLBACK_FINISH_NS &&
             custody["effectiveHardDeadlineNs"] <= custody["slotCeilingNs"] &&
             close["watchdogRunDeadlineNs"] == custody["slotCeilingNs"] && close["watchdogHardDeadlineNs"] == custody["slotCeilingNs"] &&
             close["closeEntryNs"].instance_of?(Integer) && close["closeReturnNs"].instance_of?(Integer) &&
             custody["fallbackNs"] <= close["closeEntryNs"] && close["closeReturnNs"] < custody["effectiveHardDeadlineNs"]
        raise Failure.new("fixture-result", "missing cleanup lacks the original driver-owned bounded fallback")
      end
      _entries, bindings = omission_records!(directory, manifest, graph, driver_pid: driver_dispatch.fetch("pid"),
        deadline_ns: deadline_ns, capture_entry_ns: custody.fetch("captureEntryNs"), arm_ns: custody.fetch("armNs"),
        before_ns: close.fetch("closeEntryNs"))
      unless bindings == close["omissionRecords"] && bindings.all? { |name, binding|
          prior_identity = close.fetch("omissionRecords").fetch(name).fetch("identity")
          binding.fetch("identity").all? { |key, value| prior_identity.fetch(key).instance_of?(value.class) } }
        raise Failure.new("fixture-result", "cleanup omission bytes or file identity changed after writer admission")
      end
      unless close == result["fallbackWriterClose"] && close["version"] == 1 && close["identities"] == graph &&
             close["actualOriginalWriterClose"] && close["soleFixtureWriter"] && close["originalWatchdogThread"] &&
             close["watchdogAdmittedBeforeClose"] && result["watchdogJoined"] &&
             eof["version"] == 1 && eof["eof"] && eof["controlReadNil"] && eof["pid"] == graph["validator"] &&
             eof["group"] == graph["group"] && eof["sid"] == graph["sid"] && eof["fifoIdentity"] == close["fifoIdentity"] &&
             eof["readNilNs"].instance_of?(Integer) && eof["readNilNs"] >= close["closeEntryNs"] &&
             close["closeReturnNs"] >= close["closeEntryNs"]
        raise Failure.new("fixture-result", "missing cleanup did not leave V until the original fixture EOF fallback")
      end
      # Kernel EOF can reach V before the writer's Ruby close returns. The
      # causal proof is sole original writer + actual close + SAME FIFO readnil,
      # not an invalid readNilNs >= closeReturnNs timestamp requirement.
      # The two omission flags describe C-/K-issued GROUP KILL only. They do
      # not assert absence of C's original direct cleanup of its own K child.
      proof = {"version" => 1, "kind" => "validator-survived-until-fixture-eof", "mode" => MISSING,
       "identities" => graph, "fifoIdentity" => close["fifoIdentity"], "sourceSha256" => sources,
       "helperCopy" => manifest["helperCopy"], "custodianKillOmitted" => true, "keeperKillOmitted" => true,
       "originalWatchdogWriterClosed" => true, "actualValidatorReadNil" => true,
       "validatorSurvivedUntilFallback" => true, "nativeFinality" => "unknown",
       "writerCloseEntryNs" => close["closeEntryNs"], "validatorReadNilNs" => eof["readNilNs"],
       "reportSha256" => bindings.transform_values { |binding| binding.fetch("sha256") }.merge(report_hashes(directory, records))}
      raise Failure.new("fixture-result", "missing cleanup proof completed after original cutoff") unless UploadProcessFixture.clock_ns < deadline_ns
      proof
    end
  end

  class HardLossNativeDriver < NativeSetupDriver
    def prepare_native
      super
      ContainmentEvidence.prepare(self)
    end
  end

  class HardLossAdapterDriver < AdapterDriver
    def prepare_native
      super
      ContainmentEvidence.prepare(self)
    end
  end

  class MissingCleanupDriver < NativeSetupDriver
    PREARM_NS = 5_000_000_000
    FALLBACK_DELAY_NS = 5_300_000_000
    FALLBACK_FINISH_NS = 1_000_000_000

    class FallbackControl < WorkerControl
      attr_accessor :driver
      attr_reader :close_result, :close_error, :close_entry_ns, :close_return_ns

      def close_writer
        raise Failure.new("fixture-control", "repeated negative-control writer close") if @close_entered
        @close_entered = true
        slot = driver.instance_variable_get(:@watchdog)
        session = driver.observation&.session
        arm = driver.watchdog_arm_record
        unless slot && slot.thread.equal?(Thread.current) && slot.publication_ready? && !slot.launch_retired? &&
               driver.observed["watchdogStarted"] && @anchor.state == :closed && @writer.state == :open &&
               @writer.io.close_on_exec? && OwnedChild.identity(@writer.io.stat) == @identity && session&.ready && session.reserved &&
               arm && arm.fetch(:session).equal?(session)
          raise Failure.new("fixture-control", "fallback is not the preadmitted original sole-writer watchdog")
        end
        graph = {"custodian" => session.custodian_child.pid, "keeper" => session.reserved.fetch("keeper_pid"),
          "validator" => session.ready.fetch("validator_pid"), "group" => session.ready.fetch("group_id"),
          "sid" => session.custodian_child.pid}
        custody = driver.watchdog_ownership(arm)
        prepared = driver.observed.fetch("containmentSource")
        manifest = ContainmentEvidence.manifest!(@directory, ContainmentEvidence::MISSING, prepared.fetch("sourceSha256"))
        unless manifest == prepared
          raise Failure.new("fixture-control", "cleanup omission manifest changed after original preparation")
        end
        _entries, omission_bindings = ContainmentEvidence.omission_records!(@directory, manifest, graph,
          driver_pid: custody.fetch("driverPid"), deadline_ns: custody.fetch("driverDeadlineNs"),
          capture_entry_ns: custody.fetch("captureEntryNs"), arm_ns: arm.fetch(:at_ns), before_ns: UploadProcessFixture.clock_ns)
        # Guard reads precede the short final claim. No lock spans the original
        # close or publication; after a claim the SAME worker keeps custody until
        # its actual join, even if stop is published while close is in flight.
        claim = driver.claim_watchdog_action!(arm)
        @close_entry_ns = claim.fetch(:entry_ns)
        @close_result = super
        @close_return_ns = UploadProcessFixture.clock_ns
        unless @close_return_ns < arm.fetch(:hard_ns)
          raise Failure.new("fixture-control", "original fallback close returned after its effective deadline")
        end
        evidence = {"version" => 1, "identities" => graph, "fifoIdentity" => @identity,
          "closeEntryNs" => @close_entry_ns, "closeReturnNs" => @close_return_ns,
          "actualOriginalWriterClose" => @close_result.equal?(true) && @writer.state == :closed && @writer.io.closed?,
          "soleFixtureWriter" => true, "originalWatchdogThread" => true, "watchdogAdmittedBeforeClose" => true,
          "watchdogRunDeadlineNs" => slot.run_deadline_ns, "watchdogHardDeadlineNs" => slot.hard_cleanup_deadline_ns,
          "watchdogOwnership" => custody, "omissionRecords" => omission_bindings}
        OwnedChild.write_record(File.join(@directory, "fallback-writer-close.json"), evidence)
        driver.observed["fallbackWriterClose"] = evidence
        @close_result
      rescue Exception => error
        @close_error ||= error
        raise
      end
    end

    def initialize(directory, mode, deadline_ns:)
      unless mode == ContainmentEvidence::MISSING && deadline_ns.instance_of?(Integer) && deadline_ns.positive?
        raise Failure.new("fixture-input", "missing cleanup lacks its original driver cutoff")
      end
      super(directory, mode)
      @driver_deadline_ns = deadline_ns
      @watchdog_lock = Mutex.new
      @watchdog_stopped = false
      @watchdog_arm = @watchdog_action = nil
      @control = FallbackControl.new(directory)
      @control.driver = self
    end

    def prepare_native
      # Same original native setup configuration; only the source-bound C/K
      # KILL-omission copy differs. Keep the accepted base mutation anchors.
      require_relative "../../fastlane/native_upload_validation"
      @native = MobileReleaseKit::NativeUploadValidation
      @tooling = File.realpath(File.expand_path("../../fastlane", __dir__))
      @argv = [File.realpath(RbConfig.ruby), File.realpath(__FILE__), "worker", @directory, @mode]
      ContainmentEvidence.prepare(self)
      @observation = Observation.new(self, native: @native, root: @directory)
      prepare_watchdog
    end

    def prepare_watchdog
      @watchdog_lock.synchronize do
        unless !@watchdog_stopped && @driver_thread.nil? && @watchdog.nil? && Thread.current.equal?(Thread.main)
          raise Failure.new("fixture-control", "fallback must be started once by its original driver")
        end
        @driver_thread, @driver_pid = Thread.current, Process.pid
      end
      @watchdog_prepared_ns = UploadProcessFixture.clock_ns
      @watchdog_prearm_ns = [@watchdog_prepared_ns + PREARM_NS,
        @driver_deadline_ns - FALLBACK_DELAY_NS - FALLBACK_FINISH_NS].min
      @watchdog_slot_ceiling_ns = @watchdog_prearm_ns + FALLBACK_DELAY_NS + FALLBACK_FINISH_NS
      unless @watchdog_prepared_ns < @watchdog_prearm_ns && @watchdog_slot_ceiling_ns <= @driver_deadline_ns
        raise Failure.new("fixture-control", "original fallback prearm window expired")
      end
      @watchdog = MobileReleaseKit::NativeUploadProcess::TaskSlot.new(caller: @driver_thread, parent_slot: nil,
        run_deadline_ns: @watchdog_slot_ceiling_ns, hard_cleanup_deadline_ns: @watchdog_slot_ceiling_ns)
      @watchdog_start_return = @watchdog.start { run_watchdog }
      @watchdog_start_return_ns = UploadProcessFixture.clock_ns
      raise Failure.new("fixture-control", "original fallback start was not returned") unless @watchdog_start_return.equal?(@watchdog)

      loop do
        now = UploadProcessFixture.clock_ns
        unless now < @watchdog_prearm_ns && !@watchdog.cancelled? && !@watchdog.launch_retired?
          raise Failure.new("fixture-control", "original fallback publication missed prearm admission")
        end
        break if @watchdog.publication_ready?
        sleep [10_000_000, @watchdog_prearm_ns - now].min.fdiv(1_000_000_000)
      end
      # Both original thread references are already positively published, so
      # original admit takes its immediate branch, never its S-bounded wait.
      # Publication itself may have crossed P: the previous loop sample cannot
      # authorize admission. State checks precede this fresh original-P check.
      @watchdog_lock.synchronize do
        unless !@watchdog_stopped && !@watchdog.cancelled? && !@watchdog.launch_retired? &&
               UploadProcessFixture.clock_ns < @watchdog_prearm_ns
          raise Failure.new("fixture-control", "original fallback publication missed prearm admission")
        end
      end
      @watchdog_admit_return = @watchdog.admit!
      @watchdog_admit_return_ns = UploadProcessFixture.clock_ns
      unless @watchdog_admit_return.equal?(true) && @watchdog_admit_return_ns < @watchdog_prearm_ns &&
             @watchdog.publication_ready? && !@watchdog.cancelled? && !@watchdog.launch_retired? &&
             UploadProcessFixture.clock_ns < @watchdog_prearm_ns
        raise Failure.new("fixture-control", "original fallback admission missed its prearm cutoff")
      end
      @observed["watchdogPreadmitted"] = true
      true
    end

    def native_event(name, object)
      if name == :execute_enter
        @watchdog_lock.synchronize do
          unless Thread.current.equal?(@driver_thread) && @driver_thread.equal?(Thread.main) && @capture_entry_ns.nil? &&
                 !@watchdog_stopped && @watchdog_arm.nil? && @watchdog_action.nil? &&
                 @watchdog_start_return.equal?(@watchdog) && @watchdog_admit_return.equal?(true) &&
                 @watchdog.caller.equal?(@driver_thread) && @watchdog.publication_ready? &&
                 !@watchdog.cancelled? && !@watchdog.launch_retired? && object.capture_slot.caller.equal?(@driver_thread)
            raise Failure.new("fixture-control", "native entry lacks original live fallback preadmission")
          end
          now = UploadProcessFixture.clock_ns
          raise Failure.new("fixture-control", "native entry missed its original prearm cutoff") unless now < @watchdog_prearm_ns
          @capture_entry_ns = now
        end
      end
      super
    end

    def start_watchdog
      session = @observation.session
      capture = session&.capture_slot
      unless session && session.equal?(@native_frame) && capture && capture.thread.equal?(Thread.current) &&
             capture.caller.equal?(@driver_thread) && !Thread.current.equal?(@driver_thread) &&
             session.ready && session.reserved && @observed["ready"] && @control.anchor.state == :closed &&
             @control.writer.state == :open && @control.writer.io.close_on_exec? &&
             OwnedChild.identity(@control.writer.io.stat) == @control.identity
        raise Failure.new("fixture-control", "fallback arm lacks the original capture and sole writer")
      end
      @watchdog_lock.synchronize do
        unless !@watchdog_stopped && @watchdog_arm.nil? && @watchdog_action.nil? && @driver_thread.alive? &&
               @driver_thread.equal?(Thread.main) && @watchdog.caller.equal?(@driver_thread) &&
               @watchdog_start_return.equal?(@watchdog) && @watchdog_admit_return.equal?(true) &&
               @watchdog.publication_ready? && !@watchdog.cancelled? && !@watchdog.launch_retired? &&
               @capture_entry_ns && !capture.cancelled? && !capture.launch_retired? && session.primary_error.nil? &&
               !session.retained_unknown? && session.cleanup_errors.empty?
          raise Failure.new("fixture-control", "original fallback cannot be armed in this lifecycle")
        end
        capture_run, capture_hard = capture.run_deadline_ns, capture.hard_cleanup_deadline_ns
        now = UploadProcessFixture.clock_ns
        unless @capture_entry_ns <= now && now < @watchdog_prearm_ns && now < capture_run && now < capture_hard
          raise Failure.new("fixture-control", "fallback arm missed its original lifecycle cutoff")
        end
        fallback = now + FALLBACK_DELAY_NS
        hard = fallback + FALLBACK_FINISH_NS
        raise Failure.new("fixture-control", "fallback arm exceeded its original ceiling") unless hard <= @watchdog_slot_ceiling_ns
        @watchdog_arm = {session: session, capture: capture, thread: Thread.current,
          at_ns: now, fallback_ns: fallback, hard_ns: hard}.freeze
      end
      @observed["watchdogStarted"] = true # Actual READY arm, distinct from preadmission.
      true
    end

    def watchdog_arm_record
      @watchdog_lock.synchronize { @watchdog_arm }
    end

    def watchdog_join_deadline_ns
      @watchdog_lock.synchronize { @watchdog_arm ? @watchdog_arm.fetch(:hard_ns) : @watchdog_prearm_ns }
    end

    def run_watchdog
      unless @watchdog.thread.equal?(Thread.current)
        raise Failure.new("fixture-control", "fallback worker is not its original published task")
      end
      loop do
        arm, stopped = @watchdog_lock.synchronize { [@watchdog_arm, @watchdog_stopped] }
        return true if stopped
        now = UploadProcessFixture.clock_ns
        cutoff = arm ? arm.fetch(:hard_ns) : @watchdog_prearm_ns
        unless now < cutoff && !@watchdog.cancelled? && !@watchdog.launch_retired?
          raise Failure.new("fixture-control", "original fallback effective window expired")
        end
        if arm && now >= arm.fetch(:fallback_ns)
          @observed["watchdogIntervened"] = @observed["fallbackUsed"] = true
          @control.close_writer
          return true
        end
        next_boundary = arm ? arm.fetch(:fallback_ns) : @watchdog_prearm_ns
        sleep [10_000_000, next_boundary - now].min.fdiv(1_000_000_000)
      end
    end

    def watchdog_ownership(arm)
      capture = arm.fetch(:capture)
      {"driverPid" => @driver_pid, "driverDeadlineNs" => @driver_deadline_ns,
       "preparedNs" => @watchdog_prepared_ns, "prearmDeadlineNs" => @watchdog_prearm_ns,
       "slotCeilingNs" => @watchdog_slot_ceiling_ns, "startReturnedNs" => @watchdog_start_return_ns,
       "admitReturnedNs" => @watchdog_admit_return_ns, "captureEntryNs" => @capture_entry_ns,
       "armNs" => arm.fetch(:at_ns), "fallbackNs" => arm.fetch(:fallback_ns), "effectiveHardDeadlineNs" => arm.fetch(:hard_ns),
       "actualDriverCaller" => @watchdog.caller.equal?(@driver_thread) && @driver_thread.equal?(Thread.main),
       "actualStartReturned" => @watchdog_start_return.equal?(@watchdog), "actualAdmitReturned" => @watchdog_admit_return.equal?(true),
       "captureCallerIsDriver" => capture.caller.equal?(@driver_thread),
       "captureFinishedBeforeClose" => capture.finished?, "captureJoinedBeforeClose" => capture.joined?,
       "captureThreadExitedBeforeClose" => !arm.fetch(:thread).alive?}
    end

    def claim_watchdog_action!(arm)
      @watchdog_lock.synchronize do
        unless arm && arm.equal?(@watchdog_arm) && @watchdog_action.nil? && !@watchdog_stopped &&
               @driver_thread.alive? && @driver_thread.equal?(Thread.main) && @watchdog.caller.equal?(@driver_thread) &&
               @watchdog.thread.equal?(Thread.current) && @watchdog.publication_ready? &&
               @watchdog_start_return.equal?(@watchdog) && @watchdog_admit_return.equal?(true) &&
               !@watchdog.cancelled? && !@watchdog.launch_retired?
          raise Failure.new("fixture-control", "original fallback action was not admitted")
        end
        now = UploadProcessFixture.clock_ns
        unless arm.fetch(:fallback_ns) <= now && now < arm.fetch(:hard_ns)
          raise Failure.new("fixture-control", "original fallback action missed its effective window")
        end
        @watchdog_action = {arm: arm, entry_ns: now}.freeze
      end
    end

    def stop_watchdog!
      @watchdog_lock.synchronize { @watchdog_stopped = true }
      true
    end

    def finish_resources
      cleanup_step { stop_watchdog! }
      super
    end

    def close_control
      if @watchdog
        attempted = @watchdog.start_attempted?
        if attempted.equal?(true)
          unless @watchdog.joined?.equal?(true) && @watchdog.finished?.equal?(true) && @watchdog.unresolved?.equal?(false)
            raise Failure.new("fixture-cleanup", "original fallback task still owns its control leases")
          end
        elsif attempted.equal?(false)
          unless @watchdog_unstarted_retired
            raise Failure.new("fixture-cleanup", "original fallback launch retirement is uncertain") if @watchdog_retirement_attempted
            @watchdog_retirement_attempted = true
            returned = @watchdog.close_launch!
            unless returned.equal?(true) && @watchdog.launch_retired?.equal?(true)
              raise Failure.new("fixture-cleanup", "original unstarted fallback was not retired")
            end
            @watchdog_unstarted_retired = true
          end
        else
          raise Failure.new("fixture-cleanup", "original fallback start state is uncertain")
        end
      end
      super
    rescue Exception
      # A join attempt or a stop flag is not transfer of writer custody. Root
      # the real driver/control, not a Boolean, before propagating uncertainty.
      UploadProcessFixture.retain_process_case!(self)
      UploadProcessFixture.retain_unknown_domain!(@directory)
      raise
    end
  end

  def validate_driver_input!(directory, input, ownership_mode: nil)
    unless input.instance_of?(Hash) &&
           (input.keys.sort == %w[deadlineNs mode parameters platform] ||
            input.keys.sort == %w[deadlineNs mode observeSignals parameters platform])
      raise Failure.new("fixture-input", "invalid original driver input")
    end
    platform, mode = input.values_at("platform", "mode")
    validate_request!(platform, mode, input.fetch("parameters"))
    observe_signals = input.fetch("observeSignals", false)
    validate_signal_observation!(platform, mode, observe_signals)
    if ownership_mode
      unless mode == ownership_mode && (OWNERSHIP_UNKNOWN_MODES.key?(mode) ||
        %w[ownership-async ownership-signals ownership-policies ownership-setup ownership-observation].include?(mode)) && !observe_signals
        raise Failure.new("fixture-input", "invalid fixed ownership singleton/family dispatch")
      end
    elsif mode.start_with?("ownership-")
      raise Failure.new("fixture-input", "ownership probe must use its fixed CLI")
    end
    cutoff, now = input["deadlineNs"], clock_ns
    limit = ownership_mode ? OWNERSHIP_LIMIT : DRIVER_LIMIT
    unless cutoff.instance_of?(Integer) && cutoff > now && cutoff <= now + limit * 1_000_000_000
      raise Failure.new("fixture-input", "original driver cutoff is missing or expired")
    end
    unless Dir.tmpdir == directory
      raise Failure.new("fixture-input", "driver temporary directory is not its owned case root")
    end
    owned_fixture_directory(directory)
    input
  end

  def driver(directory)
    assert_domain_reusable!
    input = validate_driver_input!(directory, read_json(File.join(directory, "input.json")))
    platform, mode = input.values_at("platform", "mode")
    OwnedChild.write_record(File.join(directory, "driver-dispatch.json"),
      {"version" => 1, "pid" => Process.pid, "argv" => [File.realpath(RbConfig.ruby), File.realpath(__FILE__), "driver", directory],
       "environment" => ENV.to_h, "cwd" => Dir.pwd, "fixtureSha256" => Digest::SHA256.file(__FILE__).hexdigest,
       "deadlineNs" => input.fetch("deadlineNs")})
    return NativeSignalProbe.execute_driver(directory, mode) if input.fetch("observeSignals", false)
    return NativePrimaryProbe.new(directory, mode).execute if NATIVE_PRIMARY_PROOFS.key?(mode)
    return NativeOrderProbe.new(directory, mode).execute if NATIVE_ORDER_MODES.include?(mode)
    return HardLossNativeDriver.new(directory, mode).execute if mode == "kill-native-setup"
    return MissingCleanupDriver.new(directory, mode, deadline_ns: input.fetch("deadlineNs")).execute if mode == ContainmentEvidence::MISSING
    return NativeSetupDriver.new(directory, mode).execute if platform == "native"
    return HardLossAdapterDriver.new(directory, platform, mode, input.fetch("parameters")).execute if ContainmentEvidence::HARD_LOSS.include?(mode)
    AdapterDriver.new(directory, platform, mode, input.fetch("parameters")).execute
  end

  def ownership_driver(directory, mode)
    assert_domain_reusable!
    input = validate_driver_input!(directory, read_json(File.join(directory, "input.json")), ownership_mode: mode)
    OwnedChild.write_record(File.join(directory, "ownership-dispatch.json"),
      {"version" => 1, "pid" => Process.pid, "argv" => [File.realpath(RbConfig.ruby), File.realpath(__FILE__), "ownership", directory, mode],
       "environment" => ENV.to_h, "cwd" => Dir.pwd, "fixtureSha256" => Digest::SHA256.file(__FILE__).hexdigest,
       "deadlineNs" => input.fetch("deadlineNs")})
    if OWNERSHIP_UNKNOWN_MODES.key?(mode)
      OwnershipProbe.new(directory, "unknown").execute_single(*OWNERSHIP_UNKNOWN_MODES.fetch(mode))
    elsif mode == "ownership-setup"
      SetupFailureProbe.new(directory).execute
    elsif mode == "ownership-observation"
      ObservationProbe.new(directory).execute
    else
      OwnershipProbe.new(directory, mode.delete_prefix("ownership-")).execute
    end
  end

  module Contracts
    def with_adapter_failure_diagnostic(platform:, mode:)
      state = {} if UploadProcessFixture.adapter_failure_mode?(platform, mode)
      yield(state ? {adapter_failure_state: state} : {})
    rescue Exception => original
      # Only the same post-run Lifetime rejection may report; no new primary.
      begin
        UploadProcessFixture.report_adapter_failure(state, original, platform: platform, mode: mode,
          callback: "#{self.class.name}##{name}") if state
      rescue Exception => diagnostic_error
        begin
          if state.instance_of?(Hash)
            state[:report_attempted] = true # A failed callback lookup is not retryable.
            state[:diagnostic_error] ||= diagnostic_error
          end
        rescue Exception
          nil
        end
      end
      raise
    end

    def assert_original_fixture_driver(value, mode)
      assert value.fetch("driverJoined"), value.inspect
      if mode.start_with?("ownership-")
        snapshot = value.fetch("probeDriverObservation")
        assert snapshot.fetch("settled"), snapshot.inspect
        refute snapshot.fetch("unknown"), snapshot.inspect
        assert snapshot.fetch("actualOwnedControlCloses"), snapshot.inspect
        assert snapshot.fetch("actualTaskJoins"), snapshot.inspect
        assert snapshot.fetch("hooksRestored"), snapshot.inspect
        assert_equal 1, snapshot.fetch("children").length
        child = snapshot.fetch("children").first
        assert_equal "finalized", child.fetch("finality")
        %w[originalWaitObserved creatorJoinObserved actualStreamEOFs actualNativeCloses].each { |key| assert child.fetch(key), child.inspect }
        provenance, dispatch = child.fetch("provenance"), value.fetch("probeDispatch")
      else
        provenance, dispatch = value.fetch("driverProvenance"), value.fetch("driverDispatch")
      end
      assert_equal "reaped", provenance.fetch("phase")
      assert provenance.fetch("numericRetired"), provenance.inspect
      assert provenance.fetch("creatorJoined"), provenance.inspect
      assert provenance.fetch("resourcesClosed"), provenance.inspect
      assert_equal({"out" => true, "err" => true}, provenance.fetch("ownedStreamEOFs"))
      assert_equal provenance.fetch("pid"), provenance.fetch("wait").fetch("pid")
      assert_equal provenance.fetch("pid"), dispatch.fetch("pid")
      assert_equal provenance.fetch("requested").fetch("argv"), dispatch.fetch("argv")
      assert_equal provenance.fetch("requested").fetch("environment"), dispatch.fetch("environment")
      assert_equal provenance.fetch("requested").fetch("cwd"), dispatch.fetch("cwd")
      assert_match(/\A[0-9a-f]{64}\z/, dispatch.fetch("fixtureSha256"))
      assert_instance_of Integer, dispatch.fetch("deadlineNs")
      assert_equal File.realpath(RbConfig.ruby), dispatch.fetch("argv").first
    end

    def assert_complete_process_case(mode)
      refute UploadProcessFixture::OWNERSHIP_UNKNOWN_MODES.key?(mode)
      refute ["ownership-observation", *UploadProcessFixture::ContainmentEvidence::HARD_LOSS].include?(mode)
      value = process_case(mode)
      assert_original_fixture_driver(value, mode)
      assert value.fetch("knownProcessesDead"), value.inspect
      refute value.fetch("retainedFixture"), value.inspect
      refute value.fetch("domainDisposalRequired"), value.inspect
      refute UploadProcessFixture.domain_disposal_required?
      unless mode.start_with?("ownership-")
        assert_equal "finalized", value.fetch("nativeFinality")
        snapshot = value.fetch("nativeObservation")
        assert snapshot.fetch("finalized"), snapshot.inspect
        assert snapshot.fetch("settled"), snapshot.inspect
        refute snapshot.fetch("unknown"), snapshot.inspect
        refute snapshot.fetch("noProducers"), snapshot.inspect
        assert snapshot.fetch("hooksRestored"), snapshot.inspect
        assert_empty snapshot.fetch("observerErrors")
        assert snapshot.fetch("streams").values.all? { |item| item.equal?(true) }, snapshot.inspect
        snapshot.fetch("tasks").each do |task|
          assert task.fetch("actualConstructionObserved"), task.inspect
          assert task.fetch("actualLaunchClosureObserved"), task.inspect
          assert task.fetch("launchRetired"), task.inspect
          assert task.fetch("finished"), task.inspect
          assert task.fetch("joined"), task.inspect
          assert task.fetch("actualJoinObserved"), task.inspect
          refute task.fetch("unresolved"), task.inspect
        end
        snapshot.fetch("leases").each do |lease|
          assert lease.fetch("noIOAcquired") || lease.fetch("closed") && lease.fetch("actualCloseObserved"), lease.inspect
          assert_nil lease.fetch("closeError"), lease.inspect
        end
        assert_equal "reaped", snapshot.fetch("custodian").fetch("state")
        assert_equal "confirmed", snapshot.fetch("final").fetch("cleanup")
        %w[keeper validator].each { |role| assert_equal "reaped", snapshot.fetch("final").fetch(role).fetch("state") }
        assert_equal "retired", snapshot.fetch("final").fetch("group").fetch("state")
        assert snapshot.fetch("final").fetch("group").fetch("absent")
        %w[ownedDescriptorsClosed tasksJoined watchdogJoined injectorsJoined handlersRestored registryInactive].each { |key| assert value.fetch(key), value.inspect }
        refute value.fetch("pendingInterrupt"), value.inspect
        assert_empty value.fetch("cleanupErrors")
        assert value.fetch("adapterCallObserved"), value.inspect
        assert_equal UploadProcessFixture::DEADLINE, value.fetch("adapterLimitSeconds")
      end
      value
    end

    # Deliberate UNKNOWN is retained through this original singleton's exit.
    # Driver wait/EOF is checked independently and never upgraded into C/K/V
    # finality. The guard assertion itself performs no acquisition or cleanup.
    def assert_retained_process_case(mode)
      value = process_case(mode)
      assert_original_fixture_driver(value, mode)
      assert_equal "unknown", value.fetch("nativeFinality")
      assert value.fetch("retainedFixture"), value.inspect
      assert value.fetch("domainDisposalRequired"), value.inspect
      refute value.key?("knownProcessesDead"), value.inspect
      refute value.key?("allAcquiredChildrenJoined"), value.inspect
      assert UploadProcessFixture.expected_unknown_retention?(@root)
      error = assert_raises(UploadProcessFixture::Failure) { UploadProcessFixture.assert_domain_reusable! }
      assert_equal "fixture-domain", error.kind
      value
    end

    def assert_inherited_adapter_proof(value)
      %w[ready stdinClosedAfterReady descendantLiveBeforeRelease inheritedPipeBlockObserved validatorReapedAfterRelease
         commitAfterDataEOF adapterRejected adapterEmptyJSONObserved adapterJSONErrorSameObject deadBeforeFallback].each do |key|
        assert value.fetch(key), value.inspect
      end
      assert_equal "MobileReleaseKit::ContractError", value.fetch("adapterErrorClass")
      assert_match(/\Acurrent (?:IPA|AAB) validation result is invalid UTF-8 JSON: JSON::ParserError\z/, value.fetch("adapterError"))
      final = value.fetch("nativeObservation").fetch("final")
      assert_equal "ok", final.fetch("outcome")
      assert_equal "exit", final.fetch("validator").fetch("status_kind")
      assert_equal 0, final.fetch("validator").fetch("status_code")
      proof = value.fetch("descendantProof")
      fork, child = proof.values_at("forkReturn", "readyRecord")
      assert_equal final.fetch("validator").fetch("pid"), fork.fetch("parent")
      assert_equal final.fetch("group").fetch("id"), fork.fetch("group")
      assert_equal fork.fetch("child"), child.fetch("pid")
      assert_equal fork.fetch("group"), child.fetch("group")
      assert_equal value.fetch("nativeObservation").fetch("custodian").fetch("pid"), child.fetch("sid")
      assert_equal proof.fetch("stdoutReaderIdentity"), child.fetch("stdout")
      assert_equal proof.fetch("stderrReaderIdentity"), child.fetch("stderr")
      ["stdout", "stderr"].each { |role| assert_equal "fifo", child.fetch(role).fetch("type") }
      assert_operator value.fetch("validatorReleasedNs"), :<, value.fetch("commitQueuedNs")
      assert_operator value.fetch("commitQueuedNs"), :<, value.fetch("nativeRunDeadlineNs")
      assert_operator value.fetch("readinessSeconds"), :<, UploadProcessFixture::DEADLINE
      refute value.fetch("legacyRecordUsedForOwnership"), value.inspect
      refute value.fetch("fallbackUsed"), value.inspect
    end

    def assert_original_timeout(value, premature: false)
      assert value.fetch("ready"), value.inspect
      assert value.fetch("stdinClosedAfterReady"), value.inspect
      assert value.fetch("deadlinePrimarySameObject"), value.inspect
      assert value.fetch("deadlineResultSameObject"), value.inspect
      assert_match(/timed out/, value.fetch("adapterError"))
      # Competing original tasks may construct timeout objects in a different
      # order from the shared first-error record. Check the actual selected
      # primary, not an assumed constructor/record or last-data-wait ordering.
      start, cutoff, decision = value.values_at("nativeStartedNs", "nativeRunDeadlineNs", "selectedTimeoutNs")
      [start, cutoff, decision, value.fetch("firstTimeoutDecisionNs")].each { |time| assert_instance_of Integer, time }
      assert_equal UploadProcessFixture::DEADLINE * 1_000_000_000, cutoff - start
      assert_operator decision, :>=, start
      assert_operator decision, premature ? :< : :>=, cutoff
      if premature
        assert_equal 0, value.fetch("blockedDataWaits"), value.inspect
      else
        assert_operator value.fetch("blockedDataWaits"), :>, 0
        assert_operator value.fetch("firstBlockedDataNs"), :>=, start
        assert_operator value.fetch("firstBlockedDataNs"), :<, cutoff
      end
      refute value.fetch("watchdogIntervened"), value.inspect
    end

    def test_deadline_terminates_validator_without_authorizing_upload
      value = assert_complete_process_case("real-deadline")
      assert_original_timeout(value)
      assert value.fetch("deadBeforeFallback"), value.inspect
      refute value.fetch("fallbackUsed"), value.inspect
      assert_operator value.fetch("captureSeconds"), :<, UploadProcessFixture::CAPTURE_LIMIT
    end

    def test_deadline_terminates_inherited_pipe_children_after_validator_parent_exits
      assert_inherited_adapter_proof(assert_complete_process_case("inherited"))
    end

    def test_descendant_boundary_survives_delayed_start_and_late_parent_record
      %w[delayed-start late-record].each do |mode|
        value = assert_complete_process_case(mode)
        assert_inherited_adapter_proof(value)
        delay = value.fetch("workerDelay")
        assert_equal mode == "delayed-start" ? "before_fork" : "after_release", delay.fetch("stage")
        assert_equal delay.fetch("stage"), value.fetch("workerDelayStage")
        assert_operator delay.fetch("startNs"), :>=, value.fetch("nativeStartedNs")
        assert_operator delay.fetch("endNs"), :<, value.fetch("nativeRunDeadlineNs")
        assert_operator delay.fetch("endNs") - delay.fetch("startNs"), :>=, 300_000_000
        assert_operator value.fetch("workerDelaySeconds"), :>=, 0.3
        assert_equal UploadProcessFixture::DEADLINE * 1_000_000_000, value.fetch("nativeRunDeadlineNs") - value.fetch("nativeStartedNs")
      end
    end

    def test_unready_fixture_fails_distinctly_and_stops_before_any_late_pid_record
      value = assert_complete_process_case("unready")
      assert_equal "readiness", value.fetch("kind")
      assert value.fetch("captureEntered"), value.inspect
      refute value.fetch("ready"), value.inspect
      refute value.fetch("stdinClosedAfterReady"), value.inspect
      refute value.fetch("nativeObservation").fetch("stdinCloseReturned"), value.inspect
      refute value.fetch("watchdogStarted"), value.inspect
      refute value.fetch("watchdogIntervened"), value.inspect
      refute value.fetch("legacyRecordUsedForOwnership"), value.inspect
      refute value.key?("deadBeforeFallback"), value.inspect
    end

    def test_fixture_detects_leader_only_cleanup_and_missing_deadline
      only_leader = assert_complete_process_case("leader-only")
      assert_equal "descendant-alive", only_leader.fetch("kind")
      %w[descendantLiveBeforeRelease inheritedPipeBlockObserved validatorReapedAfterRelease
         descendantLiveAfterOmittedCleanup fallbackAfterObservation fallbackUsed].each { |key| assert only_leader.fetch(key), only_leader.inspect }
      copy = only_leader.fetch("helperCopy")
      assert_equal "omitted-group-kill", copy.fetch("label")
      assert_equal copy.fetch("originalSha256"), only_leader.fetch("mutationSourceSha256")
      assert_equal copy.fetch("sha256"), only_leader.fetch("mutationSha256")
      refute_equal copy.fetch("originalSha256"), copy.fetch("sha256")
      refute only_leader.fetch("watchdogIntervened"), only_leader.inspect
      refute only_leader.key?("deadBeforeFallback"), only_leader.inspect
      no_deadline = assert_complete_process_case("no-deadline")
      assert_equal "capture-watchdog", no_deadline.fetch("kind")
      assert no_deadline.fetch("watchdogIntervened"), no_deadline.inspect
      assert no_deadline.fetch("fallbackUsed"), no_deadline.inspect
      assert no_deadline.fetch("watchdogJoined"), no_deadline.inspect
      assert_equal 10_000_000_000, no_deadline.fetch("nativeRunDeadlineNs") - no_deadline.fetch("nativeStartedNs")
      assert_equal UploadProcessFixture::CAPTURE_LIMIT * 1_000_000_000, no_deadline.fetch("watchdogDeadlineNs") - no_deadline.fetch("captureStartedNs")
      assert_operator no_deadline.fetch("captureSeconds"), :>=, UploadProcessFixture::CAPTURE_LIMIT
      copies = no_deadline.fetch("sourceCopies")
      outer = copies.find { |entry| entry.fetch("label") == "no-deadline-outer" }
      refute_nil outer
      assert_equal outer.fetch("originalSha256"), no_deadline.fetch("mutationSourceSha256")
      assert_equal outer.fetch("sha256"), no_deadline.fetch("mutationSha256")
      refute_equal outer.fetch("originalSha256"), outer.fetch("sha256")
      refute no_deadline.key?("deadBeforeFallback"), no_deadline.inspect
    end

    def test_fixture_rejects_an_immediate_timeout_even_when_the_leader_is_killed
      value = assert_complete_process_case("immediate-deadline")
      assert_equal "elapsed-bound", value.fetch("kind")
      assert_original_timeout(value, premature: true)
      refute value.key?("deadBeforeFallback"), value.inspect
    end

    def test_slow_cleanup_cannot_supply_a_positive_deadline_wait
      %w[real-deadline-slow-cleanup immediate-deadline-slow-cleanup].each do |mode|
        value = assert_complete_process_case(mode)
        assert_operator value.fetch("slowCleanupSeconds"), :>=, 4
        assert_operator value.fetch("captureSeconds"), :>=, value.fetch("slowCleanupSeconds")
        immediate = mode.start_with?("immediate")
        assert_original_timeout(value, premature: immediate)
        if immediate
          assert_equal "elapsed-bound", value.fetch("kind")
          refute value.key?("deadBeforeFallback"), value.inspect
        else
          assert_equal "pass", value.fetch("kind")
          assert value.fetch("deadBeforeFallback"), value.inspect
        end
      end
    end

    def assert_driver_loss_containment(mode)
      value = assert_retained_process_case(mode)
      assert_equal "driver-terminated", value.fetch("kind")
      assert_equal mode, value.fetch("phase")
      assert_equal Signal.list.fetch("KILL"), value.fetch("driverTermSignal")
      proof = value.fetch("containmentProof")
      assert_equal "runtime-containment-before-fixture-eof", proof.fetch("kind")
      assert_equal mode, proof.fetch("mode")
      assert_equal "unknown", proof.fetch("nativeFinality")
      %w[heldWriterOpenThroughProof originalCustodianWaitMissing reservedGroupAbsentBeforeFixtureEOF
         runtimeGroupKillObserved originalKeeperWaitObserved originalValidatorWaitObserved releasedAndControlEOFObserved].each { |key| assert proof.fetch(key), proof.inspect }
      assert_includes [0, 2], proof.fetch("keeperExitStatus")
      assert_equal "reaped", proof.fetch("validatorReceipt").fetch("state")
      assert_equal proof.fetch("identities").fetch("validator"), proof.fetch("validatorReceipt").fetch("pid")
      assert_equal proof.fetch("identities").fetch("keeper"), proof.fetch("identities").fetch("group")
      assert_equal proof.fetch("identities").fetch("custodian"), proof.fetch("identities").fetch("sid")
      assert_equal "fifo", proof.fetch("fifoIdentity").fetch("type")
      assert_equal UploadProcessFixture::ContainmentEvidence::SOURCES.sort, proof.fetch("sourceSha256").keys.sort
      assert_equal %w[containment-custodian.json containment-keeper.json], proof.fetch("helperReportSha256").keys.sort
      proof.fetch("helperReportSha256").each_value { |digest| assert_match(/\A[0-9a-f]{64}\z/, digest) }
      copy = proof.fetch("helperCopy")
      assert_equal proof.fetch("sourceSha256").fetch("fastlane/native_upload_process.rb"), copy.fetch("originalSha256")
      refute_equal copy.fetch("sha256"), copy.fetch("originalSha256")
      close = proof.fetch("heldWriterClose")
      assert close.fetch("actualCloseReturned"), close.inspect
      assert close.fetch("closed"), close.inspect
      [proof.fetch("heldWriterAcquiredNs"), proof.fetch("driverKillEntryNs"), proof.fetch("proofCompletedNs"),
       close.fetch("entryNs"), close.fetch("returnNs")].each_cons(2) { |left, right| assert_operator left, :<=, right }
      value
    end

    def test_driver_loss_during_startup_retains_unknown_native_custody
      assert_driver_loss_containment("kill-startup")
    end

    def test_driver_loss_with_inherited_pipes_retains_unknown_native_custody
      assert_driver_loss_containment("kill-descendant")
    end

    # Reused by the required adapter contract below. This helper alone is pure:
    # numeric credentials and filesystem/capture responses are synthetic, no
    # process is started and it supplies no native-platform evidence.
    def assert_process_observer_protocol
      fixture = UploadProcessFixture
      fields = [123, 122, 501, 501, 501, 20, 20, 20, 3, 0, "live"]
      line = ->(values = fields) { "MRK_PROCESS_V1 present #{values.join(' ')}\n" }
      parse = ->(text, errors = "", status = 0) { fixture.parse_process_observer(text, errors, status, 123, 122, uid: 501, gid: 20) }
      assert_equal "absent", parse.call("MRK_PROCESS_V1 absent 123\n")
      [[0, 0, "indeterminate"], [1, 0, "indeterminate"], [1, 1, "indeterminate"],
       [2, 0, "live"], [3, 0, "live"], [4, 0, "live"],
       [2, 1, "indeterminate"], [3, 1, "indeterminate"], [4, 1, "indeterminate"],
       [5, 0, "zombie"], [5, 1, "zombie"], [6, 0, "indeterminate"],
       [4_294_967_295, 0, "indeterminate"]].each do |tail|
        assert_equal tail.last, parse.call(line.call(fields.take(8) + tail))
      end
      {"live" => :live, "indeterminate" => :indeterminate,
       "zombie" => :stopped, "absent" => :stopped}.each do |word, expected|
        assert_equal expected, fixture.observer_liveness(word)
      end
      (0...10).each do |index|
        ["0#{fields[index]}", "+#{fields[index]}", "-#{fields[index]}", "#{fields[index]}.0"].each do |bad|
          altered = fields.dup
          altered[index] = bad
          assert_raises(Failure) { parse.call(line.call(altered)) }
        end
      end
      # Every PID/PGID and saved/real/effective UID/GID column is authoritative.
      (0...8).each do |index|
        altered = fields.dup
        altered[index] += 1
        assert_raises(Failure) { parse.call(line.call(altered)) }
      end
      [[3, 1, "live"], [5, 1, "indeterminate"], [5, 0, "live"],
       [1, 0, "live"], [6, 0, "live"], [3, 2, "indeterminate"],
       [4_294_967_296, 0, "indeterminate"]].each do |tail|
        assert_raises(Failure) { parse.call(line.call(fields.take(8) + tail)) }
      end
      malformed = [nil, "", "\xff".b, "x" * 513, line.call.chomp, line.call + "\n", line.call + line.call,
                   line.call.sub("V1", "V2"), line.call.sub("present ", "present  "), line.call.sub(" ", "\t"),
                   line.call.sub("live", "absent"), line.call.sub("live", "LIVE"),
                   "MRK_PROCESS_V1 absent 124\n", "MRK_PROCESS_V1 absent 0123\n",
                   "MRK_PROCESS_V1 absent 123 extra\n", "MRK_PROCESS_V1 error query\n",
                   "MRK_PROCESS_V1 denied 123 kernel 1\n", "MRK_PROCESS_V1 denied 123 identity 0\n"]
      malformed.each { |text| assert_raises(Failure) { parse.call(text) } }
      [1, 2, 3, nil, "0", 0.0].each { |status| assert_raises(Failure) { parse.call(line.call, "", status) } }
      [["MRK_PROCESS_V1 denied 123 kernel 1\n", 2], ["MRK_PROCESS_V1 denied 123 kernel 13\n", 2],
       ["MRK_PROCESS_V1 denied 123 identity 0\n", 2], ["MRK_PROCESS_V1 error query\n", 3],
       ["MRK_PROCESS_V1 absent 123\n", 1]].each do |text, status|
        assert_raises(Failure) { parse.call(text, "", status) }
      end
      assert_raises(Failure) { parse.call(line.call, "diagnostic") }
      [[1, 122, 501, 20], ["123", 122, 501, 20], [123, true, 501, 20], [123, 1, 501, 20],
       [123, 122, 0, 20], [123, 122, 501, -1], [2_147_483_648, 122, 501, 20],
       [123, 2_147_483_648, 501, 20], [123, 122, 4_294_967_296, 20],
       [123, 122, 501, 4_294_967_296]].each do |pid, group, uid, gid|
        assert_raises(Failure) { fixture.parse_process_observer(line.call, "", 0, pid, group, uid: uid, gid: gid) }
      end
      [0, 4_294_967_295].each do |gid|
        maximum = [2_147_483_647, 2_147_483_647, *([4_294_967_295] * 3), *([gid] * 3), 3, 0, "live"]
        assert_equal "live", fixture.parse_process_observer(line.call(maximum), "", 0, *maximum.take(2), uid: 4_294_967_295, gid: gid)
      end
      assert_process_observer_routing(line)
      assert_process_observer_cleanup
    end

    def assert_process_observer_routing(line)
      fixture = UploadProcessFixture
      path = "/private/tmp/mrk-synthetic-observer/bootstrap/process-observer"
      assert_nil fixture.validate_process_observer_path(nil, darwin: false)
      [nil, "", "relative/bootstrap/process-observer", "/bin/ps", path + "\0", path + "\n",
       path.sub("/bootstrap/", "/bootstrap/../bootstrap/"), path.sub("/private/tmp/", "/tmp/")].each do |bad|
        assert_raises(Failure) { fixture.validate_process_observer_path(bad, darwin: true) }
      end
      assert_raises(Failure) { fixture.validate_process_observer_path(path, darwin: false) }
      metadata = Struct.new(:uid, :nlink, :mode, :kind) do
        def file? = kind == :file
        def directory? = kind == :directory
      end
      file = metadata.new(0, 1, 0o100555, :file)
      parent = metadata.new(0, 1, 0o40755, :directory)
      root = parent.dup
      stats = {path => file, File.dirname(path) => parent, File.dirname(File.dirname(path)) => root}
      File.stub(:lstat, ->(name) { stats.fetch(name) }) do
        File.stub(:realpath, path) do
          File.stub(:executable?, true) do
            assert_equal path, fixture.validate_process_observer_path(path, darwin: true)
            [[file, :uid, 501], [file, :nlink, 2], [file, :mode, 0o106555], [file, :mode, 0o100557],
             [file, :kind, :symlink], [parent, :uid, 501], [parent, :mode, 0o40777], [root, :uid, 501]].each do |item, key, bad|
              saved = item[key]
              begin
                item[key] = bad
                assert_raises(Failure) { fixture.validate_process_observer_path(path, darwin: true) }
              ensure
                item[key] = saved
              end
            end
          end
          File.stub(:executable?, false) { assert_raises(Failure) { fixture.validate_process_observer_path(path, darwin: true) } }
        end
        File.stub(:realpath, path + "-different") { assert_raises(Failure) { fixture.validate_process_observer_path(path, darwin: true) } }
      end
      File.stub(:lstat, ->(*) { raise Errno::ENOENT }) do
        assert_raises(Failure) { fixture.validate_process_observer_path(path, darwin: true) }
      end
      canaries = {PROCESS_OBSERVER_KEY => path + "-canary", "TMPDIR" => "/synthetic-ambient-tmpdir",
                  "TMP" => "/synthetic-ambient-tmp", "TEMP" => "/synthetic-ambient-temp",
                  "GOOGLE_APPLICATION_CREDENTIALS" => "/synthetic-credential-canary", "BUNDLE_GEMFILE" => "/synthetic-config-canary"}
      original = canaries.keys.to_h { |key| [key, ENV[key]] }
      expected_environment = PROCESS_OBSERVER_SELECTION.nil? ? {} : {PROCESS_OBSERVER_KEY => PROCESS_OBSERVER_SELECTION}
      begin
        canaries.each { |key, value| ENV[key] = value }
        assert_equal expected_environment, fixture.process_observer_environment
        owned = "/synthetic-owned-case"
        File.stub(:realpath, ->(value) { value }) do
          File.stub(:lstat, metadata.new(Process.uid, 1, 0o40700, :directory)) do
            actual = fixture.driver_environment(owned)
            expected = expected_environment.merge("TMPDIR" => owned, "TMP" => owned, "TEMP" => owned)
            assert_equal expected.keys.sort, actual.keys.sort # Never print unrelated ambient values on failure.
            assert_equal expected, actual
          end
        end
      ensure
        original.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
      end

      calls, replies = [], []
      capture = lambda do |argv, seconds:, environment:, deadline: nil|
        calls << [argv, seconds, environment, deadline]
        [replies.shift || raise("unplanned synthetic observation"), "", 0]
      end
      fixture.stub(:process_observer_path, path) do
        Process.stub(:uid, 501) do
          Process.stub(:gid, 20) do
            fixture.stub(:capture_command, capture) do
              replies << line.call
              assert_equal :live, fixture.state(123, 122, seconds: 0.25)
              assert_equal [[path, "123"], 0.25, {"LANG" => "C", "LC_ALL" => "C"}, nil], calls.last
              [[1, 0, "indeterminate"], [3, 1, "indeterminate"]].each do |tail|
                replies << line.call([123, 122, 501, 501, 501, 20, 20, 20] + tail)
                refute fixture.ready?(123, 122)
              end
              replies << line.call
              assert fixture.ready?(123, 122)
              replies << line.call([123, 122, 501, 501, 501, 20, 20, 20, 5, 1, "zombie"])
              error = assert_raises(Failure) { fixture.ready?(123, 122) }
              assert_equal "readiness", error.kind
              calls.clear
              replies.concat([[3, 1, "indeterminate"], [3, 0, "live"], [5, 1, "zombie"]].map do |tail|
                line.call([123, 122, 501, 501, 501, 20, 20, 20] + tail)
              end)
              ticks = [0.0, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07]
              fixture.stub(:clock, -> { ticks.shift || raise("synthetic clock exhausted") }) do
                fixture.dead!(123, 122, deadline: 0.2)
              end
              assert_equal 3, calls.length
              assert_empty replies
              calls.zip([0.2, 0.17, 0.14]).each { |call, limit| assert_in_delta limit, call[1], 0.000_001 }
              assert_equal [0.2] * 3, calls.map(&:last)
              # Definite absence after the absolute endpoint is not success.
              calls.clear
              replies << "MRK_PROCESS_V1 absent 123\n"
              ticks = [0.0, 0.2]
              fixture.stub(:clock, -> { ticks.shift || raise("synthetic clock exhausted") }) do
                error = assert_raises(Failure) { fixture.dead!(123, 122, deadline: 0.1) }
                assert_equal "fixture-cleanup", error.kind
              end
              assert_equal 1, calls.length
              calls.clear
              fixture.stub(:clock, 0.1) do
                assert_raises(Failure) { fixture.dead!(123, 122, deadline: 0.1) }
              end
              assert_empty calls # An exhausted budget cannot acquire a new observer.
            end
          end
        end
      end
    end

    # All directory handles, enumeration, removal and run acquisition here are
    # inert doubles. Fresh receivers own the model's records/latches; the real
    # retained registries are never replaced, cleared, or used as model state.
    # Only Lifetime's actual first-error/cleanup collector is reused. Its outer
    # entrypoint and interrupt-mask primitive are replaced before any effects.
    def with_inert_contract_fixture
      real = UploadProcessFixture
      entries = lambda do |value|
        if value.instance_of?(Hash)
          value.map { |key, item| [key.object_id, item.object_id] }.sort
        elsif value.instance_of?(Array)
          value.map(&:object_id)
        end
      end
      before = real.instance_variables.to_h do |name|
        value = real.instance_variable_get(name)
        [name, [value, entries.call(value)]]
      end
      model = Object.new.extend(real)
      model.singleton_class.send(:public, *real.private_instance_methods(false))
      model.define_singleton_method(:lifetime) { |**| raise "unmocked fixture lifetime acquisition" }
      yield model
    ensure
      if before
        assert_equal before.keys.sort, real.instance_variables.sort, "real fixture registry/latch inventory changed"
        before.each do |name, (original, members)|
          current = real.instance_variable_get(name)
          assert original.equal?(current), "real fixture #{name} was replaced"
          assert_equal members, entries.call(current), "real fixture #{name} entries changed" if members
        end
      end
    end

    def with_contract_stubs(bindings, index = 0, &body)
      return body.call if index == bindings.length

      target, name, replacement = bindings.fetch(index)
      target.stub(name, replacement) { with_contract_stubs(bindings, index + 1, &body) }
    end

    def assert_process_observer_cleanup
      root, driver = "/synthetic-proof-root", "/synthetic-proof-root/native-process-fixed"
      with_inert_contract_fixture do |fixture|
        removed, visited = [], []
        listings = {root => [], driver => []}
        reader = lambda do |path|
          visited << path
          value = listings.fetch(path)
          raise value if value.is_a?(Exception)
          value
        end
        bindings = [
          [FileUtils, :remove_entry, ->(path) { removed << path }],
          [fixture, :fixture_entry_names, reader],
          # RawCaptureCleanup names the real module explicitly. Forward only
          # these calls to the isolated receiver, not to real retained state.
          [UploadProcessFixture, :assert_fixture_cleanup!, ->(path, **options) { fixture.assert_fixture_cleanup!(path, **options) }],
          [UploadProcessFixture, :cleanup_unresolved?, ->(path) { fixture.cleanup_unresolved?(path) }],
        ]
        with_contract_stubs(bindings) do
          listings[driver] = ["mrk-process-observation-retained"]
          assert_raises(Failure) { fixture.remove_fixture_directory(driver, root: root, layout: :driver) }
          assert_empty removed
          assert fixture.cleanup_unresolved?(root)
          listing_error = IOError.new("synthetic listing failure")
          listings[driver] = listing_error
          assert_same listing_error, assert_raises(IOError) { fixture.remove_fixture_directory(driver, root: root, layout: :driver) }
          assert_empty removed
          listings[root] = ["mrk-process-observation-owned-here", "native-process-fixed"]
          listings[driver] = ["mrk-process-observation-owned-by-driver"]
          visited.clear
          assert_raises(Failure) { fixture.remove_fixture_directory(root, root: root, layout: :joined_case) }
          assert_equal [root, driver], visited
          assert_empty removed
          listings[driver] = ["owner.json"]
          fixture.remove_fixture_directory(root, root: root, layout: :joined_case)
          assert_equal [root], removed # Direct scratch is covered only by the caller's original reservations.
          removed.clear
          %w[ownership-capture- ownership-run- setup-capture- setup-run- setup-ownership- observation-native-].each do |prefix|
            listings[root] = [prefix + "retained"]
            visited.clear
            assert_raises(Failure) { fixture.remove_fixture_directory(root, root: root, layout: :probe) }
            assert_equal [root], visited # Never recursively inspect a retained proof case.
          end
          assert_empty removed
          listings[root] = ["input.json", "setup-progress.json"]
          fixture.remove_fixture_directory(root, root: root, layout: :probe)
          assert_equal [root], removed
          removed.clear

          collector = Object.new.extend(RawCaptureCleanup)
          collector.instance_variable_set(:@root, root)
          listings[driver] = ["mrk-process-observation-retained"]
          assert_raises(Failure) { collector.check_raw_capture_scratch!(driver) }
          assert collector.instance_variable_get(:@retain_raw_evidence)
          assert_raises(Failure) { collector.finish_raw_proof_copies! }
          listings[driver] = []
          collector.check_raw_capture_scratch!(driver)
          assert_raises(Failure) { collector.finish_raw_proof_copies! }
          assert collector.instance_variable_get(:@retain_raw_evidence)
          assert fixture.cleanup_unresolved?(root) # A later empty listing never clears this original model latch.
          assert_empty removed
          clean = Object.new.extend(RawCaptureCleanup)
          clean_driver = "/synthetic-independent-clean-root/native-process-clean"
          listings[clean_driver] = []
          clean.instance_variable_set(:@root, File.dirname(clean_driver))
          clean.check_raw_capture_scratch!(clean_driver)
          clean.finish_raw_proof_copies!
          refute clean.instance_variable_get(:@retain_raw_evidence)
          assert collector.instance_variable_get(:@retain_raw_evidence)
        end
      end
      assert_run_cleanup_veto_with_doubles(root, driver)
      assert_bounded_fixture_enumeration
      assert_driver_temp_precondition
    end

    def assert_run_cleanup_veto_with_doubles(root, directory)
      scope_type = Struct.new(:cleanup_depth) do
        def cleanup
          self.cleanup_depth += 1
          yield
        ensure
          self.cleanup_depth -= 1
        end
      end
      io_type = Struct.new(:bytes, :closes) do
        def write(value) = (bytes << value; value.bytesize)
        def close = (self.closes += 1; nil)
      end
      lease_type = Struct.new(:io, :state, :acquisitions, :closes) do
        def acquire
          raise "model lease acquisition repeated" unless state == :unattempted
          self.acquisitions += 1
          self.io = yield
          self.state = :open
          io
        end
        def close_once
          self.closes += 1
          return true if %i[unattempted closed].include?(state)
          raise "model lease close not open" unless state == :open
          io.close
          self.state = :closed
          true
        end
      end
      vectors = [false, true].product(%i[none cleanup io_primary system_exit_primary]).map { |residue, fault| [residue, fault, nil, false, false] }
      vectors += [[false, :none, 3_000_000_000, false, false], [false, :none, nil, true, false],
                  [false, :none, 3_000_000_000, false, true]]
      vectors.each do |residue, fault, outer_span, late_handoff, nil_polls|
        with_inert_contract_fixture do |fixture|
          initial = now = 10_000_000_000
          outer = outer_span && initial + outer_span
          run_ns = [initial + DRIVER_LIMIT * 1_000_000_000, outer].compact.min
          hard_ns = [run_ns + CLEANUP_LIMIT * 1_000_000_000, outer].compact.min
          primary = fault == :io_primary ? IOError.new("synthetic original active failure") :
                    fault == :system_exit_primary ? SystemExit.new(23, "synthetic original active exit") : nil
          secondary = fault == :none ? nil : IOError.new("synthetic independent stop failure")
          removed, visited, starts, constructions, records, observations, events, masks = Array.new(8) { [] }
          observer_calls, signal_calls, settles = [], [], []
          ios = Array.new(2) { io_type.new(+"", 0) }
          leases = Array.new(2) { lease_type.new(nil, :unattempted, 0, 0) }
          pending_leases = leases.dup
          phase, status, settled, stops, polls, sleeps = :unstarted, nil, false, 0, 0, 0
          original_status = Struct.new(:exitstatus) { def exited? = true }.new(1)
          receipt = Struct.new(:raw_status).new(original_status)
          original_child = Struct.new(:receipt).new(nil_polls ? nil : receipt)
          stream_reads, eofs = {out: 0, err: 0}, {out: false, err: false}
          child = OwnedChild.allocate # No real constructor/creator/resource acquisition.
          child.define_singleton_method(:start) do |environment, *argv, **options|
            starts << [environment, argv, options]
            phase = @phase = :reserved
          end
          child.define_singleton_method(:pid) { 123 }
          child.define_singleton_method(:phase) { phase }
          child.define_singleton_method(:status) { status }
          child.define_singleton_method(:child) { original_child }
          child.define_singleton_method(:read_stream) do |role|
            next nil if eofs.fetch(role)
            stream_reads[role] += 1
            next role.to_s if stream_reads[role] == 1
            eofs[role] = true
            events << [:eof, role]
            nil
          end
          child.define_singleton_method(:streams_complete?) { eofs.values.all? }
          child.define_singleton_method(:retire_numeric!) do
            raise "model retired before both EOFs" unless phase == :reserved && eofs.values.all?
            events << :retire
            @numeric_retired = true
            phase = @phase = :waiting
          end
          child.define_singleton_method(:poll_wait) do
            raise "model waited before retirement" unless phase == :waiting
            polls += 1
            if nil_polls
              events << [:nil_poll, polls]
              next nil
            end
            events << :wait
            phase, status = :reaped, original_status
            @phase = :reaped
            status
          end
          actual_stop = OwnedChild.instance_method(:stop)
          child.define_singleton_method(:stop) do
            stops += 1
            events << [:stop, stops]
            next actual_stop.bind(self).call if nil_polls
            raise "model stop before original wait" unless phase == :reaped
            settled = true
            raise secondary if stops == 2 && secondary
            true
          end
          child.define_singleton_method(:complete?) { phase == :reaped && settled }
          child.define_singleton_method(:provenance) { {"grant" => {"state" => "closed", "bytesWritten" => 1}} }
          child.define_singleton_method(:signal) { |*arguments, **options| signal_calls << [arguments, options]; raise "model reopened a retired numeric route" }
          if nil_polls
            # Exercise the ORIGINAL OwnedChild#stop control flow on this inert
            # allocated receiver. Only resource/creator effects are replaced;
            # real cleanup_cutoff_ns/remember_error and the waiting-state gate
            # must reject at the same original hard cutoff, never signal KILL.
            acquisition = Object.new
            acquisition.define_singleton_method(:close_launch!) { true }
            {phase: :unstarted, hard_deadline_ns: hard_ns, run_deadline_ns: run_ns,
             acquisition: acquisition, grant_writer: lease_type.new(nil, :unattempted, 0, 0),
             go_state: "granted", cleanup_errors: []}.each { |name, value| child.instance_variable_set(:"@#{name}", value) }
            child.define_singleton_method(:settle_creator) { |cutoff| settles << cutoff; @creation_finished = true }
            child.define_singleton_method(:close_child_endpoints) { true }
            child.define_singleton_method(:close_resources) { @resource_close_attempted = @resources_closed = true }
            child.define_singleton_method(:fail_unknown!) do |_error|
              phase = @phase = :unknown
              @numeric_retired = true
              fixture.retain_unknown_domain!(root)
            end
          end
          none = {"state" => "not_attempted"}.freeze
          owner = {"version" => 2, "phase" => "no-native-child", "finality" => "no_producers",
                   "custodian" => none, "keeper" => none, "validator" => none, "group" => {"state" => "not_created"}, "processes" => []}
          result = {"kind" => "setup-fixture-fault", "nativeObservation" => {"version" => 1, "noProducers" => true,
                    "settled" => true, "unknown" => false, "hooksRestored" => true, "observerErrors" => [], "custodian" => none}}
          result.define_singleton_method(:merge) { |*| raise primary } if primary
          frame = Lifetime.new(scope_type.new(0), deadline_ns: -> { hard_ns })
          lifetime = lambda do |deadline_ns:, &body|
            assert_equal hard_ns, deadline_ns
            value = nil
            begin
              value = body.call(frame)
            rescue Exception => error
              frame.remember(error)
            end
            now = run_ns if late_handoff # All cleanup finished, still not a renewed acceptance window.
            raise frame.primary if frame.primary
            value
          end
          source = UploadProcessFixture.method(:run).source_location.fetch(0)
          ruby, helper, cwd, digest = "/synthetic-ruby", "/synthetic-fixture.rb", "/synthetic-cwd", "a" * 64
          environment = fixture.process_observer_environment.merge("TMPDIR" => directory, "TMP" => directory, "TEMP" => directory)
          dispatch = {"version" => 1, "argv" => [ruby, helper, "driver", directory], "environment" => environment,
                      "cwd" => cwd, "fixtureSha256" => digest, "deadlineNs" => run_ns, "pid" => 123}
          metadata = Struct.new(:dev, :ino, :mode, :uid, :gid, :rdev, :ftype, :nlink) { def directory? = true }.
            new(1, 2, 0o40700, Process.uid, Process.gid, 0, "directory", 2)
          observe_death = fixture.method(:observe_owner_death!)
          forbidden = ->(*, **) { raise "inert run reached an unmocked acquisition" }
          bindings = [
            [OwnedChild, :new, ->(**options) { constructions << options; child }],
            [OwnedChild::ControlLease, :new, -> { pending_leases.shift || raise("unexpected model control lease") }],
            [OwnedChild, :native_modules, forbidden], [Thread, :new, forbidden], [Signal, :trap, forbidden],
            [Process, :spawn, forbidden], [Process, :fork, forbidden], [Process, :kill, forbidden],
            [Thread, :handle_interrupt, ->(policy, &body) { masks << policy; body.call }],
            [Dir, :mktmpdir, ->(prefix, parent) { assert_equal ["native-process-", root], [prefix, parent]; directory }],
            [Dir, :pwd, cwd],
            [File, :realpath, ->(path) { path == RbConfig.ruby ? ruby : path == source ? helper : path }],
            [File, :lstat, ->(path) { assert_equal directory, path; metadata }],
            [File, :open, lambda { |path, flags, mode|
              index = %w[driver.stdout driver.stderr].index(File.basename(path))
              assert index, "unexpected model transcript path"
              assert_equal File.join(directory, %w[driver.stdout driver.stderr].fetch(index)), path
              assert_equal File::WRONLY | File::CREAT | File::EXCL | File::NOFOLLOW, flags
              assert_equal 0o600, mode
              metadata.nlink += 1 # Model an entry-counting filesystem, not a native observation.
              ios.fetch(index)
            }],
            [File, :file?, ->(path) { %w[driver-dispatch.json owner.json result.json].map { |name| File.join(directory, name) }.include?(path) }],
            [File, :exist?, forbidden], [File, :write, forbidden], [File, :rename, forbidden],
            [Digest::SHA256, :file, ->(path) { assert_equal source, path; Struct.new(:hexdigest).new(digest) }],
            [OwnedChild, :bounded_file, ->(path) { assert_equal File.join(directory, "driver-dispatch.json"), path; JSON.generate(dispatch) }],
            [FileUtils, :remove_entry, ->(path) { removed << path }],
            [fixture, :fixture_entry_names, ->(path) { visited << path; assert_equal directory, path; residue ? ["mrk-process-observation-retained"] : [] }],
            [fixture, :lifetime, lifetime], [fixture, :clock_ns, -> { now }], [UploadProcessFixture, :clock_ns, -> { now }],
            [fixture, :clock, -> { Rational(now, 1_000_000_000) }],
            [fixture, :sleep, lambda { |seconds|
              assert_operator seconds, :>, 0
              assert_operator seconds, :<=, 0.01
              sleeps += 1
              now = nil_polls && sleeps == 3 ? run_ns : now + 1_000_000
            }],
            [fixture, :atomic_json, ->(path, value) { metadata.nlink += 1; records << [path, value] }],
            [fixture, :read_json, ->(path) { {File.join(directory, "owner.json") => owner, File.join(directory, "result.json") => result}.fetch(path) }],
            [fixture, :state, ->(*arguments, **options) { observer_calls << [arguments, options]; raise "run acquired a fresh process observer" }],
            [fixture, :observe_owner_death!, lambda { |value, deadline:, root:|
              observations << [value, deadline, root]
              observe_death.call(value, deadline: deadline, root: root) # Empty real-validated model graph; no observer acquisition.
            }],
            [fixture, :warn, nil],
          ]
          returned = observed_error = nil
          with_contract_stubs(bindings) do
            begin
              returned = fixture.run(platform: "native", root: root, parameters: {}, mode: "native-setup-second-pipe", deadline_ns: outer)
            rescue Exception => error
              observed_error = error
            end
          end
          assert_equal [{root: directory, deadline_ns: run_ns, hard_deadline_ns: hard_ns}], constructions
          assert_equal [[environment, dispatch.fetch("argv"), {in: File::NULL, out: :pipe, err: :pipe, unsetenv_others: true, pgroup: true}]], starts
          assert_equal [[File.join(directory, "input.json"), {"platform" => "native", "parameters" => {}, "mode" => "native-setup-second-pipe", "deadlineNs" => run_ns}]], records
          assert_equal 5, metadata.nlink # Original snapshot was 2; real run cleanup must not compare that old count.
          assert_empty pending_leases
          assert_equal %w[out err], ios.map(&:bytes)
          assert_equal [1, 1], ios.map(&:closes)
          assert_equal [1, 1], leases.map(&:acquisitions)
          assert_equal(nil_polls ? [1, 1] : [2, 2], leases.map(&:closes)) # Independent ensure closes survive the stop failure.
          assert_equal [:closed, :closed], leases.map(&:state)
          assert_empty observer_calls
          assert_empty signal_calls
          if nil_polls
            assert_equal [[:eof, :out], [:eof, :err], :retire, [:nil_poll, 1], [:nil_poll, 2], [:stop, 1]], events
            assert_equal 2, polls
            assert_equal run_ns, now
            assert_equal [hard_ns], settles
            assert_equal hard_ns, child.instance_variable_get(:@cleanup_deadline_ns)
            assert child.instance_variable_get(:@numeric_retired)
            assert_equal :unknown, child.phase
            assert_nil child.status
            assert_nil child.child.receipt
            errors = frame.instance_variable_get(:@cleanup_errors)
            assert_equal 1, errors.length
            assert_equal "process-ownership", errors.first.kind
            assert_match(/child cleanup deadline expired/, errors.first.message)
            assert_same errors.first, child.instance_variable_get(:@primary)
            assert_same observed_error, frame.primary
            assert_equal "driver", observed_error.kind
            assert_match(/driver deadline expired/, observed_error.message)
            assert_nil returned
            assert_empty observations
            assert_empty visited # UNKNOWN never traverses or removes the directory.
            assert_empty removed
            assert fixture.cleanup_unresolved?(root)
            assert fixture.domain_disposal_required?
            assert_same child, fixture.instance_variable_get(:@driver_records).values.fetch(0).fetch("child")
            assert_raises(Failure) { fixture.assert_domain_reusable! }
            next
          end
          assert_equal [[:eof, :out], [:eof, :err], :retire, :wait, [:stop, 1], [:stop, 2]], events
          assert_same original_status, child.status
          assert_same original_status, child.child.receipt.raw_status
          assert_equal [[owner, Rational([initial + 1_000_000 + CLEANUP_LIMIT * 1_000_000_000, hard_ns].min, 1_000_000_000), root]], observations
          assert_equal [directory], visited
          errors = frame.instance_variable_get(:@cleanup_errors)
          assert_equal (secondary ? 1 : 0) + (residue ? 1 : 0), errors.length
          assert_same secondary, errors.first if secondary
          if primary || secondary
            assert_same(primary || secondary, observed_error)
            assert_same(primary || secondary, frame.primary)
            assert_equal 23, observed_error.status if fault == :system_exit_primary
          elsif residue
            assert_same errors.first, observed_error
          elsif late_handoff
            assert_instance_of Failure, observed_error
            assert_equal "driver", observed_error.kind
            assert_match(/result arrived after original deadline/, observed_error.message)
            assert_nil frame.primary
            assert_operator now, :<, hard_ns
          else
            assert_nil observed_error
            assert_equal dispatch, returned.fetch("driverDispatch")
            assert returned.fetch("driverJoined")
            assert returned.fetch("knownProcessesDead")
            refute returned.fetch("retainedFixture")
            refute returned.fetch("domainDisposalRequired")
          end
          if residue
            assert_empty removed
            assert fixture.cleanup_unresolved?(root)
            assert_equal "fixture-cleanup", errors.last.kind
            assert_equal 1, fixture.instance_variable_get(:@driver_records).length
          else
            assert_equal [directory], removed
            refute fixture.cleanup_unresolved?(root)
            assert_empty fixture.instance_variable_get(:@driver_records)
          end
          assert masks.all? { |policy| policy.keys == [Exception] && %i[never immediate].include?(policy.fetch(Exception)) }
        end
      end
    end

    def assert_bounded_fixture_enumeration
      with_inert_contract_fixture do |fixture|
        path = "/synthetic-enumeration-root"
        type = Struct.new(:dev, :ino, :mode, :uid, :gid, :nlink, :size, :mtime, :ctime, :rdev, :ftype) do
          def directory? = (mode & 0o170000) == 0o40000
        end
        metadata = type.new(1, 2, 0o40700, Process.uid, Process.gid, 2, 64, 1, 1, 0, "directory")
        pin = Struct.new(:stat).new(metadata)
        borrowed = Struct.new(:stat).new(metadata)
        names, reads, closed = [], 0, []
        listing_error = close_error = mutate = nil
        entries = Object.new
        entries.define_singleton_method(:fileno) { 987_654 } # Never a real FD; IO.for_fd is fully replaced below.
        entries.define_singleton_method(:each_child) do |&block|
          raise listing_error if listing_error
          names.each do |name|
            reads += 1
            block.call(name)
          end
          metadata[mutate] += 1 if mutate
        end
        file_open = lambda do |name, flags, &block|
          assert_equal path, name
          assert_equal File::RDONLY | File::NOFOLLOW | File::NONBLOCK, flags
          begin
            block.call(pin)
          ensure
            closed << :pin
            raise IOError, "synthetic pin close failure" if close_error == :pin
          end
        end
        dir_open = lambda do |name, encoding:, &block|
          assert_equal path, name
          assert_equal Encoding::BINARY, encoding
          begin
            block.call(entries)
          ensure
            closed << :directory
            raise IOError, "synthetic enumerator close failure" if close_error == :directory
          end
        end
        resolved = path
        File.stub(:realpath, ->(_path) { resolved }) do
          File.stub(:lstat, ->(*) { metadata }) do
            File.stub(:open, file_open) do
              Dir.stub(:open, dir_open) do
                IO.stub(:for_fd, lambda { |fd, autoclose:| assert_equal 987_654, fd; assert_equal false, autoclose; borrowed }) do
                  lifetime = {"dev" => 1, "ino" => 2, "mode" => 0o40700, "uid" => Process.uid,
                              "gid" => Process.gid, "rdev" => 0, "type" => "directory"}
                  [2, 4, 1, 2].each do |links|
                    metadata.nlink = links # Authorized entry creation/removal may change this positive count.
                    assert_equal lifetime, OwnedChild.directory_identity(path)
                  end
                  %i[dev ino gid rdev].each do |field|
                    metadata[field] += 1
                    refute_equal lifetime, OwnedChild.directory_identity(path)
                    metadata[field] -= 1
                  end
                  [[:uid, Process.uid + 1], [:mode, 0o40777], [:mode, 0o120700],
                   [:nlink, 0], [:nlink, -1], [:nlink, 1.0], [:nlink, "1"], [:nlink, nil], [:nlink, true]].each do |field, invalid|
                    original = metadata[field]
                    metadata[field] = invalid
                    assert_raises(Failure) { OwnedChild.directory_identity(path) }
                    metadata[field] = original
                  end
                  resolved = path + "-alias"
                  assert_raises(Failure) { OwnedChild.directory_identity(path) }
                  resolved = path
                  assert_raises(Failure) { OwnedChild.directory_identity("relative-case") }
                  assert_empty closed # Lifetime metadata validation acquires no new directory handles.
                  names = ["a" * 255]
                  assert_equal names, fixture.fixture_entry_names(path)
                  assert_equal [:directory, :pin], closed
                  names = Array.new(258) { |index| "entry-#{index}" }
                  reads = 0
                  assert_raises(Failure) { fixture.fixture_entry_names(path) }
                  assert_equal 257, reads # Bounded DURING enumeration, not after Dir.children allocation.
                  [["a" * 256], ["same", "same"], [".."], ["a/b"], ["a\0b"], ["a\nb"]].each do |bad|
                    names, closed = bad, []
                    assert_raises(Failure) { fixture.fixture_entry_names(path) }
                    assert_equal [:directory, :pin], closed
                  end
                  names, closed, listing_error = [], [], IOError.new("synthetic listing failure")
                  assert_raises(Failure) { fixture.fixture_entry_names(path) }
                  assert_equal [:directory, :pin], closed
                  listing_error = nil
                  %i[pin directory].each do |fault|
                    closed, close_error = [], fault
                    assert_raises(Failure) { fixture.fixture_entry_names(path) }
                    assert_equal [:directory, :pin], closed
                  end
                  close_error = nil
                  borrowed.stat = metadata.dup
                  borrowed.stat.ino += 1
                  names, reads, closed = ["must-not-be-read"], 0, []
                  assert_raises(Failure) { fixture.fixture_entry_names(path) }
                  assert_equal 0, reads
                  assert_equal [:directory, :pin], closed
                  borrowed.stat = metadata
                  pin.stat = metadata.dup
                  pin.stat.ino += 1
                  reads, closed = 0, []
                  assert_raises(Failure) { fixture.fixture_entry_names(path) }
                  assert_equal 0, reads
                  assert_equal [:pin], closed
                  pin.stat = metadata
                  %i[ctime nlink].each do |field|
                    mutate, closed = field, []
                    assert_raises(Failure) { fixture.fixture_entry_names(path) }
                    assert_equal [:directory, :pin], closed
                  end
                  mutate = nil
                  [0o120700, 0o40777].each do |bad_mode|
                    metadata.mode, closed = bad_mode, []
                    assert_raises(Failure) { fixture.fixture_entry_names(path) }
                    assert_empty closed # Rejected before acquiring either descriptor.
                  end
                end
              end
            end
          end
        end
      end
    end

    def assert_driver_temp_precondition
      with_inert_contract_fixture do |fixture|
        directory, mode = "/synthetic-driver-root", "native-setup-second-pipe"
        now = 7_000_000_000
        cutoff = now + DRIVER_LIMIT * 1_000_000_000
        base = {"platform" => "native", "parameters" => {}, "mode" => mode, "deadlineNs" => cutoff}
        input, temporary = base.dup, directory
        reads, acquired, missing_acquired, writes, metadata_reads = 0, [], [], [], []
        native = Object.new
        native.define_singleton_method(:execute) { :synthetic_driver_only }
        metadata = Struct.new(:uid, :mode, :kind, :nlink) { def directory? = kind == :directory }.
          new(Process.uid, 0o40700, :directory, 1)
        source = UploadProcessFixture.method(:driver).source_location.fetch(0)
        ruby, helper, cwd, digest = "/synthetic-ruby", "/synthetic-fixture.rb", "/synthetic-cwd", "b" * 64
        environment = {"TMPDIR" => directory, "TMP" => directory, "TEMP" => directory}
        forbidden = ->(*, **) { raise "inert driver reached an unexpected acquisition/dispatch" }
        bindings = [
          [fixture, :read_json, ->(path) { assert_equal File.join(directory, "input.json"), path; input }],
          [fixture, :clock_ns, now], [Dir, :tmpdir, -> { reads += 1; temporary }], [Dir, :pwd, cwd],
          [File, :realpath, ->(path) { path == RbConfig.ruby ? ruby : path == source ? helper : path }],
          [File, :lstat, ->(path) { metadata_reads << path; assert_equal directory, path; metadata }],
          [File, :open, forbidden], [File, :write, forbidden], [File, :rename, forbidden],
          [Digest::SHA256, :file, ->(path) { assert_equal source, path; Struct.new(:hexdigest).new(digest) }],
          [ENV, :to_h, environment], [Process, :pid, 123],
          [OwnedChild, :write_record, ->(path, value) { writes << [path, value] }],
          [OwnedChild, :new, forbidden], [OwnedChild, :native_modules, forbidden],
          [Thread, :new, forbidden], [Signal, :trap, forbidden],
          [Process, :spawn, forbidden], [Process, :fork, forbidden], [Process, :kill, forbidden],
          [NativeSignalProbe, :execute_driver, forbidden], [NativePrimaryProbe, :new, forbidden],
          [NativeOrderProbe, :new, forbidden], [HardLossNativeDriver, :new, forbidden],
          [HardLossAdapterDriver, :new, forbidden], [AdapterDriver, :new, forbidden],
          [MissingCleanupDriver, :new, ->(*arguments, **keywords) { missing_acquired << [arguments, keywords]; native }],
          [NativeSetupDriver, :new, ->(*arguments, **keywords) { assert_empty keywords; acquired << arguments; native }],
        ]
        with_contract_stubs(bindings) do
          invalid = [base.merge("mode" => "invalid-case"), base.merge("observeSignals" => true),
                     base.merge("extra" => true), base.reject { |key, _| key == "deadlineNs" },
                     base.merge("platform" => "ios", "mode" => "ownership-async")]
          [nil, false, cutoff.to_f, cutoff.to_s, now, now - 1, cutoff + 1].each { |value| invalid << base.merge("deadlineNs" => value) }
          invalid.each do |value|
            input = value
            error = assert_raises(Failure) { fixture.driver(directory) }
            assert_equal "fixture-input", error.kind
          end
          assert_equal 0, reads # Schema/mode/signal/original cutoff admission all precede temp lookup.
          assert_empty metadata_reads
          assert_empty acquired
          assert_empty missing_acquired
          assert_empty writes
          input, temporary = base.dup, "/synthetic-wrong-root"
          error = assert_raises(Failure) { fixture.driver(directory) }
          assert_equal "fixture-input", error.kind
          assert_equal 1, reads
          assert_empty metadata_reads
          assert_empty acquired
          assert_empty writes
          temporary, metadata.mode = directory, 0o40777
          assert_raises(Failure) { fixture.driver(directory) }
          metadata.mode, metadata.kind = 0o40700, :symlink
          assert_raises(Failure) { fixture.driver(directory) }
          assert_empty acquired
          assert_empty writes # Temp equality does not bypass the original private-directory metadata check.
          metadata.kind = :directory
          assert_equal :synthetic_driver_only, fixture.driver(directory)
          assert_equal [[directory, mode]], acquired
          assert_equal 4, reads
          assert_equal [directory, directory, directory], metadata_reads
          assert_equal [[File.join(directory, "driver-dispatch.json"), {"version" => 1, "pid" => 123,
            "argv" => [ruby, helper, "driver", directory], "environment" => environment, "cwd" => cwd,
            "fixtureSha256" => digest, "deadlineNs" => cutoff}]], writes
          assert_empty missing_acquired
          input = base.merge("mode" => ContainmentEvidence::MISSING)
          assert_equal :synthetic_driver_only, fixture.driver(directory)
          assert_equal [[[directory, ContainmentEvidence::MISSING], {deadline_ns: cutoff}]], missing_acquired
          assert_equal [[directory, mode]], acquired # Ordinary constructor never receives the missing-only keyword.
          assert_equal 5, reads
          assert_equal [directory, directory, directory, directory], metadata_reads
          assert_equal [writes.first, writes.first], writes # Dispatch and missing constructor share the exact original D.
        end
      end
    end

    def test_process_observation_rejects_errors_malformed_output_and_foreign_groups
      assert_process_observer_protocol
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
      observation = UploadProcessFixture::CommandObservation.new
      error = assert_raises(UploadProcessFixture::Failure) do
        observation.observe do
          # Exercise the silent observation cutoff, not a 50ms bootstrap race.
          # This is still ONE original startup-inclusive deadline, never renewed.
          UploadProcessFixture.capture_command([RbConfig.ruby, "-e", "sleep 30"], seconds: DEADLINE, root: @root)
        end
      end
      assert_equal "process-observation", error.kind
      assert_equal "process observation deadline expired", error.message
      snapshot = observation.snapshot
      assert snapshot.fetch("settled"), snapshot.inspect
      refute snapshot.fetch("unknown"), snapshot.inspect
      %w[nativeAttemptsBound actualOwnedControlCloses actualTaskJoins hooksRestored].each { |key| assert snapshot.fetch(key), snapshot.inspect }
      assert_empty snapshot.fetch("observerErrors")
      assert_equal 1, snapshot.fetch("children").length
      child = snapshot.fetch("children").first
      assert child.fetch("actualNativeCloses"), child.inspect
      refute child.fetch("noNativeAttemptConfirmed"), child.inspect
      assert_equal "finalized", child.fetch("finality")
      %w[originalWaitObserved creatorJoinObserved actualStreamEOFs].each { |key| assert child.fetch(key), child.inspect }
      provenance = child.fetch("provenance")
      requested = provenance.fetch("requested")
      assert_equal({"executable" => RbConfig.ruby, "argv" => [RbConfig.ruby, "-e", "sleep 30"],
        "environment" => UploadProcessFixture.process_observer_environment, "cwd" => File.realpath(Dir.pwd)}, requested)
      assert_equal({"state" => "granted", "bytesWritten" => 3}, provenance.fetch("grant"))
      # This original record proves attempted exec, not successful target code.
      # It supplements, never replaces, the actual wait/join/EOF/close witnesses.
      assert_equal({"version" => 1, "pid" => child.fetch("pid"),
        "configurationSha256" => provenance.fetch("configuration").fetch("sha256"),
        "argvSha256" => Digest::SHA256.hexdigest(JSON.generate(requested.fetch("argv"))),
        "cwd" => requested.fetch("cwd")}, provenance.fetch("execAttempt"))
      refute UploadProcessFixture.cleanup_unresolved?(@root)
      refute UploadProcessFixture.domain_disposal_required?
    end

    def assert_ownership_row(entry, unknown: false)
      assert_empty entry.fetch("failures"), entry.inspect
      assert_empty entry.fetch("unsafeSignalRequests"), entry.inspect
      assert_empty entry.fetch("unsafeWaitRequests"), entry.inspect
      %w[firstExceptionPreserved raisersJoined handlersRestored registryInactive hooksRestored].each do |key|
        assert entry.fetch(key), entry.inspect
      end
      refute entry.fetch("pendingInterrupt"), entry.inspect
      assert_equal !unknown, entry.fetch("allKnownCommandChildrenFinalized"), entry.inspect
      assert_equal unknown, entry.fetch("unknownPublication"), entry.inspect
      assert_equal unknown, entry.fetch("retainedFixture"), entry.inspect
      assert_equal unknown, entry.fetch("domainDisposalRequired"), entry.inspect
      assert_equal unknown ? "unknown" : "finalized", entry.fetch("nativeFinality")
      refute entry.key?("allAcquiredChildrenJoined"), entry.inspect
      assert_match(/\A[0-9a-f]{64}\z/, entry.fetch("proofSha256"))
    end

    %w[async signals policies].each do |family|
      define_method("test_process_ownership_#{family}_through_both_real_fixture_callers") do
        value = assert_complete_process_case("ownership-#{family}")
        assert_equal family, value.fetch("family")
        expected = %w[capture run].product(UploadProcessFixture::OwnershipProbe::CASES.fetch(family))
        assert_equal expected, value.fetch("cases").map { |entry| entry.values_at("helper", "case") }
        value.fetch("cases").each { |entry| assert_ownership_row(entry) }
      end
    end

    def assert_unknown_ownership_case(mode, helper, name)
      assert_equal [helper, name], UploadProcessFixture::OWNERSHIP_UNKNOWN_MODES.fetch(mode)
      value = assert_retained_process_case(mode)
      assert_equal "pass", value.fetch("kind")
      assert_equal "unknown", value.fetch("family")
      assert_equal [[helper, name]], value.fetch("cases").map { |entry| entry.values_at("helper", "case") }
      assert_ownership_row(value.fetch("cases").first, unknown: true)
    end

    def test_process_ownership_unknown_creation_through_real_capture
      assert_unknown_ownership_case("ownership-unknown-capture-spawn", "capture", "unknown-spawn")
    end

    def test_process_ownership_unknown_wait_through_real_capture
      assert_unknown_ownership_case("ownership-unknown-capture-reap", "capture", "unknown-reap")
    end

    def test_process_ownership_echild_after_original_wait_through_real_capture
      assert_unknown_ownership_case("ownership-unknown-capture-echild", "capture", "unknown-echild")
    end

    def test_process_ownership_unknown_creation_through_real_run
      assert_unknown_ownership_case("ownership-unknown-run-spawn", "run", "unknown-spawn")
    end

    def test_process_ownership_unknown_wait_through_real_run
      assert_unknown_ownership_case("ownership-unknown-run-reap", "run", "unknown-reap")
    end

    def test_process_ownership_echild_after_original_wait_through_real_run
      assert_unknown_ownership_case("ownership-unknown-run-echild", "run", "unknown-echild")
    end

    def test_setup_primary_survives_cleanup_failure_and_real_queued_cancellation
      value = assert_complete_process_case("ownership-setup")
      assert value.fetch("hooksRestored"), value.inspect
      expected = %w[capture run ownership].product(%w[IOError Interrupt], [false, true])
      assert_equal expected, value.fetch("cases").map { |entry| entry.values_at("helper", "setupClass", "repeatedCancellation") }
      value.fetch("cases").each do |entry|
        assert_empty entry.fetch("failures"), entry.inspect
        assert entry.fetch("setupHit"), entry.inspect
        assert entry.fetch("cleanupHit"), entry.inspect
        assert entry.fetch("cleanupFaultRaised"), entry.inspect
        assert_operator entry.fetch("cleanupDepth"), :>, 0
        assert entry.fetch("cleanupErrorReported"), entry.inspect
        assert entry.fetch("originalObjectAndMessagePreserved"), entry.inspect
        assert_equal 0, entry.fetch("spawnAttempts"), entry.inspect
        assert entry.fetch("noNativeCreateEntered"), entry.inspect
        assert entry.fetch("actualOwnedCloses"), entry.inspect
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
      value = assert_retained_process_case("ownership-observation")
      assert value.fetch("hooksRestored"), value.inspect
      entries = value.fetch("cases")
      assert_equal %w[readiness sequence transient-native persistent-native], entries.map { |entry| entry.fetch("case") }
      entries.each do |entry|
        assert_empty entry.fetch("failures"), entry.inspect
        assert entry.fetch("withinOriginalBudget"), entry.inspect
        assert_match(/\A[0-9a-f]{64}\z/, entry.fetch("observationTraceSha256"))
      end
      assert_equal [false] * 7 + [true, "readiness", "readiness"], entries[0].fetch("readinessResults")
      assert_equal 10, entries[0].fetch("observationCount")
      assert_empty entries[0].fetch("deadCalls")
      assert_equal 3, entries[1].fetch("observationCount")
      assert entries[1].fetch("onlyDefiniteStoppedAccepted")
      entries.drop(2).each do |entry|
        %w[independentRealDeathProofBeforeUncertainty originalNativeFinalityBeforeUncertainty originalDriverWaitBeforeUncertainty].each do |key|
          assert entry.fetch(key), entry.inspect
        end
        identities = entry.fetch("knownNativeIdentities")
        assert_equal 4, identities.length
        assert_equal 4, identities.map(&:first).uniq.length
        custodian, keeper, validator, descendant = identities
        assert_equal custodian.first, custodian.last
        assert_equal custodian.first, keeper.last
        assert_equal keeper.first, validator.last
        assert_equal validator.last, descendant.last
        calls = entry.fetch("deadCalls")
        assert_equal 1, calls.map { |call| call.fetch("deadlineNs") }.uniq.length
        cutoff = calls.first.fetch("deadlineNs")
        assert_instance_of Integer, cutoff
        assert_operator cutoff, :<=, value.fetch("probeDispatch").fetch("deadlineNs")
        calls.each do |call|
          assert_includes identities, call.values_at("pid", "group")
          assert_equal "fixture-cleanup", call.fetch("kind")
        end
        assert_equal 0, entry.fetch("newObserversAfterUncertainty")
      end
      transient, persistent = entries.drop(2)
      assert_equal "finalized", transient.fetch("nativeFinality")
      refute transient.fetch("retainedFixture"), transient.inspect
      refute transient.fetch("domainDisposalRequired"), transient.inspect
      assert_nil transient.fetch("originalErrorKind")
      assert_equal transient.fetch("knownNativeIdentities"), transient.fetch("deadCalls").map { |call| call.values_at("pid", "group") }
      assert_equal ["active"] * 4, transient.fetch("deadCalls").map { |call| call.fetch("phase") }
      assert_equal 12, transient.fetch("observationCount")
      assert_equal transient.fetch("knownNativeIdentities"), transient.fetch("tokenCounts").map { |row| row.fetch("identity") }
      transient.fetch("tokenCounts").each { |row| assert_equal({"?E" => 1, "S" => 1, "Z" => 1}, row.fetch("counts")) }
      assert_equal "unknown", persistent.fetch("nativeFinality")
      assert persistent.fetch("retainedFixture"), persistent.inspect
      assert persistent.fetch("domainDisposalRequired"), persistent.inspect
      assert persistent.fetch("originalObservationErrorPreserved"), persistent.inspect
      assert_equal "fixture-cleanup", persistent.fetch("originalErrorKind")
      assert_operator persistent.fetch("observationCount"), :>, 1
      calls = persistent.fetch("deadCalls")
      assert_equal %w[active cleanup], calls.map { |call| call.fetch("phase") }
      assert_equal [persistent.fetch("knownNativeIdentities").first] * 2, calls.map { |call| call.values_at("pid", "group") }
      assert_operator calls.last.fetch("atNs"), :>=, calls.first.fetch("deadlineNs")
      assert_equal [{"identity" => persistent.fetch("knownNativeIdentities").first,
        "counts" => {"?E" => persistent.fetch("observationCount")}}], persistent.fetch("tokenCounts")
    end
  end
end

if $PROGRAM_NAME == __FILE__
  File.umask(0o077)
  command, directory, mode = ARGV
  case command
  when "driver"
    abort "invalid static driver arguments" unless ARGV.length == 2
    exit UploadProcessFixture.driver(directory)
  when "owned-child"
    abort "invalid static bootstrap arguments" unless ARGV.length == 2
    Process.exit!(UploadProcessFixture::OwnedChild.bootstrap(directory))
  when "worker"
    abort "invalid static worker arguments" unless ARGV.length == 3 && UploadProcessFixture::MODES.include?(mode) && !mode.start_with?("ownership-")
    Process.exit!(UploadProcessFixture.worker(directory, mode))
  when "ownership"
    abort "invalid static ownership arguments" unless ARGV.length == 3
    output = JSON.generate(UploadProcessFixture.ownership_driver(directory, mode))
    abort "oversized static ownership result" if output.bytesize > UploadProcessFixture::OUTPUT_LIMIT
    puts output
  else
    abort "unknown static process fixture command"
  end
end
