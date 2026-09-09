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
  def capture_command(argv, seconds: 2, environment: process_observer_environment)
    lifetime do |scope|
      directory = output = errors = nil
      child = OwnedChild.new
      begin
        directory = File.realpath(Dir.mktmpdir("mrk-process-observation-"))
        output = File.open(File.join(directory, "stdout"), "w+", 0o600)
        errors = File.open(File.join(directory, "stderr"), "w+", 0o600)
        scope.active do
          child.start(environment, *argv, out: output, err: errors, in: File::NULL,
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

  def process_observer_environment
    PROCESS_OBSERVER_SELECTION.nil? ? {} : {PROCESS_OBSERVER_KEY => PROCESS_OBSERVER_SELECTION}
  end

  def owned_fixture_directory(directory)
    unless directory.is_a?(String) && directory.bytesize.between?(1, 4096) &&
           directory == File.absolute_path(directory) && File.realpath(directory) == directory
      raise Failure.new("fixture-cleanup", "fixture directory is not canonical")
    end
    value = File.lstat(directory) # A link is not an owned case directory.
    unless value.directory? && value.uid == Process.uid && (value.mode & 0o7777) == 0o700
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
      raise Failure.new("fixture-cleanup", "unresolved observer scratch prevents fixture removal") if names.any? { |name| name.start_with?("mrk-process-observation-") }
    when :joined_case
      # Direct scratch belongs to independently joined SAME-VM reservations.
      # Those reservations do not cover a nested driver's observer children.
      names.grep(/\Anative-process-/).each do |name|
        nested = fixture_entry_names(File.join(directory, name))
        raise Failure.new("fixture-cleanup", "nested observer scratch prevents case removal") if nested.any? { |entry| entry.start_with?("mrk-process-observation-") }
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

  def state(pid, group, seconds: 2)
    observer = process_observer_path
    if observer
      result = capture_command([observer, pid.to_s], seconds: seconds, environment: PROCESS_OBSERVER_LOCALE)
      observer_liveness(parse_process_observer(*result, pid, group))
    else
      result = capture_command(["/bin/ps", "-o", "pid=,pgid=,stat=", "-p", pid.to_s], seconds: seconds,
                               environment: PROCESS_OBSERVER_LOCALE)
      liveness(parse_state(*result, pid, group))
    end
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

  def validate_signal_observation!(platform, mode, enabled)
    unless (enabled.equal?(false) || enabled.equal?(true)) &&
           (!enabled || (platform == "native" && NativeSignalProbe::MODES.include?(mode)))
      raise Failure.new("fixture-input", "invalid native signal observation request")
    end
  end

  def run(platform:, root:, parameters:, mode:, observe_signals: false)
    validate_request!(platform, mode, parameters)
    validate_signal_observation!(platform, mode, observe_signals)
    if observe_signals && !NativeSignalProbe.current
      return NativeSignalProbe.observe_parent(root, mode) do
        run(platform: platform, root: root, parameters: parameters, mode: mode, observe_signals: true)
      end
    end
    if observe_signals && !NativeSignalProbe.current.parent_for?(root, mode)
      raise Failure.new("fixture-input", "native signal observer scope does not match the run")
    end
    return run_ownership_probe(platform: platform, root: root, parameters: parameters, mode: mode) if mode.start_with?("ownership-")
    lifetime do |scope|
      directory = nil
      child = OwnedChild.new
      cleaned = false
      native_deadline = nil
      result = proof = nil
      begin
        directory = File.realpath(Dir.mktmpdir("native-process-", root))
        input = {"platform" => platform, "parameters" => parameters, "mode" => mode}
        input["observeSignals"] = true if observe_signals
        atomic_json(File.join(directory, "input.json"), input)
        File.open(File.join(directory, "driver.stdout"), "w") do |output|
          File.open(File.join(directory, "driver.stderr"), "w") do |errors|
            scope.active do
              child.start(driver_environment(directory), RbConfig.ruby, File.realpath(__FILE__), "driver", directory,
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
                if observe_signals
                  signal_proof = read_json(File.join(directory, "native-signal-proof.json"))
                  unless signal_proof["case"] == mode && signal_proof["kind"] == "native-signal-observation" &&
                         signal_proof["sourceSha256"] == NativeSignalProbe.current.source_hashes &&
                         signal_proof["failures"] == [] && signal_proof["hooksRestored"] == true &&
                         signal_proof["baseDriverReturn"] == 0 && child.status.exited? && child.status.exitstatus == 0
                    raise Failure.new("fixture-result", "failed native signal proof: #{JSON.generate(signal_proof)}")
                  end
                  result = result.merge("nativeSignalProof" => signal_proof, "observedDriverExitStatus" => child.status.exitstatus)
                end
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
            names = %w[owner.json result.json driver.stderr driver.stdout]
            names << "native-signal-proof.json" if observe_signals
            names.each do |name|
              path = File.join(directory, name)
              diagnostics[name] = File.binread(path, OUTPUT_LIMIT).force_encoding("UTF-8").scrub if File.file?(path)
            end
          end
          warn JSON.generate(diagnostics)
        end
        raise
      ensure
        scope.cleanup do
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
        end
        # Independent cleanup collection preserves an earlier stop/primary error
        # if the deletion veto also fails. Even already-cleaned native workers do
        # not prove finality for a separate observer spawned inside the driver.
        scope.cleanup do
          if directory && cleaned && child.complete?
            remove_fixture_directory(directory, root: root, layout: :driver)
          elsif directory
            (@unresolved_roots ||= {})[root] = true
            warn "Fixture ownership/cleanup unresolved; preserve #{directory}"
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

  # Separate opt-in proof, never installed by the ordinary native/adapter suites.
  # The native waiter check is an observation, NOT QA-007 process authority;
  # entered runs still require the admitted disposable hosted environment.
  class NativeSignalProbe
    MODES = %w[native-setup-interrupt native-setup-system-exit native-setup-io-error
               native-setup-post-reap-cancel].freeze
    SOURCES = %w[tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb
                 fastlane/native_upload_validation.rb fastlane/release_support.rb].freeze
    class << self
      attr_accessor :current, :last_parent
    end
    attr_reader :source_hashes, :requests, :failures, :records, :control_forwards, :hooks_restored

    def initialize(role, mode, root: nil, driver: nil)
      raise "invalid fixed signal proof" unless %i[parent driver control].include?(role) && MODES.include?(mode)
      @role, @mode, @root, @driver = role, mode, root, driver
      @requests, @failures, @records, @by_pid = [], [], [], {}
      @start_owner = @signal_owner = nil
      @backend_entries = @callback_entries = @backend_depth = @control_forwards = 0
      @actual_waiter = nil
      @actual_ios = []
      @hooks_restored = false
      base = File.expand_path("../..", __dir__)
      @paths = SOURCES.to_h { |name| [name, File.realpath(File.join(base, name))] }
      @source_hashes = source_snapshot.freeze
      @anchors = {
        "native" => anchor(SOURCES[2], 'Process.kill("KILL", -waiter.pid)'),
        "fixture" => anchor(SOURCES[1], 'Process.kill(signal, group ? -@pid : @pid)'),
        "self" => anchor(SOURCES[0], 'Process.kill("INT", Process.pid)')
      }
    end

    def parent_for?(root, mode)
      @role == :parent && @root == root && @mode == mode
    end

    def source_snapshot
      @paths.to_h do |name, path|
        bytes = File.binread(path, 1_048_577)
        raise "oversized signal proof source" if bytes.bytesize > 1_048_576
        [name, Digest::SHA256.hexdigest(bytes)]
      end
    end

    def anchor(name, text)
      lines = File.readlines(@paths.fetch(name))
      matches = lines.each_index.select { |index| lines[index].strip.start_with?(text) }
      raise "native signal proof source anchor changed" unless matches.length == 1
      [@paths.fetch(name), matches.first + 1].freeze
    end

    def fail!(reason)
      @failures << reason unless @failures.include?(reason)
    end

    def owner_scope(kind, owner)
      variable = kind == :start ? :@start_owner : :@signal_owner
      previous = instance_variable_get(variable)
      instance_variable_set(variable, owner)
      yield
    ensure
      instance_variable_set(variable, previous)
    end

    def spawned(pid, options)
      if @start_owner
        prior = @by_pid[pid]
        fail!("overlapping fixture reservation") if prior && prior[:state] != :reaped
        record = {owner: @start_owner, pid: pid, private_group: options[:pgroup].equal?(true),
                  state: :live, status: nil}
        @records << record
        @by_pid[pid] = record
      elsif @backend_depth.zero?
        fail!("spawn without fixture ownership")
      end
    end

    def waited(pid, value, error = nil)
      record = @by_pid[pid]
      return unless record
      if error
        record[:state] = :unknown unless record[:state] == :reaped
      elsif value
        unless value.first == pid && value.last.is_a?(Process::Status) && value.last.pid == pid
          record[:state] = :unknown
          fail!("inconsistent fixture wait")
          return
        end
        record[:state], record[:status] = :reaped, value.last
      end
    end

    def fixture_context(signal, targets, source)
      target = targets.length == 1 && targets.first.is_a?(Integer) ? targets.first : nil
      record = target && @by_pid[target.abs]
      owner = @signal_owner
      state = if record && record[:state] == :reaped
        "reaped"
      elsif record && owner && record[:owner].equal?(owner) && record[:state] == :live && owner.phase == :live
        "live"
      else
        "unknown"
      end
      {"origin" => "fixture", "signal" => signal, "targets" => targets, "source" => source,
       "state" => state, "sourceBound" => source == @anchors.fetch("fixture"),
       "ownerBound" => !!(record && owner && record[:owner].equal?(owner) && owner.pid == record[:pid]),
       "targetBound" => !!(record && (target == record[:pid] || (target == -record[:pid] && record[:private_group])))}
    end

    def request(signal, targets, location)
      source = [location.path, location.lineno]
      context = {"origin" => "fixture", "signal" => signal, "targets" => targets, "source" => source,
                 "state" => "unknown", "sourceBound" => false, "ownerBound" => false, "targetBound" => false}
      begin
        context = fixture_context(signal, targets, source)
        if source == @anchors.fetch("native")
          context.merge!("origin" => "native", "state" => "unknown")
          joined = @actual_waiter&.join(0)
          context.merge!("state" => @actual_waiter ? (joined ? "reaped" : "live") : "unknown",
                         "sourceBound" => true,
                         "ownerBound" => @actual_waiter && @actual_waiter.equal?(@driver&.instance_variable_get(:@waiter)),
                         "targetBound" => @actual_waiter && targets == [-@actual_waiter.pid])
        elsif source == @anchors.fetch("self")
          frame = @driver&.instance_variable_get(:@native_frame)
          original = @driver&.instance_variable_get(:@injected_error)
          scope = UploadProcessFixture.instance_variable_get(:@cancellation_scope)
          context.merge!("origin" => "self", "state" => "reaped", "sourceBound" => true,
                         "ownerBound" => @mode == MODES.last && @actual_waiter&.join(0) &&
                           scope && scope.cleanup_depth.positive? && frame&.primary.equal?(original),
                         "targetBound" => targets == [Process.pid])
        end
      rescue Exception => error
        # A failed observation cannot authorize the backend or skip teardown.
        fail!("request observation:#{error.class.name}")
        context = context.merge("state" => "unknown", "ownerBound" => false)
      end
      dispatch(context)
    end

    def refusal(context)
      return "shape" unless context["targets"].length == 1 && context["targets"].first.is_a?(Integer)
      return "state" unless %w[live unknown reaped].include?(context["state"])
      if context["origin"] == "fixture" || context["origin"] == "native"
        return "unknown" if context["state"] == "unknown"
        return "post-reap" if context["state"] == "reaped"
      end
      return "source" unless context["sourceBound"]
      return "owner" unless context["ownerBound"]
      return "target" unless context["targetBound"]
      expected = context["origin"] == "self" ? "INT" : "KILL"
      return "signal" unless context["signal"] == expected
      unless context["origin"] == "fixture"
        return "repeat" if @requests.any? { |item| item["origin"] == context["origin"] }
      end
      nil
    end

    # Control contexts can never choose a backend. Only a control observer has
    # an inert backend; actual requests use the saved real Process.kill method.
    def dispatch(context)
      raise "signal observation exceeded its bound" if @requests.length >= 32
      reason = refusal(context)
      path, line = context.fetch("source")
      item = {"origin" => context.fetch("origin"), "signal" => context.fetch("signal").to_s.byteslice(0, 32),
              "targets" => context.fetch("targets").map { |target| target.is_a?(Integer) ? target : "invalid" },
              "source" => {"path" => @paths.key(path) || "unrecognized", "line" => line},
              "state" => context.fetch("state"), "forwarded" => false, "rejection" => reason}
      @requests << item
      if reason
        fail!("#{item.fetch('origin')}:#{reason}")
        return 0 # Cleanup continues, but the observer's failure cannot be cleared.
      end
      item["forwarded"] = true
      item["result"] = if @role == :control
        @control_forwards += 1
        1
      else
        @process.fetch(:kill).call(context.fetch("signal"), *context.fetch("targets"))
      end
    rescue Exception => error
      item["backendErrorClass"] = error.class.name if item && item["forwarded"]
      fail!("signal exception:#{error.class.name}")
      raise
    end

    def install
      raise "signal observer is already active" if self.class.current
      self.class.current = self
      @process = %i[spawn waitpid2 kill].to_h { |name| [name, Process.method(name)] }
      @owned = %i[start signal].to_h { |name| [name, OwnedChild.instance_method(name)] }
      probe, process, owned = self, @process, @owned
      Process.define_singleton_method(:spawn) do |*arguments, **options|
        raise "control observer cannot acquire a child" if probe.instance_variable_get(:@role) == :control
        raise "fixture reservation observation exceeded its bound" if probe.records.length >= 128
        value = process.fetch(:spawn).call(*arguments, **options)
        probe.spawned(value, options)
        value
      end
      Process.define_singleton_method(:waitpid2) do |*arguments|
        begin
          value = process.fetch(:waitpid2).call(*arguments)
        rescue Exception => error
          probe.waited(arguments.first, nil, error)
          raise
        end
        probe.waited(arguments.first, value)
        value
      end
      Process.define_singleton_method(:kill) do |signal, *targets|
        probe.request(signal, targets, caller_locations(1, 1).first)
      end
      OwnedChild.define_method(:start) do |*arguments, **options|
        probe.owner_scope(:start, self) { owned.fetch(:start).bind_call(self, *arguments, **options) }
      end
      OwnedChild.define_method(:signal) do |signal, group: true|
        probe.owner_scope(:signal, self) { owned.fetch(:signal).bind_call(self, signal, group: group) }
      end
      if @role == :driver
        @open3 = Open3.method(:popen3)
        Open3.define_singleton_method(:popen3) { |*arguments, **options, &block| probe.native_backend(*arguments, **options, &block) }
      end
    end

    def native_backend(*arguments, **options, &block)
      @backend_entries += 1
      @backend_depth += 1
      @open3.call(*arguments, **options) do |stdin, stdout, stderr, waiter|
        @callback_entries += 1
        @actual_waiter, @actual_ios = waiter, [stdin, stdout, stderr]
        block.call(stdin, stdout, stderr, waiter)
      end
    ensure
      @backend_depth -= 1
    end

    def restore
      operations = (@process || {}).map { |name, method| -> { Process.define_singleton_method(name, method) } }
      operations.concat((@owned || {}).map { |name, method| -> { OwnedChild.define_method(name, method) } })
      operations << -> { Open3.define_singleton_method(:popen3, @open3) } if @open3
      operations.each do |operation|
        begin
          operation.call
        rescue Exception => error
          fail!("hook restoration:#{error.class.name}")
        end
      end
      @hooks_restored = @process && @owned && @process.all? { |name, method| Process.method(name) == method } &&
        @owned.all? { |name, method| OwnedChild.instance_method(name) == method } && (!@open3 || Open3.method(:popen3) == @open3)
      fail!("hook restoration incomplete") unless @hooks_restored
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
            rescue Exception => error
              primary ||= error
              fail!("hook restoration:#{error.class.name}")
            ensure
              begin
                @records.each do |record|
                  owner = record.fetch(:owner)
                  unless record[:state] == :reaped && owner.phase == :reaped && record[:status].equal?(owner.status)
                    fail!("fixture reservation not finally reaped")
                  end
                end
                fail!("source changed during observation") unless source_snapshot == @source_hashes
              rescue Exception => error
                primary ||= error
                fail!("observation postcondition:#{error.class.name}")
              end
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

    def evidence
      value = {"kind" => "native-signal-observation", "role" => @role.to_s, "case" => @mode,
       "sourceSha256" => @source_hashes, "hooksRestored" => !!@hooks_restored,
       "requests" => @requests, "failures" => @failures,
       "fixtureReservations" => @records.map do |record|
         {"pid" => record[:pid], "privateGroup" => record[:private_group], "phase" => record[:state].to_s,
          "ownerPhase" => record[:owner].phase.to_s, "exitStatus" => record[:status]&.exitstatus,
          "termSignal" => record[:status]&.termsig}
       end,
       "backendEntries" => @backend_entries, "callbackEntries" => @callback_entries,
       "controlForwards" => @control_forwards}
      text = JSON.generate(value)
      raise "oversized signal observation" if text.bytesize > OUTPUT_LIMIT
      JSON.parse(text) # A detached history; inert controls cannot mutate real evidence.
    end

    def check_native(status, raw)
      check = ->(name, condition) { fail!(name) unless condition }
      check.call("base driver result", status == 0 && raw["kind"] == "pass" && raw["mode"] == @mode)
      check.call("actual native callback", @backend_entries == 1 && @callback_entries == 1 &&
                 @actual_waiter && @actual_waiter.equal?(@driver.instance_variable_get(:@waiter)))
      joined = @actual_waiter&.join(0)
      wait_status = @actual_waiter.value if joined
      check.call("actual native SIGKILL", joined && wait_status.signaled? && wait_status.termsig == Signal.list.fetch("KILL"))
      check.call("actual native descriptors", @actual_ios.length == 3 && @actual_ios.all?(&:closed?) &&
                 @driver.owned_ios.length == 7 && @driver.owned_ios.all?(&:closed?))
      primary = @driver.instance_variable_get(:@native_frame)&.primary
      original = @driver.instance_variable_get(:@injected_error)
      native_error = @driver.instance_variable_get(:@native_error)
      check.call("actual original primary", primary.equal?(original) && original.message == @driver.instance_variable_get(:@injected_message))
      if original.is_a?(IOError)
        check.call("actual IOError redaction", native_error.instance_of?(MobileReleaseKit::ContractError) &&
                   native_error.message == "Synthetic validator could not be executed safely; no upload is authorized")
      else
        check.call("actual native original", native_error.equal?(original) && native_error.message == original.message)
        check.call("actual SystemExit status", native_error.status == 23) if original.is_a?(SystemExit)
      end
      %w[ready captureEntered firstCloseFromNative originalCloseCompleted watchdogStarted deadBeforeFallback
         ownedDescriptorsClosed watchdogJoined waiterJoined injectorsJoined handlersRestored registryInactive].each do |name|
        check.call(name, raw[name] == true)
      end
      check.call("one actual first close", raw["nativeSpawnAttempts"] == 1 && raw["injectionCount"] == 1)
      check.call("no fallback or pending cleanup", !raw["fallbackUsed"] && !raw["watchdogIntervened"] &&
                 !raw.key?("workerControlEOF") && !raw["pendingInterrupt"] && raw["cleanupErrors"] == [])
      native_requests = @requests.select { |request| request["origin"] == "native" }
      check.call("one actual production KILL", native_requests.length == 1 && native_requests.first["forwarded"] && native_requests.first["result"] == 1)
      self_requests = @requests.select { |request| request["origin"] == "self" }
      if @mode == MODES.last
        injector = @driver.instance_variable_get(:@injector)
        check.call("actual post-reap repeats", raw["postReapCancellationInjected"] && raw["postReapCleanupDepth"].to_i.positive? &&
                   injector && !injector.alive? && raw["selfSignalQueued"] == Signal.list.fetch("INT") &&
                   self_requests.length == 1 && self_requests.first["forwarded"] && self_requests.first["result"] == 1)
      else
        check.call("no unexpected self signal", self_requests.empty?)
      end
      {"baseDriverReturn" => status, "actualWaiterPid" => @actual_waiter&.pid,
       "actualWorkerExitStatus" => wait_status&.exitstatus, "actualWorkerTermSignal" => wait_status&.termsig,
       "actualOriginalPrimary" => primary.equal?(original), "actualNativeDescriptorsClosed" => @actual_ios.all?(&:closed?)}
    end

    def self.observe_parent(root, mode)
      probe = new(:parent, mode, root: root)
      self.last_parent = probe # Retired actual owner/status objects for inert controls only.
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
      probe = new(:driver, mode, driver: driver)
      status = nil
      facts = {}
      begin
        probe.observe { status = driver.execute }
        facts = probe.check_native(status, UploadProcessFixture.read_json(File.join(directory, "result.json")))
      rescue Exception => error
        probe.fail!("driver proof:#{error.class.name}")
      end
      proof = probe.evidence.merge(facts).merge("baseDriverReturn" => status)
      raise "oversized native signal proof" if JSON.generate(proof).bytesize > OUTPUT_LIMIT
      UploadProcessFixture.atomic_json(File.join(directory, "native-signal-proof.json"), proof)
      probe.failures.empty? ? 0 : 1
    end

    def control_context(record, state)
      raise "only fixed inert controls accept synthetic context" unless @role == :control && %w[live unknown reaped].include?(state)
      owner = record.fetch(:owner)
      unless record[:state] == :reaped && record[:private_group] && owner.phase == :reaped && record[:status].equal?(owner.status)
        raise "control seed lacks an actual reaped private fixture child"
      end
      # This snapshot is explicitly synthetic, not a claim of renewed authority.
      {"origin" => "fixture", "signal" => "KILL", "targets" => [-record.fetch(:pid)].freeze,
       "source" => @anchors.fetch("fixture"), "state" => state,
       "sourceBound" => true, "ownerBound" => true, "targetBound" => true}.freeze
    end
  end

  def driver(directory)
    input = read_json(File.join(directory, "input.json"))
    mode, platform = input.values_at("mode", "platform")
    validate_request!(platform, mode, input.fetch("parameters"))
    observe_signals = input.fetch("observeSignals", false)
    validate_signal_observation!(platform, mode, observe_signals)
    unless Dir.tmpdir == directory
      raise Failure.new("fixture-input", "driver temporary directory is not its owned case root")
    end
    return NativeSignalProbe.execute_driver(directory, mode) if observe_signals
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
      capture = lambda do |argv, seconds:, environment:|
        calls << [argv, seconds, environment]
        [replies.shift || raise("unplanned synthetic observation"), "", 0]
      end
      fixture.stub(:process_observer_path, path) do
        Process.stub(:uid, 501) do
          Process.stub(:gid, 20) do
            fixture.stub(:capture_command, capture) do
              replies << line.call
              assert_equal :live, fixture.state(123, 122, seconds: 0.25)
              assert_equal [[path, "123"], 0.25, {"LANG" => "C", "LC_ALL" => "C"}], calls.last
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
    # inert doubles. The actual lifetime *entrypoint* is replaced; only its
    # in-memory first-error/cleanup collector is reused, without trap setup.
    def assert_process_observer_cleanup
      fixture = UploadProcessFixture
      saved_roots = fixture.instance_variable_get(:@unresolved_roots)
      fixture.instance_variable_set(:@unresolved_roots, {})
      root, driver = "/synthetic-proof-root", "/synthetic-proof-root/native-process-fixed"
      removed, visited = [], []
      listings = {root => [], driver => []}
      reader = lambda do |path|
        visited << path
        value = listings.fetch(path)
        raise value if value.is_a?(Exception)
        value
      end
      FileUtils.stub(:remove_entry, ->(path) { removed << path }) do
        fixture.stub(:fixture_entry_names, reader) do
          listings[driver] = ["mrk-process-observation-retained"]
          assert_raises(Failure) { fixture.remove_fixture_directory(driver, root: root, layout: :driver) }
          assert_empty removed
          assert fixture.cleanup_unresolved?(root)
          listing_error = IOError.new("synthetic listing failure")
          listings[driver] = listing_error
          error = assert_raises(IOError) { fixture.remove_fixture_directory(driver, root: root, layout: :driver) }
          assert_same listing_error, error
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
          collector.instance_variable_set(:@retain_raw_evidence, false)
          listings[driver] = ["mrk-process-observation-retained"]
          assert_raises(Failure) { collector.check_raw_capture_scratch!(driver) }
          assert collector.instance_variable_get(:@retain_raw_evidence)
          assert_raises(Failure) { collector.finish_raw_proof_copies! }
          assert collector.instance_variable_get(:@retain_raw_evidence)
          assert_empty removed
          fixture.instance_variable_set(:@unresolved_roots, {})
          listings[driver] = []
          collector.check_raw_capture_scratch!(driver)
          collector.finish_raw_proof_copies!
          refute collector.instance_variable_get(:@retain_raw_evidence)
          assert_run_cleanup_veto_with_doubles(root, driver, listings, removed)
        end
      end
      assert_bounded_fixture_enumeration
      assert_driver_temp_precondition
    ensure
      fixture.instance_variable_set(:@unresolved_roots, saved_roots) if fixture
    end

    def assert_run_cleanup_veto_with_doubles(root, directory, listings, removed)
      fixture = UploadProcessFixture
      scope_type = Struct.new(:cleanup_depth) do
        def cleanup
          self.cleanup_depth += 1
          yield
        ensure
          self.cleanup_depth -= 1
        end
      end
      child_type = Struct.new(:phase, :status, :stop_error, :starts) do
        def start(environment, *arguments, **options)
          self.starts << [environment, arguments, options]
          self.phase = :reaped
        end
        def poll = status
        def stop
          raise stop_error if stop_error
        end
        def complete? = phase == :reaped
      end
      owner = {"phase" => "no-native-child", "nativeSpawnAttempts" => 0}
      [false, true].each do |residue|
        [false, true].each do |with_primary|
          removed.clear
          fixture.instance_variable_set(:@unresolved_roots, {})
          listings[directory] = residue ? ["mrk-process-observation-retained"] : []
          active_error = with_primary ? IOError.new("synthetic original active failure") : nil
          stop_error = with_primary ? IOError.new("synthetic independent stop failure") : nil
          child = child_type.new(:unstarted, Struct.new(:exitstatus).new(1), stop_error, [])
          frame = Lifetime.new(scope_type.new(0))
          result = {"kind" => "setup-fixture-fault", "nativeSpawnAttempts" => 0, "ownedDescriptorsClosed" => true}
          result.define_singleton_method(:merge) { |*| raise active_error } if with_primary
          lifetime = lambda do |&body|
            value = nil
            begin
              value = body.call(frame)
            rescue Exception => error
              frame.remember(error)
            end
            raise frame.primary if frame.primary
            value
          end
          fake_directory = Struct.new(:uid, :mode) { def directory? = true }.new(Process.uid, 0o40700)
          observed_error = nil
          File.stub(:realpath, ->(path) { path }) do
            File.stub(:lstat, fake_directory) do
              File.stub(:open, ->(*, **, &block) { block.call(Object.new) }) do
                File.stub(:file?, false) do
                  Dir.stub(:mktmpdir, directory) do
                    OwnedChild.stub(:new, child) do
                      fixture.stub(:lifetime, lifetime) do
                        fixture.stub(:atomic_json, nil) do
                          fixture.stub(:read_json, ->(path) { File.basename(path) == "owner.json" ? owner : result }) do
                            fixture.stub(:clock, 0.0) do
                              fixture.stub(:wait_until, ->(*, &block) { assert block.call }) do
                                fixture.stub(:warn, nil) do
                                  begin
                                    fixture.run(platform: "native", root: root, parameters: {}, mode: "native-setup-second-pipe")
                                  rescue Exception => error
                                    observed_error = error
                                  end
                                end
                              end
                            end
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
          assert_equal 1, child.starts.length
          assert_equal fixture.process_observer_environment.merge("TMPDIR" => directory, "TMP" => directory, "TEMP" => directory), child.starts.first[0]
          assert_equal true, child.starts.first[2].fetch(:unsetenv_others)
          assert_equal true, child.starts.first[2].fetch(:pgroup)
          errors = frame.instance_variable_get(:@cleanup_errors)
          if with_primary
            assert_same active_error, observed_error
            assert_same stop_error, errors.first
          elsif residue
            assert_instance_of Failure, observed_error
          else
            assert_nil observed_error
          end
          if residue
            assert_empty removed # Active path already set cleaned=true in every vector.
            assert fixture.cleanup_unresolved?(root)
            assert_equal "fixture-cleanup", errors.last.kind
          else
            assert_equal [directory], removed
          end
          assert_equal (with_primary ? 1 : 0) + (residue ? 1 : 0), errors.length
        end
      end
    end

    def assert_bounded_fixture_enumeration
      fixture = UploadProcessFixture
      path = "/synthetic-enumeration-root"
      type = Struct.new(:dev, :ino, :mode, :uid, :gid, :nlink, :size, :mtime, :ctime) do
        def directory? = (mode & 0o170000) == 0o40000
      end
      metadata = type.new(1, 2, 0o40700, Process.uid, Process.gid, 2, 64, 1, 1)
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
        metadata.ctime += 1 if mutate
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
      File.stub(:realpath, path) do
        File.stub(:lstat, ->(*) { metadata }) do
          File.stub(:open, file_open) do
            Dir.stub(:open, dir_open) do
              IO.stub(:for_fd, lambda { |fd, autoclose:| assert_equal 987_654, fd; assert_equal false, autoclose; borrowed }) do
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
                mutate, closed = true, []
                assert_raises(Failure) { fixture.fixture_entry_names(path) }
                assert_equal [:directory, :pin], closed
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

    def assert_driver_temp_precondition
      fixture = UploadProcessFixture
      directory, mode = "/synthetic-driver-root", "native-setup-second-pipe"
      input = {"platform" => "native", "parameters" => {}, "mode" => mode}
      reads, acquired = 0, []
      temporary = directory
      native = Object.new
      native.define_singleton_method(:execute) { :synthetic_driver_only }
      factory = ->(*arguments) { acquired << arguments; native }
      fixture.stub(:read_json, ->(*) { input }) do
        Dir.stub(:tmpdir, -> { reads += 1; temporary }) do
          NativeSetupDriver.stub(:new, factory) do
            input["mode"] = "invalid-case"
            assert_raises(Failure) { fixture.driver(directory) }
            input["mode"], input["observeSignals"] = mode, true
            assert_raises(Failure) { fixture.driver(directory) }
            assert_equal 0, reads # Both input validations precede the actual temp precondition.
            assert_empty acquired
            input.delete("observeSignals")
            temporary = "/synthetic-wrong-root"
            error = assert_raises(Failure) { fixture.driver(directory) }
            assert_equal "fixture-input", error.kind
            assert_empty acquired
            temporary = directory
            assert_equal :synthetic_driver_only, fixture.driver(directory)
            assert_equal [[directory, mode]], acquired
          end
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
