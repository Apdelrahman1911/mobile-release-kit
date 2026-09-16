# frozen_string_literal: true

# Native test launcher only. The reviewed controller copies these exact bytes
# to its own .../launcher/fastlane/run_lane.rb; the real product entrypoint is
# separately bound and loaded unchanged. No Store service or release is called.
require "json"
require "digest"
require "rbconfig"
require "shellwords"

module StoreLaneNativeFixture
  REQUEST_KEY = "MOBILE_RELEASE_TEST_STORE_NATIVE_REQUEST"
  MAX_JSON = 65_536
  MODES = %w[success0 ordinary75 system-exit0 system-exit75
             terminal-close-return-loss terminal-link-return-loss
             nested-ios-success nested-android-success nested-android-inherited-pipe
             bridge-success bridge-ordinary-error clock-expired clock-wrong-label].freeze
  EARLY_UNKNOWN_MODES = %w[success0 ordinary75 nested-ios-success nested-android-success
                          nested-android-inherited-pipe bridge-success bridge-ordinary-error].freeze
  class Failure < StandardError; end
  class OrdinaryFailure < StandardError; end
  INNER_FAILURE_REASONS = {
    "store-runtime-error" => %w[app_id binding_missing bridge_reused bridges_not_admitted clock completion cwd deadline
      directory_api directory_return document_missing environment environment_changed exit_api
      exit_not_captured exit_owner exit_returned exit_status foreign_origin inactive_runtime integer
      invocation_missing key_id lane nonce nonlocal_completion output_scope path resources_missing
      root_identity runtime_api runtime_missing runtime_reused temporary_scope terminal_entry_changed
      terminal_link_return terminal_nonlocal terminal_reused terminal_root_changed terminal_root_identity
      terminal_size terminal_unretired terminal_write_progress terminal_writer_changed
      terminal_writer_identity unregistered_runtime unsettled_lane api_key_route fastlane_interface
      fastlane_platform fastlane_source_path fastlane_version package_route pilot_platform_changed
      pilot_route transporter_route].freeze,
    "store-resource-error" => %w[admission_reused artifact_route asset_platform close_unconfirmed created_directory_identity
      created_file_identity creation_role deadline duplicate_parent duplicate_role entry_changed
      entry_name file_api file_contents finish_missing finish_reused foreign_origin inventory_unavailable
      key_identity mkdir_return open_return_missing package_file_route package_platform parent_changed
      parent_closed parent_identity parent_route read_progress resource_busy resource_return_missing
      resources_not_admitted root_ancestry_changed root_identity shell_home_not_admitted shell_home_route
      slot_reused source_admission_closed source_growth source_identity source_pin source_revision
      source_role unowned_removal_request unretired_resource unretired_writer uuid write_progress
      written_revision written_size].freeze,
    "store-document-error" => %w[acquisition_return_missing already_attempted close_not_confirmed destination_exists foreign_origin
      incomplete_publication initial_stage_unknown invalid_path no_successful_publication
      nonlocal_completion parent_changed parent_custody_missing parent_not_directory
      required_filesystem_api_missing stage_bytes_changed stage_changed stage_custody_missing
      stage_reappeared stage_revision_changed stage_unlink_unconfirmed write_progress_missing
      written_stage_custody_missing].freeze,
    "native-process-error" => %w[abi runtime origin symbol spec launch deadline state io fd busy native waitability spawn wait join
      close unknown].freeze,
  }.freeze

  module_function

  def need(value, reason)
    raise Failure, "Store native fixture #{reason}" unless value
  end

  def json(path)
    stat = File.lstat(path)
    need(stat.file? && !stat.symlink? && stat.nlink == 1 && stat.uid == Process.euid &&
         (stat.mode & 0o7777) == 0o600 && stat.size.between?(1, MAX_JSON), "request custody")
    raw = File.binread(path, MAX_JSON + 1)
    need(raw.bytesize <= MAX_JSON, "request bound")
    JSON.parse(raw, max_nesting: 32)
  end

  def read_request(path)
    request = json(path)
    need(request.keys.sort == %w[binding diagnostic diagnosticIdentity fixtureFiles mode nested phase root sourceRoot version wheel], "request shape")
    need(request.fetch("version") == 1 && MODES.include?(request.fetch("mode")) &&
         %w[source wheel].include?(request.fetch("phase")), "request role")
    root, source = request.values_at("root", "sourceRoot")
    need([root, source].all? { |item| item.is_a?(String) && File.realpath(item) == item && !File.symlink?(item) } &&
         root != source && !root.start_with?(source + "/"), "request roots")
    need(File.realpath(path) == File.join(root, "request.json") && request.fetch("diagnostic") == File.join(root, "observation.json"),
         "fixed request/diagnostic entries")
    request.fetch("fixtureFiles").each do |relative, expected|
      need(%w[tests/workflow/store_lane_native_fixture.rb tests/workflow/installed_ruby_capture_fixture.rb
              tests/workflow/upload_process_fixture.rb tests/workflow/upload_process_ownership.rb].include?(relative), "fixture inventory")
      entry = File.join(source, relative)
      need(File.realpath(entry) == entry && Digest::SHA256.file(entry).hexdigest == expected, "fixture origin")
    end
    need(request.fetch("fixtureFiles").keys.sort == %w[tests/workflow/installed_ruby_capture_fixture.rb
         tests/workflow/store_lane_native_fixture.rb tests/workflow/upload_process_fixture.rb
         tests/workflow/upload_process_ownership.rb].sort, "fixture closure")
    require File.join(source, "tests/workflow/installed_ruby_capture_fixture.rb")
    binding = request.fetch("binding")
    expected = if request.fetch("phase") == "source"
                 need(request.fetch("wheel").nil?, "source is not wheel evidence")
                 InstalledRubyCaptureFixture.source_layout(binding.fetch("prefix"), source, profile: :store_native)
               else
                 wheel = original_wheel(request.fetch("wheel"), binding.fetch("wheelSha256"))
                 InstalledRubyCaptureFixture.installed_layout(binding.fetch("prefix"), source,
                   wheel: wheel, wheel_sha256: binding.fetch("wheelSha256"), profile: :store_native)
               end
    need(binding == expected, "selected original installation")
    need(Digest::SHA256.file(__FILE__).hexdigest == request.fetch("fixtureFiles").fetch("tests/workflow/store_lane_native_fixture.rb"), "launcher bytes")
    InstalledRubyCaptureFixture.verify_binding!(binding)
    info = request.fetch("nested")
    bridge = %w[bridge-success bridge-ordinary-error].include?(request.fetch("mode"))
    if request.fetch("mode").start_with?("nested-") || bridge
      platform = (request.fetch("mode") == "nested-ios-success" || bridge) ? "ios" : "android"
      directory = File.join(root, "nested")
      extension = platform == "ios" ? "ipa" : "aab"
      need(info.is_a?(Hash) && info.keys.sort == %w[app artifact platform root validator value] &&
           info.fetch("platform") == platform && info.fetch("root") == directory && info.fetch("app") == File.join(directory, "app") &&
           info.fetch("artifact") == File.join(directory, "app/candidate.#{extension}") &&
           info.fetch("validator") == File.join(directory, "trusted-validator"), "fixed nested fixture entries")
    else
      need(info.nil?, "unselected nested role")
    end
    request
  end

  def original_wheel(path, sha256)
    need(path.is_a?(String) && path.end_with?(".whl") && File.realpath(path) == path &&
         sha256.is_a?(String) && sha256.match?(/\A[0-9a-f]{64}\z/), "original wheel identity")
    value = File.lstat(path)
    need(value.file? && !value.symlink? && value.nlink == 1 && value.size.between?(1, 64 * 1024 * 1024) &&
         Digest::SHA256.file(path).hexdigest == sha256, "original wheel bytes")
    path
  end

  def identity(stat)
    {"device" => stat.dev, "inode" => stat.ino, "uid" => stat.uid, "gid" => stat.gid,
     "mode" => stat.mode & 0o7777}
  end

  def first_primary_diagnostic(error, request)
    empty = {"category" => "unclassified", "reason" => nil, "locations" => []}
    return empty.merge("category" => "none") if error.nil?
    # Exact known classes only. Neither messages nor arbitrary class/reason
    # string conversions are diagnostic data.
    classes = {
      SystemExit => "system-exit", Interrupt => "interrupt", IOError => "io-error", EOFError => "eof-error",
      ArgumentError => "argument-error", TypeError => "type-error", NameError => "name-error",
      NoMethodError => "no-method-error", LoadError => "load-error", NotImplementedError => "not-implemented-error",
      RuntimeError => "runtime-error", SyntaxError => "syntax-error", SecurityError => "security-error",
      StandardError => "standard-error", Exception => "exception",
      Errno::ENOENT => "errno-enoent", Errno::EACCES => "errno-eacces", Errno::EPERM => "errno-eperm",
      Errno::EBADF => "errno-ebadf", Errno::EIO => "errno-eio", Errno::EEXIST => "errno-eexist",
      Errno::ENOSPC => "errno-enospc", Failure => "fixture-error", OrdinaryFailure => "ordinary-fixture-error",
      MobileReleaseKit::StoreLaneRuntime::Error => "store-runtime-error",
      MobileReleaseKit::StoreLaneResources::Error => "store-resource-error",
      MobileReleaseKit::StoreDocument::Error => "store-document-error",
      MobileReleaseKit::NativeProcessSpawn::Error => "native-process-error",
      MobileReleaseKit::StoreLaneLifetime::LifetimeError => "store-lifetime-error",
      MobileReleaseKit::StoreLaneLifetime::CommandExitError => "store-command-exit-error",
      MobileReleaseKit::NativeUploadProcess::Error => "native-upload-error",
      MobileReleaseKit::NativeUploadProcess::ProtocolError => "native-upload-protocol-error",
      MobileReleaseKit::NativeUploadProcess::LifecycleError => "native-upload-lifecycle-error"
    }
    original_class = Object.instance_method(:class)
    category = classes.fetch(original_class.bind_call(error), "unclassified")
    reason = nil
    if INNER_FAILURE_REASONS.key?(category)
      field = category == "native-process-error" ? :@code : :@reason
      raw = Object.instance_method(:instance_variable_get).bind_call(error, field)
      kind = original_class.bind_call(raw)
      reason = INNER_FAILURE_REASONS.fetch(category).find do |allowed|
        (kind.equal?(Symbol) && allowed.to_sym.equal?(raw)) || (kind.equal?(String) && allowed == raw)
      end
    end
    # These paths were already checked by read_request. Projection does not
    # inspect/resolve any source path or walk an exception's reported path.
    filenames = {}
    request.fetch("binding").fetch("files").each do |relative, binding|
      next unless relative.start_with?("fastlane/") && (relative.end_with?(".rb") || relative == "fastlane/Fastfile")
      filenames[binding.fetch("path")] = relative
    end
    request.fetch("fixtureFiles").each_key do |relative|
      filenames[request.fetch("sourceRoot") + "/" + relative] = relative
    end
    filenames[request.fetch("root") + "/launcher/fastlane/run_lane.rb"] = "tests/workflow/store_lane_native_fixture.rb"
    locations = []
    backtrace = Exception.instance_method(:backtrace_locations).bind_call(error)
    # Ruby starts with the cause. Keep the FIRST relevant source-bound frames.
    Array(backtrace).first(128).each do |location|
      next unless location.instance_of?(Thread::Backtrace::Location)
      relative = filenames[location.absolute_path]
      line = location.lineno
      next unless relative && line.instance_of?(Integer) && line.between?(1, 999_999)
      locations << {"file" => relative, "line" => line}
      break if locations.length == 8
    end
    {"category" => category, "reason" => reason, "locations" => locations}
  rescue Exception # rubocop:disable Lint/RescueException
    empty # Optional projection cannot alter the first primary or observer flush.
  end

  class Observation
    attr_reader :request, :slots, :events, :ordinary

    def initialize(request)
      @request, @slots, @events = request, [], []
      @closed = @flush_attempted = false
      @ordinary = OrdinaryFailure.new("fixed synthetic lane failure")
      @facts = {"version" => 1, "mode" => request.fetch("mode"), "phase" => request.fetch("phase"),
                "atExitArmed" => false, "terminalLinkCalls" => 0, "terminalLinkReturned" => 0,
                "nested" => nil, "bridge" => nil, "pipe" => nil, "clock" => nil}
    end

    def fact(name, value)
      StoreLaneNativeFixture.need(!@flush_attempted && @facts.key?(name), "late observer fact")
      @facts[name] = value
    end

    def event(value)
      StoreLaneNativeFixture.need(!@flush_attempted && @events.length < 128, "late/overflow observer event")
      @events << value
    end

    def bind_hooks(hooks)
      StoreLaneNativeFixture.need(@hooks.nil?, "single observer hook owner")
      @hooks = hooks
    end

    def observe_slot(slot, io, path)
      StoreLaneNativeFixture.need(!@flush_attempted && io.instance_of?(File) && @slots.length < 64, "slot observation")
      io.singleton_class # Stabilize Method equality before the per-file wrapper.
      original = io.method(:close)
      StoreLaneNativeFixture.need(original.source_location.nil? && original.owner == IO, "original File close")
      row = {"path" => File.expand_path(path), "calls" => 0, "returns" => 0, "slot" => slot, "io" => io}
      @slots << row
      observer = self
      io.define_singleton_method(:close) do
        StoreLaneNativeFixture.need(row.fetch("calls").zero?, "original close repeated")
        row["calls"] += 1
        answer = original.call
        row["returns"] += 1
        if observer.request.fetch("mode") == "terminal-close-return-loss" && File.basename(row.fetch("path")) == "terminal.part"
          raise IOError, "fixed terminal close return loss"
        end
        answer
      end
      row["installed"] = io.method(:close)
      row["original"] = original
    end

    def original_slots
      runtime = MobileReleaseKit::StoreLaneRuntime.current_runtime!
      slots = runtime.resources.instance_variable_get(:@handles).dup
      publisher = runtime.instance_variable_get(:@publisher)
      slots.concat([publisher.instance_variable_get(:@root), publisher.instance_variable_get(:@writer)]) if publisher
      document = runtime.invocation.instance_variable_get(:@document_reservation)
      slots.concat([document.instance_variable_get(:@parent), document.instance_variable_get(:@stage)]) if document
      slots
    end

    def original_slots_covered?
      originals = original_slots.select(&:io)
      originals.length == @slots.length && originals.uniq.length == originals.length &&
        originals.all? { |slot| @slots.one? { |row| row.fetch("slot").equal?(slot) && row.fetch("io").equal?(slot.io) } }
    end

    def all_slots_retired?
      original_slots_covered? && original_slots.all?(&:retired?) &&
        @slots.all? { |row| row.fetch("calls") == 1 && row.fetch("returns") == 1 &&
                         row.fetch("slot").retired? && row.fetch("io").closed? }
    end

    def terminal_link(original, args)
      StoreLaneNativeFixture.need(args == ["terminal.part", "terminal.json"] && !@flush_attempted, "terminal link shape")
      @facts["terminalLinkCalls"] += 1
      StoreLaneNativeFixture.need(@facts.fetch("terminalLinkCalls") == 1 && all_slots_retired?, "original FD retirement before link")
      if request.fetch("mode") == "terminal-link-return-loss"
        answer = original.call(*args)
        StoreLaneNativeFixture.need(answer == 0, "original terminal link return")
        @facts["terminalLinkReturned"] += 1
        flush("link-return-lost")
        raise IOError, "fixed terminal link return loss"
      end
      # Diagnostics close BEFORE terminal linearization. No observer writes or
      # callback is inserted after the product's final active completion check.
      flush("before-terminal-link")
      original.call(*args)
    end

    def flush(stage)
      return if @closed
      StoreLaneNativeFixture.need(!@flush_attempted, "observer publication repeated")
      @flush_attempted = true
      # Bind the actual retained primary BEFORE optional restoration/facts can
      # fail. A preparation error is separate data, not a replacement primary.
      runtime = MobileReleaseKit::StoreLaneRuntime.current_runtime!
      primary = runtime.first_primary
      begin
        restore_hooks!
        facts = stage == "unknown-exit76" ? minimal_facts(stage, primary) : full_facts(stage, runtime, primary)
        raw = observation_bytes(facts)
      rescue Exception => preparation # rubocop:disable Lint/RescueException
        begin
          # Still the SAME unused writer attempt. There is no restoration retry,
          # and any fallback failure must leave this preparation exception first.
          write_observation(observation_bytes(minimal_facts("observer-preparation-failed", primary, preparation)))
        rescue Exception # rubocop:disable Lint/RescueException
          nil
        end
        raise
      end
      # Writer custody starts here. Nothing below can select another payload,
      # reopen the entry, repeat a close, or retry a failed observation at exit76.
      write_observation(raw)
    end

    def minimal_facts(stage, primary, preparation = nil)
      facts = {"version" => 1, "mode" => request.fetch("mode"), "phase" => request.fetch("phase"),
               "stage" => stage, "primaryDiagnostic" => StoreLaneNativeFixture.first_primary_diagnostic(primary, request)}
      if stage == "observer-preparation-failed"
        facts["preparationDiagnostic"] = StoreLaneNativeFixture.first_primary_diagnostic(preparation, request)
      end
      facts
    end

    def full_facts(stage, runtime, primary)
      binding = runtime.binding
      root = File.lstat(binding.fetch("root"))
      cwd = File.stat(".")
      StoreLaneNativeFixture.need(root.directory? && !root.symlink? && cwd.directory?, "observed original root/cwd type")
      @facts.merge!("stage" => stage, "events" => @events,
                    "binding" => binding, "ordinaryPrimarySame" => primary.equal?(@ordinary),
                    "primaryClass" => primary&.class&.name,
                    "primaryDiagnostic" => StoreLaneNativeFixture.first_primary_diagnostic(primary, request),
                    "originalSlotsCovered" => original_slots_covered?, "originalSlotsCount" => original_slots.length,
                    "observerRestored" => @restored,
                    "rootIdentity" => StoreLaneNativeFixture.identity(root), "cwdIdentity" => StoreLaneNativeFixture.identity(cwd),
                    "cwd" => Dir.pwd, "rootCanonical" => File.realpath(binding.fetch("root")),
                    "slots" => @slots.map { |row| {"path" => row.fetch("path"), "calls" => row.fetch("calls"),
                      "returns" => row.fetch("returns"), "retired" => row.fetch("slot").retired?,
                      "closed" => row.fetch("io").closed?} },
                    "exitOrigin" => {"owner" => Process.method(:exit!).owner.to_s,
                                     "source" => Process.method(:exit!).source_location,
                                     "arity" => Process.method(:exit!).arity},
                    "fchdirOrigin" => {"owner" => Dir.method(:fchdir).owner.to_s,
                                       "source" => Dir.method(:fchdir).source_location,
                                       "arity" => Dir.method(:fchdir).arity},
                    "productOrigins" => StoreLaneNativeFixture.product_origins(request),
                    "fastlane" => StoreLaneNativeFixture.fastlane_origins(request))
    end

    def observation_bytes(facts)
      raw = JSON.generate(facts)
      StoreLaneNativeFixture.need(raw.bytesize <= MAX_JSON, "observer output bound")
      raw
    end

    def write_observation(raw)
      path = request.fetch("diagnostic")
      entry = File.lstat(path)
      StoreLaneNativeFixture.need(StoreLaneNativeFixture.identity(entry) == request.fetch("diagnosticIdentity") &&
                                  entry.file? && entry.nlink == 1 && entry.size.zero? && !entry.symlink?, "observer original entry")
      io = File.open(path, File::WRONLY | File::NOFOLLOW | File::NONBLOCK)
      begin
        StoreLaneNativeFixture.need(StoreLaneNativeFixture.identity(io.stat) == request.fetch("diagnosticIdentity"), "observer original descriptor")
        offset = 0
        while offset < raw.bytesize
          count = io.write(raw.byteslice(offset..))
          StoreLaneNativeFixture.need(count.is_a?(Integer) && count.positive?, "observer progress")
          offset += count
        end
        io.flush
        io.fsync
      ensure
        io.close
      end
      @closed = true
    end

    def restore_hooks!
      StoreLaneNativeFixture.need(!@restore_attempted && @hooks, "observer restoration admission")
      @restore_attempted = true
      errors = []
      @slots.reverse_each do |row|
        io = row.fetch("io")
        if io.method(:close) != row.fetch("installed")
          errors << "changed-close-observer"
          next # Never replace another owner's method.
        end
        begin
          io.singleton_class.send(:remove_method, :close)
          errors << "close-origin-not-restored" unless io.method(:close) == row.fetch("original")
        rescue Exception => error # rubocop:disable Lint/RescueException
          errors << error.class.name
        end
      end
      errors.concat(@hooks.restore)
      @restored = errors.empty?
      StoreLaneNativeFixture.need(@restored, "observer hooks did not restore")
    end

    def unknown_tail
      runtime = MobileReleaseKit::StoreLaneRuntime.current_runtime!
      flush("unknown-cleanup") if runtime.instance_variable_get(:@state) == :unknown && !@flush_attempted
    end

    def unknown_exit76(boundary)
      return if @flush_attempted || !EARLY_UNKNOWN_MODES.include?(request.fetch("mode"))
      owner = MobileReleaseKit::StoreLaneRuntime
      return unless owner.instance_variable_get(:@exit_boundary).equal?(boundary)
      runtime = owner.current_runtime!
      return unless runtime.instance_of?(owner::Runtime) &&
                    runtime.instance_variable_get(:@exit_boundary).equal?(boundary) &&
                    runtime.instance_variable_get(:@state) == :unknown
      flush("unknown-exit76")
    end
  end

  def product_origins(request)
    binding = request.fetch("binding")
    methods = {"runtime" => MobileReleaseKit::StoreLaneRuntime.method(:run_upload!),
               "clock" => MobileReleaseKit::NativeProcessSpawn.method(:monotonic_ns),
               "document" => MobileReleaseKit::StoreDocument::Publication.instance_method(:publish!)}
    methods.transform_values do |method|
      origin = InstalledRubyCaptureFixture.method_origin(method)
      need(binding.fetch("files").values.any? { |item| item.fetch("path") == origin.fetch("path") &&
            item.fetch("sha256") == origin.fetch("sha256") }, "product method origin")
      origin
    end
  end

  def fastlane_origins(request)
    specification = Gem.loaded_specs.fetch("fastlane")
    need(specification.version.to_s == "2.235.0", "actual pinned Fastlane version")
    root = File.realpath(specification.full_gem_path)
    pins = MobileReleaseKit::StoreLaneFastlaneBridges.const_get(:SOURCES, false)
    files = pins.to_h do |relative, expected|
      item = InstalledRubyCaptureFixture.file_binding(File.join(root, relative))
      need(item.fetch("sha256") == expected, "actual fixed Fastlane source pin")
      [relative, item]
    end
    methods = {"pipe" => FastlaneCore::FastlanePty.method(:spawn),
      "key" => FastlaneCore::TransporterExecutor.instance_method(:prepare),
      "transporter" => FastlaneCore::ItunesTransporter.instance_method(:upload),
      "package" => FastlaneCore::IpaUploadPackageBuilder.instance_method(:generate),
      "pilot" => Pilot::BuildManager.instance_method(:upload)}
    bridge = request.fetch("binding").fetch("files").fetch("fastlane/store_lane_fastlane_bridges.rb")
    origins = methods.transform_values do |method|
      observed = InstalledRubyCaptureFixture.method_origin(method)
      original = InstalledRubyCaptureFixture.method_origin(method.super_method)
      need(observed.fetch("path") == bridge.fetch("path") && observed.fetch("sha256") == bridge.fetch("sha256") &&
           files.values.any? { |item| original.fetch("path") == item.fetch("path") && original.fetch("sha256") == item.fetch("sha256") },
           "actual bridge and pinned underlying method origins")
      {"bridge" => observed, "original" => original, "owner" => method.owner.to_s,
       "parameters" => method.parameters.map { |row| row.map(&:to_s) }}
    end
    {"version" => specification.version.to_s, "root" => root, "files" => files, "methods" => origins,
     "macos" => FastlaneCore::Helper.is_mac?, "testMode" => FastlaneCore::Helper.test?}
  end

  def install_observer(observer)
    @observer = observer
    hooks = UploadProcessFixture::CaptureObservation::Hooks.new
    observer.bind_hooks(hooks)
    boundary = MobileReleaseKit::StoreLaneRuntime.instance_variable_get(:@exit_boundary)
    hooks.wrap(MobileReleaseKit::StoreLaneRuntime.const_get(:ExitBoundary, false), :exit_status!) do |original, object, args, keywords, block|
      begin
        if args.length == 1 && args.first.equal?(76) && keywords.empty? && block.nil? && object.equal?(boundary)
          observer.unknown_exit76(boundary)
        end
      rescue Exception # rubocop:disable Lint/RescueException
        nil # Optional attribution cannot replace the original unknown exit.
      end
      original.call(*args, **keywords, &block) # Exactly once; forwarding errors are NOT observer errors.
    end
    hooks.wrap(MobileReleaseKit::StoreLaneResources::FileSlot, :acquire) do |original, object, args, keywords, block|
      result = original.call(*args, **keywords, &block)
      observer.observe_slot(object, result, args.fetch(0))
      result
    end
    handle = MobileReleaseKit::StoreDocument::Publication.const_get(:Handle, false)
    hooks.wrap(handle, :acquire) do |original, object, args, keywords, block|
      result = original.call(*args, **keywords, &block)
      observer.observe_slot(object, object.io, args.fetch(0))
      result
    end
    hooks.wrap(MobileReleaseKit::StoreLaneResources::Inventory, :close_independent!) do |original, _object, args, keywords, block|
      answer = original.call(*args, **keywords, &block)
      observer.unknown_tail
      answer
    end
    original_link = File.method(:link)
    need(original_link.source_location.nil?, "original hard-link API")
    hooks.wrap(File.singleton_class, :link) do |original, _object, args, keywords, block|
      if args == ["terminal.part", "terminal.json"]
        need(keywords.empty? && block.nil?, "fixed terminal link call")
        observer.terminal_link(original, args)
      else
        original.call(*args, **keywords, &block)
      end
    end
  end

  def observer
    @observer or raise Failure, "missing original observer"
  end

  def publish_document(runtime)
    publication = MobileReleaseKit::StoreDocument::Publication.new(
      path: runtime.binding.fetch("output"), contents: {"fixture" => "synthetic-no-store", "version" => 1})
    runtime.invocation.reserve_store_document!(publication)
    publication.publish!
    runtime.invocation.record_store_document!(publication)
    observer.event("original-document-closed-and-recorded")
  end

  def nested(runtime, request)
    info = request.fetch("nested")
    need(info.is_a?(Hash) && %w[ios android].include?(info.fetch("platform")), "nested fixed platform")
    invocation = runtime.invocation
    root, binding = info.fetch("root"), request.fetch("binding")
    require File.join(binding.fetch("toolingRoot"), "#{info.fetch('platform')}_upload_validation.rb")
    gate = info.fetch("platform") == "ios" ? MobileReleaseKit::IosUploadValidation : MobileReleaseKit::AndroidUploadValidation
    observation = UploadProcessFixture::CaptureObservation.new(native: MobileReleaseKit::NativeUploadValidation, root: root)
    extension = info.fetch("platform") == "ios" ? "ipa" : "aab"
    result = observation.observe do
      gate.current!(**{python: info.fetch("validator"), module_root: binding.fetch("moduleRoot"), app_root: info.fetch("app"),
        config_path: File.join(info.fetch("app"), "release/mobile-release.json"), intent_path: File.join(info.fetch("app"), "intent.json"),
        "#{extension}_path".to_sym => info.fetch("artifact"), intent_sha256: "a" * 64,
        environment: {"HOME" => info.fetch("app"), "PATH" => "/usr/bin:/bin", "LANG" => "C", "LC_ALL" => "C"},
        tooling_directory: binding.fetch("toolingRoot")})
    end
    capture = observation.snapshot
    need(InstalledRubyCaptureFixture.finalized_capture?(capture), "actual nested wait/EOF finality")
    original = invocation.instance_variable_get(:@nested)
    same_invocation = MobileReleaseKit::StoreLaneRuntime.current_runtime!.equal?(runtime) &&
      runtime.invocation.equal?(invocation) && MobileReleaseKit::StoreLaneLifetime.current_invocation.equal?(invocation) &&
      original && original.instance_variable_get(:@invocation).equal?(invocation)
    same_original = original && original.instance_variable_get(:@session).equal?(observation.session)
    same_result = original && original.instance_variable_get(:@result).equal?(result)
    need(same_invocation && same_original && same_result && result.frozen? && original.retired? && result == info.fetch("value") &&
         !File.exist?(File.join(root, "fallback.json")), "original nested retirement before fallback")
    runtime.require_active!
    observer.fact("nested", {"platform" => info.fetch("platform"), "artifact" => info.fetch("artifact"), "capture" => capture,
      "sameOriginalInvocation" => same_invocation, "sameOriginalResult" => same_result, "resultFrozen" => result.frozen?,
      "retired" => original.retired?, "sameOriginalSession" => same_original, "fallbackUsed" => false,
      "descendant" => File.file?(File.join(root, "descendant.json")) ? InstalledRubyCaptureFixture.read_json(File.join(root, "descendant.json")) : nil,
      "adapterOrigin" => InstalledRubyCaptureFixture.method_origin(gate.method(:current!)),
      "helperOrigin" => InstalledRubyCaptureFixture.method_origin(MobileReleaseKit::NativeUploadProcess.method(:helper_argv))})
    observer.event("same-original-nested-call-retired")
    [invocation, original, observation.session, result].freeze
  end

  def bridge(runtime, request)
    need(runtime.binding.fetch("lane") == "ios_testflight_internal", "bridge lane")
    info, artifact = request.fetch("nested"), runtime.binding.fetch("artifact")
    need(info.is_a?(Hash) && info.fetch("platform") == "ios" && info.fetch("artifact") == artifact,
         "same original bridge validation artifact")
    invocation, validation, session, result = nested(runtime, request)
    key = {key_id: runtime.binding.fetch("key_id"), key: "fictional-not-a-private-key", issuer_id: "fictional-issuer"}
    executor_class = runtime.binding.fetch("macos") ? FastlaneCore::AltoolTransporterExecutor : FastlaneCore::JavaTransporterExecutor
    executor = executor_class.allocate
    commands, dispatches = [], []
    executor.define_singleton_method(:build_upload_command) do |user, password, path, options|
      StoreLaneNativeFixture.need(user.nil? && [nil, "YourPassword"].include?(password) &&
        path.is_a?(String) && options.keys.sort == %i[api_key jwt platform provider_public_id provider_short_name].sort &&
        options[:platform] == "ios", "fixed executor command seam")
      commands << {"path" => path, "placeholder" => options[:api_key][:key_id] == "YourKeyID"}
      "STORE-NATIVE-INERT-EXECUTOR-TOKEN"
    end
    executor.define_singleton_method(:execute) do |token, hide|
      StoreLaneNativeFixture.need(token == "STORE-NATIVE-INERT-EXECUTOR-TOKEN" && [true, false].include?(hide), "fixed executor dispatch seam")
      same_validation = MobileReleaseKit::StoreLaneRuntime.current_runtime!.equal?(runtime) &&
        runtime.invocation.equal?(invocation) && MobileReleaseKit::StoreLaneLifetime.current_invocation.equal?(invocation) &&
        invocation.instance_variable_get(:@nested).equal?(validation) && validation.instance_variable_get(:@invocation).equal?(invocation) &&
        validation.instance_variable_get(:@session).equal?(session) && validation.instance_variable_get(:@result).equal?(result) &&
        result.frozen? && validation.retired? && runtime.binding.fetch("artifact") == artifact && info.fetch("artifact") == artifact
      StoreLaneNativeFixture.need(same_validation, "same original current validation before executor")
      runtime.resources.require_ready_for_executor!
      entries = runtime.resources.instance_variable_get(:@entries)
      StoreLaneNativeFixture.need(entries.key?("key") && entries.key?("package-ipa") &&
        entries.values.all? { |entry| entry.fetch(:kind) == "directory" || entry.fetch(:slot).retired? }, "generated custody before dispatch")
      StoreLaneNativeFixture.observer.event("original-bridge-executor-dispatch")
      dispatches << entries.keys.sort
      StoreLaneNativeFixture.observer.fact("bridge", {"macos" => runtime.binding.fetch("macos"), "rolesBeforeDispatch" => entries.keys.sort,
        "commands" => commands, "dispatches" => dispatches.length, "syntheticExecutor" => true,
        "sameOriginalValidationAtDispatch" => same_validation,
        "fastlaneVersion" => Gem.loaded_specs.fetch("fastlane").version.to_s,
        "seams" => %w[executor.build_upload_command executor.execute pilot.start pilot.config pilot.check_for_changelog_or_whats_new!
                       pilot.fetch_app_id pilot.fetch_app_platform pilot.transporter_for_selected_team]})
      raise StoreLaneNativeFixture.observer.ordinary if request.fetch("mode") == "bridge-ordinary-error"
      true
    end
    transporter = FastlaneCore::ItunesTransporter.allocate
    {:@api_key => key, :@transporter_executor => executor, :@user => nil, :@password => nil,
     :@jwt => nil, :@provider_short_name => nil, :@provider_public_id => nil}.each do |name, value|
      transporter.instance_variable_set(name, value)
    end
    options = {apple_id: runtime.binding.fetch("app_id"), api_key: key,
      ipa: runtime.binding.fetch("artifact"), pkg: nil, app_platform: "ios", skip_waiting_for_build_processing: true,
      skip_submission: true, changelog: nil, distribute_external: false, app_identifier: "example.synthetic.native",
      app_version: "1.0", build_number: "1"}
    manager = Pilot::BuildManager.allocate
    manager.define_singleton_method(:start) do |actual, should_login:|
      StoreLaneNativeFixture.need(actual.equal?(options) && should_login == false, "no account/login seam")
    end
    manager.define_singleton_method(:config) { options }
    manager.define_singleton_method(:check_for_changelog_or_whats_new!) do |actual|
      StoreLaneNativeFixture.need(actual.equal?(options) && actual[:changelog].nil?, "no changelog seam")
    end
    manager.define_singleton_method(:fetch_app_id) { options.fetch(:apple_id) }
    manager.define_singleton_method(:fetch_app_platform) { "ios" }
    manager.define_singleton_method(:transporter_for_selected_team) do |actual|
      StoreLaneNativeFixture.need(actual.equal?(options), "selected synthetic transporter")
      transporter
    end
    # Select the fixture's logging preference through the original Fastlane API.
    FastlaneCore::ItunesTransporter.hide_transporter_output
    manager.upload(options)
    need(dispatches.length == 1 && commands.length == 2, "real bridge dispatch count")
    # A separate benign direct child exercises the real installed PipeBridge.
    output = +""
    command = "#{Shellwords.escape(File.realpath(RbConfig.ruby))} -e #{Shellwords.escape('STDOUT.write("store-native-pipe")')}"
    status = FastlaneCore::FastlanePty.spawn(command) do |stdout, _stdin, _pid|
      stdout.each { |line| output << line; need(output.bytesize <= 64, "pipe fixture output") }
    end
    need(status == 0 && output == "store-native-pipe", "real pipe adapter")
    adapters = runtime.invocation.instance_variable_get(:@adapters)
    need(adapters.length == 1 && adapters.fetch(0).retired?, "actual original pipe adapter retirement")
    original = adapters.fetch(0)
    observer.fact("pipe", {"retired" => original.retired?, "waitState" => original.instance_variable_get(:@wait).to_s,
      "status" => original.instance_variable_get(:@status).exitstatus, "pid" => original.instance_variable_get(:@pid),
      "eof" => original.instance_variable_get(:@view).eof,
      "endpointsRetired" => original.instance_variable_get(:@endpoints).all?(&:retired?)})
    observer.event("real-pilot-package-key-and-pipe-bodies-returned")
  end

  def lane_body(runtime, request)
    mode = request.fetch("mode")
    case mode
    when "system-exit0" then raise SystemExit.new(0)
    when "system-exit75" then raise SystemExit.new(75)
    when "ordinary75" then raise observer.ordinary
    when /\Anested-/ then nested(runtime, request)
    when /\Abridge-/ then bridge(runtime, request)
    when "clock-expired"
      endpoint = runtime.binding.fetch("run_deadline_ns")
      entered = MobileReleaseKit::NativeProcessSpawn.monotonic_ns
      need(entered < endpoint, "short runtime admitted before expiry")
      sleep 0.001 while MobileReleaseKit::NativeProcessSpawn.monotonic_ns < endpoint
      observer.fact("clock", {"label" => MobileReleaseKit::NativeProcessSpawn.monotonic_domain,
        "entered" => entered, "run" => endpoint, "after" => MobileReleaseKit::NativeProcessSpawn.monotonic_ns})
      runtime.require_active! # Actual deadline check; must refuse, not publish.
      raise Failure, "expired runtime continued"
    end
    publish_document(runtime)
  end

  def composite(path)
    request = read_request(path)
    binding = request.fetch("binding")
    require File.join(binding.fetch("toolingRoot"), "store_lane_runtime.rb")
    MobileReleaseKit::StoreLaneRuntime.capture_exit_boundary!
    install_observer(Observation.new(request))
    sentinel = File.join(request.fetch("root"), "at-exit.json")
    at_exit { File.write(sentinel, "ordinary-at-exit-ran\n") }
    observer.fact("atExitArmed", true)
    require "fastlane"
    Fastlane::LaneManager.define_singleton_method(:cruise_lane) do |platform, lane, options, fastfile|
      StoreLaneNativeFixture.need(platform.nil? && lane == ENV.fetch("MOBILE_RELEASE_OPERATION") && options == {} &&
        fastfile == File.join(binding.fetch("toolingRoot"), "Fastfile"), "fixed synthetic lane seam")
      StoreLaneNativeFixture.lane_body(MobileReleaseKit::StoreLaneRuntime.current_runtime!, request)
    end
    if request.fetch("mode") == "clock-expired"
      # Runtime-only case, not the sealed Python3600s composite invocation.
      run = MobileReleaseKit::NativeProcessSpawn.monotonic_ns + 2_000_000_000
      ENV["MOBILE_RELEASE_STORE_LANE_RUN_DEADLINE_NS"] = run.to_s
      ENV["MOBILE_RELEASE_STORE_LANE_HARD_DEADLINE_NS"] = (run + 3_000_000_000).to_s
    elsif request.fetch("mode") == "clock-wrong-label"
      ENV["MOBILE_RELEASE_STORE_LANE_CLOCK"] = "unsupported-peer-domain"
    end
    need(ARGV == [ENV.fetch("MOBILE_RELEASE_OPERATION")], "fixed sealed lane argv")
    load File.join(binding.fetch("toolingRoot"), "run_lane.rb")
    raise Failure, "original product entrypoint unexpectedly returned"
  end

  def select_binding_environment(phase, source, directory)
    need(%w[source wheel].include?(phase), "binding phase")
    need(source == File.expand_path("../..", __dir__) && File.realpath(source) == source, "binding fixture source")
    work = File.join(File.dirname(source), "work")
    expected = File.join(work, "store-lane", phase, "binding-capture")
    need(File.basename(source) == "source" && directory == expected, "fixed binding directory")
    root = File.lstat(directory)
    [work, File.join(work, "store-lane"), File.dirname(expected), expected].each do |path|
      value = File.lstat(path)
      need(File.realpath(path) == path && value.directory? && !value.symlink? &&
           [value.uid, value.gid, value.mode & 0o7777, value.dev] == [0, 0, 0o755, root.dev], "root-held binding path")
    end
    %w[home tmp gem-cache bundle-config bundle-home].each do |name|
      path = File.join(expected, name)
      value = File.lstat(path)
      need(File.realpath(path) == path && value.directory? && !value.symlink? &&
           [value.uid, value.gid, value.mode & 0o7777, value.dev] ==
             [Process.euid, Process.egid, 0o700, root.dev], "binding leaf custody")
    end
    {"GEM_SPEC_CACHE" => "gem-cache", "BUNDLE_APP_CONFIG" => "bundle-config", "BUNDLE_USER_HOME" => "bundle-home"}.each do |key, name|
      need(ENV[key] == File.join(expected, name), "binding cache selector")
    end
    scratch = File.join(expected, "tmp")
    selected = %w[HOME TMPDIR TMP TEMP].map { |key| ENV[key] }
    need([[File.join(work, "home")] + [File.join(work, "tmp")] * 3,
          [File.join(expected, "home")] + [scratch] * 3].include?(selected), "binding environment placement")
    ENV.update("HOME" => File.join(expected, "home"), "TMPDIR" => scratch, "TMP" => scratch, "TEMP" => scratch)
  end

  def binding_record(arguments)
    phase = arguments.first
    need((phase == "source" && arguments.length == 5) || (phase == "wheel" && arguments.length == 7), "fixed binding form")
    _phase, prefix, source, module_root, directory, wheel, wheel_sha256 = arguments
    select_binding_environment(phase, source, directory)
    require File.join(source, "tests/workflow/installed_ruby_capture_fixture.rb")
    binding = phase == "source" ? InstalledRubyCaptureFixture.source_layout(prefix, source, profile: :store_native) :
      InstalledRubyCaptureFixture.installed_layout(prefix, source,
        wheel: original_wheel(wheel, wheel_sha256), wheel_sha256: wheel_sha256, profile: :store_native)
    need(binding.fetch("moduleRoot") == module_root, "selected Python module root")
    raw = JSON.generate(binding)
    need(raw.bytesize <= MAX_JSON, "binding output")
    STDOUT.write(raw + "\n")
    0
  end

  def simple(arguments)
    need(arguments.length == 2 && %w[clock at-exit-control].include?(arguments.first), "fixed primitive form")
    mode, path = arguments
    request = read_request(path)
    if mode == "at-exit-control"
      at_exit { File.write(File.join(request.fetch("root"), "at-exit.json"), "ordinary-at-exit-ran\n") }
      return 0
    end
    require File.join(request.fetch("binding").fetch("toolingRoot"), "native_process_spawn.rb")
    require File.join(request.fetch("binding").fetch("toolingRoot"), "native_upload_process.rb")
    sample = {"label" => MobileReleaseKit::NativeProcessSpawn.monotonic_domain,
      "nanoseconds" => MobileReleaseKit::NativeProcessSpawn.monotonic_ns,
      "helperNanoseconds" => MobileReleaseKit::NativeUploadProcess.monotonic_ns,
      "fixtureNanoseconds" => UploadProcessFixture.clock_ns, "installedClockSeconds" => InstalledRubyCaptureFixture.clock,
      "rubyEngine" => RUBY_ENGINE, "rubyVersion" => RUBY_VERSION,
      "clockIdentifier" => MobileReleaseKit::NativeProcessSpawn.monotonic_clock.fetch(1),
      "fixtureIdentifier" => UploadProcessFixture.clock_identifier,
      "clockOrigin" => InstalledRubyCaptureFixture.method_origin(MobileReleaseKit::NativeProcessSpawn.method(:monotonic_ns))}
    STDOUT.write(JSON.generate(sample) + "\n")
    0
  end
end

if $PROGRAM_NAME == __FILE__
  File.umask(0o077)
  if ARGV.first == "binding"
    exit StoreLaneNativeFixture.binding_record(ARGV.drop(1))
  elsif %w[clock at-exit-control].include?(ARGV.first)
    exit StoreLaneNativeFixture.simple(ARGV)
  else
    StoreLaneNativeFixture.composite(ENV.fetch(StoreLaneNativeFixture::REQUEST_KEY))
  end
end
