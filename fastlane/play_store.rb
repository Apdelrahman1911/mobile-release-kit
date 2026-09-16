# frozen_string_literal: true

require "digest"
require "bigdecimal"
require "fileutils"
require "json"
require "tempfile"
require "time"
require "supply"
require "supply/options"

require_relative "release_support"

module MobileReleaseKit
  # Supply 2.235.0 replaces Track.releases when it uploads or promotes a build.
  # This adapter retains Supply's metadata helpers and Publisher's upload
  # protocol, but owns the edit lifecycle and singleton, current-validated AAB send.
  class PreservingSupplyUploader < Supply::Uploader
    CANONICALIZATION = "mrk-play-track-state-v2"
    EXPECTED_TRACK_RELEASE_WRITERS = %i[
      country_targeting=
      in_app_update_priority=
      name=
      release_notes=
      status=
      user_fraction=
      version_codes=
    ].freeze
    COMMIT_REVIEW_BEHAVIOR = "ERROR_IF_IN_REVIEW"
    COMMIT_CHANGES_NOT_SENT_FOR_REVIEW = false
    MAX_JOURNAL_BYTES = 2 * 1024 * 1024
    MAX_JOURNAL_HISTORY = 256
    DISPATCH_PHASES = %w[mutation-dispatched mapping-recovery-dispatched].freeze
    AMBIGUOUS_COMMIT_ERRORS = [
      Google::Apis::TransmissionError,
      Google::Apis::RequestTimeOutError,
      Google::Apis::ServerError,
    ].freeze

    # A mapping is sent from this one verified reader, never from a pathname
    # checked earlier. This holder owns only its three Files and temporary name.
    class MappingSnapshot
      CHUNK_BYTES = 64 * 1024

      attr_reader :reader, :cleanup_errors, :cleanup_records

      def initialize(path:, size:, sha256:)
        @path, @size, @sha256 = path, size, sha256
        @slots, @cleanup_errors, @cleanup_records = {}, [], []
        @state = :new
      end

      def acquire!
        raise ContractError, "Mapping snapshot may only be acquired once" unless @state == :new

        @state = :acquiring
        source = acquire_file(:source) { File.open(@path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK) }
        original = source.stat
        unless original.file? && original.size == @size && File.realpath(@path) == @path && same_inode?(File.lstat(@path), original)
          raise ContractError, "Mapping input must be the exact regular intent-bound file"
        end
        writer = acquire_file(:writer) { Tempfile.create("mrk-play-mapping-") }
        raise ContractError, "Mapping temporary writer must be private" unless (writer.stat.mode & 0o777) == 0o600
        total = 0
        loop do
          chunk = source.read([CHUNK_BYTES, @size - total + 1].min)
          break if chunk.nil?
          raise ContractError, "Mapping input changed size while being copied" if chunk.empty? || total + chunk.bytesize > @size

          write_chunk(writer, chunk)
          total += chunk.bytesize
        end
        after = source.stat
        unless total == @size && same_inode?(after, original) && after.size == original.size &&
               after.mtime == original.mtime && after.ctime == original.ctime
          raise ContractError, "Mapping input changed while being copied"
        end
        writer.flush
        @reader = acquire_file(:reader) { File.open(@temporary.fetch(:path), File::RDONLY | File::NOFOLLOW) }
        retained = @reader.stat
        unless retained.file? && retained.size == @size && retained.nlink == 1 && same_inode?(retained, writer.stat)
          raise ContractError, "Mapping snapshot inode differs from its owned writer"
        end
        digest = Digest::SHA256.new
        copied = 0
        while (chunk = @reader.read([CHUNK_BYTES, @size - copied + 1].min))
          copied += chunk.bytesize
          raise ContractError, "Mapping snapshot changed size" if chunk.empty? || copied > @size
          digest.update(chunk)
        end
        unless copied == @size && digest.hexdigest == @sha256
          raise ContractError, "Mapping snapshot differs from the authenticated intent bytes"
        end
        @reader.rewind
        unlink_temporary
        close_slot(:source)
        close_slot(:writer)
        raise @cleanup_errors.first unless @cleanup_errors.empty?
        unless @reader.stat.nlink.zero? && @reader.stat.size == @size && @reader.stat.mtime == retained.mtime
          raise ContractError, "Mapping snapshot did not become an anonymous unchanged reader"
        end

        @state = :ready
        self
      end

      def ready? = @state == :ready
      def closed? = @state == :closed

      def cleanup!
        # These are only the four bounded local disposal transitions, never a
        # copy or network call. A pending interrupt cannot strand later slots.
        Thread.handle_interrupt(Exception => :never) do
          unlink_temporary
          %i[source writer reader].each { |role| close_slot(role) }
          @state = @cleanup_errors.empty? ? :closed : :unknown
        end
      end

      private

      def acquire_file(role)
        file = nil
        # Only acquisition and registration are inseparable. Copying and SDK
        # calls remain interruptible; no block Tempfile owner can clean twice.
        Thread.handle_interrupt(Exception => :never) do
          file = yield
          record = { role: role, resource: file, state: :open }
          @slots[role] = record
          @cleanup_records << record
          if role == :writer
            @temporary = { role: :temporary_name, path: file.path.dup.freeze, state: :open }
            @cleanup_records << @temporary
            @temporary[:identity] = file.stat
          end
        end
        file.binmode
        file.close_on_exec = true
        file
      end

      def same_inode?(left, right)
        left.file? && right.file? && left.dev == right.dev && left.ino == right.ino
      end

      def write_chunk(writer, chunk)
        offset = 0
        while offset < chunk.bytesize
          written = writer.write(chunk.byteslice(offset, chunk.bytesize - offset))
          unless written.is_a?(Integer) && written.positive? && written <= chunk.bytesize - offset
            raise ContractError, "Mapping snapshot copy made invalid write progress"
          end
          offset += written
        end
      end

      def close_slot(role)
        Thread.handle_interrupt(Exception => :never) do
          record = @slots.delete(role)
          return unless record

          # Keep the exact File on an UNKNOWN record before the one attempt.
          # Never retry a numeric FD after an ambiguous close result.
          record[:state] = :unknown
          begin
            record.fetch(:resource).close
            record[:state] = :closed
          rescue Exception => error # rubocop:disable Lint/RescueException -- preserve every cleanup outcome
            record[:error] = error
            @cleanup_errors << error
          end
        end
      end

      def unlink_temporary
        Thread.handle_interrupt(Exception => :never) do
          return unless @temporary && @temporary[:state] == :open

          @temporary[:state] = :unknown
          begin
            identity = @temporary[:identity]
            unless identity && same_inode?(File.lstat(@temporary.fetch(:path)), identity)
              raise ContractError, "Mapping temporary name no longer identifies the owned inode"
            end
            File.unlink(@temporary.fetch(:path))
            descriptor = @reader || @slots.fetch(:writer).fetch(:resource)
            raise ContractError, "Mapping temporary inode still has a name" unless descriptor.stat.nlink.zero?

            @temporary[:state] = :closed
          rescue Exception => error # rubocop:disable Lint/RescueException
            @temporary[:error] = error
            @cleanup_errors << error
          end
        end
      end
    end
    private_constant :MappingSnapshot

    attr_reader :outcome, :state_evidence, :cleanup_failures

    def self.configuration(options)
      unless options[:skip_upload_aab] == true || (options[:aab].is_a?(String) && !options[:aab].empty?)
        raise ContractError, "New Play uploads require an explicit AAB path, not Supply discovery defaults"
      end
      # Never discover a binary from the toolkit working directory or adopt
      # ambient SUPPLY_* path defaults. Only pinned caller options select files.
      paths = { apk: nil, apk_paths: nil, aab: nil, aab_paths: nil, mapping: nil, mapping_paths: nil }
      available = Supply::Options.available_options.map do |item|
        next item unless paths.key?(item.key)

        # Supply memoizes cwd-derived defaults. Explicit nil does not disable
        # Fastlane's default verification or environment/default fallback. Work
        # on clones so other Supply users retain their original option contract.
        item.dup.tap do |copy|
          copy.default_value = nil
          copy.default_value_dynamic = false
          copy.env_name = nil
          copy.env_names = []
        end
      end
      FastlaneCore::Configuration.create(available, paths.merge(options))
    end

    FACTORY_GATE = Mutex.new
    private_constant :FACTORY_GATE

    # Supply.config is process-global. One bounded, strongly class-rooted cell
    # keeps an UNKNOWN owner alive even when the original exception is frozen.
    # All inherited factories use the same base cell/gate, not subclass copies.
    def self.with_factory_custody
      base = PreservingSupplyUploader
      gate = FACTORY_GATE
      locked = false
      cell = nil
      primary = nil
      release_error = nil
      boundary_error = nil
      Thread.handle_interrupt(Exception => :never) do
        begin
          raise ContractError, "Another guarded Play factory owns this process" unless gate.try_lock

          locked = true
          if base.instance_variable_get(:@factory_custody)
            raise ContractError, "A guarded Play invocation still owns unresolved cleanup"
          end
          cell = { cleanup_errors: [], owner_thread: Thread.current, owner_fiber: Fiber.current }
          base.instance_variable_set(:@factory_custody, cell)
          install = lambda do |uploader|
            Thread.handle_interrupt(Exception => :never) do
              unless base.instance_variable_get(:@factory_custody).equal?(cell) && !cell.key?(:uploader)
                raise ContractError, "Guarded Play factory custody changed before installation"
              end
              cell[:uploader] = uploader
            end
          end
          # Configuration/construction and all operation I/O remain cancellable.
          Thread.handle_interrupt(Exception => :immediate) { yield install }
        rescue Exception => error # rubocop:disable Lint/RescueException
          owner = cell && cell[:uploader]
          primary = owner&.instance_variable_get(:@primary_error) ||
                    owner&.instance_variable_get(:@cleanup_failures)&.first || error
          if cell
            cell[:primary] = primary
            # Ruby can copy a frozen exception on raise. Do not replace the
            # exact operation error with that observed propagation value.
            cell[:escaped_failure] = error
          end
        ensure
          if locked
            settled = false
            begin
              settled = !cell || !cell[:uploader] || cell.fetch(:uploader).cleanup_confirmed?
              if !settled && !primary
                release_error = ContractError.new("Guarded Play cleanup is not positively settled")
                cell[:cleanup_errors] << release_error
              end
            rescue Exception => error # rubocop:disable Lint/RescueException
              release_error = error
              cell[:cleanup_errors] << error if cell
            ensure
              begin
                # Keep the strong cell until unlock has positively returned.
                # Other factories seeing it during this interval only refuse.
                gate.unlock
                locked = false
                if cell && settled && !release_error && base.instance_variable_get(:@factory_custody).equal?(cell)
                  base.instance_variable_set(:@factory_custody, nil)
                end
              rescue Exception => error # rubocop:disable Lint/RescueException
                release_error ||= error
                cell[:cleanup_errors] << error if cell
              end
            end
          end
        end
      end
    rescue Exception => boundary_error # rubocop:disable Lint/RescueException
      cell[:cleanup_errors] << boundary_error if cell
    ensure
      failure = primary || release_error || boundary_error
      raise failure, cause: failure.cause if failure
    end
    private_class_method :with_factory_custody

    def self.run(
      options:,
      journal_path:,
      before_mutation_guard: nil,
      after_mutation_guard: nil,
      metadata_languages: nil,
      changelog_input: nil,
      intent_sha256: nil,
      expected_bundle_sha256: nil,
      expected_bundle: nil,
      expected_mapping: nil,
      bundle_validation: nil
    )
      with_factory_custody do |install|
        Supply.config = configuration(options)
        uploader = new(
          journal_path: journal_path,
          before_mutation_guard: before_mutation_guard,
          after_mutation_guard: after_mutation_guard,
          metadata_languages: metadata_languages,
          changelog_input: changelog_input,
          intent_sha256: intent_sha256,
          expected_bundle_sha256: expected_bundle_sha256,
          expected_bundle: expected_bundle,
          expected_mapping: expected_mapping,
          bundle_validation: bundle_validation,
        )
        install.call(uploader)
        uploader.perform_upload
        uploader
      end
    end

    def self.replay_mapping(options:, journal_path:, target_guard:, intent_sha256:, expected_mapping:)
      with_factory_custody do |install|
        Supply.config = configuration(options)
        uploader = new(
          journal_path: journal_path, before_mutation_guard: target_guard,
          after_mutation_guard: target_guard, intent_sha256: intent_sha256,
          expected_mapping: expected_mapping,
        )
        install.call(uploader)
        uploader.perform_mapping_recovery
        uploader
      end
    end

    def self.observe_existing(
      options:,
      journal_path:,
      source_track:,
      destination_track:,
      version_code:,
      expected_status:
    )
      with_factory_custody do |install|
        Supply.config = configuration(options)
        uploader = new(journal_path: journal_path)
        install.call(uploader)
        present = uploader.observe_existing(
          source_track: source_track,
          destination_track: destination_track,
          version_code: version_code,
          expected_status: expected_status,
        )
        present ? uploader : nil
      end
    end

    def self.assert_dependency_contract!
      actual = AndroidPublisher::TrackRelease.instance_methods(false).grep(/=$/).sort
      return if actual == EXPECTED_TRACK_RELEASE_WRITERS.sort

      raise ContractError,
            "Pinned Google Play TrackRelease fields changed; review preservation canonicalization"
    end

    def self.track_state(track, track_name)
      raw = if track
              JSON.parse(track.to_json)
            else
              { "track" => track_name, "releases" => [] }
            end
      raw["track"] = track_name if raw["track"].to_s.empty?
      raw["releases"] = Array(raw["releases"]).map { |release| normalize_release(release) }
      raw["releases"].sort_by! { |release| canonical_json(release) }
      {
        "canonicalization" => CANONICALIZATION,
        "track" => raw.fetch("track").to_s,
        "releases" => raw.fetch("releases"),
      }
    rescue JSON::ParserError, TypeError, KeyError => e
      raise ContractError, "Google Play returned an unserializable track: #{e.class}"
    end

    def self.normalize_release(release)
      raise ContractError, "Google Play release must be an object" unless release.is_a?(Hash)

      # The API omits unset fields even when an SDK object serializes an explicit
      # nil after a setter. Those two observations mean the same Store state.
      value = deep_sort(release).reject { |_key, item| item.nil? }
      value.delete("releaseNotes") if value["releaseNotes"] == []
      # JSON floats do not have a cross-language canonical representation.
      # Evidence uses a lossless decimal spelling of the API's JSON number;
      # original Track/TrackRelease objects are retained for the actual write.
      if value.key?("userFraction") && !value["userFraction"].nil?
        fraction = BigDecimal(value.fetch("userFraction").to_s)
        unless fraction.finite? && fraction.positive? && fraction < 1
          raise ContractError, "Google Play rollout fraction is invalid"
        end
        value["userFraction"] = fraction.to_s("F").sub(/0+\z/, "")
      end
      if value.key?("versionCodes")
        value["versionCodes"] = Array(value["versionCodes"]).map(&:to_s).sort
      end
      if value.key?("releaseNotes")
        value["releaseNotes"] = Array(value["releaseNotes"])
                                  .map { |item| deep_sort(item) }
                                  .sort_by { |item| canonical_json(item) }
      end
      targeting = value["countryTargeting"]
      if targeting.is_a?(Hash) && targeting.key?("countries")
        targeting["countries"] = Array(targeting["countries"]).map(&:to_s).sort
      end
      deep_sort(value)
    rescue ArgumentError, TypeError
      raise ContractError, "Google Play returned an invalid release value"
    end

    def self.deep_sort(value)
      case value
      when Hash
        value.keys.map(&:to_s).sort.each_with_object({}) do |key, result|
          source_key = value.key?(key) ? key : value.keys.find { |candidate| candidate.to_s == key }
          result[key] = deep_sort(value.fetch(source_key))
        end
      when Array
        value.map { |item| deep_sort(item) }
      else
        value
      end
    end

    def self.canonical_json(value)
      JSON.generate(deep_sort(value))
    end

    def self.digest(value, domain: "track")
      Digest::SHA256.hexdigest("#{CANONICALIZATION}:#{domain}:#{canonical_json(value)}")
    end

    def self.read_journal_history(path, intent_sha256:, package_name:)
      path = File.expand_path(path)
      return nil unless File.exist?(path) || File.symlink?(path)

      unless !File.symlink?(path) && File.file?(path) && File.realpath(path) == path
        raise ContractError, "Play operation journal must be a regular non-symlink file"
      end
      raw = File.open(path, File::RDONLY | File::NOFOLLOW) do |file|
        raise ContractError, "Play operation journal must be a regular file" unless file.stat.file?
        file.read(MAX_JOURNAL_BYTES + 1) || +""
      end
      raise ContractError, "Play operation journal exceeds its diagnostic bound" if raw.bytesize > MAX_JOURNAL_BYTES

      document = MobileReleaseKit.strict_json(raw.force_encoding(Encoding::UTF_8), label: "Play operation journal")
      unless document.is_a?(Hash) && document["schemaVersion"] == 1 &&
             document["kind"] == "google-play-track-state-journal" && document["canonicalization"] == CANONICALIZATION &&
             document["packageName"] == package_name &&
             (intent_sha256.nil? ? !document.key?("operationIntentSha256") : document["operationIntentSha256"] == intent_sha256)
        raise ContractError, "Play operation journal belongs to another intent, application or format"
      end
      history = document["history"]
      unless history.is_a?(Array) && history.length <= 10_000 && history.all? do |row|
        row.is_a?(Hash) && (row.keys - %w[phase observedAt failureClass failureRole]).empty? &&
          row["phase"].is_a?(String) && row["phase"].match?(/\A[a-z][a-z0-9-]{0,99}\z/) &&
          row["observedAt"].is_a?(String) && row["observedAt"].match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/) &&
          (!row.key?("failureClass") || (row["failureClass"].is_a?(String) && row["failureClass"].match?(/\A[A-Za-z_][A-Za-z0-9_:]{0,199}\z/))) &&
          (!row.key?("failureRole") || %w[commit reconciliation terminal].include?(row["failureRole"]))
      end
        raise ContractError, "Play operation journal history is invalid"
      end
      history
    rescue SystemCallError, IOError
      raise ContractError, "Play operation journal could not be read safely"
    end

    def self.compact_journal_history(history)
      return history if history.length <= MAX_JOURNAL_HISTORY

      # Dispatch signals are monotonic, even after hundreds of failed later
      # invocations. They are local ambiguity signals, never Store/auth proof.
      retained = DISPATCH_PHASES.filter_map { |phase| history.index { |row| row["phase"] == phase } }
      start = history.length - (MAX_JOURNAL_HISTORY - retained.length)
      (retained + (start...history.length).to_a).uniq.sort.map { |index| history.fetch(index) }
    end

    def initialize(
      journal_path:,
      client: nil,
      before_mutation_guard: nil,
      after_mutation_guard: nil,
      metadata_languages: nil,
      changelog_input: nil,
      intent_sha256: nil,
      expected_bundle_sha256: nil,
      expected_bundle: nil,
      expected_mapping: nil,
      bundle_validation: nil
    )
      super()
      self.class.assert_dependency_contract!
      @journal_path = File.expand_path(journal_path)
      @client = client if client
      @guard = nil
      @state_evidence = nil
      @mutation_edit_id = nil
      @readback_edit_id = nil
      @outcome = nil
      @primary_error = nil
      @before_mutation_guard = before_mutation_guard
      @after_mutation_guard = after_mutation_guard
      @metadata_languages = metadata_languages
      @changelog_input = changelog_input
      @intent_sha256 = intent_sha256
      @expected_bundle_sha256 = expected_bundle_sha256
      @expected_bundle = expected_bundle
      @expected_mapping = expected_mapping
      @bundle_validation = bundle_validation
      @cleanup_failures = []
      @edit_cleanup_records = []
      @active_edit_owner = nil
      @commit_failure_class = nil
      @reconciliation_failure_class = nil
      @terminal_failure_class = nil
      @journal_history = self.class.read_journal_history(
        @journal_path, intent_sha256: @intent_sha256, package_name: Supply.config[:package_name].to_s,
      )
    end

    # Mirrors the small, pinned Supply orchestration deliberately. Unlike
    # Supply::Uploader#perform_upload, this puts a complete state check directly
    # before a non-retrying, review-safe commit.
    def perform_upload
      claim_invocation!
      with_owned_operation { perform_upload_once }
    end

    def perform_upload_once
      FastlaneCore::PrintTable.print_values(
        config: Supply.config,
        hide_keys: [:issuer],
        mask_keys: [:json_key_data],
        title: "Summary for guarded supply #{Fastlane::VERSION}",
      )
      verify_config!
      reject_unsafe_supply_options!
      validate_changelog_input!
      prepare_mapping_snapshot!
      begin_owned_edit!
      @mutation_edit_id = client.current_edit.id.to_s
      @mapping_edit_owner = @active_edit_owner if @mapping_snapshot
      precondition = @before_mutation_guard&.call(client)

      version_codes = reusable_bundle_version_codes(precondition)
      if !Supply.config[:skip_upload_aab] && version_codes.empty?
        version_codes = upload_validated_bundle
      end
      validate_uploaded_version_codes!(version_codes) unless version_codes.empty?
      # Do not mint this invocation's prior-execution marker before the final
      # pre-upload read. Foreign matching state appearing during validation is
      # not recovery authority. Reuse/promotion still journals before mutation.
      persist_journal("mutation-dispatched")
      @mapping_send_due = true
      upload_mapping(version_codes)

      if !version_codes.empty?
        update_track(version_codes)
      elsif Supply.config[:track_promote_to]
        promote_track
      elsif !Supply.config[:rollout].nil? && Supply.config[:track].to_s != ""
        FastlaneCore::UI.user_error!("Guarded Play adapter does not support rollout mutation")
      else
        FastlaneCore::UI.user_error!("Guarded Play adapter requires one upload or promotion")
      end

      target_track = Supply.config[:track_promote_to] || Supply.config[:track]
      perform_upload_meta(version_codes, target_track)
      verify_guard_before_commit!
      @after_mutation_guard&.call(client)
      assert_owned_edit!
      client.validate_current_edit!
      persist_journal("validated-before-commit")
      if Supply.config[:validate_only]
        FastlaneCore::UI.success("Successfully validated the guarded Google Play edit")
        return self
      end

      commit_and_reconcile!
      self
    end
    private :perform_upload_once

    # Publisher has no mapping digest readback. Even when the track is already
    # final, recovery must replay the authenticated bytes in a fresh edit and
    # receive a successful commit response. Track-only readback cannot prove an
    # ambiguous mapping commit; another recovery can safely replay the same file.
    def perform_mapping_recovery
      claim_invocation!
      with_owned_operation(failure_phase: "mapping-recovery-failed", cancellation_phase: "mapping-recovery-failed") do
        perform_mapping_recovery_once
      end
    end

    def perform_mapping_recovery_once
      verify_config!
      reject_unsafe_supply_options!
      raise ContractError, "Mapping recovery requires exactly one mapping" unless Supply.config[:mapping] && !Supply.config[:mapping_paths]
      prepare_mapping_snapshot!
      begin_owned_edit!
      @mutation_edit_id = client.current_edit.id.to_s
      @mapping_edit_owner = @active_edit_owner
      @before_mutation_guard&.call(client)
      persist_journal("mapping-recovery-dispatched")
      @mapping_send_due = true
      upload_mapping([@invocation_version])
      @after_mutation_guard&.call(client)
      assert_owned_edit!
      client.validate_current_edit!
      options = Google::Apis::RequestOptions.new
      options.retries = 0
      assert_owned_edit!
      client.client.commit_edit(
        client.current_package_name, client.current_edit.id,
        changes_in_review_behavior: COMMIT_REVIEW_BEHAVIOR,
        changes_not_sent_for_review: COMMIT_CHANGES_NOT_SENT_FOR_REVIEW,
        options: options,
      )
      clear_active_edit_handle!
      begin_owned_edit!
      @readback_edit_id = client.current_edit.id.to_s
      @after_mutation_guard&.call(client)
      @outcome = "reconciled"
      persist_journal("mapping-replayed-and-committed")
      self
    end
    private :perform_mapping_recovery_once

    def observe_existing(source_track:, destination_track:, version_code:, expected_status:)
      claim_invocation!
      with_owned_operation do
        observe_existing_once(source_track: source_track, destination_track: destination_track, version_code: version_code, expected_status: expected_status)
      end
    end

    def observe_existing_once(source_track:, destination_track:, version_code:, expected_status:)
      verify_config!
      reject_unsafe_supply_options!
      begin_owned_edit!
      @readback_edit_id = client.current_edit.id.to_s
      destination = fetch_track(destination_track)
      destination_state = self.class.track_state(destination, destination_track)
      matches = releases_with_code(destination_state, version_code)
      return false if matches.empty?

      require_target_release!(destination_state, version_code, expected_status)
      source = fetch_track(source_track)
      source_state = self.class.track_state(source, source_track)
      source_matches = releases_with_code(source_state, version_code)
      source_transition = if source_matches.empty?
                            "already-deactivated"
                          else
                            require_source_release!(source_state, version_code)
                            "retained"
                          end
      @outcome = "already-present"
      @guard = {
        destination_name: destination_track,
        destination_before: destination_state,
        destination_expected: destination_state,
        target_code: version_code.to_i,
        target_status: expected_status,
        source_name: source_track,
        source_before: source_state,
        source_expected: source_state,
        source_observed: source_state,
        source_transition: source_transition,
      }
      build_state_evidence!(destination_state, source_state, mode: "observation")
      persist_journal("observed-existing")
      true
    end
    private :observe_existing_once

    def cleanup_confirmed?
      @cleanup_failures.empty? && @active_edit_owner.nil? && (!@mapping_snapshot || @mapping_snapshot.closed?)
    end

    private

    def with_owned_operation(failure_phase: "failed", cancellation_phase: "cancelled")
      boundary_error = nil
      # Install the cleanup handoff before any owned resource can be acquired.
      # Only bookkeeping/disposal transitions are deferred: the whole body,
      # abort request and diagnostic I/O explicitly remain interruptible.
      Thread.handle_interrupt(Exception => :never) do
        begin
          Thread.handle_interrupt(Exception => :immediate) { yield }
        rescue Exception => error # rubocop:disable Lint/RescueException
          phase = error.is_a?(Interrupt) || error.is_a?(SystemExit) ? cancellation_phase : failure_phase
          record_operation_failure(phase, error)
        ensure
          finalize_owned_resources
        end
      end
    rescue Exception => boundary_error # rubocop:disable Lint/RescueException
      # Ruby checks pending exceptions while restoring the caller's mask.
      # Disposal has run; retain this late error without replacing the body or
      # first cleanup error. It must never turn into a successful return.
      record_cleanup_failure(boundary_error)
      persist_cleanup_diagnostics([boundary_error])
    ensure
      failure = @primary_error || @cleanup_failures.first || boundary_error
      # Preserve the captured object and cause in our records. Ruby 3.3 itself
      # can duplicate a frozen exception during raise; do not mutate or wrap it.
      raise failure, cause: failure.cause if failure
    end

    def claim_invocation!
      # This is outside the operation body's rescue/ensure. A rejected inner
      # invocation must not dispose the outer invocation's edit or reader.
      cell = PreservingSupplyUploader.instance_variable_get(:@factory_custody)
      if cell && !cell[:uploader].equal?(self)
        raise ContractError, "Another guarded Play factory retains process ownership"
      end
      raise ContractError, "A guarded Play uploader is single-use" if @invocation_started

      @invocation_started = true
      @owner_thread, @owner_fiber = Thread.current, Fiber.current
      @invocation_config = Supply.config
      @invocation_package = Supply.config[:package_name].to_s.dup.freeze
      version = Supply.config[:version_code]
      unless (version.is_a?(Integer) || version.is_a?(String)) && version.to_s.match?(/\A[1-9][0-9]*\z/) && !@invocation_package.empty?
        raise ContractError, "Guarded Play invocation requires an explicit package and positive version"
      end
      @invocation_version = version.to_i
      @mapping_path = Supply.config[:mapping]
      @mapping_path = @mapping_path.dup.freeze if @mapping_path.is_a?(String)
      if @expected_mapping.is_a?(Hash)
        @expected_mapping = @expected_mapping.to_h { |key, value| [key, value.is_a?(String) ? value.dup.freeze : value] }.freeze
      end
      filename = @expected_mapping.is_a?(Hash) && @expected_mapping["fileName"]
      @mapping_type = filename.is_a?(String) && (File.extname(filename).downcase == ".zip" ? "nativeCode" : "proguard").freeze
    end

    def assert_unbatched_owner!
      unless Thread.current.equal?(@owner_thread) && Fiber.current.equal?(@owner_fiber) && Thread.current[:google_api_batch].nil?
        raise ContractError, "Guarded Play requests require their original synchronous non-batch context"
      end
    end

    def prepare_mapping_snapshot!
      assert_unbatched_owner!
      if Supply.config[:mapping_paths] || Supply.config[:mapping] != @mapping_path
        raise ContractError, "Guarded Play mapping selection changed or selected multiple paths"
      end
      return if @mapping_path.nil? && @expected_mapping.nil?

      bound = @expected_mapping
      unless !Supply.config[:track_promote_to] && @mapping_path.is_a?(String) &&
             @mapping_path.start_with?(File::SEPARATOR) && !@mapping_path.match?(/[\x00-\x1f\x7f]/) &&
             bound.is_a?(Hash) && bound["logicalName"] == "android-mapping" &&
             bound["size"].is_a?(Integer) && bound["size"].positive? &&
             bound["sha256"].is_a?(String) && bound["sha256"].match?(/\A[0-9a-f]{64}\z/) &&
             bound["fileName"].is_a?(String) && !bound["fileName"].empty? &&
             (File.extname(@mapping_path).downcase == ".zip") == (File.extname(bound["fileName"]).downcase == ".zip")
        raise ContractError, "Mapping path, bytes and type require one authenticated intent record"
      end
      @mapping_snapshot = MappingSnapshot.new(path: @mapping_path, size: bound.fetch("size"), sha256: bound.fetch("sha256"))
      @mapping_snapshot.acquire!
    end

    def begin_owned_edit!
      assert_unbatched_owner!
      unless Supply.config.equal?(@invocation_config) && Supply.config[:package_name].to_s == @invocation_package
        raise ContractError, "Guarded Play invocation configuration changed"
      end
      current = client
      service = current.client
      if @invocation_client && (!current.equal?(@invocation_client) || !service.equal?(@invocation_service))
        raise ContractError, "Guarded Play invocation client changed"
      end
      raise ContractError, "Guarded Play adapter cannot adopt an existing edit" if @active_edit_owner || current.current_edit

      @invocation_client, @invocation_service = current, service
      owner = { client: current, service: service, package: @invocation_package, state: :opening }
      @edit_cleanup_records << owner
      @active_edit_owner = owner
      current.begin_edit(package_name: @invocation_package)
      owner[:edit] = current.current_edit
      owner[:id] = current.current_edit&.id.to_s.dup.freeze
      unless owner[:edit] && !owner[:id].empty? && current.current_package_name.to_s == @invocation_package
        raise ContractError, "Google Play did not return the owned package/edit"
      end
      owner[:state] = :open
      assert_owned_edit!(owner)
      owner
    end

    def assert_owned_edit!(owner = @active_edit_owner)
      assert_unbatched_owner!
      unless owner && owner[:state] == :open && @active_edit_owner.equal?(owner) &&
             @client.equal?(owner[:client]) && @client.client.equal?(owner[:service]) &&
             @client.current_edit.equal?(owner[:edit]) && @client.current_edit.id.to_s == owner[:id] &&
             @client.current_package_name.to_s == owner[:package] &&
             Supply.config.equal?(@invocation_config) && Supply.config[:package_name].to_s == @invocation_package &&
             Supply.config[:version_code].to_s == @invocation_version.to_s
        raise ContractError, "Guarded Play request no longer owns its original client/package/edit/version"
      end
    end

    def upload_mapping(version_codes)
      unless @mapping_send_due && !@mapping_send_consumed
        raise ContractError, "Mapping send is not authorized or has already been consumed"
      end
      unless @mapping_snapshot
        raise ContractError, "Unbound ambient mapping cannot be uploaded" if Supply.config[:mapping] || Supply.config[:mapping_paths]

        @mapping_send_consumed = true
        return
      end
      unless @mapping_snapshot.ready? && version_codes.is_a?(Array) && version_codes.length == 1 &&
             (version_codes.first.is_a?(Integer) || version_codes.first.is_a?(String)) &&
             version_codes.first.to_s == @invocation_version.to_s && Supply.config[:mapping] == @mapping_path && !Supply.config[:mapping_paths]
        raise ContractError, "Mapping send differs from its authenticated singleton binding"
      end
      assert_owned_edit!(@mapping_edit_owner)
      reader = @mapping_snapshot.reader
      reader.rewind
      options = Google::Apis::RequestOptions.new
      options.retries = 0
      # No application callback between this final no-batch check, consuming
      # the one-use grant and invoking the pinned synchronous generated API.
      assert_unbatched_owner!
      @mapping_send_consumed = true
      @mapping_send_due = false
      @mapping_edit_owner.fetch(:service).upload_edit_deobfuscationfile(
        @invocation_package, @mapping_edit_owner.fetch(:id), @invocation_version, @mapping_type,
        upload_source: reader, content_type: "application/octet-stream", options: options,
      )
    end

    def validate_changelog_input!
      if Supply.config[:skip_upload_changelogs]
        raise ContractError, "Skipped Play changelogs must not receive replacement notes" unless @changelog_input.nil?
        return
      end
      unless @changelog_input.is_a?(Hash) && @changelog_input.length == 2 &&
             @changelog_input.key?(:notes) && @changelog_input.key?(:version_code)
        raise ContractError, "Play changelog upload requires validated version-bound notes"
      end
      version = @changelog_input.fetch(:version_code)
      MobileReleaseKit.validate_android_note_scope(@metadata_languages, version)
      unless version.to_s == Supply.config[:version_code].to_s
        raise ContractError, "Play changelog version differs from the upload/promotion version"
      end
      notes = @changelog_input.fetch(:notes)
      unless notes.is_a?(Array) && notes.length == @metadata_languages.length
        raise ContractError, "Play changelog upload must bind each configured locale exactly once"
      end
      notes.each do |note|
        unless note.is_a?(Hash) && note.length == 2 && note.key?("language") && note.key?("text") && note["language"].is_a?(String)
          raise ContractError, "Play changelog records require only language and text"
        end
      end
      unless notes.map { |note| note.fetch("language") }.sort == @metadata_languages.sort
        raise ContractError, "Play changelog locale scope differs from configuration"
      end
      @validated_changelog_version = version.to_s.freeze
      @metadata_languages = @metadata_languages.map { |language| language.dup.freeze }.freeze
      @validated_changelogs = notes.to_h do |note|
        [note.fetch("language").dup.freeze, MobileReleaseKit.validate_android_release_note(note.fetch("text")).freeze]
      end.freeze
    end

    def upload_changelog(language, version_code)
      unless @validated_changelogs && version_code.to_s == @validated_changelog_version && @validated_changelogs.key?(language)
        raise ContractError, "Play changelog worker differs from the validated locale/version scope"
      end
      AndroidPublisher::LocalizedText.new(language: language, text: @validated_changelogs.fetch(language))
    end

    # Keep metadata on the original edit/configuration owner. Supply's pinned
    # QueueWorker can leave other locale workers running when a join raises;
    # our edit cleanup must never race a worker still issuing metadata requests.
    def perform_upload_meta(version_codes, track_name)
      return unless (!Supply.config[:skip_upload_metadata] || !Supply.config[:skip_upload_images] ||
                     !Supply.config[:skip_upload_changelogs] || !Supply.config[:skip_upload_screenshots]) && metadata_path

      # The invocation and uploaded-version guards already require one positive
      # version; promotion uses the same explicit configuration fallback.
      version_codes = [Supply.config[:version_code]] if version_codes.empty?
      version_codes.each do |version_code|
        FastlaneCore::UI.user_error!("Could not find folder #{metadata_path}") unless File.directory?(metadata_path)
        track, release = fetch_track_and_release!(track_name, version_code)
        FastlaneCore::UI.user_error!("Unable to find the requested track - '#{Supply.config[:track]}'") unless track
        FastlaneCore::UI.user_error!("Could not find release for version code '#{version_code}' to update changelog") unless release

        release_notes = []
        all_languages.reject { |language| language.start_with?(".") }.each do |language|
          begin
            FastlaneCore::UI.message("Preparing uploads for language '#{language}'...")
            start_time = Time.now
            listing = client.listing_for_language(language)
            upload_metadata(language, listing) unless Supply.config[:skip_upload_metadata]
            upload_images(language) unless Supply.config[:skip_upload_images]
            upload_screenshots(language) unless Supply.config[:skip_upload_screenshots]
            release_notes << upload_changelog(language, version_code) unless Supply.config[:skip_upload_changelogs]
            FastlaneCore::UI.message("Uploaded all items for language '#{language}'... (#{Time.now - start_time} secs)")
          rescue StandardError => error
            # Match Supply's ordinary per-locale error context without wrapping
            # Interrupt/SystemExit or allowing a later locale to begin.
            FastlaneCore::UI.abort_with_message!("#{language} - #{error}")
          end
        end
        upload_changelogs(release_notes, release, track, track_name) unless release_notes.empty?
      end
    end

    def all_languages
      # Supply otherwise scans every directory, including locales not authorized
      # by configuration or the pre-mutation metadata target.
      @metadata_languages || super
    end

    def reusable_bundle_version_codes(precondition)
      return [] if Supply.config[:skip_upload_aab]

      unless precondition.is_a?(Hash) && precondition[:phase] == :before && precondition[:bundles].is_a?(Array)
        raise ContractError, "AAB reuse/upload requires a complete classified Store precondition"
      end
      expected_code = Supply.config[:version_code].to_i
      # Consume the SAME full observation whose before/target/authority checks
      # passed. A separate bundle read must not introduce newly visible foreign
      # state after those checks and silently authorize its reuse.
      matches = precondition.fetch(:bundles).select { |bundle| bundle.fetch("versionCode") == expected_code }
      return [] if matches.empty?
      raise ContractError, "Google Play returned duplicate bundles for the target version code" unless matches.length == 1
      raise ContractError, "Operation intent does not bind the candidate AAB digest" unless @expected_bundle_sha256
      unless matches.first.fetch("sha256") == @expected_bundle_sha256
        raise ContractError, "Existing Google Play bundle digest differs from the operation intent"
      end

      persist_journal("reusing-exact-bundle")
      [expected_code]
    end

    def upload_validated_bundle
      unless @bundle_validation.respond_to?(:call) && @before_mutation_guard.respond_to?(:call)
        raise ContractError, "Every new AAB upload requires current validation and a full Store precondition guard"
      end
      aab = final_bundle_path!
      @bundle_validation.call(aab)
      # Slow validation may span unrelated Store changes or edit invalidation.
      # Never silently replace this edit or adopt a first-invocation appearance.
      precondition = @before_mutation_guard.call(client)
      existing = reusable_bundle_version_codes(precondition)
      return existing unless existing.empty?

      options = Google::Apis::RequestOptions.new
      options.retries = 0
      persist_journal("mutation-dispatched")
      aab = final_bundle_path!
      assert_owned_edit!
      result = client.client.upload_edit_bundle(
        client.current_package_name, client.current_edit.id,
        upload_source: aab, content_type: "application/octet-stream",
        ack_bundle_installation_warning: Supply.config[:ack_bundle_installation_warning],
        options: options,
      )
      # Own the logical request rather than inherited Supply upload_bundle or
      # call_google_api retry loops. SDK same-session resumable transfers/auth
      # refresh are still used; failure never dispatches another logical upload.
      codes = [result.version_code]
      validate_uploaded_version_codes!(codes)
      codes
    end

    def final_bundle_path!
      path = Supply.config[:aab]
      unless @expected_bundle.is_a?(Hash) && @expected_bundle["logicalName"] == "android-aab" &&
             @expected_bundle["size"].is_a?(Integer) && @expected_bundle["size"].positive? &&
             @expected_bundle["sha256"].is_a?(String) && @expected_bundle["sha256"].match?(/\A[0-9a-f]{64}\z/) &&
             @expected_bundle["sha256"] == @expected_bundle_sha256 &&
             path.is_a?(String) && path.start_with?(File::SEPARATOR) && !path.match?(/[\x00-\x1f\x7f]/) &&
             File.file?(path) && !File.symlink?(path) && File.realpath(path) == path &&
             File.basename(path) == @expected_bundle["fileName"] && File.size(path) == @expected_bundle["size"] &&
             Digest::SHA256.file(path).hexdigest == @expected_bundle_sha256
        raise ContractError, "New AAB upload requires the exact regular original intent-bound bundle"
      end
      path
    rescue SystemCallError
      raise ContractError, "New AAB upload requires the exact regular original intent-bound bundle"
    end

    def reject_unsafe_supply_options!
      unless Supply.config[:skip_upload_apk] == true && !Supply.config[:apk] && !Supply.config[:apk_paths] && !Supply.config[:aab_paths]
        raise ContractError, "Guarded Play adapter only supports an explicit singleton AAB, never APKs or batch uploads"
      end
      unless Supply.config[:skip_upload_aab] == true || (Supply.config[:aab].is_a?(String) && !Supply.config[:aab].empty? && !Supply.config[:track_promote_to])
        raise ContractError, "New Play uploads require one explicit AAB path and no promotion options"
      end
      if Supply.config[:mapping_paths] || (Supply.config[:track_promote_to] && (Supply.config[:mapping] || @expected_mapping))
        raise ContractError, "Guarded Play adapter forbids mapping batches and mappings during promotion"
      end
      if Supply.config[:version_codes_to_retain]&.any?
        FastlaneCore::UI.user_error!("Guarded Play adapter does not accept version_codes_to_retain")
      end
      if Supply.config[:changes_not_sent_for_review] != COMMIT_CHANGES_NOT_SENT_FOR_REVIEW
        FastlaneCore::UI.user_error!("Guarded Play adapter requires changes_not_sent_for_review=false")
      end
      if Supply.config[:rollout] || Supply.config[:in_app_update_priority]
        FastlaneCore::UI.user_error!("Guarded Play adapter does not accept rollout or update-priority mutation")
      end
      return unless Supply.config[:rescue_changes_not_sent_for_review]

      FastlaneCore::UI.user_error!("Guarded Play adapter forbids review-policy retry fallback")
    end

    def validate_uploaded_version_codes!(version_codes)
      expected = @invocation_version.to_s
      unless version_codes.length == 1 && (version_codes.first.is_a?(Integer) || version_codes.first.is_a?(String)) && version_codes.first.to_s == expected
        FastlaneCore::UI.user_error!("Google Play upload returned an unexpected version code")
      end
    end

    def update_track(version_codes)
      track_name = Supply.config[:track]
      current = fetch_track(track_name)
      before = self.class.track_state(current, track_name)
      version_code = version_codes.fetch(0).to_i
      reject_existing_target!(before, version_code)
      release = AndroidPublisher::TrackRelease.new(
        name: Supply.config[:version_name],
        status: Supply.config[:release_status],
        version_codes: [version_code],
      )
      desired = current || AndroidPublisher::Track.new(track: track_name, releases: [])
      desired.releases = Array(desired.releases) + [release]
      @guard = {
        destination_name: track_name,
        destination_before: before,
        target_code: version_code,
        target_status: Supply.config[:release_status],
      }
      persist_journal("prepared-before-track-update")
      client.update_track(track_name, desired)
      verify_initial_update!
    end

    def promote_track
      source_name = Supply.config[:track]
      destination_name = Supply.config[:track_promote_to]
      version_code = Supply.config[:version_code].to_i
      source = fetch_track(source_name)
      source_state = self.class.track_state(source, source_name)
      source_release = require_source_release!(source_state, version_code)
      destination = fetch_track(destination_name)
      destination_before = self.class.track_state(destination, destination_name)
      reject_existing_target!(destination_before, version_code)

      promoted = AndroidPublisher::TrackRelease.from_json(JSON.generate(source_release))
      promoted.version_codes = [version_code]
      promoted.status = Supply.config[:track_promote_release_status]
      promoted.user_fraction = nil
      desired = destination || AndroidPublisher::Track.new(track: destination_name, releases: [])
      desired.releases = Array(desired.releases) + [promoted]
      @guard = {
        destination_name: destination_name,
        destination_before: destination_before,
        target_code: version_code,
        target_status: Supply.config[:track_promote_release_status],
        source_name: source_name,
        source_before: source_state,
        source_transition: nil,
      }
      persist_journal("prepared-before-track-update")
      client.update_track(destination_name, desired)
      verify_initial_update!
    end

    def verify_initial_update!
      current = state_for(@guard.fetch(:destination_name))
      verify_preserved_destination!(current, allow_target_notes_change: false)
      if @guard[:source_name]
        source = state_for(@guard.fetch(:source_name))
        @guard[:source_after_update] = source
        verify_source_transition!(source)
      end
      @guard[:target_baseline] = require_target_release!(
        current,
        @guard.fetch(:target_code),
        @guard.fetch(:target_status),
      )
      persist_journal("track-updated-in-edit")
    end

    def verify_guard_before_commit!
      current = state_for(@guard.fetch(:destination_name))
      verify_preserved_destination!(current, allow_target_notes_change: true)
      @guard[:destination_expected] = current
      if @guard[:source_name]
        source = state_for(@guard.fetch(:source_name))
        verify_source_transition!(source)
        @guard[:source_expected] = source
      end
    end

    def verify_preserved_destination!(current, allow_target_notes_change:)
      before = @guard.fetch(:destination_before)
      code = @guard.fetch(:target_code)
      before_unrelated = releases_without_code(before, code)
      current_unrelated = releases_without_code(current, code)
      unless before.fetch("releases").length == before_unrelated.length
        raise ContractError, "Target version code already existed in the destination Play track"
      end
      unless before_unrelated == current_unrelated
        raise ContractError, "Google Play edit changed an unrelated destination-track release"
      end
      unless current.fetch("releases").length == before.fetch("releases").length + 1
        raise ContractError, "Google Play edit added or removed an unexpected destination release"
      end
      target = require_target_release!(current, code, @guard.fetch(:target_status))
      return unless @guard[:target_baseline]

      expected_target = @guard.fetch(:target_baseline)
      if allow_target_notes_change
        target = target.reject { |key, _value| key == "releaseNotes" }
        expected_target = expected_target.reject { |key, _value| key == "releaseNotes" }
      end
      return if target == expected_target

      raise ContractError, "Google Play metadata update changed a protected target-release field"
    end

    def verify_source_transition!(current)
      before = @guard.fetch(:source_before)
      code = @guard.fetch(:target_code)
      unless releases_without_code(current, code) == releases_without_code(before, code)
        raise ContractError, "Google Play changed an unrelated source-track release"
      end

      matches = releases_with_code(current, code)
      transition = if matches.empty?
                     expected = before.merge("releases" => releases_without_code(before, code))
                     unless current == expected
                       raise ContractError, "Google Play made an unsupported source-track transition"
                     end
                     "deactivated"
                   else
                     require_source_release!(current, code)
                     unless current == before
                       raise ContractError, "Google Play changed the promoted source release"
                     end
                     "retained"
                   end
      if @guard[:source_transition] == "deactivated" && transition == "retained"
        raise ContractError, "Google Play reactivated the promoted source release within one edit"
      end
      @guard[:source_transition] = transition
      transition
    end

    def require_source_release!(state, version_code)
      matches = releases_with_code(state, version_code)
      unless matches.length == 1
        raise ContractError, "Source Play track must contain the target version code exactly once"
      end
      release = matches.fetch(0)
      unless release.fetch("versionCodes", []) == [version_code.to_i.to_s]
        raise ContractError, "Source Play release must contain only the target version code"
      end
      unless release["status"].to_s == "completed"
        raise ContractError, "Source Play release must still have completed status"
      end
      release
    end

    def require_target_release!(state, version_code, expected_status)
      matches = releases_with_code(state, version_code)
      unless matches.length == 1
        raise ContractError, "Destination Play track must contain the target version code exactly once"
      end
      release = matches.fetch(0)
      unless release.fetch("versionCodes", []) == [version_code.to_i.to_s]
        raise ContractError, "Destination Play release must contain only the target version code"
      end
      unless release["status"].to_s == expected_status.to_s
        raise ContractError,
              "Destination Play release status is #{release['status']}, expected #{expected_status}"
      end
      release
    end

    def reject_existing_target!(state, version_code)
      return if releases_with_code(state, version_code).empty?

      raise ContractError, "Target version code already exists in the destination Play track"
    end

    def releases_with_code(state, version_code)
      code = version_code.to_i.to_s
      state.fetch("releases").select { |release| release.fetch("versionCodes", []).include?(code) }
    end

    def releases_without_code(state, version_code)
      code = version_code.to_i.to_s
      state.fetch("releases")
           .reject { |release| release.fetch("versionCodes", []).include?(code) }
           .sort_by { |release| self.class.canonical_json(release) }
    end

    def fetch_track(track_name)
      matches = client.tracks(track_name)
      raise ContractError, "Google Play returned duplicate track records for #{track_name}" if matches.length > 1

      matches.first
    end

    def state_for(track_name)
      self.class.track_state(fetch_track(track_name), track_name)
    end

    def commit_and_reconcile!
      request_options = Google::Apis::RequestOptions.new
      request_options.retries = 0
      begin
        assert_owned_edit!
        client.client.commit_edit(
          client.current_package_name,
          client.current_edit.id,
          changes_in_review_behavior: COMMIT_REVIEW_BEHAVIOR,
          changes_not_sent_for_review: COMMIT_CHANGES_NOT_SENT_FOR_REVIEW,
          options: request_options,
        )
        clear_active_edit_handle!
        @outcome = "mutated"
      rescue *AMBIGUOUS_COMMIT_ERRORS => commit_error
        reconcile_ambiguous_commit!(commit_error)
        return
      end
      verify_committed_state!
    end

    def reconcile_ambiguous_commit!(commit_error)
      clear_active_edit_handle!
      @commit_failure_class = commit_error.class.name
      persist_journal(
        "commit-response-ambiguous",
        failure_class: commit_error.class.name,
        failure_role: "commit",
      )
      begin
        verify_committed_state!(reconciled: true)
      rescue Interrupt, SystemExit
        raise
      rescue Exception => readback_error # rubocop:disable Lint/RescueException
        @outcome = nil
        @reconciliation_failure_class = readback_error.class.name
        persist_journal(
          "reconciliation-failed",
          failure_class: readback_error.class.name,
          failure_role: "reconciliation",
        ) rescue nil
        raise ContractError,
              "Google Play commit outcome is ambiguous; exact state could not be reconciled: " \
              "#{readback_error.class}",
              cause: commit_error
      end
    end

    def verify_committed_state!(reconciled: false)
      # This is terminal readback on both commit paths. The invocation driver
      # owns its abort together with mapping disposal, so no inner ensure can
      # replace a real readback failure or race the final cleanup handoff.
      begin_owned_edit!
      @readback_edit_id = client.current_edit.id.to_s
      destination = state_for(@guard.fetch(:destination_name))
      @guard[:destination_observed] = destination
      persist_journal("readback-destination-observed")
      source = nil
      if @guard[:source_name]
        source = state_for(@guard.fetch(:source_name))
        @guard[:source_observed] = source
        persist_journal("readback-source-observed")
      end
      unless destination == @guard.fetch(:destination_expected)
        raise ContractError, "Committed Google Play destination state differs from the validated edit"
      end
      verify_source_transition!(source) if @guard[:source_name]
      @outcome = "reconciled" if reconciled
      @after_mutation_guard&.call(client)
      build_state_evidence!(destination, source, mode: "mutation")
      persist_journal("committed-and-read-back")
    end

    def build_state_evidence!(destination, source, mode:)
      before = @guard.fetch(:destination_before)
      expected = @guard.fetch(:destination_expected)
      code = @guard.fetch(:target_code)
      evidence = {
        canonicalization: CANONICALIZATION,
        mode: mode,
        readbackEditId: @readback_edit_id,
        destinationBeforeSha256: self.class.digest(before),
        destinationExpectedSha256: self.class.digest(expected),
        destinationCommittedSha256: self.class.digest(destination),
        unrelatedBeforeSha256: self.class.digest(releases_without_code(before, code), domain: "release-set"),
        unrelatedCommittedSha256: self.class.digest(
          releases_without_code(destination, code),
          domain: "release-set",
        ),
        targetReleaseSha256: self.class.digest(
          require_target_release!(destination, code, @guard.fetch(:target_status)),
          domain: "release",
        ),
      }
      evidence[:mutationEditId] = @mutation_edit_id if mode == "mutation"
      if @guard[:source_name]
        source_before = @guard.fetch(:source_before)
        source_expected = @guard.fetch(:source_expected)
        evidence[:sourceBeforeSha256] = self.class.digest(source_before)
        evidence[:sourceExpectedSha256] = self.class.digest(source_expected)
        evidence[:sourceCommittedSha256] = self.class.digest(source)
        evidence[:sourceUnrelatedBeforeSha256] = self.class.digest(
          releases_without_code(source_before, code),
          domain: "release-set",
        )
        evidence[:sourceUnrelatedCommittedSha256] = self.class.digest(
          releases_without_code(source, code),
          domain: "release-set",
        )
        evidence[:sourceTargetTransition] = @guard.fetch(:source_transition)
      end
      @state_evidence = evidence
    end

    def clear_active_edit_handle!
      assert_owned_edit!
      @active_edit_owner.fetch(:client).current_edit = nil
      @active_edit_owner.fetch(:client).current_package_name = nil
      # Commit/reconciliation, not an abort receipt, now owns remote outcome.
      @active_edit_owner[:state] = :released_after_commit
      @active_edit_owner = nil
    end

    def abort_active_edit_without_masking
      Thread.handle_interrupt(Exception => :never) do
        owner = @active_edit_owner
        return unless owner && !owner[:cleanup_attempted]

        begin
          owner[:cleanup_attempted] = true
          assert_owned_edit!(owner)
          owner[:state] = :unknown
          Thread.handle_interrupt(Exception => :immediate) { owner.fetch(:client).abort_current_edit }
          unless owner.fetch(:client).current_edit.nil? && owner.fetch(:client).current_package_name.nil?
            raise ContractError, "Owned Play edit abort did not clear its original handle"
          end
          owner[:state] = :closed
          @active_edit_owner = nil
        rescue Exception => cleanup_error # rubocop:disable Lint/RescueException
          owner[:state] = :unknown
          owner[:error] = cleanup_error
          record_cleanup_failure(cleanup_error)
        end
      end
    end

    def record_operation_failure(phase, error)
      @primary_error ||= error
      @terminal_failure_class = @primary_error.class.name
      Thread.handle_interrupt(Exception => :immediate) do
        persist_journal(phase, failure_class: @primary_error.class.name, failure_role: "terminal")
      end
    rescue Exception => journal_error # rubocop:disable Lint/RescueException
      record_cleanup_failure(journal_error)
    end

    def record_cleanup_failure(error)
      @cleanup_failures << error unless @cleanup_failures.any? { |recorded| recorded.equal?(error) }
    end

    def finalize_owned_resources
      begin
        abort_active_edit_without_masking
      rescue Exception => error # rubocop:disable Lint/RescueException
        record_cleanup_failure(error)
      ensure
        begin
          @mapping_snapshot&.cleanup!
        rescue Exception => error # rubocop:disable Lint/RescueException
          record_cleanup_failure(error)
        ensure
          Array(@mapping_snapshot&.cleanup_errors).each { |error| record_cleanup_failure(error) }
        end
      end
      # Deliver a pending cancellation only after all independent disposal
      # attempts, including when there was no edit/network call to deliver it.
      begin
        Thread.handle_interrupt(Exception => :immediate) { nil }
      rescue Exception => error # rubocop:disable Lint/RescueException
        record_cleanup_failure(error)
      end
      persist_cleanup_diagnostics(@cleanup_failures.dup)
    end

    def persist_cleanup_diagnostics(errors)
      return if errors.empty?

      Thread.handle_interrupt(Exception => :never) do
        first = @primary_error || @cleanup_failures.first || errors.first
        @terminal_failure_class ||= first.class.name
        phase = first.is_a?(Interrupt) || first.is_a?(SystemExit) ? "cancelled" : "failed"
        # Existing class-only role; journal I/O may fail or be interrupted but
        # must not replace the primary or prevent other disposal/diagnostics.
        errors.each do |error|
          begin
            Thread.handle_interrupt(Exception => :immediate) do
              persist_journal(phase, failure_class: error.class.name, failure_role: "terminal")
            end
          rescue Exception => journal_error # rubocop:disable Lint/RescueException
            record_cleanup_failure(journal_error)
          end
        end
      end
    end

    def journal_document(phase, observed_at:, history:)
      document = {
        "schemaVersion" => 1,
        "kind" => "google-play-track-state-journal",
        "canonicalization" => CANONICALIZATION,
        "phase" => phase,
        "packageName" => Supply.config[:package_name].to_s,
        "observedAt" => observed_at,
        "history" => history,
      }
      document["operationIntentSha256"] = @intent_sha256 if @intent_sha256
      document["mutationEditId"] = @mutation_edit_id if @mutation_edit_id
      document["readbackEditId"] = @readback_edit_id if @readback_edit_id
      document["outcome"] = @outcome if @outcome
      failures = {
        "commit" => @commit_failure_class,
        "reconciliation" => @reconciliation_failure_class,
        "terminal" => @terminal_failure_class,
      }.compact
      document["failures"] = failures unless failures.empty?
      if @guard
        document["destination"] = {
          "name" => @guard[:destination_name],
          "before" => @guard[:destination_before],
          "expected" => @guard[:destination_expected],
          "observed" => @guard[:destination_observed],
        }.compact
        if @guard[:source_name]
          document["source"] = {
            "name" => @guard[:source_name],
            "before" => @guard[:source_before],
            "afterUpdate" => @guard[:source_after_update],
            "expected" => @guard[:source_expected],
            "observed" => @guard[:source_observed],
            "targetTransition" => @guard[:source_transition],
          }.compact
        end
      end
      document["stateEvidence"] = @state_evidence if @state_evidence
      document
    end

    def persist_journal(phase, failure_class: nil, failure_role: nil)
      observed_at = Time.now.utc.iso8601
      history_entry = { "phase" => phase, "observedAt" => observed_at }
      history_entry["failureClass"] = failure_class if failure_class
      history_entry["failureRole"] = failure_role if failure_role
      path = @journal_path
      previous = self.class.read_journal_history(
        path, intent_sha256: @intent_sha256, package_name: Supply.config[:package_name].to_s,
      )
      # Workflows serialize mutations and have one local journal writer. Never
      # erase a previously loaded dispatch signal if the file disappears or is
      # replaced/truncated while this invocation is validating or reading Store.
      unless previous == @journal_history
        raise ContractError, "Play operation journal changed during this invocation; preserve it and reconcile in a new invocation"
      end
      history = self.class.compact_journal_history(Array(previous) + [history_entry])
      contents = JSON.pretty_generate(journal_document(phase, observed_at: observed_at, history: history)) + "\n"
      raise ContractError, "Play operation journal exceeds its diagnostic bound" if contents.bytesize > MAX_JOURNAL_BYTES

      FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
      temporary = "#{path}.tmp-#{Process.pid}-#{Thread.current.object_id}"
      File.open(temporary, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        file.write(contents)
        file.flush
        file.fsync
      end
      File.rename(temporary, path)
      @journal_history = history
      begin
        File.open(File.dirname(path), File::RDONLY) { |directory| directory.fsync }
      rescue Errno::EINVAL, Errno::ENOTSUP
        nil
      end
    ensure
      FileUtils.rm_f(temporary) if defined?(temporary) && temporary
    end
  end
end
