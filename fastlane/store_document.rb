# frozen_string_literal: true

require "json"
require "digest/sha2"

module MobileReleaseKit
  # One original receipt/precondition publication, not the Store-lane terminal
  # transport and not authority to remove any final output or parent directory.
  module StoreDocument
    class Error < StandardError
      attr_reader :reason

      def initialize(reason)
        super("Store document publication is unconfirmed; preserve existing files")
        @reason = reason
      end
    end

    class Publication
      READ_BYTES = 4_096
      ERROR_LIMIT = 8
      private_constant :READ_BYTES, :ERROR_LIMIT

      # Pure construction. The caller roots this original owner BEFORE mkdir_p
      # and publish!, so serialization cannot leave new filesystem state.
      def initialize(path:, contents:)
        unless path.instance_of?(String) && path.start_with?(File::SEPARATOR) &&
               !path.match?(/[\x00-\x1f\x7f]/) && File.expand_path(path) == path &&
               File.basename(path) != File::SEPARATOR
          raise Error.new(:invalid_path)
        end
        @pid, @thread = Process.pid, Thread.current
        @path, @parent_path = path.dup.freeze, File.dirname(path).freeze
        @stage_path = "#{path}.tmp-#{@pid}".freeze
        @payload = (JSON.pretty_generate(contents) + "\n").b.freeze
        @sha256 = Digest::SHA256.hexdigest(@payload).freeze
        @parent, @stage = Handle.new, Handle.new
        @state = :reserved
        @secondary_errors, @cleanup_errors = [], []
        @expected_links = 1
      end

      def publish!
        origin!
        # A second call cannot replace/reset even a failed original attempt.
        raise Error.new(:already_attempted) unless @state == :reserved

        @state = :publishing
        begin
          Thread.handle_interrupt(Exception => :never) do
            begin
              begin
                Thread.handle_interrupt(Exception => :immediate) { publish_body }
              rescue Exception => error # rubocop:disable Lint/RescueException
                retain_error(error)
              ensure
                retain_error(Error.new(:nonlocal_completion)) unless @body_returned || @first_primary
                begin
                  collect_cleanup { Thread.handle_interrupt(Exception => :immediate) { remove_original_stage } }
                ensure
                  begin
                    collect_cleanup(@stage) { @stage.close_once }
                  ensure
                    collect_cleanup(@parent) { @parent.close_once }
                  end
                end
              end
              # Pending delivery precedes acceptance. No filesystem work follows
              # this point; every original descriptor close has actually returned.
              Thread.handle_interrupt(Exception => :immediate) do
                admit_success!
              end
              @result = {
                "path" => @path, "identity" => @stage_identity, "revision" => @final_revision,
                "size" => @payload.bytesize, "sha256" => @sha256,
              }.freeze
              @state = :succeeded
              return self
            rescue Exception => error # rubocop:disable Lint/RescueException
              # Preserve a real post-cleanup/pending-delivery failure BEFORE
              # final unwind bookkeeping can classify a non-exception exit.
              retain_error(error)
              @state = :failed
              raise
            ensure
              # This final bookkeeping is INSIDE both the mask and the outer
              # rescue. A raised/lost final ensure cannot leave usable success.
              finish_unwind!
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          retain_error(error)
          @state = :failed
          raise_primary!
        end
      end

      def successful?
        origin!
        @state == :succeeded && @first_primary.nil? && !@result.nil?
      end

      def result
        origin!
        raise Error.new(:no_successful_publication) unless successful?
        @result
      end

      def first_primary
        origin!
        @first_primary
      end

      def secondary_errors
        origin!
        @secondary_errors.dup.freeze
      end

      def cleanup_errors
        origin!
        @cleanup_errors.dup.freeze
      end

      private

      def admit_success!
        raise_primary! if @first_primary
        unless @body_returned && @stage_removed && @final_revision && @stage.retired? && @parent.retired?
          raise Error.new(:incomplete_publication)
        end
      end

      def finish_unwind!
        return if @state == :succeeded
        @state = :failed
        retain_error(Error.new(:nonlocal_completion)) unless @first_primary
      end

      # The two original File objects are retained even after a close failure.
      # closed? can confirm a returned close, never repair a raised/lost close.
      class Handle
        attr_reader :io

        def initialize
          @state = :reserved
          @close_errors = []
        end

        def acquire(path, flags, mode = nil)
          @state = :acquiring
          Thread.handle_interrupt(Exception => :never) do
            @io = mode ? File.open(path, flags, mode) : File.open(path, flags)
            @state = :open
            @io.autoclose = false
            @io.close_on_exec = true
          end
          @io
        end

        def attempted?
          @state != :reserved
        end

        def open?
          @state == :open && !@close_attempted
        end

        def retired?
          @state == :reserved || @state == :closed
        end

        def close_errors
          @close_errors.dup.freeze
        end

        def close_once
          return if @state == :reserved || @close_attempted
          begin
            Thread.handle_interrupt(Exception => :never) do
              @close_attempted, @state = true, :closing
              begin
                raise Error.new(:acquisition_return_missing) unless @io
                fd = @io.fileno
                raise Error.new(:close_not_confirmed) unless fd.instance_of?(Integer) && fd >= 3 && @io.pid.nil?
                @io.autoclose = true
                raise Error.new(:close_not_confirmed) unless @io.autoclose? == true
                returned = Thread.handle_interrupt(Exception => :immediate) { @io.close }
                raise Error.new(:close_not_confirmed) unless returned.nil? && @io.closed? == true
                @state = :closed
              rescue Exception => error # rubocop:disable Lint/RescueException
                retain_close_error(error)
              ensure
                unconfirmed_close! unless @state == :closed
              end
            end
          rescue Exception => error # rubocop:disable Lint/RescueException
            Thread.handle_interrupt(Exception => :never) do
              @close_attempted = true
              retain_close_error(error)
              unconfirmed_close!
            end
          end
        end

        private

        def retain_close_error(error)
          @state = :unknown
          @first_close_error ||= error
          if @close_errors.length < 4 && !@close_errors.any? { |item| item.equal?(error) }
            @close_errors << error
          end
        end

        def unconfirmed_close!
          retain_close_error(Error.new(:close_not_confirmed)) unless @first_close_error
          unless @disarm_attempted
            @disarm_attempted = true
            returned, raised = false, false
            begin
              raise Error.new(:acquisition_return_missing) unless @io
              @io.autoclose = false
              returned = true
            rescue Exception => error # rubocop:disable Lint/RescueException
              raised = true
              retain_close_error(error)
            ensure
              retain_close_error(Error.new(:close_not_confirmed)) unless returned || raised
              raise @first_close_error, cause: @first_close_error.cause
            end
          end
          raise @first_close_error, cause: @first_close_error.cause
        end
      end
      private_constant :Handle

      def origin!
        raise Error.new(:foreign_origin) unless @pid == Process.pid && @thread.equal?(Thread.current)
      end

      def retain_error(error, cleanup: false)
        Thread.handle_interrupt(Exception => :never) do
          @first_primary ||= error
          if !error.equal?(@first_primary) && @secondary_errors.length < ERROR_LIMIT &&
             !@secondary_errors.any? { |item| item.equal?(error) }
            @secondary_errors << error
          end
          if cleanup && @cleanup_errors.length < ERROR_LIMIT && !@cleanup_errors.any? { |item| item.equal?(error) }
            @cleanup_errors << error
          end
        end
      end

      def raise_primary!
        # Keep the actual primary object AND its existing exception graph; a
        # later cleanup rescue must not become an implicit replacement cause.
        raise @first_primary, cause: @first_primary.cause
      end

      def collect_cleanup(handle = nil)
        # Keep independent-close entry masked. Each Handle records its one
        # close attempt before making the actual call immediately cancellable.
        failure = nil
        begin
          yield
        rescue Exception => error # rubocop:disable Lint/RescueException
          failure = error
        ensure
          handle&.close_errors&.each { |error| retain_error(error, cleanup: true) }
          retain_error(failure, cleanup: true) if failure
        end
      end

      def identity(value)
        {"device" => value.dev, "inode" => value.ino, "uid" => value.uid,
         "gid" => value.gid, "mode" => value.mode & 0o7777}.freeze
      end

      def revision(value)
        {"size" => value.size, "mtime_ns" => value.mtime.to_i * 1_000_000_000 + value.mtime.nsec,
         "ctime_ns" => value.ctime.to_i * 1_000_000_000 + value.ctime.nsec}.freeze
      end

      def absent!(path, reason)
        File.lstat(path)
        raise Error.new(reason)
      rescue Errno::ENOENT
        true
      end

      def verify_parent!
        raise Error.new(:parent_custody_missing) unless @parent.open? && @parent_identity
        descriptor, entry = @parent.io.stat, File.lstat(@parent_path)
        unless descriptor.directory? && entry.directory? && !entry.symlink? &&
               identity(descriptor) == @parent_identity && identity(entry) == @parent_identity
          raise Error.new(:parent_changed)
        end
        true
      end

      def verify_stage!(links:, expected_revision: nil, after_link_change: false, entry_path: @stage_path)
        verify_parent!
        raise Error.new(:stage_custody_missing) unless @stage.open? && @stage_identity
        before = @stage.io.stat
        unless before.file? && identity(before) == @stage_identity && before.nlink == links &&
               before.size == @payload.bytesize
          raise Error.new(:stage_changed)
        end
        before_revision = revision(before)
        if expected_revision
          keys = after_link_change ? %w[size mtime_ns] : %w[size mtime_ns ctime_ns]
          unless keys.all? { |key| before_revision.fetch(key) == expected_revision.fetch(key) }
            raise Error.new(:stage_revision_changed)
          end
        end
        offset = 0
        while offset < @payload.bytesize
          bytes = @stage.io.pread([READ_BYTES, @payload.bytesize - offset].min, offset)
          unless bytes.instance_of?(String) && !bytes.empty? && bytes == @payload.byteslice(offset, bytes.bytesize)
            raise Error.new(:stage_bytes_changed)
          end
          offset += bytes.bytesize
        end
        after, entry = @stage.io.stat, File.lstat(entry_path)
        unless after.file? && identity(after) == @stage_identity && after.nlink == links &&
               revision(after) == before_revision && entry.file? && !entry.symlink? &&
               identity(entry) == @stage_identity && entry.nlink == links && revision(entry) == before_revision
          raise Error.new(:stage_changed)
        end
        verify_parent!
        before_revision
      end

      def publish_body
        unless File.const_defined?(:NOFOLLOW) && File.const_defined?(:NONBLOCK)
          raise Error.new(:required_filesystem_api_missing)
        end
        @parent.acquire(@parent_path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK)
        parent_stat = @parent.io.stat
        raise Error.new(:parent_not_directory) unless parent_stat.directory?
        @parent_identity = identity(parent_stat)
        verify_parent!
        absent!(@path, :destination_exists)
        @stage.acquire(@stage_path, File::RDWR | File::CREAT | File::EXCL | File::NOFOLLOW | File::NONBLOCK, 0o600)
        initial = @stage.io.stat
        unless initial.file? && initial.dev == parent_stat.dev && initial.uid == Process.euid &&
               (initial.mode & 0o7777) == 0o600 && initial.nlink == 1 && initial.size.zero?
          raise Error.new(:initial_stage_unknown)
        end
        @stage_identity = identity(initial)
        initial_revision = revision(initial)
        initial_entry = File.lstat(@stage_path)
        unless initial_entry.file? && !initial_entry.symlink? && identity(initial_entry) == @stage_identity &&
               initial_entry.nlink == 1 && revision(initial_entry) == initial_revision
          raise Error.new(:initial_stage_unknown)
        end
        verify_parent!
        @stage.io.sync = true
        offset = 0
        while offset < @payload.bytesize
          count = @stage.io.write(@payload.byteslice(offset..))
          unless count.instance_of?(Integer) && count.positive? && count <= @payload.bytesize - offset
            raise Error.new(:write_progress_missing)
          end
          offset += count
        end
        @written_revision = verify_stage!(links: 1)
        @stage.io.flush
        verify_stage!(links: 1, expected_revision: @written_revision)
        @stage.io.fsync
        verify_stage!(links: 1, expected_revision: @written_revision)
        absent!(@path, :destination_exists)
        File.link(@stage_path, @path)
        @expected_links = 2 # Only the actual link's successful return changes this.
        @linked_revision = verify_stage!(links: 2, expected_revision: @written_revision, after_link_change: true)
        verify_stage!(links: 2, expected_revision: @linked_revision, entry_path: @path)
        @parent.io.fsync
        verify_stage!(links: 2, expected_revision: @linked_revision)
        verify_stage!(links: 2, expected_revision: @linked_revision, entry_path: @path)
        @body_returned = true
      end

      def remove_original_stage
        return unless @stage.attempted?
        # Initial-fstat/lost-return/partial-write uncertainty is not permission
        # to adopt and remove a surviving pathname. Retain it for the owner.
        raise Error.new(:written_stage_custody_missing) unless @written_revision && @stage_identity
        expected = @linked_revision || @written_revision
        verify_stage!(links: @expected_links, expected_revision: expected,
          after_link_change: @expected_links == 2 && @linked_revision.nil?)
        if @expected_links == 2
          verify_stage!(links: 2, expected_revision: expected,
            after_link_change: @linked_revision.nil?, entry_path: @path)
        end
        File.unlink(@stage_path)
        @stage_removed = true
        absent!(@stage_path, :stage_reappeared)
        if @expected_links == 2
          final = verify_stage!(links: 1, expected_revision: expected, after_link_change: true, entry_path: @path)
          @parent.io.fsync
          @final_revision = verify_stage!(links: 1, expected_revision: final, entry_path: @path)
          absent!(@stage_path, :stage_reappeared)
        else
          verify_parent!
          descriptor = @stage.io.stat
          unless descriptor.file? && identity(descriptor) == @stage_identity && descriptor.nlink.zero?
            raise Error.new(:stage_unlink_unconfirmed)
          end
          @parent.io.fsync
          verify_parent!
          absent!(@stage_path, :stage_reappeared)
        end
      end
    end
  end
end
