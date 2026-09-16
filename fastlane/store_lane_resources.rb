# frozen_string_literal: true

require "digest/sha2"
require "digest/md5"
require "securerandom"
require_relative "store_lane_lifetime"

module MobileReleaseKit
  # Fixed Store-lane generated roles only. Ruby records original creation and
  # closes its handles; only the original Python owner may later remove entries
  # after both process-family and composite settlement. No Ruby deletion here.
  module StoreLaneResources
    class Error < StandardError
      attr_reader :reason
      def initialize(reason)
        super("Store lane generated-resource custody is unconfirmed")
        @reason = reason
      end
    end

    # Shared internally by the finite inventory and terminal writer. No finalizer,
    # numeric-FD adoption, repeated close, or closed?-based error repair.
    class FileSlot
      attr_reader :io, :path
      def initialize
        @pid, @thread, @state = Process.pid, Thread.current, :reserved
      end
      def acquire(path, flags, mode = nil)
        origin!
        raise Error.new(:slot_reused) unless @state == :reserved
        @path, @state = path.dup.freeze, :acquiring
        Thread.handle_interrupt(Exception => :never) do
          @io = mode ? File.open(path, flags, mode) : File.open(path, flags)
          @state = :open
          raise Error.new(:file_api) unless @io.instance_of?(File)
          @io.autoclose = false
          @io.close_on_exec = true
        end
        @io
      end
      def open?
        origin!
        @state == :open && !@close_attempted
      end
      def retired?
        origin!
        @state == :reserved || @state == :closed
      end
      def close_once
        origin!
        return if @state == :reserved || @close_attempted
        begin
          Thread.handle_interrupt(Exception => :never) do
            @close_attempted, @state = true, :closing
            raise Error.new(:open_return_missing) unless @io
            Thread.handle_interrupt(Exception => :immediate) { @io.close }
            raise Error.new(:close_unconfirmed) unless @io.closed?
            @state = :closed
          end
        rescue Exception # rubocop:disable Lint/RescueException
          @state = :unknown
          raise
        end
      end
      private
      def origin!
        raise Error.new(:foreign_origin) unless @pid == Process.pid && @thread.equal?(Thread.current)
      end
    end

    def self.identity(value)
      {"device" => value.dev, "inode" => value.ino, "uid" => value.uid,
       "gid" => value.gid, "mode" => value.mode & 0o7777}.freeze
    end

    def self.revision(value)
      [value.size, value.mtime.to_i * 1_000_000_000 + value.mtime.nsec,
       value.ctime.to_i * 1_000_000_000 + value.ctime.nsec].freeze
    end

    class Inventory
      COPY_BYTES = 64 * 1_024
      UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/
      private_constant :COPY_BYTES, :UUID

      def initialize(invocation:, binding:)
        @invocation, @binding = invocation, binding
        @handles, @entries, @parents, @requested = [], {}, {}, []
        @busy = @unknown = @sealed = @admitted = false
      end

      def bound_to?(invocation)
        @invocation.origin!
        @invocation.equal?(invocation)
      end

      def admit!
        @invocation.origin!
        raise Error.new(:admission_reused) if @admitted || @busy || @sealed
        guarded do
          root = bind_parent("root", @binding.fetch("root"), nil)
          unless root.fetch(:identity).fetch("device") == @binding.fetch("root_device") &&
                 root.fetch(:identity).fetch("inode") == @binding.fetch("root_inode")
            raise Error.new(:root_identity)
          end
          bind_parent("tmp", File.join(@binding.fetch("root"), "tmp"), "root")
          bind_parent("runner", File.join(@binding.fetch("root"), "runner"), "root")
          if @binding.fetch("shell_home")
            bind_parent("home", File.join(@binding.fetch("root"), "home"), "root")
            bind_parent("appstoreconnect", File.join(@binding.fetch("root"), "home/.appstoreconnect"), "home")
            bind_parent("shell-keys", File.join(@binding.fetch("root"), "home/.appstoreconnect/private_keys"), "appstoreconnect")
          end
          @admitted = true
        end
      end

      def continuation_allowed?
        @invocation.origin!
        @admitted && !@unknown && !@busy && @entries.values.all? { |entry| entry.fetch(:kind) == "directory" || entry.fetch(:slot).retired? }
      end

      def create_pilot_root!
        creation { create_directory("pilot-root", "tmp", "pilot-#{SecureRandom.hex(16)}") }
      end

      def create_package!(pilot_path:, app_id:)
        creation do
          require_path!("pilot-root", pilot_path)
          raise Error.new(:package_platform) unless @binding.fetch("macos") && app_id.to_s == @binding.fetch("app_id")
          create_directory("package", "pilot-root", "#{app_id}-#{uuid}.itmsp")
        end
      end

      def copy_package_ipa!(ipa_path:, package_path:)
        parent = @binding.fetch("macos") ? "package" : "pilot-root"
        creation do
          require_path!(parent, package_path)
          require_artifact!(ipa_path)
          copy_file("package-ipa", parent, ipa_path, sha_name: true)
        end
      end

      def copy_appstore_info!(source:, pilot_path:)
        creation do
          raise Error.new(:package_platform) if @binding.fetch("macos")
          require_path!("pilot-root", pilot_path)
          unless source == File.join(File.dirname(@binding.fetch("artifact")), "AppStoreInfo.plist")
            raise Error.new(:source_role)
          end
          copy_file("package-appstore-info", "pilot-root", source, name: "AppStoreInfo.plist")
        end
      end

      def write_metadata!(package_path:, contents:)
        creation do
          require_path!("package", package_path)
          write_file("package-metadata", "package", "metadata.xml", contents)
        end
      end

      def copy_upload_asset!(source:)
        creation do
          raise Error.new(:asset_platform) unless @binding.fetch("macos")
          require_artifact!(source)
          copy_file("upload-asset", "tmp", source, name: "#{uuid}.ipa")
        end
      end

      def write_api_key!(key_id:, contents:, shell:)
        creation do
          raise Error.new(:key_identity) unless key_id == @binding.fetch("key_id") &&
            contents.instance_of?(String) && !contents.empty?
          parent = if shell
                     raise Error.new(:shell_home_not_admitted) unless @binding.fetch("shell_home")
                     "shell-keys"
                   else
                     raise Error.new(:shell_home_route) if @binding.fetch("shell_home")
                     create_directory("key-dir", "tmp", "deliver-#{SecureRandom.hex(16)}")
                     "key-dir"
                   end
          write_file("key", parent, "AuthKey_#{key_id}.p8", contents)
          @parents.fetch(parent).fetch(:path)
        end
      end

      def require_ready_for_executor!
        @invocation.require_upload_continuation!
        raise Error.new(:resources_not_admitted) unless @admitted && !@sealed
        require_time!
        @entries.each_value { |entry| verify_entry!(entry) }
        true
      rescue Exception => error # rubocop:disable Lint/RescueException
        unknown!(error)
        raise
      end

      def require_upload_inputs!(package_path:, asset_path:)
        @invocation.require_upload_continuation!
        require_artifact!(asset_path)
        require_path!(@binding.fetch("macos") ? "package" : "pilot-root", package_path)
        true
      rescue Exception => error # rubocop:disable Lint/RescueException
        unknown!(error)
        raise
      end

      def defer_removal!(path, primary: nil)
        @invocation.origin!
        entry = @entries.values.find { |item| item.fetch(:path) == path }
        unless entry || (@binding.fetch("shell_home") && @parents.fetch("shell-keys").fetch(:path) == path)
          raise Error.new(:unowned_removal_request)
        end
        @requested << path unless @requested.include?(path)
        true # A request is not deletion, writer retirement or process finality.
      rescue Exception => error # rubocop:disable Lint/RescueException
        unknown!(primary) if primary.is_a?(Exception)
        unknown!(error)
        raise
      end

      def seal!
        @invocation.origin!
        @sealed = true
        raise Error.new(:unretired_writer) unless continuation_allowed?
        true
      end

      def finish!
        @invocation.origin!
        raise Error.new(:finish_reused) if @finish_attempted
        @finish_attempted = true
        body_returned, rows = false, nil
        begin
          Thread.handle_interrupt(Exception => :never) do
            begin
              begin
                Thread.handle_interrupt(Exception => :immediate) do
                  seal!
                  @parents.each_key { |role| verify_parent!(role) }
                  @entries.each_value { |entry| verify_entry!(entry) }
                  rows = @entries.values.map do |entry|
                    {"role" => entry.fetch(:role), "parent" => entry.fetch(:parent), "name" => entry.fetch(:name),
                     "kind" => entry.fetch(:kind)}.merge(entry.fetch(:identity)).freeze
                  end.freeze
                  body_returned = true
                end
              rescue Exception => error # rubocop:disable Lint/RescueException
                unknown!(error)
              ensure
                unknown!(Error.new(:finish_missing)) unless body_returned || @unknown
                close_independent!
              end
              Thread.handle_interrupt(Exception => :immediate) do
                require_time!
                raise Error.new(:unretired_resource) unless !@unknown && @handles.all?(&:retired?)
              end
              @inventory, @finished = rows, true
              return @inventory
            rescue Exception => error # rubocop:disable Lint/RescueException
              unknown!(error)
              raise
            ensure
              unknown!(Error.new(:finish_missing)) unless @finished || @unknown
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          unknown!(error)
          @invocation.raise_unknown!
        end
      end

      def sealed_and_retired?
        @invocation.origin!
        @sealed && @admitted && @finished && !@unknown && !@inventory.nil? && @handles.all?(&:retired?)
      end

      def inventory
        raise Error.new(:inventory_unavailable) unless sealed_and_retired?
        @inventory
      end

      def close_independent!
        @invocation.origin!
        Thread.handle_interrupt(Exception => :never) do
          @handles.reverse_each do |slot|
            begin
              slot.close_once
            rescue Exception => error # rubocop:disable Lint/RescueException
              unknown!(error, cleanup: true)
            end
          end
        end
      end

      # Fixed pinned bridge reads are tracked too: an interrupted read/close is
      # not repaired by a later File.read or automatic GC close.
      def read_pinned_source!(path, expected_sha256)
        @invocation.require_upload_continuation!
        raise Error.new(:source_admission_closed) if @sealed
        guarded do
          bytes = read_source(path, max_bytes: 1_048_576)
          raise Error.new(:source_pin) unless Digest::SHA256.hexdigest(bytes) == expected_sha256
          bytes.freeze
        end
      end

      def package_file_attributes!(path)
        @invocation.require_upload_continuation!
        guarded do
          entry = @entries.fetch("package-ipa")
          raise Error.new(:package_file_route) unless entry.fetch(:path) == path
          verify_entry!(entry)
          size, digest = read_source_digest(path, entry)
          {size: size, md5: digest}.freeze
        end
      end

      private

      def unknown!(error, cleanup: false)
        @invocation.origin!
        @unknown = true
        @invocation.mark_unknown!(error, cleanup: cleanup)
      end

      def require_time!
        @invocation.origin!
        raise Error.new(:deadline) unless NativeUploadProcess.monotonic_ns < @binding.fetch("run_deadline_ns")
      end

      def guarded
        @invocation.origin!
        raise Error.new(:resource_busy) if @busy || @unknown
        @busy, returned = true, false
        begin
          Thread.handle_interrupt(Exception => :never) do
            begin
              value = Thread.handle_interrupt(Exception => :immediate) { yield }
              returned = true
              value
            rescue Exception => error # rubocop:disable Lint/RescueException
              unknown!(error)
              raise
            ensure
              unknown!(Error.new(:resource_return_missing)) unless returned || @unknown
              @busy = false
            end
          end
        rescue Exception => error # rubocop:disable Lint/RescueException
          unknown!(error)
          raise
        end
      end

      def creation(&body)
        @invocation.require_upload_continuation!
        unless @admitted && !@sealed && @invocation.mode == "execute" && @invocation.lane == "ios_testflight_internal"
          raise Error.new(:creation_role)
        end
        require_time!
        guarded(&body)
      rescue Exception => error # rubocop:disable Lint/RescueException
        unknown!(error)
        raise
      end

      def slot
        value = FileSlot.new
        @handles << value # Original slot is rooted before File.open can run.
        value
      end

      def bind_parent(role, path, parent_role)
        raise Error.new(:duplicate_parent) if @parents.key?(role)
        verify_parent!(parent_role) if parent_role
        handle = slot
        handle.acquire(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK)
        value, entry = handle.io.stat, File.lstat(path)
        unless value.directory? && entry.directory? && !entry.symlink? &&
               value.uid == Process.euid && (value.mode & 0o7777) == 0o700 &&
               value.dev == @binding.fetch("root_device") && StoreLaneResources.identity(value) == StoreLaneResources.identity(entry)
          raise Error.new(:parent_identity)
        end
        @parents[role] = {path: path.dup.freeze, slot: handle, identity: StoreLaneResources.identity(value), parent: parent_role}.freeze
      end

      def verify_parent!(role)
        parent = @parents.fetch(role)
        if parent.fetch(:parent)
          verify_parent!(parent.fetch(:parent))
        else
          raise Error.new(:root_ancestry_changed) unless File.realpath(parent.fetch(:path)) == parent.fetch(:path)
        end
        raise Error.new(:parent_closed) unless parent.fetch(:slot).open?
        current, entry = parent.fetch(:slot).io.stat, File.lstat(parent.fetch(:path))
        unless current.directory? && entry.directory? && !entry.symlink? &&
               StoreLaneResources.identity(current) == parent.fetch(:identity) &&
               StoreLaneResources.identity(entry) == parent.fetch(:identity)
          raise Error.new(:parent_changed)
        end
        parent
      end

      def reserve_entry(role, parent, name, kind)
        raise Error.new(:duplicate_role) if @entries.key?(role) || @entries.size >= 32
        raise Error.new(:entry_name) unless name.instance_of?(String) && name.bytesize.between?(1, 512) &&
          !name.match?(/[\x00-\x20\x7f\/]/) && !%w[. ..].include?(name)
        directory = verify_parent!(parent)
        entry = {role: role.freeze, parent: parent.freeze, name: name.freeze, kind: kind.freeze,
                 path: File.join(directory.fetch(:path), name).freeze, slot: slot, identity: nil}
        @entries[role] = entry
        entry
      end

      def create_directory(role, parent, name)
        entry = reserve_entry(role, parent, name, "directory")
        # Only the actual exclusive mkdir return allows the first local binding.
        # No producer receives this pathname before the following original FD.
        Thread.handle_interrupt(Exception => :never) do
          raise Error.new(:mkdir_return) unless Dir.mkdir(entry.fetch(:path), 0o700) == 0
          entry.fetch(:slot).acquire(entry.fetch(:path), File::RDONLY | File::NOFOLLOW | File::NONBLOCK)
        end
        value = entry.fetch(:slot).io.stat
        unless value.directory? && value.uid == Process.euid && (value.mode & 0o7777) == 0o700 && value.dev == @binding.fetch("root_device")
          raise Error.new(:created_directory_identity)
        end
        entry[:identity] = StoreLaneResources.identity(value)
        @parents[role] = {path: entry.fetch(:path), slot: entry.fetch(:slot), identity: entry.fetch(:identity), parent: parent}.freeze
        verify_parent!(parent)
        verify_entry!(entry)
        entry.fetch(:path)
      end

      def create_file(role, parent, name)
        entry = reserve_entry(role, parent, name, "file")
        file = entry.fetch(:slot).acquire(entry.fetch(:path), File::RDWR | File::CREAT | File::EXCL | File::NOFOLLOW | File::NONBLOCK, 0o600)
        file.binmode
        value = file.stat
        unless value.file? && value.uid == Process.euid && (value.mode & 0o7777) == 0o600 &&
               value.dev == @binding.fetch("root_device") && value.nlink == 1 && value.size.zero?
          raise Error.new(:created_file_identity)
        end
        entry[:identity] = StoreLaneResources.identity(value)
        verify_entry!(entry)
        entry
      end

      def verify_entry!(entry)
        verify_parent!(entry.fetch(:parent))
        current = File.lstat(entry.fetch(:path))
        valid_type = entry.fetch(:kind) == "directory" ? current.directory? : current.file? && current.nlink == 1
        unless valid_type && !current.symlink? && entry.fetch(:identity) &&
               StoreLaneResources.identity(current) == entry.fetch(:identity)
          raise Error.new(:entry_changed)
        end
        if entry.fetch(:slot).open?
          actual = entry.fetch(:slot).io.stat
          raise Error.new(:entry_changed) unless StoreLaneResources.identity(actual) == entry.fetch(:identity)
        end
        true
      end

      def require_path!(role, path)
        expected = @parents.fetch(role)
        raise Error.new(:parent_route) unless path == expected.fetch(:path)
        verify_parent!(role)
      end

      def require_artifact!(path)
        raise Error.new(:artifact_route) unless path.instance_of?(String) && path == @binding.fetch("artifact")
      end

      def uuid
        value = SecureRandom.uuid
        raise Error.new(:uuid) unless value.match?(UUID)
        value
      end

      def write_bytes(file, bytes)
        offset = 0
        while offset < bytes.bytesize
          require_time!
          count = file.write(bytes.byteslice(offset..))
          raise Error.new(:write_progress) unless count.instance_of?(Integer) && count.positive? && count <= bytes.bytesize - offset
          offset += count
        end
      end

      def finish_file(entry, size, digest)
        file = entry.fetch(:slot).io
        file.flush
        file.fsync
        before = file.stat
        raise Error.new(:written_size) unless before.size == size
        observed, offset = Digest::SHA256.new, 0
        while offset < size
          require_time!
          bytes = file.pread([COPY_BYTES, size - offset].min, offset)
          raise Error.new(:read_progress) unless bytes.instance_of?(String) && !bytes.empty?
          observed.update(bytes)
          offset += bytes.bytesize
        end
        unless observed.hexdigest == digest && StoreLaneResources.revision(file.stat) == StoreLaneResources.revision(before)
          raise Error.new(:written_revision)
        end
        verify_entry!(entry)
        Thread.handle_interrupt(Exception => :never) { entry.fetch(:slot).close_once }
        entry.fetch(:path)
      end

      def write_file(role, parent, name, contents)
        maximum = role == "key" ? 65_536 : 1_048_576
        raise Error.new(:file_contents) unless contents.instance_of?(String) && contents.bytesize.between?(1, maximum)
        bytes = contents.b.dup.freeze
        entry = create_file(role, parent, name)
        write_bytes(entry.fetch(:slot).io, bytes)
        finish_file(entry, bytes.bytesize, Digest::SHA256.hexdigest(bytes))
      end

      def copy_file(role, parent, source, name: nil, sha_name: false)
        input = slot
        file = input.acquire(source, File::RDONLY | File::NOFOLLOW | File::NONBLOCK)
        file.binmode
        before, named = file.stat, File.lstat(source)
        unless before.file? && !named.symlink? && StoreLaneResources.identity(before) == StoreLaneResources.identity(named)
          raise Error.new(:source_identity)
        end
        if sha_name
          hash, count = Digest::SHA256.new, 0
          while (bytes = file.read(COPY_BYTES))
            require_time!
            raise Error.new(:read_progress) if bytes.empty?
            count += bytes.bytesize
            raise Error.new(:source_growth) if count > before.size
            hash.update(bytes)
          end
          raise Error.new(:source_revision) unless count == before.size && StoreLaneResources.revision(file.stat) == StoreLaneResources.revision(before)
          name = "#{hash.hexdigest}.ipa"
          file.rewind
        end
        entry = create_file(role, parent, name)
        digest, count = Digest::SHA256.new, 0
        while (bytes = file.read(COPY_BYTES))
          require_time!
          raise Error.new(:read_progress) if bytes.empty?
          count += bytes.bytesize
          raise Error.new(:source_growth) if count > before.size
          digest.update(bytes)
          write_bytes(entry.fetch(:slot).io, bytes)
        end
        unless count == before.size && StoreLaneResources.identity(file.stat) == StoreLaneResources.identity(before) &&
               StoreLaneResources.revision(file.stat) == StoreLaneResources.revision(before) &&
               StoreLaneResources.identity(File.lstat(source)) == StoreLaneResources.identity(before) &&
               (!sha_name || name == "#{digest.hexdigest}.ipa")
          raise Error.new(:source_revision)
        end
        Thread.handle_interrupt(Exception => :never) { input.close_once }
        finish_file(entry, count, digest.hexdigest)
      end

      def read_source(path, max_bytes:)
        bytes = +"".b
        read_original_source(path, max_bytes: max_bytes) { |chunk| bytes << chunk }
        bytes
      end

      def read_source_digest(path, entry)
        digest = Digest::MD5.new
        size = read_original_source(path, expected_identity: entry.fetch(:identity)) { |chunk| digest.update(chunk) }
        verify_entry!(entry)
        [size, digest.hexdigest.freeze].freeze
      end

      def read_original_source(path, max_bytes: nil, expected_identity: nil)
        input = slot
        file = input.acquire(path, File::RDONLY | File::NOFOLLOW | File::NONBLOCK)
        file.binmode
        before, named = file.stat, File.lstat(path)
        unless before.file? && named.file? && !named.symlink? &&
               StoreLaneResources.identity(before) == StoreLaneResources.identity(named) &&
               (!expected_identity || StoreLaneResources.identity(before) == expected_identity) &&
               (!max_bytes || before.size <= max_bytes)
          raise Error.new(:source_identity)
        end
        count = 0
        while (bytes = file.read(COPY_BYTES))
          require_time!
          raise Error.new(:read_progress) if bytes.empty?
          count += bytes.bytesize
          raise Error.new(:source_growth) if count > before.size
          yield bytes
        end
        after, named = file.stat, File.lstat(path)
        unless count == before.size && StoreLaneResources.identity(after) == StoreLaneResources.identity(before) &&
               StoreLaneResources.revision(after) == StoreLaneResources.revision(before) &&
               StoreLaneResources.identity(named) == StoreLaneResources.identity(before) &&
               StoreLaneResources.revision(named) == StoreLaneResources.revision(before)
          raise Error.new(:source_revision)
        end
        input.close_once
        count
      end
    end
  end
end
