# frozen_string_literal: true

# Filesystem-only failure models. No process, signal, Store, network or native
# producer is started; these are not cross-platform durability/finality receipts.
require "minitest/autorun"
require "minitest/mock"
require "tmpdir"
require "fileutils"
require_relative "../../fastlane/store_document"

class StoreDocumentPublicationTest < Minitest::Test
  Publication = MobileReleaseKit::StoreDocument::Publication
  Failure = MobileReleaseKit::StoreDocument::Error

  def setup
    @root = File.realpath(Dir.mktmpdir("mrk-store-document-"))
    stat = File.lstat(@root)
    @root_identity = [stat.dev, stat.ino]
    @parent = File.join(@root, "output")
    Dir.mkdir(@parent, 0o700)
    @contents = {"schemaVersion" => 1, "documentType" => "synthetic-precondition", "snapshot" => {"visible" => false}}
    @opened = []
  end

  def teardown
    assert @opened.all? { |_, file| file.closed? }, "an original test descriptor was not closed"
    current = File.lstat(@root)
    assert current.directory? && !current.symlink? && [current.dev, current.ino] == @root_identity
    FileUtils.remove_entry(@root) # Original private fixture; all consumers are inert/closed.
  end

  def publication(name = "receipt.json", contents: @contents)
    @path = File.join(@parent, name)
    @stage = "#{@path}.tmp-#{Process.pid}"
    Publication.new(path: @path, contents: contents)
  end

  def observe_files(configure = nil)
    original = File.method(:open)
    wrapper = lambda do |path, *arguments, **keywords|
      file = original.call(path, *arguments, **keywords)
      role = path == @parent ? :parent : :stage
      @opened << [role, file]
      configure&.call(role, file)
      file
    end
    File.stub(:open, wrapper) { yield }
  end

  def fail_once(file, method, error, after: false)
    original, raised = file.method(method), false
    file.define_singleton_method(method) do |*arguments, **keywords|
      unless raised
        raised = true
        original.call(*arguments, **keywords) if after
        raise error
      end
      original.call(*arguments, **keywords)
    end
  end

  def assert_failed(owner, primary = nil)
    refute owner.successful?
    assert_same primary, owner.first_primary if primary
    assert_raises(Failure) { owner.result }
    assert @opened.all? { |_, file| file.closed? }
  end

  def test_healthy_exact_exclusive_publication_exposes_only_immutable_original_success
    owner = publication
    original_contents = JSON.pretty_generate(@contents) + "\n"
    @contents["snapshot"]["visible"] = true # Construction already froze the exact payload.
    assert_raises(Failure) { owner.result }
    assert_same owner, observe_files { owner.publish! }
    assert owner.successful?
    assert_equal original_contents, File.binread(@path)
    refute File.exist?(@stage)
    stat, result = File.stat(@path), owner.result
    assert_equal 1, stat.nlink
    assert_equal 0o600, stat.mode & 0o7777
    assert_equal @path, result.fetch("path")
    assert_equal({"device" => stat.dev, "inode" => stat.ino, "uid" => stat.uid,
      "gid" => stat.gid, "mode" => 0o600}, result.fetch("identity"))
    assert_equal stat.size, result.fetch("size")
    assert_equal Digest::SHA256.hexdigest(original_contents), result.fetch("sha256")
    assert_equal stat.mtime.to_i * 1_000_000_000 + stat.mtime.nsec, result.fetch("revision").fetch("mtime_ns")
    assert_equal stat.ctime.to_i * 1_000_000_000 + stat.ctime.nsec, result.fetch("revision").fetch("ctime_ns")
    assert result.frozen? && result.fetch("identity").frozen? && result.fetch("revision").frozen?
    assert_empty owner.cleanup_errors
    assert_raises(Failure) { owner.publish! }
    assert_same result, owner.result
    Process.stub(:pid, Process.pid + 1) { assert_raises(Failure) { owner.result } }
  end

  def test_serialization_precedes_filesystem_effects_and_existing_destinations_survive
    contents = Object.new
    original = RuntimeError.new("synthetic serialization failure")
    contents.define_singleton_method(:to_json) { |*| raise original }
    File.stub(:open, ->(*) { flunk "serialization acquired a file" }) do
      assert_same original, assert_raises(RuntimeError) { publication(contents: contents) }
    end
    assert_empty Dir.children(@parent)
    owner = publication
    File.write(@path, "original destination")
    error = observe_files { assert_raises(Failure) { owner.publish! } }
    assert_equal :destination_exists, error.reason
    assert_equal "original destination", File.binread(@path)
    refute File.exist?(@stage)
    assert_failed(owner, error)
  end

  def test_occupied_stage_regular_file_and_symlink_are_never_adopted_or_removed
    %i[regular symlink].each do |kind|
      owner = publication("#{kind}.json")
      target = File.join(@root, "#{kind}-sentinel")
      File.write(target, "foreign target")
      kind == :regular ? File.write(@stage, "foreign stage") : File.symlink(target, @stage)
      original = File.lstat(@stage)
      observe_files { assert_raises(SystemCallError) { owner.publish! } }
      assert_equal [original.dev, original.ino], [File.lstat(@stage).dev, File.lstat(@stage).ino]
      assert_equal kind == :symlink, File.symlink?(@stage)
      assert_equal "foreign target", File.binread(target)
      assert_equal "foreign stage", File.binread(@stage) if kind == :regular
      refute File.exist?(@path)
      assert_failed(owner)
    end
  end

  def test_write_flush_fsync_and_initial_fstat_errors_keep_original_failure_and_close_both_handles
    [[:stat, false], [:write, false], [:write, true], [:flush, false], [:fsync, false]].each_with_index do |(method, after), index|
      owner = publication("fault-#{index}.json")
      primary = IOError.new("synthetic #{method} failure")
      configure = ->(role, file) { fail_once(file, method, primary, after: after) if role == :stage }
      observe_files(configure) { assert_same primary, assert_raises(IOError) { owner.publish! } }
      assert_failed(owner, primary)
      refute File.exist?(@path)
      # No initial identity/full written revision means no pathname cleanup.
      assert_equal %i[stat write].include?(method), File.exist?(@stage)
    end
  end

  def test_link_failures_collision_and_lost_return_never_remove_a_final_destination
    %i[before collision after].each do |cut|
      owner = publication("link-#{cut}.json")
      primary = IOError.new("synthetic link return failure")
      original = File.method(:link)
      wrapper = lambda do |source, destination|
        case cut
        when :before then raise primary
        when :collision
          File.write(destination, "foreign destination")
          original.call(source, destination)
        when :after
          original.call(source, destination)
          raise primary
        end
      end
      observe_files do
        File.stub(:link, wrapper) { assert_raises(cut == :collision ? Errno::EEXIST : IOError) { owner.publish! } }
      end
      assert_failed(owner, cut == :collision ? nil : primary)
      if cut == :before
        refute File.exist?(@path)
        refute File.exist?(@stage)
      elsif cut == :collision
        assert_equal "foreign destination", File.binread(@path)
        refute File.exist?(@stage)
      else
        assert_equal JSON.pretty_generate(@contents) + "\n", File.binread(@path)
        assert File.exist?(@stage), "a missing actual link return cannot adopt nlink2"
        assert_equal 2, File.stat(@path).nlink
      end
    end
  end

  def test_stage_replacement_in_place_mutation_and_extra_link_before_cleanup_are_retained
    %i[replacement mutation extra_link].each do |cut|
      owner = publication("changed-#{cut}.json")
      primary = IOError.new("synthetic interruption before publication")
      original_link = File.method(:link)
      wrapper = lambda do |_source, _destination|
        case cut
        when :replacement
          File.rename(@stage, "#{@stage}.original")
          File.write(@stage, "foreign stage")
        when :mutation
          bytes = File.binread(@stage)
          File.binwrite(@stage, "X" + bytes.byteslice(1..))
        when :extra_link
          original_link.call(@stage, "#{@stage}.extra")
        end
        raise primary
      end
      observe_files { File.stub(:link, wrapper) { assert_raises(IOError) { owner.publish! } } }
      assert_failed(owner, primary)
      assert File.exist?(@stage)
      refute_empty owner.cleanup_errors
      assert_equal "foreign stage", File.binread(@stage) if cut == :replacement
      assert_equal "X", File.binread(@stage).byteslice(0, 1) if cut == :mutation
      assert_equal 2, File.stat(@stage).nlink if cut == :extra_link
      refute File.exist?(@path)
    end
  end

  def test_parent_replacement_does_not_remove_entries_in_either_directory
    owner = publication
    original_parent = "#{@parent}-original"
    primary = IOError.new("synthetic parent replacement")
    wrapper = lambda do |*|
      File.rename(@parent, original_parent)
      Dir.mkdir(@parent, 0o700)
      File.write(@stage, "foreign parent stage")
      raise primary
    end
    observe_files { File.stub(:link, wrapper) { assert_raises(IOError) { owner.publish! } } }
    assert_failed(owner, primary)
    assert_equal "foreign parent stage", File.binread(@stage)
    assert File.exist?(File.join(original_parent, File.basename(@stage)))
    refute_empty owner.cleanup_errors
  end

  def test_post_unlink_replacements_and_lost_return_cannot_produce_success
    %i[stage_recreated destination_replaced lost_return].each do |cut|
      owner = publication("unlink-#{cut}.json")
      original = File.method(:unlink)
      primary = IOError.new("synthetic unlink return failure")
      wrapper = lambda do |path|
        result = original.call(path)
        if path == @stage
          case cut
          when :stage_recreated then File.write(@stage, "new foreign stage")
          when :destination_replaced
            original.call(@path)
            File.write(@path, "new foreign destination")
          when :lost_return then raise primary
          end
        end
        result
      end
      observe_files { File.stub(:unlink, wrapper) { assert_raises(cut == :lost_return ? IOError : Failure) { owner.publish! } } }
      assert_failed(owner, cut == :lost_return ? primary : nil)
      assert File.exist?(@path), "cleanup never removes a final destination"
      assert_equal "new foreign stage", File.binread(@stage) if cut == :stage_recreated
      assert_equal "new foreign destination", File.binread(@path) if cut == :destination_replaced
      refute_empty owner.cleanup_errors
    end
  end

  def test_original_interrupt_and_system_exit_keep_identity_and_cause_despite_independent_close_failures
    [Interrupt.new("synthetic interruption"), SystemExit.new(75), IOError.new("synthetic primary")].each_with_index do |primary, index|
      owner = publication("primary-#{index}.json")
      original_cause = primary.cause
      closes, cleanup = [], {}
      configure = lambda do |role, file|
        cleanup[role] = IOError.new("synthetic #{role} close failure after actual close")
        original = file.method(:close)
        file.define_singleton_method(:close) do
          closes << role
          original.call
          raise cleanup.fetch(role)
        end
      end
      observe_files(configure) do
        File.stub(:link, ->(*) { raise primary }) do
          assert_same primary, assert_raises(primary.class) { owner.publish! }
        end
      end
      assert_failed(owner, primary)
      assert_same original_cause, primary.cause
      assert_equal %i[stage parent], closes
      cleanup.each_value { |error| assert_includes owner.cleanup_errors, error }
      assert @opened.last(2).all? { |_, file| file.closed? }
      assert_raises(Failure) { owner.publish! }
      assert_equal %i[stage parent], closes, "failed closes must not be retried"
    end
  end

  def test_parent_sync_or_returned_close_error_denies_success_even_when_final_bytes_survive
    %i[fsync close].each do |method|
      owner = publication("parent-#{method}.json")
      primary = IOError.new("synthetic parent #{method} failure")
      configure = ->(role, file) { fail_once(file, method, primary, after: true) if role == :parent }
      observe_files(configure) { assert_same primary, assert_raises(IOError) { owner.publish! } }
      assert_failed(owner, primary)
      assert_equal JSON.pretty_generate(@contents) + "\n", File.binread(@path)
      refute File.exist?(@stage)
      assert_equal 1, File.stat(@path).nlink
      assert @opened.last(2).all? { |_, file| file.closed? }
    end
  end

  def test_created_stage_without_original_open_return_is_not_recovered_from_its_path
    owner = publication
    primary = IOError.new("synthetic lost acquisition return")
    configure = lambda do |role, file|
      if role == :stage
        # This fault model itself owns the lost return; close its real handle
        # before raising. The helper never sees that token or gains its proof.
        file.close
        raise primary
      end
    end
    observe_files(configure) { assert_same primary, assert_raises(IOError) { owner.publish! } }
    assert_failed(owner, primary)
    assert File.exist?(@stage)
    assert_equal "", File.binread(@stage)
    refute File.exist?(@path)
    refute_empty owner.cleanup_errors
  end

  def test_final_ensure_interruption_is_retained_and_cannot_leave_readable_success
    [Interrupt.new("synthetic final-unwind interruption"), SystemExit.new(75)].each_with_index do |primary, index|
      owner = publication("final-unwind-#{index}.json")
      original_cause = primary.cause
      original = owner.method(:finish_unwind!)
      owner.define_singleton_method(:finish_unwind!) do
        original.call
        raise primary # Synchronous finite cut in the actual final ensure, not a signal/thread.
      end
      observe_files { assert_same primary, assert_raises(primary.class) { owner.publish! } }
      assert_failed(owner, primary)
      assert_same original_cause, primary.cause
      assert_equal JSON.pretty_generate(@contents) + "\n", File.binread(@path)
      refute File.exist?(@stage)
      assert_equal 1, File.stat(@path).nlink
    end
  end

  def test_post_cleanup_interruption_precedes_synthetic_nonlocal_failure
    [Interrupt.new("synthetic pending-delivery interruption"), SystemExit.new(0)].each_with_index do |primary, index|
      owner = publication("post-cleanup-#{index}.json")
      original_cause = primary.cause
      owner.define_singleton_method(:admit_success!) { raise primary }
      observe_files { assert_same primary, assert_raises(primary.class) { owner.publish! } }
      assert_failed(owner, primary)
      assert_same original_cause, primary.cause
      assert_equal JSON.pretty_generate(@contents) + "\n", File.binread(@path)
      refute File.exist?(@stage)
      assert_equal 1, File.stat(@path).nlink
    end
  end
end
