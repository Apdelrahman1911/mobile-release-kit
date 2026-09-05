# frozen_string_literal: true

require "minitest/autorun"
require "minitest/mock"
require "rbconfig"
require_relative "../../fastlane/native_upload_validation"

class NativeUploadValidationTest < Minitest::Test
  def test_cancellation_or_io_error_at_first_setup_step_cleans_up_the_real_child
    [Interrupt.new("synthetic setup cancellation"), SystemExit.new(23), IOError.new("synthetic private diagnostic")].each do |injected_error|
      original_spawn = Open3.method(:popen3)
      pid = watchdog = nil
      watchdog_required = injected = false
      begin
        expected = injected_error.is_a?(IOError) ? MobileReleaseKit::ContractError : injected_error.class
        error = Open3.stub(:popen3, lambda do |*arguments, **options, &block|
          original_spawn.call(*arguments, **options) do |stdin, stdout, stderr, waiter|
            pid = waiter.pid
            original_close = stdin.method(:close)
            stdin.define_singleton_method(:close) do
              original_close.call unless closed?
              unless injected
                injected = true
                raise injected_error
              end
            end
            # A pre-fix failure must not leave this test hung with a live child.
            # Passing requires production cleanup, never this safety watchdog.
            watchdog = Thread.new do
              sleep 3
              if waiter.alive?
                watchdog_required = true
                Process.kill("KILL", -pid)
              end
            end
            block.call(stdin, stdout, stderr, waiter)
          end
        end) do
          assert_raises(expected) do
            MobileReleaseKit::NativeUploadValidation.capture(
              {}, [RbConfig.ruby, "-e", "sleep 30"], File.expand_path("../../fastlane", __dir__),
              max_seconds: 0.1, max_output_bytes: 1_024,
              label: "Synthetic", failure_message: "synthetic validation failure",
            )
          end
        end
        assert injected
        refute watchdog_required, "setup failure left cleanup to an external watchdog"
        assert_raises(Errno::ESRCH) { Process.kill(0, pid) }
        if injected_error.is_a?(IOError)
          refute_includes error.message, "private diagnostic"
        else
          assert_same injected_error, error, "cleanup must preserve the original cancellation"
        end
      ensure
        watchdog&.kill
        watchdog&.join
        if pid
          begin
            Process.kill("KILL", -pid)
          rescue Errno::ESRCH
            nil
          end
        end
      end
    end
  end
end
