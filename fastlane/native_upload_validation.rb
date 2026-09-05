# frozen_string_literal: true

require "open3"
require_relative "release_support"

module MobileReleaseKit
  # Share only bounded process capture. Platform-specific argv, environment,
  # result validation and eligibility remain in their respective adapters.
  module NativeUploadValidation
    module_function

    def capture(environment, argv, tooling_directory, max_seconds:, max_output_bytes:, label:, failure_message:)
      output = {}
      complete = false
      Open3.popen3(environment, *argv, chdir: File.realpath(tooling_directory), unsetenv_others: true, pgroup: true) do |stdin, stdout, stderr, waiter|
        begin
          # Install cleanup before even closing stdin: cancellation or an IO
          # error during setup still owns a live private child process group.
          stdin.close
          streams = [stdout, stderr]
          streams.each { |stream| output[stream] = +"".b }
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + max_seconds
          until streams.empty?
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise ContractError, "#{label} validation timed out; no upload is authorized" unless remaining.positive?
            ready = IO.select(streams, nil, nil, [remaining, 1].min)
            next unless ready
            ready.first.each do |stream|
              chunk = stream.read_nonblock(4_096, exception: false)
              if chunk.nil?
                streams.delete(stream)
              elsif chunk != :wait_readable
                output[stream] << chunk
                raise ContractError, "#{label} validation output exceeded its safety bound" if output[stream].bytesize > max_output_bytes
              end
            end
          end
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          unless remaining.positive? && waiter.join(remaining)
            raise ContractError, "#{label} validation timed out; no upload is authorized"
          end
          # Neither stream may be forwarded on failure. Native diagnostics can
          # include private filesystem, profile or environment information.
          raise ContractError, failure_message unless waiter.value.success?
          complete = true
          output.fetch(stdout)
        ensure
          # A reaped interpreter can leave native descendants holding its
          # pipes open. Kill the entire private group on every incomplete exit.
          unless complete
            begin
              Process.kill("KILL", -waiter.pid)
            rescue Errno::ESRCH
              nil
            end
          end
          waiter.join
        end
      end
    rescue SystemCallError, IOError
      raise ContractError, "#{label} validator could not be executed safely; no upload is authorized"
    end
  end
end
