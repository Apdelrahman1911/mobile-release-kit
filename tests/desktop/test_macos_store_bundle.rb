# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "fileutils"
require "open3"
require "rbconfig"
require "json"

# Run in a disposable nonroot PID/network namespace. Uses the host Ruby only
# with an inert setup fixture: real Bundler/native Mac behavior is a CI smoke.
class MacStoreBundleTest < Minitest::Test
  TOOLS = File.expand_path("../../desktop/tools", __dir__)

  def with_runtime
    Dir.mktmpdir("mrk Ruby Store runtime ") do |root|
      library = File.join(root, "lib/ruby/gems/3.3.0/gems/bundler-4.0.16")
      FileUtils.mkdir_p(File.join(root, "bin"))
      FileUtils.mkdir_p(File.join(library, "lib/bundler"))
      FileUtils.mkdir_p(File.join(library, "exe"))
      FileUtils.cp(File.join(TOOLS, "macos_store_bundle.sh"), File.join(root, "bin/bundle"))
      File.chmod(0o755, File.join(root, "bin/bundle"))
      FileUtils.cp(File.join(TOOLS, "macos_store_bundle_setup.rb"), File.join(root, "bin/mrk_bundle_setup.rb"))
      File.symlink(RbConfig.ruby, File.join(root, "bin/ruby")) # Fixture only; production Ruby is an ordinary executable.
      File.write(File.join(library, "lib/bundler/setup.rb"), <<~RUBY)
        module Bundler; VERSION = "4.0.16"; end
        ENV["RUBYOPT"] = "-r" + __FILE__ # The exact upstream space-path failure.
      RUBY
      File.write(File.join(library, "exe/bundle"), 'require "json"; puts JSON.generate(ARGV)')
      yield root
    end
  end

  def command(root, *arguments)
    Open3.capture3({"PATH" => "/usr/bin:/bin", "RUBYOPT" => "-rDO_NOT_LOAD",
      "RUBYLIB" => "/never-use-ambient", "GEMRC" => "/never-use-ambient"},
      File.join(root, "bin/bundle"), *arguments, unsetenv_others: true)
  end

  def test_spaced_installation_preserves_script_arguments_exit_and_two_child_generations
    with_runtime do |root|
      script = File.join(root, "ordinary script.rb")
      File.write(script, <<~'RUBY')
        require "json"
        require "open3"
        require "rbconfig"
        if ARGV.first == "exit"
          exit 7
        end
        generation = Integer(ARGV.fetch(0))
        unless ENV.fetch("RUBYOPT") == "-rmrk_bundle_setup"
          abort "unsafe child options"
        end
        if generation > 0
          output, error, status = Open3.capture3(RbConfig.ruby, $PROGRAM_NAME, (generation - 1).to_s, ARGV.fetch(1))
          abort error unless status.success?
          print output
        else
          puts JSON.generate({"program" => $PROGRAM_NAME, "arguments" => ARGV,
            "rubyopt" => ENV.fetch("RUBYOPT"), "rubylib" => ENV.fetch("RUBYLIB"),
            "frozen" => ENV.fetch("BUNDLE_FROZEN"), "gemfile" => ENV.fetch("BUNDLE_GEMFILE")})
        end
      RUBY
      out, err, status = command(root, "exec", "ruby", script, "2", "value with spaces 'quotes'")
      assert status.success?, err
      result = JSON.parse(out)
      assert_equal script, result.fetch("program")
      assert_equal ["0", "value with spaces 'quotes'"], result.fetch("arguments")
      assert_equal "-rmrk_bundle_setup", result.fetch("rubyopt")
      assert_equal [File.join(root, "bin"), File.join(root, "lib/ruby/gems/3.3.0/gems/bundler-4.0.16/lib")].join(File::PATH_SEPARATOR), result.fetch("rubylib")
      assert_equal "true", result.fetch("frozen")
      assert_equal File.join(root, "tooling/Gemfile"), result.fetch("gemfile")
      _, _, status = command(root, "exec", "ruby", script, "exit")
      assert_equal 7, status.exitstatus
    end
  end

  def test_standard_cli_is_retained_but_arbitrary_exec_interpreters_are_refused
    with_runtime do |root|
      out, err, status = command(root, "check")
      assert status.success?, err
      assert_equal ["check"], JSON.parse(out)
      out, _, status = command(root, "exec", "sh", "-c", "echo unexpected")
      assert_equal 64, status.exitstatus
      assert_empty out
    end
  end
end
