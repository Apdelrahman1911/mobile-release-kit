# frozen_string_literal: true

# Bundler 4.0.16's SharedHelpers#set_rubyopt inserts an absolute require path
# without quoting; Ruby splits RUBYOPT on spaces. Use Bundler's supported setup
# API and an exact owned load path instead, including after Ruby re-execution.
root = File.expand_path("..", __dir__)
library = File.join(root, "lib/ruby/gems/3.3.0/gems/bundler-4.0.16/lib")
$LOAD_PATH.unshift(library)
require File.join(library, "bundler/setup")
abort "The packaged Store runtime requires Bundler 4.0.16." unless Bundler::VERSION == "4.0.16"
# Requiring this pathless shim repeats the correction in every child, rather
# than allowing that child's Bundler setup to restore the broken RUBYOPT.
ENV["RUBYOPT"] = "-rmrk_bundle_setup"
ENV["RUBYLIB"] = [File.join(root, "bin"), library].join(File::PATH_SEPARATOR)
