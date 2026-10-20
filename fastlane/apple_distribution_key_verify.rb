# frozen_string_literal: true

# Fixed read-only internal companion. Same owned runtime/FiniteScratch and
# private channel as key preparation; no key generation or provider action.
require_relative 'apple_distribution_key'

if $PROGRAM_NAME == __FILE__
  begin
    status = MRKAppleDistributionKey.verify_main(ARGV)
  rescue Exception
    status = 1 # Do not print fatal exceptions/backtraces/private input.
  end
  exit status
end
