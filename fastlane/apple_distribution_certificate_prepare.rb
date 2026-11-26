# frozen_string_literal: true

# The same original command-six fixed stored-key verification. Refuse before
# any provider write if the nominated offline resources cannot be validated.
require_relative 'apple_distribution_certificate_policy'
require_relative 'apple_distribution_key'

begin
  MRKAppleDistributionCertificate.preflight_resources!
  status = MRKAppleDistributionKey.verify_main(ARGV)
rescue Exception
  status = 1
end
exit status
