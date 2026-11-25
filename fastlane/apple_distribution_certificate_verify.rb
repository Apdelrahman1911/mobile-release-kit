# frozen_string_literal: true

require_relative 'apple_distribution_certificate_policy'
begin
  status = MRKAppleDistributionCertificate.main(ARGV)
rescue Exception
  status = 1
end
exit status
