# frozen_string_literal: true

# A second FIXED read entry on the existing selected-P8/raw-response owner.
# It requests profile + referenced certificate metadata, never profileContent,
# certificateContent, a relationship download, a second page or a write.
require_relative "apple_provisioning_bundle_read"

module MobileReleaseKit
  module AppleProfileRead
    class Input < AppleBundleRead::Input
      def request
        { "kind" => "list_profiles", "method" => "GET", "path" => "/v1/profiles", "body" => nil,
          "query" => AppleProvisioning::PROFILE_RELATIONS.merge(
            "filter[profileType]" => "IOS_APP_STORE", "fields[profiles]" => AppleProvisioning::PROFILE_FIELDS,
            "limit" => "200") }
      end

      def inspect = "#<AppleProfileRead::Input private>"
    end

    def self.main(arguments, environment, output)
      AppleBundleRead.main(arguments, environment, output, query: :profiles)
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    code = MobileReleaseKit::AppleProfileRead.main(ARGV, ENV, STDOUT)
  rescue Exception
    # Fatal/interrupted workers are failures, not observations or cleanup proof.
    Process.exit!(70)
  end
  exit(code)
end
