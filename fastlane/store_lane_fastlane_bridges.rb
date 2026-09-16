# frozen_string_literal: true

require "erb"
require_relative "store_lane_runtime"

module MobileReleaseKit
  # Only the pinned first-party iOS/API-key Pilot path is admitted. No global
  # Dir/FileUtils patch, gem modification, super through unsafe cleanup, password
  # retry, or adoption of a temporary pathname created by an upstream method.
  module StoreLaneFastlaneBridges
    SOURCES = {
      "fastlane_core/lib/fastlane_core/fastlane_pty.rb" => "641e0b3ea465517a544ce59f15474480613adccdde0e0bbb8af1039b87c3fcc7",
      "fastlane_core/lib/fastlane_core/itunes_transporter.rb" => "2a55acc0841ac715a3d55ea23a31710e0ab41977ea2684848edb94624838005c",
      "fastlane_core/lib/fastlane_core/ipa_upload_package_builder.rb" => "4ea5857408aaae25656c4be1009361214cffb8a68ee8a67b8318c30489c4be54",
      "pilot/lib/pilot/build_manager.rb" => "5dbd5904563779b46f738c5c4d2e1e19cb1b68bbd8882b72f8c20514f313bc89",
      "fastlane_core/lib/assets/XMLTemplate.xml.erb" => "06c2baa8929fd215c25e4782c1c3859a18b588d4653f46ceee90ef2c95c6af11",
    }.freeze
    private_constant :SOURCES

    def self.refuse!(runtime, reason)
      error = StoreLaneRuntime::Error.new(reason)
      runtime.mark_unknown!(error)
      raise error
    end

    def self.install!(runtime)
      runtime.origin!
      runtime.invocation.require_upload_continuation!
      specification = Gem.loaded_specs.fetch("fastlane")
      refuse!(runtime, :fastlane_version) unless specification.version.to_s == "2.235.0"
      root = File.realpath(specification.full_gem_path)
      originals = SOURCES.to_h do |relative, digest|
        path = File.join(root, relative)
        refuse!(runtime, :fastlane_source_path) unless File.realpath(path) == path
        [relative, runtime.resources.read_pinned_source!(path, digest)]
      end
      # Load fixed pinned interfaces only after the source checks; no action or
      # Store request is invoked by these installation statements.
      require "fastlane_core/fastlane_pty"
      require "fastlane_core/itunes_transporter"
      require "fastlane_core/ipa_upload_package_builder"
      require "pilot/build_manager"
      interfaces = [
        [FastlaneCore::FastlanePty.singleton_class, :spawn, "fastlane_core/lib/fastlane_core/fastlane_pty.rb", 23,
         [[:req, :command], [:block, :block]]],
        [FastlaneCore::TransporterExecutor, :prepare, "fastlane_core/lib/fastlane_core/itunes_transporter.rb", 70,
         [[:keyreq, :original_api_key]]],
        [FastlaneCore::ItunesTransporter, :upload, "fastlane_core/lib/fastlane_core/itunes_transporter.rb", 832,
         [[:opt, :app_id], [:opt, :dir], [:key, :package_path], [:key, :asset_path], [:key, :platform]]],
        [FastlaneCore::IpaUploadPackageBuilder, :generate, "fastlane_core/lib/fastlane_core/ipa_upload_package_builder.rb", 15,
         [[:key, :app_id], [:key, :ipa_path], [:key, :package_path], [:key, :platform], [:key, :app_identifier], [:key, :short_version], [:key, :bundle_version]]],
        [Pilot::BuildManager, :upload, "pilot/lib/pilot/build_manager.rb", 13, [[:req, :options]]],
      ]
      interfaces.each do |owner, name, relative, line, parameters|
        method = owner.instance_method(name)
        source = method.source_location
        unless method.owner.equal?(owner) && source && File.realpath(source.fetch(0)) == File.join(root, relative) &&
               source.fetch(1) == line && method.parameters == parameters
          refuse!(runtime, :fastlane_interface)
        end
      end
      unless FastlaneCore::Helper.is_mac? == runtime.binding.fetch("macos") && !FastlaneCore::Helper.test?
        refuse!(runtime, :fastlane_platform)
      end
      FastlaneCore::FastlanePty.singleton_class.prepend(PipeBridge)
      FastlaneCore::TransporterExecutor.prepend(KeyBridge)
      FastlaneCore::ItunesTransporter.prepend(TransporterBridge)
      FastlaneCore::IpaUploadPackageBuilder.prepend(PackageBridge)
      Pilot::BuildManager.prepend(PilotBridge)
      originals.fetch("fastlane_core/lib/assets/XMLTemplate.xml.erb")
    end

    def self.runtime!
      StoreLaneRuntime.current_runtime!.tap(&:require_active!)
    end

    module PipeBridge
      def spawn(command, &block)
        StoreLaneFastlaneBridges.runtime!.invocation.spawn_with_pipes(command, &block)
      end
    end

    module KeyBridge
      def prepare(original_api_key:)
        runtime = StoreLaneFastlaneBridges.runtime!
        unless original_api_key.instance_of?(Hash) &&
               original_api_key[:key_id] == runtime.binding.fetch("key_id") &&
               original_api_key[:key].instance_of?(String) && !original_api_key[:key].empty?
          StoreLaneFastlaneBridges.refuse!(runtime, :api_key_route)
        end
        api_key = original_api_key.dup
        api_key[:key_dir] = runtime.resources.write_api_key!(key_id: api_key[:key_id],
          contents: api_key[:key], shell: instance_of?(FastlaneCore::ShellScriptTransporterExecutor))
        api_key
      end
    end

    module TransporterBridge
      def upload(app_id = nil, dir = nil, package_path: nil, asset_path: nil, platform: nil)
        runtime = StoreLaneFastlaneBridges.runtime!
        unless app_id.nil? && dir.nil? && platform == "ios" && @api_key.instance_of?(Hash) &&
               [FastlaneCore::AltoolTransporterExecutor, FastlaneCore::JavaTransporterExecutor,
                FastlaneCore::ShellScriptTransporterExecutor].any? { |type| @transporter_executor.instance_of?(type) }
          StoreLaneFastlaneBridges.refuse!(runtime, :transporter_route)
        end
        runtime.resources.require_upload_inputs!(package_path: package_path, asset_path: asset_path)
        force_itmsp = FastlaneCore::Env.truthy?("ITMSTRANSPORTER_FORCE_ITMS_PACKAGE_UPLOAD")
        actual_dir = if runtime.binding.fetch("macos") && asset_path && !force_itmsp
                       runtime.resources.copy_upload_asset!(source: asset_path)
                     else
                       package_path
                     end
        FastlaneCore::UI.message("Going to upload updated app to App Store Connect")
        FastlaneCore::UI.success("This might take a few minutes. Please don't interrupt the script.")
        password_placeholder = @jwt.nil? ? "YourPassword" : nil
        jwt_placeholder = @jwt.nil? ? nil : "YourJWT"
        api_key_placeholder = {key_id: "YourKeyID", issuer_id: "YourIssuerID", key_dir: "YourTmpP8KeyDir"}
        api_key = @transporter_executor.prepare(original_api_key: @api_key)
        upload_options = {provider_short_name: @provider_short_name, provider_public_id: @provider_public_id,
          jwt: @jwt, platform: platform, api_key: api_key}
        upload_options_placeholder = {provider_short_name: @provider_short_name, provider_public_id: @provider_public_id,
          jwt: jwt_placeholder, platform: platform, api_key: api_key_placeholder}
        command = @transporter_executor.build_upload_command(@user, @password, actual_dir, upload_options)
        FastlaneCore::UI.verbose(@transporter_executor.build_upload_command(@user, password_placeholder, actual_dir, upload_options_placeholder))
        runtime.require_active!
        runtime.resources.require_ready_for_executor!
        primary = nil
        begin
          result = @transporter_executor.execute(command, FastlaneCore::ItunesTransporter.hide_transporter_output?)
          # The fixed API-key lane has no password-acquisition/re-upload branch.
          # Ordinary errors still reach the existing readback-first reconciler.
        rescue Exception => error # rubocop:disable Lint/RescueException
          primary = error
          raise
        ensure
          begin
            runtime.resources.defer_removal!(api_key.fetch(:key_dir), primary: primary)
          rescue Exception => error # rubocop:disable Lint/RescueException
            runtime.mark_unknown!(primary || error)
            runtime.mark_unknown!(error, cleanup: true)
            raise primary || error, cause: (primary || error).cause
          end
        end
        runtime.require_active!
        if result
          FastlaneCore::UI.header("Successfully uploaded package to App Store Connect. It might take a few minutes until it's visible online.")
          runtime.resources.defer_removal!(actual_dir)
        else
          handle_error(@password)
        end
        result
      end
    end

    module PackageBridge
      def generate(app_id: nil, ipa_path: nil, package_path: nil, platform: nil, app_identifier: nil, short_version: nil, bundle_version: nil)
        runtime = StoreLaneFastlaneBridges.runtime!
        unless app_id.to_s == runtime.binding.fetch("app_id") && platform == "ios" &&
               [app_identifier, short_version, bundle_version].all? { |value| value.instance_of?(String) && !value.empty? }
          StoreLaneFastlaneBridges.refuse!(runtime, :package_route)
        end
        unless runtime.binding.fetch("macos")
          self.package_path = package_path
          copy_ipa(ipa_path)
          app_store_info_path = File.join(File.dirname(ipa_path), "AppStoreInfo.plist")
          if File.exist?(app_store_info_path) || File.symlink?(app_store_info_path)
            runtime.resources.copy_appstore_info!(source: app_store_info_path, pilot_path: self.package_path)
          end
          return self.package_path
        end
        self.package_path = runtime.resources.create_package!(pilot_path: package_path, app_id: app_id)
        copied = copy_ipa(ipa_path)
        attributes = runtime.resources.package_file_attributes!(copied)
        @data = {apple_id: app_id, file_size: attributes.fetch(:size), ipa_path: File.basename(copied),
          md5: attributes.fetch(:md5), archive_type: "bundle", platform: platform,
          app_identifier: app_identifier, short_version: short_version, bundle_version: bundle_version}
        xml = ERB.new(runtime.xml_template).result(binding)
        runtime.resources.write_metadata!(package_path: self.package_path, contents: xml)
        FastlaneCore::UI.success("Wrote XML data to '#{self.package_path}'") if FastlaneCore::Globals.verbose?
        self.package_path
      end

      private

      def copy_ipa(ipa_path)
        StoreLaneFastlaneBridges.runtime!.resources.copy_package_ipa!(ipa_path: ipa_path, package_path: package_path)
      end
    end

    module PilotBridge
      # Source-checked pinned method body. The single creation expression is
      # replaced BEFORE the builder receives a path. Fixed current callers also
      # reject generic pkg/password/changelog routes, which are not Store lanes.
      def upload(options)
        runtime = StoreLaneFastlaneBridges.runtime!
        unless runtime.binding.fetch("lane") == "ios_testflight_internal" && runtime.binding.fetch("mode") == "execute" &&
               options[:apple_id].to_s == runtime.binding.fetch("app_id") && options[:api_key].instance_of?(Hash) &&
               options[:ipa] == runtime.binding.fetch("artifact") && options[:pkg].nil? && options[:app_platform] == "ios" &&
               options[:skip_waiting_for_build_processing] == true && options[:skip_submission] == true &&
               options[:changelog].nil? && options[:distribute_external] == false &&
               [options[:app_identifier], options[:app_version], options[:build_number]].all? { |value| value.instance_of?(String) && !value.empty? }
          StoreLaneFastlaneBridges.refuse!(runtime, :pilot_route)
        end
        should_login_in_start = options[:apple_id].nil?
        start(options, should_login: should_login_in_start)
        FastlaneCore::UI.user_error!("No ipa or pkg file given") if config[:ipa].nil? && config[:pkg].nil?
        if config[:ipa] && config[:pkg]
          FastlaneCore::UI.important("WARNING: Both `ipa` and `pkg` options are defined either explicitly or with default_value (build found in directory)")
          FastlaneCore::UI.important("Uploading `ipa` is preferred by default. Set `app_platform` to `osx` to force uploading `pkg`")
        end
        check_for_changelog_or_whats_new!(options)
        FastlaneCore::UI.success("Ready to upload new build to TestFlight (App: #{fetch_app_id})...")
        dir = runtime.resources.create_pilot_root!
        platform = fetch_app_platform
        ipa_path = options[:ipa]
        if ipa_path && platform != "osx"
          asset_path = ipa_path
          app_identifier = config[:app_identifier] || fetch_app_identifier
          short_version = config[:app_version] || FastlaneCore::IpaFileAnalyser.fetch_app_version(ipa_path)
          bundle_version = config[:build_number] || FastlaneCore::IpaFileAnalyser.fetch_app_build(ipa_path)
          package_path = FastlaneCore::IpaUploadPackageBuilder.new.generate(app_id: fetch_app_id,
            ipa_path: ipa_path, package_path: dir, platform: platform, app_identifier: app_identifier,
            short_version: short_version, bundle_version: bundle_version)
        else
          # An admitted current caller cannot reach generic pkg creation.
          StoreLaneFastlaneBridges.refuse!(runtime, :pilot_platform_changed)
        end
        transporter = transporter_for_selected_team(options)
        result = transporter.upload(package_path: package_path, asset_path: asset_path, platform: platform)
        runtime.require_active!
        unless result
          transporter_errors = transporter.displayable_errors
          file_type = platform == "osx" ? "pkg" : "ipa"
          FastlaneCore::UI.user_error!("Error uploading #{file_type} file: \n #{transporter_errors}")
        end
        FastlaneCore::UI.success("Successfully uploaded the new binary to App Store Connect")
        return_when_build_appears = false
        if config[:skip_waiting_for_build_processing]
          if config[:changelog].nil?
            FastlaneCore::UI.important("`skip_waiting_for_build_processing` used and no `changelog` supplied - skipping waiting for build processing")
            return
          else
            FastlaneCore::UI.important("`skip_waiting_for_build_processing` used and `changelog` supplied - will wait until build appears on App Store Connect, update the changelog and then skip the rest of the remaining of the processing steps.")
            return_when_build_appears = true
          end
        end
        login unless should_login_in_start
        if config[:skip_waiting_for_build_processing].nil?
          FastlaneCore::UI.message("If you want to skip waiting for the processing to be finished, use the `skip_waiting_for_build_processing` option")
          FastlaneCore::UI.message("Note that if `skip_waiting_for_build_processing` is used but a `changelog` is supplied, this process will wait for the build to appear on App Store Connect, update the changelog and then skip the remaining of the processing steps.")
        end
        latest_build = wait_for_build_processing_to_be_complete(return_when_build_appears)
        distribute(options, build: latest_build)
      end
    end
    private_constant :PipeBridge, :KeyBridge, :TransporterBridge, :PackageBridge, :PilotBridge
  end
end
