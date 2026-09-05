# frozen_string_literal: true

require_relative "apple_store"

module MobileReleaseKit
  # Apple does not document idempotency keys or a visibility deadline for its
  # create endpoints. Absence in a later process is NOT permission to POST again.
  # This guard grants one request per logical resource, never a generic retry.
  class AppleCreateRetry
    DOMAIN = "mrk-ios-create-retry-v1"
    TYPES = %w[appStoreVersions appStoreVersionLocalizations appInfoLocalizations
               appScreenshotSets appScreenshots appStoreReviewDetails
               reviewSubmissions reviewSubmissionItems betaBuildLocalizations
               betaAppReviewSubmissions betaGroupRelationships].freeze
    class Denied < ContractError; end
    attr_reader :inventory

    def initialize(intent_sha256:, stage:, bundle_id:, app_id:, version:, build_number:, build_id:,
                   authority:, authorized_by:, environment:, journal:, prior_claim: false)
      @intent, @stage = intent_sha256, stage
      @application = { "bundleId" => bundle_id, "appStoreAppId" => app_id }
      @candidate = { "marketingVersion" => version, "buildNumber" => build_number, "storeBuildId" => build_id }
      @scope = { "appStoreAppId" => app_id, "platform" => "IOS", "marketingVersion" => version,
                 "buildNumber" => build_number, "storeBuildId" => build_id }
      @authority, @authorized_by, @environment, @journal = authority, authorized_by, environment, journal
      @prior_claim = prior_claim
      @nodes, @used, @resolved, @replacement = {}, {}, {}, {}
      @operator_retry = false
    end

    def identity(type, locator = {})
      raise ContractError, "Unsupported Apple creation resource" unless TYPES.include?(type)
      { "resourceType" => type, "scope" => @scope, "locator" => locator }
    end

    def logical_key(type, locator = {})
      Digest::SHA256.hexdigest("#{DOMAIN}:logical-key:#{MobileReleaseKit.canonical_json(identity(type, locator))}")
    end

    def present(type, id)
      unless id.is_a?(String) && id.match?(/\A[A-Za-z0-9_.-]{1,255}\z/)
        raise ContractError, "Apple create parent identity is invalid"
      end
      { "mode" => "present", "resourceType" => type, "id" => id }
    end

    def missing(type, locator = {})
      { "mode" => "missing", "resourceType" => type, "logicalKeySha256" => logical_key(type, locator) }
    end

    def automatic_info(reference_sha256)
      { "mode" => "automatic", "resourceType" => "appInfos", "appStoreAppId" => @scope.fetch("appStoreAppId"),
        "referenceSha256" => reference_sha256, "versionKeySha256" => logical_key("appStoreVersions") }
    end

    def node(type, locator:, parent:, target:, dependencies: [])
      deps = dependencies.dup
      deps << parent.fetch("logicalKeySha256") if parent.fetch("mode") == "missing"
      deps << parent.fetch("versionKeySha256") if parent.fetch("mode") == "automatic"
      {
        "logicalIdentity" => identity(type, locator), "logicalKeySha256" => logical_key(type, locator),
        "resourceType" => type, "method" => "POST", "endpointKind" => type, "parent" => parent,
        "dependencies" => deps.uniq.sort, "targetSha256" => Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(target)),
      }
    end

    def build_inventory(public_state, nodes)
      raise ContractError, "Apple retry creation inventory is oversized" if nodes.length > 2_000
      keys = nodes.map { |node| node.fetch("logicalKeySha256") }
      raise ContractError, "Apple retry logical keys are duplicated" unless keys.uniq.length == keys.length
      # Dependencies must be other missing creates. Existing parents are IDs,
      # never an unbound logical reference. Verify acyclic resolution as well.
      completed = []
      until completed.length == keys.length
        available = nodes.reject { |node| completed.include?(node.fetch("logicalKeySha256")) }.select do |node|
          (node.fetch("dependencies") - completed).empty?
        end
        raise ContractError, "Apple retry dependencies are missing or cyclic" if available.empty?
        completed.concat(available.map { |node| node.fetch("logicalKeySha256") })
      end
      result = {
        "documentType" => "ios-create-retry-inventory", "schemaVersion" => 1,
        "operationIntentSha256" => @intent, "stage" => @stage, "platform" => "ios",
        "application" => @application, "candidate" => @candidate,
        "publicStateSha256" => Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(public_state)),
        "creates" => nodes.sort_by { |node| node.fetch("logicalKeySha256") },
      }
      raise ContractError, "Apple retry inventory exceeds the evidence bound" if MobileReleaseKit.canonical_json(result).bytesize > 1024 * 1024
      result
    end

    def arm!(public_state:, nodes:, resuming:)
      raise ContractError, "Apple create authorization can be armed only once" if @inventory
      @inventory = build_inventory(public_state, nodes)
      @inventory_hash = Digest::SHA256.hexdigest(MobileReleaseKit.canonical_json(@inventory))
      if resuming && nodes.any?
        expected = "retry-ios-operation-creates:#{@intent}:#{@inventory_hash}"
        unless fresh_recovery? && @environment["MOBILE_RELEASE_RECOVERY_CONFIRMATION"] == expected
          @journal.call("create-retry-required", { "createRetryInventory" => @inventory, "confirmation" => expected })
          raise ContractError, "A prior Apple creation may still be accepted. Resolve that ambiguity independently; use a NEW protected first-attempt recovery dispatch with #{expected}"
        end
        @operator_retry = true
      end
      @nodes = nodes.to_h { |node| [node.fetch("logicalKeySha256"), node] }
      # Written before ANY mutation, not after a request. A new process on this
      # same runner/attempt may reconcile, but cannot reuse this grant.
      @journal.call("execution-claimed", { "executedBy" => @authority, "inventorySha256" => @inventory_hash })
      self
    end

    def fresh_recovery?
      @authority.fetch("attempt") == 1 && @authority.fetch("event") == "workflow_dispatch" &&
        @authority.fetch("runId") != @authorized_by.fetch("runId") &&
        @environment["MOBILE_RELEASE_RECOVERY_RUN_ID"] == @authorized_by.fetch("runId") && !@prior_claim
    end

    def resolve!(type, locator, id)
      key = logical_key(type, locator)
      if @resolved[key] && @resolved[key] != id && !(@replacement[key] == @resolved[key] && @used.key?(key))
        raise ContractError, "Apple created-resource identity changed during this execution"
      end
      present(type, id) # validate the ID, including response-only IDs
      @resolved[key] = id
    end

    def permit_replacement!(node, original_id)
      key = node.fetch("logicalKeySha256")
      if @used.key?(key) || @replacement.key?(key)
        raise ContractError, "Screenshot creation budget is exhausted; retain the original reservation"
      end
      raise ContractError, "Only an exact screenshot reservation can be replaced" unless node.fetch("resourceType") == "appScreenshots"
      @replacement[key] = original_id
      @nodes[key] = node
      @resolved.delete(key)
    end

    def consume!(type, locator:, parent_id:)
      raise Denied, "Apple creation guard is not armed" unless @inventory
      key = logical_key(type, locator)
      node = @nodes[key]
      raise Denied, "Apple create is outside the authorized missing-resource inventory" unless node
      raise Denied, "Apple resource create was already dispatched; only readback is safe" if @used.key?(key)
      parent = node.fetch("parent")
      expected_parent = case parent.fetch("mode")
                        when "present" then parent.fetch("id")
                        when "missing" then @resolved[parent.fetch("logicalKeySha256")]
                        when "automatic" then @resolved["automatic-app-info"]
                        end
      raise Denied, "Apple create parent is missing or substituted" unless expected_parent && expected_parent == parent_id
      unless node.fetch("dependencies").all? { |dependency| @resolved.key?(dependency) }
        raise Denied, "Apple create dependency has not been observed"
      end
      @used[key] = { "logicalKeySha256" => key, "resourceId" => nil }
      @journal.call("create-dispatched", { "logicalKeySha256" => key, "executedBy" => @authority })
      key
    end

    def resolve_automatic_info!(id)
      present("appInfos", id)
      if @resolved["automatic-app-info"] && @resolved["automatic-app-info"] != id
        raise ContractError, "Automatically initialized AppInfo identity changed"
      end
      @resolved["automatic-app-info"] = id
    end

    def observe!(type, locator:, id:)
      resolve!(type, locator, id)
      key = logical_key(type, locator)
      @used[key]["resourceId"] = id if @used[key]
    end

    def retry_evidence
      return nil unless @operator_retry && @used.any?
      raise ContractError, "Retried Apple resource creation lacks exact readback" unless @used.values.all? { |entry| entry.fetch("resourceId") }
      authorized_keys = @inventory.fetch("creates").map { |node| node.fetch("logicalKeySha256") }
      used = @used.values.select { |entry| authorized_keys.include?(entry.fetch("logicalKeySha256")) }
      return nil if used.empty?
      { "mode" => "operator-authorized-create-retry", "inventorySha256" => @inventory_hash,
        "inventory" => @inventory, "executedBy" => @authority, "usedCreates" => used.sort_by { |entry| entry.fetch("logicalKeySha256") } }
    end
  end
end
