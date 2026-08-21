# frozen_string_literal: true

require "minitest/autorun"
require "psych"

class WorkflowYamlStructureTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  WORKFLOWS = Dir[
    File.join(ROOT, ".github/workflows/*.yml"),
    File.join(ROOT, "templates/workflows/*.yml"),
  ].sort.freeze

  def scalar_key(node)
    node.is_a?(Psych::Nodes::Scalar) ? node.value : nil
  end

  def inspect_node(node, path)
    case node
    when Psych::Nodes::Mapping
      seen = {}
      node.children.each_slice(2) do |key, value|
        name = scalar_key(key)
        unless name.nil?
          refute seen.key?(name), "duplicate YAML key #{name.inspect} at #{path}"
          seen[name] = true
          validate_steps(value, "#{path}.steps") if name == "steps"
        end
        inspect_node(value, name.nil? ? path : "#{path}.#{name}")
      end
    when Psych::Nodes::Sequence
      node.children.each_with_index { |child, index| inspect_node(child, "#{path}[#{index}]") }
    end
  end

  def validate_steps(node, path)
    assert_instance_of Psych::Nodes::Sequence, node, "#{path} must be a sequence"
    node.children.each_with_index do |step, index|
      assert_instance_of Psych::Nodes::Mapping, step, "#{path}[#{index}] must be a mapping"
      keys = step.children.each_slice(2).filter_map { |key, _value| scalar_key(key) }
      execution_keys = keys & ["run", "uses"]
      assert_equal 1, execution_keys.length, "#{path}[#{index}] must have exactly one of run/uses"
    end
  end

  def test_workflows_have_no_duplicate_mapping_keys_or_empty_steps
    refute_empty WORKFLOWS
    WORKFLOWS.each do |path|
      document = Psych.parse_file(path)
      refute_nil document, "could not parse #{path}"
      inspect_node(document.root, path.delete_prefix("#{ROOT}/"))
    end
  end
end
