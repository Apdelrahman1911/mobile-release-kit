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

  def inspect_node(node, path, anchors = {}, steps: false)
    assert_instance_of Psych::Nodes::Sequence, node, "#{path} must be a sequence" if steps
    if node.is_a?(Psych::Nodes::Alias)
      assert anchors.key?(node.anchor), "undefined YAML alias #{node.anchor.inspect} at #{path}"
    elsif node.respond_to?(:anchor) && node.anchor
      anchors[node.anchor] = node
    end
    case node
    when Psych::Nodes::Mapping
      seen = {}
      node.children.each_slice(2) do |key, value|
        name = scalar_key(key)
        unless name.nil?
          refute seen.key?(name), "duplicate YAML key #{name.inspect} at #{path}"
          seen[name] = true
        end
        inspect_node(value, name.nil? ? path : "#{path}.#{name}", anchors, steps: name == "steps")
      end
    when Psych::Nodes::Sequence
      node.children.each_with_index do |child, index|
        child_path = "#{path}[#{index}]"
        validate_step(child, child_path, anchors) if steps
        inspect_node(child, child_path, anchors)
      end
    end
  end

  def validate_step(step, path, anchors)
    step = anchors[step.anchor] if step.is_a?(Psych::Nodes::Alias)
    assert_instance_of Psych::Nodes::Mapping, step, "#{path} must be a mapping or an alias to a preceding mapping"
    keys = step.children.each_slice(2).filter_map { |key, _value| scalar_key(key) }
    execution_keys = keys & ["run", "uses"]
    assert_equal 1, execution_keys.length, "#{path} must have exactly one of run/uses"
  end

  def test_step_aliases_still_require_one_executable_mapping
    valid = "steps: [&step {run: 'echo test'}, *step]\n"
    inspect_node(Psych.parse(valid).root, "fixture")
    ["steps: [*step, &step {run: 'echo test'}]\n",
     "fixture: &step 'echo test'\nsteps: [*step]\n",
     "fixture: &step {}\nsteps: [*step]\n",
     "fixture: &step {run: 'echo test', uses: 'fixture/action@v1'}\nsteps: [*step]\n",
     "fixture: &step {run: 'echo test', run: 'echo duplicate'}\nsteps: [*step]\n"].each do |invalid|
      assert_raises(Minitest::Assertion) { inspect_node(Psych.parse(invalid).root, "fixture") }
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
