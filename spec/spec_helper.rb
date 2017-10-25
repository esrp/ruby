if ENV['COVERAGE']
  require 'simplecov'
  SimpleCov.start do
    add_filter '/spec/'
  end
end

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'esrp/all'

Dir[File.join(Dir.pwd, 'spec/shared_examples/**/*.rb')].each { |f| require f }

RSpec.configure do |config|
  config.filter_run :focus
  config.run_all_when_everything_filtered = true
  config.shared_context_metadata_behavior = :apply_to_host_groups

  if config.files_to_run.one?
    config.full_backtrace = true

    config.default_formatter = 'doc'
  end

  config.order = :random

  Kernel.srand(config.seed)

  config.disable_monkey_patching!
  config.warnings = false

  config.expect_with :rspec do |expectations|
    expectations.syntax = :expect
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.syntax = :expect
    mocks.verify_partial_doubles = true
    mocks.verify_doubled_constant_names = true
  end
end
