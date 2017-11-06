# frozen_string_literal: true

require 'json'
require 'esrp/value'

class TestVectors
  ROOT = File.dirname(__FILE__)

  attr_reader :description

  def initialize(name)
    file = File.read(File.join(ROOT, 'vectors', "#{name}.json"))
    @content = JSON.load(file).freeze

    @description = @content['description'].freeze
    @values      = @content['values'].freeze
    @results     = @content['results'].freeze
  end

  def [](key)
    ESRP::Value.new(@values[key.to_s])
  end

  def expected(key)
    @results[key.to_s]
  end
end
