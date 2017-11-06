# frozen_string_literal: true

RSpec.describe ESRP::Engine do
  let(:instance) { ESRP::Engine.new(crypto, group) }

  let(:vectors)  { TestVectors.new('base') }
  let(:crypto)   { instance_double('ESRP::Crypto') }
  let(:group)    { instance_double('ESRP::Group', g: vectors[:g], N: vectors[:N]) }

  describe '#calc_v' do
    subject { instance.calc_v(x) }
    let(:expected) { vectors.expected(:v) }

    let(:x) { vectors[:x] }

    it 'calculates proper "v"' do
      expect(subject.hex).to eql(expected)
    end
  end

  describe '#calc_A' do
    subject { instance.calc_A(a) }
    let(:expected) { vectors.expected(:A) }

    let(:a) { vectors[:a] }

    it 'calculates proper "A"' do
      expect(subject.hex).to eql(expected)
    end
  end

  describe '#calc_B' do
    subject { instance.calc_B(b, v) }
    let(:expected) { vectors.expected(:B) }

    let(:b) { vectors[:b] }
    let(:v) { instance.calc_v(vectors[:x]) }

    before(:each) do
      allow(instance).to receive(:k).and_return(vectors[:k])
    end

    it 'calculates proper "B"' do
      expect(subject.hex).to eql(expected)
    end
  end

  describe '#calc_client_S' do
    subject { instance.calc_client_S(bb, a, x, u) }
    let(:expected) { vectors.expected(:S) }

    let(:bb) { instance.calc_B(vectors[:b], instance.calc_v(x)) }
    let(:a)  { vectors[:a] }
    let(:x)  { vectors[:x] }
    let(:u)  { vectors[:u] }

    before(:each) do
      allow(instance).to receive(:k).and_return(vectors[:k])
    end

    it 'calculates proper "S"' do
      expect(subject.hex).to eql(expected)
    end
  end

  describe '#calc_server_S' do
    subject { instance.calc_server_S(aa, b, v, u) }
    let(:expected) { vectors.expected(:S) }

    let(:aa) { instance.calc_A(vectors[:a]) }
    let(:b)  { vectors[:b] }
    let(:v)  { instance.calc_v(vectors[:x]) }
    let(:u)  { vectors[:u] }

    it 'calculates proper "S"' do
      expect(subject.hex).to eql(expected)
    end
  end


end
