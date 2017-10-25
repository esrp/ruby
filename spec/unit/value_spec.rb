RSpec.describe ESRP::Value do
  let(:instance) { described_class.new(value) }

  let(:num) { 14159265359   }
  let(:hex) { '034bf53e4f'  }
  let(:bin) { "\x03K\xF5>O".force_encoding(Encoding::BINARY) }

  describe '#hex' do
    subject { instance.hex }

    context 'from hex string' do
      let(:value) { hex }

      it { expect(subject).to eql(hex) }
    end

    context 'from number' do
      let(:value) { num }

      it { expect(subject).to eql(hex) }
    end

    context 'from byte string' do
      let(:value) { bin }

      it { expect(subject).to eql(hex) }
    end
  end

  describe '#int' do
    subject { instance.int }

    context 'from hex string' do
      let(:value) { hex }

      it { expect(subject).to equal(num) }
    end

    context 'from number' do
      let(:value) { num }

      it { expect(subject).to equal(num) }
    end

    context 'from byte string' do
      let(:value) { bin }

      it { expect(subject).to equal(num) }
    end
  end

  describe '#bin' do
    subject { instance.bin }

    context 'from hex string' do
      let(:value) { hex }

      it { expect(subject).to eql(bin) }
    end

    context 'from number' do
      let(:value) { num }

      it { expect(subject).to eql(bin) }
    end

    context 'from byte string' do
      let(:value) { bin }

      it { expect(subject).to eql(bin) }
    end
  end
end
