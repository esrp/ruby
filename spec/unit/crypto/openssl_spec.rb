# frozen_string_literal: true

RSpec.describe ESRP::Crypto::OpenSSL do
  let(:instance) { described_class.new(options) }

  describe '.new' do
    subject { instance }

    context 'when hash name is not applicable' do
      let(:options) do
        { hash: hash }
      end
      let(:hash) { :blake2b }

      it do
        expect { subject }.to raise_error(
          ESRP::Crypto::NotApplicableError,
          "hash: '#{hash}' is not a valid option, available options: sha1, sha256, sha384, sha512"
        )
      end
    end

    context 'when kdf name is not applicable' do
      let(:options) do
        { kdf: kdf }
      end
      let(:kdf) { :scrypt }

      it do
        expect { subject }.to raise_error(
          ESRP::Crypto::NotApplicableError,
          "kdf: '#{kdf}' is not a valid option, available options: pbkdf2, legacy"
        )
      end
    end

    context 'when mac name is not applicable' do
      let(:options) do
        { mac: mac}
      end
      let(:mac) { :foo }

      it do
        expect { subject }.to raise_error(
          ESRP::Crypto::NotApplicableError,
          "mac: '#{mac}' is not a valid option, available options: hmac, legacy"
        )
      end
    end
  end

  describe '#H' do
    subject { instance.H(message).hex }

    let(:message) { ESRP::Value.new('07c0') }

    context 'when hash: :sha1' do
      let(:options) do
        { hash: :sha1 }
      end

      it { expect(subject).to eql('00ff3b16b0f555d3feb62f988fb3aab81c1c50ea') }
    end

    context 'when hash: :sha256' do
      let(:options) do
        { hash: :sha256 }
      end

      it { expect(subject).to eql('34b902c818ebdb547c4aa8d161dd701bd5f78ac3df6b5ab7fac3c35dae795e56') }
    end

    context 'when hash: :sha384' do
      let(:options) do
        { hash: :sha384 }
      end

      it { expect(subject).to eql('87f7dd5d5e3b905a1f8317a170516d95717b488c1d8d49e5254cf30bbf5bbd822adcbf60c1b9aa0c100c28e2505fdfe8') }
    end

    context 'when hash: :sha512' do
      let(:options) do
        { hash: :sha512 }
      end

      it { expect(subject).to eql('ff860fd40517a0de51b3747587177f02aeffc629dd37934035ec79113733041a42c23ba503cf9294284bb5fc77d4242e17664fb4d1c69ee4e27e96d4c17a3fcd') }
    end

    context 'when hex: true' do
      let(:options) do
        { hex: true }
      end

      it { expect(subject).to eql('23d1c63672c74b3d0a0e2b14fcc9d511e8c5156f42294924a57a2d7c177328ca') }
    end
  end

  describe '#password_hash' do
    subject { instance.password_hash(salt, password).hex }

    let(:salt)     { ESRP::Value.new(1117) }
    let(:password) { 'verysecure' }

    context 'when kdf: :pbkdf2' do
      let(:options) do
        { kdf: :pbkdf2, hash: hash }
      end

      context 'when hash: :sha1' do
        let(:hash) { :sha1 }

        it { expect(subject).to eql('f2960ac838b31a4dcb1b4ddf5bf6af4ecec4eb38') }
      end

      context 'when hash: :sha256' do
        let(:hash) { :sha256 }

        it { expect(subject).to eql('9e4cae19d40bc58571ae7237cb13563f5598da5d596389cb55e8311be2d90cbe') }
      end

      context 'when hash: :sha384' do
        let(:hash) { :sha384 }

        it { expect(subject).to eql('6f4618cc20ea1c25aa5e475099c609d4b5955fe859bc0198fa333cddf096108d50cf8361f374f20ac0362a16026f51a0') }
      end

      context 'when hash: :sha512' do
        let(:hash) { :sha512 }

        it { expect(subject).to eql('868b4c9f961fdb2ee4d066d74de2c0432eafa01b714c2f749c4b13d1e370e04bb57eaecdb1f36fa15646439710f886a0fe974b59228178e1a61bbbd3aaae135b') }
      end
    end

    context 'when kdf: :legacy' do
      let(:options) do
        { kdf: :legacy, hash: hash }
      end

      context 'when hash: :sha1' do
        let(:hash) { :sha1 }

        it { expect(subject).to eql('4fb8f49a9526730f9b49ae5915011fd43c0dd598') }
      end

      context 'when hash: :sha256' do
        let(:hash) { :sha256 }

        it { expect(subject).to eql('ee36a8a3b95a6d3e02680b603f71f71e911a6f69c384aa0d18bd03f18c810d1f') }
      end

      context 'when hash: :sha384' do
        let(:hash) { :sha384 }

        it { expect(subject).to eql('3b9b35652dd6c98a73b31cf9e020482a4d2400632601cc7e9cc095952b7434c7214a4b6657fe7ba4c1d6bca8e1cb6c9a') }
      end

      context 'when hash: :sha512' do
        let(:hash) { :sha512 }

        it { expect(subject).to eql('d17cf68960f86086ca789d7e56e3fd050a8848ccbf5d7034ce449c8a897c6b6932c76e20a48e4cc4898e7fd436b93c6dcc8f852cb498f156e4aed9c096bfd279') }
      end
    end
  end

  describe '#keyed_hash' do
    subject { instance.keyed_hash(key, msg).hex }

    let(:key) { ESRP::Value.new('abcd') }
    let(:msg) { ESRP::Value.new('07c0') }

    context 'when mac: :hmac' do
      let(:options) do
        { mac: :hmac, hash: hash }
      end

      context 'when hash: :sha1' do
        let(:hash) { :sha1 }

        it { expect(subject).to eql('66b94122dc788495c7a962d8b98b59ce6af9be8b') }
      end

      context 'when hash: :sha256' do
        let(:hash) { :sha256 }

        it { expect(subject).to eql('2975112b38aaaa32e06799b25fba6dbe03a9420aea1184173736c59f9345dcae') }
      end

      context 'when hash: :sha384' do
        let(:hash) { :sha384 }

        it { expect(subject).to eql('c8bfc04a07bd0d6f0046331c370c0e9cb6151338694776fdadb672e86f9bb700346da475f330ddc62c739c3517abe2a8') }
      end

      context 'when hash: :sha512' do
        let(:hash) { :sha512 }

        it { expect(subject).to eql('5dab373651dbca7a5f637ffc1c0c4a64b3aba8b0821ce048590063c2aea3340e999e077483ec98771eda325ec9d0cafc2a4160d188262f52b876bc0c07877c3d') }
      end
    end

    context 'when mac: :legacy' do
      let(:options) do
        { mac: :legacy, hash: hash }
      end

      context 'when hash: :sha1' do
        let(:hash) { :sha1 }

        it { expect(subject).to eql('a19b96e98cae5ba7b41a8a389bdb61cebe2d0a17') }
      end

      context 'when hash: :sha256' do
        let(:hash) { :sha256 }

        it { expect(subject).to eql('c9acde151ea824509dbf03801b1823776037b9bc1596930359657966159b29b0') }
      end

      context 'when hash: :sha384' do
        let(:hash) { :sha384 }

        it { expect(subject).to eql('673380f8736d89cce61c211b813d9098c226bac4c707755e029a9567b0ba07e4fe05513b413b16c93d8173d7e7656d3a') }
      end

      context 'when hash: :sha512' do
        let(:hash) { :sha512 }

        it { expect(subject).to eql('e1d9ff539354a19735591e2aadf544200219d45986e9c99ba3b477e5eb65eaacad32988a11ec95d5752294e6279661875ce558f663d9d006bc3914b28453c52d') }
      end
    end
  end

  describe '#random' do
    subject { instance.random(length).bin }

    let(:length) { rand(1..64) }
    let(:options) { Hash.new }

    it { expect(subject.length).to eql(length) }
  end

  describe '#secure_compare' do
    subject { instance.secure_compare(a, b) }

    let(:options) { Hash.new }

    context 'when equal' do
      let(:a) { ESRP::Value.new('00ff3b16b0f555d3feb62f988fb3aab81c1c50ea') }
      let(:b) { ESRP::Value.new('00ff3b16b0f555d3feb62f988fb3aab81c1c50ea') }

      it { expect(subject).to be(true) }
    end

    context 'when not equal' do
      let(:a) { ESRP::Value.new('00ff3b16b0f555d3feb62f988fb3aab81c1c50ea') }
      let(:b) { ESRP::Value.new('00ff3b16b0f555d3feb62f988fb3aab81c1c50eb') }

      it { expect(subject).to be(false) }
    end
  end

end
