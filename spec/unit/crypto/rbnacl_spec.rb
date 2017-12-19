RSpec.describe ESRP::Crypto::RbNaCl do
  let(:instance) { described_class.new(options) }

  describe '.new' do
    subject { instance }

    context 'when hash name is not applicable' do
      let(:options) do
        { hash: hash }
      end
      let(:hash) { :sha1 }

      it do
        expect { subject }.to raise_error(
          ESRP::Crypto::NotApplicableError,
          "hash: '#{hash}' is not a valid option, available options: sha256, sha512, blake2b"
        )
      end
    end

    context 'when kdf name is not applicable' do
      let(:options) do
        { kdf: kdf }
      end
      let(:kdf) { :pbkdf2 }

      it do
        expect { subject }.to raise_error(
          ESRP::Crypto::NotApplicableError,
          "kdf: '#{kdf}' is not a valid option, available options: scrypt, argon2"
        )
      end
    end
  end

  describe '#H' do
    subject { instance.H(message).hex }

    let(:message) { ESRP::Value.new('07c0') }

    context 'when hash: :sha256' do
      let(:options) do
        { hash: :sha256 }
      end

      it { expect(subject).to eql('34b902c818ebdb547c4aa8d161dd701bd5f78ac3df6b5ab7fac3c35dae795e56') }
    end

    context 'when hash: :sha512' do
      let(:options) do
        { hash: :sha512 }
      end

      it { expect(subject).to eql('ff860fd40517a0de51b3747587177f02aeffc629dd37934035ec79113733041a42c23ba503cf9294284bb5fc77d4242e17664fb4d1c69ee4e27e96d4c17a3fcd') }
    end

    context 'when hash: :blake2b' do
      let(:options) do
        { hash: :blake2b }
      end

      it { expect(subject).to eql('db37202f77f5c6c7c6dd07f893547753d7f07dc649e97477eaca178366cc0125') }
    end

    context 'when hash: :blake2b and blake_digest_size: 64' do
      let(:options) do
        { hash: :blake2b, blake_digest_size: 64 }
      end

      it { expect(subject).to eql('924bb7d1885981f00d721ace8e92406ff2d411d66f366c2273141f78fb4fca7a1f44ed8fa53e7433d4ea0b4d61cc24a2c8c388e5010a38dec869015c392d71bd') }
    end
  end

  describe '#password_hash' do
    subject { instance.password_hash(salt, password).hex }

    let(:password) { 'verysecure' }

    context 'when kdf: :scrypt' do
      let(:salt) { ESRP::Value.new('dbcd6d34e827bcbdfcc06f0d7c6b54880d8f892701f81880ad319883ec6d6510') }
      let(:options) do
        { kdf: 'SCrypt' }
      end

      it { expect(subject).to eql('1bc06a2b66fd4ddc348885c62d22b388d68115cab7649a321845e5dc6db4ab75ffeb44951ec84a6a18745117c48012ea0125d785cb87b6cdf53212e7a06b9309') }
    end

    context 'when kdf: :argon2' do
      let(:salt) { ESRP::Value.new('93ba4abc16637fa77fe2aca725d91f28') }
      let(:options) do
        { kdf: 'argon2' }
      end

      it { expect(subject).to eql('abdcdf66dd9dfe74eb4fd657e701c644f9572a58c8f1ceedb69fdda8176718630b7ad8f6faf95835ed8de1d9c54b5b66cd878d260c1fdf3b9494b8a6501d8f7f') }
    end
  end

  describe '#keyed_hash' do
    subject { instance.keyed_hash(key, msg).hex }

    let(:key) { ESRP::Value.new('f4ffd830b255f778b9d88966e87ae1d72702227cfcbeae4bd1e4b39fff136060') }
    let(:msg) { ESRP::Value.new('07c0') }

    context 'when mac: :hmac' do
      let(:options) do
        { mac: :hmac, hash: hash }
      end

      context 'when hash: :sha256' do
        let(:hash) { :sha256 }

        it { expect(subject).to eql('ecfa17f317164259824287aa9feabeda9c784e7d672b118965ebff33f5373abe') }
      end

      context 'when hash: :sha512' do
        let(:hash) { :sha512 }

        it { expect(subject).to eql('8a93a38e2f274f99cdd25be0620bcee180e1cec062b22b09c314b051edf51ab3fb221b191e569d500bce1708f0e6ed7b745a1df6575c05c7ed5742a78ca7ad71') }
      end

      context 'when hash: :blake2b' do
        let(:hash) { :blake2b }

        it { expect(subject).to eql('ecfa17f317164259824287aa9feabeda9c784e7d672b118965ebff33f5373abe') }
      end
    end
  end
end
