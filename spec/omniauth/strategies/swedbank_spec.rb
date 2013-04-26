require 'spec_helper'

describe OmniAuth::Strategies::Swedbank do
  EXPECTED_VALUES = {
    :VK_SERVICE => :"4002",
    :VK_VERSION => :"008",
    :VK_SND_ID => :MY_SND_ID,
    :VK_REC_ID => :MY_REC_ID,
    :VK_RETURN => :"http://example.org/auth/swedbank/callback"
  }

  PRIVATE_KEY_FILE = File.join RSpec.configuration.cert_folder, "request.private.pem"
  PUBLIC_KEY_FILE = File.join RSpec.configuration.cert_folder, "response.public.pem"

  let(:app){ Rack::Builder.new do |b|

    b.use Rack::Session::Cookie, {:secret => "abc123"}
    b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, "MY_SND_ID", "MY_REC_ID")
    b.run lambda{|env| [404, {}, ['Not Found']]}
  end.to_app }

  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(PRIVATE_KEY_FILE)) }
  let(:last_response_nonce) { last_response.body.match(/name="VK_NONCE" value="([^"]*)"/)[1] }
  let(:last_response_mac) { last_response.body.match(/name="VK_MAC" value="([^"]*)"/)[1] }

  context "request phase" do
    before(:each){ get '/auth/swedbank' }

    it "displays a single form" do
      expect(last_response.status).to eq(200)
      expect(last_response.body.scan('<form').size).to eq(1)
    end

    it "has JavaScript code to submit the form after it's created" do
      expect(last_response.body).to be_include("</form><script type=\"text/javascript\">document.forms[0].submit();</script>")
    end

    EXPECTED_VALUES.each_pair do |k,v|
      it "has hidden input field #{k} => #{v}" do
        expect(last_response.body.scan(
          "<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
      end
    end

    it "has a 50 byte long nonce field value" do
      expect(last_response_nonce.bytesize).to eq(50)
    end

    it "has a correct VK_MAC signature" do
      sig_str =
        "0044002" + # VK_SERVICE
        "003008" +  # VK_VERSION
        "009MY_SND_ID" +  # VK_SND_ID
        "009MY_REC_ID" +  # VK_REC_ID
        "050" + last_response_nonce +  # VK_NONCE
        "041#{EXPECTED_VALUES[:VK_RETURN]}"  # V_RETURN

      expected_mac = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, sig_str))
      expect(last_response_mac).to eq(expected_mac)
    end

    context "with default options" do

      it "has the default action tag value" do
        expect(last_response.body).to be_include("action='https://ib.swedbank.lv/banklink'")
      end

    end

    context "with custom options" do

      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {:secret => "abc123"}
        b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, "MY_SND_ID", "MY_REC_ID",
          :site => "https://test.lv/banklink")
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it "has the custom action tag value" do
        expect(last_response.body).to be_include("action='https://test.lv/banklink'")
      end

    end

  end

end