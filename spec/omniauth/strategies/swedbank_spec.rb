require 'spec_helper'

describe OmniAuth::Strategies::Swedbank do
  private_key_file = File.join RSpec.configuration.cert_folder, "request.private.pem"
  public_key_file = File.join RSpec.configuration.cert_folder, "response.public.pem"

  let(:app){ Rack::Builder.new do |b|

    b.use Rack::Session::Cookie, {:secret => "abc123"}
    b.use(OmniAuth::Strategies::Swedbank, private_key_file, public_key_file, "MY_SND_ID", "MY_REC_ID")
    b.run lambda{|env| [404, {}, ['Not Found']]}
  end.to_app }

  #before { OmniAuth.config.test_mode = true }
  #after { OmniAuth.config.test_mode = false }

  before :each do

  end

  context "request phase" do
    before(:each){ get '/auth/swedbank' }

    it "displays a single form" do
      expect(last_response.status).to eq(200)
      expect(last_response.body.scan('<form').size).to eq(1)
    end

    it "has JavaScript code to submit the form after it's created" do
      expect(last_response.body).to be_include("</form><script type=\"text/javascript\">document.forms[0].submit();</script>")
    end

    { :VK_SERVICE => :"4002", :VK_VERSION => :"008", :VK_SND_ID => :MY_SND_ID, :VK_REC_ID => :MY_REC_ID }.each_pair do |k,v|
      it "has a hidden input field for the #{k} parameter with value #{v}" do
        expect(last_response.body.scan(
          "<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
      end
    end

    context "with default options" do

      it "has the default action tag value" do
        expect(last_response.body).to be_include("action='https://ib.swedbank.lv/banklink'")
      end

    end

    context "with custom options" do

      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {:secret => "abc123"}
        b.use(OmniAuth::Strategies::Swedbank, private_key_file, public_key_file, "MY_SND_ID", "MY_REC_ID",
          :site => "https://test.lv/banklink")
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it "has the custom action tag value" do
        expect(last_response.body).to be_include("action='https://test.lv/banklink'")
      end

    end

  end

end