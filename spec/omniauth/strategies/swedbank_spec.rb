require 'spec_helper'

describe OmniAuth::Strategies::Swedbank do

  PRIVATE_KEY_FILE = File.join RSpec.configuration.cert_folder, 'request.private.pem'
  PUBLIC_KEY_FILE = File.join RSpec.configuration.cert_folder, 'response.public.pem'

  let(:app){ Rack::Builder.new do |b|
    b.use Rack::Session::Cookie, {secret: 'abc123'}
    b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, 'MY_SND_ID', 'MY_REC_ID')
    b.run lambda{|env| [404, {}, ['Not Found']]}
  end.to_app }

  let(:private_key) { OpenSSL::PKey::RSA.new(File.read(PRIVATE_KEY_FILE)) }
  let(:public_key) { OpenSSL::PKey::RSA.new(File.read(PUBLIC_KEY_FILE)) }
  let(:last_response_nonce) { last_response.body.match(/name="VK_NONCE" value="([^"]*)"/)[1] }
  let(:last_response_mac) { last_response.body.match(/name="VK_MAC" value="([^"]*)"/)[1] }

  context 'request phase' do
    EXPECTED_VALUES = {
      'VK_SERVICE' => '4002',
      'VK_VERSION' => '008',
      'VK_SND_ID' =>  'MY_SND_ID',
      'VK_REC_ID' =>  'MY_REC_ID',
      'VK_RETURN' =>  'http://example.org/auth/swedbank/callback'
    }

    before(:each){ get '/auth/swedbank' }

    it 'displays a single form' do
      expect(last_response.status).to eq(200)
      expect(last_response.body.scan('<form').size).to eq(1)
    end

    it 'has JavaScript code to submit the form after it is created' do
      expect(last_response.body).to be_include('</form><script type="text/javascript">document.forms[0].submit();</script>')
    end

    EXPECTED_VALUES.each_pair do |k,v|
      it "has hidden input field #{k} => #{v}" do
        expect(last_response.body.scan(
          "<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
      end
    end

    it 'has a 50 byte long nonce field value' do
      expect(last_response_nonce.bytesize).to eq(20)
    end

    it 'has a correct VK_MAC signature' do
      sig_str =
        '0044002' + # VK_SERVICE
        '003008' +  # VK_VERSION
        '009MY_SND_ID' +  # VK_SND_ID
        '009MY_REC_ID' +  # VK_REC_ID
        "020#{last_response_nonce}" +  # VK_NONCE
        "041#{EXPECTED_VALUES['VK_RETURN']}"  # V_RETURN

      expected_mac = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, sig_str))
      expect(last_response_mac).to eq(expected_mac)
    end

    context 'with default options' do
      it 'has the default action tag value' do
        expect(last_response.body).to be_include("action='https://ib.swedbank.lv/banklink'")
      end

      it 'has the default VK_LANG value' do
        expect(last_response.body).to be_include("action='https://ib.swedbank.lv/banklink'")
      end
    end

    context 'with custom options' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE, 'MY_SND_ID', 'MY_REC_ID',
          site: 'https://test.lv/banklink')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'has the custom action tag value' do
        expect(last_response.body).to be_include("action='https://test.lv/banklink'")
      end
    end

    context 'with non-existant private key files' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Swedbank, 'missing-private-key-file.pem', PUBLIC_KEY_FILE, 'MY_SND_ID', 'MY_REC_ID')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=private_key_load_err&strategy=swedbank')
      end
    end
  end

  context 'callback phase' do
    let(:auth_hash){ last_request.env['omniauth.auth'] }

    context 'with valid response' do
      before do
        post '/auth/swedbank/callback',
          'VK_SERVICE' =>   '3003',
          'VK_VERSION' =>   '008',
          'VK_SND_ID' =>    'HP',
          'VK_REC_ID' =>    'MY_REC_ID',
          'VK_NONCE' =>     'pXXXlocalhostX3000b41292810c0345a7b3770b1c807bed7a',
          'VK_INFO' =>      'ISIK:123456-12345;NIMI:Example User',
          'VK_MAC' =>       'cmXyp2My7P9pTgrzqJeg7qH+NPCuyaiGNpQIrcCr6S44w0bH+Ao4WDViqytaPH2vENooVPXDSgOcBqHTg44gJ9FlrhI5StiouHVhjpCcWg+h/ERcyc8w58PjsEmdsd4BIpaGXNyhvcIKdWfNwYA1UCIrmFsPAPWfVeorNxp81E7pvY4p4zsqMF80YZ7/RdOpjrtuXJ4nYJ7d+2fXJKKmUlqArCc786DJdb/z8wVDSNA9BZxnf8EE6s//p9gzqLPAg/T9Xp/2024n2JtC6kwsWF614bn64LEZz5c8owZth6FV+2fjnzHxOiifOe+jc9SRstCLITK6Y0j+6n8auiEZ5g==',
          'VK_LANG' =>      'LAT',
          'VK_ENCODING' =>  'UTF-8'
      end

      it 'sets the correct uid value in the auth hash' do
        expect(auth_hash.uid).to eq('123456-12345')
      end

      it 'sets the correct info.full_name value in the auth hash' do
        expect(auth_hash.info.full_name).to eq('Example User')
      end
    end

    context 'with non-existant public key file' do
      let(:app){ Rack::Builder.new do |b|
        b.use Rack::Session::Cookie, {secret: 'abc123'}
        b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY_FILE, 'missing-public-key-file.pem', 'MY_SND_ID', 'MY_REC_ID')
        b.run lambda{|env| [404, {}, ['Not Found']]}
      end.to_app }

      it 'redirects to /auth/failure with appropriate query params' do
        post '/auth/swedbank/callback' # Params are not important, because we're testing public key loading
        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=public_key_load_err&strategy=swedbank')
      end
    end

    context 'with invalid response' do
      it 'detects invalid signature' do
        post '/auth/swedbank/callback',
          'VK_SERVICE' =>   '3003',
          'VK_VERSION' =>   '008',
          'VK_SND_ID' =>    'HP',
          'VK_REC_ID' =>    'MY_REC_ID',
          'VK_NONCE' =>     'pXXXlocalhostX3000b41292810c0345a7b3770b1c807bed7a',
          'VK_INFO' =>      'ISIK:123456-12345;NIMI:Example User',
          'VK_MAC' =>       'invalid signature',
          'VK_LANG' =>      'LAT',
          'VK_ENCODING' =>  'UTF-8'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=invalid_response_signature_err&strategy=swedbank')
      end

      it 'detects unsupported VK_SERVICE values' do
        post '/auth/swedbank/callback',
          'VK_SERVICE' =>   '3004',
          'VK_VERSION' =>   '008',
          'VK_SND_ID' =>    'HP',
          'VK_REC_ID' =>    'MY_REC_ID',
          'VK_NONCE' =>     'pXXXlocalhostX3000b41292810c0345a7b3770b1c807bed7a',
          'VK_INFO' =>      'ISIK:123456-12345;NIMI:Example User',
          'VK_MAC' =>       'cmXyp2My7P9pTgrzqJeg7qH+NPCuyaiGNpQIrcCr6S44w0bH+Ao4WDViqytaPH2vENooVPXDSgOcBqHTg44gJ9FlrhI5StiouHVhjpCcWg+h/ERcyc8w58PjsEmdsd4BIpaGXNyhvcIKdWfNwYA1UCIrmFsPAPWfVeorNxp81E7pvY4p4zsqMF80YZ7/RdOpjrtuXJ4nYJ7d+2fXJKKmUlqArCc786DJdb/z8wVDSNA9BZxnf8EE6s//p9gzqLPAg/T9Xp/2024n2JtC6kwsWF614bn64LEZz5c8owZth6FV+2fjnzHxOiifOe+jc9SRstCLITK6Y0j+6n8auiEZ5g==',
          'VK_LANG' =>      'LAT',
          'VK_ENCODING' =>  'UTF-8'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_service_err&strategy=swedbank')
      end

      it 'detects unsupported VK_VERSION values' do
        post '/auth/swedbank/callback',
          'VK_SERVICE' =>   '3003',
          'VK_VERSION' =>   '009',
          'VK_SND_ID' =>    'HP',
          'VK_REC_ID' =>    'MY_REC_ID',
          'VK_NONCE' =>     'pXXXlocalhostX3000b41292810c0345a7b3770b1c807bed7a',
          'VK_INFO' =>      'ISIK:123456-12345;NIMI:Example User',
          'VK_MAC' =>       'cmXyp2My7P9pTgrzqJeg7qH+NPCuyaiGNpQIrcCr6S44w0bH+Ao4WDViqytaPH2vENooVPXDSgOcBqHTg44gJ9FlrhI5StiouHVhjpCcWg+h/ERcyc8w58PjsEmdsd4BIpaGXNyhvcIKdWfNwYA1UCIrmFsPAPWfVeorNxp81E7pvY4p4zsqMF80YZ7/RdOpjrtuXJ4nYJ7d+2fXJKKmUlqArCc786DJdb/z8wVDSNA9BZxnf8EE6s//p9gzqLPAg/T9Xp/2024n2JtC6kwsWF614bn64LEZz5c8owZth6FV+2fjnzHxOiifOe+jc9SRstCLITK6Y0j+6n8auiEZ5g==',
          'VK_LANG' =>      'LAT',
          'VK_ENCODING' =>  'UTF-8'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_version_err&strategy=swedbank')
      end

      it 'detects unsupported VK_ENCODING values' do
        post '/auth/swedbank/callback',
          'VK_SERVICE' =>   '3003',
          'VK_VERSION' =>   '008',
          'VK_SND_ID' =>    'HP',
          'VK_REC_ID' =>    'MY_REC_ID',
          'VK_NONCE' =>     'pXXXlocalhostX3000b41292810c0345a7b3770b1c807bed7a',
          'VK_INFO' =>      'ISIK:123456-12345;NIMI:Example User',
          'VK_MAC' =>       'cmXyp2My7P9pTgrzqJeg7qH+NPCuyaiGNpQIrcCr6S44w0bH+Ao4WDViqytaPH2vENooVPXDSgOcBqHTg44gJ9FlrhI5StiouHVhjpCcWg+h/ERcyc8w58PjsEmdsd4BIpaGXNyhvcIKdWfNwYA1UCIrmFsPAPWfVeorNxp81E7pvY4p4zsqMF80YZ7/RdOpjrtuXJ4nYJ7d+2fXJKKmUlqArCc786DJdb/z8wVDSNA9BZxnf8EE6s//p9gzqLPAg/T9Xp/2024n2JtC6kwsWF614bn64LEZz5c8owZth6FV+2fjnzHxOiifOe+jc9SRstCLITK6Y0j+6n8auiEZ5g==',
          'VK_LANG' =>      'LAT',
          'VK_ENCODING' =>  'ASCII'

        expect(last_response.status).to eq(302)
        expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_encoding_err&strategy=swedbank')
      end
    end
  end
end
