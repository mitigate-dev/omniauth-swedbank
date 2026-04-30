require 'spec_helper'
require 'rack-protection'
require 'rack/session'

describe OmniAuth::Strategies::Swedbank do

  PRIVATE_KEY = File.read(File.join(RSpec.configuration.cert_folder, 'request.private.pem'))
  PUBLIC_KEY = File.read(File.join(RSpec.configuration.cert_folder, 'response.public.pem'))
  PUBLIC_KEY_V009 = File.read(File.join(RSpec.configuration.cert_folder, 'response.v009.public.pem'))

  let(:token){ Rack::Protection::AuthenticityToken.random_token }

  let(:last_response_nonce) { last_response.body.match(/name="VK_NONCE" value="([^"]*)"/)[1] }
  let(:last_response_mac) { last_response.body.match(/name="VK_MAC" value="([^"]*)"/)[1] }

  context 'v008 (default)' do
    let(:app){ Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, {secret: '5242e6bd9daf0e9645c2d4e22b11ba8cee0bed44439906d5f1bd5dad409d8637'}
      b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY, PUBLIC_KEY, 'MY_SND_ID', 'MY_REC_ID')
      b.run lambda{|env| [404, {}, ['Not Found']]}
    end.to_app }

    context 'request phase' do
      EXPECTED_VALUES_V008 = {
        'VK_SERVICE' => '4002',
        'VK_VERSION' => '008',
        'VK_SND_ID' =>  'MY_SND_ID',
        'VK_REC_ID' =>  'MY_REC_ID',
        'VK_RETURN' =>  'http://example.org/auth/swedbank/callback'
      }

      before(:each) do
        post(
          '/auth/swedbank',
          {},
          'rack.session' => {csrf: token},
          'HTTP_X_CSRF_TOKEN' => token
        )
      end

      it 'displays a single form' do
        expect(last_response.status).to eq(200)
        expect(last_response.body.scan('<form').size).to eq(1)
      end

      it 'has JavaScript code to submit the form after it is created' do
        expect(last_response.body).to be_include('</form><script type="text/javascript">document.forms[0].submit();</script>')
      end

      EXPECTED_VALUES_V008.each_pair do |k,v|
        it "has hidden input field #{k} => #{v}" do
          expect(last_response.body.scan(
            "<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
        end
      end

      it 'has a 20 byte long nonce field value' do
        expect(last_response_nonce.bytesize).to eq(20)
      end

      it 'has a correct VK_MAC signature' do
        sig_str =
          '0044002' + # VK_SERVICE
          '003008' +  # VK_VERSION
          '009MY_SND_ID' +  # VK_SND_ID
          '009MY_REC_ID' +  # VK_REC_ID
          "020#{last_response_nonce}" +  # VK_NONCE
          "041#{EXPECTED_VALUES_V008['VK_RETURN']}"  # V_RETURN

        private_key = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
        expected_mac = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, sig_str))
        expect(last_response_mac).to eq(expected_mac)
      end

      it 'does not include VK_DATETIME field' do
        expect(last_response.body).not_to include('name="VK_DATETIME"')
      end

      it 'does not include VK_RID field' do
        expect(last_response.body).not_to include('name="VK_RID"')
      end

      it 'outputs a deprecation warning' do
        expect { post('/auth/swedbank', {}, 'rack.session' => {csrf: token}, 'HTTP_X_CSRF_TOKEN' => token) }
          .to output(/DEPRECATION.*v008.*2026-06-02/).to_stderr
      end

      context 'with default options' do
        it 'has the default action tag value' do
          expect(last_response.body).to be_include("action='https://www.swedbank.lv/banklink'")
        end

        it 'has the default VK_LANG value' do
          expect(last_response.body).to be_include("action='https://www.swedbank.lv/banklink'")
        end
      end

      context 'with custom options' do
        let(:app){ Rack::Builder.new do |b|
          b.use Rack::Session::Cookie, {secret: '5242e6bd9daf0e9645c2d4e22b11ba8cee0bed44439906d5f1bd5dad409d8637'}
          b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY, PUBLIC_KEY, 'MY_SND_ID', 'MY_REC_ID',
            site: 'https://test.lv/banklink')
          b.run lambda{|env| [404, {}, ['Not Found']]}
        end.to_app }

        it 'has the custom action tag value' do
          expect(last_response.body).to be_include("action='https://test.lv/banklink'")
        end
      end

      context 'with non-existant private key files' do
        let(:app){ Rack::Builder.new do |b|
          b.use Rack::Session::Cookie, {secret: '5242e6bd9daf0e9645c2d4e22b11ba8cee0bed44439906d5f1bd5dad409d8637'}
          b.use(OmniAuth::Strategies::Swedbank, 'missing-private-key-file.pem', PUBLIC_KEY, 'MY_SND_ID', 'MY_REC_ID')
          b.run lambda{|env| [404, {}, ['Not Found']]}
        end.to_app }

        it 'redirects to /auth/failure with appropriate query params' do
          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=private_key_load_err&strategy=swedbank')
        end
      end

      context 'with invalid version' do
        let(:app){ Rack::Builder.new do |b|
          b.use Rack::Session::Cookie, {secret: '5242e6bd9daf0e9645c2d4e22b11ba8cee0bed44439906d5f1bd5dad409d8637'}
          b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY, PUBLIC_KEY, 'MY_SND_ID', 'MY_REC_ID',
            version: '010')
          b.run lambda{|env| [404, {}, ['Not Found']]}
        end.to_app }

        it 'fails with unsupported_version_err on request phase' do
          post('/auth/swedbank', {}, 'rack.session' => {csrf: token}, 'HTTP_X_CSRF_TOKEN' => token)
          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_version_err&strategy=swedbank')
        end

        it 'fails with unsupported_version_err on callback phase' do
          post '/auth/swedbank/callback', 'VK_SERVICE' => '3003'
          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_version_err&strategy=swedbank')
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
          b.use Rack::Session::Cookie, {secret: '5242e6bd9daf0e9645c2d4e22b11ba8cee0bed44439906d5f1bd5dad409d8637'}
          b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY, 'missing-public-key-file.pem', 'MY_SND_ID', 'MY_REC_ID')
          b.run lambda{|env| [404, {}, ['Not Found']]}
        end.to_app }

        it 'redirects to /auth/failure with appropriate query params' do
          post '/auth/swedbank/callback'
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

  context 'v009' do
    let(:app){ Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, {secret: '5242e6bd9daf0e9645c2d4e22b11ba8cee0bed44439906d5f1bd5dad409d8637'}
      b.use(OmniAuth::Strategies::Swedbank, PRIVATE_KEY, PUBLIC_KEY_V009, 'MY_SND_ID', 'MY_REC_ID',
        version: '009')
      b.run lambda{|env| [404, {}, ['Not Found']]}
    end.to_app }

    context 'request phase' do
      EXPECTED_VALUES_V009 = {
        'VK_SERVICE' => '4012',
        'VK_VERSION' => '009',
        'VK_SND_ID' =>  'MY_SND_ID',
        'VK_REC_ID' =>  'MY_REC_ID',
        'VK_RETURN' =>  'http://example.org/auth/swedbank/callback'
      }

      let(:last_response_datetime) { last_response.body.match(/name="VK_DATETIME" value="([^"]*)"/)[1] }
      let(:last_response_rid) { last_response.body.match(/name="VK_RID" value="([^"]*)"/)[1] }

      before(:each) do
        post(
          '/auth/swedbank',
          {},
          'rack.session' => {csrf: token},
          'HTTP_X_CSRF_TOKEN' => token
        )
      end

      it 'displays a single form' do
        expect(last_response.status).to eq(200)
        expect(last_response.body.scan('<form').size).to eq(1)
      end

      EXPECTED_VALUES_V009.each_pair do |k,v|
        it "has hidden input field #{k} => #{v}" do
          expect(last_response.body.scan(
            "<input type=\"hidden\" name=\"#{k}\" value=\"#{v}\"").size).to eq(1)
        end
      end

      it 'has a VK_DATETIME field' do
        expect(last_response_datetime).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}/)
      end

      it 'has a VK_RID field' do
        expect(last_response.body).to include('name="VK_RID"')
      end

      it 'has a 20 byte long nonce field value' do
        expect(last_response_nonce.bytesize).to eq(20)
      end

      it 'has a correct VK_MAC signature using SHA-512' do
        sig_str =
          '0044012' + # VK_SERVICE
          '003009' +  # VK_VERSION
          '009MY_SND_ID' +  # VK_SND_ID
          '009MY_REC_ID' +  # VK_REC_ID
          "020#{last_response_nonce}" +  # VK_NONCE
          "041#{EXPECTED_VALUES_V009['VK_RETURN']}" +  # VK_RETURN
          "#{'%03d' % last_response_datetime.length}#{last_response_datetime}" +  # VK_DATETIME
          "000"  # VK_RID (empty)

        private_key = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
        expected_mac = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA512.new, sig_str))
        expect(last_response_mac).to eq(expected_mac)
      end

      it 'does not output a deprecation warning' do
        expect { post('/auth/swedbank', {}, 'rack.session' => {csrf: token}, 'HTTP_X_CSRF_TOKEN' => token) }
          .not_to output(/DEPRECATION/).to_stderr
      end
    end

    context 'callback phase' do
      let(:auth_hash){ last_request.env['omniauth.auth'] }

      # Generate a valid v009 MAC for test data
      let(:v009_response_params) do
        nonce = 'pXXXlocalhostX3000b41292810c0345a7b3770b1c807bed7a'
        datetime = '2026-04-29T12:00:00+0300'
        user_name = 'Example User'
        user_id = '123456-12345'
        country = 'LV'
        other = ''
        token_val = '7'
        rid = ''

        sig_str = [
          '3013', '009', datetime, 'SWEDBANK_LV', 'MY_REC_ID',
          nonce, user_name, user_id, country, other, token_val, rid
        ].map{|v| '%03d' % v.to_s.length + v.to_s.dup.force_encoding('ascii')}.join

        private_key = OpenSSL::PKey::RSA.new(PRIVATE_KEY)
        mac = Base64.encode64(private_key.sign(OpenSSL::Digest::SHA512.new, sig_str))

        {
          'VK_SERVICE' =>    '3013',
          'VK_VERSION' =>    '009',
          'VK_DATETIME' =>   datetime,
          'VK_SND_ID' =>     'SWEDBANK_LV',
          'VK_REC_ID' =>     'MY_REC_ID',
          'VK_NONCE' =>      nonce,
          'VK_USER_NAME' =>  user_name,
          'VK_USER_ID' =>    user_id,
          'VK_COUNTRY' =>    country,
          'VK_OTHER' =>      other,
          'VK_TOKEN' =>      token_val,
          'VK_RID' =>        rid,
          'VK_MAC' =>        mac,
          'VK_LANG' =>       'LAT',
          'VK_ENCODING' =>   'UTF-8'
        }
      end

      context 'with valid response' do
        before do
          post '/auth/swedbank/callback', v009_response_params
        end

        it 'sets the correct uid value in the auth hash' do
          expect(auth_hash.uid).to eq('123456-12345')
        end

        it 'sets the correct info.full_name value in the auth hash' do
          expect(auth_hash.info.full_name).to eq('Example User')
        end

        it 'sets the correct info.country value in the auth hash' do
          expect(auth_hash.info.country).to eq('LV')
        end

        it 'includes all v009 params in extra.raw_info' do
          expect(auth_hash.extra.raw_info).to include(
            'VK_SERVICE' => '3013',
            'VK_VERSION' => '009',
            'VK_SND_ID' => 'SWEDBANK_LV',
            'VK_USER_NAME' => 'Example User',
            'VK_USER_ID' => '123456-12345',
            'VK_COUNTRY' => 'LV',
            'VK_TOKEN' => '7',
            'VK_RID' => ''
          )
        end

        it 'does not include VK_INFO in extra.raw_info' do
          expect(auth_hash.extra.raw_info).not_to have_key('VK_INFO')
        end
      end

      context 'with invalid response' do
        it 'detects invalid signature' do
          params = v009_response_params.merge('VK_MAC' => 'invalid signature')
          post '/auth/swedbank/callback', params

          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=invalid_response_signature_err&strategy=swedbank')
        end

        it 'detects unsupported VK_SERVICE values' do
          params = v009_response_params.merge('VK_SERVICE' => '3003')
          post '/auth/swedbank/callback', params

          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_service_err&strategy=swedbank')
        end

        it 'detects unsupported VK_VERSION values' do
          params = v009_response_params.merge('VK_VERSION' => '008')
          post '/auth/swedbank/callback', params

          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_version_err&strategy=swedbank')
        end

        it 'detects unsupported VK_ENCODING values' do
          params = v009_response_params.merge('VK_ENCODING' => 'ASCII')
          post '/auth/swedbank/callback', params

          expect(last_response.status).to eq(302)
          expect(last_response.headers['Location']).to eq('/auth/failure?message=unsupported_response_encoding_err&strategy=swedbank')
        end
      end
    end
  end
end
