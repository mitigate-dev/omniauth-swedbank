require 'omniauth'

module OmniAuth
  module Strategies
    class Swedbank
      # TODO add support for overriding the VK_LANG parameter
      # TODO i18n for all texts

      include OmniAuth::Strategy

      AUTH_SERVICE_ID = :"4002"
      AUTH_SERVICE_VERSION = :"008" # This value must not be used as a number, so as to not lose the padding
                                    # Padding is important when generating the VK_MAC value

      args [:private_key_file, :public_key_file, :snd_id, :rec_id]

      option :private_key_file, nil
      option :public_key_file, nil
      option :snd_id, nil
      option :rec_id, nil

      option :name, "swedbank"
      option :site, "https://ib.swedbank.lv/banklink"

      def callback_url
        full_host + script_name + callback_path
      end

      def nonce
        ((full_host.gsub(/[\:\/]/, "X") + SecureRandom.uuid.gsub("-", "")).rjust 50, " ")[-50, 50]
      end

      def request_phase
        #return redirect_to_failure
        begin
          #puts options.public_key_file
          #puts options.private_key_file
          pub_cert = OpenSSL::X509::Certificate.new(File.read(options.public_key_file || ""))
          #puts "Certificate from file (#{options.public_key_file}): #{pub_cert}"
          priv_key = OpenSSL::PKey::RSA.new(File.read(options.private_key_file))
          #puts "Private key from file (#{options.private_key_file}): #{priv_key}"
        rescue Errno::ENOENT
          request.env['omniauth.error.type'] = "failedToLoadCerts"
          return FailureEndpoint.new(request.env).redirect_to_failure
        end

        puts options.site
        OmniAuth.config.form_css = nil
        form = OmniAuth::Form.new(:title => "Please wait ...", :url => options.site)

        form.html "<input type=\"hidden\" name=\"VK_SERVICE\" value=\"#{AUTH_SERVICE_ID}\" />"
        form.html "<input type=\"hidden\" name=\"VK_VERSION\" value=\"#{AUTH_SERVICE_VERSION}\" />"
        form.html "<input type=\"hidden\" name=\"VK_SND_ID\" value=\"#{options.snd_id}\" />"
        form.html "<input type=\"hidden\" name=\"VK_REC_ID\" value=\"#{options.rec_id}\" />"
        form.html "<input type=\"hidden\" name=\"VK_NONCE\" value=\"#{nonce}\" />"
        form.html "<input type=\"hidden\" name=\"VK_RETURN\" value=\"#{callback_url}\" />"
        form.html "<input type=\"hidden\" name=\"VK_LANG\" value=\"LAT\" />"
        form.html "<input type=\"hidden\" name=\"VK_MAC\" value=\"test mac\" />"

        form.button "Click here if not redirected automatically ..."

        form.instance_variable_set("@html",
          form.to_html.gsub("</form>", "</form><script type=\"text/javascript\">document.forms[0].submit();</script>"))
        #puts form.to_html
        form.to_response
      end
    end
  end
end