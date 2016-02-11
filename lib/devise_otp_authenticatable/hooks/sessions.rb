
###
# back ported support Devise 3.2.4
# NOTE: The following was not available in 3.1.0 (The version specified in the original gemspec).
# Devise::Controllers::Helper#stored_location_for is defined but no #store_location_for.
# I think the original developer just was a little sloppy in the gem spec and the original impl really only supports devise 3.2 and later.
require "uri"

#module Devise
module DeviseOtpAuthenticatable # Adjust name spece to not conflict with existing devise gem
  module Controllers
    # Provide the ability to store a location.
    # Used to redirect back to a desired path after sign in.
    # Included by default in all controllers.
    module StoreLocation
      # Returns and delete (if it's navigational format) the url stored in the session for
      # the given scope. Useful for giving redirect backs after sign up:
      #
      # Example:
      #
      #   redirect_to stored_location_for(:user) || root_path
      #
      def stored_location_for(resource_or_scope)
        session_key = stored_location_key_for(resource_or_scope)

        if is_navigational_format?
          session.delete(session_key)
        else
          session[session_key]
        end
      end

      # Stores the provided location to redirect the user after signing in.
      # Useful in combination with the `stored_location_for` helper.
      #
      # Example:
      #
      #   store_location_for(:user, dashboard_path)
      #   redirect_to user_omniauth_authorize_path(:facebook)
      #
      def store_location_for(resource_or_scope, location)
        session_key = stored_location_key_for(resource_or_scope)
        if location
          uri = URI.parse(location)
          session[session_key] = [uri.path.sub(/\A\/+/, '/'), uri.query].compact.join('?')
        end
      end

      private

      def stored_location_key_for(resource_or_scope)
        scope = Devise::Mapping.find_scope!(resource_or_scope)
        "#{scope}_return_to"
      end
    end
  end
end
###

module DeviseOtpAuthenticatable::Hooks
  module Sessions
    extend ActiveSupport::Concern
    include DeviseOtpAuthenticatable::Controllers::UrlHelpers
    include DeviseOtpAuthenticatable::Controllers::StoreLocation

    included do
      alias_method_chain :create, :otp
    end

    #
    # replaces Devise::SessionsController#create
    #
    def create_with_otp

      resource = warden.authenticate!(auth_options)

      devise_stored_location = stored_location_for(resource) # Grab the current stored location before it gets lost by warden.logout

      otp_refresh_credentials_for(resource)

      if otp_challenge_required_on?(resource)
        challenge = resource.generate_otp_challenge!
        warden.logout
        store_location_for(resource, devise_stored_location) # restore the stored location
        respond_with resource, :location => otp_credential_path_for(resource, {:challenge => challenge})
      elsif otp_mandatory_on?(resource) # if mandatory, log in user but send him to the must activate otp
        set_flash_message(:notice, :signed_in_but_otp) if is_navigational_format?
        sign_in(resource_name, resource)
        respond_with resource, :location => otp_token_path_for(resource)
      else

        set_flash_message(:notice, :signed_in) if is_navigational_format?
        sign_in(resource_name, resource)
        respond_with resource, :location => after_sign_in_path_for(resource)
      end
    end


    private

    #
    # resource should be challenged for otp
    #
    def otp_challenge_required_on?(resource)
      return false unless resource.respond_to?(:otp_enabled) && resource.respond_to?(:otp_auth_secret)
      resource.otp_enabled && !is_otp_trusted_device_for?(resource)
    end

    #
    # the resource -should- have otp turned on, but it isn't
    #
    def otp_mandatory_on?(resource)
      return true if resource.class.otp_mandatory
      return false unless resource.respond_to?(:otp_mandatory)

      resource.otp_mandatory && !resource.otp_enabled
    end
  end
end