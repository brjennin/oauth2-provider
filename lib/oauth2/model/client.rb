module OAuth2
  module Model

    class Client < ActiveRecord::Base
      self.table_name = "oauth2_clients"

      belongs_to :oauth2_client_owner, :polymorphic => true
      alias :owner  :oauth2_client_owner
      alias :owner= :oauth2_client_owner=

      has_many :authorizations, :class_name => 'OAuth2::Model::Authorization', :dependent => :destroy

      validates_uniqueness_of :client_id

      before_create :generate_credentials

      def self.create_client_id
        OAuth2.generate_id do |client_id|
          count(:conditions => {:client_id => client_id}).zero?
        end
      end

      def regenerate_secret
        self.set_client_secret(OAuth2.random_string)
        self.save!
      end
      # attr_reader :client_secret

      def set_client_secret(secret)
        @client_secret = secret
        self.client_secret = secret
        self.client_secret_hash = BCrypt::Password.create(secret)
      end

      def valid_client_secret?(secret)
        BCrypt::Password.new(client_secret_hash) == secret
      end

    private
      def generate_credentials
        self.client_id = self.class.create_client_id
        self.set_client_secret(OAuth2.random_string)
      end
    end

  end
end

