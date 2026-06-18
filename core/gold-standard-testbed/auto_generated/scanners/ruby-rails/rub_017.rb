# Vulnerable: RUB-017
Rails.application.config.action_dispatch.cookies_serializer = :marshal
end
class Cookie_serialization
