#include "source/extensions/filters/http/api_key_auth/config.h"

#include "source/common/config/datasource.h"
#include "source/extensions/filters/http/api_key_auth/api_key_auth_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace APIKeyAuth {

using envoy::extensions::filters::http::api_key_auth::v3::APIKeyAuth;
using envoy::extensions::filters::http::api_key_auth::v3::APIKeyAuthPerRoute;

namespace {

UserMap readKey(const std::string& keys) {
  UserMap users;

  std::istringstream keys_ss(keys);
  std::string line;

  while (std::getline(keys_ss, line)) {
    // Skip empty lines and comments.
    if (line.empty() || line[0] == '#') {
      continue;
    }

    const size_t colon_pos = line.find(':');
    if (colon_pos == std::string::npos) {
      throw EnvoyException("api_key auth: invalid keys format, apikey:username is expected");
    }

    std::string key = line.substr(0, colon_pos);
    std::string username = line.substr(colon_pos + 1);

    if (key.empty() || username.empty()) {
      throw EnvoyException("api_key auth: empty api key or user name");
    }

    if (users.contains(username)) {
      throw EnvoyException("api_key auth: duplicate users");
    }

    users.insert({username, {username, key}});
  }

  return users;
}

} // namespace

Http::FilterFactoryCb APIKeyAuthFilterFactory::createFilterFactoryFromProtoTyped(
    const APIKeyAuth& proto_config, const std::string& stats_prefix,
    Server::Configuration::FactoryContext& context) {
  UserMap users = readKey(THROW_OR_RETURN_VALUE(
      Config::DataSource::read(proto_config.keys(), false, context.serverFactoryContext().api()),
      std::string));
  FilterConfigConstSharedPtr config = std::make_unique<FilterConfig>(
      std::move(users), proto_config.forward_username_header(),
      proto_config.authentication_header(), stats_prefix, context.scope());
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<APIKeyAuthFilter>(config));
  };
}

Router::RouteSpecificFilterConfigConstSharedPtr
APIKeyAuthFilterFactory::createRouteSpecificFilterConfigTyped(
    const APIKeyAuthPerRoute& proto_config, Server::Configuration::ServerFactoryContext& context,
    ProtobufMessage::ValidationVisitor&) {
  UserMap users = readKey(THROW_OR_RETURN_VALUE(
      Config::DataSource::read(proto_config.keys(), true, context.api()), std::string));
  return std::make_unique<FilterConfigPerRoute>(std::move(users));
}

REGISTER_FACTORY(APIKeyAuthFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace APIKeyAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
