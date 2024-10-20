#pragma once

#include "envoy/extensions/filters/http/api_key_auth/v3/api_key_auth.pb.h"
#include "envoy/extensions/filters/http/api_key_auth/v3/api_key_auth.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace APIKeyAuth {

class APIKeyAuthFilterFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::http::api_key_auth::v3::APIKeyAuth,
          envoy::extensions::filters::http::api_key_auth::v3::APIKeyAuthPerRoute> {
public:
  APIKeyAuthFilterFactory() : FactoryBase("envoy.filters.http.api_key_auth") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::api_key_auth::v3::APIKeyAuth& config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
  Router::RouteSpecificFilterConfigConstSharedPtr createRouteSpecificFilterConfigTyped(
      const envoy::extensions::filters::http::api_key_auth::v3::APIKeyAuthPerRoute& proto_config,
      Server::Configuration::ServerFactoryContext& context,
      ProtobufMessage::ValidationVisitor&) override;
};

} // namespace APIKeyAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
