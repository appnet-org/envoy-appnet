#include <string>

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "appnet_filter/appnet_filter.pb.h"
#include "appnet_filter/appnet_filter.pb.validate.h"
#include "appnet_filter.h"

namespace Envoy {
namespace Server {
namespace Configuration {

namespace AppNetSampleFilter {

using namespace Envoy::Http::AppNetSampleFilter;

class AppnetFilterConfigFactory : public NamedHttpFilterConfigFactory {
public:
  absl::StatusOr<Http::FilterFactoryCb> createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                     const std::string&,
                                                     FactoryContext& context) override {

    return createFilter(Envoy::MessageUtil::downcastAndValidate<const sample::FilterConfig&>(
                            proto_config, context.messageValidationVisitor()),
                        context);
  }

  /**
   *  Return the Protobuf Message that represents your config incase you have config proto
   */
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new sample::FilterConfig()};
  }

  std::string name() const override { return "AppNetSampleFilter"; }

private:
  Http::FilterFactoryCb createFilter(const sample::FilterConfig& proto_config, FactoryContext &factory_ctx) {
    AppnetFilterConfigSharedPtr config =
        std::make_shared<AppnetFilterConfig>(
            AppnetFilterConfig(proto_config, factory_ctx));

    // We leak it intentionally.
    auto _ = new AppNetWeakSyncTimer(
        config,
        factory_ctx.serverFactoryContext().mainThreadDispatcher(), 
        std::chrono::milliseconds(1000));

    return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      auto filter = new AppnetFilter(config);
      callbacks.addStreamFilter(Http::StreamFilterSharedPtr{filter});
    };
  }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<AppnetFilterConfigFactory, NamedHttpFilterConfigFactory>
    register_;

} // namespace AppNetSampleFilter
} // namespace Configuration
} // namespace Server
} // namespace Envoy
