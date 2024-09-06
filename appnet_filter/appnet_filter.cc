#include <netinet/in.h>
#include <string>
#include <mutex>
#include <algorithm>

#include "appnet_filter.h"
#include "appnet_filter/echo.pb.h"

#include "envoy/server/filter_config.h"
#include "source/common/http/utility.h"
#include "source/common/http/message_impl.h" 
#include "envoy/upstream/resource_manager.h"

// Don't remove those headers. They are used in the generated code.
#include "thirdparty/json.hpp"
#include "google/protobuf/extension_set.h"
#include <random>
#include <chrono>

namespace Envoy {
namespace Http {

namespace AppNetSampleFilter {
  

template<typename A, typename B>
auto my_min(A a, B b) {
  return a < b ? a : b;
}

template<typename A, typename B>
auto my_max(A a, B b) {
  return a > b ? a : b;
}

template<typename K, typename V>
std::optional<V> map_get_opt(const std::map<K, V> &m, const K &key) {
  auto it = m.find(key);
  if (it == m.end()) {
    return std::nullopt;
  }
  return std::make_optional(it->second);
}


std::string get_rpc_field(const ::appnetsamplefilter::Msg& rpc, const std::string& field) {
  if (field == "body") {
    return rpc.body();
  } else {
    throw std::runtime_error("Unknown field: " + field);
  }
}

void set_rpc_field(::appnetsamplefilter::Msg& rpc, const std::string& field, const std::string& value) {
  if (field == "body") {
    rpc.set_body(value);
  } else {
    throw std::runtime_error("Unknown field: " + field);
  }
}

void replace_payload(Buffer::Instance *data, ::appnetsamplefilter::Msg& rpc) {
  std::string serialized;
  rpc.SerializeToString(&serialized);
  
  // drain the original data
  data->drain(data->length());
  // fill 0x00 and then the length of new message
  std::vector<uint8_t> new_data(5 + serialized.size());
  new_data[0] = 0x00;
  uint32_t len = serialized.size();
  *reinterpret_cast<uint32_t*>(&new_data[1]) = ntohl(len);
  std::copy(serialized.begin(), serialized.end(), new_data.begin() + 5);
  data->add(new_data.data(), new_data.size());
}

std::mutex global_state_lock;

bool init = false;
// !APPNET_STATE

AppnetFilterConfig::AppnetFilterConfig(
  const ::appnetsamplefilter::FilterConfig&, Envoy::Server::Configuration::FactoryContext &ctx)
  : ctx_(ctx) {
  
}

AppnetFilter::AppnetFilter(AppnetFilterConfigSharedPtr config)
  : config_(config), empty_callback_(new EmptyCallback{}) {

  std::unique_lock<std::mutex> guard(global_state_lock);
  if (!init) {
    init = true;

    // !APPNET_INIT
  }
}

AppnetFilter::~AppnetFilter() {
  ENVOY_LOG(info, "[Appnet Filter] ~AppnetFilter");
}

void AppnetFilter::onDestroy() {}

FilterHeadersStatus AppnetFilter::decodeHeaders(RequestHeaderMap & headers, bool) {
  ENVOY_LOG(warn, "[Native] Executing in decodeHeaders this={}, headers={}", static_cast<void*>(this), headers);
  this->request_headers_ = &headers;

  // If have no "appnet-rpc-id", just continue
  // We do this to skip TLS handshake stuff which only occurs in ambient waypoints.
  if (headers.get(LowerCaseString("appnet-rpc-id")).empty()) {
    ENVOY_LOG(info, "[Appnet Filter] decodeHeaders skip irrelevant request");
    return FilterHeadersStatus::Continue;
  }
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus AppnetFilter::decodeData(Buffer::Instance &data, bool end_of_stream) {
  ENVOY_LOG(warn, "[Native] Executing in decodeData this={}, end_of_stream={}", static_cast<void*>(this), end_of_stream);

  // If no "appnet-rpc-id", it means this is not a appnet rpc. 
  // We do this to skip TLS handshake stuff which only occurs in ambient waypoints.
  // Yongtong: sometimes request_headers_ is nullptr, I don't know why. Just skip it.
  if (request_headers_ == nullptr || this->request_headers_->get(LowerCaseString("appnet-rpc-id")).empty()) {
    ENVOY_LOG(info, "[Appnet Filter] decodeData skip irrelevant request");
    return FilterDataStatus::Continue;
  }
  
  if (!end_of_stream) {
    ENVOY_LOG(info, "[Appnet Filter] decodeData not end of stream, skip");
    return FilterDataStatus::Continue;
  }

  ENVOY_LOG(info, "[Appnet Filter] decodeData this={}, end_of_stream={}", static_cast<void*>(this), end_of_stream);
  this->request_buffer_ = &data;
  this->appnet_coroutine_.emplace(this->startRequestAppnet());
  this->in_decoding_or_encoding_ = true;
  this->appnet_coroutine_.value().handle_.value().resume(); // the coroutine will be started here.
  if (this->appnet_coroutine_.value().handle_.value().done()) {
    ENVOY_LOG(info, "[Appnet Filter] decodeData done in one time, req_appnet_blocked_={}", this->req_appnet_blocked_);
    // no more callback
    return this->req_appnet_blocked_ ? FilterDataStatus::StopIterationNoBuffer : FilterDataStatus::Continue;
  } else {
    ENVOY_LOG(info, "[Appnet Filter] decodeData not done in one time, req_appnet_blocked_={}", this->req_appnet_blocked_);
    return FilterDataStatus::StopIterationAndBuffer;
  }
}

void AppnetFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void AppnetFilter::setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) {
  encoder_callbacks_ = &callbacks;
}

FilterHeadersStatus AppnetFilter::encodeHeaders(ResponseHeaderMap& headers, bool) {
  ENVOY_LOG(warn, "[Native] Executing in encodeHeaders this={}, headers={}", static_cast<void*>(this), headers);
  this->response_headers_ = &headers;

  // Server response and element error response both have "grpc-status" header.
  // We do this to filter out irrelevant response such as TLS handshake stuff.
  if (headers.get(LowerCaseString("grpc-status")).empty()) {
    ENVOY_LOG(info, "[Appnet Filter] encodeHeaders skip irrelevant response");
    return FilterHeadersStatus::Continue;
  }

  // We cannot stop a header-only response.
  // For now, only error message is header-only, so we use this to detect it.
  const Envoy::Http::HeaderEntry *grpc_status = headers.get(LowerCaseString("grpc-status"))[0];
  if (grpc_status->value().getStringView() != "0") {
    // TODO: This still causes a chain bug that the expected response handling is not triggered.
    // See https://github.com/appnet-org/compiler/issues/37
    ENVOY_LOG(info, "[Appnet Filter] encodeHeaders skip error response");
    return FilterHeadersStatus::Continue;
  }

  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus AppnetFilter::encodeData(Buffer::Instance &data, bool end_of_stream) {
  ENVOY_LOG(warn, "[Native] Executing in encodeData");

  // Server response and element error response both have "grpc-status" header.
  // We do this to filter out irrelevant response such as TLS handshake stuff.
  // Yongtong: sometimes response_headers_ is nullptr, I don't know why. Just skip it.
  if (this->response_headers_ == nullptr ||  this->response_headers_->get(LowerCaseString("grpc-status")).empty()) {
    ENVOY_LOG(info, "[Appnet Filter] encodeData skip irrelevant response");
    return FilterDataStatus::Continue;
  }

  // We cannot stop a header-only response.
  // For now, only error message is header-only, so we use this to detect it.
  const Envoy::Http::HeaderEntry *grpc_status = this->response_headers_->get(LowerCaseString("grpc-status"))[0];
  if (grpc_status->value().getStringView() != "0") {
    // TODO: This still causes a chain bug that the expected response handling is not triggered.
    // See https://github.com/appnet-org/compiler/issues/37
    ENVOY_LOG(info, "[Appnet Filter] encodeData skip error response");
    return FilterDataStatus::Continue;
  }

  ENVOY_LOG(info, "[Appnet Filter] encodeData this={}, end_of_stream={}", static_cast<void*>(this), end_of_stream);
  this->response_buffer_ = &data;

  this->appnet_coroutine_.emplace(this->startResponseAppnet());
  this->in_decoding_or_encoding_ = true;
  this->appnet_coroutine_.value().handle_.value().resume(); // the coroutine will be started here.
  if (this->appnet_coroutine_.value().handle_.value().done()) {
    // no more callback
    ENVOY_LOG(info, "[Appnet Filter] encodeData done in one time, resp_appnet_blocked_={}", this->resp_appnet_blocked_);
    return this->resp_appnet_blocked_ ? FilterDataStatus::StopIterationNoBuffer : FilterDataStatus::Continue;
  } else {
    ENVOY_LOG(info, "[Appnet Filter] encodeData not done in one time, resp_appnet_blocked_={}", this->resp_appnet_blocked_);
    return FilterDataStatus::StopIterationAndBuffer;
  }
}

// Callback of async http response handling
void AppnetFilter::onSuccess(const Http::AsyncClient::Request&,
                 Http::ResponseMessagePtr&& message) {
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onSuccess");
  this->external_response_ = std::move(message);
  assert(message.get() == nullptr);
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onSuccess (second step)");
  assert(this->http_awaiter_.has_value());
  this->in_decoding_or_encoding_ = false;
  this->http_awaiter_.value()->i_am_ready();
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onSuccess (3rd step)");
}

void AppnetFilter::onFailure(const Http::AsyncClient::Request&,
                 Http::AsyncClient::FailureReason) {
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onFailure");
  assert(0);
}

void AppnetFilter::onBeforeFinalizeUpstreamSpan(Tracing::Span&,
                          const Http::ResponseHeaderMap*) {
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onBeforeFinalizeUpstreamSpan");
}

bool AppnetFilter::sendWebdisRequest(const std::string path, Callbacks &callback) {
  return this->sendHttpRequest("webdis_cluster", path, callback);
}

bool AppnetFilter::sendHttpRequest(const std::string cluster_name, const std::string path, Callbacks &callback) {
  auto cluster = this->config_->ctx_.serverFactoryContext().clusterManager().getThreadLocalCluster(cluster_name);
  if (!cluster) {
    ENVOY_LOG(info, "cluster {} not found", cluster_name);
    assert(0);
    return false;
  }
  Http::RequestMessagePtr request = std::make_unique<Http::RequestMessageImpl>();

  request->headers().setMethod(Http::Headers::get().MethodValues.Get);
  request->headers().setHost("localhost:7379");
  ENVOY_LOG(info, "[AppNet Filter] requesting path={}", path);
  request->headers().setPath(path);
  auto options = Http::AsyncClient::RequestOptions()
           .setTimeout(std::chrono::milliseconds(1000))
           .setSampled(absl::nullopt);
  cluster->httpAsyncClient().send(std::move(request), callback, options);
  return true;
}


AppnetCoroutine AppnetFilter::startRequestAppnet() {
  // !APPNET_REQUEST
  
  co_return;
}


AppnetCoroutine AppnetFilter::startResponseAppnet() {
  // !APPNET_RESPONSE

  co_return;
}

void AppNetWeakSyncTimer::onTick() {
  // ENVOY_LOG(info, "[AppNet Filter] onTick");

  // !APPNET_ONTICK

  this->tick_timer_->enableTimer(this->timeout_);
}


  
} // namespace AppNetSampleFilter

} // namespace Http
} // namespace Envoy
