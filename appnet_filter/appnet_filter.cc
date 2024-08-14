#include <netinet/in.h>
#include <string>
#include <chrono>
#include <mutex>
#include "thirdparty/json.hpp"
#include "thirdparty/base64.h"

#include "appnet_filter.h"
#include "appnet_filter/echo.pb.h"

#include "envoy/server/filter_config.h"
#include "google/protobuf/extension_set.h"
#include "source/common/http/utility.h"
#include "source/common/http/message_impl.h" 
#include "envoy/upstream/resource_manager.h"


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


std::string get_rpc_field(const pb::Msg& rpc, const std::string& field) {
  if (field == "body") {
    return rpc.body();
  } else {
    throw std::runtime_error("Unknown field: " + field);
  }
}

void set_rpc_field(pb::Msg& rpc, const std::string& field, const std::string& value) {
  if (field == "body") {
    rpc.set_body(value);
  } else {
    throw std::runtime_error("Unknown field: " + field);
  }
}

void replace_payload(Buffer::Instance *data, pb::Msg& rpc) {
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
  const sample::FilterConfig&, Envoy::Server::Configuration::FactoryContext &ctx)
  : ctx_(ctx) {
  
}

AppnetFilter::AppnetFilter(AppnetFilterConfigSharedPtr config)
  : config_(config), empty_callback_(new EmptyCallback{}) {

  std::lock_guard<std::mutex> guard(global_state_lock);
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
  ENVOY_LOG(info, "[Appnet Filter] decodeHeaders {}", headers);
  this->request_headers_ = &headers;
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus AppnetFilter::decodeData(Buffer::Instance &data, bool end_of_stream) {
  if (!end_of_stream) 
    return FilterDataStatus::Continue;

  ENVOY_LOG(info, "[Appnet Filter] decodeData");
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
  ENVOY_LOG(info, "[Appnet Filter] encodeHeaders {}", headers);
  this->response_headers_ = &headers;
  if (this->req_appnet_blocked_) {
    ENVOY_LOG(info, "[Appnet Filter] encodeHeaders req_appnet_blocked_={}", this->req_appnet_blocked_);
    // We don't process the response if the request is blocked.
    return FilterHeadersStatus::Continue;
  }
  return FilterHeadersStatus::StopIteration;
}

FilterDataStatus AppnetFilter::encodeData(Buffer::Instance &data, bool end_of_stream) {
  if (this->req_appnet_blocked_) {
    // We don't process the response if the request is blocked.
    return FilterDataStatus::Continue;
  }

  ENVOY_LOG(info, "[Appnet Filter] encodeData end_of_stream={}", end_of_stream);
  this->response_buffer_ = &data;

  // std::vector<uint8_t> data_bytes(data.length());
  // data.copyOut(0, data.length(), data_bytes.data());
  // this->response_msg_ = pb::Msg::ParseFromString(data_bytes.data() + 5, data_bytes.size() - 5);

  this->appnet_coroutine_.emplace(this->startResponseAppnet());
  this->in_decoding_or_encoding_ = true;
  this->appnet_coroutine_.value().handle_.value().resume(); // the coroutine will be started here.
  if (this->appnet_coroutine_.value().handle_.value().done()) {
    // no more callback
    ENVOY_LOG(info, "[Appnet Filter] encodeData done in one time, req_appnet_blocked_={}", this->req_appnet_blocked_);
    return this->resp_appnet_blocked_ ? FilterDataStatus::StopIterationNoBuffer : FilterDataStatus::Continue;
  } else {
    ENVOY_LOG(info, "[Appnet Filter] encodeData not done in one time, req_appnet_blocked_={}", this->req_appnet_blocked_);
    return FilterDataStatus::StopIterationAndBuffer;
  }
}

// For now, it's dedicated to the webdis response.
void AppnetFilter::onSuccess(const Http::AsyncClient::Request&,
                 Http::ResponseMessagePtr&& message) {
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onSuccess");
  this->external_response_ = std::move(message);
  assert(message.get() == nullptr);
  ENVOY_LOG(info, "[Appnet Filter] ExternalResponseCallback onSuccess (second step)");
  assert(this->webdis_awaiter_.has_value());
  this->in_decoding_or_encoding_ = false;
  this->webdis_awaiter_.value()->i_am_ready();
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
  auto cluster = this->config_->ctx_.serverFactoryContext().clusterManager().getThreadLocalCluster("webdis_cluster");
  if (!cluster) {
    ENVOY_LOG(info, "webdis_cluster not found");
    assert(0);
    return false;
  }
  Http::RequestMessagePtr request = std::make_unique<Http::RequestMessageImpl>();

  request->headers().setMethod(Http::Headers::get().MethodValues.Get);
  request->headers().setHost("localhost:7379");
  ENVOY_LOG(info, "[AppNet Filter] webdis requesting path={}", path);
  request->headers().setPath(path);
  auto options = Http::AsyncClient::RequestOptions()
           .setTimeout(std::chrono::milliseconds(1000))
           .setSampled(absl::nullopt);
  cluster->httpAsyncClient().send(std::move(request), callback, options);
  return true;
}

AppnetCoroutine AppnetFilter::startRequestAppnet() {
  this->setRoutingEndpoint(0);

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
