/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/RTCRtpSender.h>

#include <AK/Optional.h>
#include <AK/String.h>
#include <AK/Vector.h>

namespace Web::WebRTC {

using RTCRtpHeaderExtensionParameters = Bindings::RTCRtpHeaderExtensionParameters;

using RTCRtcpParameters = Bindings::RTCRtcpParameters;

using RTCRtpCodec = Bindings::RTCRtpCodec;

using RTCRtpCodecParameters = Bindings::RTCRtpCodecParameters;

using RTCRtpCodingParameters = Bindings::RTCRtpCodingParameters;

using RTCRtpEncodingParameters = Bindings::RTCRtpEncodingParameters;

using RTCRtpParameters = Bindings::RTCRtpParameters;

using RTCRtpSendParameters = Bindings::RTCRtpSendParameters;

using RTCRtpReceiveParameters = Bindings::RTCRtpReceiveParameters;

using RTCSetParameterOptions = Bindings::RTCSetParameterOptions;

using RTCRtpHeaderExtensionCapability = Bindings::RTCRtpHeaderExtensionCapability;

using RTCRtpCapabilities = Bindings::RTCRtpCapabilities;

}
