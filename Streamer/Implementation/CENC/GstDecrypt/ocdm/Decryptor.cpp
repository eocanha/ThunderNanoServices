/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2020 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Decryptor.hpp"

#include <gst/gstbuffer.h>
#include <gst/gstevent.h>
#include <thread>

#include "open_cdm_adapter.h"

namespace WPEFramework {
namespace CENCDecryptor {

    OCDMDecryptor::OCDMDecryptor()
        : _system(nullptr)
        , _session(nullptr)
        , _exchanger()
        , _factory()
        , _callbacks({ process_challenge_callback,
              key_update_callback,
              error_message_callback,
              keys_updated_callback })
        , _keyReceived(false, true)
        , _protectionLock()
    {
    }

    gboolean OCDMDecryptor::Initialize(std::unique_ptr<IExchangeFactory> factory)
    {
        _factory = std::move(factory);
        return TRUE;
    }

    gboolean OCDMDecryptor::HandleProtection(GstEvent* event)
    {
        gboolean result = TRUE;

        if (_system == nullptr) {

            CENCSystemMetadata metadata;
            ParseProtectionEvent(metadata, *event);
            auto domainName = GetDomainName(metadata.keySystem.c_str());
            _system = opencdm_create_system(domainName.c_str());
            if (_system != nullptr) {

                BufferView dataView(metadata.initData, GST_MAP_READ);

                OpenCDMError ocdmResult = opencdm_construct_session(_system,
                    LicenseType::Temporary,
                    "cenc",
                    dataView.Raw(),
                    static_cast<uint16_t>(dataView.Size()),
                    nullptr,
                    0,
                    &_callbacks,
                    this,
                    &_session);

                if (ocdmResult != OpenCDMError::ERROR_NONE) {
                    result = FALSE;
                    TRACE_L1("Failed to construct session with error: <%d>", ocdmResult);
                }

            } else {
                TRACE_L1("Cannot construct opencdm_system for <%s> keysystem", metadata.keySystem.c_str());
                result = FALSE;
            }
        }

        return result;
    }

    GstFlowReturn OCDMDecryptor::Decrypt(GstBuffer* buffer)
    {
        DecryptionMetadata dashData;
        ParseDecryptionData(dashData, *buffer);

        if (dashData.isClear())
            return GST_FLOW_OK;

        if (dashData.IsValid()) {
            BufferView dataView(dashData.keyID, GST_MAP_READ);

            // TODO: The key might still arrive within a short period of time.
            KeyStatus keyStatus = opencdm_session_status(_session, dataView.Raw(), dataView.Size());
            uint32_t result = Core::ERROR_NONE;

            if (keyStatus != KeyStatus::Usable) {
                TRACE_L1("Waiting for the key to arrive with timeout: <%d>", Core::infinite);
                result = _keyReceived.Lock(Core::infinite);
            }

            if (result == Core::ERROR_NONE) {
                OpenCDMError result = opencdm_gstreamer_session_decrypt(_session,
                    buffer,
                    dashData.subSample,
                    dashData.subSampleCount,
                    dashData.IV,
                    dashData.keyID,
                    0);

                gst_buffer_remove_meta(buffer, reinterpret_cast<GstMeta*>(dashData.protectionMeta));

                return result != OpenCDMError::ERROR_NONE ? GST_FLOW_NOT_SUPPORTED : GST_FLOW_OK;
            } else {
                TRACE_L1("Abandoning decryption with result: <%d>", result);
                return GST_FLOW_NOT_SUPPORTED;
            }

        } else {
            TRACE_L1("Invalid decryption metadata.");
            return GST_FLOW_NOT_SUPPORTED;
        }
    }

    void OCDMDecryptor::ParseProtectionEvent(CENCSystemMetadata& metadata, GstEvent& event)
    {
        const char* systemId = nullptr;
        const char* origin = nullptr;
        GstBuffer* data = nullptr;

        gst_event_parse_protection(&event, &systemId, &data, &origin);
        metadata.keySystem.assign(systemId);
        metadata.origin.assign(origin);
        metadata.initData = data;
    }

    std::string OCDMDecryptor::GetDomainName(const std::string& guid)
    {
        // TODO: This is a mocked version of what should be provided from ocdm.
        if (guid == "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
            return "com.widevine.alpha";
        else if (guid == "9a04f079-9840-4286-ab92-e65be0885f95")
            return "com.microsoft.playready";
    }

    Core::ProxyType<Web::Request> OCDMDecryptor::PrepareChallenge(const string& challenge)
    {
        size_t index = challenge.find(":Type:");
        size_t offset = 0;

        if (index != std::string::npos)
            offset = index + strlen(":Type:");

        auto request(Core::ProxyType<Web::Request>::Create());
        auto requestBody(Core::ProxyType<Web::TextBody>::Create());
        std::string reqBodyStr(challenge.substr(offset));
        requestBody->assign(reqBodyStr);

        request->Body<Web::TextBody>(requestBody);
        request->Verb = Web::Request::HTTP_POST;
        request->Connection = Web::Request::CONNECTION_CLOSE;
        request->ContentType = Web::MIMETypes::MIME_TEXT_XML;
        request->ContentLength = reqBodyStr.length();

        return request;
    }

    void OCDMDecryptor::ParseDecryptionData(DecryptionMetadata& metadata, GstBuffer& buffer)
    {
        GstProtectionMeta* protectionMeta = reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta(&buffer));
        if (!protectionMeta) {
            metadata.protectionMeta = nullptr;
        } else {
            gst_structure_remove_field(protectionMeta->info, "stream-encryption-events");

            const GValue* value;
            value = gst_structure_get_value(protectionMeta->info, "kid");

            metadata.keyID = gst_value_get_buffer(value);

            unsigned ivSize;
            gst_structure_get_uint(protectionMeta->info, "iv_size", &ivSize);

            gboolean encrypted;
            gst_structure_get_boolean(protectionMeta->info, "encrypted", &encrypted);

            if (!ivSize || !encrypted) {
                gst_buffer_remove_meta(&buffer, reinterpret_cast<GstMeta*>(protectionMeta));
                metadata.protectionMeta = nullptr;
            } else {
                gst_structure_get_uint(protectionMeta->info, "subsample_count", &metadata.subSampleCount);
                if (metadata.subSampleCount) {
                    const GValue* value2 = gst_structure_get_value(protectionMeta->info, "subsamples");
                    metadata.subSample = gst_value_get_buffer(value2);
                }

                const GValue* value3;
                value3 = gst_structure_get_value(protectionMeta->info, "iv");
                metadata.IV = gst_value_get_buffer(value3);
            }
        }
    }
}
}
