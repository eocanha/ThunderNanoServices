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

    gboolean OCDMDecryptor::Initialize(std::unique_ptr<IExchangeFactory> factory,
        const std::string& keysystem,
        const std::string& origin,
        BufferView& initData)
    {
        _factory = std::move(factory);
        return SetupOCDM(keysystem, origin, initData);
    }

    bool OCDMDecryptor::SetupOCDM(const std::string& keysystem,
        const std::string& origin,
        BufferView& initData)
    {
        if (_system == nullptr) {
            auto domainName = GetDomainName(keysystem.c_str());
            _system = opencdm_create_system(domainName.c_str());
            if (_system != nullptr) {
                OpenCDMError ocdmResult = opencdm_construct_session(_system,
                    LicenseType::Temporary,
                    "cenc",
                    initData.Raw(),
                    static_cast<uint16_t>(initData.Size()),
                    nullptr,
                    0,
                    &_callbacks,
                    this,
                    &_session);

                if (ocdmResult != OpenCDMError::ERROR_NONE) {
                    TRACE_L1("Failed to construct session with error: <%d>", ocdmResult);
                    return false;
                }

            } else {
                TRACE_L1("Cannot construct opencdm_system for <%s> keysystem", keysystem.c_str());
                return false;
            }
        }
        return true;
    }

    // TODO: Should this be provided by the ocdm?
    std::string OCDMDecryptor::GetDomainName(const std::string& guid)
    {
        if (guid == "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
            return "com.widevine.alpha";
        else if (guid == "9a04f079-9840-4286-ab92-e65be0885f95")
            return "com.microsoft.playready";
        else
            return "";
    }

    GstFlowReturn OCDMDecryptor::Decrypt(std::shared_ptr<EncryptedBuffer> buffer)
    {
        if (buffer->IsClear())
            return GST_FLOW_OK;

        if (buffer->IsValid()) {
            BufferView keyIdView(buffer->KeyId(), GST_MAP_READ);
            uint32_t waitResult = WaitForKeyId(keyIdView, Core::infinite);
            if (waitResult == Core::ERROR_NONE) {
                OpenCDMError result = opencdm_gstreamer_session_decrypt(_session,
                    buffer->Buffer(),
                    buffer->SubSample(),
                    buffer->SubSampleCount(),
                    buffer->IV(),
                    buffer->KeyId(),
                    0);

                buffer->StripProtection();

                return result != OpenCDMError::ERROR_NONE ? GST_FLOW_NOT_SUPPORTED : GST_FLOW_OK;
            } else {
                TRACE_L1("Waiting for key failed with: <%d>", waitResult);
                return GST_FLOW_NOT_SUPPORTED;
            }

        } else {
            TRACE_L1("Invalid decryption metadata.");
            return GST_FLOW_NOT_SUPPORTED;
        }
    }

    uint32_t OCDMDecryptor::WaitForKeyId(BufferView& keyId, uint32_t timeout)
    {
        KeyStatus keyStatus = opencdm_session_status(_session, keyId.Raw(), keyId.Size());
        uint32_t result = Core::ERROR_NONE;

        if (keyStatus != KeyStatus::Usable) {
            TRACE_L1("Waiting for the key to arrive with timeout: <%d>", Core::infinite);
            result = _keyReceived.Lock(Core::infinite);
        }
        return result;
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
}
}
