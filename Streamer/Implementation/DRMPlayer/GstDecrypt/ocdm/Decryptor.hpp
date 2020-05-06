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

#pragma once

#include "GstBufferView.hpp"
#include "IExchangeFactory.hpp"
#include "IGstDecryptor.hpp"
#include "ResponseCallback.hpp"
#include <ocdm/open_cdm.h>

#include <gst/gstprotection.h>

namespace WPEFramework {
namespace CENCDecryptor {
    class OCDMDecryptor : public IGstDecryptor {
    public:
        OCDMDecryptor();
        OCDMDecryptor(const OCDMDecryptor&) = delete;
        OCDMDecryptor& operator=(const OCDMDecryptor&) = delete;

        gboolean Initialize(std::unique_ptr<IExchangeFactory>) override;

        gboolean HandleProtection(GstEvent*) override;
        GstFlowReturn Decrypt(GstBuffer*) override;

    private:
        struct DecryptionMetadata {
            GstBuffer* subSample;
            uint32_t subSampleCount;
            GstBuffer* IV;
            GstBuffer* keyID;
            GstProtectionMeta* protectionMeta;

            bool isClear() { return protectionMeta == nullptr; }

            bool IsValid()
            {
                return subSample != nullptr
                    && subSampleCount > 0
                    && IV != nullptr
                    && keyID != nullptr;
            }
        };

        struct CENCSystemMetadata {
            std::string keySystem;
            std::string origin;
            GstBuffer* initData;

            bool CheckIntegrity() { return !keySystem.empty() && !origin.empty() && initData != nullptr; }
        };

        void ParseProtectionEvent(CENCSystemMetadata& metadata, GstEvent& event);
        void ParseDecryptionData(DecryptionMetadata&, GstBuffer& buffer);
        std::string GetDomainName(const std::string& guid);

        OpenCDMSystem* _system;
        OpenCDMSession* _session;
        std::unique_ptr<IExchange> _exchanger;
        std::unique_ptr<IExchangeFactory> _factory;
        OpenCDMSessionCallbacks _callbacks;

        Core::Event _keyReceived;
        mutable Core::CriticalSection _protectionLock;

    private:
        Core::ProxyType<Web::Request> PrepareChallenge(const string& challenge);

        // Callbacks used for wrapping the OpenCDM C-API.
        // ------------------------------------------------------------------------------
        static void process_challenge_callback(OpenCDMSession* session,
            void* userData,
            const char url[],
            const uint8_t challenge[],
            const uint16_t challengeLength)
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            string challengeData(reinterpret_cast<const char*>(challenge), challengeLength);
            comm->ProcessChallengeCallback(session, std::string(url), challengeData);
        }

        static void key_update_callback(OpenCDMSession* session,
            void* userData,
            const uint8_t keyId[],
            const uint8_t length)
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            comm->KeyUpdateCallback(session, userData, keyId, length);
        }

        static void error_message_callback(OpenCDMSession* session,
            void* userData,
            const char message[])
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            comm->ErrorMessageCallback();
        }

        static void keys_updated_callback(const OpenCDMSession* session, void* userData)
        {
            OCDMDecryptor* comm = reinterpret_cast<OCDMDecryptor*>(userData);
            comm->KeysUpdatedCallback();
        }

        void ProcessChallengeCallback(OpenCDMSession* session,
            const string& url,
            const string& challenge)
        {
            auto callback(Core::ProxyType<IExchange::ICallback>(Core::ProxyType<OCDMResponseCallback>::Create(_session)));
            std::unique_ptr<IExchange> exchange(_factory->Create(url));
            exchange->Submit(PrepareChallenge(challenge), callback, Core::infinite);
        }

        void KeyUpdateCallback(OpenCDMSession* session,
            void* userData,
            const uint8_t keyId[],
            const uint8_t length)
        {
        }

        void ErrorMessageCallback()
        {
            TRACE_L1("Error Message Callback called");
        }

        void KeysUpdatedCallback()
        {
            _keyReceived.SetEvent();
        }
    };
}
}
