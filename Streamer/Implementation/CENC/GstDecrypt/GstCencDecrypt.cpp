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

#include "GstCencDecrypt.hpp"

#include "IExchangeFactory.hpp"

#include "ocdm/Decryptor.hpp"
#include "ocdm/ExchangeFactory.hpp"
#include "ocdm/KeySystems.hpp"

#include <core/Queue.h>

#include <gst/base/gstbasetransform.h>
#include <gst/gst.h>
#include <gst/gstprotection.h>

#include <map>

using namespace WPEFramework::CENCDecryptor;

GST_DEBUG_CATEGORY_STATIC(gst_cencdecrypt_debug_category);
#define GST_CAT_DEFAULT gst_cencdecrypt_debug_category

G_DEFINE_TYPE_WITH_CODE(GstCencDecrypt, gst_cencdecrypt, GST_TYPE_BASE_TRANSFORM,
    GST_DEBUG_CATEGORY_INIT(gst_cencdecrypt_debug_category, "cencdecrypt", 0,
        "debug category for cencdecrypt element"));

constexpr static auto clearContentTypes = { "video/mp4", "audio/mp4", "audio/mpeg", "video/x-h264" };

// TODO: This information should be returned from OpenCDM.
static std::map<std::string, std::string> keySystems{ { "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed", "com.widevine.alpha" },
    { "9a04f079-9840-4286-ab92-e65be0885f95", "com.microsoft.playready" } };
constexpr static auto cencPrefix = "application/x-cenc";

// Overwritten GstBaseTransform callbacks:
static GstCaps*
TransformCaps(GstBaseTransform* trans, GstPadDirection direction,
    GstCaps* caps, GstCaps* filter);
static gboolean SinkEvent(GstBaseTransform* trans, GstEvent* event);
static GstFlowReturn TransformIp(GstBaseTransform* trans, GstBuffer* buffer);
static void Finalize(GObject* object);

static void AddCapsForKeysystem(GstCaps*& caps, const string& keysystem)
{
    for (auto& type : clearContentTypes) {
        gst_caps_append_structure(caps,
            gst_structure_new(cencPrefix,
                "original-media-type", G_TYPE_STRING, type,
                "protection-system", G_TYPE_STRING, keysystem.c_str(), NULL));
    }
}
static GstCaps* SinkCaps(GstCencDecryptClass* klass)
{
    GstCaps* cencCaps = gst_caps_new_empty();
    for (auto& system : keySystems) {
        AddCapsForKeysystem(cencCaps, system.first);
    }
    return cencCaps;
}

static GstCaps* SrcCaps()
{
    GstCaps* caps = gst_caps_new_empty();
    for (auto& type : clearContentTypes)
        gst_caps_append_structure(caps, gst_structure_new_from_string(type));
    return caps;
}

struct GstCencDecryptImpl {
    std::unique_ptr<IGstDecryptor> _decryptor;
};

void gst_cencdecrypt_dispose(GObject* object)
{
    GstCencDecrypt* cencdecrypt = GST_CENCDECRYPT(object);

    GST_DEBUG_OBJECT(cencdecrypt, "dispose");
    // WPEFramework::Core::Singleton::Dispose();

    G_OBJECT_CLASS(gst_cencdecrypt_parent_class)->dispose(object);
}

static void
gst_cencdecrypt_class_init(GstCencDecryptClass* klass)
{
    GstBaseTransformClass* base_transform_class = GST_BASE_TRANSFORM_CLASS(klass);

    gst_element_class_add_pad_template(GST_ELEMENT_CLASS(klass),
        gst_pad_template_new("src", GST_PAD_SRC, GST_PAD_ALWAYS, SrcCaps()));

    gst_element_class_add_pad_template(GST_ELEMENT_CLASS(klass),
        gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, SinkCaps(klass))); // TODO: KeySystemzzz

    gst_element_class_set_static_metadata(GST_ELEMENT_CLASS(klass),
        "FIXME Long name", GST_ELEMENT_FACTORY_KLASS_DECRYPTOR, "FIXME Description",
        "FIXME <fixme@example.com>");

    G_OBJECT_CLASS(klass)->finalize = Finalize;

    base_transform_class->transform_caps = GST_DEBUG_FUNCPTR(TransformCaps);

    base_transform_class->accept_caps = [](GstBaseTransform* trans, GstPadDirection direction,
                                            GstCaps* caps) -> gboolean {
        GST_FIXME_OBJECT(GST_CENCDECRYPT(trans), "Element accepts all caps");
        return TRUE;
    };

    base_transform_class->transform_ip = GST_DEBUG_FUNCPTR(TransformIp);
    base_transform_class->sink_event = GST_DEBUG_FUNCPTR(SinkEvent);
}

static void gst_cencdecrypt_init(GstCencDecrypt* cencdecrypt)
{
    GstBaseTransform* base = GST_BASE_TRANSFORM(cencdecrypt);
    gst_base_transform_set_in_place(base, TRUE);
    gst_base_transform_set_passthrough(base, FALSE);
    gst_base_transform_set_gap_aware(base, FALSE);

    cencdecrypt->_impl = std::move(std::unique_ptr<GstCencDecryptImpl>(new GstCencDecryptImpl()));
    cencdecrypt->_impl->_decryptor = std::move(std::unique_ptr<OCDMDecryptor>(new OCDMDecryptor()));
    cencdecrypt->_impl->_decryptor->Initialize(std::unique_ptr<ExchangeFactory>(new ExchangeFactory()));

    GST_FIXME_OBJECT(cencdecrypt, "Flushing the pipeline doesn't free ocdm system/session");
    GST_FIXME_OBJECT(cencdecrypt, "Element is accepting all caps");
    GST_FIXME_OBJECT(cencdecrypt, "Upstream caps transformation not implemented");
    GST_FIXME_OBJECT(cencdecrypt, "Caps are constructed based on hard coded keysystem values");
    GST_FIXME_OBJECT(cencdecrypt, "Element doesn't handle dash manifests - mpd");
}

static void clearCencStruct(GstStructure*& structure)
{
    gst_structure_set_name(structure, gst_structure_get_string(structure, "original-media-type"));
    gst_structure_remove_field(structure, "protection-system");
    gst_structure_remove_field(structure, "original-media-type");
}

static GstCaps* TransformCaps(GstBaseTransform* trans, GstPadDirection direction,
    GstCaps* caps, GstCaps* filter)
{
    GstCencDecrypt* cencdecrypt = GST_CENCDECRYPT(trans);
    GstCaps* othercaps;

    GST_DEBUG_OBJECT(cencdecrypt, "transform_caps");
    GST_FIXME_OBJECT(cencdecrypt, "Upstream caps transformation not implemented");

    if (direction == GST_PAD_SRC) {
        // TODO:
        // Fired on reconfigure events.
        othercaps = gst_caps_copy(caps);
    } else {
        GST_INFO("Transforming caps going downstream");
        othercaps = gst_caps_new_empty();
        size_t size = gst_caps_get_size(caps);
        for (size_t index = 0; index < size; ++index) {
            GstStructure* upstreamStruct = gst_caps_get_structure(caps, index);
            GstStructure* copyUpstream = gst_structure_copy(upstreamStruct);

            // Removes all fields related to encryption, so the downstream caps intersection succeeds.
            clearCencStruct(copyUpstream);
            // "othercaps" become the owner of the "copyUpstream" structure, so no need to free.
            gst_caps_append_structure(othercaps, copyUpstream);
        }
    }

    if (filter) {
        GstCaps* intersect;
        othercaps = gst_caps_copy(caps);
        intersect = gst_caps_intersect(othercaps, filter);
        gst_caps_unref(othercaps);
        othercaps = intersect;
    }
    return othercaps;
}

static gboolean SinkEvent(GstBaseTransform* trans, GstEvent* event)
{
    GstCencDecrypt* cencdecrypt = GST_CENCDECRYPT(trans);
    GST_DEBUG_OBJECT(cencdecrypt, "sink_event");
    switch (GST_EVENT_TYPE(event)) {
    case GST_EVENT_PROTECTION: {
        gboolean result = cencdecrypt->_impl->_decryptor->HandleProtection(event);
        gst_event_unref(event);
        return result;
    }
    default: {
        return GST_BASE_TRANSFORM_CLASS(gst_cencdecrypt_parent_class)->sink_event(trans, event);
    }
    }
}

static GstFlowReturn TransformIp(GstBaseTransform* trans, GstBuffer* buffer)
{
    GstCencDecrypt* cencdecrypt = GST_CENCDECRYPT(trans);

    GST_DEBUG_OBJECT(cencdecrypt, "transform_ip");

    return cencdecrypt->_impl->_decryptor->Decrypt(buffer);
}

void Finalize(GObject* object)
{
    GstCencDecrypt* cencdecrypt = GST_CENCDECRYPT(object);
    GST_DEBUG_OBJECT(cencdecrypt, "finalize");
    G_OBJECT_CLASS(gst_cencdecrypt_parent_class)->finalize(object);
}

static gboolean
plugin_init(GstPlugin* plugin)
{
    return gst_element_register(plugin, "cencdecrypt", GST_RANK_PRIMARY,
        GST_TYPE_CENCDECRYPT);
}

#ifndef VERSION
#define VERSION "0.0.FIXME"
#endif
#ifndef PACKAGE
#define PACKAGE "FIXME_package"
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "FIXME_package_name"
#endif
#ifndef GST_PACKAGE_ORIGIN
#define GST_PACKAGE_ORIGIN "http://FIXME.org/"
#endif

GST_PLUGIN_DEFINE(GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    cencdecrypt,
    "FIXME plugin description",
    plugin_init, VERSION, "LGPL", PACKAGE_NAME, GST_PACKAGE_ORIGIN)
