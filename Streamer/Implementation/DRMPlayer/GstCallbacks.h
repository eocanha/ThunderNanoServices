#pragma once

#include "DRMPlayer.h"
#include <gst/gst.h>

namespace WPEFramework {
namespace Player {
    namespace Implementation {
        namespace {
            namespace GstCallbacks {
                gboolean gstBusCallback(GstBus* bus, GstMessage* message, DRMPlayer::PipelineData* data)
                {
                    switch (GST_MESSAGE_TYPE(message)) {
                    case GST_MESSAGE_ERROR: {

                        GError* err;
                        gchar* debugInfo;
                        gst_message_parse_error(message, &err, &debugInfo);
                        TRACE_L1("Error received from element %s: %s\n", gst_object_get_name(message->src), err->message);
                        TRACE_L1("Debugging information: %s\n", debugInfo ? debugInfo : "none");
                        g_clear_error(&err);
                        g_free(debugInfo);

                        gst_element_set_state(data->_playbin, GST_STATE_NULL);
                        g_main_loop_quit(data->_mainLoop);
                        break;
                    }
                    case GST_MESSAGE_EOS: {
                        TRACE_L1("Reached end of stream");
                        gst_element_set_state(data->_playbin, GST_STATE_NULL);
                        break;
                    }
                    case GST_MESSAGE_STATE_CHANGED: {
                        GstState old_state, new_state;
                        gst_message_parse_state_changed(message, &old_state, &new_state, NULL);
                        std::string old_str(gst_element_state_get_name(old_state)), new_str(gst_element_state_get_name(new_state));
                        std::string filename(old_str + "->" + new_str);
                        GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS(GST_BIN(data->_playbin), GST_DEBUG_GRAPH_SHOW_ALL, filename.c_str());
                        break;
                    }
                    default:
                        break;
                    }
                    return TRUE;
                }
            } // namespace GstCallbacks
        }
    } // namespace Implementation
} // namespace Player
} // namespace WPEFramework