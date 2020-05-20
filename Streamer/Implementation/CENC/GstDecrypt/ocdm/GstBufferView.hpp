#pragma once

#include <gst/gstbuffer.h>

namespace WPEFramework {
namespace CENCDecryptor {
    class BufferView {
    public:
        BufferView() = delete;
        BufferView(const BufferView&) = delete;
        BufferView& operator=(const BufferView&) = delete;

        explicit BufferView(GstBuffer* buffer, GstMapFlags flags)
            : _buffer(buffer)
        {
            gst_buffer_map(_buffer, &_dataView, flags);
        }

        gsize Size() { return _dataView.size; }
        guint8* Raw() { return _dataView.data; }

        ~BufferView()
        {
            gst_buffer_unmap(_buffer, &_dataView);
        }

    private:
        GstBuffer* _buffer;
        GstMapInfo _dataView;
    };
}
}
