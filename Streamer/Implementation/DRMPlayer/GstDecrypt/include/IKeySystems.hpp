#pragma once

#include <com/com.h>

namespace WPEFramework {
namespace CENCDecryptor {
    class IKeySystems {
    public:
        virtual RPC::IStringIterator* Get() = 0;
    };
}
}
