// Vulnerable: VUL-CVE-2018-1000178
transfermanager.cpp
    util.cpp

    protocols/datastream/datastreampeer.cpp
// --- datastreampeer.cpp ---
#include "datastreampeer.h"

using namespace Protocol;
...
    stream.setVersion(QDataStream::Qt_4_2);
    QVariantList list;
...
    else {
        stream >> item;
    }
