// Vulnerable: VUL-CVE-2022-36012
#include "tensorflow/core/platform/errors.h"
#include "tensorflow/core/platform/status.h"

using tensorflow::AttrValue;
...
using tensorflow::OpDef_AttrDef;
using tensorflow::Status;
using tensorflow::errors::InvalidArgument;
using tensorflow::protobuf::RepeatedPtrField;
...
    OperationState state(unknown_loc, absl::StrCat("tfg.", node.op()));
...
          ret_val.first);
    Value result = value_manager.GetValueOrCreatePlaceholder(
        (Twine("^") + ret_val.second).str());
