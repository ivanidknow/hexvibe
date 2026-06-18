// Vulnerable: VUL-CVE-2022-3008
// Version:
//  - v2.5.0 Add SetPreserveImageChannels() option to load image data as is.
//  - v2.4.3 Fix null object output when when material has all default
...
#define TINYGLTF_COMPONENT_TYPE_UNSIGNED_INT (5125)
#define TINYGLTF_COMPONENT_TYPE_FLOAT (5126)
#define TINYGLTF_COMPONENT_TYPE_DOUBLE (5130) // OpenGL double type. Note that some of glTF 2.0 validator does not support double type even the schema seems allow any value of integer: https://github.com/KhronosGroup/glTF/blob/b9884a2fd45130b4d673dd6c8a706ee21ee5c5f7/specification/2.0/schema/accessor.schema.json#L22

#define TINYGLTF_TEXTURE_FILTER_NEAREST (9728)
...
      TINYGLTF_TEXTURE_WRAP_REPEAT;  // ["CLAMP_TO_EDGE", "MIRRORED_REPEAT",
...
  const uint32_t bin_padding_size = binBuffer_size % 4 == 0 ? 0 : 4 - binBuffer_size % 4;

  // 12 bytes for header, JSON content length, 8 bytes for JSON chunk info.
