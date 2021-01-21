
#ifndef __SANITIZE_CONVERAGE_H__
#define __SANITIZE_CONVERAGE_H__

#ifdef __clang__  // avoid gcc warning.
#  if __has_attribute(no_sanitize)
#    define ATTRIBUTE_NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
#  else
#    define ATTRIBUTE_NO_SANITIZE_MEMORY
#  endif
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
#  define ATTRIBUTE_NO_SANITIZE_MEMORY
#  define ALWAYS_INLINE
#endif // __clang__

#define ATTRIBUTE_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#define ATTRIBUTE_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize("undefined")))

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define ATTRIBUTE_NO_SANITIZE_ALL ATTRIBUTE_NO_SANITIZE_ADDRESS
#  elif __has_feature(memory_sanitizer)
#    define ATTRIBUTE_NO_SANITIZE_ALL ATTRIBUTE_NO_SANITIZE_MEMORY
#  else
#    define ATTRIBUTE_NO_SANITIZE_ALL
#  endif
#else
#  define ATTRIBUTE_NO_SANITIZE_ALL
#endif

#endif