#ifndef OUIJA_CPP_SANDBOX_HPP
#define OUIJA_CPP_SANDBOX_HPP

#include "ouija_core.h"
#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

namespace ouija {

/**
 * RAII Secure Buffer that allocates page-locked memory (mlock)
 * and wipes it using x86_64 assembly (ouija_secure_memzero_asm) upon destruction.
 */
template<typename T = uint8_t>
class SecureBuffer {
private:
    T* data_;
    size_t size_;

public:
    explicit SecureBuffer(size_t size) : size_(size), data_(nullptr) {
        if (size_ > 0) {
            data_ = static_cast<T*>(ouija_secure_alloc(size_ * sizeof(T)));
            if (!data_) {
                throw std::runtime_error("SecureBuffer: Failed to allocate locked memory");
            }
        }
    }

    ~SecureBuffer() {
        if (data_) {
            ouija_secure_free(data_, size_ * sizeof(T));
            data_ = nullptr;
        }
    }

    // Non-copyable for security
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            if (data_) ouija_secure_free(data_, size_ * sizeof(T));
            data_ = other.data_;
            size_ = other.size_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    T* data() noexcept { return data_; }
    const T* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    size_t size_bytes() const noexcept { return size_ * sizeof(T); }

    T& operator[](size_t index) { return data_[index]; }
    const T& operator[](size_t index) const { return data_[index]; }
};

/**
 * Constant-time comparison wrapper
 */
inline bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t len) {
    return ouija_ct_memcmp_asm(a, b, len) == 0;
}

/**
 * One-Time Pad XOR wrapper
 */
inline void otp_xor(const uint8_t* src, const uint8_t* pad, uint8_t* dst, size_t len) {
    ouija_otp_xor_asm(src, pad, dst, len);
}

} // namespace ouija

#endif // OUIJA_CPP_SANDBOX_HPP
