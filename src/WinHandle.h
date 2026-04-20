#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

class UniqueHandle final
{
public:
    UniqueHandle() = default;

    explicit UniqueHandle(HANDLE handle) noexcept
        : handle_(handle)
    {
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept
        : handle_(other.handle_)
    {
        other.handle_ = nullptr;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept
    {
        if (this != &other)
        {
            reset(other.release());
        }

        return *this;
    }

    ~UniqueHandle()
    {
        reset();
    }

    [[nodiscard]] HANDLE get() const noexcept
    {
        return handle_;
    }

    [[nodiscard]] bool valid() const noexcept
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return valid();
    }

    HANDLE release() noexcept
    {
        HANDLE releasedHandle = handle_;
        handle_ = nullptr;
        return releasedHandle;
    }

    void reset(HANDLE nextHandle = nullptr) noexcept
    {
        if (valid())
        {
            CloseHandle(handle_);
        }

        handle_ = nextHandle;
    }

private:
    HANDLE handle_ = nullptr;
};
