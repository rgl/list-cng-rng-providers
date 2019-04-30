/* list cng rng providers.
*
* Copyright (c) 2019, Rui Lopes (ruilopes.com)
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
*   * Redistributions of source code must retain the above copyright notice,
*     this list of conditions and the following disclaimer.
*   * Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in the
*     documentation and/or other materials provided with the distribution.
*   * Neither the name of Redis nor the names of its contributors may be used
*     to endorse or promote products derived from this software without
*     specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

#define _WIN32_WINNT 0x0A00 // Windows 10+
#define WINVER _WIN32_WINNT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <wchar.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <io.h>

void LOG(const char *format, ...) {
    time_t t;
    time(&t);
    char buffer[128];
    strftime(buffer, 128, "%Y-%m-%d %H:%M:%S ", localtime(&t));
    int l = strlen(buffer);
    va_list args;
    va_start(args, format);
    vsprintf_s(buffer+l, 128-l, format, args);
    va_end(args);
    puts(buffer);
    l = strlen(buffer);
    buffer[l++] = '\n';
    buffer[l] = 0;
    FILE *log = fopen("list-cng-rng-providers.log", "a+");
    fputs(buffer, log);
    fclose(log);
}

int wmain(int argc, wchar_t *argv[]) {
    LOG("Running (pid=%d)...", GetCurrentProcessId());

    // see HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Cryptography\Providers
    // see https://github.com/virtio-win/kvm-guest-drivers-windows/blob/master/viorng/cng/um/viorngum.c

    ULONG providersSize = 0;
    PCRYPT_PROVIDER_REFS providers = NULL;

    NTSTATUS status = BCryptResolveProviders(
        NULL,                   // pszContext
        BCRYPT_RNG_INTERFACE,   // dwInterface
        BCRYPT_RNG_ALGORITHM,   // pszFunction
        NULL,                   // pszProvider
        CRYPT_UM,               // dwMode
        CRYPT_ALL_PROVIDERS,    // dwFlags
        &providersSize,         // pcbBuffer
        &providers              // ppBuffer
    );
    if (STATUS_SUCCESS != status) {
        switch (status) {
            case STATUS_BUFFER_TOO_SMALL:
                LOG("ERROR Failed to call BCryptResolveProviders with status STATUS_BUFFER_TOO_SMALL");
                break;
            case STATUS_INVALID_PARAMETER:
                LOG("ERROR Failed to call BCryptResolveProviders with status STATUS_INVALID_PARAMETER");
                break;
            case STATUS_NOT_FOUND:
                LOG("ERROR Failed to call BCryptResolveProviders with status STATUS_NOT_FOUND");
                break;
            default:
                LOG("ERROR Failed to call BCryptResolveProviders with status 0x%08x (%d)", status, status);
        }
        return 1;
    }

    for (ULONG n = 0; n < providers->cProviders; ++n) {
        PCRYPT_PROVIDER_REF provider = providers->rgpProviders[n];

        if (provider->dwInterface != BCRYPT_RNG_INTERFACE) {
            LOG("ERROR Provider %d dwInterface was %d instead of %d", n, provider->dwInterface, BCRYPT_RNG_INTERFACE);
            break;
        }

        if (wcscmp(provider->pszFunction, BCRYPT_RNG_ALGORITHM)) {
            LOG("ERROR Provider %d pszFunction was %s instead of %s", n, provider->pszFunction, BCRYPT_RNG_ALGORITHM);
            break;
        }

        LOG("RNG provider: %S", provider->pszProvider);

        // show aliases (normally there are none)
        ULONG providerRegistrationSize = 0;
        PCRYPT_PROVIDER_REG providerRegistration = NULL;
        status = BCryptQueryProviderRegistration(
            provider->pszProvider,      // pszProvider
            CRYPT_UM,                   // dwMode
            BCRYPT_RNG_INTERFACE,       // dwInterface
            &providerRegistrationSize,  // pcbBuffer
            &providerRegistration       // ppBuffer
        );
        if (STATUS_SUCCESS != status) {
            switch (status) {
                case STATUS_BUFFER_TOO_SMALL:
                    LOG("ERROR Failed to call BCryptQueryProviderRegistration with status STATUS_BUFFER_TOO_SMALL");
                    break;
                case STATUS_INVALID_PARAMETER:
                    LOG("ERROR Failed to call BCryptQueryProviderRegistration with status STATUS_INVALID_PARAMETER");
                    break;
                case STATUS_NOT_FOUND:
                    LOG("ERROR Failed to call BCryptQueryProviderRegistration with status STATUS_NOT_FOUND");
                    break;
                default:
                    LOG("ERROR Failed to call BCryptQueryProviderRegistration with status 0x%08x (%d)", status, status);
            }
            return 1;
        }
        for (ULONG i = 0; i < providerRegistration->cAliases; ++i) {
            LOG("RNG provider %S alias: %S", provider->pszProvider, providerRegistration->rgpszAliases[i]);
        }
        BCryptFreeBuffer(providerRegistration);

        // list properties (normally there are none).
        for (ULONG i = 0; i < provider->cProperties; ++i) {
            PCRYPT_PROPERTY_REF property = provider->rgpProperties[i];

            LOG("RNG provider property: %S", property->pszProperty);
        }
    }

    UCHAR buffer[32];
    status = BCryptGenRandom(
        NULL,                           // hAlgorithm
        buffer,                         // pbBuffer
        sizeof(buffer),                 // cbBuffer
        BCRYPT_USE_SYSTEM_PREFERRED_RNG // dwFlags
    );
    if (STATUS_SUCCESS != status) {
        switch (status) {
            case STATUS_INVALID_HANDLE:
                LOG("ERROR Failed to call BCryptGenRandom with status STATUS_INVALID_HANDLE");
                break;
            case STATUS_INVALID_PARAMETER:
                LOG("ERROR Failed to call BCryptGenRandom with status STATUS_INVALID_PARAMETER");
                break;
            default:
                LOG("ERROR Failed to call BCryptGenRandom with status 0x%08x (%d)", status, status);
        }
        return 1;
    }
    char randomHex[sizeof(buffer)*2+1];
    for (int i = 0; i < sizeof(buffer); ++i) {
        sprintf(&randomHex[i*2], "%02x", buffer[i]);
    }
    randomHex[sizeof(buffer)*2] = 0;
    LOG("Random %s", randomHex);

    BCryptFreeBuffer(providers);
    return 0;
}