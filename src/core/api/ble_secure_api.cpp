/*
 *  Copyright (c) 2022, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements the OpenThread BLE Secure API.
 */

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_BLE_SECURE_ENABLE

#include <openthread/ble_secure.h>

#include "radio/ble_secure.hpp"
#include <openthread/platform/ble.h>
#include "common/as_core_type.hpp"
#include "common/locator_getters.hpp"

#include <openthread/platform/ble.h>

using namespace ot;

otError otBleSecureStart(otInstance *               aInstance,
                         otHandleBleSecureReceive   aHandler,
                         bool                       aLineMode,
                         void *                     aContext)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().Start(aHandler, aLineMode, aContext);
}

void otBleSecureStop(otInstance *aInstance)
{
    AsCoreType(aInstance).GetApplicationBleSecure().Stop();
}

#ifdef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
void otBleSecureSetPsk(otInstance *   aInstance,
                       const uint8_t *aPsk,
                       uint16_t       aPskLength,
                       const uint8_t *aPskIdentity,
                       uint16_t       aPskIdLength)
{
    OT_ASSERT(aPsk != nullptr && aPskLength != 0 && aPskIdentity != nullptr && aPskIdLength != 0);

    AsCoreType(aInstance).GetApplicationBleSecure().SetPreSharedKey(aPsk, aPskLength, aPskIdentity, aPskIdLength);
}
#endif // MBEDTLS_KEY_EXCHANGE_PSK_ENABLED

#if defined(MBEDTLS_BASE64_C) && defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
otError otBleSecureGetPeerCertificateBase64(otInstance *   aInstance,
                                            unsigned char *aPeerCert,
                                            size_t *       aCertLength,
                                            size_t         aCertBufferSize)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().GetPeerCertificateBase64(aPeerCert, aCertLength,
                                                                                     aCertBufferSize);
}
#endif // defined(MBEDTLS_BASE64_C) && defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)

void otBleSecureSetClientConnectedCallback(otInstance *                    aInstance,
                                           otHandleBleSecureClientConnect  aHandler,
                                           void *                          aContext)
{
    AsCoreType(aInstance).GetApplicationBleSecure().SetClientConnectedCallback(aHandler, aContext);
}

void otBleSecureSetSslAuthMode(otInstance *aInstance, bool aVerifyPeerCertificate)
{
    AsCoreType(aInstance).GetApplicationBleSecure().SetSslAuthMode(aVerifyPeerCertificate);
}

#ifdef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
void otBleSecureSetCertificate(otInstance *   aInstance,
                               const uint8_t *aX509Cert,
                               uint32_t       aX509Length,
                               const uint8_t *aPrivateKey,
                               uint32_t       aPrivateKeyLength)
{
    OT_ASSERT(aX509Cert != nullptr && aX509Length != 0 && aPrivateKey != nullptr && aPrivateKeyLength != 0);

    AsCoreType(aInstance).GetApplicationBleSecure().SetCertificate(aX509Cert, aX509Length, aPrivateKey,
                                                                    aPrivateKeyLength);
}

void otBleSecureSetCaCertificateChain(otInstance *   aInstance,
                                      const uint8_t *aX509CaCertificateChain,
                                      uint32_t       aX509CaCertChainLength)
{
    OT_ASSERT(aX509CaCertificateChain != nullptr && aX509CaCertChainLength != 0);

    AsCoreType(aInstance).GetApplicationBleSecure().SetCaCertificateChain(aX509CaCertificateChain,
                                                                           aX509CaCertChainLength);
}
#endif // MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

otError otBleSecureConnect(otInstance *                    aInstance,
                           otHandleBleSecureClientConnect  aHandler,
                           void *                          aContext)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().Connect(aHandler, aContext);
}

void otBleSecureDisconnect(otInstance *aInstance)
{
    AsCoreType(aInstance).GetApplicationBleSecure().Disconnect();
}

bool otBleSecureIsConnected(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsConnected();
}

bool otBleSecureIsConnectionActive(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsConnectionActive();
}

otError otBleSecureSendMessage(otInstance *     aInstance, 
                               otMessage *      aMessage)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().SendMessage(AsCoapMessage(aMessage));
}

otError otBleSecureSend(otInstance *    aInstance, 
                        uint8_t *       aBuf,
                        uint16_t        aLength)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().Send(aBuf, aLength);
}

void otPlatBleGattServerOnWriteRequest(otInstance *aInstance, uint16_t aHandle, otBleRadioPacket *aPacket)
{
    OT_UNUSED_VARIABLE(aHandle);

    if(aPacket == NULL) return;

    // Check handle?
    AsCoreType(aInstance).GetApplicationBleSecure().HandleBleReceive(aPacket->mValue, aPacket->mLength);
}

#endif // OPENTHREAD_CONFIG_BLE_SECURE_ENABLE
