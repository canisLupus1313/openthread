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

#if OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#include <openthread/ble_secure.h>

#include <openthread/platform/ble.h>
#include "common/as_core_type.hpp"
#include "common/locator_getters.hpp"
#include "meshcop/tcat_agent.hpp"
#include "radio/ble_secure.hpp"

#include <openthread/platform/ble.h>

using namespace ot;

otError otBleSecureStart(otInstance              *aInstance,
                         otHandleBleSecureConnect aConnectHandler,
                         otHandleBleSecureReceive aReceiveHandler,
                         bool                     aTlvMode,
                         void                    *aContext)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().Start(aConnectHandler, aReceiveHandler, aTlvMode, aContext);
}

otError otBleSecureTcatStart(otInstance       *aInstance,
                             otTcatVendorInfo *aVendorInfo,
                             otHandleTcatJoin  aHandler)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().TcatStart(
        static_cast<MeshCoP::TcatAgent::VendorInfo *>(aVendorInfo), aHandler);
}

void otBleSecureStop(otInstance *aInstance) { AsCoreType(aInstance).GetApplicationBleSecure().Stop(); }

#ifdef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
void otBleSecureSetPsk(otInstance    *aInstance,
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
otError otBleSecureGetPeerCertificateBase64(otInstance    *aInstance,
                                            unsigned char *aPeerCert,
                                            size_t        *aCertLength,
                                            size_t         aCertBufferSize)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().GetPeerCertificateBase64(aPeerCert, aCertLength,
                                                                                    aCertBufferSize);
}
#endif // defined(MBEDTLS_BASE64_C) && defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)

#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
otError otBleSecureGetPeerSubjectAttributeByOid(otInstance    *aInstance,
                                                const char    *aOid,
                                                size_t         aOidLength,
                                                unsigned char *aAttributeBuffer,
                                                size_t        *aAttributeLength,
                                                size_t         aAttributeBufferSize,
                                                int           *aAns1Type)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().GetPeerSubjectAttributeByOid(
        aOid, aOidLength, aAttributeBuffer, aAttributeLength, aAttributeBufferSize, aAns1Type);
}

otError otBleSecureGetThreadAttributeFromPeerCertificate(otInstance    *aInstance,
                                                         int            aThreadOidDescriptor,
                                                         unsigned char *aAttributeBuffer,
                                                         size_t        *aAttributeLength,
                                                         size_t         aAttributeBufferSize)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().GetThreadAttributeFromPeerCertificate(
        aThreadOidDescriptor, aAttributeBuffer, aAttributeLength, aAttributeBufferSize);
}
#endif // defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)

otError otBleSecureGetThreadAttributeFromOwnCertificate(otInstance    *aInstance,
                                                        int            aThreadOidDescriptor,
                                                        unsigned char *aAttributeBuffer,
                                                        size_t        *aAttributeLength,
                                                        size_t         aAttributeBufferSize)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().GetThreadAttributeFromOwnCertificate(
        aThreadOidDescriptor, aAttributeBuffer, aAttributeLength, aAttributeBufferSize);
}

otError otBleSecureGetThreadAttributeFromCaCertificateChain(otInstance    *aInstance,
                                                            int            aThreadOidDescriptor,
                                                            unsigned char *aAttributeBuffer,
                                                            size_t        *aAttributeLength,
                                                            size_t         aAttributeBufferSize)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().GetThreadAttributeFromCaCertificateChain(
        aThreadOidDescriptor, aAttributeBuffer, aAttributeLength, aAttributeBufferSize);
}

void otBleSecureSetSslAuthMode(otInstance *aInstance, bool aVerifyPeerCertificate)
{
    AsCoreType(aInstance).GetApplicationBleSecure().SetSslAuthMode(aVerifyPeerCertificate);
}

#ifdef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
void otBleSecureSetCertificate(otInstance    *aInstance,
                               const uint8_t *aX509Cert,
                               uint32_t       aX509Length,
                               const uint8_t *aPrivateKey,
                               uint32_t       aPrivateKeyLength)
{
    OT_ASSERT(aX509Cert != nullptr && aX509Length != 0 && aPrivateKey != nullptr && aPrivateKeyLength != 0);

    AsCoreType(aInstance).GetApplicationBleSecure().SetCertificate(aX509Cert, aX509Length, aPrivateKey,
                                                                   aPrivateKeyLength);
}

void otBleSecureSetCaCertificateChain(otInstance    *aInstance,
                                      const uint8_t *aX509CaCertificateChain,
                                      uint32_t       aX509CaCertChainLength)
{
    OT_ASSERT(aX509CaCertificateChain != nullptr && aX509CaCertChainLength != 0);

    AsCoreType(aInstance).GetApplicationBleSecure().SetCaCertificateChain(aX509CaCertificateChain,
                                                                          aX509CaCertChainLength);
}
#endif // MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

otError otBleSecureConnect(otInstance *aInstance) { return AsCoreType(aInstance).GetApplicationBleSecure().Connect(); }

void otBleSecureDisconnect(otInstance *aInstance) { AsCoreType(aInstance).GetApplicationBleSecure().Disconnect(); }

bool otBleSecureIsConnected(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsConnected();
}

bool otBleSecureIsConnectionActive(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsConnectionActive();
}

bool otBleSecureIsPskdVerified(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsPskdVerified();
}

bool otBleSecureIsPskcVerified(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsPskcVerified();
}

bool otBleSecureIsTcatEnabled(otInstance *aInstance)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().IsTcatEnabled();
}

otError otBleSecureSendMessage(otInstance *aInstance, otMessage *aMessage)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().SendMessage(static_cast<Message *>(aMessage));
}

otError otBleSecureSend(otInstance *aInstance, uint8_t *aBuf, uint16_t aLength)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().Send(aBuf, aLength);
}

otError otBleSecureSendApplicationTlv(otInstance *aInstance, uint8_t *aBuf, uint16_t aLength)
{
    return AsCoreType(aInstance).GetApplicationBleSecure().SendApplicationTlv(aBuf, aLength);
}

otError otBleSecureFlush(otInstance *aInstance) { return AsCoreType(aInstance).GetApplicationBleSecure().Flush(); }

void otPlatBleGattServerOnWriteRequest(otInstance *aInstance, uint16_t aHandle, otBleRadioPacket *aPacket)
{
    OT_UNUSED_VARIABLE(aHandle); // Only a single handle is expected for RX

    if (aPacket == NULL)
        return;

    AsCoreType(aInstance).GetApplicationBleSecure().HandleBleReceive(aPacket->mValue, aPacket->mLength);
}

void otPlatBleGapOnConnected(otInstance *aInstance, uint16_t aConnectionId)
{
    AsCoreType(aInstance).GetApplicationBleSecure().HandleBleConnected(aConnectionId);
}

void otPlatBleGapOnDisconnected(otInstance *aInstance, uint16_t aConnectionId)
{
    AsCoreType(aInstance).GetApplicationBleSecure().HandleBleDisconnected(aConnectionId);
}

#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE
