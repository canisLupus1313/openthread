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

#ifndef BLE_SECURE_HPP_
#define BLE_SECURE_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_BLE_SECURE_ENABLE

#include <openthread/ble_secure.h>

#include "meshcop/dtls.hpp"
#include "meshcop/meshcop.hpp"

//#include <openthread/ble_secure.h>

/**
 * @file
 *   This file includes definitions for the secure Ble agent.
 */

namespace ot {

namespace Ble {

class BleSecure : public InstanceLocator, private NonCopyable
{
public:
    /**
     * This function pointer is called once TLS connection is established.
     *
     * @param[in]  aConnected   TRUE if a connection was established, FALSE otherwise.
     * @param[in]  aContext     A pointer to arbitrary context information.
     *
     */
    typedef void (*ConnectedCallback)(bool aConnected, void *aContext);

     /**
     * This function pointer is called when data was received over the TLS connection.
     * If line mode is activated the function is called only after EOL has been received. 
     *
     *  Please see otHandleBleSecureReceive for details.
     *
     */
    typedef otHandleBleSecureReceive ReceiveCallback;

    /**
     * This constructor initializes the object.
     *
     * @param[in]  aInstance    A reference to the OpenThread instance.
     *
     */
    explicit BleSecure(Instance &aInstance);

    /**
     * This method starts the secure Ble agent.
     *
     * @retval kErrorNone       Successfully started the Ble agent.
     * @retval kErrorAlready    Already started.
     *
     */
    Error Start(ReceiveCallback aHandler, bool aLineMode, void *aContext);

    /**
     * This method sets connected callback of this secure Ble agent.
     *
     * @param[in]  aCallback  A pointer to a function to get called when connection state changes.
     * @param[in]  aContext   A pointer to arbitrary context information.
     *
     */
    void SetConnectedCallback(ConnectedCallback aCallback, void *aContext)
    {
        mConnectedCallback = aCallback;
        mConnectedContext  = aContext;
    }

    /**
     * This method stops the secure Ble agent.
     *
     */
    void Stop(void);

    /**
     * This method initializes TLS session with a peer.
     *
     * @param[in]  aCallback               A pointer to a function that will be called once TLS connection is
     * established.
     *
     * @retval kErrorNone  Successfully started TLS connection.
     *
     */
    Error Connect(ConnectedCallback aCallback, void *aContext);

    /**
     * This method indicates whether or not the TLS session is active.
     *
     * @retval TRUE  If TLS session is active.
     * @retval FALSE If TLS session is not active.
     *
     */
    bool IsConnectionActive(void) const { return mTls.IsConnectionActive(); }

    /**
     * This method indicates whether or not the TLS session is connected.
     *
     * @retval TRUE   The TLS session is connected.
     * @retval FALSE  The TLS session is not connected.
     *
     */
    bool IsConnected(void) const { return mTls.IsConnected(); }

    /**
     * This method stops the TLS connection.
     *
     */
    void Disconnect(void) { mTls.Disconnect(); }

    /**
     * This method sets the PSK.
     *
     * @param[in]  aPsk        A pointer to the PSK.
     * @param[in]  aPskLength  The PSK length.
     *
     * @retval kErrorNone         Successfully set the PSK.
     * @retval kErrorInvalidArgs  The PSK is invalid.
     *
     */
    Error SetPsk(const uint8_t *aPsk, uint8_t aPskLength) { return mTls.SetPsk(aPsk, aPskLength); }

    /**
     * This method sets the PSK.
     *
     * @param[in]  aPskd  A Joiner PSKd.
     *
     */
    void SetPsk(const MeshCoP::JoinerPskd &aPskd);

#ifdef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
    /**
     * This method sets the Pre-Shared Key (PSK) for TLS sessions identified by a PSK.
     *
     * TLS mode "TLS with AES 128 CCM 8" for secure Ble.
     *
     * @param[in]  aPsk          A pointer to the PSK.
     * @param[in]  aPskLength    The PSK char length.
     * @param[in]  aPskIdentity  The Identity Name for the PSK.
     * @param[in]  aPskIdLength  The PSK Identity Length.
     *
     */
    void SetPreSharedKey(const uint8_t *aPsk, uint16_t aPskLength, const uint8_t *aPskIdentity, uint16_t aPskIdLength)
    {
        mTls.SetPreSharedKey(aPsk, aPskLength, aPskIdentity, aPskIdLength);
    }
#endif // MBEDTLS_KEY_EXCHANGE_PSK_ENABLED

#ifdef MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    /**
     * This method sets a X509 certificate with corresponding private key for TLS session.
     *
     * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure Ble.
     *
     * @param[in]  aX509Cert          A pointer to the PEM formatted X509 PEM certificate.
     * @param[in]  aX509Length        The length of certificate.
     * @param[in]  aPrivateKey        A pointer to the PEM formatted private key.
     * @param[in]  aPrivateKeyLength  The length of the private key.
     *
     */
    void SetCertificate(const uint8_t *aX509Cert,
                        uint32_t       aX509Length,
                        const uint8_t *aPrivateKey,
                        uint32_t       aPrivateKeyLength)
    {
        mTls.SetCertificate(aX509Cert, aX509Length, aPrivateKey, aPrivateKeyLength);
    }

    /**
     * This method sets the trusted top level CAs. It is needed for validate the certificate of the peer.
     *
     * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure Ble.
     *
     * @param[in]  aX509CaCertificateChain  A pointer to the PEM formatted X509 CA chain.
     * @param[in]  aX509CaCertChainLength   The length of chain.
     *
     */
    void SetCaCertificateChain(const uint8_t *aX509CaCertificateChain, uint32_t aX509CaCertChainLength)
    {
        mTls.SetCaCertificateChain(aX509CaCertificateChain, aX509CaCertChainLength);
    }
#endif // MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

#if defined(MBEDTLS_BASE64_C) && defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    /**
     * This method returns the peer x509 certificate base64 encoded.
     *
     * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure Ble.
     *
     * @param[out]  aPeerCert        A pointer to the base64 encoded certificate buffer.
     * @param[out]  aCertLength      The length of the base64 encoded peer certificate.
     * @param[in]   aCertBufferSize  The buffer size of aPeerCert.
     *
     * @retval kErrorNone    Successfully get the peer certificate.
     * @retval kErrorNoBufs  Can't allocate memory for certificate.
     *
     */
    Error GetPeerCertificateBase64(unsigned char *aPeerCert, size_t *aCertLength, size_t aCertBufferSize)
    {
        return mTls.GetPeerCertificateBase64(aPeerCert, aCertLength, aCertBufferSize);
    }
#endif // defined(MBEDTLS_BASE64_C) && defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)

    /**
     * This method sets the connected callback to indicate, when a client connected to the Ble Secure server.
     *
     * @param[in]  aCallback     A pointer to a function that will be called once TLS connection is established.
     * @param[in]  aContext      A pointer to arbitrary context information.
     *
     */
    void SetClientConnectedCallback(ConnectedCallback aCallback, void *aContext)
    {
        mConnectedCallback = aCallback;
        mConnectedContext  = aContext;
    }

    /**
     * This method sets the authentication mode for the Ble secure connection. It disables or enables the verification
     * of peer certificate.
     *
     * @param[in]  aVerifyPeerCertificate  true, if the peer certificate should be verified
     *
     */
    void SetSslAuthMode(bool aVerifyPeerCertificate) { mTls.SetSslAuthMode(aVerifyPeerCertificate); }

    /**
     * This method sends a Ble message over secure TLS connection.
     *
     * @param[in]  aMessage        A reference to the message to send.
     *
     * @retval kErrorNone          Successfully sent Ble message.
     * @retval kErrorNoBufs        Failed to allocate retransmission data.
     * @retval kErrorInvalidState  TLS connection was not initialized.
     *
     */
    Error SendMessage(Message &aMessage);

    /**
     * This method sends a Ble data packet over secure TLS connection.
     *
     * @param[in]  aBuf            A pointer to the data to send.
     * @param[in]  aLength         A number indicationg the lenght of the data buffer.
     *
     * @retval kErrorNone          Successfully sent Ble message.
     * @retval kErrorNoBufs        Failed to allocate retransmission data.
     * @retval kErrorInvalidState  TLS connection was not initialized.
     *
     */
    Error Send(uint8_t *aBuf, uint16_t aLength);

    /**
     * This method is used to pass data received over a Ble link to the secure Ble server.
     *
     * @param[in]  aBuf            A pointer to the data received.
     * @param[in]  aLength         A number indicationg the lenght of the data buffer.
     *
     */
    Error HandleBleReceive(uint8_t *aBuf, uint16_t aLength);

private:
    static constexpr uint8_t kPacketBufferSize  = 20; 
    static constexpr uint8_t kMaxPacketSize     = 20;    // MTU size - 3 or less (const for now)  
    
    static void HandleTlsConnected(void *aContext, bool aConnected);
    void        HandleTlsConnected(bool aConnected);

    static void HandleTlsReceive(void *aContext, uint8_t *aBuf, uint16_t aLength);
    void        HandleTlsReceive(uint8_t *aBuf, uint16_t aLength);

    static void HandleTransmit(Tasklet &aTasklet);
    void        HandleTransmit(void);

    static Error HandleTransport(void *aContext, ot::Message &aMessage, const Ip6::MessageInfo &aMessageInfo);
    Error        HandleTransport(ot::Message &aMessage);

    MeshCoP::Dtls     mTls;
    ReceiveCallback   mReceiveCallback;
    void *            mReceiveContext;
    bool              mLineMode;
    ConnectedCallback mConnectedCallback;
    void *            mConnectedContext;
    ot::MessageQueue  mTransmitQueue;
    TaskletContext    mTransmitTask;
    uint8_t           mPacketBuffer[kPacketBufferSize];
    uint16_t          mHandle;
};

} // namespace Ble
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_SECURE_ENABLE

#endif // BLE_SECURE_HPP_
