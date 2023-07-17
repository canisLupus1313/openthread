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

#if OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#include <openthread/ble_secure.h>

#include "meshcop/dtls.hpp"
#include "meshcop/meshcop.hpp"
#include "meshcop/tcat_agent.hpp"

//#include <openthread/ble_secure.h>

/**
 * @file
 *   This file includes definitions for the secure BLE agent.
 */

namespace ot {

namespace Ble {

class BleSecure : public InstanceLocator, private NonCopyable
{
public:
    /**
     * This function pointer is called when the secure BLE connection state changes.
     *
     *  Please see otHandleBleSecureConnect for details.
     *
     */
    typedef otHandleBleSecureConnect ConnectCallback;

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
     * This method starts the secure BLE agent.
     *
     * @retval kErrorNone       Successfully started the BLE agent.
     * @retval kErrorAlready    Already started.
     *
     */
    Error Start(ConnectCallback aConnectHandler, ReceiveCallback aReceiveHandler, bool aTlvMode, void *aContext);

    /**
     * Enables the TCAT protocol over BLE Secure.
     *
     * @retval kErrorNone           Successfully started the BLE Secure Joiner role.
     * @retval kErrorInvalidArgs    The aVendorInfo is invalid.
     * @retval kErrorInvaidState    The BLE function has not been started or line mode is not selected.
     *
     */
    Error TcatStart(MeshCoP::TcatAgent::VendorInfo  *aVendorInfo,
                    MeshCoP::TcatAgent::JoinCallback aHandler);

    /**
     * This method stops the secure BLE agent.
     *
     */
    void Stop(void);

    /**
     * This method initializes TLS session with a peer using an already open BLE connection.
     *
     * @retval kErrorNone  Successfully started TLS connection.
     *
     */
    Error Connect();

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
     * This method indicates whether or not the TCAT agent is enabled.
     *
     * @retval TRUE   The TCAT agent is enabled.
     * @retval FALSE  The TCAT agent is not enabled.
     *
     */
    bool IsTcatEnabled(void) const { return mTcatAgent.IsEnabled(); }

    /**
     * This method indicates whether or not the TCAT session has verified the commissioner is in possesion of PSKd.
     *
     * @retval TRUE   The TCAT session has verified PSKd.
     * @retval FALSE  The TCAT session does not verified PSKd.
     *
     */
    bool IsPskdVerified(void) const { return mTcatAgent.IsPskdVerified(); }

    /**
     * This method indicates whether or not the TCAT session has verified the commissioner is in possesion of PSKc.
     *
     * @retval TRUE   The TCAT session has verified PSKc.
     * @retval FALSE  The TCAT session does not verified PSKc.
     *
     */
    bool IsPskcVerified(void) const { return mTcatAgent.IsPskcVerified(); }

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
     * TLS mode "TLS with AES 128 CCM 8" for secure BLE.
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
     * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure BLE.
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
     * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure BLE.
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
     * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure BLE.
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

#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    /**
     * This method returns an attribute value identified by its OID from the subject
     * of the peer x509 certificate. The peer OID is provided in binary format.
     * The attribute length is set if the attribute was successfully read or zero
     * if unsuccessful. The ANS1 type as is set as defineded in the ITU-T X.690 standard
     * if the attribute was successfully read.
     *
     * @param[in]   aOid                  A pointer to the OID to be found.
     * @param[in]   aOidLength            The length of the OID.
     * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
     * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
     * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
     * @param[out]  aAns1Type             A pointer to the ANS1 type of the attribute written to the buffer.
     *
     * @retval kErrorInvalidState   Not connected yet.
     * @retval kErrorNone           Successfully read attribute.
     * @retval kErrorNoBufs         Insufficient memory for storing the attribute value.
     *
     */
    Error GetPeerSubjectAttributeByOid(const char    *aOid,
                                       size_t         aOidLength,
                                       unsigned char *aAttributeBuffer,
                                       size_t        *aAttributeLength,
                                       size_t         aAttributeBufferSize,
                                       int           *aAns1Type)
    {
        return mTls.GetPeerSubjectAttributeByOid(aOid, aOidLength, aAttributeBuffer, aAttributeLength,
                                                 aAttributeBufferSize, aAns1Type);
    }

    /**
     * This method returns an attribute value for the OID 1.3.6.1.4.1.44970.x from the v3 extensions of
     * the peer x509 certificate, where the last digit x is set to aThreadOidDescriptor.
     * The attribute length is set if the attribute was successfully read or zero if unsuccessful.
     * This method requires a connection to be active.
     *
     * @param[in]   aThreadOidDescriptor  The last digit of the Thread attribute OID.
     * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
     * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
     * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
     *
     * @retval kErrorNone             Successfully read attribute.
     * @retval kErrorNotFound         The requested attribute was not found.
     * @retval kErrorNoBufs           Insufficient memory for storing the attribute value.
     * @retval kErrorInvalidState     Not connected yet.
     * @retval kErrorNotImplemented   The value of aThreadOidDescriptor is >127.
     * @retval kErrorParse            The certificate extensions could not be parsed.
     *
     */
    Error GetThreadAttributeFromPeerCertificate(int            aThreadOidDescriptor,
                                                unsigned char *aAttributeBuffer,
                                                size_t        *aAttributeLength,
                                                size_t         aAttributeBufferSize)
    {
        return mTls.GetThreadAttributeFromPeerCertificate(aThreadOidDescriptor, aAttributeBuffer, aAttributeLength,
                                                          aAttributeBufferSize);
    }
#endif // defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)

    /**
     * This method returns an attribute value for the OID 1.3.6.1.4.1.44970.x from the v3 extensions of
     * the own x509 certificate, where the last digit x is set to aThreadOidDescriptor.
     * The attribute length is set if the attribute was successfully read or zero if unsuccessful.
     * This method requires a connection to be active.
     *
     * @param[in]   aThreadOidDescriptor  The last digit of the Thread attribute OID.
     * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
     * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
     * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
     *
     * @retval kErrorNone             Successfully read attribute.
     * @retval kErrorNotFound         The requested attribute was not found.
     * @retval kErrorNoBufs           Insufficient memory for storing the attribute value.
     * @retval kErrorInvalidState     Not connected yet.
     * @retval kErrorNotImplemented   The value of aThreadOidDescriptor is >127.
     * @retval kErrorParse            The certificate extensions could not be parsed.
     *
     */
    Error GetThreadAttributeFromOwnCertificate(int            aThreadOidDescriptor,
                                               unsigned char *aAttributeBuffer,
                                               size_t        *aAttributeLength,
                                               size_t         aAttributeBufferSize)
    {
        return mTls.GetThreadAttributeFromOwnCertificate(aThreadOidDescriptor, aAttributeBuffer, aAttributeLength,
                                                         aAttributeBufferSize);
    }

    /**
     * This method returns an attribute value for the OID 1.3.6.1.4.1.44970.x from the v3 extensions of
     * the CA x509 certificate chain, where the last digit x is set to aThreadOidDescriptor.
     * The attribute length is set if the attribute was successfully read or zero if unsuccessful.
     * This method requires a connection to be active.
     *
     * @param[in]   aThreadOidDescriptor  The last digit of the Thread attribute OID.
     * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
     * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
     * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
     *
     * @retval kErrorNone             Successfully read attribute.
     * @retval kErrorNotFound         The requested attribute was not found.
     * @retval kErrorNoBufs           Insufficient memory for storing the attribute value.
     * @retval kErrorInvalidState     Not connected yet.
     * @retval kErrorNotImplemented   The value of aThreadOidDescriptor is >127.
     * @retval kErrorParse            The certificate extensions could not be parsed.
     *
     */
    Error GetThreadAttributeFromCaCertificateChain(int            aThreadOidDescriptor,
                                                   unsigned char *aAttributeBuffer,
                                                   size_t        *aAttributeLength,
                                                   size_t         aAttributeBufferSize)
    {
        return mTls.GetThreadAttributeFromCaCertificateChain(aThreadOidDescriptor, aAttributeBuffer, aAttributeLength,
                                                             aAttributeBufferSize);
    }

    /**
     * This method sets the authentication mode for the BLE secure connection. It disables or enables the verification
     * of peer certificate.
     *
     * @param[in]  aVerifyPeerCertificate  true, if the peer certificate should be verified
     *
     */
    void SetSslAuthMode(bool aVerifyPeerCertificate) { mTls.SetSslAuthMode(aVerifyPeerCertificate); }

    /**
     * This method sends a secure BLE message.
     *
     * @param[in]  aMessage        A pointer to the message to send.
     *
     * If the return value is kErrorNone, OpenThread takes ownership of @p aMessage, and the caller should no longer
     * reference @p aMessage. If the return value is not kErrorNone, the caller retains ownership of @p aMessage,
     * including freeing @p aMessage if the message buffer is no longer needed.
     *
     * @retval kErrorNone          Successfully sent message.
     * @retval kErrorNoBufs        Failed to allocate buffer memory.
     * @retval kErrorInvalidState  TLS connection was not initialized.
     *
     */
    Error SendMessage(Message *aMessage);

    /**
     * This method sends a secure BLE data packet.
     *
     * @param[in]  aBuf            A pointer to the data to send.
     * @param[in]  aLength         A number indicating the length of the data buffer.
     *
     * @retval kErrorNone          Successfully sent data.
     * @retval kErrorNoBufs        Failed to allocate buffer memory.
     * @retval kErrorInvalidState  TLS connection was not initialized.
     *
     */
    Error Send(uint8_t *aBuf, uint16_t aLength);

    /**
     * This method sends a secure BLE data packet containing a TCAT application TLV.
     *
     * @param[in]  aBuf            A pointer to the data to send.
     * @param[in]  aLength         A number indicating the length of the data buffer.
     *
     * @retval kErrorNone          Successfully sent data.
     * @retval kErrorNoBufs        Failed to allocate buffer memory.
     * @retval kErrorInvalidState  TLS connection was not initialized.
     *
     */
    Error SendApplicationTlv(uint8_t *aBuf, uint16_t aLength);

    /**
     * This method sends all remaining bytes in the send buffer.
     *
     * @retval kErrorNone          Successfully enqueued data into the output interface.
     * @retval kErrorNoBufs        Failed to allocate buffer memory.
     * @retval kErrorInvalidState  TLS connection was not initialized.
     *
     */
    Error Flush();

    /**
     * This method is used to pass data received over a BLE link to the secure BLE server.
     *
     * @param[in]  aBuf            A pointer to the data received.
     * @param[in]  aLength         A number indicating the length of the data buffer.
     *
     */
    Error HandleBleReceive(uint8_t *aBuf, uint16_t aLength);

    /**
     * This method is used to notify the secure BLE server that a BLE Device has been connected.
     *
     * @param[in]  aConnectionId    The identifier of the open connection.
     *
     */
    Error HandleBleConnected(uint16_t aConnectionId);

    /**
     * This method is used to notify the secure BLE server that the BLE Device has been disconnected.
     *
     * @param[in]  aConnectionId    The identifier of the open connection.
     *
     */
    Error HandleBleDisconnected(uint16_t aConnectionId);

private:
    static constexpr uint8_t  kInitialMtuSize   = 23; // ATT_MTU
    static constexpr uint8_t  kGattOverhead     = 3;  // BLE GATT payload fits MTU size - 3 bytes
    static constexpr uint8_t  kPacketBufferSize = 64; // must be >= kInitialMtuSize - kGattOverhead
    static constexpr uint16_t kTxBleHandle      = 0;  // Characteristics Handle for TX (not used)
    static constexpr uint16_t kFlushThreshold =
        256; // mSentMessage length exceeding this threshold triggers flushing the buffer

    static void HandleTlsConnected(void *aContext, bool aConnected);
    void        HandleTlsConnected(bool aConnected);

    static void HandleTlsReceive(void *aContext, uint8_t *aBuf, uint16_t aLength);
    void        HandleTlsReceive(uint8_t *aBuf, uint16_t aLength);

    static void HandleTransmit(Tasklet &aTasklet);
    void        HandleTransmit(void);

    static Error HandleTransport(void *aContext, ot::Message &aMessage, const Ip6::MessageInfo &aMessageInfo);
    Error        HandleTransport(ot::Message &aMessage);

    MeshCoP::Dtls               mTls;
    MeshCoP::TcatAgent          mTcatAgent;
    Callback<ConnectCallback>   mConnectCallback;
    Callback<ReceiveCallback>   mReceiveCallback;
    bool                        mTlvMode;
    ot::Message*                mReceivedMessage;
    ot::Message*                mSentMessage;
    ot::MessageQueue            mTransmitQueue;
    TaskletContext              mTransmitTask;
    uint8_t                     mPacketBuffer[kPacketBufferSize];
    bool                        mBleConnectionOpen;
    uint16_t                    mMtuSize;
};

} // namespace Ble
} // namespace ot

#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE

#endif // BLE_SECURE_HPP_
