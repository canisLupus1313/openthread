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
 * @brief
 *  This file defines the top-level functions for the OpenThread BLE Secure implementation.
 *
 *  @note
 *   The functions in this module require the build-time feature `OPENTHREAD_CONFIG_BLE_TCAT_ENABLE=1`.
 *
 *  @note
 *   To enable cipher suite DTLS_PSK_WITH_AES_128_CCM_8, MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
 *    must be enabled in mbedtls-config.h
 *   To enable cipher suite DTLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
 *    MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED must be enabled in mbedtls-config.h.
 */

#ifndef OPENTHREAD_BLE_SECURE_H_
#define OPENTHREAD_BLE_SECURE_H_

#include <stdint.h>
#include <openthread/message.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-ble-secure
 *
 * @brief
 *   This module includes functions that control BLE Secure (TLS over BLE) communication.
 *
 *   The functions in this module are available when BLE Secure API feature
 *   (`OPENTHREAD_CONFIG_BLE_TCAT_ENABLE`) is enabled.
 *
 * @{
 *
 */

#define OT_TCAT_ELEVATION_PSK_LENGTH \
    32 ///< Maximum string length of a secure BLE elevation PSK (does not include null char).

/**
 * This enumeration represents TCAT TLV types.
 *
 */
typedef enum otTcatTlvType
{
    OT_TCAT_TLV_COMMAND        = 0,  ///< TCAT Command TLV
    OT_TCAT_TLV_RESPONSE       = 1,  ///< TCAT Response TLV
    OT_TCAT_TLV_ACTIVE_DATASET = 16, ///< TCAT Active Dataset TLV
    OT_TCAT_TLV_APPLICATION    = 18, ///< TCAT Application TLV

} otTcatTlvType;

/**
 * This enumeration represents TCAT Command types.
 *
 */
typedef enum otTcatCommandType
{
    OT_TCAT_COMMAND_TERMINATE    = 0, ///< Terminate connection
    OT_TCAT_COMMAND_THREAD_START = 1, ///< Start Thread Interface
    OT_TCAT_COMMAND_THREAD_STOP  = 2, ///< Stop Thread Interface

} otTcatCommandType;

/**
 * This enumeration represents TCAT Command types.
 *
 */
typedef enum otTcatResponseType
{
    OT_TCAT_RESPONSE_SUCCESS       = 0, ///< Success
    OT_TCAT_RESPONSE_INVALID_STATE = 1, ///< Invalid State
    OT_TCAT_RESPONSE_PARSE_ERROR   = 2, ///< Invalid State

} otTcatResponseType;

/**
 * This structure represents a TCAT vendor information.
 *
 */
typedef struct otTcatVendorInfo
{
    const char *mProvisioningUrl; ///< Provisioning URL path string
    const char *mVendorName;      ///< Vendor name string
    const char *mVendorModel;     ///< Vendor model string
    const char *mVendorSwVersion; ///< Venor softwae version string
    const char *mVendorData;      ///< Vendor stpecific data string
} otTcatVendorInfo;

/**
 * This structure represents a TCAT elevation PSKd.
 *
 */
typedef struct otTcatElevationPsk
{
    char m8[OT_TCAT_ELEVATION_PSK_LENGTH + 1]; ///< Char string array (must be null terminated - +1 is for null char).
} otTcatElevationPsk;

/**
 * This function pointer is called to notify the completion of a join operation.
 *
 * @param[in]  aInstance            A pointer to an OpenThread instance.
 * @param[in]  aError           OT_ERROR_NONE if the join process succeeded.
 *                              OT_ERROR_SECURITY if the join process failed due to security credentials.
 *
 * @param[in]  aContext         A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleTcatJoin)(otError aError, void *aContext);

/**
 * This function pointer is called when the secure BLE connection state changes.
 *
 * @param[in]  aInstance            A pointer to an OpenThread instance.
 * @param[in]  aConnected           TRUE, if a secure connection was established, FALSE otherwise.
 * @param[in]  aBleConnectionOpen   TRUE if a BLE connection was established to carry a TLS data stream, FALSE
 *                                  otherwise.
 * @param[in]  aContext             A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleBleSecureConnect)(otInstance *aInstance, bool aConnected, bool aBleConnectionOpen, void *aContext);

/**
 * This function pointer is called when data was received over the TLS connection.
 * When TLV mode is activate, the function will be called once a complete TLV was received and the
 * message offset points to the TLV value.
 *
 *
 * @param[in]  aMessage         A pointer to the message.
 * @param[in]  aContext         A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleBleSecureReceive)(otInstance *aInstance, otMessage *aMessage, void *aContext);

/**
 * This function starts the BLE Secure service.
 * When TLV mode is activate, the function will be called once a complete TLV was received and the
 * message offset points to the TLV value.
 *
 * @param[in]  aInstance        A pointer to an OpenThread instance.
 * @param[in]  aConnectHandler  A pointer to a function that will be called when the connection
 *                              state changes.
 * @param[in]  aReceiveHandler  A pointer to a function that will be called once data has been received
 *                              over the TLS connection.
 * @param[in]  aTlvMode         A boolean value indicating if line mode shall be activated.
 * @param[in]  aContext         A pointer to arbitrary context information. May be NULL if not used.
 *
 * @retval OT_ERROR_NONE        Successfully started the BLE Secure server.
 * @retval OT_ERROR_ALREADY     The service was stated already.
 *
 */
otError otBleSecureStart(otInstance              *aInstance,
                         otHandleBleSecureConnect aConnectHandler,
                         otHandleBleSecureReceive aReceiveHandler,
                         bool                     aTlvMode,
                         void                    *aContext);

/**
 * Enables the TCAT protocol over BLE Secure.
 *
 * @param[in]  aInstance         A pointer to an OpenThread instance.
 * @param[in]  aElevationPsk     A pointer to the PSK for elevating the commissioner rights (may be NULL).
 * @param[in]  aVendorInfo       A pointer to the Vendor Information (must remain valid after the method call, may be
 * NULL).
 * @param[in]  aHandler          A pointer to a function that is called when the join operation completes.
 *
 * @retval OT_ERROR_NONE              Successfully started the BLE Secure Joiner role.
 * @retval OT_ERROR_INVALID_ARGS      @p aElevationPsk or @p aVendorInfo is invalid.
 * @retval OT_ERROR_INVALID_STATE     The BLE function has not been started or line mode is not selected.
 *
 */
otError otBleSecureTcatStart(otInstance       *aInstance,
                             const char       *aElevationPsk,
                             otTcatVendorInfo *aVendorInfo,
                             otHandleTcatJoin  aHandler);

/**
 * This function stops the BLE Secure server.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 */
void otBleSecureStop(otInstance *aInstance);

/**
 * This method sets the Pre-Shared Key (PSK) and cipher suite
 * TLS_PSK_WITH_AES_128_CCM_8.
 *
 * @note This function requires the build-time feature `MBEDTLS_KEY_EXCHANGE_PSK_ENABLED` to be enabled.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 * @param[in]  aPsk          A pointer to the PSK.
 * @param[in]  aPskLength    The PSK length.
 * @param[in]  aPskIdentity  The Identity Name for the PSK.
 * @param[in]  aPskIdLength  The PSK Identity Length.
 *
 */
void otBleSecureSetPsk(otInstance    *aInstance,
                       const uint8_t *aPsk,
                       uint16_t       aPskLength,
                       const uint8_t *aPskIdentity,
                       uint16_t       aPskIdLength);

/**
 * This method returns the peer x509 certificate base64 encoded.
 *
 * @note This function requires the build-time features `MBEDTLS_BASE64_C` and
 *       `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` to be enabled.
 *
 * @param[in]   aInstance        A pointer to an OpenThread instance.
 * @param[out]  aPeerCert        A pointer to the base64 encoded certificate buffer.
 * @param[out]  aCertLength      The length of the base64 encoded peer certificate.
 * @param[in]   aCertBufferSize  The buffer size of aPeerCert.
 *
 * @retval OT_ERROR_INVALID_STATE   Not connected yet.
 * @retval OT_ERROR_NONE            Successfully get the peer certificate.
 * @retval OT_ERROR_NO_BUFS         Can't allocate memory for certificate.
 *
 */
otError otBleSecureGetPeerCertificateBase64(otInstance    *aInstance,
                                            unsigned char *aPeerCert,
                                            size_t        *aCertLength,
                                            size_t         aCertBufferSize);

/**
 * This method returns an attribute value identified by its OID from the subject
 * of the peer x509 certificate. The peer OID is provided in binary format.
 * The attribute length is set if the attribute was successfully read or zero
 * if unsuccessful. The ANS1 type as is set as defineded in the ITU-T X.690 standard
 * if the attribute was successfully read.
 *
 * @note This function requires the build-time feature
 *       `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` to be enabled.
 *
 * @param[in]   aInstance             A pointer to an OpenThread instance.
 * @param[in]   aOid                  A pointer to the OID to be found.
 * @param[in]   aOidLength            The length of the OID.
 * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
 * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
 * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
 * @param[out]  aAns1Type             A pointer to the ANS1 type of the attribute written to the buffer.
 *
 * @retval OT_ERROR_INVALID_STATE   Not connected yet.
 * @retval OT_ERROR_NONE            Successfully read attribute.
 * @retval OT_ERROR_NO_BUFS         Insufficient memory for storing the attribute value.
 *
 */
otError otBleSecureGetPeerSubjectAttributeByOid(otInstance    *aInstance,
                                                const char    *aOid,
                                                size_t         aOidLength,
                                                unsigned char *aAttributeBuffer,
                                                size_t        *aAttributeLength,
                                                size_t         aAttributeBufferSize,
                                                int           *aAns1Type);

/**
 * This method returns an attribute value for the OID 1.3.6.1.4.1.44970.x from the v3 extensions of
 * the peer x509 certificate, where the last digit x is set to aThreadOidDescriptor.
 * The attribute length is set if the attribute was successfully read or zero if unsuccessful.
 * This method requires a connection to be active.
 *
 * @note This function requires the build-time feature
 *       `MBEDTLS_SSL_KEEP_PEER_CERTIFICATE` to be enabled.
 *
 * @param[in]   aInstance             A pointer to an OpenThread instance.
 * @param[in]   aThreadOidDescriptor  The last digit of the Thread attribute OID.
 * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
 * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
 * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
 *
 * @retval OT_ERROR_NONE             Successfully read attribute.
 * @retval OT_NOT_FOUND              The requested attribute was not found.
 * @retval OT_ERROR_NO_BUFS          Insufficient memory for storing the attribute value.
 * @retval OT_ERROR_INVALID_STATE    Not connected yet.
 * @retval OT_ERROR_NOT_IMPLEMENTED  The value of aThreadOidDescriptor is >127.
 * @retval OT_ERROR_PARSE            The certificate extensions could not be parsed.
 *
 */
otError otBleSecureGetThreadAttributeFromPeerCertificate(otInstance    *aInstance,
                                                         int            aThreadOidDescriptor,
                                                         unsigned char *aAttributeBuffer,
                                                         size_t        *aAttributeLength,
                                                         size_t         aAttributeBufferSize);

/**
 * This method returns an attribute value for the OID 1.3.6.1.4.1.44970.x from the v3 extensions of
 * the own x509 certificate, where the last digit x is set to aThreadOidDescriptor.
 * The attribute length is set if the attribute was successfully read or zero if unsuccessful.
 * This method requires a connection to be active.
 *
 * @param[in]   aInstance             A pointer to an OpenThread instance.
 * @param[in]   aThreadOidDescriptor  The last digit of the Thread attribute OID.
 * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
 * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
 * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
 *
 * @retval OT_ERROR_NONE             Successfully read attribute.
 * @retval OT_NOT_FOUND              The requested attribute was not found.
 * @retval OT_ERROR_NO_BUFS          Insufficient memory for storing the attribute value.
 * @retval OT_ERROR_INVALID_STATE    Not connected yet.
 * @retval OT_ERROR_NOT_IMPLEMENTED  The value of aThreadOidDescriptor is >127.
 * @retval OT_ERROR_PARSE            The certificate extensions could not be parsed.
 *
 */
otError otBleSecureGetThreadAttributeFromOwnCertificate(otInstance    *aInstance,
                                                        int            aThreadOidDescriptor,
                                                        unsigned char *aAttributeBuffer,
                                                        size_t        *aAttributeLength,
                                                        size_t         aAttributeBufferSize);

/**
 * This method returns an attribute value for the OID 1.3.6.1.4.1.44970.x from the v3 extensions of
 * the CA x509 certificate chain, where the last digit x is set to aThreadOidDescriptor.
 * The attribute length is set if the attribute was successfully read or zero if unsuccessful.
 * This method requires a connection to be active.
 *
 * @param[in]   aInstance             A pointer to an OpenThread instance.
 * @param[in]   aThreadOidDescriptor  The last digit of the Thread attribute OID.
 * @param[out]  aAttributeBuffer      A pointer to the attribute buffer.
 * @param[out]  aAttributeLength      A pointer to the length of the attribute written to the buffer.
 * @param[in]   aAttributeBufferSize  The buffer size of aAttributeBuffer.
 *
 * @retval OT_ERROR_NONE             Successfully read attribute.
 * @retval OT_NOT_FOUND              The requested attribute was not found.
 * @retval OT_ERROR_NO_BUFS          Insufficient memory for storing the attribute value.
 * @retval OT_ERROR_INVALID_STATE    Not connected yet.
 * @retval OT_ERROR_NOT_IMPLEMENTED  The value of aThreadOidDescriptor is >127.
 * @retval OT_ERROR_PARSE            The certificate extensions could not be parsed.
 *
 */
otError otBleSecureGetThreadAttributeFromCaCertificateChain(otInstance    *aInstance,
                                                            int            aThreadOidDescriptor,
                                                            unsigned char *aAttributeBuffer,
                                                            size_t        *aAttributeLength,
                                                            size_t         aAttributeBufferSize);

/**
 * This method sets the authentication mode for the BLE secure connection.
 *
 * Disable or enable the verification of peer certificate.
 * Must be called before start.
 *
 * @param[in]   aInstance               A pointer to an OpenThread instance.
 * @param[in]   aVerifyPeerCertificate  true, to verify the peer certificate.
 *
 */
void otBleSecureSetSslAuthMode(otInstance *aInstance, bool aVerifyPeerCertificate);

/**
 * This method sets the local device's X509 certificate with corresponding private key for
 * TLS session with TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8.
 *
 * @note This function requires `MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED=1`.
 *
 * @param[in]  aInstance          A pointer to an OpenThread instance.
 * @param[in]  aX509Cert          A pointer to the PEM formatted X509 certificate.
 * @param[in]  aX509Length        The length of certificate.
 * @param[in]  aPrivateKey        A pointer to the PEM formatted private key.
 * @param[in]  aPrivateKeyLength  The length of the private key.
 *
 */
void otBleSecureSetCertificate(otInstance    *aInstance,
                               const uint8_t *aX509Cert,
                               uint32_t       aX509Length,
                               const uint8_t *aPrivateKey,
                               uint32_t       aPrivateKeyLength);

/**
 * This method sets the trusted top level CAs. It is needed for validating the
 * certificate of the peer.
 *
 * TLS mode "ECDHE ECDSA with AES 128 CCM 8" for secure BLE.
 *
 * @note This function requires `MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED=1`.
 *
 * @param[in]  aInstance                A pointer to an OpenThread instance.
 * @param[in]  aX509CaCertificateChain  A pointer to the PEM formatted X509 CA chain.
 * @param[in]  aX509CaCertChainLength   The length of chain.
 *
 */
void otBleSecureSetCaCertificateChain(otInstance    *aInstance,
                                      const uint8_t *aX509CaCertificateChain,
                                      uint32_t       aX509CaCertChainLength);

/**
 * This method initializes TLS session with a peer using an already open BLE connection.
 *
 * @param[in]  aInstance               A pointer to an OpenThread instance.
 *
 * @retval OT_ERROR_NONE  Successfully started TLS connection.
 *
 */
otError otBleSecureConnect(otInstance *aInstance);

/**
 * This method stops the TLS connection.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 */
void otBleSecureDisconnect(otInstance *aInstance);

/**
 * This method indicates whether or not the TLS session is connected.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 * @retval TRUE   The TLS session is connected.
 * @retval FALSE  The TLS session is not connected.
 *
 */
bool otBleSecureIsConnected(otInstance *aInstance);

/**
 * This method indicates whether or not the TLS session is active.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 * @retval TRUE  If TLS session is active.
 * @retval FALSE If TLS session is not active.
 *
 */
bool otBleSecureIsConnectionActive(otInstance *aInstance);

/**
 * This method indicates whether or not the commissioner rights have been elevated using elevation PSK.
 *
 * @param[in]  aInstance  A pointer to an OpenThread instance.
 *
 * @retval TRUE  If commissioner rights are elevated.
 * @retval FALSE If commissioner rights are not elevated.
 *
 */
bool otBleSecureIsTcatElevated(otInstance *aInstance);

/**
 * This method indicates whether or not the TCAT agent is enabled.
 *
 * @retval TRUE   The TCAT agent is enabled.
 * @retval FALSE  The TCAT agent is not enabled.
 *
 */
bool otBleSecureIsTcatEnabled(otInstance *aInstance);

/**
 * This method sends a secure BLE message.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 * @param[in]  aMessage      A pointer to the message to send.
 *
 * If the return value is OT_ERROR_NONE, OpenThread takes ownership of @p aMessage, and the caller should no longer
 * reference @p aMessage. If the return value is not OT_ERROR_NONE, the caller retains ownership of @p aMessage,
 * including freeing @p aMessage if the message buffer is no longer needed.
 *
 * @retval OT_ERROR_NONE           Successfully sent message.
 * @retval OT_ERROR_NO_BUFS        Failed to allocate buffer memory.
 * @retval OT_ERROR_INVALID_STATE  TLS connection was not initialized.
 *
 */
otError otBleSecureSendMessage(otInstance *aInstance, otMessage *aMessage);

/**
 * This method sends a secure BLE data packet.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 * @param[in]  aBuf          A pointer to the data to send.
 * @param[in]  aLength       A number indicating the length of the data buffer.
 *
 * @retval OT_ERROR_NONE           Successfully sent data.
 * @retval OT_ERROR_NO_BUFS        Failed to allocate buffer memory.
 * @retval OT_ERROR_INVALID_STATE  TLS connection was not initialized.
 *
 */
otError otBleSecureSend(otInstance *aInstance, uint8_t *aBuf, uint16_t aLength);

/**
 * This method sends a secure BLE data packet containing a TCAT application TLV.
 *
 * @param[in]  aInstance       A pointer to an OpenThread instance.
 * @param[in]  aBuf            A pointer to the data to send.
 * @param[in]  aLength         A number indicating the length of the data buffer.
 *
 * @retval OT_ERROR_NONE           Successfully sent data.
 * @retval OT_ERROR_NO_BUFS        Failed to allocate buffer memory.
 * @retval OT_ERROR_INVALID_STATE  TLS connection was not initialized.
 *
 */
otError otBleSecureSendApplicationTlv(otInstance *aInstance, uint8_t *aBuf, uint16_t aLength);

/**
 * This method flushes the send buffer.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 *
 * @retval OT_ERROR_NONE           Successfully flushed output buffer.
 * @retval OT_ERROR_NO_BUFS        Failed to allocate buffer memory.
 * @retval OT_ERROR_INVALID_STATE  TLS connection was not initialized.
 *
 */
otError otBleSecureFlush(otInstance *aInstance);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OPENTHREAD_BLE_SECURE_H_ */
