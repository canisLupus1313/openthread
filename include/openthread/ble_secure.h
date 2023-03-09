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
 *   The functions in this module require the build-time feature `OPENTHREAD_CONFIG_BLE_SECURE_ENABLE=1`.
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
 *   (`OPENTHREAD_CONFIG_BLE_SECURE_ENABLE`) is enabled.
 *
 * @{
 *
 */

/**
 * This function pointer is called when the TLS connection state changes.
 *
 * @param[in]  aConnected       true, if a connection was established, false otherwise.
 * @param[in]  aContext         A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleBleSecureClientConnect)(bool aConnected, void *aContext);

/**
 * This function pointer is called when data was received over the TLS connection.
 *
 * @param[in]  aMessage         A pointer to the message.
 * @param[in]  aContext         A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleBleSecureReceive)(otMessage *aMessage, void *aContext);


/**
 * This function starts the BLE Secure service.
 *
 * @param[in]  aInstance        A pointer to an OpenThread instance.
 * @param[in]  aHandler         A pointer to a function that will be called once data has been receoved over the TLS connection.
 * @param[in]  aLineMode        A boolean value indicating if line mode shall be activated.
 * @param[in]  aContext         A pointer to arbitrary context information. May be NULL if not used.
 *
 * @retval OT_ERROR_NONE        Successfully started the BLE Secure server.
 * @retval OT_ERROR_ALREADY     The service was stated already.
 *
 */
otError otBleSecureStart(otInstance *             aInstance,
                         otHandleBleSecureReceive aHandler,
                         bool                     aLineMode,
                         void *                   aContext);

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
void otBleSecureSetPsk(otInstance *   aInstance,
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
otError otBleSecureGetPeerCertificateBase64(otInstance *   aInstance,
                                            unsigned char *aPeerCert,
                                            size_t *       aCertLength,
                                            size_t         aCertBufferSize);

/**
 * This method sets the connected callback to indicate, when
 * a client connected to the BLE Secure server.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 * @param[in]  aHandler      A pointer to a function that will be called once TLS connection is established.
 * @param[in]  aContext      A pointer to arbitrary context information. May be NULL if not used.
 *
 */
void otBleSecureSetClientConnectedCallback(otInstance *                   aInstance,
                                           otHandleBleSecureClientConnect aHandler,
                                           void *                         aContext);

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
void otBleSecureSetSslAuthMode(otInstance   *aInstance, 
                               bool          aVerifyPeerCertificate);

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
void otBleSecureSetCertificate(otInstance *   aInstance,
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
void otBleSecureSetCaCertificateChain(otInstance *   aInstance,
                                      const uint8_t *aX509CaCertificateChain,
                                      uint32_t       aX509CaCertChainLength);

/**
 * This method initializes TLS session with a peer.
 *
 * @param[in]  aInstance               A pointer to an OpenThread instance.
 * @param[in]  aHandler                A pointer to a function that will be called when the TLS connection
 *                                     state changes.
 * @param[in]  aContext                A pointer to arbitrary context information.
 *
 * @retval OT_ERROR_NONE  Successfully started TLS connection.
 *
 */
otError otBleSecureConnect(otInstance *                    aInstance,
                           otHandleBleSecureClientConnect  aHandler,
                           void *                          aContext);

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
 * This method sends a BLE message over secure TLS connection.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 * @param[in]  aMessage      A reference to the message to send.
 *
 * @retval OT_ERROR_NONE           Successfully sent BLE message.
 * @retval OT_ERROR_NO_BUFS        Failed to allocate retransmission data.
 * @retval OT_ERROR_INVALID_STATE  TLS connection was not initialized.
 *
 */
otError otBleSecureSendMessage(otInstance *aInstance, otMessage *aMessage);

/**
 * This method sends a BLE data packet over secure TLS connection.
 *
 * @param[in]  aInstance     A pointer to an OpenThread instance.
 * @param[in]  aBuf          A pointer to the data to send.
 * @param[in]  aLength       A number indicationg the lenght of the data buffer.
 *
 * @retval OT_ERROR_NONE           Successfully sent BLE message.
 * @retval OT_ERROR_NO_BUFS        Failed to allocate retransmission data.
 * @retval OT_ERROR_INVALID_STATE  TLS connection was not initialized.
 *
 */
otError otBleSecureSend(otInstance *aInstance, uint8_t *aBuf, uint16_t aLength);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OPENTHREAD_BLE_SECURE_H_ */
