/*
 *  Copyright (c) 2023, The OpenThread Authors.
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
 *  This file defines the top-level functions for the OpenThread TCAT.
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

#ifndef OPENTHREAD_TCAT_H_
#define OPENTHREAD_TCAT_H_

#include <stdint.h>
#include <openthread/message.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup api-ble-secure
 *
 * @brief
 *   This module includes functions that implement TCAT communication.
 *
 *   The functions in this module are available when TCAT feature
 *   (`OPENTHREAD_CONFIG_BLE_TCAT_ENABLE`) is enabled.
 *
 * @{
 *
 */

/**
 * This enumeration represents TCAT TLV types.
 *
 */
typedef enum otTcatTlvType
{
    // Command Class General
    OT_TCAT_TLV_COMMAND                         = 0,    ///< TCAT command TLV   -->  !!!! OBSOLETE!!!!
    OT_TCAT_TLV_RESPONSE_WITH_STATUS            = 1,    ///< TCAT response with status value TLV
    OT_TCAT_TLV_RESPONSE_WITH_PAYLOAD           = 2,    ///< TCAT response with payload TLV
    OT_TCAT_TLV_RESPONSE_EVENT                  = 3,    ///< TCAT response event TLV (reserved)
    OT_TCAT_TLV_GET_NETWORK_NAME                = 8,    ///< TCAT network name query TLV
    OT_TCAT_TLV_DISCONNECT                      = 9,    ///< TCAT disconnect request TLV
    OT_TCAT_TLV_PING                            = 10,   ///< TCAT ping request TLV
    OT_TCAT_TLV_GET_DEVICE_ID                   = 11,   ///< TCAT device ID query TLV
    OT_TCAT_TLV_GET_EXTENDED_PAN_ID             = 12,   ///< TCAT extended PAN ID query TLV
    OT_TCAT_TLV_PRESENT_PSKD_HASH               = 30, //16,   ///< TCAT commissioner rights elevation request TLV using PSKd hash
    OT_TCAT_TLV_PRESENT_PSKC_HASH               = 17,   ///< TCAT commissioner rights elevation request TLV using PSKc hash
    OT_TCAT_TLV_PRESENT_INSTALL_CODE_HASH       = 31, //18,   ///< TCAT commissioner rights elevation request TLV using install code
    OT_TCAT_TLV_REQUEST_RANDOM_NUM_CHALLENGE    = 19,   ///< TCAT random number challenge query TLV
    OT_TCAT_TLV_REQUEST_PSKD_HASH               = 20,   ///< TCAT PSKd hash request TLV

    // Command Class Commissioning
    OT_TCAT_TLV_SET_ACTIVE_OPERATIONAL_DATASET  = 16, // 32,   ///< TCAT active operational dataset TLV
    OT_TCAT_TLV_SET_ACTIVE_OPERATIONAL_DATASET1 = 33,   ///< TCAT active operational dataset alterative #1 TLV
    OT_TCAT_TLV_GET_PROVISIONING_TLVS           = 36,   ///< TCAT provisioning TLVs query TLV
    OT_TCAT_TLV_GET_COMMISSIONER_CERTIFICATE    = 37,   ///< TCAT commissioner certificate query TLV
    OT_TCAT_TLV_GET_DIAGNOSTIC_TLVS             = 38,   ///< TCAT diagnostics TLVs query TLV
    OT_TCAT_TLV_START_THREAD_INTERFACE          = 39,   ///< TCAT start thread interface request TLV
    OT_TCAT_TLV_STOP_THREAD_INTERFACE           = 40,   ///< TCAT stop thread interface request TLV

    // Command Class Extraction
    OT_TCAT_TLV_GET_ACTIVE_OPERATIONAL_DATASET  = 48,   ///< TCAT active oerational dataset query TLV
    OT_TCAT_TLV_GET_ACTIVE_OPERATIONAL_DATASET1 = 49,   ///< TCAT active oerational dataset alterative #1 query TLV

    // Command Class Decommissioning
    OT_TCAT_TLV_DECOMMISSION                    = 96,   ///< TCAT decommission request TLV

    // Command Class Application
    OT_TCAT_TLV_SELECT_APPLICATION_LAYER_UDP    = 128,  ///< TCAT select UDP protocol application layer request TLV
    OT_TCAT_TLV_SELECT_APPLICATION_LAYER_TCP    = 129,  ///< TCAT select TCP protocol application layer request TLV
    OT_TCAT_TLV_SEND_APPLICATION_DATA           = 18, //130,  ///< TCAT send application data TLV
    OT_TCAT_TLV_SEND_VENDOR_SPECIFIC_DATA       = 159,  ///< TCAT send vendor specific command or data TLV

    // Command Class CCM
    OT_TCAT_TLV_SET_LDEVID_OPERATIONAL_CERT     = 160,  ///< TCAT LDevID operational certificate TLV
    OT_TCAT_TLV_SET_LDEVID_PRIVATE_KEY          = 161,  ///< TCAT LDevID operational certificate pricate key TLV
    OT_TCAT_TLV_SET_DOMAIN_CA_CERT              = 162,  ///< TCAT domain CA certificate TLV

} otTcatTlvType;

/**
 * This enumeration represents TCAT Command types.    ---> OBSOLETE
 *
 */
typedef enum otTcatCommandType
{
    OT_TCAT_COMMAND_TERMINATE    = 0, ///< Terminate connection
    OT_TCAT_COMMAND_THREAD_START = 1, ///< Start Thread Interface
    OT_TCAT_COMMAND_THREAD_STOP  = 2, ///< Stop Thread Interface

} otTcatCommandType;

/**
 * This enumeration represents TCAT status code.
 *
 */
typedef enum otTcatStatusCode
{
    OT_TCAT_STATUS_SUCCESS                      = 0,    ///< Command or request was successfully processed
    OT_TCAT_STATUS_UNSUPPORTED                  = 1,    ///< Requested command or received TLV is not supported
    OT_TCAT_STATUS_PARSE_ERROR                  = 2,    ///< Request / command could not be parsed correctly
    OT_TCAT_STATUS_VALUE_ERROR                  = 3,    ///< The value of the transmitted TLV has an error
    OT_TCAT_STATUS_GENERAL_ERROR                = 4,    ///< An error not matching any other category occurred
    OT_TCAT_STATUS_BUSY                         = 5,    ///< Command cannot be executed because the resource is busy
    OT_TCAT_STATUS_UNDEFINED                    = 6,    ///< The requested value, data or service is not defined (currently) or not present
    OT_TCAT_STATUS_HASH_ERROR                   = 7,    ///< The hash value presented by the commissioner was incorrect
    OT_TCAT_STATUS_UNAUTHORIZED                 = 8,    ///< Sender does not have sufficient authorization for the given command
    
} otTcatStatusCode;

/**
 * This enumeration represents TCAT status.
 *
 */
typedef enum otTcatMessageType
{
    OT_TCAT_MESSAGE_TYPE_RAW                    = 0,    ///< Message which has been sent without activating the TCAT agent
    OT_TCAT_MESSAGE_TYPE_STATUS                 = 1,    ///< Message contaning a status code (byte) as definded in otTcatStatusCode 
    OT_TCAT_MESSAGE_TYPE_UDP                    = 2,    ///< Message directed to a UDP service
    OT_TCAT_MESSAGE_TYPE_TCP                    = 3,    ///< Message directed to a TCP service
    OT_TCAT_MESSAGE_TYPE_CHANGED_TO_UDP_SERVICE = 4,    ///< Client has changed to a UDP service
    OT_TCAT_MESSAGE_TYPE_CHANGED_TO_TCP_SERVICE = 5,    ///< Client has changed to a TCP service

} otTcatMessageType;

/**
 * The command class flag type to indicate which requirments apply for a given command class.
 *
 * This is a combination of bit-flags. The specific bit-flags are defined in the enumeration `OT_TCAT_COMMAND_CLASS_FLAG_*`.
 *
 */
typedef uint8_t otTcatCertificateAuthorizationFieldHeader ;

enum
{
    OT_TCAT_CERTIFICATE_AUTHORIZATION_FIELD_HEADER_C_FLAG = 1 << 0, ///< TCAT commissioner ('1') or device ('0')
    OT_TCAT_CERTIFICATE_AUTHORIZATION_FIELD_HEADER_VERSION = 0xD0,  ///< Header version (3 bits)
};

/**
 * The command class flag type to indicate which requirments apply for a given command class.
 *
 * This is a combination of bit-flags. The specific bit-flags are defined in the enumeration `OT_TCAT_COMMAND_CLASS_FLAG_*`.
 *
 */
typedef uint8_t otTcatCommandClassFlags;

enum
{
    OT_TCAT_COMMAND_CLASS_FLAG_ACCESS        = 1 << 0, ///< Access to the command class (device: without without additional requirments).
    OT_TCAT_COMMAND_CLASS_FLAG_PSKD          = 1 << 1, ///< Access requires proof-of-possession of the device's PSKd
    OT_TCAT_COMMAND_CLASS_FLAG_NETWORK_NAME  = 1 << 2, ///< Access requires matching network name
    OT_TCAT_COMMAND_CLASS_FLAG_XPANID        = 1 << 3, ///< Access requires matching XPANID
    OT_TCAT_COMMAND_CLASS_FLAG_THREAD_DOMAIN = 1 << 4, ///< Access requires matching XPANID
    OT_TCAT_COMMAND_CLASS_FLAG_PSKC          = 1 << 5, ///< Access requires proof-of-possession of the device's PSKc
};

/**
 * @struct otTcatCertificateAuthorizationField
 * 
 * Represents a data structure for storing TCAT Commissioner authorization information is the field 1.3.6.1.4.1.44970.3.
 *
 */
OT_TOOL_PACKED_BEGIN
struct otTcatCertificateAuthorizationField
{
    otTcatCertificateAuthorizationFieldHeader   mHeader;                ///< Typ and version
    otTcatCommandClassFlags                     mCommissioningFlags;    ///< Command class flags
    otTcatCommandClassFlags                     mExtractionFlags;       ///< Command class flags
    otTcatCommandClassFlags                     mDecommissioningFlags;  ///< Command class flags
    otTcatCommandClassFlags                     mApplicationFlags;      ///< Command class flags

} OT_TOOL_PACKED_END;

/**
 * Represents a data structure for storing TCAT Commissioner authorization information is the field 1.3.6.1.4.1.44970.3.
 *
 */
typedef struct otTcatCertificateAuthorizationField otTcatCertificateAuthorizationField;

/**
 * This structure represents a TCAT vendor information.
 *
 */
typedef struct otTcatVendorInfo
{
    const char *mProvisioningUrl; ///< Provisioning URL path string
    const char *mVendorName;      ///< Vendor name string
    const char *mVendorModel;     ///< Vendor model string
    const char *mVendorSwVersion; ///< Vendor software version string
    const char *mVendorData;      ///< Vendor specific data string
    const char *mPskdString;      ///< Vendor managed pre-shared key for device
    const char *mInstallCode;     ///< Vendor managed install code string
    const char *mDeviceId;        ///< Vendor managed device ID string (if NULL: device ID is set to EUI-64 in binary format)

} otTcatVendorInfo;

/**
 * This function pointer is called when application data was received over a TCAT TLS connection.
 *
 *
 * @param[in]  aMessage          A pointer to the message.
 * @param[in]  aTcatMessageType  The message type received.
 * @param[in]  aServiceName      The name of the service the message is direced to.
 * @param[in]  aContext          A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleTcatApplicationDataReceive)(otMessage *aMessage, otTcatMessageType aTcatMessageType, const char* aServiceName, void *aContext);

/**
 * This function pointer is called to notify the completion of a join operation.
 *
 * @param[in]  aError           OT_ERROR_NONE if the join process succeeded.
 *                              OT_ERROR_SECURITY if the join process failed due to security credentials.
 *
 * @param[in]  aContext         A pointer to arbitrary context information.
 *
 */
typedef void (*otHandleTcatJoin)(otError aError, void *aContext);

/**
 * @}
 *
 */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* OPENTHREAD_TCAT_H_ */
