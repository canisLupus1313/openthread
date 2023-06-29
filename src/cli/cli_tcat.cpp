/*
 *  Copyright (c) 2020, The OpenThread Authors.
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


#include "openthread-core-config.h"

#include "cli/cli_output.hpp"

#include "cli/cli_tcat.hpp"

#include <openthread/ble_secure.h>

#include <openthread/platform/ble.h>
#include <openthread/platform/ble.h>
#include <mbedtls/oid.h>

#if OPENTHREAD_CONFIG_BLE_TCAT_ENABLE && OPENTHREAD_CONFIG_BLE_SECURE_CLI_ENABLE

#define OT_CLI_BBTC_X509_CERT \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIBdzCCAR2gAwIBAgIEESIzAzAKBggqhkjOPQQDAjBaMQswCQYDVQQGEwJERTER\r\n" \
    "MA8GA1UEBxMIR2FyY2hpbmcxDDAKBgNVBAsTA1NUQTERMA8GA1UEChMITXlWZW5k\r\n" \
    "b3IxFzAVBgNVBAMTDm9wdG90cm9uaWMuY29tMB4XDTIzMDUyMDIzMDYxNloXDTI0\r\n" \
    "MDUyMDIzMDYxNlowFTETMBEGA1UEAxMKRGV2aWNlVHlwZTBZMBMGByqGSM49AgEG\r\n" \
    "CCqGSM49AwEHA0IABNmItKyl/hfcUXALCehmka0iO7sZtRUcLIqL2zbD6X+2EjY7\r\n" \
    "sInir9hSIyf7V+doP/Z+W5v8yG3402jJNk47ZqOjFjAUMBIGCSsGAQQBgt8qAwQF\r\n" \
    "AAA/AAAwCgYIKoZIzj0EAwIDSAAwRQIhAPrqeTxnxkDbA/lDpvozNsc5UPeY6xt5\r\n" \
    "kRjRj73CUN3tAiBycioHdhXOx8+f7fYe030Nw5wzDgjJ8wuu/QElIeCzCg==\r\n" \
    "-----END CERTIFICATE-----\r\n"

#define OT_CLI_BBTC_PRIV_KEY \
    "-----BEGIN EC PRIVATE KEY-----\r\n" \
    "MHcCAQEEIF4xKKPlATLttEC2OOvzjKSFUo85tE7uh68vdn0hj965oAoGCCqGSM49\r\n" \
    "AwEHoUQDQgAE2Yi0rKX+F9xRcAsJ6GaRrSI7uxm1FRwsiovbNsPpf7YSNjuwieKv\r\n" \
    "2FIjJ/tX52g/9n5bm/zIbfjTaMk2Tjtmow==\r\n" \
    "-----END EC PRIVATE KEY-----\r\n"

#define OT_CLI_BBTC_TRUSTED_ROOT_CERTIFICATE \
    "-----BEGIN CERTIFICATE-----\r\n" \
    "MIIB3TCCAYOgAwIBAgIJAIEkU9Kpk7sQMAoGCCqGSM49BAMCMFoxCzAJBgNVBAYT\r\n" \
    "AkRFMREwDwYDVQQHEwhHYXJjaGluZzEMMAoGA1UECxMDU1RBMREwDwYDVQQKEwhN\r\n" \
    "eVZlbmRvcjEXMBUGA1UEAxMOb3B0b3Ryb25pYy5jb20wHhcNMjMwMzI0MjMwODI2\r\n" \
    "WhcNMjYwMzI0MjMwODI2WjBaMQswCQYDVQQGEwJERTERMA8GA1UEBxMIR2FyY2hp\r\n" \
    "bmcxDDAKBgNVBAsTA1NUQTERMA8GA1UEChMITXlWZW5kb3IxFzAVBgNVBAMTDm9w\r\n" \
    "dG90cm9uaWMuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIZXjlDNlAxIV\r\n" \
    "k19EVfeQRj755MWWlZnDhaZKbMPuuP+EML9zdIwWDeCleRP5tKq5fmWp0s81lRjr\r\n" \
    "F2AwIs/TLaMyMDAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUDf0KHNxzEy7q\r\n" \
    "znA405Fx1lQsRLowCgYIKoZIzj0EAwIDSAAwRQIhAPDKNTxO8sLkns1y7ec2w2oR\r\n" \
    "CYoQyDj2d498XeWYkSVuAiBz+GSRnTmdCFzQKfL8/ma7QaNdXihKYrWUdqvlynVV\r\n" \
    "MQ==\r\n" \
    "-----END CERTIFICATE-----\r\n"


namespace ot {

namespace Cli {

// BleSecure callback functions

static void HandleBleSecureClientConnect(otInstance *aInstance, bool aConnected, bool aBleConnectionOpen, void *aContext)
{
    OT_UNUSED_VARIABLE(aBleConnectionOpen);
    OT_UNUSED_VARIABLE(aContext);
	//LOG_INF("TLS Connected: %s, BLE connection open: %s", aConnected ? "YES" : " NO",
	//	aBleConnectionOpen ? "YES" : " NO");

	if (aConnected) {
		uint8_t buf[20];
		size_t len;

		otBleSecureGetPeerSubjectAttributeByOid(aInstance, MBEDTLS_OID_AT_CN,
							sizeof(MBEDTLS_OID_AT_CN) - 1, buf, &len,
							sizeof(buf) - 1, NULL);

		buf[len] = 0;
		//LOG_INF("Peer cert. Common Name:%s", buf);

		otBleSecureGetThreadAttributeFromPeerCertificate(aInstance, 3, buf, &len,
								 sizeof(buf));
		if (len > 0) {
			//LOG_INF("Peer OID 1.3.6.1.4.1.44970.3: %02X%02X%02X%02X%02X (len = %d)",
			//	buf[0], buf[1], buf[2], buf[3], buf[4], len);
		}

		otBleSecureGetThreadAttributeFromOwnCertificate(aInstance, 3, buf, &len,
								sizeof(buf));
		if (len > 0) {
			//LOG_INF("Own OID 1.3.6.1.4.1.44970.3: %02X%02X%02X%02X%02X (len = %d)",
			//	buf[0], buf[1], buf[2], buf[3], buf[4], len);
		}
	}
}

static void HandleBleSecureReceive(otInstance *aInstance, otMessage *aMessage, void *aContext)
{
    OT_UNUSED_VARIABLE(aContext);

	uint16_t nLen;
	uint8_t buf[100];

	//LOG_INF("TLS Data Received len:%d offset:%d", (int)otMessageGetLength(aMessage),
	//	(int)otMessageGetOffset(aMessage));

	nLen = otMessageRead(aMessage, otMessageGetOffset(aMessage), buf + 5, sizeof(buf) - 6);
	buf[nLen + 5] = 0;

	//LOG_INF("Received:%s", buf + 5);
	memcpy(buf, "RECV:", 5);

	otBleSecureSendApplicationTlv(aInstance, buf, strlen((char*)buf));
	otBleSecureFlush(aInstance);
}

template <> otError Tcat::Process<Cmd("start")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;

    OT_UNUSED_VARIABLE(aArgs);
	otInstance *myOpenThreadInstance = GetInstancePtr();

	otBleSecureSetCertificate(myOpenThreadInstance, (const uint8_t *)(OT_CLI_BBTC_X509_CERT),
				  sizeof(OT_CLI_BBTC_X509_CERT),
				  (const uint8_t *)(OT_CLI_BBTC_PRIV_KEY),
				  sizeof(OT_CLI_BBTC_PRIV_KEY));

	otBleSecureSetCaCertificateChain(myOpenThreadInstance,
					 (const uint8_t *)(OT_CLI_BBTC_TRUSTED_ROOT_CERTIFICATE),
					 sizeof(OT_CLI_BBTC_TRUSTED_ROOT_CERTIFICATE));

	otBleSecureSetSslAuthMode(myOpenThreadInstance, true);

	otBleSecureStart(myOpenThreadInstance, HandleBleSecureClientConnect, HandleBleSecureReceive,
			 true, NULL);
	otBleSecureTcatStart(myOpenThreadInstance, "SECRET", NULL, NULL);
    return error;
}

template <> otError Tcat::Process<Cmd("stop")>(Arg aArgs[])
{
    otError error = OT_ERROR_NONE;
    otBleSecureStop(GetInstancePtr());
    OT_UNUSED_VARIABLE(aArgs);
    return error;
}

otError Tcat::Process(Arg aArgs[]) {

#define CmdEntry(aCommandString)                                  \
    {                                                             \
        aCommandString, &Tcat::Process<Cmd(aCommandString)> \
    }

    static constexpr Command kCommands[] = {
        CmdEntry("start"), CmdEntry("stop")
    };

    static_assert(BinarySearch::IsSorted(kCommands), "kCommands is not sorted");

    otError        error = OT_ERROR_NONE;
    const Command *command;

    if (aArgs[0].IsEmpty())
    {
        OutputCommandTable(kCommands);
        ExitNow(error = OT_ERROR_INVALID_ARGS);
    }

    command = BinarySearch::Find(aArgs[0].GetCString(), kCommands);
    VerifyOrExit(command != nullptr);

    error = (this->*command->mHandler)(aArgs + 1);

exit:
    return error;
}

}
}
#endif // OPENTHREAD_CONFIG_BLE_TCAT_ENABLE && OPENTHREAD_CONFIG_BLE_SECURE_CLI_ENABLE