from sslyze import (
    Scanner,
    ServerScanRequest,
    SslyzeOutputAsJson,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerScanResult,
    ServerScanResultAsJson
)

from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt
import sys
import json

ACCEPTED_TLS_1_2_CIPHER_SUITES = ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
,"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
,"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
,"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
,"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
,"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"]
ACCEPTED_TLS_1_3_CIPHER_SUITES = ["TLS_AES_128_GCM_SHA256"
,"TLS_AES_256_GCM_SHA384"
,"TLS_CHACHA20_POLY1305_SHA256"
,"TLS_AES_128_CCM_SHA256"
,"TLS_AES_128_CCM_8_SHA256"
]


def scan(host):
    
    try:
        requests = [ServerScanRequest(server_location=ServerNetworkLocation(host))]


    except ServerHostnameCouldNotBeResolved as ex:
        print(ex)

    scanner = Scanner()
    scanner.queue_scans(requests)

    output = {
        "tls1.0": False,
        "tls1.1": False,
        "tls_1_2_bad": [],
        "tls_1_3_bad": [],
    }


    for response in scanner.get_results():
        if response.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            continue

        assert response.scan_result

        tls1_0 = response.scan_result.tls_1_0_cipher_suites

        if tls1_0.status == ScanCommandAttemptStatusEnum.COMPLETED:
              output["tls1.0"] = True          
        
        tls1_1 = response.scan_result.tls_1_1_cipher_suites
        if tls1_1.status == ScanCommandAttemptStatusEnum.COMPLETED:
            output["tls1.1"] = True        

        tls1_2 = response.scan_result.tls_1_2_cipher_suites
        if tls1_2.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_2_accepted_cipher_suites = tls1_2.result.accepted_cipher_suites

            tls1_2_not_permitted = [cipher.cipher_suite.name for cipher in tls1_2_accepted_cipher_suites if cipher.cipher_suite.name not in ACCEPTED_TLS_1_2_CIPHER_SUITES]

            if len(tls1_2_not_permitted) > 0:
                output["tls_1_2_bad"] = tls1_2_not_permitted


        tls1_3 = response.scan_result.tls_1_3_cipher_suites
        if tls1_3.status == ScanCommandAttemptStatusEnum.COMPLETED:
            tls1_3_accepted_cipher_suites = tls1_3.result.accepted_cipher_suites

            tls1_3_not_permitted = [cipher.cipher_suite.name for cipher in tls1_3_accepted_cipher_suites if cipher.cipher_suite.name not in ACCEPTED_TLS_1_3_CIPHER_SUITES]

            if len(tls1_2_not_permitted) > 0:
                for cipher in tls1_3_not_permitted:
                    message = cipher + " accepted! " + cipher +" not recommended."
                    output["tls_1_2_bad"] = tls1_3_not_permitted
    print(json.dumps(output))


if __name__ == "__main__":
    scan(sys.argv[1])