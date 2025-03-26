from burp import IBurpExtender, IExtensionStateListener, IHttpListener
from burp import IScanIssue
from burp import IScannerCheck
from helper import automateRequests
from Constants import *
from CustomScanIssue import CustomScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
       self._callbacks = callbacks
       self._helpers = callbacks.getHelpers()
       callbacks.setExtensionName("ASVS-v13.1.5")
       callbacks.registerScannerCheck(self)
       callbacks.registerHttpListener(self)

       self._requests = []
       self._url = ""


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        
        self._requests =  automateRequests("payloads.txt")
        self.sendAPIRequests(self._url)
    
    def sendAPIRequests(self, url):
        for method, endpoint, payload, contentType in self._requests:
            try:
                headers = [
                    f"{method} {endpoint} HTTP/1.1",
                    f"Host: {url}",
                    f"Content-Type: content"
                    ]

                httpClient =  self._helpers.buildHttpService(url, 80, True)
                body = self._helpers.stringToBytes(payload)

                request = self._helpers.buildHttpMessage(headers, body)
                response = self._callbacks.makeHttpRequest(httpClient, request)

            
            except Exception as ex:
                print(ex)

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        response = self._helpers.analyzeResponse(baseRequestResponse)
        statusCode = response.getStatusCode()
        if statusCode != UNACCEPTABLE or statusCode != UNSUPPORTED_MEDIA:
            issues.append(CustomScanIssue(baseRequestResponse,UNSUPPORTED_CONTENT_MEDIA_ISSUE,
                                          UNSUPPORTED_CONTENT_MEDIA_DETAILS, UNSUPPORTED_CONTENT_MEDIA_REMEDIATION, LOW, CERTAIN))
        return issues

    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0
