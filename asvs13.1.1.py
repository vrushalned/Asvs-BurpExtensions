from burp import IBurpExtender, IExtensionStateListener, IHttpListener
from burp import IScanIssue
from burp import IScannerCheck
from helper import automateRequests
from CustomScanIssue import CustomScanIssue
from Constants import *


class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ASVS-v13.1.1")
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)

        self._analyzedResponses = []
        self._requests = None
        self._analyze = False


    def doActiveScan(self, baseRequestResponse, insertionPoint):
        try:
            self._requests = automateRequests("payloads.txt")
            url =""
            self.sendAPIRequests(url)
        except Exception as ex:
            print(ex)
   
    

    def sendAPIRequests(self, url):

        for method, endpoint, payload, contentType in self._requests:
            try:
                headers = [
                    f"{method} {endpoint} HTTP/1.1",
                    f"Host: {url}",
                    f"Content-Type: {contentType}"
                    ]

                httpClient =  self._helpers.buildHttpService(url, 80, True)
                body = self._helpers.stringToBytes(payload)

                request = self._helpers.buildHttpMessage(headers, body)
                response = self._callbacks.makeHttpRequest(httpClient, request)
                responseParsed = self._helpers.analyzeResponse(response.getResponse())
                self._analyzedResponses.append((method, endpoint, responseParsed))

            
            except Exception as ex:
                print(ex)
        self._analyze = True

    def doPassiveScan(self, baseRequestResponse):
        if self._analyze is True:
            contentTypes = []
            encodings = []
            issues = []

            for method, endpoint, response in self._analyzedResponses:
                headers = response.getHeaders()
                for header in headers:
                    if header.lower().startswith("content-type"):
                        content = header.split(";")[0]
                        encoding = header.split(";")[1] if len(header.split(";")) > 1 else ""

                        contentTypes.append(content)
                        encodings.append(encoding)

            if len(set(contentTypes)) > 1 and len(set(encodings)) > 2:
                issues.append(CustomScanIssue(baseRequestResponse,INCONSISTENT_CONTENT_ISSUE,
                                          INCONSISTENT_CONTENT_ENCODING_TYPE, INCONSISTENT_CONTENT_REMEDIATION, LOW, CERTAIN))
            elif len(set(contentTypes)) > 1:
                issues.append(CustomScanIssue(baseRequestResponse, INCONSISTENT_CONTENT_ISSUE,
                                         INCONSISTENT_CONTENT_TYPE, INCONSISTENT_CONTENT_REMEDIATION, LOW, CERTAIN))
            elif len(set(encodings)) > 2:
                issues.append(CustomScanIssue(baseRequestResponse, INCONSISTENT_CONTENT_ISSUE,
                                          INCONSISTENT_CONTENT_ENCODING, INCONSISTENT_CONTENT_REMEDIATION, LOW, CERTAIN))

            return issues
        
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

    def __init__(self):
        self._endpoint_content_types = {}







