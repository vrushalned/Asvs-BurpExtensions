from burp import IBurpExtender, IExtensionStateListener, IHttpListener
from burp import IScanIssue
from burp import IScannerCheck


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
            self._requests = self.automateRequests("payloads.txt")
            url =""
            self.sendAPIRequests(url)
        except Exception as ex:
            print(ex)


    def automateRequests(self, file):
        requests = []
        try:
            with open(file, 'r') as src:
                lines = src.readlines()
                method = None
                contentType = None
                payload = None
                endpoint = None

                for line in lines:
                    line = line.strip()
                    
                    if line.startswith("POST") or line.startswith("GET"):
                        parts = line.split(" ")
                        method = parts[0]
                        endpoint = parts[1]

                    elif line.startswith("json") or line.startswith("xml") or line.startswith("text"):
                        content = line.split(" - ")
                        payload = content[1]
                        if content[0].lower() == "json":
                            contentType = "application/json"
                        elif content[0].lower() == "xml":
                            contentType = "application/xml"
                        elif content[0].lower() == "text":
                            contentType = "text/plain"
                        
                    elif line.startswith("-----"):
                        requests.append(
                            (method, endpoint, payload, contentType)
                        )

                        method = None
                        endpoint = None
                        payload = None
                        contentType = None
        except Exception as e:
            print("file not loaded properly")
        
        return requests
    

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
                issues.append(CustomScanIssue(baseRequestResponse, "API Request Content-Type Inconsistency",
                                          "The response Content-Type and ecncoidng is inconsistent.", "Low"))
            elif len(set(contentTypes)) > 1:
                issues.append(CustomScanIssue(baseRequestResponse, "API Request Content-Type Inconsistency",
                                          "The response Content-Type is inconsistent.", "Low"))
            elif len(set(encodings)) > 2:
                issues.append(CustomScanIssue(baseRequestResponse, "API Request Content-Type Inconsistency",
                                          "The response ecncoding is inconsistent.", "Low"))

            return issues
        
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

    def __init__(self):
        self._endpoint_content_types = {}



class CustomScanIssue(IScanIssue):
    def __init__(self, requestResponse, issueName, issueDetail, severity):
        self._requestResponse = requestResponse
        self._issueName = issueName
        self._issueDetail = issueDetail
        self._severity = severity

    def getUrl(self):
        return self._requestResponse.getUrl()

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._issueDetail

    def getRemediationDetail(self):
        return "Inconsistencies in encoidng and parsing in the application components!"

    def getHttpMessages(self):
        return [self._requestResponse]

    def getHttpService(self):
        return self._requestResponse.getHttpService()



